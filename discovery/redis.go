package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RedisConfig struct {
	Addr     string
	Password string
	Prefix   string
	TTL      time.Duration
}

type RedisRegistrar struct {
	cfg    RedisConfig
	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
}

func NewRedisRegistrar(cfg RedisConfig) *RedisRegistrar {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:6379"
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "saker:services"
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 30 * time.Second
	}
	return &RedisRegistrar{cfg: cfg}
}

func (r *RedisRegistrar) Register(ctx context.Context, svc ServiceInstance) error {
	return r.Refresh(ctx, svc)
}

func (r *RedisRegistrar) Heartbeat(ctx context.Context, serviceID, instanceID string) error {
	return r.command(ctx, "EXPIRE", r.key(serviceID, instanceID), strconv.Itoa(int(r.cfg.TTL.Seconds())))
}

func (r *RedisRegistrar) Refresh(ctx context.Context, svc ServiceInstance) error {
	normalized, err := Normalize(svc)
	if err != nil {
		return err
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	if err := r.command(ctx, "SET", r.key(normalized.ID, normalized.InstanceID), string(data), "EX", strconv.Itoa(int(r.cfg.TTL.Seconds()))); err != nil {
		return err
	}
	if err := r.command(ctx, "SADD", r.indexKey(), normalized.ID+":"+normalized.InstanceID); err != nil {
		return err
	}
	return r.command(ctx, "PUBLISH", r.eventsKey(), string(data))
}

func (r *RedisRegistrar) Deregister(ctx context.Context, instanceID string) error {
	// Common services know their instance ID but not the service index members.
	// The WebHub Redis provider reconcile loop removes expired stale members.
	_ = instanceID
	return nil
}

func (r *RedisRegistrar) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeConnLocked()
}

func (r *RedisRegistrar) command(ctx context.Context, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.commandLocked(ctx, args...); err != nil {
		r.closeConnLocked()
		return r.commandLocked(ctx, args...)
	}
	return nil
}

func (r *RedisRegistrar) commandLocked(ctx context.Context, args ...string) error {
	if err := r.ensureConnLocked(ctx); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = r.conn.SetDeadline(deadline)
	}
	if err := writeCommand(r.conn, args...); err != nil {
		return err
	}
	return readSimple(r.reader)
}

func (r *RedisRegistrar) ensureConnLocked(ctx context.Context) error {
	if r.conn != nil {
		return nil
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", r.cfg.Addr)
	if err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	if r.cfg.Password != "" {
		if err := writeCommand(conn, "AUTH", r.cfg.Password); err != nil {
			_ = conn.Close()
			return err
		}
		if err := readSimple(reader); err != nil {
			_ = conn.Close()
			return err
		}
	}
	r.conn = conn
	r.reader = reader
	return nil
}

func (r *RedisRegistrar) closeConnLocked() error {
	if r.conn != nil {
		err := r.conn.Close()
		r.conn = nil
		r.reader = nil
		return err
	}
	return nil
}

func writeCommand(conn net.Conn, args ...string) error {
	if _, err := fmt.Fprintf(conn, "*%d\r\n", len(args)); err != nil {
		return err
	}
	for _, arg := range args {
		if _, err := fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(arg), arg); err != nil {
			return err
		}
	}
	return nil
}

func readSimple(reader *bufio.Reader) error {
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.HasPrefix(line, "-") {
		return fmt.Errorf("redis error: %s", strings.TrimSpace(line[1:]))
	}
	return nil
}

func (r *RedisRegistrar) key(serviceID, instanceID string) string {
	return r.cfg.Prefix + ":" + serviceID + ":" + instanceID
}

func (r *RedisRegistrar) indexKey() string {
	return r.cfg.Prefix + ":index"
}

func (r *RedisRegistrar) eventsKey() string {
	return r.cfg.Prefix + ":events"
}

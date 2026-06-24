package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type RedisConfig struct {
	Addr     string
	Password string
	Prefix   string
	TTL      time.Duration
}

type RedisRegistrar struct {
	cfg RedisConfig
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
	return nil
}

func (r *RedisRegistrar) command(ctx context.Context, args ...string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", r.cfg.Addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	reader := bufio.NewReader(conn)
	if r.cfg.Password != "" {
		if err := writeCommand(conn, "AUTH", r.cfg.Password); err != nil {
			return err
		}
		if err := readSimple(reader); err != nil {
			return err
		}
	}
	if err := writeCommand(conn, args...); err != nil {
		return err
	}
	return readSimple(reader)
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

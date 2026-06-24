package discovery

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	mdnsAddr = "224.0.0.251:5353"
	typeA    = 1
	typePTR  = 12
	typeTXT  = 16
	typeSRV  = 33
	classIN  = 1
)

type MDNSConfig struct {
	ServiceType string
	Domain      string
}

type MDNSRegistrar struct {
	cfg      MDNSConfig
	conn     net.PacketConn
	records  map[string]ServiceInstance
	stop     chan struct{}
	stopOnce sync.Once
	mu       sync.RWMutex
}

func NewMDNSRegistrar(cfg MDNSConfig) *MDNSRegistrar {
	if cfg.ServiceType == "" {
		cfg.ServiceType = "_saker._tcp"
	}
	if cfg.Domain == "" {
		cfg.Domain = "local."
	}
	return &MDNSRegistrar{cfg: cfg, records: map[string]ServiceInstance{}, stop: make(chan struct{})}
}

func (r *MDNSRegistrar) Register(ctx context.Context, svc ServiceInstance) error {
	return r.Refresh(ctx, svc)
}

func (r *MDNSRegistrar) Heartbeat(context.Context, string, string) error {
	r.announceAll()
	return nil
}

func (r *MDNSRegistrar) Refresh(ctx context.Context, svc ServiceInstance) error {
	normalized, err := Normalize(svc)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.records[normalized.InstanceID] = normalized
	r.mu.Unlock()
	if err := r.ensureConn(ctx); err != nil {
		return err
	}
	return r.announce(normalized.InstanceID)
}

func (r *MDNSRegistrar) Deregister(context.Context, string) error {
	return nil
}

func (r *MDNSRegistrar) Close() error {
	r.stopOnce.Do(func() { close(r.stop) })
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		err := r.conn.Close()
		r.conn = nil
		return err
	}
	return nil
}

func (r *MDNSRegistrar) ensureConn(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		return nil
	}
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	r.conn = conn
	go r.loop(ctx)
	return nil
}

func (r *MDNSRegistrar) loop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		case <-ticker.C:
			r.announceAll()
		}
	}
}

func (r *MDNSRegistrar) announceAll() {
	r.mu.RLock()
	ids := make([]string, 0, len(r.records))
	for id := range r.records {
		ids = append(ids, id)
	}
	r.mu.RUnlock()
	for _, id := range ids {
		_ = r.announce(id)
	}
}

func (r *MDNSRegistrar) announce(instanceID string) error {
	r.mu.RLock()
	svc, ok := r.records[instanceID]
	conn := r.conn
	r.mu.RUnlock()
	if !ok || conn == nil {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp4", mdnsAddr)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(r.buildAnnouncement(svc), addr)
	return err
}

func (r *MDNSRegistrar) buildAnnouncement(svc ServiceInstance) []byte {
	service := serviceFQDN(r.cfg)
	instance := dnsInstanceName(r.cfg, svc)
	host := strings.ReplaceAll(svc.ID, ".", "-") + ".local."
	ip := net.ParseIP(svc.Address).To4()
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1)
	}
	var out []byte
	out = append(out, 0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0)
	out = appendRRName(out, service, typePTR, 120, mustName(instance))
	out = appendSRV(out, instance, 120, svc.Port, host)
	out = appendTXT(out, instance, 120, serviceTXT(svc))
	out = appendA(out, host, 120, ip)
	return out
}

func serviceFQDN(cfg MDNSConfig) string {
	return strings.TrimSuffix(cfg.ServiceType, ".") + "." + strings.Trim(strings.TrimSuffix(cfg.Domain, "."), ".") + "."
}

func dnsInstanceName(cfg MDNSConfig, svc ServiceInstance) string {
	name := svc.Name
	if name == "" {
		name = svc.ID
	}
	return strings.ReplaceAll(name, ".", "-") + "." + serviceFQDN(cfg)
}

func serviceTXT(svc ServiceInstance) []string {
	return []string{
		"id=" + svc.ID,
		"name=" + svc.Name,
		"scheme=" + svc.Scheme,
		"prefix=" + svc.Prefix,
		"health=" + svc.HealthPath,
		"audience=" + svc.Audience,
		"native_route=" + svc.NativeRoute,
		"version=" + svc.Version,
		"status=" + svc.Status,
		"weight=" + strconv.Itoa(svc.Weight),
	}
}

func appendRRHeader(out []byte, name string, typ uint16, ttl uint32, rdlen int) []byte {
	out = append(out, mustName(name)...)
	out = binary.BigEndian.AppendUint16(out, typ)
	out = binary.BigEndian.AppendUint16(out, classIN|0x8000)
	out = binary.BigEndian.AppendUint32(out, ttl)
	out = binary.BigEndian.AppendUint16(out, uint16(rdlen))
	return out
}

func appendRRName(out []byte, name string, typ uint16, ttl uint32, target []byte) []byte {
	out = appendRRHeader(out, name, typ, ttl, len(target))
	return append(out, target...)
}

func appendSRV(out []byte, name string, ttl uint32, port int, host string) []byte {
	target := mustName(host)
	rdata := make([]byte, 6, 6+len(target))
	binary.BigEndian.PutUint16(rdata[4:6], uint16(port))
	rdata = append(rdata, target...)
	out = appendRRHeader(out, name, typeSRV, ttl, len(rdata))
	return append(out, rdata...)
}

func appendTXT(out []byte, name string, ttl uint32, txt []string) []byte {
	var rdata []byte
	for _, entry := range txt {
		if len(entry) > 255 {
			entry = entry[:255]
		}
		rdata = append(rdata, byte(len(entry)))
		rdata = append(rdata, entry...)
	}
	out = appendRRHeader(out, name, typeTXT, ttl, len(rdata))
	return append(out, rdata...)
}

func appendA(out []byte, name string, ttl uint32, ip net.IP) []byte {
	out = appendRRHeader(out, name, typeA, ttl, 4)
	return append(out, ip.To4()...)
}

func mustName(name string) []byte {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	var out []byte
	for _, label := range labels {
		if len(label) > 63 {
			label = label[:63]
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

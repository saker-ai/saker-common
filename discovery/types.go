package discovery

import (
	"context"
	"time"
)

const (
	StatusPassing = "passing"
)

type ServiceInstance struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	InstanceID  string            `json:"instance_id"`
	Scheme      string            `json:"scheme"`
	Address     string            `json:"address"`
	Port        int               `json:"port"`
	BaseURL     string            `json:"base_url"`
	Prefix      string            `json:"prefix"`
	HealthPath  string            `json:"health_path"`
	Audience    string            `json:"audience"`
	NativeRoute string            `json:"native_route"`
	Version     string            `json:"version"`
	Status      string            `json:"status"`
	Weight      int               `json:"weight"`
	Region      string            `json:"region,omitempty"`
	Zone        string            `json:"zone,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	StartedAt   time.Time         `json:"started_at"`
	LastSeenAt  time.Time         `json:"last_seen_at"`
	TTL         time.Duration     `json:"ttl"`
	Source      string            `json:"source"`
}

type Registrar interface {
	Register(ctx context.Context, svc ServiceInstance) error
	Heartbeat(ctx context.Context, serviceID, instanceID string) error
	Refresh(ctx context.Context, svc ServiceInstance) error
	Deregister(ctx context.Context, instanceID string) error
	Close() error
}

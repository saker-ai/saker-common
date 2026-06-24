package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type ConsulConfig struct {
	Addr  string
	Token string
}

type ConsulRegistrar struct {
	cfg    ConsulConfig
	client *http.Client
}

func NewConsulRegistrar(cfg ConsulConfig) *ConsulRegistrar {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8500"
	}
	if !strings.HasPrefix(cfg.Addr, "http://") && !strings.HasPrefix(cfg.Addr, "https://") {
		cfg.Addr = "http://" + cfg.Addr
	}
	return &ConsulRegistrar{cfg: cfg, client: http.DefaultClient}
}

func (r *ConsulRegistrar) Register(ctx context.Context, svc ServiceInstance) error {
	return r.Refresh(ctx, svc)
}

func (r *ConsulRegistrar) Heartbeat(context.Context, string, string) error {
	return nil
}

func (r *ConsulRegistrar) Refresh(ctx context.Context, svc ServiceInstance) error {
	normalized, err := Normalize(svc)
	if err != nil {
		return err
	}
	body := map[string]any{
		"ID":      normalized.InstanceID,
		"Name":    normalized.ID,
		"Address": normalized.Address,
		"Port":    normalized.Port,
		"Tags": []string{
			"saker",
			"prefix=" + normalized.Prefix,
			"audience=" + normalized.Audience,
			"native_route=" + normalized.NativeRoute,
			"scheme=" + normalized.Scheme,
			"health=" + normalized.HealthPath,
			"version=" + normalized.Version,
		},
		"Check": map[string]any{
			"HTTP":     normalized.BaseURL + normalized.HealthPath,
			"Interval": "10s",
			"Timeout":  "2s",
		},
	}
	data, _ := json.Marshal(body)
	req, err := r.request(ctx, http.MethodPut, "/v1/agent/service/register", bytes.NewReader(data))
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("consul register: %s", resp.Status)
	}
	return nil
}

func (r *ConsulRegistrar) Deregister(ctx context.Context, instanceID string) error {
	req, err := r.request(ctx, http.MethodPut, "/v1/agent/service/deregister/"+url.PathEscape(instanceID), bytes.NewReader(nil))
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("consul deregister: %s", resp.Status)
	}
	return nil
}

func (r *ConsulRegistrar) Close() error {
	return nil
}

func (r *ConsulRegistrar) request(ctx context.Context, method, path string, body *bytes.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(r.cfg.Addr, "/")+path, body)
	if err != nil {
		return nil, err
	}
	if r.cfg.Token != "" {
		req.Header.Set("X-Consul-Token", r.cfg.Token)
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

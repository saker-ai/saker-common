package warden

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type CasdoorMode string

const (
	CasdoorModeEmbedded       CasdoorMode = "embedded"
	CasdoorModeManagedSidecar CasdoorMode = "managed_sidecar"
	CasdoorModeExternalCompat CasdoorMode = "external_compat"
)

type CasdoorConfig struct {
	Mode           CasdoorMode
	BaseURL        string
	IssuerURL      string
	Version        string
	AllowExternal  bool
	Command        string
	Args           []string
	Env            []string
	HealthPath     string
	StartupTimeout time.Duration
}

type CasdoorManager interface {
	Start(context.Context) error
	Shutdown(context.Context) error
	HealthEndpoint() string
}

type CasdoorBootstrapper interface {
	BootstrapCasdoor(context.Context, CasdoorConfig) error
}

type CasdoorLeaderLock interface {
	IsLeader(context.Context) (bool, error)
}

type ManagedCasdoorManager struct {
	cfg          CasdoorConfig
	client       *http.Client
	bootstrapper CasdoorBootstrapper
	leader       CasdoorLeaderLock

	mu      sync.Mutex
	cmd     *exec.Cmd
	started bool
}

func NewManagedCasdoorManager(cfg CasdoorConfig, bootstrapper CasdoorBootstrapper, leader CasdoorLeaderLock) *ManagedCasdoorManager {
	if cfg.Mode == "" {
		cfg.Mode = CasdoorModeManagedSidecar
	}
	if cfg.HealthPath == "" {
		cfg.HealthPath = "/.well-known/openid-configuration"
	}
	if cfg.StartupTimeout <= 0 {
		cfg.StartupTimeout = 30 * time.Second
	}
	return &ManagedCasdoorManager{cfg: cfg, client: http.DefaultClient, bootstrapper: bootstrapper, leader: leader}
}

func (m *ManagedCasdoorManager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	if m.cfg.Mode == CasdoorModeExternalCompat {
		if !m.cfg.AllowExternal {
			m.mu.Unlock()
			return errors.New("external casdoor compatibility mode must be explicitly enabled")
		}
		m.started = true
		m.mu.Unlock()
		return m.bootstrapIfLeader(ctx)
	}
	if strings.TrimSpace(m.cfg.Command) != "" {
		cmd := exec.Command(m.cfg.Command, m.cfg.Args...)
		cmd.Env = append(os.Environ(), m.cfg.Env...)
		if err := cmd.Start(); err != nil {
			m.mu.Unlock()
			return fmt.Errorf("start casdoor sidecar: %w", err)
		}
		m.cmd = cmd
		go func() { _ = cmd.Wait() }()
	} else if m.cfg.Mode == CasdoorModeManagedSidecar {
		if strings.TrimSpace(m.cfg.BaseURL) == "" {
			m.started = true
			m.mu.Unlock()
			return m.bootstrapIfLeader(ctx)
		}
	}
	m.started = true
	m.mu.Unlock()

	if strings.TrimSpace(m.cfg.Command) != "" {
		if err := m.waitHealthy(ctx); err != nil {
			_ = m.Shutdown(context.Background())
			return err
		}
	}
	if err := m.bootstrapIfLeader(ctx); err != nil {
		_ = m.Shutdown(context.Background())
		return err
	}
	return nil
}

func (m *ManagedCasdoorManager) Shutdown(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started = false
	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}
	err := m.cmd.Process.Kill()
	m.cmd = nil
	if err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("shutdown casdoor sidecar: %w", err)
	}
	return nil
}

func (m *ManagedCasdoorManager) HealthEndpoint() string {
	base := strings.TrimRight(strings.TrimSpace(m.cfg.BaseURL), "/")
	if base == "" {
		return ""
	}
	return base + "/" + strings.TrimLeft(m.cfg.HealthPath, "/")
}

func (m *ManagedCasdoorManager) waitHealthy(ctx context.Context) error {
	endpoint := m.HealthEndpoint()
	if endpoint == "" {
		return nil
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, m.cfg.StartupTimeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		resp, err := m.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				return nil
			}
		}
		select {
		case <-timeoutCtx.Done():
			return fmt.Errorf("casdoor health check %s: %w", endpoint, timeoutCtx.Err())
		case <-ticker.C:
		}
	}
}

func (m *ManagedCasdoorManager) bootstrapIfLeader(ctx context.Context) error {
	if m.bootstrapper == nil {
		return nil
	}
	if m.leader != nil {
		ok, err := m.leader.IsLeader(ctx)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
	}
	return m.bootstrapper.BootstrapCasdoor(ctx, m.cfg)
}

type CasdoorProxy struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
}

func NewCasdoorProxy(baseURL string) (*CasdoorProxy, error) {
	target, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, err
	}
	target.Path = ""
	target.RawPath = ""
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		forwardedHost := req.Host
		originalDirector(req)
		req.Host = target.Host
		req.Header.Set("X-Forwarded-Host", forwardedHost)
		if req.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			req.Header.Set("X-Forwarded-Proto", "http")
		}
	}
	return &CasdoorProxy{target: target, proxy: proxy}, nil
}

func (p *CasdoorProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p == nil || p.proxy == nil || !IsCasdoorEntrypointPath(r.URL.Path) {
		writeJSONError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	p.proxy.ServeHTTP(w, r)
}

func IsCasdoorEntrypointPath(path string) bool {
	switch {
	case path == "/.well-known/openid-configuration":
		return true
	case strings.HasPrefix(path, "/.well-known/") && strings.HasSuffix(path, "/openid-configuration"):
		return true
	case path == "/.well-known/jwks":
		return true
	case strings.HasPrefix(path, "/login/oauth/"):
		return true
	case strings.HasPrefix(path, "/api/login/oauth/"):
		return true
	case path == "/api/userinfo":
		return true
	case path == "/api/login" || strings.HasPrefix(path, "/api/login/"):
		return true
	case path == "/api/signup" || strings.HasPrefix(path, "/api/signup/"):
		return true
	case strings.HasPrefix(path, "/api/get-application"):
		return true
	case strings.HasPrefix(path, "/api/device-auth"):
		return true
	case path == "/api/get-account":
		return true
	case strings.HasPrefix(path, "/api/get-app-login"):
		return true
	case path == "/api/logout":
		return true
	case strings.HasPrefix(path, "/api/verify-code/"):
		return true
	case strings.HasPrefix(path, "/api/send-verification-code/"):
		return true
	case strings.HasPrefix(path, "/login"):
		return true
	case strings.HasPrefix(path, "/signup"):
		return true
	case strings.HasPrefix(path, "/forget"):
		return true
	case strings.HasPrefix(path, "/cas/"):
		return true
	case strings.HasPrefix(path, "/static/"):
		return true
	default:
		return false
	}
}

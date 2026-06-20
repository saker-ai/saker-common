package warden

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestIsCasdoorEntrypointPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "openid config", path: "/.well-known/openid-configuration", want: true},
		{name: "tenant openid config", path: "/.well-known/acme/openid-configuration", want: true},
		{name: "jwks", path: "/.well-known/jwks", want: true},
		{name: "login", path: "/login/oauth/authorize", want: true},
		{name: "signup api", path: "/api/signup/send-verification-code", want: true},
		{name: "verify code", path: "/api/verify-code/email", want: true},
		{name: "iam context", path: "/iam/context", want: false},
		{name: "internal jwt", path: "/internal/internal-jwts", want: false},
		{name: "app api", path: "/v1/chat", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCasdoorEntrypointPath(tt.path); got != tt.want {
				t.Fatalf("IsCasdoorEntrypointPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestCasdoorProxyForwardsOnlyCasdoorEntrypoints(t *testing.T) {
	var gotHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Header.Get("X-Forwarded-Host")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("casdoor"))
	}))
	defer upstream.Close()

	proxy, err := NewCasdoorProxy(upstream.URL)
	if err != nil {
		t.Fatalf("NewCasdoorProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "saker.example.com"
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "casdoor" {
		t.Fatalf("proxied status=%d body=%q", rec.Code, rec.Body.String())
	}
	if gotHost != "saker.example.com" {
		t.Fatalf("X-Forwarded-Host = %q, want saker.example.com", gotHost)
	}

	req = httptest.NewRequest(http.MethodGet, "/iam/context", nil)
	rec = httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-casdoor status=%d, want 404", rec.Code)
	}
}

func TestManagedCasdoorManagerBootstrapsOnlyOnLeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	bootstrap := &recordingBootstrapper{}
	manager := NewManagedCasdoorManager(CasdoorConfig{
		Mode:           CasdoorModeManagedSidecar,
		BaseURL:        upstream.URL,
		HealthPath:     "/health",
		StartupTimeout: time.Second,
	}, bootstrap, staticLeader{leader: false})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start non-leader: %v", err)
	}
	if bootstrap.calls != 0 {
		t.Fatalf("bootstrap calls = %d, want 0", bootstrap.calls)
	}

	manager = NewManagedCasdoorManager(CasdoorConfig{
		Mode:           CasdoorModeManagedSidecar,
		BaseURL:        upstream.URL,
		HealthPath:     "/health",
		StartupTimeout: time.Second,
		Version:        "v-test",
	}, bootstrap, staticLeader{leader: true})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start leader: %v", err)
	}
	if bootstrap.calls != 1 || bootstrap.version != "v-test" {
		t.Fatalf("bootstrap calls=%d version=%q", bootstrap.calls, bootstrap.version)
	}
}

func TestManagedCasdoorManagerRequiresExplicitExternalCompat(t *testing.T) {
	manager := NewManagedCasdoorManager(CasdoorConfig{
		Mode: CasdoorModeExternalCompat,
	}, nil, nil)

	if err := manager.Start(context.Background()); err == nil {
		t.Fatal("Start external compat without AllowExternal succeeded, want error")
	}

	manager = NewManagedCasdoorManager(CasdoorConfig{
		Mode:          CasdoorModeExternalCompat,
		AllowExternal: true,
	}, nil, nil)
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start external compat with AllowExternal: %v", err)
	}
}

func TestManagedCasdoorManagerStartsAndStopsSidecar(t *testing.T) {
	if os.Getenv("WARDEN_CASDOOR_HELPER") == "1" {
		time.Sleep(time.Minute)
		return
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	manager := NewManagedCasdoorManager(CasdoorConfig{
		Mode:           CasdoorModeManagedSidecar,
		BaseURL:        upstream.URL,
		HealthPath:     "/health",
		StartupTimeout: time.Second,
		Command:        os.Args[0],
		Args:           []string{"-test.run=TestManagedCasdoorManagerStartsAndStopsSidecar"},
		Env:            []string{"WARDEN_CASDOOR_HELPER=1"},
	}, nil, nil)
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if manager.cmd == nil || manager.cmd.Process == nil {
		t.Fatal("sidecar process was not started")
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

type recordingBootstrapper struct {
	calls   int
	version string
}

func (b *recordingBootstrapper) BootstrapCasdoor(_ context.Context, cfg CasdoorConfig) error {
	b.calls++
	b.version = cfg.Version
	return nil
}

type staticLeader struct {
	leader bool
}

func (l staticLeader) IsLeader(context.Context) (bool, error) { return l.leader, nil }

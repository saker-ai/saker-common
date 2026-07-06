package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientDisabledNoop(t *testing.T) {
	c, err := NewClient(Config{Enabled: false})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if err := c.Notify(context.Background(), Event{Title: "x"}); err != nil {
		t.Fatalf("disabled err=%v", err)
	}
}

func TestClientEnabledRequiresConfig(t *testing.T) {
	if _, err := NewClient(Config{Enabled: true}); err == nil {
		t.Fatal("want error when webhub_url missing")
	}
	if _, err := NewClient(Config{Enabled: true, WebHubURL: "http://h"}); err == nil {
		t.Fatal("want error when warden_url missing")
	}
	if _, err := NewClient(Config{Enabled: true, WebHubURL: "http://h", WardenURL: "http://w"}); err == nil {
		t.Fatal("want error when api_key missing")
	}
}

func TestClientNotifyFlow(t *testing.T) {
	var tokenCalls int32
	warden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/internal-jwts" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		atomic.AddInt32(&tokenCalls, 1)
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["api_key"] != "test-key" {
			t.Errorf("api_key=%v want test-key", req["api_key"])
		}
		if req["audience"] != "webhub" {
			t.Errorf("audience=%v want webhub", req["audience"])
		}
		actions, _ := req["actions"].([]any)
		if len(actions) != 1 || actions[0] != "write" {
			t.Errorf("actions=%v want [write]", actions)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "signed-jwt",
			"expires_at": time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer warden.Close()

	var received struct {
		Headers http.Header
		Body    map[string]any
	}
	webhub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		_ = json.Unmarshal(body, &parsed)
		received.Headers = r.Header
		received.Body = parsed
		w.WriteHeader(http.StatusCreated)
	}))
	defer webhub.Close()

	c, err := NewClient(Config{
		Enabled:   true,
		WebHubURL: webhub.URL + "/v1/notifications",
		WardenURL: warden.URL,
		APIKey:    "test-key",
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}

	err = c.Notify(context.Background(), Event{
		Type:      "chathub.run_finished",
		Title:     "Chat run finished",
		Body:      "Run abc-123 completed.",
		TenantID:  "tenant-a",
		SourceApp: "chathub",
		Severity:  "info",
		Href:      "/chat/threads/thread-1",
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if atomic.LoadInt32(&tokenCalls) != 1 {
		t.Fatalf("token calls=%d want 1", tokenCalls)
	}
	auth := received.Headers.Get("X-Saker-Internal-Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != "signed-jwt" {
		t.Fatalf("auth header=%q", auth)
	}
	if received.Body["type"] != "chathub.run_finished" {
		t.Fatalf("type=%v", received.Body["type"])
	}
	if received.Body["tenant_id"] != "tenant-a" {
		t.Fatalf("tenant_id=%v", received.Body["tenant_id"])
	}
	if received.Body["source_app"] != "chathub" {
		t.Fatalf("source_app=%v", received.Body["source_app"])
	}
	if received.Body["title"] != "Chat run finished" {
		t.Fatalf("title=%v", received.Body["title"])
	}
}

func TestClientCachesToken(t *testing.T) {
	var tokenCalls int32
	warden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&tokenCalls, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "cached-jwt",
			"expires_at": time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer warden.Close()

	webhub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer webhub.Close()

	c, _ := NewClient(Config{
		Enabled:   true,
		WebHubURL: webhub.URL + "/v1/notifications",
		WardenURL: warden.URL,
		APIKey:    "test-key",
	})
	for i := 0; i < 3; i++ {
		if err := c.Notify(context.Background(), Event{Title: "t"}); err != nil {
			t.Fatalf("notify[%d]: %v", i, err)
		}
	}
	if atomic.LoadInt32(&tokenCalls) != 1 {
		t.Fatalf("token calls=%d want 1 (cached)", tokenCalls)
	}
}

func TestClientErrorOnWebHubFailure(t *testing.T) {
	warden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "tok",
			"expires_at": time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer warden.Close()

	webhub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer webhub.Close()

	c, _ := NewClient(Config{
		Enabled:   true,
		WebHubURL: webhub.URL + "/v1/notifications",
		WardenURL: warden.URL,
		APIKey:    "test-key",
	})
	err := c.Notify(context.Background(), Event{Title: "t"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err=%v want 403", err)
	}
}

func TestClientRejectsEmptyTitle(t *testing.T) {
	c, _ := NewClient(Config{Enabled: true, WebHubURL: "http://h", WardenURL: "http://w", APIKey: "k"})
	if err := c.Notify(context.Background(), Event{Title: "  "}); err == nil {
		t.Fatal("want error when title empty")
	}
}

package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConsulRegistrarRegister(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agent/service/register" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	registrar := NewConsulRegistrar(ConsulConfig{Addr: server.URL})
	err := registrar.Register(context.Background(), ServiceInstance{
		ID: "knowhub", InstanceID: "knowhub-1", Scheme: "http", Address: "127.0.0.1", Port: 17100,
		BaseURL: "http://127.0.0.1:17100", Prefix: "/knowhub", HealthPath: "/healthz", Audience: "knowhub",
	})
	if err != nil {
		t.Fatal(err)
	}
	if payload["Name"] != "knowhub" || payload["ID"] != "knowhub-1" {
		t.Fatalf("payload = %+v", payload)
	}
}

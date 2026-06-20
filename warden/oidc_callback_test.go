package warden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCompleteOIDCCallbackSyncsDirectoryAndConsumesState(t *testing.T) {
	ctx := context.Background()
	svc, _ := newOIDCTestService(t)
	if err := svc.PutOIDCLoginState(ctx, OIDCLoginState{
		State: "state-a", Nonce: "nonce-a", CodeVerifier: "verifier-a", RedirectURL: "/app", ExpiresAt: testNow().Add(time.Minute),
	}); err != nil {
		t.Fatalf("PutOIDCLoginState: %v", err)
	}

	session, identity, redirectURL, err := svc.CompleteOIDCCallback(ctx, "code-a", "state-a", testNow())
	if err != nil {
		t.Fatalf("CompleteOIDCCallback: %v", err)
	}
	if session.ID == "" || identity.Subject.ExternalID != "casdoor-user-a" || identity.CurrentTenant.ID != "tenant-a" || redirectURL != "/app" {
		t.Fatalf("session=%+v identity=%+v redirect=%q", session, identity, redirectURL)
	}
	if _, _, _, err := svc.CompleteOIDCCallback(ctx, "code-a", "state-a", testNow()); err == nil {
		t.Fatal("replayed state succeeded, want error")
	}
}

func TestStartOIDCLoginStoresPKCEState(t *testing.T) {
	ctx := context.Background()
	svc, store := newOIDCTestService(t)
	started, err := svc.StartOIDCLogin(ctx, StartOIDCLoginRequest{RedirectURL: "/app", Now: testNow()})
	if err != nil {
		t.Fatalf("StartOIDCLogin: %v", err)
	}
	if started.AuthorizationURL == "" || started.State == "" || started.Nonce == "" || started.CodeChallenge == "" || started.CodeChallengeMethod != "S256" {
		t.Fatalf("started = %+v", started)
	}
	state, err := store.TakeOIDCLoginState(ctx, started.State)
	if err != nil {
		t.Fatalf("TakeOIDCLoginState: %v", err)
	}
	if state.Nonce != started.Nonce || state.CodeVerifier == "" || state.RedirectURL != "/app" {
		t.Fatalf("state = %+v started=%+v", state, started)
	}
	if codeChallengeS256(state.CodeVerifier) != started.CodeChallenge {
		t.Fatalf("stored verifier does not match challenge")
	}
}

func TestHTTPHandlerOIDCStart(t *testing.T) {
	svc, _ := newOIDCTestService(t)
	handler := NewHTTPHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/start", strings.NewReader(`{"redirect_url":"/app"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var started StartedOIDCLogin
	if err := json.Unmarshal(rec.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	if started.AuthorizationURL == "" || started.CodeChallengeMethod != "S256" {
		t.Fatalf("started = %+v", started)
	}
}

func TestHTTPHandlerOIDCCallbackSetsSessionCookie(t *testing.T) {
	ctx := context.Background()
	svc, _ := newOIDCTestService(t)
	if err := svc.PutOIDCLoginState(ctx, OIDCLoginState{
		State: "state-a", Nonce: "nonce-a", CodeVerifier: "verifier-a", ExpiresAt: testNow().Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=code-a&state=state-a", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	var csrfCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == SessionCookieName {
			sessionCookie = cookie
		}
		if cookie.Name == CSRFCookieName {
			csrfCookie = cookie
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" || !sessionCookie.HttpOnly || !sessionCookie.Secure {
		t.Fatalf("session cookie = %+v", sessionCookie)
	}
	if csrfCookie == nil || csrfCookie.Value == "" || csrfCookie.HttpOnly || !csrfCookie.Secure {
		t.Fatalf("csrf cookie = %+v", csrfCookie)
	}
	var identity IdentityContext
	if err := json.Unmarshal(rec.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	if identity.Subject.PrincipalID == "" || identity.CurrentTenant.ID != "tenant-a" {
		t.Fatalf("identity = %+v", identity)
	}
}

func newOIDCTestService(t *testing.T) (*Service, *MemoryStore) {
	t.Helper()
	now := testNow()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []any{map[string]any{
		"kty": "RSA",
		"kid": "kid-a",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}),
	}}}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(jwksServer.Close)
	idToken := signOIDCTestToken(t, key, map[string]any{
		"iss":                "https://saker.example.com/auth",
		"sub":                "casdoor-user-a",
		"aud":                "saker-web",
		"exp":                now.Add(time.Minute).Unix(),
		"iat":                now.Add(-time.Minute).Unix(),
		"nonce":              "nonce-a",
		"email":              "alice@example.com",
		"name":               "Alice",
		"preferred_username": "alice",
	})
	store := NewMemoryStore()
	svc, err := NewService(Config{
		Issuer:       "warden",
		MasterSecret: testSecret,
		InternalTTL:  5 * time.Minute,
		OIDCVerifier: &OIDCVerifier{
			Issuer:   "https://saker.example.com/auth",
			ClientID: "saker-web",
			JWKSURL:  jwksServer.URL,
			Now:      func() time.Time { return now },
		},
		OIDCTokenExchanger: staticTokenExchanger{idToken: idToken},
		DirectorySource:    staticDirectorySource{},
	}, store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store
}

type staticTokenExchanger struct {
	idToken string
}

func (e staticTokenExchanger) ExchangeCode(_ context.Context, code, verifier string) (OIDCTokenSet, error) {
	if code != "code-a" || verifier != "verifier-a" {
		return OIDCTokenSet{}, ErrUnauthorized
	}
	return OIDCTokenSet{IDToken: e.idToken, TokenType: "Bearer"}, nil
}

type staticDirectorySource struct{}

var staticDirectoryReconcileCalls int

func (staticDirectorySource) SyncUser(_ context.Context, casdoorUserID string) ([]CasdoorDirectorySnapshot, error) {
	return []CasdoorDirectorySnapshot{{
		Tenant: Tenant{ID: "tenant-a", CasdoorOrgName: "acme", Slug: "acme", DisplayName: "Acme", Status: "active"},
		User:   CasdoorUser{ID: casdoorUserID, Username: "alice", Email: "alice@example.com", DisplayName: "Alice"},
		Groups: []CasdoorGroup{{ID: "group-a", Name: "research", DisplayName: "Research"}},
		Roles:  []string{"app.chathub.user"},
	}}, nil
}

func (staticDirectorySource) Reconcile(context.Context) error {
	staticDirectoryReconcileCalls++
	return nil
}

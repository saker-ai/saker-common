//go:build integration

package warden

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiscoveredOIDCBrowserLoginExchangesPKCEAndVerifiesToken(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer, nonce, challenge string
	var exchanges atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/app/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/app/keys",
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "authorization_response_iss_parameter_supported": true,
			})
		case "/token":
			exchanges.Add(1)
			clientID, secret, ok := r.BasicAuth()
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if !ok || clientID != "app" || secret != "fixture-secret" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "code" || codeChallengeS256(r.Form.Get("code_verifier")) != challenge || r.Form.Get("redirect_uri") != "https://portal.example/warden/auth/oidc/callback" {
				t.Error("token exchange lost client authentication, PKCE or callback binding")
				w.WriteHeader(400)
				return
			}
			access := "fixture-access"
			hash := sha256.Sum256([]byte(access))
			token := signOIDCTestToken(t, key, map[string]any{
				"iss": issuer, "sub": "casdoor-user-a", "aud": "app", "nonce": nonce,
				"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "at_hash": base64.RawURLEncoding.EncodeToString(hash[:16]),
			})
			_ = json.NewEncoder(w).Encode(map[string]any{"id_token": token, "access_token": access, "token_type": "Bearer", "expires_in": 60})
		case "/app/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
				"kty": "RSA", "kid": "kid-a", "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB",
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	client, err := NewOIDCClient(t.Context(), OIDCClientConfig{
		Issuer: issuer, DiscoveryURL: issuer + "/.well-known/app/openid-configuration", ClientID: "app", ClientSecret: "fixture-secret",
		RedirectURL: "https://portal.example/warden/auth/oidc/callback", ProviderHint: "provider-github",
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{MasterSecret: testSecret, OIDCVerifier: client.Verifier, OIDCTokenExchanger: client, DirectorySource: staticDirectorySource{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(svc)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/oidc/start?return_to=%2Fworkbench%2F", nil))
	if w.Code != 303 {
		t.Fatalf("start=%d %s", w.Code, w.Body.String())
	}
	authorize, _ := url.Parse(w.Header().Get("Location"))
	q := authorize.Query()
	nonce, challenge = q.Get("nonce"), q.Get("code_challenge")
	if q.Get("provider_hint") != "provider-github" {
		t.Fatal("provider hint missing")
	}
	cookie := w.Result().Cookies()[0]
	callbackPath := "/auth/oidc/callback?" + url.Values{"code": {"code"}, "state": {q.Get("state")}, "iss": {issuer}}.Encode()
	callback := func(withCookie bool, suffix string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, callbackPath+suffix, nil)
		if withCookie {
			r.AddCookie(cookie)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		return out
	}
	if out := callback(false, ""); out.Code != 401 {
		t.Fatalf("unbound callback=%d", out.Code)
	}
	if out := callback(true, "&iss=https%3A%2F%2Fevil.example"); out.Code != 401 {
		t.Fatalf("duplicate issuer=%d", out.Code)
	}
	withoutIssuer := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?"+url.Values{"code": {"code"}, "state": {q.Get("state")}}.Encode(), nil)
	withoutIssuer.AddCookie(cookie)
	missingIssuer := httptest.NewRecorder()
	handler.ServeHTTP(missingIssuer, withoutIssuer)
	if missingIssuer.Code != http.StatusUnauthorized {
		t.Fatalf("missing response issuer=%d", missingIssuer.Code)
	}
	out := callback(true, "")
	if out.Code != 303 || out.Header().Get("Location") != "/workbench/" {
		t.Fatalf("callback=%d %s", out.Code, out.Body.String())
	}
	var session *http.Cookie
	for _, c := range out.Result().Cookies() {
		if c.Name == SessionCookieName {
			session = c
		}
	}
	if session == nil || !session.Secure || !session.HttpOnly {
		t.Fatalf("session=%+v", session)
	}
	if _, principal, err := svc.ValidateSession(t.Context(), session.Value, time.Now()); err != nil || principal.TenantID != "tenant-a" {
		t.Fatalf("session principal=%+v error=%v", principal, err)
	}
	if out := callback(true, ""); out.Code != 401 {
		t.Fatalf("replay=%d", out.Code)
	}
	if exchanges.Load() != 1 {
		t.Fatalf("exchanges=%d", exchanges.Load())
	}
}

func TestOIDCDiscoveryRejectsInvalidTrustConfiguration(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"issuer-mismatch", func(m map[string]any) { m["issuer"] = "https://wrong.example" }},
		{"remote-http-token", func(m map[string]any) { m["token_endpoint"] = "http://unsafe.example/token" }},
		{"missing-keys", func(m map[string]any) { delete(m, "jwks_uri") }},
		{"unsupported-client-auth", func(m map[string]any) { m["token_endpoint_auth_methods_supported"] = []string{"none"} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var issuer string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				m := map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys"}
				tt.mutate(m)
				_ = json.NewEncoder(w).Encode(m)
			}))
			defer server.Close()
			issuer = server.URL
			if _, err := NewOIDCClient(t.Context(), OIDCClientConfig{Issuer: issuer, ClientID: "app", ClientSecret: "fixture", RedirectURL: "https://portal.example/callback"}); err == nil {
				t.Fatal("invalid discovery accepted")
			}
		})
	}
}

func TestOIDCTokenSetRejectsInvalidIdentityAndAccessBinding(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "kid-a", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
	}))
	defer server.Close()
	now := time.Now()
	v := OIDCVerifier{Issuer: "https://id.example", ClientID: "app", JWKSURL: server.URL, Now: func() time.Time { return now }}
	for _, tt := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"nonce", func(m map[string]any) { m["nonce"] = "other" }},
		{"audience", func(m map[string]any) { m["aud"] = "other" }},
		{"issuer", func(m map[string]any) { m["iss"] = "https://other.example" }},
		{"expired", func(m map[string]any) { m["exp"] = now.Add(-time.Second).Unix() }},
		{"future-nbf", func(m map[string]any) { m["nbf"] = now.Add(time.Minute).Unix() }},
		{"future-iat", func(m map[string]any) { m["iat"] = now.Add(time.Minute).Unix() }},
		{"multi-audience-no-azp", func(m map[string]any) { m["aud"] = []string{"app", "other"} }},
		{"wrong-azp", func(m map[string]any) { m["azp"] = "other" }},
		{"at-hash", func(m map[string]any) { m["at_hash"] = "wrong" }},
		{"missing-subject", func(m map[string]any) { delete(m, "sub") }},
		{"malformed-audience", func(m map[string]any) { m["aud"] = []any{"app", 4} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := map[string]any{"iss": v.Issuer, "sub": "user", "aud": "app", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "nonce": "nonce"}
			tt.mutate(m)
			if _, err := v.VerifyTokenSet(t.Context(), OIDCTokenSet{IDToken: signOIDCTestToken(t, key, m), AccessToken: "access"}, "nonce"); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
}

func TestOIDCExchangeDoesNotFollowRedirectsOrLeakProviderErrors(t *testing.T) {
	t.Parallel()
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true); w.WriteHeader(500) }))
	defer other.Close()
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprint("redirect-", redirect), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if redirect {
					http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"secret-provider-token"}`))
			}))
			defer server.Close()
			client, err := NewOIDCClient(t.Context(), OIDCClientConfig{Issuer: server.URL, ClientID: "app", ClientSecret: "fixture", RedirectURL: "https://portal.example/callback", AuthorizationURL: server.URL + "/authorize", TokenURL: server.URL + "/token", JWKSURL: server.URL + "/keys"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.ExchangeCode(t.Context(), "code", strings.Repeat("x", 43)); err != ErrUnauthorized {
				t.Fatalf("unsafe provider error: %v", err)
			}
		})
	}
	if leaked.Load() {
		t.Fatal("client followed credential-bearing redirect")
	}
}

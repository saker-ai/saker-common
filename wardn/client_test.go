package wardn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryAttempts struct {
	mu     sync.Mutex
	values map[string]Attempt
}

func (s *memoryAttempts) Save(_ context.Context, a Attempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[a.StateHash] = a
	return nil
}
func (s *memoryAttempts) Consume(_ context.Context, state, browser string) (Attempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.values[state]
	if !ok || a.BrowserHash != browser {
		return Attempt{}, ErrLogin
	}
	delete(s.values, state)
	return a, nil
}

func TestSignedLoginAndRejectedCallbacks(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "reauth", "signature", "nonce", "owner", "audience", "issuer", "azp", "future", "access-hash", "expired-attempt", "browser", "replay", "duplicate-token", "trailing-token"} {
		t.Run(mode, func(t *testing.T) {
			var issuer, nonce, challenge string
			var calls int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/discovery":
					_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize?organization=saker&prompt=login", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}, "authorization_response_iss_parameter_supported": true})
				case "/jwks":
					_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
				case "/token":
					calls++
					if r.ParseForm() != nil {
						t.Error("bad token form")
					}
					sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
					if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge || r.Form.Get("redirect_uri") != "http://localhost/callback" {
						t.Error("PKCE or callback mismatch")
					}
					claims := map[string]any{"iss": issuer, "aud": "client", "sub": "immutable-user", "owner": "saker", "nonce": nonce, "name": "95b34f50-f608-4b31-a1c6-99ff2552f2f2", "email": "alice@example.test", "emailVerified": true, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
					switch mode {
					case "nonce":
						claims["nonce"] = "wrong"
					case "owner":
						claims["owner"] = "built-in"
					case "audience":
						claims["aud"] = "other"
					case "issuer":
						claims["iss"] = "https://other.test"
					case "azp":
						claims["azp"] = "other"
					case "future":
						claims["nbf"] = time.Now().Add(time.Hour).Unix()
					case "access-hash":
						claims["at_hash"] = "wrong"
					}
					header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test"})
					body, _ := json.Marshal(claims)
					unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
					digest := sha256.Sum256([]byte(unsigned))
					sig, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
					if e != nil {
						t.Error(e)
					}
					if mode == "signature" {
						sig[0] ^= 1
					}
					bodyOut, _ := json.Marshal(map[string]string{"access_token": "access", "token_type": "Bearer", "id_token": unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)})
					if mode == "duplicate-token" {
						bodyOut = append(bodyOut[:len(bodyOut)-1], []byte(`,"id_token":"other"}`)...)
					}
					if mode == "trailing-token" {
						bodyOut = append(bodyOut, []byte(` {}`)...)
					}
					_, _ = w.Write(bodyOut)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			issuer = server.URL
			client, err := New(t.Context(), Config{Issuer: issuer, DiscoveryURL: issuer + "/discovery", ClientID: "client", ClientSecret: "secret", RedirectURL: "http://localhost/callback", AllowInsecureLoopback: true})
			if err != nil {
				t.Fatal(err)
			}
			store := &memoryAttempts{values: map[string]Attempt{}}
			browser := strings.Repeat("a", 43)
			target, err := client.Begin(t.Context(), store, browser, mode == "reauth")
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(target)
			q := u.Query()
			nonce, challenge = q.Get("nonce"), q.Get("code_challenge")
			if q.Get("organization") != "saker" || q.Get("code_challenge_method") != "S256" || q.Get("prompt") != map[bool]string{true: "login", false: ""}[mode == "reauth"] {
				t.Fatal("bad authorization URL")
			}
			if mode == "expired-attempt" {
				a := store.values[hash(q.Get("state"))]
				a.ExpiresAt = time.Now().Add(-time.Second)
				store.values[a.StateHash] = a
			}
			if mode == "browser" {
				browser = strings.Repeat("b", 43)
			}
			id, err := client.Complete(t.Context(), store, browser, q.Get("state"), "code", issuer)
			valid := mode == "valid" || mode == "reauth" || mode == "replay"
			if valid {
				if err != nil || id.Subject != "immutable-user" || id.Profile.AccountName() != "alice@example.test" {
					t.Fatal("valid signed identity rejected")
				}
			} else if !errors.Is(err, ErrLogin) {
				t.Fatal("invalid identity accepted")
			}
			before := calls
			if _, err := client.Complete(t.Context(), store, browser, q.Get("state"), "code", issuer); err == nil || calls != before {
				t.Fatal("replay reached token endpoint")
			}
		})
	}
}

func TestDiscoveryFailsClosed(t *testing.T) {
	for _, mode := range []string{"wrong-issuer", "foreign-endpoint", "weak-algorithm", "redirect", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			var issuer string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, r, "/other", 302)
					return
				}
				if mode == "oversized" {
					_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
					return
				}
				claims := map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}}
				switch mode {
				case "wrong-issuer":
					claims["issuer"] = "https://wrong.test"
				case "foreign-endpoint":
					claims["token_endpoint"] = "https://other.test/token"
				case "weak-algorithm":
					claims["id_token_signing_alg_values_supported"] = []string{"HS256", "none"}
				}
				_ = json.NewEncoder(w).Encode(claims)
			}))
			defer server.Close()
			issuer = server.URL
			if _, err := New(t.Context(), Config{Issuer: issuer, ClientID: "client", ClientSecret: "secret", RedirectURL: "http://localhost/callback", AllowInsecureLoopback: true}); !errors.Is(err, ErrLogin) {
				t.Fatal("unsafe discovery accepted")
			}
		})
	}
}

func TestNativeCallbacksAndRegionalTransportStayBound(t *testing.T) {
	cfg := Config{Issuer: "https://wardn.bxf.me/identity", ClientID: "native", ClientSecret: "secret", RedirectURL: "sakerwork://auth/callback", NativeRedirectScheme: "sakerwork", Region: "cn"}
	metadata := Metadata{Issuer: cfg.Issuer, AuthorizationURL: cfg.Issuer + "/authorize?organization=saker", TokenURL: cfg.Issuer + "/token", JWKSURL: cfg.Issuer + "/jwks", Algorithms: []string{"RS256"}}
	client, err := NewWithMetadata(t.Context(), cfg, metadata)
	if err != nil {
		t.Fatal(err)
	}
	target, err := client.AuthorizationURL(AuthorizationRequest{State: "persisted-state", Nonce: "persisted-nonce", Verifier: strings.Repeat("a", 43)})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(target)
	if u.Path != "/cn/identity/authorize" || u.Query().Get("redirect_uri") != cfg.RedirectURL || u.Query().Get("organization") != "saker" {
		t.Fatal("native redirect or regional endpoint lost")
	}
	if _, err = client.AuthorizationURL(AuthorizationRequest{State: "state", Nonce: "nonce", Verifier: strings.Repeat("a", 43), RedirectURL: "sakerwork://evil/callback"}); err == nil {
		t.Fatal("native callback was not pinned")
	}
	cfg.NativeRedirectScheme = ""
	if _, err = NewWithMetadata(t.Context(), cfg, metadata); err == nil {
		t.Fatal("custom callback accepted without explicit scheme")
	}
	if RegionalURL(cfg.Issuer, "cn") != cfg.Issuer || RegionalURL("https://wardn.bxf.me.evil/identity/token", "cn") != "https://wardn.bxf.me.evil/identity/token" {
		t.Fatal("canonical issuer or foreign host rewritten")
	}
}

package warden

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOIDCRejectsExternalReturnTargets(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"https://evil.example", "//evil.example", "/%2f/evil.example", "/%5cevil.example", "/app%0d%0aLocation:evil"} {
		t.Run(target, func(t *testing.T) {
			svc, err := NewService(Config{MasterSecret: testSecret, OIDCVerifier: &OIDCVerifier{Issuer: "https://id.example", ClientID: "app"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.StartOIDCLogin(t.Context(), StartOIDCLoginRequest{RedirectURL: target}); err == nil {
				t.Fatal("external or ambiguous return target accepted")
			}
		})
	}
}

func TestOIDCStartSetsPerAttemptBrowserBinding(t *testing.T) {
	t.Parallel()
	svc, err := NewService(Config{MasterSecret: testSecret, OIDCVerifier: &OIDCVerifier{
		Issuer: "https://id.example", ClientID: "app", RedirectURL: "https://portal.example/warden/auth/oidc/callback",
		AuthorizationURL: "https://id.example/oauth/authorize", ProviderHint: "github-fixture",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(svc)
	names := map[string]bool{}
	for range 2 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/oidc/start?return_to=%2Fworkbench%2F", nil))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("status=%d, body=%s", w.Code, w.Body.String())
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("cookies=%d", len(cookies))
		}
		cookie := cookies[0]
		if !cookie.Secure || !cookie.HttpOnly || !strings.HasPrefix(cookie.Name, "__Host-") || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatalf("unsafe attempt cookie: %+v", cookie)
		}
		if names[cookie.Name] {
			t.Fatal("parallel attempts reused a cookie")
		}
		names[cookie.Name] = true
		authorize, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		q := authorize.Query()
		if q.Get("provider_hint") != "github-fixture" || q.Get("redirect_uri") != svc.oidcVerifier.RedirectURL || q.Get("code_challenge_method") != "S256" {
			t.Fatalf("authorization query=%v", q)
		}
		state, err := svc.store.TakeOIDCLoginState(t.Context(), q.Get("state"))
		if err != nil {
			t.Fatal(err)
		}
		if state.BrowserBinding == cookie.Value || state.BrowserBinding != oidcBindingHash(cookie.Value) {
			t.Fatal("browser secret not hashed in storage")
		}
	}
}

func TestBoundCallbackRejectsUnboundOrWrongBrowser(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct{ name, stored, supplied string }{
		{"legacy-unbound", "", "browser"},
		{"missing-browser", oidcBindingHash("browser"), ""},
		{"other-browser", oidcBindingHash("browser"), "other"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := NewService(Config{MasterSecret: testSecret, OIDCVerifier: &OIDCVerifier{}, OIDCTokenExchanger: neverExchange{}, DirectorySource: staticDirectorySource{}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.PutOIDCLoginState(t.Context(), OIDCLoginState{State: "state", Nonce: "nonce", CodeVerifier: "verifier", BrowserBinding: tt.stored, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := svc.CompleteBoundOIDCCallback(t.Context(), "code", "state", tt.supplied, time.Now()); err != ErrUnauthorized {
				t.Fatalf("err=%v", err)
			}
			if _, err := svc.store.TakeOIDCLoginState(t.Context(), "state"); err != nil {
				t.Fatal("wrong browser consumed the legitimate login state")
			}
		})
	}
}

type neverExchange struct{}

func (neverExchange) ExchangeCode(context.Context, string, string) (OIDCTokenSet, error) {
	panic("invalid browser binding reached token endpoint")
}

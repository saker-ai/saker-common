package warden

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOIDCVerifierVerifyIDToken(t *testing.T) {
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
	defer jwksServer.Close()

	token := signOIDCTestToken(t, key, map[string]any{
		"iss":   "https://saker.example.com/auth",
		"sub":   "casdoor-user-a",
		"aud":   []string{"saker-web"},
		"exp":   now.Add(time.Minute).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"nonce": "nonce-a",
		"email": "alice@example.com",
	})
	verifier := OIDCVerifier{
		Issuer:   "https://saker.example.com/auth",
		ClientID: "saker-web",
		JWKSURL:  jwksServer.URL,
		Now:      func() time.Time { return now },
	}
	claims, err := verifier.VerifyIDToken(context.Background(), token, "nonce-a")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if claims.Subject != "casdoor-user-a" || claims.Email != "alice@example.com" {
		t.Fatalf("claims = %+v", claims)
	}

	if _, err := verifier.VerifyIDToken(context.Background(), token, "wrong"); err != ErrOIDCInvalidToken {
		t.Fatalf("wrong nonce err = %v, want ErrOIDCInvalidToken", err)
	}
}

func signOIDCTestToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "kid-a"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + strings.TrimRight(base64.RawURLEncoding.EncodeToString(sig), "=")
}

package internaljwt

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestSignAndVerify(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	signer, err := NewSigner("synapse", testSecret, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	token, claims, err := signer.Sign(SignInput{
		Audience:      "skillhub",
		TenantID:      "tenant-a",
		OrgID:         "org-a",
		PrincipalType: "user",
		PrincipalID:   "user-a",
		Roles:         []string{"admin"},
		Scopes:        []string{"skillhub:read"},
		Resource:      &ResourceRef{Type: "namespace", ID: "ns-a"},
		SessionID:     "sess-a",
		Source:        "api_key",
		Now:           now,
		JWTID:         "jwt-a",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if claims.Subject != "user-a" {
		t.Fatalf("subject = %q", claims.Subject)
	}
	verifier, err := NewVerifier(VerifierOptions{
		Issuer:       "synapse",
		Audience:     "skillhub",
		MasterSecret: testSecret,
		TTL:          5 * time.Minute,
		Now:          func() time.Time { return now.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	principal, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if principal.TenantID != "tenant-a" || principal.ResourceID != "ns-a" || !HasScope(principal.Scopes, "skillhub:read") {
		t.Fatalf("principal = %#v", principal)
	}
}

func TestVerifierRejectsWrongAudience(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	signer, _ := NewSigner("synapse", testSecret, 5*time.Minute)
	token, _, err := signer.Sign(SignInput{
		Audience:      "skillhub",
		TenantID:      "tenant-a",
		PrincipalType: "user",
		PrincipalID:   "user-a",
		Scopes:        []string{"skillhub:read"},
		Now:           now,
		JWTID:         "jwt-a",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifier, _ := NewVerifier(VerifierOptions{
		Issuer:       "synapse",
		Audience:     "assethub",
		MasterSecret: testSecret,
		Now:          func() time.Time { return now },
	})
	if _, err := verifier.Verify(token); !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("Verify err = %v, want ErrInvalidClaims", err)
	}
}

func TestVerifierAcceptsPreviousPeriodOnlyInBoundaryWindow(t *testing.T) {
	issued := time.Date(2026, 6, 30, 23, 59, 30, 0, time.UTC)
	signer, _ := NewSigner("synapse", testSecret, 5*time.Minute)
	token, _, err := signer.Sign(SignInput{
		Audience:      "skillhub",
		TenantID:      "tenant-a",
		PrincipalType: "user",
		PrincipalID:   "user-a",
		Scopes:        []string{"skillhub:read"},
		Now:           issued,
		JWTID:         "jwt-a",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	withinBoundary, _ := NewVerifier(VerifierOptions{
		Issuer:       "synapse",
		Audience:     "skillhub",
		MasterSecret: testSecret,
		TTL:          5 * time.Minute,
		ClockSkew:    30 * time.Second,
		Now:          func() time.Time { return time.Date(2026, 7, 1, 0, 1, 0, 0, time.UTC) },
	})
	if _, err := withinBoundary.Verify(token); err != nil {
		t.Fatalf("Verify within boundary: %v", err)
	}
	outsideBoundary, _ := NewVerifier(VerifierOptions{
		Issuer:       "synapse",
		Audience:     "skillhub",
		MasterSecret: testSecret,
		TTL:          5 * time.Minute,
		ClockSkew:    30 * time.Second,
		Now:          func() time.Time { return time.Date(2026, 7, 1, 0, 10, 0, 0, time.UTC) },
	})
	if _, err := outsideBoundary.Verify(token); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify outside boundary err = %v, want ErrInvalidSignature", err)
	}
}

func TestTokenFromRequestRequiresInternalHeaderByDefault(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(HeaderAuthorization, "Bearer authz")
	if _, err := TokenFromRequest(req, false); !errors.Is(err, ErrMissingToken) {
		t.Fatalf("TokenFromRequest err = %v, want ErrMissingToken", err)
	}
	token, err := TokenFromRequest(req, true)
	if err != nil {
		t.Fatalf("TokenFromRequest fallback: %v", err)
	}
	if token != "authz" {
		t.Fatalf("token = %q", token)
	}
	req.Header.Set(HeaderInternalAuthorization, "Bearer internal")
	token, err = TokenFromRequest(req, true)
	if err != nil {
		t.Fatalf("TokenFromRequest internal: %v", err)
	}
	if token != "internal" {
		t.Fatalf("token = %q", token)
	}
}

func TestDefaultScopesForAudience(t *testing.T) {
	tests := []struct {
		name     string
		audience string
		want     string
	}{
		{name: "skillhub", audience: AudienceSkillHub, want: ScopeSkillHubWrite},
		{name: "assethub", audience: AudienceAssetHub, want: ScopeAssetHubUpload},
		{name: "chathub", audience: AudienceChatHub, want: ScopeChatHubWrite},
		{name: "filestore", audience: AudienceFileStore, want: ScopeFileStoreWrite},
		{name: "saker", audience: AudienceSaker, want: ScopeSakerToolExecute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scopes := DefaultScopesForAudience(tt.audience)
			if !HasScope(scopes, tt.want) {
				t.Fatalf("DefaultScopesForAudience(%q) = %v, missing %q", tt.audience, scopes, tt.want)
			}
		})
	}
	if scopes := DefaultScopesForAudience("unknown"); scopes != nil {
		t.Fatalf("unknown scopes = %v, want nil", scopes)
	}
}

func TestHasAnyScope(t *testing.T) {
	if !HasAnyScope([]string{ScopeAssetHubRead}, ScopeAssetHubWrite, ScopeAssetHubRead) {
		t.Fatal("HasAnyScope returned false for matching scope")
	}
	if HasAnyScope([]string{ScopeAssetHubRead}, ScopeSkillHubRead, ScopeAssetHubWrite) {
		t.Fatal("HasAnyScope returned true without matching scope")
	}
}

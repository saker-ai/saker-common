package wardn_test

import (
	"testing"

	"github.com/saker-ai/saker-common/wardn"
)

func TestAccountNamesAndEmailVerification(t *testing.T) {
	yes, no := true, false
	const opaque = "95b34f50-f608-4b31-a1c6-99ff2552f2f2"
	for _, tc := range []struct {
		name            string
		claims          wardn.Claims
		private, public string
	}{
		{"native nickname", wardn.Claims{Name: opaque, DisplayName: "小明"}, "小明", "小明"},
		{"native email", wardn.Claims{Name: opaque, Email: "alice@example.test", NativeVerified: &yes}, "alice@example.test", ""},
		{"standard email", wardn.Claims{Name: opaque, Email: "alice@example.test", EmailVerified: &yes}, "alice@example.test", ""},
		{"unverified", wardn.Claims{Name: opaque, Email: "alice@example.test", EmailVerified: &no}, "", ""},
		{"missing verification", wardn.Claims{Name: opaque, Email: "alice@example.test"}, "", ""},
		{"conflicting verification", wardn.Claims{Email: "alice@example.test", EmailVerified: &yes, NativeVerified: &no}, "", ""},
		{"internal subject", wardn.Claims{Name: "generated-id", Subject: "generated-id", Email: "alice@example.test", EmailVerified: &yes}, "alice@example.test", ""},
		{"standard nickname", wardn.Claims{Name: " Alice ", PreferredUsername: opaque}, "Alice", "Alice"},
		{"username fallback", wardn.Claims{PreferredUsername: "alice"}, "alice", "alice"},
		{"unverified email-shaped name", wardn.Claims{Name: "other@example.test"}, "", ""},
		{"decorated email", wardn.Claims{Email: "Alice <alice@example.test>", EmailVerified: &yes}, "", ""},
		{"control character", wardn.Claims{DisplayName: "Bad\x00Name", Name: "Alice"}, "Alice", "Alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.claims.AccountName(); got != tc.private {
				t.Fatalf("private=%q want %q", got, tc.private)
			}
			if got := tc.claims.PublicName(); got != tc.public {
				t.Fatalf("public=%q want %q", got, tc.public)
			}
		})
	}
}

func TestIdentityKeyNeverUsesMutableProfile(t *testing.T) {
	a := wardn.Identity{Issuer: "https://wardn.test/identity", Subject: "original", Profile: wardn.Claims{Name: "Alice"}}
	b := a
	b.Profile = wardn.Claims{Name: "Bob", Email: "changed@example.test"}
	if a.Key() != b.Key() {
		t.Fatal("profile changed identity key")
	}
	b.Subject = "other"
	if a.Key() == b.Key() {
		t.Fatal("different subjects share identity")
	}
	b = a
	b.Issuer = "https://other.test/identity"
	if a.Key() == b.Key() {
		t.Fatal("different issuers share identity")
	}
}

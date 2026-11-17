package warden

import (
	"slices"
	"testing"

	"github.com/saker-ai/saker-common/internaljwt"
)

func TestSakerWebPermissionsSeparateReadRunAndTerminal(t *testing.T) {
	t.Parallel()
	policy := DefaultPolicy()
	for _, tt := range []struct {
		name, role, action, scope string
		allowed                   bool
	}{
		{"viewer-reads", RoleSakerWebViewer, "read", internaljwt.ScopeSakerWebRead, true},
		{"viewer-cannot-run", RoleSakerWebViewer, "run", internaljwt.ScopeSakerWebRun, false},
		{"user-runs", RoleSakerWebUser, "run", internaljwt.ScopeSakerWebRun, true},
		{"user-writes", RoleSakerWebUser, "write", internaljwt.ScopeSakerWebWrite, true},
		{"user-cannot-terminal", RoleSakerWebUser, "terminal", internaljwt.ScopeSakerWebTerminal, false},
		{"operator-terminal", RoleSakerWebOperator, "terminal", internaljwt.ScopeSakerWebTerminal, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scopes := policy.ScopesForActions([]RoleGrant{{Key: tt.role}}, internaljwt.AudienceSakerWeb, []string{tt.action})
			if slices.Contains(scopes, tt.scope) != tt.allowed {
				t.Fatalf("scopes=%v, allowed=%t", scopes, tt.allowed)
			}
		})
	}
	if _, ok := NormalizeRoleKey(RoleSakerWebUser); !ok {
		t.Fatal("SakerWeb role cannot be projected from a directory mapping")
	}
}

package warden

import (
	"testing"

	"github.com/saker-ai/saker-common/internaljwt"
)

func TestNewPolicyFromRoleScopes(t *testing.T) {
	policy, err := NewPolicy(map[string][]string{
		RoleTenantViewer: {" skillhub:read ", internaljwt.ScopeChatHubRead, internaljwt.ScopeChatHubRead, ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	scopes := policy.ScopesForRoles([]RoleGrant{{Key: RoleTenantViewer}})
	if len(scopes) != 2 || scopes[0] != internaljwt.ScopeChatHubRead || scopes[1] != internaljwt.ScopeSkillHubRead {
		t.Fatalf("scopes = %v", scopes)
	}

	if _, err := NewPolicy(map[string][]string{"legacy.admin": {internaljwt.ScopeSynapseRead}}); err == nil {
		t.Fatal("NewPolicy accepted unknown role")
	}
}

func TestDefaultRoleScopesReturnsCopy(t *testing.T) {
	first := DefaultRoleScopes()
	first[RoleTenantViewer] = nil
	second := DefaultRoleScopes()
	if len(second[RoleTenantViewer]) == 0 {
		t.Fatal("DefaultRoleScopes returned shared mutable state")
	}
}

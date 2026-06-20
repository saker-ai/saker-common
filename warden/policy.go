package warden

import (
	"sort"
	"strings"

	"github.com/saker-ai/saker-common/internaljwt"
)

const (
	RolePlatformOwner     = "platform.owner"
	RolePlatformAdmin     = "platform.admin"
	RoleTenantOwner       = "tenant.owner"
	RoleTenantAdmin       = "tenant.admin"
	RoleTenantOperator    = "tenant.operator"
	RoleTenantViewer      = "tenant.viewer"
	RoleTeamAdmin         = "team.admin"
	RoleTeamEditor        = "team.editor"
	RoleTeamViewer        = "team.viewer"
	RoleSakerRunner       = "app.saker.runner"
	RoleChatHubUser       = "app.chathub.user"
	RoleAssetHubEditor    = "app.assethub.editor"
	RoleSkillHubPublisher = "app.skillhub.publisher"
	RoleFrontendUser      = "frontend.user"
)

var knownRoleKeys = map[string]bool{
	RolePlatformOwner: true, RolePlatformAdmin: true,
	RoleTenantOwner: true, RoleTenantAdmin: true, RoleTenantOperator: true, RoleTenantViewer: true,
	RoleTeamAdmin: true, RoleTeamEditor: true, RoleTeamViewer: true,
	RoleSakerRunner: true, RoleChatHubUser: true, RoleAssetHubEditor: true, RoleSkillHubPublisher: true,
	RoleFrontendUser: true,
}

var shorthandRoles = map[string]string{
	"owner": RoleTenantOwner, "admin": RoleTenantAdmin, "operator": RoleTenantOperator, "viewer": RoleTenantViewer,
}

type Policy struct {
	roleScopes map[string][]string
}

func DefaultPolicy() Policy {
	return Policy{roleScopes: map[string][]string{
		RolePlatformOwner: allScopes(),
		RolePlatformAdmin: allScopes(),
		RoleTenantOwner:   allScopes(),
		RoleTenantAdmin:   allScopes(),
		RoleTenantOperator: {
			internaljwt.ScopeSynapseRead, internaljwt.ScopeSynapseWrite,
			internaljwt.ScopeChatHubRead, internaljwt.ScopeChatHubWrite,
			internaljwt.ScopeAssetHubRead, internaljwt.ScopeAssetHubUpload, internaljwt.ScopeAssetHubWrite,
			internaljwt.ScopeSkillHubRead, internaljwt.ScopeSkillHubWrite,
			internaljwt.ScopeFileStoreRead, internaljwt.ScopeFileStoreWrite,
			internaljwt.ScopeSakerRun, internaljwt.ScopeSakerToolExecute,
		},
		RoleTenantViewer: {
			internaljwt.ScopeSynapseRead,
			internaljwt.ScopeChatHubRead,
			internaljwt.ScopeAssetHubRead,
			internaljwt.ScopeSkillHubRead,
			internaljwt.ScopeFileStoreRead,
		},
		RoleTeamAdmin:         {internaljwt.ScopeChatHubRead, internaljwt.ScopeChatHubWrite, internaljwt.ScopeAssetHubRead, internaljwt.ScopeAssetHubUpload, internaljwt.ScopeAssetHubWrite},
		RoleTeamEditor:        {internaljwt.ScopeChatHubRead, internaljwt.ScopeChatHubWrite, internaljwt.ScopeAssetHubRead, internaljwt.ScopeAssetHubUpload},
		RoleTeamViewer:        {internaljwt.ScopeChatHubRead, internaljwt.ScopeAssetHubRead},
		RoleSakerRunner:       {internaljwt.ScopeSakerRun, internaljwt.ScopeSakerToolExecute},
		RoleChatHubUser:       {internaljwt.ScopeChatHubRead, internaljwt.ScopeChatHubWrite},
		RoleAssetHubEditor:    {internaljwt.ScopeAssetHubRead, internaljwt.ScopeAssetHubUpload, internaljwt.ScopeAssetHubWrite},
		RoleSkillHubPublisher: {internaljwt.ScopeSkillHubRead, internaljwt.ScopeSkillHubPublish, internaljwt.ScopeSkillHubWrite},
		RoleFrontendUser:      {internaljwt.ScopeSynapseRead},
	}}
}

func NormalizeRoleKey(role string) (string, bool) {
	role = strings.TrimSpace(role)
	if role == "" {
		return "", false
	}
	if strings.Contains(role, ".") {
		return role, knownRoleKeys[role]
	}
	if mapped, ok := shorthandRoles[role]; ok {
		return mapped, true
	}
	return "", false
}

func (p Policy) ScopesForRoles(roles []RoleGrant) []string {
	set := map[string]bool{}
	for _, role := range roles {
		key, ok := NormalizeRoleKey(role.Key)
		if !ok {
			continue
		}
		for _, scope := range p.roleScopes[key] {
			set[scope] = true
		}
	}
	return sortedKeys(set)
}

func (p Policy) ScopesForActions(roles []RoleGrant, audience string, actions []string) []string {
	allowed := sliceSet(p.ScopesForRoles(roles))
	requested := map[string]bool{}
	for _, action := range actions {
		for _, scope := range scopesForAction(audience, action) {
			requested[scope] = true
		}
	}
	if len(requested) == 0 {
		for _, scope := range internaljwt.DefaultScopesForAudience(audience) {
			requested[scope] = true
		}
	}
	out := map[string]bool{}
	for scope := range requested {
		if allowed[scope] {
			out[scope] = true
		}
	}
	return sortedKeys(out)
}

func AppsForScopes(scopes []string) []AppContext {
	set := sliceSet(scopes)
	apps := []AppContext{
		{ID: internaljwt.AudienceChatHub, Enabled: set[internaljwt.ScopeChatHubRead] || set[internaljwt.ScopeChatHubWrite] || set[internaljwt.ScopeChatHubAdmin]},
		{ID: internaljwt.AudienceAssetHub, Enabled: set[internaljwt.ScopeAssetHubRead] || set[internaljwt.ScopeAssetHubUpload] || set[internaljwt.ScopeAssetHubWrite] || set[internaljwt.ScopeAssetHubAdmin]},
		{ID: internaljwt.AudienceSkillHub, Enabled: set[internaljwt.ScopeSkillHubRead] || set[internaljwt.ScopeSkillHubWrite] || set[internaljwt.ScopeSkillHubAdmin]},
	}
	return apps
}

func ConsoleAccess(roles []RoleGrant) bool {
	for _, role := range roles {
		key, ok := NormalizeRoleKey(role.Key)
		if ok && key != RoleFrontendUser {
			return true
		}
	}
	return false
}

func scopesForAction(audience, action string) []string {
	action = strings.TrimSpace(strings.ToLower(action))
	switch audience {
	case internaljwt.AudienceChatHub:
		switch action {
		case "read", "list":
			return []string{internaljwt.ScopeChatHubRead}
		case "write", "run", "delete", "archive":
			return []string{internaljwt.ScopeChatHubWrite}
		case "admin":
			return []string{internaljwt.ScopeChatHubAdmin}
		}
	case internaljwt.AudienceAssetHub:
		switch action {
		case "read", "list":
			return []string{internaljwt.ScopeAssetHubRead}
		case "upload", "create":
			return []string{internaljwt.ScopeAssetHubUpload}
		case "write", "update", "delete":
			return []string{internaljwt.ScopeAssetHubWrite}
		case "admin":
			return []string{internaljwt.ScopeAssetHubAdmin}
		}
	case internaljwt.AudienceSkillHub:
		switch action {
		case "read", "list":
			return []string{internaljwt.ScopeSkillHubRead}
		case "write", "update":
			return []string{internaljwt.ScopeSkillHubWrite}
		case "publish":
			return []string{internaljwt.ScopeSkillHubPublish}
		case "admin":
			return []string{internaljwt.ScopeSkillHubAdmin}
		}
	case internaljwt.AudienceSaker:
		switch action {
		case "run":
			return []string{internaljwt.ScopeSakerRun}
		case "tool:execute", "execute":
			return []string{internaljwt.ScopeSakerToolExecute}
		case "tool:approve", "approve":
			return []string{internaljwt.ScopeSakerToolApprove}
		}
	case internaljwt.AudienceFileStore:
		switch action {
		case "read", "list":
			return []string{internaljwt.ScopeFileStoreRead}
		case "write", "upload", "delete":
			return []string{internaljwt.ScopeFileStoreWrite}
		case "admin":
			return []string{internaljwt.ScopeFileStoreAdmin}
		}
	case internaljwt.AudienceSynapse:
		switch action {
		case "read", "list":
			return []string{internaljwt.ScopeSynapseRead}
		case "write", "update":
			return []string{internaljwt.ScopeSynapseWrite}
		case "admin":
			return []string{internaljwt.ScopeSynapseAdmin}
		}
	case internaljwt.AudienceWebHub:
		switch action {
		case "notifications:write", "notify", "write":
			return []string{internaljwt.ScopeWebHubNotificationsWrite}
		}
	}
	return nil
}

func allScopes() []string {
	return []string{
		internaljwt.ScopeSynapseRead, internaljwt.ScopeSynapseWrite, internaljwt.ScopeSynapseAdmin,
		internaljwt.ScopeSakerRun, internaljwt.ScopeSakerToolExecute, internaljwt.ScopeSakerToolApprove,
		internaljwt.ScopeChatHubRead, internaljwt.ScopeChatHubWrite, internaljwt.ScopeChatHubAdmin,
		internaljwt.ScopeAssetHubRead, internaljwt.ScopeAssetHubUpload, internaljwt.ScopeAssetHubWrite, internaljwt.ScopeAssetHubAdmin,
		internaljwt.ScopeSkillHubRead, internaljwt.ScopeSkillHubWrite, internaljwt.ScopeSkillHubPublish, internaljwt.ScopeSkillHubAdmin,
		internaljwt.ScopeFileStoreRead, internaljwt.ScopeFileStoreWrite, internaljwt.ScopeFileStoreAdmin,
		internaljwt.ScopeWebHubNotificationsWrite,
	}
}

func intersectScopes(left, right []string) []string {
	lset := sliceSet(left)
	out := map[string]bool{}
	for _, scope := range right {
		if lset[scope] {
			out[scope] = true
		}
	}
	return sortedKeys(out)
}

func sliceSet(values []string) map[string]bool {
	set := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = true
		}
	}
	return set
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

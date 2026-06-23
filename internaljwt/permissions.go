package internaljwt

const (
	AudienceSkillHub  = "skillhub"
	AudienceAssetHub  = "assethub"
	AudienceChatHub   = "chathub"
	AudienceFileStore = "filestore"
	AudienceSaker     = "saker"
	AudienceSynapse   = "synapse"
	AudienceWebHub    = "webhub"
	AudienceAIHub     = "aihub"
	AudienceStockHub  = "stockhub"
	AudienceKnowHub   = "knowhub"
	AudienceWarden    = "warden"

	PrincipalTypeUser           = "user"
	PrincipalTypeAPIKey         = "api_key"
	PrincipalTypeToken          = "token"
	PrincipalTypeServiceAccount = "service_account"
	PrincipalTypeAgent          = "agent"
	PrincipalTypeSystem         = "system"

	RoleAdmin     = "admin"
	RoleModerator = "moderator"
	RoleUser      = "user"

	ScopeSkillHubRead    = "skillhub:read"
	ScopeSkillHubWrite   = "skillhub:write"
	ScopeSkillHubPublish = "skillhub:publish"
	ScopeSkillHubAdmin   = "skillhub:admin"

	ScopeAssetHubRead   = "assethub:read"
	ScopeAssetHubUpload = "assethub:upload"
	ScopeAssetHubWrite  = "assethub:write"
	ScopeAssetHubAdmin  = "assethub:admin"

	ScopeChatHubRead  = "chathub:read"
	ScopeChatHubWrite = "chathub:write"
	ScopeChatHubAdmin = "chathub:admin"

	ScopeFileStoreRead  = "filestore:read"
	ScopeFileStoreWrite = "filestore:write"
	ScopeFileStoreAdmin = "filestore:admin"

	ScopeSakerRun         = "saker:run"
	ScopeSakerToolExecute = "saker:tool:execute"
	ScopeSakerToolApprove = "saker:tool:approve"

	ScopeSynapseRead  = "synapse:read"
	ScopeSynapseWrite = "synapse:write"
	ScopeSynapseAdmin = "synapse:admin"

	ScopeWebHubNotificationsWrite = "webhub:notifications:write"

	ScopeAIHubRead   = "aihub:read"
	ScopeAIHubInvoke = "aihub:invoke"
	ScopeAIHubAdmin  = "aihub:admin"

	ScopeStockHubRead     = "stockhub:read"
	ScopeStockHubRetrieve = "stockhub:retrieve"
	ScopeStockHubUpload   = "stockhub:upload"
	ScopeStockHubWrite    = "stockhub:write"
	ScopeStockHubReview   = "stockhub:review"
	ScopeStockHubAdmin    = "stockhub:admin"

	ScopeKnowHubRead     = "knowhub:read"
	ScopeKnowHubRetrieve = "knowhub:retrieve"
	ScopeKnowHubWrite    = "knowhub:write"
	ScopeKnowHubAdmin    = "knowhub:admin"

	ScopeWardenRead  = "warden:read"
	ScopeWardenWrite = "warden:write"
	ScopeWardenAdmin = "warden:admin"
)

func DefaultScopesForAudience(audience string) []string {
	switch audience {
	case AudienceSkillHub:
		return []string{ScopeSkillHubRead, ScopeSkillHubWrite}
	case AudienceAssetHub:
		return []string{ScopeAssetHubRead, ScopeAssetHubUpload, ScopeAssetHubWrite}
	case AudienceChatHub:
		return []string{ScopeChatHubRead, ScopeChatHubWrite}
	case AudienceFileStore:
		return []string{ScopeFileStoreRead, ScopeFileStoreWrite}
	case AudienceSaker:
		return []string{ScopeSakerRun, ScopeSakerToolExecute}
	case AudienceWebHub:
		return []string{ScopeWebHubNotificationsWrite}
	case AudienceAIHub:
		return []string{ScopeAIHubRead, ScopeAIHubInvoke}
	case AudienceStockHub:
		return []string{ScopeStockHubRead, ScopeStockHubRetrieve}
	case AudienceKnowHub:
		return []string{ScopeKnowHubRead, ScopeKnowHubRetrieve}
	case AudienceWarden:
		return []string{ScopeWardenRead}
	default:
		return nil
	}
}

func HasAnyScope(scopes []string, required ...string) bool {
	for _, scope := range required {
		if HasScope(scopes, scope) {
			return true
		}
	}
	return false
}

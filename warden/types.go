package warden

import (
	"context"
	"errors"
	"time"

	"github.com/saker-ai/saker-common/internaljwt"
)

var (
	ErrNotFound             = errors.New("warden: not found")
	ErrDisabled             = errors.New("warden: principal disabled")
	ErrUnauthorized         = errors.New("warden: unauthorized")
	ErrForbidden            = errors.New("warden: forbidden")
	ErrInvalidInput         = errors.New("warden: invalid input")
	ErrInsufficientRole     = errors.New("warden: insufficient role")
	ErrAuthorizationPending = errors.New("warden: authorization pending")
)

const (
	PrincipalTypeUser           = internaljwt.PrincipalTypeUser
	PrincipalTypeServiceAccount = internaljwt.PrincipalTypeServiceAccount
	PrincipalTypeAPIKey         = internaljwt.PrincipalTypeAPIKey
	PrincipalTypeAgent          = internaljwt.PrincipalTypeAgent
	PrincipalTypeSystem         = internaljwt.PrincipalTypeSystem

	SessionSourceWeb          = "web_session"
	SessionSourceAPIKey       = "api_key"
	SessionSourceServiceToken = "service_token"
	SessionSourceAgent        = "agent_delegation"
)

type Tenant struct {
	ID             string
	CasdoorOrgName string
	Slug           string
	DisplayName    string
	Status         string
}

type Team struct {
	ID             string
	TenantID       string
	CasdoorGroupID string
	Name           string
	DisplayName    string
	ParentTeamID   string
	Status         string
}

type Principal struct {
	ID            string
	TenantID      string
	CasdoorUserID string
	Username      string
	Email         string
	DisplayName   string
	Type          string
	Status        string
	Roles         []RoleGrant
	Teams         []Team
}

type RoleGrant struct {
	Key       string
	ScopeType string
	ScopeID   string
}

type Session struct {
	ID            string
	PrincipalID   string
	TenantID      string
	CurrentTeamID string
	AuthTime      time.Time
	ExpiresAt     time.Time
	Source        string
}

type APIKey struct {
	ID            string
	Name          string
	TenantID      string
	PrincipalType string
	PrincipalID   string
	KeyHash       string
	Scopes        []string
	ExpiresAt     time.Time
	Status        string
	CreatedAt     time.Time
	LastUsedAt    time.Time
}

type ServiceAccount struct {
	ID        string
	TenantID  string
	Name      string
	Status    string
	CreatedBy string
	CreatedAt time.Time
}

type AgentRun struct {
	ID               string
	TenantID         string
	ActorPrincipalID string
	AgentPrincipalID string
	Status           string
	CreatedAt        time.Time
}

type AuditEvent struct {
	TenantID      string
	ActorType     string
	ActorID       string
	PrincipalType string
	PrincipalID   string
	Action        string
	ResourceType  string
	ResourceID    string
	Decision      string
	JWTID         string
	CreatedAt     time.Time
}

type CasdoorUser struct {
	ID          string
	Username    string
	Email       string
	DisplayName string
	Disabled    bool
}

type CasdoorGroup struct {
	ID            string
	Name          string
	DisplayName   string
	ParentGroupID string
}

type CasdoorDirectorySnapshot struct {
	Tenant Tenant
	User   CasdoorUser
	Groups []CasdoorGroup
	Roles  []string
}

type OIDCLoginState struct {
	State        string
	Nonce        string
	CodeVerifier string
	RedirectURL  string
	ExpiresAt    time.Time
}

type StartOIDCLoginRequest struct {
	RedirectURL string    `json:"redirect_url,omitempty"`
	Now         time.Time `json:"now,omitempty"`
}

type StartedOIDCLogin struct {
	AuthorizationURL    string `json:"authorization_url"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	ExpiresIn           int    `json:"expires_in"`
}

type DeviceCode struct {
	DeviceCode  string
	UserCode    string
	PrincipalID string
	ExpiresAt   time.Time
	Interval    time.Duration
	Status      string
	CreatedAt   time.Time
}

type OIDCTokenSet struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
}

type OIDCTokenExchanger interface {
	ExchangeCode(ctx context.Context, code, codeVerifier string) (OIDCTokenSet, error)
}

type DirectorySource interface {
	SyncUser(ctx context.Context, casdoorUserID string) ([]CasdoorDirectorySnapshot, error)
	Reconcile(ctx context.Context) error
}

type IdentityContext struct {
	Subject          SubjectContext  `json:"subject"`
	CurrentTenant    TenantContext   `json:"current_tenant"`
	CurrentTeam      *TeamContext    `json:"current_team,omitempty"`
	AvailableTenants []TenantContext `json:"available_tenants"`
	Teams            []TeamContext   `json:"teams"`
	RoleKeys         []string        `json:"role_keys"`
	Permissions      []string        `json:"permissions"`
	ConsoleAccess    bool            `json:"console_access"`
	Apps             []AppContext    `json:"apps"`
}

type SwitchTenantRequest struct {
	SessionID string    `json:"session_id"`
	TenantID  string    `json:"tenant_id"`
	TeamID    string    `json:"team_id,omitempty"`
	Now       time.Time `json:"now,omitempty"`
}

type SwitchTeamRequest struct {
	SessionID string    `json:"session_id"`
	TeamID    string    `json:"team_id"`
	Now       time.Time `json:"now,omitempty"`
}

type SubjectContext struct {
	PrincipalID string `json:"principal_id"`
	ExternalID  string `json:"external_id,omitempty"`
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

type TenantContext struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

type TeamContext struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type AppContext struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

type InternalJWTRequest struct {
	SessionID              string                   `json:"session_id"`
	APIKey                 string                   `json:"api_key,omitempty"`
	ClientCredentialsToken string                   `json:"client_credentials_token,omitempty"`
	Audience               string                   `json:"audience"`
	Actions                []string                 `json:"actions"`
	Resource               *internaljwt.ResourceRef `json:"resource,omitempty"`
	Now                    time.Time                `json:"now,omitempty"`
	JWTID                  string                   `json:"request_id,omitempty"`
}

type InternalJWTResult struct {
	Token  string             `json:"token"`
	Claims internaljwt.Claims `json:"claims"`
}

type RecordAuditEventRequest struct {
	SessionID string                   `json:"session_id,omitempty"`
	APIKey    string                   `json:"api_key,omitempty"`
	Action    string                   `json:"action"`
	Resource  *internaljwt.ResourceRef `json:"resource,omitempty"`
	Decision  string                   `json:"decision"`
	JWTID     string                   `json:"jwt_id,omitempty"`
	Now       time.Time                `json:"now,omitempty"`
}

type TokenValidationResult struct {
	TenantID  string    `json:"tenant_id"`
	KeyID     string    `json:"key_id"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Principal Principal `json:"principal"`
}

type DelegateAgentRequest struct {
	SessionID string                   `json:"session_id"`
	RunID     string                   `json:"run_id"`
	Audience  string                   `json:"audience"`
	Actions   []string                 `json:"actions"`
	Scopes    []string                 `json:"scopes,omitempty"`
	Resource  *internaljwt.ResourceRef `json:"resource,omitempty"`
	Now       time.Time                `json:"now,omitempty"`
	JWTID     string                   `json:"request_id,omitempty"`
}

type CreateAPIKeyRequest struct {
	SessionID string    `json:"session_id"`
	Name      string    `json:"name,omitempty"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Now       time.Time `json:"now,omitempty"`
}

type CreateServiceAccountRequest struct {
	SessionID string    `json:"session_id"`
	Name      string    `json:"name"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Now       time.Time `json:"now,omitempty"`
}

type StartDeviceAuthRequest struct {
	Now time.Time `json:"now,omitempty"`
}

type StartedDeviceAuth struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type ApproveDeviceAuthRequest struct {
	SessionID string    `json:"session_id"`
	UserCode  string    `json:"user_code"`
	Now       time.Time `json:"now,omitempty"`
}

type DeviceTokenRequest struct {
	DeviceCode string    `json:"device_code"`
	Now        time.Time `json:"now,omitempty"`
}

type DeviceTokenResult struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	KeyID       string    `json:"key_id"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

type CreatedAPIKey struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type CreatedServiceAccountToken struct {
	ServiceAccountID string    `json:"service_account_id"`
	KeyID            string    `json:"key_id"`
	Token            string    `json:"token"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
}

type APIKeySummary struct {
	ID            string    `json:"id"`
	Name          string    `json:"name,omitempty"`
	TenantID      string    `json:"tenant_id"`
	PrincipalType string    `json:"principal_type"`
	PrincipalID   string    `json:"principal_id"`
	Scopes        []string  `json:"scopes"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	LastUsedAt    time.Time `json:"last_used_at,omitempty"`
}

type ServiceAccountSummary struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Store interface {
	UpsertTenant(ctx context.Context, tenant Tenant) error
	UpsertPrincipal(ctx context.Context, principal Principal) error
	GetTenant(ctx context.Context, tenantID string) (Tenant, error)
	GetPrincipal(ctx context.Context, principalID string) (Principal, error)
	ListPrincipalsByCasdoorUser(ctx context.Context, casdoorUserID string) ([]Principal, error)
	PutOIDCLoginState(ctx context.Context, state OIDCLoginState) error
	TakeOIDCLoginState(ctx context.Context, state string) (OIDCLoginState, error)
	PutDeviceCode(ctx context.Context, code DeviceCode) error
	GetDeviceCode(ctx context.Context, deviceCode string) (DeviceCode, error)
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (DeviceCode, error)
	UpdateDeviceCode(ctx context.Context, code DeviceCode) error
	PutSession(ctx context.Context, session Session) error
	GetSession(ctx context.Context, sessionID string) (Session, error)
	UpdateSessionContext(ctx context.Context, sessionID, principalID, tenantID, teamID string) error
	DeleteSession(ctx context.Context, sessionID string) error
	DeleteSessionsByPrincipal(ctx context.Context, principalID string) error
	PutServiceAccount(ctx context.Context, account ServiceAccount) error
	ListServiceAccounts(ctx context.Context, tenantID string) ([]ServiceAccount, error)
	DisableServiceAccount(ctx context.Context, accountID, tenantID string) error
	PutAPIKey(ctx context.Context, key APIKey) error
	GetAPIKeyByHash(ctx context.Context, keyHash string) (APIKey, error)
	ListAPIKeys(ctx context.Context, principalID string) ([]APIKey, error)
	RevokeAPIKey(ctx context.Context, keyID, principalID string) error
	TouchAPIKeyLastUsed(ctx context.Context, keyID string, lastUsedAt time.Time) error
	PutAgentRun(ctx context.Context, run AgentRun) error
	AppendAudit(ctx context.Context, event AuditEvent) error
}

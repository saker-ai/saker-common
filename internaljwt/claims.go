package internaljwt

import "time"

const (
	TypeInternalAccess = "internal_access"

	HeaderInternalAuthorization = "X-Saker-Internal-Authorization"
	HeaderAuthorization         = "Authorization"
)

type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf,omitempty"`
	IssuedAt  int64  `json:"iat"`
	JWTID     string `json:"jti"`

	Type    string `json:"typ"`
	Version int    `json:"ver"`

	TenantID      string `json:"tenant_id"`
	OrgID         string `json:"org_id,omitempty"`
	PrincipalType string `json:"principal_type"`
	PrincipalID   string `json:"principal_id"`

	Email  string   `json:"email,omitempty"`
	Name   string   `json:"name,omitempty"`
	Handle string   `json:"handle,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Scopes []string `json:"scopes,omitempty"`

	Resource *ResourceRef `json:"resource,omitempty"`

	SessionID string `json:"session_id,omitempty"`
	AuthTime  int64  `json:"auth_time,omitempty"`
	Source    string `json:"source,omitempty"`

	Actor      *ActorRef      `json:"actor,omitempty"`
	Delegation *DelegationRef `json:"delegation,omitempty"`
}

type ResourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type ActorRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type DelegationRef struct {
	OnBehalfOf string `json:"on_behalf_of"`
	SessionID  string `json:"session_id,omitempty"`
	RunID      string `json:"run_id,omitempty"`
}

type Principal struct {
	TenantID string
	OrgID    string

	Type string
	ID   string

	Roles  []string
	Scopes []string

	ResourceType string
	ResourceID   string

	SessionID string
	Source    string
	JWTID     string

	Claims Claims
}

type SignInput struct {
	Issuer        string
	Audience      string
	TTL           time.Duration
	TenantID      string
	OrgID         string
	PrincipalType string
	PrincipalID   string
	Email         string
	Name          string
	Handle        string
	Roles         []string
	Scopes        []string
	Resource      *ResourceRef
	SessionID     string
	AuthTime      time.Time
	Source        string
	Now           time.Time
	JWTID         string
	Actor         *ActorRef
	Delegation    *DelegationRef
}

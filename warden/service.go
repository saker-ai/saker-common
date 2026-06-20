package warden

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/saker-ai/saker-common/internaljwt"
)

type Config struct {
	Issuer             string
	MasterSecret       string
	InternalTTL        time.Duration
	AgentTTL           time.Duration
	SessionTTL         time.Duration
	APIKeyPrefix       string
	Policy             Policy
	OIDCVerifier       *OIDCVerifier
	OIDCTokenExchanger OIDCTokenExchanger
	DirectorySource    DirectorySource
}

type Service struct {
	cfg            Config
	store          Store
	signer         *internaljwt.Signer
	policyMu       sync.RWMutex
	policy         Policy
	oidcVerifier   *OIDCVerifier
	tokenExchanger OIDCTokenExchanger
	directory      DirectorySource
}

func NewService(cfg Config, store Store) (*Service, error) {
	if store == nil {
		store = NewMemoryStore()
	}
	if strings.TrimSpace(cfg.Issuer) == "" {
		cfg.Issuer = "warden"
	}
	if cfg.InternalTTL <= 0 {
		cfg.InternalTTL = 5 * time.Minute
	}
	if cfg.AgentTTL <= 0 || cfg.AgentTTL > cfg.InternalTTL {
		cfg.AgentTTL = cfg.InternalTTL / 2
		if cfg.AgentTTL <= 0 {
			cfg.AgentTTL = time.Minute
		}
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 24 * time.Hour
	}
	if cfg.APIKeyPrefix == "" {
		cfg.APIKeyPrefix = "sak"
	}
	signer, err := internaljwt.NewSigner(cfg.Issuer, cfg.MasterSecret, cfg.InternalTTL)
	if err != nil {
		return nil, err
	}
	policy := cfg.Policy
	if policy.roleScopes == nil {
		policy = DefaultPolicy()
	}
	return &Service{
		cfg: cfg, store: store, signer: signer, policy: policy,
		oidcVerifier: cfg.OIDCVerifier, tokenExchanger: cfg.OIDCTokenExchanger, directory: cfg.DirectorySource,
	}, nil
}

func (s *Service) Store() Store { return s.store }

func (s *Service) UpdatePolicy(policy Policy) {
	if policy.roleScopes == nil {
		policy = DefaultPolicy()
	}
	s.policyMu.Lock()
	s.policy = policy
	s.policyMu.Unlock()
}

func (s *Service) Policy() Policy {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	if s.policy.roleScopes == nil {
		return DefaultPolicy()
	}
	return Policy{roleScopes: s.policy.RoleScopes()}
}

func (s *Service) scopesForRoles(roles []RoleGrant) []string {
	return s.Policy().ScopesForRoles(roles)
}

func (s *Service) scopesForActions(roles []RoleGrant, audience string, actions []string) []string {
	return s.Policy().ScopesForActions(roles, audience, actions)
}

func (s *Service) PutOIDCLoginState(ctx context.Context, state OIDCLoginState) error {
	if strings.TrimSpace(state.State) == "" || strings.TrimSpace(state.Nonce) == "" || strings.TrimSpace(state.CodeVerifier) == "" {
		return ErrInvalidInput
	}
	if state.ExpiresAt.IsZero() {
		state.ExpiresAt = time.Now().UTC().Add(10 * time.Minute)
	}
	return s.store.PutOIDCLoginState(ctx, state)
}

func (s *Service) StartOIDCLogin(ctx context.Context, req StartOIDCLoginRequest) (StartedOIDCLogin, error) {
	if s.oidcVerifier == nil || strings.TrimSpace(s.oidcVerifier.Issuer) == "" || strings.TrimSpace(s.oidcVerifier.ClientID) == "" {
		return StartedOIDCLogin{}, ErrInvalidInput
	}
	now := normalizeNow(req.Now)
	state := "oidc_" + randomString()
	nonce := "nonce_" + randomString()
	verifier := randomString() + randomString()
	challenge := codeChallengeS256(verifier)
	expiresAt := now.Add(10 * time.Minute)
	if err := s.store.PutOIDCLoginState(ctx, OIDCLoginState{
		State: state, Nonce: nonce, CodeVerifier: verifier, RedirectURL: req.RedirectURL, ExpiresAt: expiresAt,
	}); err != nil {
		return StartedOIDCLogin{}, err
	}
	authURL, err := url.Parse(strings.TrimRight(s.oidcVerifier.Issuer, "/") + "/login/oauth/authorize")
	if err != nil {
		return StartedOIDCLogin{}, err
	}
	q := authURL.Query()
	q.Set("client_id", s.oidcVerifier.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()
	return StartedOIDCLogin{
		AuthorizationURL: authURL.String(),
		State:            state, Nonce: nonce, CodeChallenge: challenge, CodeChallengeMethod: "S256",
		ExpiresIn: int(expiresAt.Sub(now).Seconds()),
	}, nil
}

func (s *Service) StartDeviceAuth(ctx context.Context, req StartDeviceAuthRequest) (StartedDeviceAuth, error) {
	now := normalizeNow(req.Now)
	deviceCode := "dev_" + randomString() + randomString()
	userCode := strings.ToUpper(strings.ReplaceAll(randomString()[:9], "_", "A"))
	interval := 5 * time.Second
	expiresAt := now.Add(15 * time.Minute)
	code := DeviceCode{
		DeviceCode: deviceCode, UserCode: userCode, ExpiresAt: expiresAt,
		Interval: interval, Status: "pending", CreatedAt: now,
	}
	if err := s.store.PutDeviceCode(ctx, code); err != nil {
		return StartedDeviceAuth{}, err
	}
	return StartedDeviceAuth{
		DeviceCode: deviceCode, UserCode: userCode, VerificationURI: "/auth/device",
		ExpiresIn: int(expiresAt.Sub(now).Seconds()), Interval: int(interval.Seconds()),
	}, nil
}

func (s *Service) ApproveDeviceAuth(ctx context.Context, req ApproveDeviceAuthRequest) error {
	_, principal, err := s.ValidateSession(ctx, req.SessionID, req.Now)
	if err != nil {
		return err
	}
	userCode := strings.ToUpper(strings.TrimSpace(req.UserCode))
	if userCode == "" {
		return ErrInvalidInput
	}
	code, err := s.store.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		return ErrUnauthorized
	}
	now := normalizeNow(req.Now)
	if !code.ExpiresAt.IsZero() && !now.Before(code.ExpiresAt) {
		return ErrUnauthorized
	}
	if code.Status != "pending" {
		return ErrForbidden
	}
	code.PrincipalID = principal.ID
	code.Status = "approved"
	if err := s.store.UpdateDeviceCode(ctx, code); err != nil {
		return err
	}
	s.audit(ctx, principal, "device.approve", nil, "allow", "")
	return nil
}

func (s *Service) ExchangeDeviceToken(ctx context.Context, req DeviceTokenRequest) (DeviceTokenResult, error) {
	deviceCode := strings.TrimSpace(req.DeviceCode)
	if deviceCode == "" {
		return DeviceTokenResult{}, ErrInvalidInput
	}
	code, err := s.store.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return DeviceTokenResult{}, ErrUnauthorized
	}
	now := normalizeNow(req.Now)
	if !code.ExpiresAt.IsZero() && !now.Before(code.ExpiresAt) {
		return DeviceTokenResult{}, ErrUnauthorized
	}
	switch code.Status {
	case "pending":
		return DeviceTokenResult{}, ErrAuthorizationPending
	case "approved":
	default:
		return DeviceTokenResult{}, ErrUnauthorized
	}
	principal, err := s.store.GetPrincipal(ctx, code.PrincipalID)
	if err != nil {
		return DeviceTokenResult{}, ErrUnauthorized
	}
	if principal.Status == "disabled" {
		return DeviceTokenResult{}, ErrDisabled
	}
	token := s.cfg.APIKeyPrefix + "_dev_" + randomString() + randomString()
	expiresAt := now.Add(30 * 24 * time.Hour)
	key := APIKey{
		ID: "key_" + randomString(), TenantID: principal.TenantID, PrincipalType: principal.Type, PrincipalID: principal.ID,
		KeyHash: HashAPIKey(token), Scopes: s.scopesForRoles(principal.Roles), ExpiresAt: expiresAt, Status: "active", CreatedAt: now,
	}
	if err := s.store.PutAPIKey(ctx, key); err != nil {
		return DeviceTokenResult{}, err
	}
	code.Status = "consumed"
	if err := s.store.UpdateDeviceCode(ctx, code); err != nil {
		return DeviceTokenResult{}, err
	}
	s.audit(ctx, principal, "device.token", nil, "allow", "")
	return DeviceTokenResult{AccessToken: token, TokenType: "Bearer", KeyID: key.ID, ExpiresAt: expiresAt}, nil
}

func (s *Service) CompleteOIDCCallback(ctx context.Context, code, stateValue string, now time.Time) (Session, IdentityContext, string, error) {
	if s.oidcVerifier == nil || s.tokenExchanger == nil || s.directory == nil {
		return Session{}, IdentityContext{}, "", ErrInvalidInput
	}
	code = strings.TrimSpace(code)
	stateValue = strings.TrimSpace(stateValue)
	if code == "" || stateValue == "" {
		return Session{}, IdentityContext{}, "", ErrInvalidInput
	}
	state, err := s.store.TakeOIDCLoginState(ctx, stateValue)
	if err != nil {
		return Session{}, IdentityContext{}, "", ErrUnauthorized
	}
	now = normalizeNow(now)
	if !state.ExpiresAt.IsZero() && !now.Before(state.ExpiresAt) {
		return Session{}, IdentityContext{}, "", ErrUnauthorized
	}
	tokens, err := s.tokenExchanger.ExchangeCode(ctx, code, state.CodeVerifier)
	if err != nil {
		return Session{}, IdentityContext{}, "", err
	}
	claims, err := s.oidcVerifier.VerifyIDToken(ctx, tokens.IDToken, state.Nonce)
	if err != nil {
		return Session{}, IdentityContext{}, "", err
	}
	principals, err := s.SyncDirectoryUser(ctx, s.directory, claims.Subject)
	if err != nil {
		return Session{}, IdentityContext{}, "", err
	}
	if len(principals) == 0 {
		return Session{}, IdentityContext{}, "", ErrUnauthorized
	}
	session, err := s.CreateSession(ctx, principals[0].ID, now)
	if err != nil {
		return Session{}, IdentityContext{}, "", err
	}
	identity, err := s.IdentityContext(ctx, session.ID, now)
	if err != nil {
		return Session{}, IdentityContext{}, "", err
	}
	return session, identity, state.RedirectURL, nil
}

func (s *Service) CreateSession(ctx context.Context, principalID string, now time.Time) (Session, error) {
	now = normalizeNow(now)
	principal, err := s.store.GetPrincipal(ctx, principalID)
	if err != nil {
		return Session{}, err
	}
	if principal.Status == "disabled" {
		return Session{}, ErrDisabled
	}
	session := Session{
		ID:          "sess_" + randomString(),
		PrincipalID: principal.ID,
		TenantID:    principal.TenantID,
		AuthTime:    now,
		ExpiresAt:   now.Add(s.cfg.SessionTTL),
		Source:      SessionSourceWeb,
	}
	if err := s.store.PutSession(ctx, session); err != nil {
		return Session{}, err
	}
	return session, nil
}

func (s *Service) ValidateSession(ctx context.Context, sessionID string, now time.Time) (Session, Principal, error) {
	now = normalizeNow(now)
	session, err := s.store.GetSession(ctx, strings.TrimSpace(sessionID))
	if err != nil {
		return Session{}, Principal{}, ErrUnauthorized
	}
	if !session.ExpiresAt.IsZero() && !now.Before(session.ExpiresAt) {
		_ = s.store.DeleteSession(ctx, session.ID)
		return Session{}, Principal{}, ErrUnauthorized
	}
	principal, err := s.store.GetPrincipal(ctx, session.PrincipalID)
	if err != nil {
		return Session{}, Principal{}, ErrUnauthorized
	}
	if principal.Status == "disabled" {
		return Session{}, Principal{}, ErrDisabled
	}
	return session, principal, nil
}

func (s *Service) IdentityContext(ctx context.Context, sessionID string, now time.Time) (IdentityContext, error) {
	session, principal, err := s.ValidateSession(ctx, sessionID, now)
	if err != nil {
		return IdentityContext{}, err
	}
	tenant, err := s.store.GetTenant(ctx, session.TenantID)
	if err != nil {
		return IdentityContext{}, err
	}
	scopes := s.scopesForRoles(principal.Roles)
	roleKeys := make([]string, 0, len(principal.Roles))
	for _, role := range principal.Roles {
		if key, ok := NormalizeRoleKey(role.Key); ok {
			roleKeys = append(roleKeys, key)
		}
	}
	teams := make([]TeamContext, 0, len(principal.Teams))
	var currentTeam *TeamContext
	for _, team := range principal.Teams {
		ctxTeam := TeamContext{ID: team.ID, Name: team.Name, DisplayName: team.DisplayName}
		teams = append(teams, ctxTeam)
		if team.ID == session.CurrentTeamID {
			currentTeam = &ctxTeam
		}
	}
	availableTenants, err := s.availableTenants(ctx, principal)
	if err != nil {
		return IdentityContext{}, err
	}
	return IdentityContext{
		Subject: SubjectContext{
			PrincipalID: principal.ID,
			ExternalID:  principal.CasdoorUserID,
			Username:    principal.Username,
			DisplayName: principal.DisplayName,
		},
		CurrentTenant:    TenantContext{ID: tenant.ID, Slug: tenant.Slug, DisplayName: tenant.DisplayName},
		CurrentTeam:      currentTeam,
		AvailableTenants: availableTenants,
		Teams:            teams,
		RoleKeys:         roleKeys,
		Permissions:      scopes,
		ConsoleAccess:    ConsoleAccess(principal.Roles),
		Apps:             AppsForScopes(scopes),
	}, nil
}

func (s *Service) SwitchTenant(ctx context.Context, req SwitchTenantRequest) (IdentityContext, error) {
	session, principal, err := s.ValidateSession(ctx, req.SessionID, req.Now)
	if err != nil {
		return IdentityContext{}, err
	}
	targetTenantID := strings.TrimSpace(req.TenantID)
	if targetTenantID == "" {
		return IdentityContext{}, ErrInvalidInput
	}
	targetPrincipal := principal
	if targetTenantID != session.TenantID {
		if principal.CasdoorUserID == "" {
			return IdentityContext{}, ErrForbidden
		}
		principals, err := s.store.ListPrincipalsByCasdoorUser(ctx, principal.CasdoorUserID)
		if err != nil {
			return IdentityContext{}, err
		}
		found := false
		for _, candidate := range principals {
			if candidate.TenantID == targetTenantID && candidate.Status != "disabled" {
				targetPrincipal = candidate
				found = true
				break
			}
		}
		if !found {
			return IdentityContext{}, ErrForbidden
		}
	}
	teamID, err := validateTeamSelection(targetPrincipal, req.TeamID)
	if err != nil {
		return IdentityContext{}, err
	}
	if err := s.store.UpdateSessionContext(ctx, session.ID, targetPrincipal.ID, targetPrincipal.TenantID, teamID); err != nil {
		return IdentityContext{}, err
	}
	return s.IdentityContext(ctx, session.ID, req.Now)
}

func (s *Service) SwitchTeam(ctx context.Context, req SwitchTeamRequest) (IdentityContext, error) {
	session, principal, err := s.ValidateSession(ctx, req.SessionID, req.Now)
	if err != nil {
		return IdentityContext{}, err
	}
	teamID, err := validateTeamSelection(principal, req.TeamID)
	if err != nil {
		return IdentityContext{}, err
	}
	if err := s.store.UpdateSessionContext(ctx, session.ID, principal.ID, session.TenantID, teamID); err != nil {
		return IdentityContext{}, err
	}
	return s.IdentityContext(ctx, session.ID, req.Now)
}

func (s *Service) availableTenants(ctx context.Context, principal Principal) ([]TenantContext, error) {
	principals := []Principal{principal}
	if principal.CasdoorUserID != "" {
		loaded, err := s.store.ListPrincipalsByCasdoorUser(ctx, principal.CasdoorUserID)
		if err != nil {
			return nil, err
		}
		if len(loaded) > 0 {
			principals = loaded
		}
	}
	seen := map[string]bool{}
	out := make([]TenantContext, 0, len(principals))
	for _, candidate := range principals {
		if candidate.Status == "disabled" || seen[candidate.TenantID] {
			continue
		}
		tenant, err := s.store.GetTenant(ctx, candidate.TenantID)
		if err != nil {
			return nil, err
		}
		seen[candidate.TenantID] = true
		out = append(out, TenantContext{ID: tenant.ID, Slug: tenant.Slug, DisplayName: tenant.DisplayName})
	}
	return out, nil
}

func validateTeamSelection(principal Principal, teamID string) (string, error) {
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return "", nil
	}
	for _, team := range principal.Teams {
		if team.ID == teamID && team.TenantID == principal.TenantID && team.Status != "disabled" {
			return teamID, nil
		}
	}
	return "", ErrForbidden
}

func (s *Service) SignInternalJWT(ctx context.Context, req InternalJWTRequest) (InternalJWTResult, error) {
	if strings.TrimSpace(req.ClientCredentialsToken) != "" {
		return s.signInternalJWTForClientCredentials(ctx, req)
	}
	if strings.TrimSpace(req.SessionID) == "" && strings.TrimSpace(req.APIKey) != "" {
		return s.signInternalJWTForAPIKey(ctx, req)
	}
	session, principal, err := s.ValidateSession(ctx, req.SessionID, req.Now)
	if err != nil {
		return InternalJWTResult{}, err
	}
	scopes := s.scopesForActions(principal.Roles, req.Audience, req.Actions)
	if len(scopes) == 0 {
		s.audit(ctx, principal, "internal_jwt.sign", req.Resource, "deny", "")
		return InternalJWTResult{}, ErrForbidden
	}
	return s.sign(ctx, principal, session, req.Audience, scopes, req.Resource, SessionSourceWeb, req.JWTID, req.Now, nil, nil, s.cfg.InternalTTL)
}

func (s *Service) signInternalJWTForClientCredentials(ctx context.Context, req InternalJWTRequest) (InternalJWTResult, error) {
	if s.oidcVerifier == nil {
		return InternalJWTResult{}, ErrInvalidInput
	}
	claims, err := s.oidcVerifier.VerifyIDToken(ctx, req.ClientCredentialsToken, "")
	if err != nil {
		return InternalJWTResult{}, err
	}
	tenantID := strings.TrimSpace(claims.TenantID)
	if tenantID == "" {
		return InternalJWTResult{}, ErrUnauthorized
	}
	scopesFromToken := strings.Fields(claims.Scope)
	if len(scopesFromToken) == 0 {
		return InternalJWTResult{}, ErrForbidden
	}
	now := normalizeNow(req.Now)
	tenant := Tenant{ID: tenantID, Slug: tenantID, DisplayName: tenantID, Status: "active"}
	if err := s.store.UpsertTenant(ctx, tenant); err != nil {
		return InternalJWTResult{}, err
	}
	principalID := StableProjectionID("svc", tenantID, claims.Subject)
	name := claims.PreferredName
	if name == "" {
		name = claims.Subject
	}
	principal := Principal{
		ID: principalID, TenantID: tenantID, CasdoorUserID: claims.Subject, Username: name, DisplayName: firstNonEmpty(claims.Name, name),
		Type: PrincipalTypeServiceAccount, Status: "active", Roles: []RoleGrant{{Key: RoleTenantAdmin}},
	}
	if err := s.store.UpsertPrincipal(ctx, principal); err != nil {
		return InternalJWTResult{}, err
	}
	if err := s.store.PutServiceAccount(ctx, ServiceAccount{
		ID: principalID, TenantID: tenantID, Name: principal.DisplayName, Status: "active", CreatedBy: "casdoor", CreatedAt: now,
	}); err != nil {
		return InternalJWTResult{}, err
	}
	requested := s.scopesForActions(principal.Roles, req.Audience, req.Actions)
	scopes := intersectScopes(scopesFromToken, requested)
	if len(scopes) == 0 {
		s.audit(ctx, principal, "internal_jwt.sign", req.Resource, "deny", "")
		return InternalJWTResult{}, ErrForbidden
	}
	session := Session{
		ID: "client_credentials:" + claims.Subject, PrincipalID: principal.ID, TenantID: tenantID,
		AuthTime: now, ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(), Source: SessionSourceServiceToken,
	}
	return s.sign(ctx, principal, session, req.Audience, scopes, req.Resource, SessionSourceServiceToken, req.JWTID, req.Now, nil, nil, s.cfg.InternalTTL)
}

func (s *Service) signInternalJWTForAPIKey(ctx context.Context, req InternalJWTRequest) (InternalJWTResult, error) {
	key, principal, err := s.ValidateAPIKey(ctx, req.APIKey, req.Now)
	if err != nil {
		return InternalJWTResult{}, err
	}
	requested := s.scopesForActions(principal.Roles, req.Audience, req.Actions)
	scopes := intersectScopes(key.Scopes, requested)
	if len(scopes) == 0 {
		s.audit(ctx, principal, "internal_jwt.sign", req.Resource, "deny", "")
		return InternalJWTResult{}, ErrForbidden
	}
	session := Session{
		ID:          key.ID,
		PrincipalID: principal.ID,
		TenantID:    key.TenantID,
		AuthTime:    key.CreatedAt,
		ExpiresAt:   key.ExpiresAt,
		Source:      SessionSourceAPIKey,
	}
	return s.sign(ctx, principal, session, req.Audience, scopes, req.Resource, SessionSourceAPIKey, req.JWTID, req.Now, nil, nil, s.cfg.InternalTTL)
}

func (s *Service) CreateAPIKey(ctx context.Context, req CreateAPIKeyRequest) (CreatedAPIKey, error) {
	session, principal, err := s.ValidateSession(ctx, req.SessionID, req.Now)
	if err != nil {
		return CreatedAPIKey{}, err
	}
	allowed := sliceSet(s.scopesForRoles(principal.Roles))
	for _, scope := range req.Scopes {
		if !allowed[scope] {
			return CreatedAPIKey{}, ErrForbidden
		}
	}
	now := normalizeNow(req.Now)
	token := s.cfg.APIKeyPrefix + "_" + randomString() + randomString()
	key := APIKey{
		ID:            "key_" + randomString(),
		Name:          strings.TrimSpace(req.Name),
		TenantID:      session.TenantID,
		PrincipalType: principal.Type,
		PrincipalID:   principal.ID,
		KeyHash:       HashAPIKey(token),
		Scopes:        req.Scopes,
		ExpiresAt:     req.ExpiresAt,
		Status:        "active",
		CreatedAt:     now,
	}
	if err := s.store.PutAPIKey(ctx, key); err != nil {
		return CreatedAPIKey{}, err
	}
	s.audit(ctx, principal, "api_key.create", nil, "allow", "")
	return CreatedAPIKey{ID: key.ID, Token: token, ExpiresAt: key.ExpiresAt}, nil
}

func (s *Service) CreateServiceAccountToken(ctx context.Context, req CreateServiceAccountRequest) (CreatedServiceAccountToken, error) {
	session, creator, err := s.ValidateSession(ctx, req.SessionID, req.Now)
	if err != nil {
		return CreatedServiceAccountToken{}, err
	}
	if !canManageServiceAccounts(creator.Roles) {
		return CreatedServiceAccountToken{}, ErrForbidden
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return CreatedServiceAccountToken{}, ErrInvalidInput
	}
	allowed := sliceSet(s.scopesForRoles(creator.Roles))
	for _, scope := range req.Scopes {
		if !allowed[scope] {
			return CreatedServiceAccountToken{}, ErrForbidden
		}
	}
	now := normalizeNow(req.Now)
	accountID := "svc_" + randomString()
	account := ServiceAccount{
		ID: accountID, TenantID: session.TenantID, Name: name, Status: "active", CreatedBy: creator.ID, CreatedAt: now,
	}
	principal := Principal{
		ID: accountID, TenantID: session.TenantID, Username: name, DisplayName: name,
		Type: PrincipalTypeServiceAccount, Status: "active",
		Roles: []RoleGrant{{Key: RoleTenantAdmin}},
	}
	token := s.cfg.APIKeyPrefix + "_svc_" + randomString() + randomString()
	key := APIKey{
		ID: "key_" + randomString(), TenantID: session.TenantID, PrincipalType: PrincipalTypeServiceAccount, PrincipalID: accountID,
		KeyHash: HashAPIKey(token), Scopes: req.Scopes, ExpiresAt: req.ExpiresAt, Status: "active", CreatedAt: now,
	}
	if err := s.store.UpsertPrincipal(ctx, principal); err != nil {
		return CreatedServiceAccountToken{}, err
	}
	if err := s.store.PutServiceAccount(ctx, account); err != nil {
		return CreatedServiceAccountToken{}, err
	}
	if err := s.store.PutAPIKey(ctx, key); err != nil {
		return CreatedServiceAccountToken{}, err
	}
	s.audit(ctx, creator, "service_account.create_token", &internaljwt.ResourceRef{Type: "service_account", ID: accountID}, "allow", "")
	return CreatedServiceAccountToken{ServiceAccountID: accountID, KeyID: key.ID, Token: token, ExpiresAt: key.ExpiresAt}, nil
}

func (s *Service) ListAPIKeys(ctx context.Context, sessionID string, now time.Time) ([]APIKeySummary, error) {
	_, principal, err := s.ValidateSession(ctx, sessionID, now)
	if err != nil {
		return nil, err
	}
	keys, err := s.store.ListAPIKeys(ctx, principal.ID)
	if err != nil {
		return nil, err
	}
	out := make([]APIKeySummary, 0, len(keys))
	for _, key := range keys {
		out = append(out, APIKeySummary{
			ID: key.ID, Name: key.Name, TenantID: key.TenantID, PrincipalType: key.PrincipalType, PrincipalID: key.PrincipalID,
			Scopes: key.Scopes, ExpiresAt: key.ExpiresAt, Status: key.Status, CreatedAt: key.CreatedAt, LastUsedAt: key.LastUsedAt,
		})
	}
	return out, nil
}

func (s *Service) ListServiceAccounts(ctx context.Context, sessionID string, now time.Time) ([]ServiceAccountSummary, error) {
	session, principal, err := s.ValidateSession(ctx, sessionID, now)
	if err != nil {
		return nil, err
	}
	if !canManageServiceAccounts(principal.Roles) {
		return nil, ErrForbidden
	}
	accounts, err := s.store.ListServiceAccounts(ctx, session.TenantID)
	if err != nil {
		return nil, err
	}
	out := make([]ServiceAccountSummary, 0, len(accounts))
	for _, account := range accounts {
		out = append(out, ServiceAccountSummary{
			ID: account.ID, TenantID: account.TenantID, Name: account.Name,
			Status: account.Status, CreatedBy: account.CreatedBy, CreatedAt: account.CreatedAt,
		})
	}
	return out, nil
}

func (s *Service) DisableServiceAccount(ctx context.Context, sessionID, accountID string, now time.Time) error {
	session, principal, err := s.ValidateSession(ctx, sessionID, now)
	if err != nil {
		return err
	}
	if !canManageServiceAccounts(principal.Roles) {
		return ErrForbidden
	}
	if strings.TrimSpace(accountID) == "" {
		return ErrInvalidInput
	}
	if err := s.store.DisableServiceAccount(ctx, accountID, session.TenantID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrForbidden
		}
		return err
	}
	s.audit(ctx, principal, "service_account.disable", &internaljwt.ResourceRef{Type: "service_account", ID: accountID}, "allow", "")
	return nil
}

func (s *Service) RevokeAPIKey(ctx context.Context, sessionID, keyID string, now time.Time) error {
	_, principal, err := s.ValidateSession(ctx, sessionID, now)
	if err != nil {
		return err
	}
	if strings.TrimSpace(keyID) == "" {
		return ErrInvalidInput
	}
	if err := s.store.RevokeAPIKey(ctx, keyID, principal.ID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrForbidden
		}
		return err
	}
	s.audit(ctx, principal, "api_key.revoke", &internaljwt.ResourceRef{Type: "api_key", ID: keyID}, "allow", "")
	return nil
}

func canManageServiceAccounts(roles []RoleGrant) bool {
	for _, role := range roles {
		key, ok := NormalizeRoleKey(role.Key)
		if !ok {
			continue
		}
		switch key {
		case RolePlatformOwner, RolePlatformAdmin, RoleTenantOwner, RoleTenantAdmin:
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (s *Service) ValidateAPIKey(ctx context.Context, token string, now time.Time) (APIKey, Principal, error) {
	key, err := s.store.GetAPIKeyByHash(ctx, HashAPIKey(token))
	if err != nil {
		return APIKey{}, Principal{}, ErrUnauthorized
	}
	now = normalizeNow(now)
	if key.Status != "active" || (!key.ExpiresAt.IsZero() && !now.Before(key.ExpiresAt)) {
		return APIKey{}, Principal{}, ErrUnauthorized
	}
	principal, err := s.store.GetPrincipal(ctx, key.PrincipalID)
	if err != nil {
		return APIKey{}, Principal{}, ErrUnauthorized
	}
	if principal.Status == "disabled" {
		return APIKey{}, Principal{}, ErrDisabled
	}
	if err := s.store.TouchAPIKeyLastUsed(ctx, key.ID, now); err != nil {
		return APIKey{}, Principal{}, err
	}
	key.LastUsedAt = now
	return key, principal, nil
}

func (s *Service) ValidateToken(ctx context.Context, token string, now time.Time) (TokenValidationResult, error) {
	key, principal, err := s.ValidateAPIKey(ctx, token, now)
	if err != nil {
		return TokenValidationResult{}, err
	}
	key.KeyHash = ""
	return TokenValidationResult{
		TenantID: key.TenantID, KeyID: key.ID, Scopes: key.Scopes, ExpiresAt: key.ExpiresAt, Principal: principal,
	}, nil
}

func (s *Service) RecordAuditEvent(ctx context.Context, req RecordAuditEventRequest) error {
	action := strings.TrimSpace(req.Action)
	decision := strings.TrimSpace(req.Decision)
	if action == "" || decision == "" {
		return ErrInvalidInput
	}
	var (
		principal Principal
		err       error
	)
	if strings.TrimSpace(req.SessionID) != "" {
		_, principal, err = s.ValidateSession(ctx, req.SessionID, req.Now)
	} else if strings.TrimSpace(req.APIKey) != "" {
		_, principal, err = s.ValidateAPIKey(ctx, req.APIKey, req.Now)
	} else {
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	event := AuditEvent{
		TenantID: principal.TenantID, PrincipalType: principal.Type, PrincipalID: principal.ID,
		Action: action, Decision: decision, JWTID: strings.TrimSpace(req.JWTID), CreatedAt: normalizeNow(req.Now),
	}
	if req.Resource != nil {
		event.ResourceType = strings.TrimSpace(req.Resource.Type)
		event.ResourceID = strings.TrimSpace(req.Resource.ID)
	}
	return s.store.AppendAudit(ctx, event)
}

func (s *Service) DelegateAgent(ctx context.Context, req DelegateAgentRequest) (InternalJWTResult, error) {
	session, actor, err := s.ValidateSession(ctx, req.SessionID, req.Now)
	if err != nil {
		return InternalJWTResult{}, err
	}
	actorScopes := s.scopesForActions(actor.Roles, req.Audience, req.Actions)
	delegatedScopes := req.Scopes
	if len(delegatedScopes) == 0 {
		delegatedScopes = actorScopes
	}
	scopes := intersectScopes(actorScopes, delegatedScopes)
	if len(scopes) == 0 {
		s.auditWithActor(ctx, actor, "agent.delegate", req.Resource, "deny", "", &internaljwt.ActorRef{Type: actor.Type, ID: actor.ID})
		return InternalJWTResult{}, ErrForbidden
	}
	runID := strings.TrimSpace(req.RunID)
	if runID == "" {
		runID = "run_" + randomString()
	}
	agentID := "agent_" + runID
	agent := Principal{
		ID: agentID, TenantID: actor.TenantID, Type: PrincipalTypeAgent, Status: "active",
		Roles: []RoleGrant{{Key: RoleSakerRunner}},
	}
	if err := s.store.UpsertPrincipal(ctx, agent); err != nil {
		return InternalJWTResult{}, err
	}
	if err := s.store.PutAgentRun(ctx, AgentRun{
		ID: runID, TenantID: actor.TenantID, ActorPrincipalID: actor.ID, AgentPrincipalID: agentID, Status: "running", CreatedAt: normalizeNow(req.Now),
	}); err != nil {
		return InternalJWTResult{}, err
	}
	return s.sign(ctx, agent, session, req.Audience, scopes, req.Resource, SessionSourceAgent, req.JWTID, req.Now,
		&internaljwt.ActorRef{Type: actor.Type, ID: actor.ID},
		&internaljwt.DelegationRef{OnBehalfOf: actor.ID, SessionID: session.ID, RunID: runID},
		s.cfg.AgentTTL)
}

func (s *Service) sign(ctx context.Context, principal Principal, session Session, audience string, scopes []string, resource *internaljwt.ResourceRef, source, jwtID string, now time.Time, actor *internaljwt.ActorRef, delegation *internaljwt.DelegationRef, ttl time.Duration) (InternalJWTResult, error) {
	token, claims, err := s.signer.Sign(internaljwt.SignInput{
		Audience: audience, TTL: ttl, TenantID: session.TenantID, PrincipalType: principal.Type, PrincipalID: principal.ID,
		Email: principal.Email, Name: principal.DisplayName, Handle: principal.Username, Roles: roleKeys(principal.Roles),
		Scopes: scopes, Resource: resource, SessionID: session.ID, AuthTime: session.AuthTime, Source: source,
		Now: now, JWTID: jwtID, Actor: actor, Delegation: delegation,
	})
	if err != nil {
		return InternalJWTResult{}, err
	}
	s.auditWithActor(ctx, principal, "internal_jwt.sign", resource, "allow", claims.JWTID, actor)
	return InternalJWTResult{Token: token, Claims: claims}, nil
}

func (s *Service) audit(ctx context.Context, principal Principal, action string, resource *internaljwt.ResourceRef, decision, jwtID string) {
	s.auditWithActor(ctx, principal, action, resource, decision, jwtID, nil)
}

func (s *Service) auditWithActor(ctx context.Context, principal Principal, action string, resource *internaljwt.ResourceRef, decision, jwtID string, actor *internaljwt.ActorRef) {
	event := AuditEvent{
		TenantID: principal.TenantID, PrincipalType: principal.Type, PrincipalID: principal.ID,
		Action: action, Decision: decision, JWTID: jwtID, CreatedAt: time.Now().UTC(),
	}
	if actor != nil {
		event.ActorType = actor.Type
		event.ActorID = actor.ID
	}
	if resource != nil {
		event.ResourceType = resource.Type
		event.ResourceID = resource.ID
	}
	_ = s.store.AppendAudit(ctx, event)
}

func roleKeys(roles []RoleGrant) []string {
	out := make([]string, 0, len(roles))
	for _, role := range roles {
		if key, ok := NormalizeRoleKey(role.Key); ok {
			out = append(out, key)
		}
	}
	return out
}

func HashAPIKey(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func normalizeNow(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now.UTC()
}

func randomString() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

package warden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/saker-ai/saker-common/internaljwt"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestIdentityContextAndInternalJWT(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "principal-a", TenantID: "tenant-a", CasdoorUserID: "casdoor-a",
		Username: "alice", DisplayName: "Alice", Type: PrincipalTypeUser, Status: "active",
		Roles: []RoleGrant{{Key: RoleTenantViewer}, {Key: RoleChatHubUser}, {Key: "unknown.role"}},
	})
	session, err := svc.CreateSession(ctx, "principal-a", testNow())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	identity, err := svc.IdentityContext(ctx, session.ID, testNow())
	if err != nil {
		t.Fatalf("IdentityContext: %v", err)
	}
	if identity.Subject.PrincipalID != "principal-a" || !identity.ConsoleAccess {
		t.Fatalf("identity = %+v", identity)
	}
	if !has(identity.Permissions, internaljwt.ScopeChatHubWrite) || has(identity.RoleKeys, "unknown.role") {
		t.Fatalf("permissions=%v roleKeys=%v", identity.Permissions, identity.RoleKeys)
	}

	result, err := svc.SignInternalJWT(ctx, InternalJWTRequest{
		SessionID: session.ID,
		Audience:  internaljwt.AudienceChatHub,
		Actions:   []string{"write"},
		Resource:  &internaljwt.ResourceRef{Type: "thread", ID: "thread-a"},
		Now:       testNow(),
		JWTID:     "jwt-a",
	})
	if err != nil {
		t.Fatalf("SignInternalJWT: %v", err)
	}
	if result.Token == "" || result.Claims.TenantID != "tenant-a" || !has(result.Claims.Scopes, internaljwt.ScopeChatHubWrite) {
		t.Fatalf("claims = %+v", result.Claims)
	}

	_, err = svc.SignInternalJWT(ctx, InternalJWTRequest{
		SessionID: session.ID,
		Audience:  internaljwt.AudienceAssetHub,
		Actions:   []string{"upload"},
		Now:       testNow(),
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("asset upload err = %v, want ErrForbidden", err)
	}
}

func TestAPIKeyStoresOnlyHashAndValidates(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "principal-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: "active",
		Roles: []RoleGrant{{Key: RoleAssetHubEditor}},
	})
	session, err := svc.CreateSession(ctx, "principal-a", testNow())
	if err != nil {
		t.Fatal(err)
	}
	created, err := svc.CreateAPIKey(ctx, CreateAPIKeyRequest{
		SessionID: session.ID,
		Scopes:    []string{internaljwt.ScopeAssetHubRead, internaljwt.ScopeAssetHubUpload},
		ExpiresAt: testNow().Add(time.Hour),
		Now:       testNow(),
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if created.Token == "" || created.ID == "" {
		t.Fatalf("created key = %+v", created)
	}
	if _, _, err := svc.ValidateAPIKey(ctx, created.Token, testNow()); err != nil {
		t.Fatalf("ValidateAPIKey: %v", err)
	}
	if _, err := store.GetAPIKeyByHash(ctx, created.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("plaintext lookup err = %v, want ErrNotFound", err)
	}
	if _, _, err := svc.ValidateAPIKey(ctx, created.Token+"x", testNow()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("invalid key err = %v, want ErrUnauthorized", err)
	}

	keys, err := svc.ListAPIKeys(ctx, session.ID, testNow())
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].ID != created.ID || keys[0].Status != "active" {
		t.Fatalf("keys = %+v", keys)
	}
	if err := svc.RevokeAPIKey(ctx, session.ID, created.ID, testNow()); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if _, _, err := svc.ValidateAPIKey(ctx, created.Token, testNow()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked key err = %v, want ErrUnauthorized", err)
	}
	if err := svc.RevokeAPIKey(ctx, session.ID, "key-other", testNow()); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoke other key err = %v, want ErrForbidden", err)
	}
}

func TestCreateServiceAccountTokenSignsAsServiceAccount(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "principal-admin", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: "active",
		Roles: []RoleGrant{{Key: RoleTenantAdmin}},
	})
	session, err := svc.CreateSession(ctx, "principal-admin", testNow())
	if err != nil {
		t.Fatal(err)
	}
	created, err := svc.CreateServiceAccountToken(ctx, CreateServiceAccountRequest{
		SessionID: session.ID,
		Name:      "synapse-filestorage",
		Scopes:    []string{internaljwt.ScopeAssetHubRead, internaljwt.ScopeAssetHubUpload, internaljwt.ScopeWebHubNotificationsWrite},
		Now:       testNow(),
	})
	if err != nil {
		t.Fatalf("CreateServiceAccountToken: %v", err)
	}
	validation, err := svc.ValidateToken(ctx, created.Token, testNow())
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if validation.Principal.Type != PrincipalTypeServiceAccount || validation.Principal.ID != created.ServiceAccountID {
		t.Fatalf("validation = %+v", validation)
	}
	result, err := svc.SignInternalJWT(ctx, InternalJWTRequest{
		APIKey:   created.Token,
		Audience: internaljwt.AudienceAssetHub,
		Actions:  []string{"upload"},
		Now:      testNow(),
		JWTID:    "jwt-svc",
	})
	if err != nil {
		t.Fatalf("SignInternalJWT: %v", err)
	}
	if result.Claims.PrincipalType != PrincipalTypeServiceAccount || result.Claims.PrincipalID != created.ServiceAccountID || !has(result.Claims.Scopes, internaljwt.ScopeAssetHubUpload) {
		t.Fatalf("claims = %+v", result.Claims)
	}
	result, err = svc.SignInternalJWT(ctx, InternalJWTRequest{
		APIKey:   created.Token,
		Audience: internaljwt.AudienceWebHub,
		Actions:  []string{"notifications:write"},
		Now:      testNow(),
		JWTID:    "jwt-webhub-notify",
	})
	if err != nil {
		t.Fatalf("SignInternalJWT webhub notifications: %v", err)
	}
	if result.Claims.Audience != internaljwt.AudienceWebHub || !has(result.Claims.Scopes, internaljwt.ScopeWebHubNotificationsWrite) {
		t.Fatalf("webhub notification claims = %+v", result.Claims)
	}
	_, err = svc.SignInternalJWT(ctx, InternalJWTRequest{
		APIKey:   created.Token,
		Audience: internaljwt.AudienceAssetHub,
		Actions:  []string{"admin"},
		Now:      testNow(),
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin signing err = %v, want ErrForbidden", err)
	}
}

func TestRecordAuditEventResolvesSessionPrincipal(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "principal-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: "active",
		Roles: []RoleGrant{{Key: RoleSakerRunner}},
	})
	session, err := svc.CreateSession(ctx, "principal-a", testNow())
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.RecordAuditEvent(ctx, RecordAuditEventRequest{
		SessionID: session.ID,
		Action:    "agent.approval",
		Decision:  "allow",
		Resource:  &internaljwt.ResourceRef{Type: "run", ID: "run-a"},
		Now:       testNow(),
	}); err != nil {
		t.Fatalf("RecordAuditEvent: %v", err)
	}

	audits := store.AuditEvents()
	if len(audits) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audits))
	}
	audit := audits[0]
	if audit.TenantID != "tenant-a" || audit.PrincipalType != PrincipalTypeUser || audit.PrincipalID != "principal-a" {
		t.Fatalf("audit principal = %+v", audit)
	}
	if audit.Action != "agent.approval" || audit.Decision != "allow" || audit.ResourceType != "run" || audit.ResourceID != "run-a" {
		t.Fatalf("audit event = %+v", audit)
	}
}

func TestCreateServiceAccountTokenRequiresAdminRole(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "principal-viewer", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: "active",
		Roles: []RoleGrant{{Key: RoleTenantViewer}},
	})
	session, err := svc.CreateSession(ctx, "principal-viewer", testNow())
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateServiceAccountToken(ctx, CreateServiceAccountRequest{
		SessionID: session.ID,
		Name:      "ci",
		Scopes:    []string{internaljwt.ScopeChatHubRead},
		Now:       testNow(),
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("CreateServiceAccountToken err = %v, want ErrForbidden", err)
	}
}

func TestClientCredentialsTokenSignsAsServiceAccount(t *testing.T) {
	ctx := context.Background()
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
		"iss":       "https://saker.example.com/auth",
		"sub":       "casdoor-client-a",
		"aud":       "saker-m2m",
		"exp":       now.Add(time.Minute).Unix(),
		"iat":       now.Add(-time.Minute).Unix(),
		"tenant_id": "tenant-a",
		"scope":     internaljwt.ScopeAssetHubRead + " " + internaljwt.ScopeAssetHubUpload,
	})
	store := NewMemoryStore()
	svc, err := NewService(Config{
		Issuer:       "warden",
		MasterSecret: testSecret,
		InternalTTL:  5 * time.Minute,
		OIDCVerifier: &OIDCVerifier{
			Issuer:   "https://saker.example.com/auth",
			ClientID: "saker-m2m",
			JWKSURL:  jwksServer.URL,
			Now:      func() time.Time { return now },
		},
	}, store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	result, err := svc.SignInternalJWT(ctx, InternalJWTRequest{
		ClientCredentialsToken: token,
		Audience:               internaljwt.AudienceAssetHub,
		Actions:                []string{"upload"},
		Now:                    now,
		JWTID:                  "jwt-m2m",
	})
	if err != nil {
		t.Fatalf("SignInternalJWT client credentials: %v", err)
	}
	if result.Claims.PrincipalType != PrincipalTypeServiceAccount || result.Claims.TenantID != "tenant-a" || !has(result.Claims.Scopes, internaljwt.ScopeAssetHubUpload) {
		t.Fatalf("claims = %+v", result.Claims)
	}
	_, err = svc.SignInternalJWT(ctx, InternalJWTRequest{
		ClientCredentialsToken: token,
		Audience:               internaljwt.AudienceAssetHub,
		Actions:                []string{"admin"},
		Now:                    now,
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin err = %v, want ErrForbidden", err)
	}
}

func TestDeviceCodeFlowIssuesTokenOnce(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "principal-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: "active",
		Roles: []RoleGrant{{Key: RoleChatHubUser}},
	})
	session, err := svc.CreateSession(ctx, "principal-a", testNow())
	if err != nil {
		t.Fatal(err)
	}
	started, err := svc.StartDeviceAuth(ctx, StartDeviceAuthRequest{Now: testNow()})
	if err != nil {
		t.Fatalf("StartDeviceAuth: %v", err)
	}
	if started.DeviceCode == "" || started.UserCode == "" || started.ExpiresIn <= 0 {
		t.Fatalf("started = %+v", started)
	}
	if _, err := svc.ExchangeDeviceToken(ctx, DeviceTokenRequest{DeviceCode: started.DeviceCode, Now: testNow()}); !errors.Is(err, ErrAuthorizationPending) {
		t.Fatalf("pending exchange err = %v, want ErrAuthorizationPending", err)
	}
	if err := svc.ApproveDeviceAuth(ctx, ApproveDeviceAuthRequest{SessionID: session.ID, UserCode: started.UserCode, Now: testNow()}); err != nil {
		t.Fatalf("ApproveDeviceAuth: %v", err)
	}
	token, err := svc.ExchangeDeviceToken(ctx, DeviceTokenRequest{DeviceCode: started.DeviceCode, Now: testNow()})
	if err != nil {
		t.Fatalf("ExchangeDeviceToken: %v", err)
	}
	if token.AccessToken == "" || token.TokenType != "Bearer" || token.KeyID == "" {
		t.Fatalf("token = %+v", token)
	}
	if _, _, err := svc.ValidateAPIKey(ctx, token.AccessToken, testNow()); err != nil {
		t.Fatalf("ValidateAPIKey: %v", err)
	}
	if _, err := svc.ExchangeDeviceToken(ctx, DeviceTokenRequest{DeviceCode: started.DeviceCode, Now: testNow()}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replayed exchange err = %v, want ErrUnauthorized", err)
	}
}

func TestDelegateAgentIntersectsActorScopes(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "principal-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: "active",
		Roles: []RoleGrant{{Key: RoleAssetHubEditor}},
	})
	session, err := svc.CreateSession(ctx, "principal-a", testNow())
	if err != nil {
		t.Fatal(err)
	}

	result, err := svc.DelegateAgent(ctx, DelegateAgentRequest{
		SessionID: session.ID,
		RunID:     "run-a",
		Audience:  internaljwt.AudienceAssetHub,
		Actions:   []string{"read", "upload"},
		Scopes:    []string{internaljwt.ScopeAssetHubRead, internaljwt.ScopeAssetHubAdmin},
		Resource:  &internaljwt.ResourceRef{Type: "run", ID: "run-a"},
		Now:       testNow(),
		JWTID:     "jwt-agent",
	})
	if err != nil {
		t.Fatalf("DelegateAgent: %v", err)
	}
	if result.Claims.PrincipalType != PrincipalTypeAgent || result.Claims.Actor == nil || result.Claims.Delegation == nil {
		t.Fatalf("delegated claims = %+v", result.Claims)
	}
	if !has(result.Claims.Scopes, internaljwt.ScopeAssetHubRead) || has(result.Claims.Scopes, internaljwt.ScopeAssetHubAdmin) {
		t.Fatalf("delegated scopes = %v", result.Claims.Scopes)
	}
	audits := store.AuditEvents()
	if len(audits) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audits))
	}
	audit := audits[0]
	if audit.ActorID != "principal-a" || audit.ActorType != PrincipalTypeUser {
		t.Fatalf("audit actor = %s/%s, want user/principal-a", audit.ActorType, audit.ActorID)
	}
	if audit.PrincipalType != PrincipalTypeAgent || audit.PrincipalID != "agent_run-a" {
		t.Fatalf("audit principal = %s/%s, want agent/agent_run-a", audit.PrincipalType, audit.PrincipalID)
	}
	if audit.ResourceType != "run" || audit.ResourceID != "run-a" || audit.JWTID != "jwt-agent" {
		t.Fatalf("audit resource/jwt = %+v", audit)
	}

	_, err = svc.DelegateAgent(ctx, DelegateAgentRequest{
		SessionID: session.ID,
		Audience:  internaljwt.AudienceAssetHub,
		Actions:   []string{"admin"},
		Scopes:    []string{internaljwt.ScopeAssetHubAdmin},
		Now:       testNow(),
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin delegation err = %v, want ErrForbidden", err)
	}
}

func TestSwitchTenantUsesMatchingCasdoorPrincipal(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	if err := store.UpsertTenant(ctx, Tenant{ID: "tenant-a", Slug: "acme", DisplayName: "Acme", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertTenant(ctx, Tenant{ID: "tenant-b", Slug: "beta", DisplayName: "Beta", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPrincipal(ctx, Principal{
		ID: "principal-a", TenantID: "tenant-a", CasdoorUserID: "casdoor-a", Type: PrincipalTypeUser, Status: "active",
		Roles: []RoleGrant{{Key: RoleTenantViewer}},
		Teams: []Team{{ID: "team-a", TenantID: "tenant-a", Name: "research", DisplayName: "Research", Status: "active"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPrincipal(ctx, Principal{
		ID: "principal-b", TenantID: "tenant-b", CasdoorUserID: "casdoor-a", Type: PrincipalTypeUser, Status: "active",
		Roles: []RoleGrant{{Key: RoleChatHubUser}},
		Teams: []Team{{ID: "team-b", TenantID: "tenant-b", Name: "ops", DisplayName: "Ops", Status: "active"}},
	}); err != nil {
		t.Fatal(err)
	}
	session, err := svc.CreateSession(ctx, "principal-a", testNow())
	if err != nil {
		t.Fatal(err)
	}

	identity, err := svc.SwitchTenant(ctx, SwitchTenantRequest{SessionID: session.ID, TenantID: "tenant-b", TeamID: "team-b", Now: testNow()})
	if err != nil {
		t.Fatalf("SwitchTenant: %v", err)
	}
	if identity.Subject.PrincipalID != "principal-b" || identity.CurrentTenant.ID != "tenant-b" || identity.CurrentTeam == nil || identity.CurrentTeam.ID != "team-b" {
		t.Fatalf("identity = %+v", identity)
	}
	if len(identity.AvailableTenants) != 2 {
		t.Fatalf("available tenants = %+v", identity.AvailableTenants)
	}
	updated, err := store.GetSession(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.PrincipalID != "principal-b" || updated.TenantID != "tenant-b" || updated.CurrentTeamID != "team-b" {
		t.Fatalf("updated session = %+v", updated)
	}
}

func TestSwitchRejectsUnauthorizedTenantAndTeam(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "principal-a", TenantID: "tenant-a", CasdoorUserID: "casdoor-a", Type: PrincipalTypeUser, Status: "active",
		Roles: []RoleGrant{{Key: RoleTenantViewer}},
		Teams: []Team{{ID: "team-a", TenantID: "tenant-a", Name: "research", DisplayName: "Research", Status: "active"}},
	})
	session, err := svc.CreateSession(ctx, "principal-a", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SwitchTenant(ctx, SwitchTenantRequest{SessionID: session.ID, TenantID: "tenant-b", Now: testNow()}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("SwitchTenant err = %v, want ErrForbidden", err)
	}
	if _, err := svc.SwitchTeam(ctx, SwitchTeamRequest{SessionID: session.ID, TeamID: "team-other", Now: testNow()}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("SwitchTeam err = %v, want ErrForbidden", err)
	}
}

func newTestService(t *testing.T) (*Service, *MemoryStore) {
	t.Helper()
	store := NewMemoryStore()
	svc, err := NewService(Config{Issuer: "warden", MasterSecret: testSecret, InternalTTL: 5 * time.Minute}, store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store
}

func seedPrincipal(t *testing.T, ctx context.Context, store *MemoryStore, principal Principal) {
	t.Helper()
	if err := store.UpsertTenant(ctx, Tenant{ID: principal.TenantID, Slug: "acme", DisplayName: "Acme", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPrincipal(ctx, principal); err != nil {
		t.Fatal(err)
	}
}

func testNow() time.Time {
	return time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
}

func has(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

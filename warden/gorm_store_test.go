package warden

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/saker-ai/saker-common/internaljwt"
)

func TestGORMStorePersistsIAMProjection(t *testing.T) {
	ctx := context.Background()
	store := newTestGORMStore(t)
	defer func() { _ = store.Close() }()

	if err := store.UpsertTenant(ctx, Tenant{ID: "tenant-a", CasdoorOrgName: "acme", Slug: "acme", DisplayName: "Acme", Status: "active"}); err != nil {
		t.Fatalf("UpsertTenant: %v", err)
	}
	if err := store.UpsertPrincipal(ctx, Principal{
		ID: "principal-a", TenantID: "tenant-a", CasdoorUserID: "casdoor-user-a",
		Username: "alice", Email: "alice@example.com", DisplayName: "Alice", Type: PrincipalTypeUser, Status: "active",
		Roles: []RoleGrant{
			{Key: RoleTenantAdmin, ScopeType: "tenant", ScopeID: "tenant-a"},
			{Key: "unknown.role"},
		},
		Teams: []Team{
			{ID: "team-a", TenantID: "tenant-a", CasdoorGroupID: "group-a", Name: "research", DisplayName: "Research", Status: "active"},
		},
	}); err != nil {
		t.Fatalf("UpsertPrincipal: %v", err)
	}
	session := Session{
		ID: "sess-a", PrincipalID: "principal-a", TenantID: "tenant-a", CurrentTeamID: "team-a",
		AuthTime: testNow(), ExpiresAt: testNow().Add(time.Hour), Source: SessionSourceWeb,
	}
	if err := store.PutSession(ctx, session); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	key := APIKey{
		ID: "key-a", TenantID: "tenant-a", PrincipalType: PrincipalTypeUser, PrincipalID: "principal-a",
		KeyHash: HashAPIKey("sak_test"), Scopes: []string{internaljwt.ScopeChatHubRead}, ExpiresAt: testNow().Add(time.Hour),
		Status: "active", CreatedAt: testNow(),
	}
	if err := store.PutAPIKey(ctx, key); err != nil {
		t.Fatalf("PutAPIKey: %v", err)
	}
	if err := store.PutAgentRun(ctx, AgentRun{ID: "run-a", TenantID: "tenant-a", ActorPrincipalID: "principal-a", AgentPrincipalID: "agent-a", Status: "running", CreatedAt: testNow()}); err != nil {
		t.Fatalf("PutAgentRun: %v", err)
	}
	if err := store.AppendAudit(ctx, AuditEvent{TenantID: "tenant-a", PrincipalType: PrincipalTypeUser, PrincipalID: "principal-a", Action: "internal_jwt.sign", Decision: "allow", CreatedAt: testNow()}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	gotPrincipal, err := store.GetPrincipal(ctx, "principal-a")
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}
	if gotPrincipal.CasdoorUserID != "casdoor-user-a" || len(gotPrincipal.Roles) != 2 || len(gotPrincipal.Teams) != 1 {
		t.Fatalf("principal = %+v", gotPrincipal)
	}
	gotSession, err := store.GetSession(ctx, "sess-a")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if gotSession.CurrentTeamID != "team-a" || gotSession.ExpiresAt.IsZero() {
		t.Fatalf("session = %+v", gotSession)
	}
	gotKey, err := store.GetAPIKeyByHash(ctx, HashAPIKey("sak_test"))
	if err != nil {
		t.Fatalf("GetAPIKeyByHash: %v", err)
	}
	if len(gotKey.Scopes) != 1 || gotKey.Scopes[0] != internaljwt.ScopeChatHubRead {
		t.Fatalf("api key = %+v", gotKey)
	}
	if _, err := store.GetAPIKeyByHash(ctx, "sak_test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("plaintext key lookup err = %v, want ErrNotFound", err)
	}
}

func TestGORMStoreWorksWithService(t *testing.T) {
	ctx := context.Background()
	store := newTestGORMStore(t)
	defer func() { _ = store.Close() }()
	if err := store.UpsertTenant(ctx, Tenant{ID: "tenant-a", Slug: "acme", DisplayName: "Acme", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPrincipal(ctx, Principal{
		ID: "principal-a", TenantID: "tenant-a", Username: "alice", Type: PrincipalTypeUser, Status: "active",
		Roles: []RoleGrant{{Key: RoleChatHubUser}},
		Teams: []Team{{ID: "team-a", TenantID: "tenant-a", Name: "research", DisplayName: "Research", Status: "active"}},
	}); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{Issuer: "warden", MasterSecret: testSecret, InternalTTL: 5 * time.Minute}, store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	session, err := svc.CreateSession(ctx, "principal-a", testNow())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	identity, err := svc.IdentityContext(ctx, session.ID, testNow())
	if err != nil {
		t.Fatalf("IdentityContext: %v", err)
	}
	if identity.CurrentTenant.ID != "tenant-a" || !has(identity.Permissions, internaljwt.ScopeChatHubWrite) {
		t.Fatalf("identity = %+v", identity)
	}
}

func newTestGORMStore(t *testing.T) *GORMStore {
	t.Helper()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "warden.db")
	store, err := OpenGORMStore(context.Background(), dsn)
	if err != nil {
		t.Fatalf("OpenGORMStore: %v", err)
	}
	return store
}

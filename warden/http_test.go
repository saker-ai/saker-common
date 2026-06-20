package warden

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/saker-ai/saker-common/internaljwt"
)

func TestHTTPHandlerIdentityContextAndInternalJWT(t *testing.T) {
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
	handler := NewHTTPHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/iam/context", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("context status=%d body=%s", rec.Code, rec.Body.String())
	}
	var identity IdentityContext
	if err := json.Unmarshal(rec.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	if identity.Subject.PrincipalID != "principal-a" || !has(identity.Permissions, internaljwt.ScopeChatHubRead) {
		t.Fatalf("identity = %+v", identity)
	}

	body := bytes.NewBufferString(`{"session_id":"` + session.ID + `","audience":"chathub","actions":["write"],"request_id":"req-a"}`)
	req = httptest.NewRequest(http.MethodPost, "/internal/internal-jwts", body)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("jwt status=%d body=%s", rec.Code, rec.Body.String())
	}
	var result InternalJWTResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Token == "" || !has(result.Claims.Scopes, internaljwt.ScopeChatHubWrite) {
		t.Fatalf("jwt result = %+v", result.Claims)
	}
}

func TestHTTPHandlerRejectsUnknownFields(t *testing.T) {
	svc, _ := newTestService(t)
	handler := NewHTTPHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/internal/internal-jwts", bytes.NewBufferString(`{"session_id":"s","audience":"chathub","scopes":["chathub:admin"]}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTPHandlerInternalRoutesRequireCallerTokenWhenConfigured(t *testing.T) {
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
	handler := NewHTTPHandlerWithInternalAPIKey(svc, "internal-secret")

	req := httptest.NewRequest(http.MethodPost, "/internal/session/validate", bytes.NewBufferString(`{"session_id":"`+session.ID+`"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/session/validate", bytes.NewBufferString(`{"session_id":"`+session.ID+`"}`))
	req.Header.Set(InternalCallerTokenHeader, "wrong-secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/session/validate", bytes.NewBufferString(`{"session_id":"`+session.ID+`"}`))
	req.Header.Set(InternalCallerTokenHeader, "internal-secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTPHandlerRecordAuditEventRequiresInternalToken(t *testing.T) {
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
	handler := NewHTTPHandlerWithInternalAPIKey(svc, "internal-secret")
	body := `{"session_id":"` + session.ID + `","action":"agent.approval","decision":"deny","resource":{"type":"run","id":"run-a"}}`

	req := httptest.NewRequest(http.MethodPost, "/internal/audit-events", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/audit-events", bytes.NewBufferString(body))
	req.Header.Set(InternalCallerTokenHeader, "internal-secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("record audit status=%d body=%s", rec.Code, rec.Body.String())
	}
	audits := store.AuditEvents()
	if len(audits) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audits))
	}
	if audits[0].PrincipalID != "principal-a" || audits[0].Action != "agent.approval" || audits[0].Decision != "deny" {
		t.Fatalf("audit = %+v", audits[0])
	}
}

func TestHTTPHandlerInternalJWTWithAPIKey(t *testing.T) {
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
		Name:      "developer laptop",
		Scopes:    []string{internaljwt.ScopeAssetHubRead, internaljwt.ScopeAssetHubUpload},
		Now:       testNow(),
	})
	if err != nil {
		t.Fatal(err)
	}

	handler := NewHTTPHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/internal/internal-jwts", bytes.NewBufferString(`{"api_key":"`+created.Token+`","audience":"assethub","actions":["upload"]}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var result InternalJWTResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Token == "" || result.Claims.Source != SessionSourceAPIKey || !has(result.Claims.Scopes, internaljwt.ScopeAssetHubUpload) {
		t.Fatalf("claims = %+v", result.Claims)
	}

	req = httptest.NewRequest(http.MethodGet, "/iam/api-keys", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list keys status=%d body=%s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(HashAPIKey(created.Token))) {
		t.Fatalf("list keys leaked key hash: %s", rec.Body.String())
	}
	var listedKeys struct {
		Data []APIKeySummary `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listedKeys); err != nil {
		t.Fatal(err)
	}
	if len(listedKeys.Data) != 1 || listedKeys.Data[0].Name != "developer laptop" || listedKeys.Data[0].LastUsedAt.IsZero() {
		t.Fatalf("listed keys = %+v", listedKeys.Data)
	}

	req = httptest.NewRequest(http.MethodDelete, "/iam/api-keys/"+created.ID, nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	addCSRF(req)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke key status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTPHandlerServiceAccountToken(t *testing.T) {
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
	handler := NewHTTPHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/iam/service-accounts", bytes.NewBufferString(`{"name":"ci","scopes":["assethub:read"]}`))
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	addCSRF(req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create service account status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created CreatedServiceAccountToken
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Token == "" || created.ServiceAccountID == "" {
		t.Fatalf("created = %+v", created)
	}

	req = httptest.NewRequest(http.MethodGet, "/iam/service-accounts", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list service accounts status=%d body=%s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Data []ServiceAccountSummary `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Data) != 1 || listed.Data[0].Name != "ci" || listed.Data[0].Status != "active" {
		t.Fatalf("listed = %+v", listed.Data)
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/tokens/validate", bytes.NewBufferString(`{"api_key":"`+created.Token+`"}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("validate token status=%d body=%s", rec.Code, rec.Body.String())
	}
	var validation TokenValidationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &validation); err != nil {
		t.Fatal(err)
	}
	if validation.Principal.Type != PrincipalTypeServiceAccount || validation.KeyID != created.KeyID || !has(validation.Scopes, internaljwt.ScopeAssetHubRead) {
		t.Fatalf("validation = %+v", validation)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(HashAPIKey(created.Token))) {
		t.Fatalf("validate token leaked key hash: %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/iam/service-accounts/"+created.ServiceAccountID, nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	addCSRF(req)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable service account status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/tokens/validate", bytes.NewBufferString(`{"api_key":"`+created.Token+`"}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled token status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTPHandlerSwitchTenantAndTeam(t *testing.T) {
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
	handler := NewHTTPHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/iam/tenants/switch", bytes.NewBufferString(`{"tenant_id":"tenant-b","team_id":"team-b"}`))
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	addCSRF(req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("switch tenant status=%d body=%s", rec.Code, rec.Body.String())
	}
	var identity IdentityContext
	if err := json.Unmarshal(rec.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	if identity.CurrentTenant.ID != "tenant-b" || identity.CurrentTeam == nil || identity.CurrentTeam.ID != "team-b" {
		t.Fatalf("identity = %+v", identity)
	}

	req = httptest.NewRequest(http.MethodPost, "/iam/teams/switch", bytes.NewBufferString(`{"team_id":"team-a"}`))
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	addCSRF(req)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("switch team status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTPHandlerRejectsMissingCSRFForCookieWrites(t *testing.T) {
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
	handler := NewHTTPHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/iam/api-keys", bytes.NewBufferString(`{"scopes":["chathub:read"]}`))
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTPHandlerDirectorySync(t *testing.T) {
	svc, _ := newOIDCTestService(t)
	staticDirectoryReconcileCalls = 0
	handler := NewHTTPHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/internal/directory/sync", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if staticDirectoryReconcileCalls != 1 {
		t.Fatalf("reconcile calls = %d, want 1", staticDirectoryReconcileCalls)
	}
}

func TestHTTPHandlerDeviceCodeFlow(t *testing.T) {
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
	handler := NewHTTPHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/auth/device/code", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("device code status=%d body=%s", rec.Code, rec.Body.String())
	}
	var started StartedDeviceAuth
	if err := json.Unmarshal(rec.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/device/token", bytes.NewBufferString(`{"device_code":"`+started.DeviceCode+`"}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("pending token status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/device/approve", bytes.NewBufferString(`{"user_code":"`+started.UserCode+`"}`))
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	addCSRF(req)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/device/token", bytes.NewBufferString(`{"device_code":"`+started.DeviceCode+`"}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", rec.Code, rec.Body.String())
	}
	var token DeviceTokenResult
	if err := json.Unmarshal(rec.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	if token.AccessToken == "" || token.TokenType != "Bearer" {
		t.Fatalf("token = %+v", token)
	}
}

func addCSRF(req *http.Request) {
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-a"})
	req.Header.Set("X-CSRF-Token", "csrf-a")
}

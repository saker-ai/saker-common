package warden

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/saker-ai/saker-common/internaljwt"
)

func TestSessionValidationPublishesCurrentPolicyIncludingEmptyGrants(t *testing.T) {
	svc, store := newTestService(t)
	seedPrincipal(t, t.Context(), store, Principal{ID: "viewer", TenantID: "tenant", Type: PrincipalTypeUser, Status: PrincipalStatusActive, Roles: []RoleGrant{{Key: RoleSakerWebViewer}}})
	session, err := svc.CreateSession(t.Context(), "viewer", testNow())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandlerWithInternalAPIKey(svc, "fixture-internal")
	call := func() []string {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/internal/session/validate", bytes.NewBufferString(`{"session_id":"`+session.ID+`"}`)).WithContext(t.Context())
		request.Header.Set(InternalCallerTokenHeader, "fixture-internal")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != 200 {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var response struct {
			Valid       bool      `json:"valid"`
			SessionID   string    `json:"session_id"`
			Permissions *[]string `json:"permissions"`
			Roles       []string  `json:"roles"`
			Tenant      struct {
				ID string `json:"ID"`
			} `json:"tenant"`
			Principal struct {
				ID string `json:"ID"`
			} `json:"principal"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if !response.Valid || response.SessionID != session.ID || response.Principal.ID != "viewer" || response.Tenant.ID != "tenant" || !slices.Equal(response.Roles, []string{RoleSakerWebViewer}) || response.Permissions == nil {
			t.Fatalf("missing authoritative session fields: %s", recorder.Body.String())
		}
		return *response.Permissions
	}
	if scopes := call(); !slices.Equal(scopes, []string{internaljwt.ScopeSakerWebRead}) {
		t.Fatalf("viewer scopes=%v", scopes)
	}
	policy, err := NewPolicy(map[string][]string{RoleSakerWebViewer: {}})
	if err != nil {
		t.Fatal(err)
	}
	svc.UpdatePolicy(policy)
	if scopes := call(); len(scopes) != 0 {
		t.Fatalf("empty live policy restored grants: %v", scopes)
	}
}

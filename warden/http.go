package warden

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const SessionCookieName = "warden_session"
const CSRFCookieName = "warden_csrf"
const InternalCallerTokenHeader = "X-Warden-Internal-Token"

type HTTPHandler struct {
	service        *Service
	internalAPIKey string
}

func NewHTTPHandler(service *Service) *HTTPHandler {
	return &HTTPHandler{service: service}
}

func NewHTTPHandlerWithInternalAPIKey(service *Service, internalAPIKey string) *HTTPHandler {
	return &HTTPHandler{service: service, internalAPIKey: strings.TrimSpace(internalAPIKey)}
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/internal/") && !h.validInternalCaller(r) {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
		return
	}
	if requiresCSRF(r) && !validCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "csrf_rejected", "csrf rejected")
		return
	}
	switch {
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && r.URL.Path == "/auth/oidc/callback":
		h.handleOIDCCallback(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && r.URL.Path == "/auth/oidc/start":
		h.handleOIDCStart(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/auth/device/code":
		h.handleDeviceCode(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/auth/device/approve":
		h.handleDeviceApprove(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/auth/device/token":
		h.handleDeviceToken(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/iam/context":
		h.handleIdentityContext(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/iam/api-keys":
		h.handleListAPIKeys(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/iam/api-keys":
		h.handleCreateAPIKey(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/iam/api-keys/"):
		h.handleRevokeAPIKey(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/iam/service-accounts":
		h.handleListServiceAccounts(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/iam/service-accounts":
		h.handleCreateServiceAccount(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/iam/service-accounts/"):
		h.handleDisableServiceAccount(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/iam/tenants/switch":
		h.handleSwitchTenant(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/iam/teams/switch":
		h.handleSwitchTeam(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/auth/logout":
		h.handleLogout(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/internal/session/validate":
		h.handleValidateSession(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/internal/internal-jwts":
		h.handleInternalJWT(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/internal/tokens/validate":
		h.handleValidateToken(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/internal/agent/delegate":
		h.handleDelegateAgent(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/internal/audit-events":
		h.handleRecordAuditEvent(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && r.URL.Path == "/internal/directory/sync":
		h.handleDirectorySync(w, r)
	default:
		writeJSONError(w, http.StatusNotFound, "not_found", "not found")
	}
}

func (h *HTTPHandler) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	redirectURL := strings.TrimSpace(r.URL.Query().Get("redirect_url"))
	if r.Method == http.MethodPost {
		var body struct {
			RedirectURL string `json:"redirect_url"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		redirectURL = body.RedirectURL
	}
	started, err := h.service.StartOIDCLogin(r.Context(), StartOIDCLoginRequest{RedirectURL: redirectURL})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, started)
}

func (h *HTTPHandler) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	started, err := h.service.StartDeviceAuth(r.Context(), StartDeviceAuthRequest{})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, started)
}

func (h *HTTPHandler) handleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	sessionID, err := sessionIDFromRequest(r)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	var body struct {
		UserCode string `json:"user_code"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.service.ApproveDeviceAuth(r.Context(), ApproveDeviceAuthRequest{SessionID: sessionID, UserCode: body.UserCode}); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *HTTPHandler) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceCode string `json:"device_code"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := h.service.ExchangeDeviceToken(r.Context(), DeviceTokenRequest{DeviceCode: body.DeviceCode})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *HTTPHandler) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	sessionID, err := sessionIDFromRequest(r)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	keys, err := h.service.ListAPIKeys(r.Context(), sessionID, time.Time{})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": keys})
}

func (h *HTTPHandler) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if r.Method == http.MethodPost && (code == "" || state == "") {
		var body struct {
			Code  string `json:"code"`
			State string `json:"state"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if code == "" {
			code = body.Code
		}
		if state == "" {
			state = body.State
		}
	}
	session, identity, redirectURL, err := h.service.CompleteOIDCCallback(r.Context(), code, state, time.Time{})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookieName, Value: session.ID, Path: "/",
		Expires: session.ExpiresAt, HttpOnly: true, Secure: secureCookie(r), SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: CSRFCookieName, Value: randomString(), Path: "/",
		Expires: session.ExpiresAt, HttpOnly: false, Secure: secureCookie(r), SameSite: http.SameSiteLaxMode,
	})
	if strings.TrimSpace(redirectURL) != "" {
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusOK, identity)
}

func (h *HTTPHandler) handleSwitchTenant(w http.ResponseWriter, r *http.Request) {
	sessionID, err := sessionIDFromRequest(r)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	var body struct {
		TenantID string `json:"tenant_id"`
		TeamID   string `json:"team_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	identity, err := h.service.SwitchTenant(r.Context(), SwitchTenantRequest{
		SessionID: sessionID,
		TenantID:  body.TenantID,
		TeamID:    body.TeamID,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, identity)
}

func (h *HTTPHandler) handleSwitchTeam(w http.ResponseWriter, r *http.Request) {
	sessionID, err := sessionIDFromRequest(r)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	var body struct {
		TeamID string `json:"team_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	identity, err := h.service.SwitchTeam(r.Context(), SwitchTeamRequest{
		SessionID: sessionID,
		TeamID:    body.TeamID,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, identity)
}

func (h *HTTPHandler) handleIdentityContext(w http.ResponseWriter, r *http.Request) {
	sessionID, err := sessionIDFromRequest(r)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	identity, err := h.service.IdentityContext(r.Context(), sessionID, time.Time{})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, identity)
}

func (h *HTTPHandler) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	sessionID, err := sessionIDFromRequest(r)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	var body struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresAt string   `json:"expires_at"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	var expiresAt time.Time
	if strings.TrimSpace(body.ExpiresAt) != "" {
		expiresAt, err = time.Parse(time.RFC3339, body.ExpiresAt)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "expires_at must be RFC3339")
			return
		}
	}
	created, err := h.service.CreateAPIKey(r.Context(), CreateAPIKeyRequest{
		SessionID: sessionID,
		Name:      body.Name,
		Scopes:    body.Scopes,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (h *HTTPHandler) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	sessionID, err := sessionIDFromRequest(r)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	keyID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/iam/api-keys/"))
	if err := h.service.RevokeAPIKey(r.Context(), sessionID, keyID, time.Time{}); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *HTTPHandler) handleListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	sessionID, err := sessionIDFromRequest(r)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	accounts, err := h.service.ListServiceAccounts(r.Context(), sessionID, time.Time{})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": accounts})
}

func (h *HTTPHandler) handleCreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	sessionID, err := sessionIDFromRequest(r)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	var body struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresAt string   `json:"expires_at"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	var expiresAt time.Time
	if strings.TrimSpace(body.ExpiresAt) != "" {
		expiresAt, err = time.Parse(time.RFC3339, body.ExpiresAt)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "expires_at must be RFC3339")
			return
		}
	}
	created, err := h.service.CreateServiceAccountToken(r.Context(), CreateServiceAccountRequest{
		SessionID: sessionID,
		Name:      body.Name,
		Scopes:    body.Scopes,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (h *HTTPHandler) handleDisableServiceAccount(w http.ResponseWriter, r *http.Request) {
	sessionID, err := sessionIDFromRequest(r)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	accountID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/iam/service-accounts/"))
	if err := h.service.DisableServiceAccount(r.Context(), sessionID, accountID, time.Time{}); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *HTTPHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID, err := sessionIDFromRequest(r)
	if err == nil {
		_ = h.service.store.DeleteSession(r.Context(), sessionID)
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: secureCookie(r), SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *HTTPHandler) handleValidateSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionID string `json:"session_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	session, principal, err := h.service.ValidateSession(r.Context(), body.SessionID, time.Time{})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": session.ID,
		"tenant_id":  session.TenantID,
		"principal":  principal,
	})
}

func (h *HTTPHandler) handleInternalJWT(w http.ResponseWriter, r *http.Request) {
	var body InternalJWTRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := h.service.SignInternalJWT(r.Context(), body)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *HTTPHandler) handleValidateToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		APIKey string `json:"api_key"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := h.service.ValidateToken(r.Context(), body.APIKey, time.Time{})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *HTTPHandler) handleDelegateAgent(w http.ResponseWriter, r *http.Request) {
	var body DelegateAgentRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := h.service.DelegateAgent(r.Context(), body)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *HTTPHandler) handleRecordAuditEvent(w http.ResponseWriter, r *http.Request) {
	var body RecordAuditEventRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.service.RecordAuditEvent(r.Context(), body); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
}

func (h *HTTPHandler) handleDirectorySync(w http.ResponseWriter, r *http.Request) {
	if err := h.service.ReconcileDirectory(r.Context()); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *HTTPHandler) validInternalCaller(r *http.Request) bool {
	expected := strings.TrimSpace(h.internalAPIKey)
	if expected == "" {
		return true
	}
	got := strings.TrimSpace(r.Header.Get(InternalCallerTokenHeader))
	if got == "" {
		const bearer = "Bearer "
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(auth, bearer) {
			got = strings.TrimSpace(strings.TrimPrefix(auth, bearer))
		}
	}
	if got == "" || len(got) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

func sessionIDFromRequest(r *http.Request) (string, error) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return strings.TrimSpace(cookie.Value), nil
	}
	if header := strings.TrimSpace(r.Header.Get("X-Warden-Session")); header != "" {
		return header, nil
	}
	return "", ErrUnauthorized
}

func requiresCSRF(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/internal/") {
		return false
	}
	if r.URL.Path == "/auth/oidc/callback" {
		return false
	}
	if r.URL.Path == "/auth/device/approve" {
		return true
	}
	return strings.HasPrefix(r.URL.Path, "/iam/") || r.URL.Path == "/auth/logout"
}

func validCSRF(r *http.Request) bool {
	if _, err := r.Cookie(SessionCookieName); err != nil {
		return true
	}
	cookie, err := r.Cookie(CSRFCookieName)
	if err != nil {
		return false
	}
	header := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	return header != "" && header == cookie.Value
}

func secureCookie(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func decodeJSON(r *http.Request, dst any) error {
	defer func() { _ = r.Body.Close() }()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrDisabled):
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrInsufficientRole):
		writeJSONError(w, http.StatusForbidden, "forbidden", "forbidden")
	case errors.Is(err, ErrAuthorizationPending):
		writeJSONError(w, http.StatusAccepted, "authorization_pending", "authorization pending")
	case errors.Is(err, ErrInvalidInput):
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid request")
	default:
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "internal error")
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

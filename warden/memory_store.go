package warden

import (
	"context"
	"sort"
	"sync"
	"time"
)

type MemoryStore struct {
	mu          sync.RWMutex
	tenants     map[string]Tenant
	principals  map[string]Principal
	oidcStates  map[string]OIDCLoginState
	deviceCodes map[string]DeviceCode
	sessions    map[string]Session
	accounts    map[string]ServiceAccount
	apiKeys     map[string]APIKey
	agentRuns   map[string]AgentRun
	audits      []AuditEvent
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tenants: map[string]Tenant{}, principals: map[string]Principal{},
		oidcStates:  map[string]OIDCLoginState{},
		deviceCodes: map[string]DeviceCode{},
		sessions:    map[string]Session{}, accounts: map[string]ServiceAccount{},
		apiKeys: map[string]APIKey{}, agentRuns: map[string]AgentRun{},
	}
}

func (s *MemoryStore) UpsertTenant(_ context.Context, tenant Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants[tenant.ID] = tenant
	return nil
}

func (s *MemoryStore) UpsertPrincipal(_ context.Context, principal Principal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principals[principal.ID] = principal
	return nil
}

func (s *MemoryStore) GetTenant(_ context.Context, tenantID string) (Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tenant, ok := s.tenants[tenantID]
	if !ok {
		return Tenant{}, ErrNotFound
	}
	return tenant, nil
}

func (s *MemoryStore) GetPrincipal(_ context.Context, principalID string) (Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	principal, ok := s.principals[principalID]
	if !ok {
		return Principal{}, ErrNotFound
	}
	return principal, nil
}

func (s *MemoryStore) ListPrincipalsByCasdoorUser(_ context.Context, casdoorUserID string) ([]Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Principal
	for _, principal := range s.principals {
		if principal.CasdoorUserID != "" && principal.CasdoorUserID == casdoorUserID {
			out = append(out, principal)
		}
	}
	return out, nil
}

func (s *MemoryStore) PutOIDCLoginState(_ context.Context, state OIDCLoginState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oidcStates[state.State] = state
	return nil
}

func (s *MemoryStore) TakeOIDCLoginState(_ context.Context, stateValue string) (OIDCLoginState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.oidcStates[stateValue]
	if !ok {
		return OIDCLoginState{}, ErrNotFound
	}
	delete(s.oidcStates, stateValue)
	return state, nil
}

func (s *MemoryStore) PutDeviceCode(_ context.Context, code DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceCodes[code.DeviceCode] = code
	return nil
}

func (s *MemoryStore) GetDeviceCode(_ context.Context, deviceCode string) (DeviceCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	code, ok := s.deviceCodes[deviceCode]
	if !ok {
		return DeviceCode{}, ErrNotFound
	}
	return code, nil
}

func (s *MemoryStore) GetDeviceCodeByUserCode(_ context.Context, userCode string) (DeviceCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, code := range s.deviceCodes {
		if code.UserCode == userCode {
			return code, nil
		}
	}
	return DeviceCode{}, ErrNotFound
}

func (s *MemoryStore) UpdateDeviceCode(_ context.Context, code DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.deviceCodes[code.DeviceCode]; !ok {
		return ErrNotFound
	}
	s.deviceCodes[code.DeviceCode] = code
	return nil
}

func (s *MemoryStore) PutSession(_ context.Context, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *MemoryStore) GetSession(_ context.Context, sessionID string) (Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return Session{}, ErrNotFound
	}
	return session, nil
}

func (s *MemoryStore) UpdateSessionContext(_ context.Context, sessionID, principalID, tenantID, teamID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return ErrNotFound
	}
	session.PrincipalID = principalID
	session.TenantID = tenantID
	session.CurrentTeamID = teamID
	s.sessions[sessionID] = session
	return nil
}

func (s *MemoryStore) DeleteSession(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

func (s *MemoryStore) DeleteSessionsByPrincipal(_ context.Context, principalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sessionID, session := range s.sessions {
		if session.PrincipalID == principalID {
			delete(s.sessions, sessionID)
		}
	}
	return nil
}

func (s *MemoryStore) PutServiceAccount(_ context.Context, account ServiceAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts[account.ID] = account
	return nil
}

func (s *MemoryStore) ListServiceAccounts(_ context.Context, tenantID string) ([]ServiceAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ServiceAccount
	for _, account := range s.accounts {
		if tenantID == "" || account.TenantID == tenantID {
			out = append(out, account)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) DisableServiceAccount(_ context.Context, accountID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	account, ok := s.accounts[accountID]
	if !ok || account.TenantID != tenantID {
		return ErrNotFound
	}
	account.Status = "disabled"
	s.accounts[accountID] = account
	if principal, ok := s.principals[accountID]; ok && principal.TenantID == tenantID {
		principal.Status = "disabled"
		s.principals[accountID] = principal
	}
	return nil
}

func (s *MemoryStore) PutAPIKey(_ context.Context, key APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys[key.KeyHash] = key
	return nil
}

func (s *MemoryStore) GetAPIKeyByHash(_ context.Context, keyHash string) (APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.apiKeys[keyHash]
	if !ok {
		return APIKey{}, ErrNotFound
	}
	return key, nil
}

func (s *MemoryStore) ListAPIKeys(_ context.Context, principalID string) ([]APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []APIKey
	for _, key := range s.apiKeys {
		if key.PrincipalID == principalID {
			out = append(out, key)
		}
	}
	return out, nil
}

func (s *MemoryStore) RevokeAPIKey(_ context.Context, keyID, principalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, key := range s.apiKeys {
		if key.ID == keyID && key.PrincipalID == principalID {
			key.Status = "revoked"
			s.apiKeys[hash] = key
			return nil
		}
	}
	return ErrNotFound
}

func (s *MemoryStore) TouchAPIKeyLastUsed(_ context.Context, keyID string, lastUsedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, key := range s.apiKeys {
		if key.ID == keyID {
			key.LastUsedAt = lastUsedAt
			s.apiKeys[hash] = key
			return nil
		}
	}
	return ErrNotFound
}

func (s *MemoryStore) PutAgentRun(_ context.Context, run AgentRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agentRuns[run.ID] = run
	return nil
}

func (s *MemoryStore) AppendAudit(_ context.Context, event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audits = append(s.audits, event)
	return nil
}

func (s *MemoryStore) AuditEvents() []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEvent, len(s.audits))
	copy(out, s.audits)
	return out
}

func (s *MemoryStore) ListTenants(_ context.Context, limit int) ([]Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tenant, 0, len(s.tenants))
	for _, tenant := range s.tenants {
		out = append(out, tenant)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return limitSlice(out, limit), nil
}

func (s *MemoryStore) ListPrincipals(_ context.Context, tenantID string, limit int) ([]Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Principal, 0, len(s.principals))
	for _, principal := range s.principals {
		if tenantID != "" && principal.TenantID != tenantID {
			continue
		}
		out = append(out, principal)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return limitSlice(out, limit), nil
}

func (s *MemoryStore) ListSessions(_ context.Context, tenantID string, limit int) ([]Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		if tenantID != "" && session.TenantID != tenantID {
			continue
		}
		out = append(out, session)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AuthTime.After(out[j].AuthTime) })
	return limitSlice(out, limit), nil
}

func (s *MemoryStore) ListAgentRuns(_ context.Context, tenantID string, limit int) ([]AgentRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AgentRun, 0, len(s.agentRuns))
	for _, run := range s.agentRuns {
		if tenantID != "" && run.TenantID != tenantID {
			continue
		}
		out = append(out, run)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return limitSlice(out, limit), nil
}

func (s *MemoryStore) ListAuditEvents(_ context.Context, tenantID string, limit int) ([]AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEvent, 0, len(s.audits))
	for _, event := range s.audits {
		if tenantID != "" && event.TenantID != tenantID {
			continue
		}
		out = append(out, event)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return limitSlice(out, limit), nil
}

func limitSlice[T any](values []T, limit int) []T {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

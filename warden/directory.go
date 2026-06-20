package warden

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func (s *Service) SyncDirectorySnapshot(ctx context.Context, snapshot CasdoorDirectorySnapshot) (Principal, error) {
	if strings.TrimSpace(snapshot.Tenant.ID) == "" {
		return Principal{}, ErrInvalidInput
	}
	if strings.TrimSpace(snapshot.User.ID) == "" {
		return Principal{}, ErrInvalidInput
	}
	tenant := snapshot.Tenant
	if tenant.Status == "" {
		tenant.Status = "active"
	}
	if err := s.store.UpsertTenant(ctx, tenant); err != nil {
		return Principal{}, err
	}
	principal := Principal{
		ID:            StableProjectionID("principal", tenant.ID, snapshot.User.ID),
		TenantID:      tenant.ID,
		CasdoorUserID: snapshot.User.ID,
		Username:      snapshot.User.Username,
		Email:         snapshot.User.Email,
		DisplayName:   snapshot.User.DisplayName,
		Type:          PrincipalTypeUser,
		Status:        "active",
		Roles:         normalizedDirectoryRoles(snapshot.Roles),
		Teams:         directoryTeams(tenant.ID, snapshot.Groups),
	}
	if snapshot.User.Disabled {
		principal.Status = "disabled"
	}
	if err := s.store.UpsertPrincipal(ctx, principal); err != nil {
		return Principal{}, err
	}
	if principal.Status == "disabled" {
		if err := s.store.DeleteSessionsByPrincipal(ctx, principal.ID); err != nil {
			return Principal{}, err
		}
	}
	s.audit(ctx, principal, "directory.sync", nil, "allow", "")
	return principal, nil
}

func (s *Service) SyncDirectoryUser(ctx context.Context, source DirectorySource, casdoorUserID string) ([]Principal, error) {
	if source == nil || strings.TrimSpace(casdoorUserID) == "" {
		return nil, ErrInvalidInput
	}
	snapshots, err := source.SyncUser(ctx, casdoorUserID)
	if err != nil {
		return nil, err
	}
	principals := make([]Principal, 0, len(snapshots))
	for _, snapshot := range snapshots {
		principal, err := s.SyncDirectorySnapshot(ctx, snapshot)
		if err != nil {
			return nil, err
		}
		principals = append(principals, principal)
	}
	return principals, nil
}

func (s *Service) ReconcileDirectory(ctx context.Context) error {
	if s.directory == nil {
		return ErrInvalidInput
	}
	return s.directory.Reconcile(ctx)
}

func normalizedDirectoryRoles(roles []string) []RoleGrant {
	out := make([]RoleGrant, 0, len(roles)+1)
	seen := map[string]bool{}
	for _, role := range roles {
		key, ok := NormalizeRoleKey(role)
		if !ok || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, RoleGrant{Key: key})
	}
	if len(out) == 0 {
		out = append(out, RoleGrant{Key: RoleFrontendUser})
	}
	return out
}

func directoryTeams(tenantID string, groups []CasdoorGroup) []Team {
	out := make([]Team, 0, len(groups))
	for _, group := range groups {
		if strings.TrimSpace(group.ID) == "" {
			continue
		}
		out = append(out, Team{
			ID:             StableProjectionID("team", tenantID, group.ID),
			TenantID:       tenantID,
			CasdoorGroupID: group.ID,
			Name:           group.Name,
			DisplayName:    group.DisplayName,
			ParentTeamID:   parentTeamID(tenantID, group.ParentGroupID),
			Status:         "active",
		})
	}
	return out
}

func parentTeamID(tenantID, parentGroupID string) string {
	if strings.TrimSpace(parentGroupID) == "" {
		return ""
	}
	return StableProjectionID("team", tenantID, parentGroupID)
}

func StableProjectionID(prefix string, parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(strings.TrimSpace(part)))
		_, _ = h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	return prefix + "_" + hex.EncodeToString(sum[:12])
}

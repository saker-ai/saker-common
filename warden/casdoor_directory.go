package warden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

var ErrDirectoryUnavailable = errors.New("warden: directory unavailable")

// CasdoorTenantMapping explicitly maps one IdP organization/group boundary to
// one Warden tenant. External admin flags never grant Warden privileges.
type CasdoorTenantMapping struct {
	Organization   string              `json:"organization" yaml:"organization"`
	TenantID       string              `json:"tenant_id" yaml:"tenant_id"`
	TenantSlug     string              `json:"tenant_slug" yaml:"tenant_slug"`
	DisplayName    string              `json:"display_name" yaml:"display_name"`
	RequiredGroups []string            `json:"required_groups,omitempty" yaml:"required_groups,omitempty"`
	DefaultRoles   []string            `json:"default_roles,omitempty" yaml:"default_roles,omitempty"`
	RoleMappings   map[string][]string `json:"role_mappings,omitempty" yaml:"role_mappings,omitempty"`
}

type CasdoorDirectoryConfig struct {
	BaseURL, ClientID, ClientSecret string
	Mappings                        []CasdoorTenantMapping
	Client                          *http.Client
}

// CasdoorDirectorySource uses authenticated Casdoor get-user(owner,userId).
// Subject is the stable UUID from the verified token, not username or email.
type CasdoorDirectorySource struct {
	baseURL                string
	clientID, clientSecret string
	mappings               []CasdoorTenantMapping
	client                 *http.Client
	mu                     sync.Mutex
	service                *Service
}

func NewCasdoorDirectorySource(cfg CasdoorDirectoryConfig) (*CasdoorDirectorySource, error) {
	if _, err := oidcEndpoint(cfg.BaseURL); err != nil {
		return nil, err
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" || len(cfg.Mappings) == 0 {
		return nil, ErrInvalidInput
	}
	mappings := make([]CasdoorTenantMapping, 0, len(cfg.Mappings))
	seen := map[string]bool{}
	for _, mapping := range cfg.Mappings {
		if strings.TrimSpace(mapping.Organization) == "" || strings.ContainsAny(mapping.Organization, "/\\") || strings.TrimSpace(mapping.TenantID) == "" || seen[mapping.TenantID] {
			return nil, ErrInvalidInput
		}
		seen[mapping.TenantID] = true
		if mapping.TenantSlug == "" {
			mapping.TenantSlug = mapping.TenantID
		}
		if mapping.DisplayName == "" {
			mapping.DisplayName = mapping.TenantSlug
		}
		mapping.RequiredGroups = slices.Clone(mapping.RequiredGroups)
		mapping.DefaultRoles = slices.Clone(mapping.DefaultRoles)
		roles := make(map[string][]string, len(mapping.RoleMappings))
		for external, grants := range mapping.RoleMappings {
			// Fully qualified external role IDs avoid collisions between orgs.
			if !strings.HasPrefix(external, mapping.Organization+"/") {
				return nil, ErrInvalidInput
			}
			roles[external] = slices.Clone(grants)
		}
		mapping.RoleMappings = roles
		for _, group := range mapping.RequiredGroups {
			if !strings.HasPrefix(group, mapping.Organization+"/") {
				return nil, ErrInvalidInput
			}
		}
		allRoles := slices.Clone(mapping.DefaultRoles)
		for _, grants := range roles {
			allRoles = append(allRoles, grants...)
		}
		for _, role := range allRoles {
			if _, ok := NormalizeRoleKey(role); !ok {
				return nil, fmt.Errorf("unknown Warden directory role %q", role)
			}
		}
		mappings = append(mappings, mapping)
	}
	client := boundedOIDCClient(cfg.Client)
	if client.Timeout > 3*time.Second {
		client.Timeout = 3 * time.Second
	}
	return &CasdoorDirectorySource{baseURL: strings.TrimRight(cfg.BaseURL, "/"), clientID: cfg.ClientID, clientSecret: cfg.ClientSecret, mappings: mappings, client: client}, nil
}

type casdoorDirectoryUser struct {
	ID            string   `json:"id"`
	Owner         string   `json:"owner"`
	Name          string   `json:"name"`
	Email         string   `json:"email"`
	DisplayName   string   `json:"displayName"`
	EmailVerified bool     `json:"emailVerified"`
	Forbidden     bool     `json:"isForbidden"`
	Deleted       bool     `json:"isDeleted"`
	DeletedTime   string   `json:"deletedTime"`
	Groups        []string `json:"groups"`
	Roles         []struct {
		Owner   string `json:"owner"`
		Name    string `json:"name"`
		Enabled bool   `json:"isEnabled"`
	} `json:"roles"`
}

func (d *CasdoorDirectorySource) SyncUser(ctx context.Context, subject string) ([]CasdoorDirectorySnapshot, error) {
	if strings.TrimSpace(subject) == "" {
		return nil, ErrInvalidInput
	}
	users := map[string]*casdoorDirectoryUser{}
	var snapshots []CasdoorDirectorySnapshot
	for _, mapping := range d.mappings {
		user, found := users[mapping.Organization]
		if !found {
			var err error
			user, err = d.getUser(ctx, mapping.Organization, subject)
			if err != nil {
				return nil, err
			}
			users[mapping.Organization] = user
		}
		if user == nil {
			continue
		}
		member := true
		for _, group := range mapping.RequiredGroups {
			member = member && slices.Contains(user.Groups, group)
		}
		if !member {
			continue
		}
		roles := slices.Clone(mapping.DefaultRoles)
		for _, role := range user.Roles {
			if role.Enabled && role.Owner == mapping.Organization {
				roles = append(roles, mapping.RoleMappings[role.Owner+"/"+role.Name]...)
			}
		}
		var groups []CasdoorGroup
		for _, group := range user.Groups {
			if strings.HasPrefix(group, mapping.Organization+"/") {
				groups = append(groups, CasdoorGroup{ID: group, Name: strings.TrimPrefix(group, mapping.Organization+"/"), DisplayName: strings.TrimPrefix(group, mapping.Organization+"/")})
			}
		}
		snapshots = append(snapshots, CasdoorDirectorySnapshot{
			Tenant: Tenant{ID: mapping.TenantID, Slug: mapping.TenantSlug, DisplayName: mapping.DisplayName, CasdoorOrgName: mapping.Organization, Status: "active"},
			User:   CasdoorUser{ID: user.ID, Username: user.Name, Email: user.Email, DisplayName: user.DisplayName, EmailVerified: user.EmailVerified, Disabled: user.Forbidden || user.Deleted || user.DeletedTime != ""},
			Roles:  roles, Groups: groups,
		})
	}
	return snapshots, nil
}

func (d *CasdoorDirectorySource) getUser(ctx context.Context, organization, subject string) (*casdoorDirectoryUser, error) {
	u, err := url.Parse(d.baseURL + "/api/get-user")
	if err != nil {
		return nil, ErrDirectoryUnavailable
	}
	u.RawQuery = url.Values{"owner": {organization}, "userId": {subject}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, ErrDirectoryUnavailable
	}
	req.SetBasicAuth(d.clientID, d.clientSecret)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, ErrDirectoryUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrDirectoryUnavailable
	}
	var envelope struct {
		Status string                `json:"status"`
		Data   *casdoorDirectoryUser `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&envelope); err != nil || envelope.Status != "ok" {
		return nil, ErrDirectoryUnavailable
	}
	if envelope.Data == nil {
		return nil, nil
	}
	if envelope.Data.ID != subject || envelope.Data.Owner != organization {
		return nil, ErrDirectoryUnavailable
	}
	return envelope.Data, nil
}

type directorySubjectLister interface {
	ListDirectorySubjects(context.Context, string) ([]string, error)
}

func (d *CasdoorDirectorySource) bind(service *Service) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.service != nil && d.service != service {
		return errors.New("casdoor directory cannot be shared by separate Warden services")
	}
	if _, ok := service.store.(directorySubjectLister); !ok {
		return errors.New("directory projection store cannot enumerate subjects")
	}
	d.service = service
	return nil
}

// Reconcile refreshes all previously projected subjects, including after a
// restart. It does not silently limit the directory to the first admin page.
func (d *CasdoorDirectorySource) Reconcile(ctx context.Context) error {
	d.mu.Lock()
	service := d.service
	d.mu.Unlock()
	if service == nil {
		return ErrInvalidInput
	}
	store, ok := service.store.(directorySubjectLister)
	if !ok {
		return ErrInvalidInput
	}
	known := map[string][]Principal{}
	for _, mapping := range d.mappings {
		subjects, err := store.ListDirectorySubjects(ctx, mapping.TenantID)
		if err != nil {
			return err
		}
		for _, subject := range subjects {
			if _, found := known[subject]; found {
				continue
			}
			principals, err := service.store.ListPrincipalsByCasdoorUser(ctx, subject)
			if err != nil {
				return err
			}
			known[subject] = principals
		}
	}
	for subject, prior := range known {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := service.SyncDirectoryUser(ctx, d, subject)
		if err != nil {
			return err
		}
		for _, principal := range prior {
			managed := false
			for _, mapping := range d.mappings {
				managed = managed || mapping.TenantID == principal.TenantID
			}
			present := slices.ContainsFunc(current, func(candidate Principal) bool { return candidate.ID == principal.ID })
			if managed && !present {
				if err := service.revokeDirectoryPrincipal(ctx, principal); err != nil && !errors.Is(err, ErrUnauthorized) {
					return err
				}
			}
		}
	}
	return nil
}

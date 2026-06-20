package warden

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type GORMStore struct {
	db *gorm.DB
}

type tenantModel struct {
	ID             string    `gorm:"primaryKey;size:64"`
	CasdoorOrgName string    `gorm:"size:255;index"`
	Slug           string    `gorm:"size:255;uniqueIndex;not null"`
	DisplayName    string    `gorm:"size:255"`
	Status         string    `gorm:"size:32;not null;default:active"`
	Plan           string    `gorm:"size:64"`
	Quota          string    `gorm:"type:text"`
	CreatedAt      time.Time `gorm:"not null"`
	UpdatedAt      time.Time `gorm:"not null"`
}

func (tenantModel) TableName() string { return "tenants" }

type principalModel struct {
	ID            string    `gorm:"primaryKey;size:64"`
	TenantID      string    `gorm:"size:64;not null;index"`
	CasdoorUserID string    `gorm:"size:255;index"`
	Username      string    `gorm:"size:255;index"`
	Email         string    `gorm:"size:320;index"`
	DisplayName   string    `gorm:"size:255"`
	Type          string    `gorm:"size:32;not null;index"`
	Status        string    `gorm:"size:32;not null;default:active"`
	CreatedAt     time.Time `gorm:"not null"`
	UpdatedAt     time.Time `gorm:"not null"`
}

func (principalModel) TableName() string { return "principals" }

type teamModel struct {
	ID             string    `gorm:"primaryKey;size:64"`
	TenantID       string    `gorm:"size:64;not null;index"`
	CasdoorGroupID string    `gorm:"size:255;index"`
	Name           string    `gorm:"size:255;not null;index"`
	DisplayName    string    `gorm:"size:255"`
	ParentTeamID   string    `gorm:"size:64;index"`
	Status         string    `gorm:"size:32;not null;default:active"`
	CreatedAt      time.Time `gorm:"not null"`
	UpdatedAt      time.Time `gorm:"not null"`
}

func (teamModel) TableName() string { return "teams" }

type principalTeamModel struct {
	PrincipalID string    `gorm:"primaryKey;size:64"`
	TeamID      string    `gorm:"primaryKey;size:64"`
	IsPrimary   bool      `gorm:"not null;default:false"`
	CreatedAt   time.Time `gorm:"not null"`
}

func (principalTeamModel) TableName() string { return "principal_teams" }

type principalRoleModel struct {
	PrincipalID string    `gorm:"primaryKey;size:64"`
	RoleKey     string    `gorm:"primaryKey;size:128"`
	ScopeType   string    `gorm:"primaryKey;size:32"`
	ScopeID     string    `gorm:"primaryKey;size:64"`
	CreatedAt   time.Time `gorm:"not null"`
}

func (principalRoleModel) TableName() string { return "principal_roles" }

type serviceAccountModel struct {
	ID        string    `gorm:"primaryKey;size:64"`
	TenantID  string    `gorm:"size:64;not null;index"`
	Name      string    `gorm:"size:255;not null"`
	Status    string    `gorm:"size:32;not null;default:active"`
	CreatedBy string    `gorm:"size:64"`
	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time
}

func (serviceAccountModel) TableName() string { return "service_accounts" }

type oidcLoginStateModel struct {
	State        string     `gorm:"primaryKey;size:255"`
	Nonce        string     `gorm:"size:255;not null"`
	CodeVerifier string     `gorm:"size:255;not null"`
	RedirectURL  string     `gorm:"size:2048"`
	ExpiresAt    *time.Time `gorm:"index"`
	CreatedAt    time.Time  `gorm:"not null"`
}

func (oidcLoginStateModel) TableName() string { return "oidc_login_states" }

type deviceCodeModel struct {
	DeviceCode  string     `gorm:"primaryKey;size:255"`
	UserCode    string     `gorm:"size:64;uniqueIndex;not null"`
	PrincipalID string     `gorm:"size:64;index"`
	ExpiresAt   *time.Time `gorm:"index"`
	IntervalSec int        `gorm:"not null;default:5"`
	Status      string     `gorm:"size:32;not null;index"`
	CreatedAt   time.Time  `gorm:"not null"`
	UpdatedAt   time.Time  `gorm:"not null"`
}

func (deviceCodeModel) TableName() string { return "device_codes" }

type apiKeyModel struct {
	ID            string     `gorm:"primaryKey;size:64"`
	Name          string     `gorm:"size:255"`
	TenantID      string     `gorm:"size:64;not null;index"`
	PrincipalType string     `gorm:"size:32;not null"`
	PrincipalID   string     `gorm:"size:64;not null;index"`
	KeyHash       string     `gorm:"size:128;uniqueIndex;not null"`
	Scopes        stringList `gorm:"type:text"`
	ExpiresAt     *time.Time `gorm:"index"`
	Status        string     `gorm:"size:32;not null;default:active"`
	CreatedAt     time.Time  `gorm:"not null"`
	LastUsedAt    *time.Time `gorm:"index"`
}

func (apiKeyModel) TableName() string { return "api_keys" }

type sessionModel struct {
	ID            string     `gorm:"primaryKey;size:64"`
	PrincipalID   string     `gorm:"size:64;not null;index"`
	TenantID      string     `gorm:"size:64;not null;index"`
	CurrentTeamID string     `gorm:"size:64;index"`
	AuthTime      time.Time  `gorm:"not null"`
	ExpiresAt     *time.Time `gorm:"index"`
	Source        string     `gorm:"size:64;not null"`
	UserAgentHash string     `gorm:"size:128"`
	CreatedAt     time.Time  `gorm:"not null"`
	UpdatedAt     time.Time  `gorm:"not null"`
}

func (sessionModel) TableName() string { return "sessions" }

type agentRunModel struct {
	ID               string    `gorm:"primaryKey;size:64"`
	TenantID         string    `gorm:"size:64;not null;index"`
	ActorPrincipalID string    `gorm:"size:64;not null;index"`
	AgentPrincipalID string    `gorm:"size:64;not null;index"`
	Status           string    `gorm:"size:32;not null;default:running"`
	CreatedAt        time.Time `gorm:"not null"`
	UpdatedAt        time.Time `gorm:"not null"`
}

func (agentRunModel) TableName() string { return "agent_runs" }

type auditLogModel struct {
	ID            uint      `gorm:"primaryKey;autoIncrement"`
	TenantID      string    `gorm:"size:64;index"`
	ActorType     string    `gorm:"size:32"`
	ActorID       string    `gorm:"size:64"`
	PrincipalType string    `gorm:"size:32;index"`
	PrincipalID   string    `gorm:"size:64;index"`
	Action        string    `gorm:"size:128;not null;index"`
	ResourceType  string    `gorm:"size:64;index"`
	ResourceID    string    `gorm:"size:128;index"`
	Decision      string    `gorm:"size:32;not null"`
	JWTID         string    `gorm:"size:128;index"`
	CreatedAt     time.Time `gorm:"not null;index"`
}

func (auditLogModel) TableName() string { return "audit_logs" }

type stringList []string

func (l stringList) Value() (driver.Value, error) {
	if l == nil {
		return "[]", nil
	}
	b, err := json.Marshal([]string(l))
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (l *stringList) Scan(value any) error {
	if value == nil {
		*l = nil
		return nil
	}
	var raw []byte
	switch v := value.(type) {
	case string:
		raw = []byte(v)
	case []byte:
		raw = v
	default:
		return fmt.Errorf("scan stringList: unsupported type %T", value)
	}
	if len(raw) == 0 {
		*l = nil
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("scan stringList: %w", err)
	}
	*l = out
	return nil
}

func OpenGORMStore(ctx context.Context, dsn string) (*GORMStore, error) {
	db, err := openWardenGORMDB(dsn)
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("database handle: %w", err)
	}
	if strings.HasPrefix(dsn, "sqlite://") {
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	} else {
		sqlDB.SetMaxOpenConns(25)
		sqlDB.SetMaxIdleConns(10)
	}
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("database ping: %w", err)
	}
	store := &GORMStore{db: db}
	if err := store.AutoMigrate(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return store, nil
}

func NewGORMStore(db *gorm.DB) (*GORMStore, error) {
	if db == nil {
		return nil, ErrInvalidInput
	}
	return &GORMStore{db: db}, nil
}

func (s *GORMStore) AutoMigrate(ctx context.Context) error {
	if err := s.db.WithContext(ctx).AutoMigrate(
		&tenantModel{},
		&principalModel{},
		&teamModel{},
		&principalTeamModel{},
		&principalRoleModel{},
		&serviceAccountModel{},
		&oidcLoginStateModel{},
		&deviceCodeModel{},
		&apiKeyModel{},
		&sessionModel{},
		&agentRunModel{},
		&auditLogModel{},
	); err != nil {
		return fmt.Errorf("database migrate: %w", err)
	}
	return nil
}

func (s *GORMStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (s *GORMStore) ListTenants(ctx context.Context, limit int) ([]Tenant, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var models []tenantModel
	if err := s.db.WithContext(ctx).Order("created_at DESC").Limit(limit).Find(&models).Error; err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	out := make([]Tenant, 0, len(models))
	for _, model := range models {
		out = append(out, Tenant{
			ID:             model.ID,
			CasdoorOrgName: model.CasdoorOrgName,
			Slug:           model.Slug,
			DisplayName:    model.DisplayName,
			Status:         model.Status,
		})
	}
	return out, nil
}

func (s *GORMStore) ListPrincipals(ctx context.Context, tenantID string, limit int) ([]Principal, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := s.db.WithContext(ctx).Order("created_at DESC").Limit(limit)
	if strings.TrimSpace(tenantID) != "" {
		q = q.Where("tenant_id = ?", strings.TrimSpace(tenantID))
	}
	var models []principalModel
	if err := q.Find(&models).Error; err != nil {
		return nil, fmt.Errorf("list principals: %w", err)
	}
	out := make([]Principal, 0, len(models))
	for _, model := range models {
		out = append(out, Principal{
			ID: model.ID, TenantID: model.TenantID, CasdoorUserID: model.CasdoorUserID,
			Username: model.Username, Email: model.Email, DisplayName: model.DisplayName,
			Type: model.Type, Status: model.Status,
		})
	}
	return out, nil
}

func (s *GORMStore) ListSessions(ctx context.Context, tenantID string, limit int) ([]Session, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := s.db.WithContext(ctx).Order("created_at DESC").Limit(limit)
	if strings.TrimSpace(tenantID) != "" {
		q = q.Where("tenant_id = ?", strings.TrimSpace(tenantID))
	}
	var models []sessionModel
	if err := q.Find(&models).Error; err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	out := make([]Session, 0, len(models))
	for _, model := range models {
		out = append(out, sessionFromGORMModel(model))
	}
	return out, nil
}

func (s *GORMStore) ListAgentRuns(ctx context.Context, tenantID string, limit int) ([]AgentRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := s.db.WithContext(ctx).Order("created_at DESC").Limit(limit)
	if strings.TrimSpace(tenantID) != "" {
		q = q.Where("tenant_id = ?", strings.TrimSpace(tenantID))
	}
	var models []agentRunModel
	if err := q.Find(&models).Error; err != nil {
		return nil, fmt.Errorf("list agent runs: %w", err)
	}
	out := make([]AgentRun, 0, len(models))
	for _, model := range models {
		out = append(out, AgentRun{
			ID: model.ID, TenantID: model.TenantID, ActorPrincipalID: model.ActorPrincipalID,
			AgentPrincipalID: model.AgentPrincipalID, Status: model.Status, CreatedAt: model.CreatedAt,
		})
	}
	return out, nil
}

func (s *GORMStore) ListAuditEvents(ctx context.Context, tenantID string, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := s.db.WithContext(ctx).Order("created_at DESC").Limit(limit)
	if strings.TrimSpace(tenantID) != "" {
		q = q.Where("tenant_id = ?", strings.TrimSpace(tenantID))
	}
	var models []auditLogModel
	if err := q.Find(&models).Error; err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	out := make([]AuditEvent, 0, len(models))
	for _, model := range models {
		out = append(out, AuditEvent{
			TenantID: model.TenantID, ActorType: model.ActorType, ActorID: model.ActorID,
			PrincipalType: model.PrincipalType, PrincipalID: model.PrincipalID, Action: model.Action,
			ResourceType: model.ResourceType, ResourceID: model.ResourceID, Decision: model.Decision,
			JWTID: model.JWTID, CreatedAt: model.CreatedAt,
		})
	}
	return out, nil
}

func openWardenGORMDB(dsn string) (*gorm.DB, error) {
	cfg := &gorm.Config{
		Logger: gormlogger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags),
			gormlogger.Config{
				SlowThreshold:             200 * time.Millisecond,
				LogLevel:                  gormlogger.Warn,
				IgnoreRecordNotFoundError: true,
			},
		),
	}
	if strings.HasPrefix(dsn, "sqlite://") {
		path := strings.TrimPrefix(dsn, "sqlite://")
		if err := ensureWardenSQLiteDir(path); err != nil {
			return nil, err
		}
		if !strings.Contains(path, "?") {
			path += "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
		}
		return gorm.Open(sqlite.Open(path), cfg)
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return gorm.Open(postgres.Open(dsn), cfg)
	}
	return nil, fmt.Errorf("unsupported database dsn %q", dsn)
}

func ensureWardenSQLiteDir(path string) error {
	dbPath, _, _ := strings.Cut(path, "?")
	if dbPath == "" || dbPath == ":memory:" || strings.HasPrefix(dbPath, "file:") {
		return nil
	}
	dir := filepath.Dir(dbPath)
	if dir == "." || dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create sqlite database dir: %w", err)
	}
	return nil
}

func (s *GORMStore) UpsertTenant(ctx context.Context, tenant Tenant) error {
	now := time.Now().UTC()
	model := tenantModel{
		ID:             tenant.ID,
		CasdoorOrgName: tenant.CasdoorOrgName,
		Slug:           tenant.Slug,
		DisplayName:    tenant.DisplayName,
		Status:         defaultString(tenant.Status, "active"),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.db.WithContext(ctx).Save(&model).Error; err != nil {
		return fmt.Errorf("upsert tenant: %w", err)
	}
	return nil
}

func (s *GORMStore) UpsertPrincipal(ctx context.Context, principal Principal) error {
	now := time.Now().UTC()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		model := principalModel{
			ID:            principal.ID,
			TenantID:      principal.TenantID,
			CasdoorUserID: principal.CasdoorUserID,
			Username:      principal.Username,
			Email:         principal.Email,
			DisplayName:   principal.DisplayName,
			Type:          defaultString(principal.Type, PrincipalTypeUser),
			Status:        defaultString(principal.Status, "active"),
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if err := tx.Save(&model).Error; err != nil {
			return fmt.Errorf("upsert principal: %w", err)
		}
		if err := tx.Where("principal_id = ?", principal.ID).Delete(&principalRoleModel{}).Error; err != nil {
			return fmt.Errorf("replace principal roles: %w", err)
		}
		for _, role := range principal.Roles {
			if strings.TrimSpace(role.Key) == "" {
				continue
			}
			if err := tx.Create(&principalRoleModel{
				PrincipalID: principal.ID,
				RoleKey:     role.Key,
				ScopeType:   role.ScopeType,
				ScopeID:     role.ScopeID,
				CreatedAt:   now,
			}).Error; err != nil {
				return fmt.Errorf("create principal role: %w", err)
			}
		}
		if err := tx.Where("principal_id = ?", principal.ID).Delete(&principalTeamModel{}).Error; err != nil {
			return fmt.Errorf("replace principal teams: %w", err)
		}
		for i, team := range principal.Teams {
			if strings.TrimSpace(team.ID) == "" {
				continue
			}
			tm := teamModel{
				ID:             team.ID,
				TenantID:       defaultString(team.TenantID, principal.TenantID),
				CasdoorGroupID: team.CasdoorGroupID,
				Name:           team.Name,
				DisplayName:    team.DisplayName,
				ParentTeamID:   team.ParentTeamID,
				Status:         defaultString(team.Status, "active"),
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			if err := tx.Save(&tm).Error; err != nil {
				return fmt.Errorf("upsert principal team: %w", err)
			}
			if err := tx.Create(&principalTeamModel{PrincipalID: principal.ID, TeamID: team.ID, IsPrimary: i == 0, CreatedAt: now}).Error; err != nil {
				return fmt.Errorf("create principal team link: %w", err)
			}
		}
		return nil
	})
}

func (s *GORMStore) GetTenant(ctx context.Context, tenantID string) (Tenant, error) {
	var model tenantModel
	err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Tenant{}, ErrNotFound
	}
	if err != nil {
		return Tenant{}, fmt.Errorf("get tenant: %w", err)
	}
	return Tenant{
		ID: model.ID, CasdoorOrgName: model.CasdoorOrgName, Slug: model.Slug,
		DisplayName: model.DisplayName, Status: model.Status,
	}, nil
}

func (s *GORMStore) GetPrincipal(ctx context.Context, principalID string) (Principal, error) {
	var principal principalModel
	err := s.db.WithContext(ctx).Where("id = ?", principalID).First(&principal).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Principal{}, ErrNotFound
	}
	if err != nil {
		return Principal{}, fmt.Errorf("get principal: %w", err)
	}
	var roleModels []principalRoleModel
	if err := s.db.WithContext(ctx).Where("principal_id = ?", principalID).Find(&roleModels).Error; err != nil {
		return Principal{}, fmt.Errorf("get principal roles: %w", err)
	}
	var teamModels []teamModel
	if err := s.db.WithContext(ctx).
		Table("teams").
		Select("teams.*").
		Joins("JOIN principal_teams ON principal_teams.team_id = teams.id").
		Where("principal_teams.principal_id = ?", principalID).
		Order("principal_teams.is_primary DESC, teams.name ASC").
		Find(&teamModels).Error; err != nil {
		return Principal{}, fmt.Errorf("get principal teams: %w", err)
	}
	return principalFromModels(principal, roleModels, teamModels), nil
}

func (s *GORMStore) ListPrincipalsByCasdoorUser(ctx context.Context, casdoorUserID string) ([]Principal, error) {
	casdoorUserID = strings.TrimSpace(casdoorUserID)
	if casdoorUserID == "" {
		return nil, nil
	}
	var principals []principalModel
	if err := s.db.WithContext(ctx).Where("casdoor_user_id = ?", casdoorUserID).Order("tenant_id ASC").Find(&principals).Error; err != nil {
		return nil, fmt.Errorf("list principals by casdoor user: %w", err)
	}
	out := make([]Principal, 0, len(principals))
	for _, principal := range principals {
		loaded, err := s.GetPrincipal(ctx, principal.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, loaded)
	}
	return out, nil
}

func (s *GORMStore) PutOIDCLoginState(ctx context.Context, state OIDCLoginState) error {
	model := oidcLoginStateModel{
		State: state.State, Nonce: state.Nonce, CodeVerifier: state.CodeVerifier,
		RedirectURL: state.RedirectURL, ExpiresAt: timePtrOrNil(state.ExpiresAt), CreatedAt: time.Now().UTC(),
	}
	if err := s.db.WithContext(ctx).Save(&model).Error; err != nil {
		return fmt.Errorf("put oidc login state: %w", err)
	}
	return nil
}

func (s *GORMStore) TakeOIDCLoginState(ctx context.Context, stateValue string) (OIDCLoginState, error) {
	var state oidcLoginStateModel
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("state = ?", stateValue).First(&state).Error; err != nil {
			return err
		}
		if err := tx.Where("state = ?", stateValue).Delete(&oidcLoginStateModel{}).Error; err != nil {
			return err
		}
		return nil
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return OIDCLoginState{}, ErrNotFound
	}
	if err != nil {
		return OIDCLoginState{}, fmt.Errorf("take oidc login state: %w", err)
	}
	return OIDCLoginState{
		State: state.State, Nonce: state.Nonce, CodeVerifier: state.CodeVerifier,
		RedirectURL: state.RedirectURL, ExpiresAt: timeValue(state.ExpiresAt),
	}, nil
}

func (s *GORMStore) PutDeviceCode(ctx context.Context, code DeviceCode) error {
	now := time.Now().UTC()
	model := deviceCodeModel{
		DeviceCode: code.DeviceCode, UserCode: code.UserCode, PrincipalID: code.PrincipalID,
		ExpiresAt: timePtrOrNil(code.ExpiresAt), IntervalSec: int(code.Interval / time.Second),
		Status: defaultString(code.Status, "pending"), CreatedAt: defaultTime(code.CreatedAt), UpdatedAt: now,
	}
	if model.IntervalSec <= 0 {
		model.IntervalSec = 5
	}
	if err := s.db.WithContext(ctx).Save(&model).Error; err != nil {
		return fmt.Errorf("put device code: %w", err)
	}
	return nil
}

func (s *GORMStore) GetDeviceCode(ctx context.Context, deviceCode string) (DeviceCode, error) {
	var model deviceCodeModel
	err := s.db.WithContext(ctx).Where("device_code = ?", deviceCode).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return DeviceCode{}, ErrNotFound
	}
	if err != nil {
		return DeviceCode{}, fmt.Errorf("get device code: %w", err)
	}
	return deviceCodeFromModel(model), nil
}

func (s *GORMStore) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (DeviceCode, error) {
	var model deviceCodeModel
	err := s.db.WithContext(ctx).Where("user_code = ?", userCode).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return DeviceCode{}, ErrNotFound
	}
	if err != nil {
		return DeviceCode{}, fmt.Errorf("get device code by user code: %w", err)
	}
	return deviceCodeFromModel(model), nil
}

func (s *GORMStore) UpdateDeviceCode(ctx context.Context, code DeviceCode) error {
	result := s.db.WithContext(ctx).Model(&deviceCodeModel{}).
		Where("device_code = ?", code.DeviceCode).
		Updates(map[string]any{
			"principal_id": code.PrincipalID,
			"expires_at":   timePtrOrNil(code.ExpiresAt),
			"interval_sec": int(code.Interval / time.Second),
			"status":       code.Status,
			"updated_at":   time.Now().UTC(),
		})
	if result.Error != nil {
		return fmt.Errorf("update device code: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *GORMStore) PutSession(ctx context.Context, session Session) error {
	now := time.Now().UTC()
	model := sessionModel{
		ID:            session.ID,
		PrincipalID:   session.PrincipalID,
		TenantID:      session.TenantID,
		CurrentTeamID: session.CurrentTeamID,
		AuthTime:      session.AuthTime,
		ExpiresAt:     timePtrOrNil(session.ExpiresAt),
		Source:        session.Source,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.db.WithContext(ctx).Save(&model).Error; err != nil {
		return fmt.Errorf("put session: %w", err)
	}
	return nil
}

func (s *GORMStore) GetSession(ctx context.Context, sessionID string) (Session, error) {
	var model sessionModel
	err := s.db.WithContext(ctx).Where("id = ?", sessionID).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("get session: %w", err)
	}
	return sessionFromGORMModel(model), nil
}

func sessionFromGORMModel(model sessionModel) Session {
	return Session{
		ID: model.ID, PrincipalID: model.PrincipalID, TenantID: model.TenantID,
		CurrentTeamID: model.CurrentTeamID, AuthTime: model.AuthTime, ExpiresAt: timeValue(model.ExpiresAt), Source: model.Source,
	}
}

func (s *GORMStore) UpdateSessionContext(ctx context.Context, sessionID, principalID, tenantID, teamID string) error {
	result := s.db.WithContext(ctx).Model(&sessionModel{}).
		Where("id = ?", sessionID).
		Updates(map[string]any{
			"principal_id":    principalID,
			"tenant_id":       tenantID,
			"current_team_id": teamID,
			"updated_at":      time.Now().UTC(),
		})
	if result.Error != nil {
		return fmt.Errorf("update session context: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *GORMStore) DeleteSession(ctx context.Context, sessionID string) error {
	if err := s.db.WithContext(ctx).Where("id = ?", sessionID).Delete(&sessionModel{}).Error; err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *GORMStore) DeleteSessionsByPrincipal(ctx context.Context, principalID string) error {
	if err := s.db.WithContext(ctx).Where("principal_id = ?", principalID).Delete(&sessionModel{}).Error; err != nil {
		return fmt.Errorf("delete sessions by principal: %w", err)
	}
	return nil
}

func (s *GORMStore) PutServiceAccount(ctx context.Context, account ServiceAccount) error {
	now := time.Now().UTC()
	model := serviceAccountModel{
		ID: account.ID, TenantID: account.TenantID, Name: account.Name,
		Status: defaultString(account.Status, "active"), CreatedBy: account.CreatedBy, CreatedAt: defaultTime(account.CreatedAt),
		UpdatedAt: now,
	}
	if err := s.db.WithContext(ctx).Save(&model).Error; err != nil {
		return fmt.Errorf("put service account: %w", err)
	}
	return nil
}

func (s *GORMStore) ListServiceAccounts(ctx context.Context, tenantID string) ([]ServiceAccount, error) {
	q := s.db.WithContext(ctx).Order("created_at DESC")
	if strings.TrimSpace(tenantID) != "" {
		q = q.Where("tenant_id = ?", strings.TrimSpace(tenantID))
	}
	var models []serviceAccountModel
	if err := q.Find(&models).Error; err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	out := make([]ServiceAccount, 0, len(models))
	for _, model := range models {
		out = append(out, ServiceAccount{
			ID: model.ID, TenantID: model.TenantID, Name: model.Name,
			Status: model.Status, CreatedBy: model.CreatedBy, CreatedAt: model.CreatedAt,
		})
	}
	return out, nil
}

func (s *GORMStore) DisableServiceAccount(ctx context.Context, accountID, tenantID string) error {
	result := s.db.WithContext(ctx).Model(&serviceAccountModel{}).
		Where("id = ? AND tenant_id = ?", accountID, tenantID).
		Updates(map[string]any{"status": "disabled", "updated_at": time.Now().UTC()})
	if result.Error != nil {
		return fmt.Errorf("disable service account: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	if err := s.db.WithContext(ctx).Model(&principalModel{}).
		Where("id = ? AND tenant_id = ?", accountID, tenantID).
		Updates(map[string]any{"status": "disabled", "updated_at": time.Now().UTC()}).Error; err != nil {
		return fmt.Errorf("disable service account principal: %w", err)
	}
	return nil
}

func (s *GORMStore) PutAPIKey(ctx context.Context, key APIKey) error {
	model := apiKeyModel{
		ID: key.ID, Name: key.Name, TenantID: key.TenantID, PrincipalType: key.PrincipalType, PrincipalID: key.PrincipalID,
		KeyHash: key.KeyHash, Scopes: stringList(key.Scopes), ExpiresAt: timePtrOrNil(key.ExpiresAt),
		Status: defaultString(key.Status, "active"), CreatedAt: defaultTime(key.CreatedAt), LastUsedAt: timePtrOrNil(key.LastUsedAt),
	}
	if err := s.db.WithContext(ctx).Save(&model).Error; err != nil {
		return fmt.Errorf("put api key: %w", err)
	}
	return nil
}

func (s *GORMStore) GetAPIKeyByHash(ctx context.Context, keyHash string) (APIKey, error) {
	var model apiKeyModel
	err := s.db.WithContext(ctx).Where("key_hash = ?", keyHash).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return APIKey{}, ErrNotFound
	}
	if err != nil {
		return APIKey{}, fmt.Errorf("get api key: %w", err)
	}
	return APIKey{
		ID: model.ID, Name: model.Name, TenantID: model.TenantID, PrincipalType: model.PrincipalType, PrincipalID: model.PrincipalID,
		KeyHash: model.KeyHash, Scopes: []string(model.Scopes), ExpiresAt: timeValue(model.ExpiresAt), Status: model.Status, CreatedAt: model.CreatedAt,
		LastUsedAt: timeValue(model.LastUsedAt),
	}, nil
}

func (s *GORMStore) ListAPIKeys(ctx context.Context, principalID string) ([]APIKey, error) {
	var models []apiKeyModel
	if err := s.db.WithContext(ctx).Where("principal_id = ?", principalID).Order("created_at DESC").Find(&models).Error; err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	out := make([]APIKey, 0, len(models))
	for _, model := range models {
		out = append(out, APIKey{
			ID: model.ID, Name: model.Name, TenantID: model.TenantID, PrincipalType: model.PrincipalType, PrincipalID: model.PrincipalID,
			KeyHash: model.KeyHash, Scopes: []string(model.Scopes), ExpiresAt: timeValue(model.ExpiresAt), Status: model.Status, CreatedAt: model.CreatedAt,
			LastUsedAt: timeValue(model.LastUsedAt),
		})
	}
	return out, nil
}

func (s *GORMStore) RevokeAPIKey(ctx context.Context, keyID, principalID string) error {
	result := s.db.WithContext(ctx).Model(&apiKeyModel{}).
		Where("id = ? AND principal_id = ?", keyID, principalID).
		Update("status", "revoked")
	if result.Error != nil {
		return fmt.Errorf("revoke api key: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *GORMStore) TouchAPIKeyLastUsed(ctx context.Context, keyID string, lastUsedAt time.Time) error {
	if lastUsedAt.IsZero() {
		lastUsedAt = time.Now().UTC()
	}
	result := s.db.WithContext(ctx).Model(&apiKeyModel{}).Where("id = ?", keyID).Update("last_used_at", lastUsedAt.UTC())
	if result.Error != nil {
		return fmt.Errorf("touch api key last used: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *GORMStore) PutAgentRun(ctx context.Context, run AgentRun) error {
	now := time.Now().UTC()
	model := agentRunModel{
		ID: run.ID, TenantID: run.TenantID, ActorPrincipalID: run.ActorPrincipalID, AgentPrincipalID: run.AgentPrincipalID,
		Status: defaultString(run.Status, "running"), CreatedAt: defaultTime(run.CreatedAt), UpdatedAt: now,
	}
	if err := s.db.WithContext(ctx).Save(&model).Error; err != nil {
		return fmt.Errorf("put agent run: %w", err)
	}
	return nil
}

func (s *GORMStore) AppendAudit(ctx context.Context, event AuditEvent) error {
	model := auditLogModel{
		TenantID: event.TenantID, ActorType: event.ActorType, ActorID: event.ActorID,
		PrincipalType: event.PrincipalType, PrincipalID: event.PrincipalID, Action: event.Action,
		ResourceType: event.ResourceType, ResourceID: event.ResourceID, Decision: event.Decision,
		JWTID: event.JWTID, CreatedAt: defaultTime(event.CreatedAt),
	}
	if err := s.db.WithContext(ctx).Create(&model).Error; err != nil {
		return fmt.Errorf("append audit: %w", err)
	}
	return nil
}

func principalFromModels(principal principalModel, roles []principalRoleModel, teams []teamModel) Principal {
	out := Principal{
		ID: principal.ID, TenantID: principal.TenantID, CasdoorUserID: principal.CasdoorUserID,
		Username: principal.Username, Email: principal.Email, DisplayName: principal.DisplayName,
		Type: principal.Type, Status: principal.Status,
	}
	out.Roles = make([]RoleGrant, 0, len(roles))
	for _, role := range roles {
		out.Roles = append(out.Roles, RoleGrant{Key: role.RoleKey, ScopeType: role.ScopeType, ScopeID: role.ScopeID})
	}
	out.Teams = make([]Team, 0, len(teams))
	for _, team := range teams {
		out.Teams = append(out.Teams, Team{
			ID: team.ID, TenantID: team.TenantID, CasdoorGroupID: team.CasdoorGroupID,
			Name: team.Name, DisplayName: team.DisplayName, ParentTeamID: team.ParentTeamID, Status: team.Status,
		})
	}
	return out
}

func deviceCodeFromModel(model deviceCodeModel) DeviceCode {
	return DeviceCode{
		DeviceCode:  model.DeviceCode,
		UserCode:    model.UserCode,
		PrincipalID: model.PrincipalID,
		ExpiresAt:   timeValue(model.ExpiresAt),
		Interval:    time.Duration(model.IntervalSec) * time.Second,
		Status:      model.Status,
		CreatedAt:   model.CreatedAt,
	}
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func defaultTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}

func timePtrOrNil(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	v := value.UTC()
	return &v
}

func timeValue(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.UTC()
}

package wardn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrRevoked 表示原生账号停用、删除或会话已撤销。
var ErrRevoked = errors.New("wardn: session revoked")

// ErrUnavailable 表示身份服务暂不可用；不能据此宣称账号已退出。
var ErrUnavailable = errors.New("wardn: identity unavailable")

// AccountState 来自原生账号，仅用于私有账号页；不携带业务角色。
type AccountState struct {
	Active        bool   `json:"active"`
	Subject       string `json:"sub"`
	Owner         string `json:"owner"`
	Revision      int64  `json:"revision"`
	DisplayName   string `json:"displayName"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Avatar        string `json:"avatar"`
}

// Profile 复用统一的昵称及已验证邮箱规则。
func (s AccountState) Profile() Claims {
	verified := s.EmailVerified
	return Claims{Subject: s.Subject, Owner: s.Owner, DisplayName: s.DisplayName, Name: s.Name, Email: s.Email, EmailVerified: &verified}
}

type accountSnapshot struct {
	state     AccountState
	err       error
	until     time.Time
	done      chan struct{}
	abandoned bool
}

// Accounts 是按 issuer/client/region 配置隔离的原生账号客户端。
// 正向缓存至多两秒，故障不会延用过期授权；缓存有界并合并并发查询。
type Accounts struct {
	cfg        Config
	http       *http.Client
	mu         sync.Mutex
	cache      map[string]*accountSnapshot
	generation uint64
}

// NewAccounts 无需重复 discovery；只访问已配置 issuer 的固定原生账号端点。
func NewAccounts(cfg Config) (*Accounts, error) {
	if cfg.Organization == "" {
		cfg.Organization = "saker"
	}
	if !validURL(cfg.Issuer, cfg.AllowInsecureLoopback) || strings.HasSuffix(cfg.Issuer, "/") || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, ErrLogin
	}
	u, _ := url.Parse(cfg.Issuer)
	if u.RawQuery != "" {
		return nil, ErrLogin
	}
	transport := http.DefaultTransport
	if cfg.HTTPClient != nil && cfg.HTTPClient.Transport != nil {
		transport = cfg.HTTPClient.Transport
	}
	return &Accounts{cfg: cfg, http: &http.Client{Timeout: 5 * time.Second, Transport: boundedTransport{transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUnavailable }}, cache: make(map[string]*accountSnapshot)}, nil
}

// GlobalLogoutURL 打开 Wardn 原生确认页；GET 不执行退出，POST 校验原生浏览器及 CSRF。
func (a *Accounts) GlobalLogoutURL() string {
	return RegionalURL(a.cfg.Issuer+"/api/login/oauth/wardn-global-logout", a.cfg.Region)
}

// Capture 在登录回调中绑定仍有效的原生 ID token 与当前撤销版本。
// 原始 token 仅用于本次请求，不持久化也不进入浏览器。
func (a *Accounts) Capture(ctx context.Context, subject, idToken string) (AccountState, error) {
	if idToken == "" {
		return AccountState{}, ErrLogin
	}
	if ctx.Err() != nil {
		return AccountState{}, ErrUnavailable
	}
	a.mu.Lock()
	generation := a.generation
	a.mu.Unlock()
	state, err := a.fetch(ctx, subject, idToken)
	if err != nil {
		return AccountState{}, err
	}
	if ctx.Err() != nil {
		return AccountState{}, ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	entry := a.cache[subject]
	if entry != nil && entry.done == nil && entry.err == nil && entry.state.Revision > state.Revision {
		return AccountState{}, ErrRevoked
	}
	// 并发失效或查询后不预热，避免晚到的登录结果覆盖新的撤销状态。
	if a.generation == generation && (entry == nil || entry.done == nil) && a.cacheRoomLocked(subject) {
		a.cache[subject] = &accountSnapshot{state: state, until: time.Now().Add(2 * time.Second)}
		a.generation++
	}
	return state, nil
}

// Check 校验持久化会话的撤销版本，同时返回最新私有资料。
// 发布前没有版本字段的旧会话按零版本检查，首次全局撤销后失效。
func (a *Accounts) Check(ctx context.Context, subject string, revision int64) (AccountState, error) {
	if revision < 0 {
		return AccountState{}, ErrRevoked
	}
	state, err := a.current(ctx, subject)
	if err != nil {
		return AccountState{}, err
	}
	if !state.Active || state.Revision != revision {
		return AccountState{}, ErrRevoked
	}
	return state, nil
}

func (a *Accounts) current(ctx context.Context, subject string) (AccountState, error) {
	if subject == "" || len(subject) > 100 {
		return AccountState{}, ErrRevoked
	}
	for {
		if ctx.Err() != nil {
			return AccountState{}, ErrUnavailable
		}
		a.mu.Lock()
		entry := a.cache[subject]
		if entry != nil && entry.done == nil && time.Now().Before(entry.until) {
			state := entry.state
			a.mu.Unlock()
			return state, nil
		}
		if entry != nil && entry.done != nil {
			done := entry.done
			a.mu.Unlock()
			select {
			case <-done:
				a.mu.Lock()
				state, err, until, abandoned := entry.state, entry.err, entry.until, entry.abandoned
				current := a.cache[subject] == entry
				a.mu.Unlock()
				// A disconnected caller does not define the account state for
				// independent live executions waiting on its coalesced read.
				if abandoned {
					continue
				}
				if err != nil {
					return AccountState{}, err
				}
				if ctx.Err() != nil {
					return AccountState{}, ErrUnavailable
				}
				if current && time.Now().Before(until) {
					return state, nil
				}
				continue
			case <-ctx.Done():
				return AccountState{}, ErrUnavailable
			}
		}
		if !a.cacheRoomLocked(subject) {
			a.mu.Unlock()
			return AccountState{}, ErrUnavailable
		}
		entry = &accountSnapshot{done: make(chan struct{})}
		a.cache[subject] = entry
		a.generation++
		a.mu.Unlock()
		state, err := a.fetch(ctx, subject, "")
		a.mu.Lock()
		if ctx.Err() != nil {
			state, err = AccountState{}, errors.Join(ErrUnavailable, ctx.Err())
			entry.abandoned = true
		}
		entry.state, entry.err = state, err
		a.generation++
		if err == nil {
			entry.until = time.Now().Add(2 * time.Second)
		} else {
			delete(a.cache, subject)
		}
		close(entry.done)
		entry.done = nil
		a.mu.Unlock()
		return state, err
	}
}

func (a *Accounts) fetch(ctx context.Context, subject, idToken string) (AccountState, error) {
	if subject == "" || len(subject) > 100 {
		return AccountState{}, ErrRevoked
	}
	form := url.Values{"subject": {subject}}
	if idToken != "" {
		form.Set("id_token", idToken)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, RegionalURL(a.cfg.Issuer+"/api/login/oauth/wardn-account-state", a.cfg.Region), strings.NewReader(form.Encode()))
	if err != nil {
		return AccountState{}, ErrUnavailable
	}
	req.SetBasicAuth(a.cfg.ClientID, a.cfg.ClientSecret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.http.Do(req)
	if err != nil {
		return AccountState{}, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return AccountState{}, ErrRevoked
	}
	if resp.StatusCode != http.StatusOK {
		return AccountState{}, ErrUnavailable
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return AccountState{}, ErrUnavailable
	}
	if _, err = strictObject(raw); err != nil {
		return AccountState{}, ErrUnavailable
	}
	var state AccountState
	if json.Unmarshal(raw, &state) != nil || state.Subject != subject || state.Owner != a.cfg.Organization || state.Revision < 0 {
		return AccountState{}, ErrUnavailable
	}
	if !state.Active {
		return AccountState{}, ErrRevoked
	}
	return state, nil
}

// Invalidate 清除指定账号已完成的资料缓存；空 subject 清除全部已完成缓存。
// 正在执行的查询仍由原生服务决定。
func (a *Accounts) Invalidate(subject string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.generation++
	for key, entry := range a.cache {
		if (subject == "" || key == subject) && entry.done == nil {
			delete(a.cache, key)
		}
	}
}

// cacheRoomLocked 保持统一缓存预算，不因登录预热挤占正在执行的查询。
func (a *Accounts) cacheRoomLocked(subject string) bool {
	if _, exists := a.cache[subject]; exists || len(a.cache) < 1024 {
		return true
	}
	for key, entry := range a.cache {
		if entry.done == nil {
			delete(a.cache, key)
			a.generation++
			return true
		}
	}
	return false
}

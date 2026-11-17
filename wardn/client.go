package wardn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ErrLogin 表示登录资料、浏览器绑定或上游响应无效，不包含凭据与原始响应。
var ErrLogin = errors.New("wardn: invalid login")

// Config 只在服务端使用。每个应用及原生客户端使用独立的 ClientID。
type Config struct {
	Issuer, DiscoveryURL, ClientID, ClientSecret, RedirectURL, Organization string
	Region                                                                  string
	NativeRedirectScheme                                                    string
	HTTPClient                                                              *http.Client
	AllowInsecureLoopback                                                   bool
}

// Client 是可并发复用的 OIDC 客户端；业务会话和权限由应用持有。
type Client struct {
	cfg                    Config
	http                   *http.Client
	oauth                  oauth2.Config
	verifier               *oidc.IDTokenVerifier
	responseIssuerRequired bool
}

// New 校验 discovery 的 issuer 和端点来源，不接受弱签名算法或远端 HTTP。
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Organization == "" {
		cfg.Organization = "saker"
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" || strings.HasSuffix(cfg.Issuer, "/") {
		return nil, ErrLogin
	}
	if !validURL(cfg.Issuer, cfg.AllowInsecureLoopback) || !validCallback(cfg.RedirectURL, cfg) {
		return nil, ErrLogin
	}
	issuer, _ := url.Parse(cfg.Issuer)
	if issuer.RawQuery != "" {
		return nil, ErrLogin
	}
	if cfg.DiscoveryURL == "" {
		cfg.DiscoveryURL = cfg.Issuer + "/.well-known/openid-configuration"
	}
	if !sameOrigin(cfg.Issuer, cfg.DiscoveryURL, cfg.AllowInsecureLoopback) {
		return nil, ErrLogin
	}
	base := http.DefaultTransport
	if cfg.HTTPClient != nil && cfg.HTTPClient.Transport != nil {
		base = cfg.HTTPClient.Transport
	}
	h := &http.Client{Timeout: 15 * time.Second, Transport: boundedTransport{base}, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrLogin }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, RegionalURL(cfg.DiscoveryURL, cfg.Region), nil)
	if err != nil {
		return nil, ErrLogin
	}
	resp, err := h.Do(req)
	if err != nil {
		return nil, ErrLogin
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrLogin
	}
	var metadata struct {
		oidc.ProviderConfig
		ResponseIssuerRequired bool `json:"authorization_response_iss_parameter_supported"`
	}
	raw, readErr := io.ReadAll(resp.Body)
	if _, err := strictObject(raw); readErr != nil || err != nil {
		return nil, ErrLogin
	}
	if json.Unmarshal(raw, &metadata) != nil || metadata.IssuerURL != cfg.Issuer {
		return nil, ErrLogin
	}
	return NewWithMetadata(ctx, cfg, Metadata{Issuer: metadata.IssuerURL, AuthorizationURL: metadata.AuthURL, TokenURL: metadata.TokenURL, JWKSURL: metadata.JWKSURL, UserInfoURL: metadata.UserInfoURL, Algorithms: metadata.Algorithms, ResponseIssuerRequired: metadata.ResponseIssuerRequired})
}

// Attempt 只存放于服务端，禁止传给浏览器或写入公开日志。
type Attempt struct {
	StateHash, BrowserHash, Nonce, Verifier string
	ExpiresAt                               time.Time
}

// AttemptStore 必须持久化并原子消费一次性登录事务。
// Consume 必须在删除前匹配 browserHash；跨实例部署不能使用进程内 map。
type AttemptStore interface {
	Save(context.Context, Attempt) error
	Consume(ctx context.Context, stateHash, browserHash string) (Attempt, error)
}

// Begin 绑定应用自己的随机 HttpOnly 浏览器 cookie，生成 state/nonce/S256 PKCE。
// 返回授权地址，默认复用 Wardn 会话；reauthenticate 才强制重新输入凭据。
func (c *Client) Begin(ctx context.Context, store AttemptStore, browserToken string, reauthenticate bool) (string, error) {
	if store == nil || len(browserToken) < 32 || len(browserToken) > 256 {
		return "", ErrLogin
	}
	state, nonce := randomToken(), randomToken()
	a := Attempt{StateHash: hash(state), BrowserHash: hash(browserToken), Nonce: nonce, Verifier: oauth2.GenerateVerifier(), ExpiresAt: time.Now().Add(10 * time.Minute)}
	if err := store.Save(ctx, a); err != nil {
		return "", ErrLogin
	}
	return c.AuthorizationURL(AuthorizationRequest{State: state, Nonce: nonce, Verifier: a.Verifier, Reauthenticate: reauthenticate})
}

// Complete 原子消费事务，再换码和校验令牌。失败后需要重新开始登录。
func (c *Client) Complete(ctx context.Context, store AttemptStore, browserToken, state, code, responseIssuer string) (Identity, error) {
	if store == nil || len(browserToken) < 32 || len(browserToken) > 256 || len(state) != 43 || code == "" || len(code) > 4096 || c.responseIssuerRequired && responseIssuer == "" || responseIssuer != "" && responseIssuer != c.cfg.Issuer {
		return Identity{}, ErrLogin
	}
	a, err := store.Consume(ctx, hash(state), hash(browserToken))
	if err != nil || a.StateHash != hash(state) || a.BrowserHash != hash(browserToken) || !time.Now().Before(a.ExpiresAt) || a.Nonce == "" || a.Verifier == "" {
		return Identity{}, ErrLogin
	}
	token, err := c.ExchangeCode(ctx, code, a.Verifier, "")
	if err != nil {
		return Identity{}, err
	}
	return c.VerifyToken(ctx, token, a.Nonce)
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func validURL(raw string, allowLocal bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(u.Path, "\\") {
		return false
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	return u.Scheme == "https" || allowLocal && local && u.Scheme == "http"
}
func sameOrigin(issuer, endpoint string, allowLocal bool) bool {
	if !validURL(endpoint, allowLocal) {
		return false
	}
	a, _ := url.Parse(issuer)
	b, _ := url.Parse(endpoint)
	return a.Scheme == b.Scheme && a.Host == b.Host
}

type boundedTransport struct{ base http.RoundTripper }

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, ErrLogin
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return nil, ErrLogin
	}
	resp.Body = io.NopCloser(strings.NewReader(string(b)))
	return resp, nil
}

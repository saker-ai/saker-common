package wardn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
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
	if !validURL(cfg.Issuer, cfg.AllowInsecureLoopback) || !validURL(cfg.RedirectURL, cfg.AllowInsecureLoopback) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.DiscoveryURL, nil)
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
	if json.NewDecoder(resp.Body).Decode(&metadata) != nil || metadata.IssuerURL != cfg.Issuer {
		return nil, ErrLogin
	}
	for _, endpoint := range []string{metadata.AuthURL, metadata.TokenURL, metadata.JWKSURL} {
		if !sameOrigin(cfg.Issuer, endpoint, cfg.AllowInsecureLoopback) {
			return nil, ErrLogin
		}
	}
	if metadata.UserInfoURL != "" && !sameOrigin(cfg.Issuer, metadata.UserInfoURL, cfg.AllowInsecureLoopback) {
		return nil, ErrLogin
	}
	allowed := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
	algorithms := make([]string, 0, len(metadata.Algorithms))
	for _, algorithm := range metadata.Algorithms {
		if slices.Contains(allowed, algorithm) {
			algorithms = append(algorithms, algorithm)
		}
	}
	if len(algorithms) == 0 {
		return nil, ErrLogin
	}
	metadata.Algorithms = algorithms
	provider := metadata.NewProvider(oidc.ClientContext(ctx, h))
	endpoint := provider.Endpoint()
	// Wardn 原生换码使用表单凭据，避免自动探测重复提交一次性 code。
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return &Client{cfg: cfg, http: h, verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: algorithms}), responseIssuerRequired: metadata.ResponseIssuerRequired, oauth: oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL, Endpoint: endpoint, Scopes: []string{"openid", "profile", "email"}}}, nil
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
	u, _ := url.Parse(c.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(a.Verifier)))
	q := u.Query()
	q.Del("prompt")
	if reauthenticate {
		q.Set("prompt", "login")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
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
	ctx = oidc.ClientContext(ctx, c.http)
	token, err := c.oauth.Exchange(ctx, code, oauth2.VerifierOption(a.Verifier))
	if err != nil {
		return Identity{}, ErrLogin
	}
	raw, _ := token.Extra("id_token").(string)
	id, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, ErrLogin
	}
	var profile Claims
	if id.Claims(&profile) != nil || strings.TrimSpace(id.Subject) == "" || len(id.Subject) > 255 || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(a.Nonce)) != 1 || profile.Owner != c.cfg.Organization || profile.NotBefore > time.Now().Unix() || id.IssuedAt.After(time.Now().Add(5*time.Minute)) || profile.AuthorizedParty != "" && profile.AuthorizedParty != c.cfg.ClientID || len(id.Audience) > 1 && profile.AuthorizedParty != c.cfg.ClientID {
		return Identity{}, ErrLogin
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(token.AccessToken) != nil {
		return Identity{}, ErrLogin
	}
	profile.Subject = id.Subject
	return Identity{Issuer: c.cfg.Issuer, Subject: id.Subject, Profile: profile}, nil
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

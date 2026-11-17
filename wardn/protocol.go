package wardn

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Metadata 是运维配置或已验证 discovery 提供的公开端点，不包含密钥。
// 显式端点与 issuer 必须同源；应用不能从请求参数填入本结构。
type Metadata struct {
	Issuer, AuthorizationURL, TokenURL, JWKSURL, UserInfoURL string
	Algorithms                                               []string
	ResponseIssuerRequired                                   bool
}

// NewWithMetadata 接入已有显式端点配置，采用与 discovery 一致的信任边界。
func NewWithMetadata(ctx context.Context, cfg Config, m Metadata) (*Client, error) {
	if cfg.Organization == "" {
		cfg.Organization = "saker"
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" || !validURL(cfg.Issuer, cfg.AllowInsecureLoopback) || !validCallback(cfg.RedirectURL, cfg) || m.Issuer != cfg.Issuer {
		return nil, ErrLogin
	}
	issuer, _ := url.Parse(cfg.Issuer)
	if issuer.RawQuery != "" || strings.HasSuffix(cfg.Issuer, "/") {
		return nil, ErrLogin
	}
	for _, endpoint := range []string{m.AuthorizationURL, m.TokenURL, m.JWKSURL} {
		if !sameOrigin(cfg.Issuer, endpoint, cfg.AllowInsecureLoopback) {
			return nil, ErrLogin
		}
	}
	if m.UserInfoURL != "" && !sameOrigin(cfg.Issuer, m.UserInfoURL, cfg.AllowInsecureLoopback) {
		return nil, ErrLogin
	}
	allowed := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
	algorithms := make([]string, 0, len(m.Algorithms))
	for _, alg := range m.Algorithms {
		if slices.Contains(allowed, alg) {
			algorithms = append(algorithms, alg)
		}
	}
	if len(algorithms) == 0 {
		return nil, ErrLogin
	}
	base := http.DefaultTransport
	if cfg.HTTPClient != nil && cfg.HTTPClient.Transport != nil {
		base = cfg.HTTPClient.Transport
	}
	h := &http.Client{Timeout: 15 * time.Second, Transport: boundedTransport{base}, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrLogin }}
	provider := (&oidc.ProviderConfig{IssuerURL: cfg.Issuer, AuthURL: RegionalURL(m.AuthorizationURL, cfg.Region), TokenURL: RegionalURL(m.TokenURL, cfg.Region), JWKSURL: RegionalURL(m.JWKSURL, cfg.Region), UserInfoURL: RegionalURL(m.UserInfoURL, cfg.Region), Algorithms: algorithms}).NewProvider(oidc.ClientContext(ctx, h))
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return &Client{cfg: cfg, http: h, verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: algorithms}), responseIssuerRequired: m.ResponseIssuerRequired, oauth: oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL, Endpoint: endpoint, Scopes: []string{"openid", "profile", "email"}}}, nil
}

// AuthorizationRequest 复用应用已持久化的一次性事务。原生客户端可传 S256 challenge。
type AuthorizationRequest struct {
	State, Nonce, Verifier, CodeChallenge, RedirectURL string
	Reauthenticate                                     bool
}

// AuthorizationURL 统一授权参数；应用必须在回调前原子消费相应事务。
func (c *Client) AuthorizationURL(in AuthorizationRequest) (string, error) {
	redirect := in.RedirectURL
	if redirect == "" {
		redirect = c.oauth.RedirectURL
	}
	if !c.validRedirect(redirect) || in.State == "" || len(in.State) > 8192 || in.Nonce == "" || len(in.Nonce) > 512 {
		return "", ErrLogin
	}
	challenge := in.CodeChallenge
	if challenge == "" {
		if !validVerifier(in.Verifier) {
			return "", ErrLogin
		}
		challenge = oauth2.S256ChallengeFromVerifier(in.Verifier)
	}
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(challenge)
	if decodeErr != nil || len(decoded) != 32 || len(challenge) != 43 {
		return "", ErrLogin
	}
	u, _ := url.Parse(c.oauth.Endpoint.AuthURL)
	q := u.Query()
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", in.State)
	q.Set("nonce", in.Nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Del("prompt")
	if in.Reauthenticate {
		q.Set("prompt", "login")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Endpoint 返回已验证的公开 OAuth 端点，供兼容现有应用配置使用。
func (c *Client) Endpoint() oauth2.Endpoint { return c.oauth.Endpoint }

// ResponseIssuerRequired 表示 discovery 要求回调携带规范 issuer。
func (c *Client) ResponseIssuerRequired() bool { return c.responseIssuerRequired }

// ExchangeCode 只执行一次换码；应用先原子消费事务，随后调用 VerifyToken。
func (c *Client) ExchangeCode(ctx context.Context, code, verifier, redirect string) (*oauth2.Token, error) {
	if redirect == "" {
		redirect = c.oauth.RedirectURL
	}
	if !c.validRedirect(redirect) || code == "" || len(code) > 4096 || !validVerifier(verifier) {
		return nil, ErrLogin
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {c.cfg.ClientID}, "client_secret": {c.cfg.ClientSecret}, "redirect_uri": {redirect}, "code": {code}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.oauth.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, ErrLogin
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, ErrLogin
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrLogin
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrLogin
	}
	_, err = strictObject(raw)
	if err != nil {
		return nil, ErrLogin
	}
	var token struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
	}
	if json.Unmarshal(raw, &token) != nil || token.IDToken == "" || len(token.IDToken) > 16384 {
		return nil, ErrLogin
	}
	return (&oauth2.Token{AccessToken: token.AccessToken, TokenType: token.TokenType}).WithExtra(map[string]any{"id_token": token.IDToken}), nil
}

// VerifyToken 集中校验签名、issuer、audience、nonce、owner、azp、时间和 at_hash。
func (c *Client) VerifyToken(ctx context.Context, token *oauth2.Token, nonce string) (Identity, error) {
	if token == nil || nonce == "" {
		return Identity{}, ErrLogin
	}
	raw, _ := token.Extra("id_token").(string)
	if raw == "" || len(raw) > 16384 {
		return Identity{}, ErrLogin
	}
	id, err := c.verifier.Verify(oidc.ClientContext(ctx, c.http), raw)
	if err != nil {
		return Identity{}, ErrLogin
	}
	var profile Claims
	if subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(nonce)) != 1 {
		return Identity{}, fmt.Errorf("%w: nonce mismatch", ErrLogin)
	}
	if id.Claims(&profile) == nil && profile.Owner != c.cfg.Organization {
		return Identity{}, fmt.Errorf("%w: organization mismatch", ErrLogin)
	}
	if id.Claims(&profile) != nil || strings.TrimSpace(id.Subject) == "" || len(id.Subject) > 255 || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(nonce)) != 1 || profile.Owner != c.cfg.Organization || profile.NotBefore > time.Now().Unix() || id.IssuedAt.After(time.Now().Add(5*time.Minute)) || profile.AuthorizedParty != "" && profile.AuthorizedParty != c.cfg.ClientID || len(id.Audience) > 1 && profile.AuthorizedParty != c.cfg.ClientID {
		return Identity{}, ErrLogin
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(token.AccessToken) != nil {
		return Identity{}, ErrLogin
	}
	profile.Subject = id.Subject
	return Identity{Issuer: c.cfg.Issuer, Subject: id.Subject, Profile: profile}, nil
}

func (c *Client) validRedirect(raw string) bool {
	if raw == c.cfg.RedirectURL {
		return validCallback(raw, c.cfg)
	}
	return validURL(raw, c.cfg.AllowInsecureLoopback) && sameOrigin(c.cfg.RedirectURL, raw, c.cfg.AllowInsecureLoopback)
}
func validCallback(raw string, cfg Config) bool {
	if validURL(raw, cfg.AllowInsecureLoopback) {
		return true
	}
	u, err := url.Parse(raw)
	return err == nil && cfg.NativeRedirectScheme != "" && cfg.NativeRedirectScheme != "http" && cfg.NativeRedirectScheme != "https" && u.Scheme == cfg.NativeRedirectScheme && u.Host != "" && u.User == nil && u.Fragment == "" && u.RawQuery == ""
}

func validVerifier(s string) bool {
	return len(s) >= 43 && len(s) <= 128 && !strings.ContainsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~", r))
	})
}

// RegionalURL 只重写 Wardn 的传输路径；规范 issuer 始终保持不变。
func RegionalURL(raw, region string) string {
	if region != "cn" && region != "global" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "wardn.bxf.me" || u.User != nil || !strings.HasPrefix(u.Path, "/identity/") {
		return raw
	}
	u.Path = "/" + region + u.Path
	u.RawPath = ""
	return u.String()
}

// strictObject 拒绝根对象的重复字段、尾随对象和非对象响应。
func strictObject(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, ErrLogin
	}
	result := map[string]json.RawMessage{}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return nil, ErrLogin
		}
		s, ok := key.(string)
		if !ok {
			return nil, ErrLogin
		}
		if _, exists := result[s]; exists {
			return nil, ErrLogin
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrLogin
		}
		result[s] = value
	}
	if _, err = d.Token(); err != nil {
		return nil, ErrLogin
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrLogin
	}
	return result, nil
}

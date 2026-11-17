package warden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCClientConfig contains server-only relying-party configuration. Discovery
// may be application-specific; its issuer must still equal Issuer exactly.
type OIDCClientConfig struct {
	Issuer, DiscoveryURL, ClientID, ClientSecret, RedirectURL string
	ProviderHint                                              string
	// Explicit endpoints support a managed IdP without discovery. Supply all
	// three together, and leave DiscoveryURL empty in this mode.
	AuthorizationURL, TokenURL, JWKSURL string
	Client                              *http.Client
	Now                                 func() time.Time
}

// OIDCClient owns token exchange configuration and a cached external verifier.
type OIDCClient struct {
	Verifier *OIDCVerifier
	oauth    oauth2.Config
	client   *http.Client
}

// Validate checks configuration without contacting the IdP, so a managed
// deployment can reject bad configuration before starting any listener.
func (cfg OIDCClientConfig) Validate() error {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return errors.New("OIDC client ID and secret are required")
	}
	for _, raw := range []string{cfg.Issuer, cfg.RedirectURL} {
		if _, err := oidcEndpoint(raw); err != nil {
			return err
		}
	}
	explicit := cfg.AuthorizationURL != "" || cfg.TokenURL != "" || cfg.JWKSURL != ""
	if explicit && (cfg.DiscoveryURL != "" || cfg.AuthorizationURL == "" || cfg.TokenURL == "" || cfg.JWKSURL == "") {
		return errors.New("OIDC requires discovery or all explicit endpoints, not a mixture")
	}
	for _, raw := range []string{cfg.DiscoveryURL, cfg.AuthorizationURL, cfg.TokenURL, cfg.JWKSURL} {
		if raw != "" {
			if _, err := oidcEndpoint(raw); err != nil {
				return err
			}
		}
	}
	return nil
}

func NewOIDCClient(ctx context.Context, cfg OIDCClientConfig) (*OIDCClient, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client := boundedOIDCClient(cfg.Client)
	authURL, tokenURL, jwksURL := cfg.AuthorizationURL, cfg.TokenURL, cfg.JWKSURL
	requireIssuer := false
	authStyle := oauth2.AuthStyleInHeader
	explicit := authURL != "" || tokenURL != "" || jwksURL != ""
	if !explicit {
		discovery := cfg.DiscoveryURL
		if discovery == "" {
			discovery = strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
		}
		if _, err := oidcEndpoint(discovery); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, errors.New("OIDC discovery request failed")
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OIDC discovery returned HTTP %d", resp.StatusCode)
		}
		var metadata struct {
			Issuer         string   `json:"issuer"`
			AuthURL        string   `json:"authorization_endpoint"`
			TokenURL       string   `json:"token_endpoint"`
			JWKSURL        string   `json:"jwks_uri"`
			AuthMethods    []string `json:"token_endpoint_auth_methods_supported"`
			ResponseIssuer bool     `json:"authorization_response_iss_parameter_supported"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&metadata); err != nil {
			return nil, errors.New("invalid OIDC discovery document")
		}
		if metadata.Issuer != cfg.Issuer {
			return nil, errors.New("OIDC discovery issuer mismatch")
		}
		authURL, tokenURL, jwksURL, requireIssuer = metadata.AuthURL, metadata.TokenURL, metadata.JWKSURL, metadata.ResponseIssuer
		if len(metadata.AuthMethods) > 0 {
			basic, post := false, false
			for _, method := range metadata.AuthMethods {
				basic = basic || method == "client_secret_basic"
				post = post || method == "client_secret_post"
			}
			if !basic && !post {
				return nil, errors.New("OIDC discovery has no supported confidential-client authentication method")
			}
			if !basic {
				authStyle = oauth2.AuthStyleInParams
			}
		}
	}
	for _, raw := range []string{authURL, tokenURL, jwksURL} {
		if _, err := oidcEndpoint(raw); err != nil {
			return nil, err
		}
	}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(ctx, client), jwksURL)
	v := &OIDCVerifier{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID, JWKSURL: jwksURL, Client: client, Now: cfg.Now,
		AuthorizationURL: authURL, RedirectURL: cfg.RedirectURL, ProviderHint: cfg.ProviderHint,
		RequireResponseIssuer: requireIssuer,
		verifier:              externalTokenVerifier(cfg.Issuer, cfg.ClientID, keys, cfg.Now),
	}
	return &OIDCClient{Verifier: v, client: client, oauth: oauth2.Config{
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL,
		Endpoint: oauth2.Endpoint{AuthURL: authURL, TokenURL: tokenURL, AuthStyle: authStyle},
		Scopes:   []string{oidc.ScopeOpenID, "profile", "email"},
	}}, nil
}

func (c *OIDCClient) ExchangeCode(ctx context.Context, code, verifier string) (OIDCTokenSet, error) {
	if strings.TrimSpace(code) == "" || verifier == "" {
		return OIDCTokenSet{}, ErrInvalidInput
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.client)
	token, err := c.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		// oauth2 errors may contain the provider's token response; never forward
		// them to HTTP clients or logs where credentials could be disclosed.
		return OIDCTokenSet{}, ErrUnauthorized
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") {
		return OIDCTokenSet{}, ErrUnauthorized
	}
	return OIDCTokenSet{IDToken: idToken, AccessToken: token.AccessToken, TokenType: token.TokenType}, nil
}

func oidcEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" {
		return nil, errors.New("invalid OIDC endpoint URL")
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme != "https" && (u.Scheme != "http" || !local) {
		return nil, errors.New("OIDC endpoints require HTTPS (HTTP loopback is allowed)")
	}
	return u, nil
}

func boundedOIDCClient(source *http.Client) *http.Client {
	client := &http.Client{}
	if source != nil {
		*client = *source
	}
	if client.Timeout <= 0 || client.Timeout > 15*time.Second {
		client.Timeout = 15 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

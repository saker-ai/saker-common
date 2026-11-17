package warden

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	ErrOIDCInvalidToken = errors.New("warden: invalid oidc token")
	ErrOIDCNoKey        = errors.New("warden: oidc key not found")
)

// OIDCVerifier verifies external IdP tokens in a separate trust domain from
// Warden's internal JWTs. Do not mutate its configuration after first use.
// NewOIDCClient supplies a shared, cached remote key set.
type OIDCVerifier struct {
	Issuer                string
	ClientID              string
	JWKSURL               string
	Client                *http.Client
	Now                   func() time.Time
	AuthorizationURL      string
	RedirectURL           string
	ProviderHint          string
	RequireResponseIssuer bool
	verifier              *oidc.IDTokenVerifier
}

type OIDCClaims struct {
	Issuer          string   `json:"iss"`
	Subject         string   `json:"sub"`
	Audience        []string `json:"aud"`
	ExpiresAt       int64    `json:"exp"`
	NotBefore       int64    `json:"nbf,omitempty"`
	IssuedAt        int64    `json:"iat,omitempty"`
	Nonce           string   `json:"nonce,omitempty"`
	AuthorizedParty string   `json:"azp,omitempty"`
	Email           string   `json:"email,omitempty"`
	Name            string   `json:"name,omitempty"`
	PreferredName   string   `json:"preferred_username,omitempty"`
	TenantID        string   `json:"tenant_id,omitempty"`
	Scope           string   `json:"scope,omitempty"`
}

func (v OIDCVerifier) VerifyIDToken(ctx context.Context, raw, expectedNonce string) (OIDCClaims, error) {
	_, claims, err := v.verify(ctx, raw, expectedNonce)
	return claims, err
}

// VerifyTokenSet also validates at_hash when supplied by the IdP.
func (v OIDCVerifier) VerifyTokenSet(ctx context.Context, tokens OIDCTokenSet, expectedNonce string) (OIDCClaims, error) {
	token, claims, err := v.verify(ctx, tokens.IDToken, expectedNonce)
	if err != nil {
		return OIDCClaims{}, err
	}
	if token.AccessTokenHash != "" && (tokens.AccessToken == "" || token.VerifyAccessToken(tokens.AccessToken) != nil) {
		return OIDCClaims{}, ErrOIDCInvalidToken
	}
	return claims, nil
}

func (v OIDCVerifier) verify(ctx context.Context, raw, expectedNonce string) (*oidc.IDToken, OIDCClaims, error) {
	if len(raw) > 64<<10 || strings.TrimSpace(v.Issuer) == "" || strings.TrimSpace(v.ClientID) == "" {
		return nil, OIDCClaims{}, ErrOIDCInvalidToken
	}
	verifier := v.verifier
	if verifier == nil {
		if _, err := oidcEndpoint(v.JWKSURL); err != nil {
			return nil, OIDCClaims{}, ErrOIDCNoKey
		}
		client := boundedOIDCClient(v.Client)
		keySet := oidc.NewRemoteKeySet(oidc.ClientContext(ctx, client), v.JWKSURL)
		verifier = externalTokenVerifier(v.Issuer, v.ClientID, keySet, v.Now)
	}
	token, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, OIDCClaims{}, ErrOIDCInvalidToken
	}
	var claims OIDCClaims
	if err := token.Claims(&claims); err != nil {
		return nil, OIDCClaims{}, ErrOIDCInvalidToken
	}
	if err := v.validateClaims(claims, expectedNonce); err != nil {
		return nil, OIDCClaims{}, err
	}
	return token, claims, nil
}

func externalTokenVerifier(issuer, clientID string, keys oidc.KeySet, now func() time.Time) *oidc.IDTokenVerifier {
	return oidc.NewVerifier(issuer, keys, &oidc.Config{
		ClientID: clientID, Now: now,
		SupportedSigningAlgs: []string{oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512, oidc.PS256, oidc.PS384, oidc.PS512, oidc.EdDSA},
	})
}

func (v OIDCVerifier) validateClaims(claims OIDCClaims, expectedNonce string) error {
	if claims.Issuer != v.Issuer || strings.TrimSpace(claims.Subject) == "" || !slices.Contains(claims.Audience, v.ClientID) {
		return ErrOIDCInvalidToken
	}
	if len(claims.Audience) > 1 && claims.AuthorizedParty != v.ClientID || claims.AuthorizedParty != "" && claims.AuthorizedParty != v.ClientID {
		return ErrOIDCInvalidToken
	}
	if expectedNonce != "" && subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1 {
		return ErrOIDCInvalidToken
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	if claims.ExpiresAt <= 0 || !now.Before(time.Unix(claims.ExpiresAt, 0)) || claims.NotBefore > now.Unix() || claims.IssuedAt > now.Add(30*time.Second).Unix() {
		return ErrOIDCInvalidToken
	}
	return nil
}

func (c *OIDCClaims) UnmarshalJSON(data []byte) error {
	type alias OIDCClaims
	var aux struct {
		alias
		Audience json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*c = OIDCClaims(aux.alias)
	var single string
	if err := json.Unmarshal(aux.Audience, &single); err == nil && single != "" {
		c.Audience = []string{single}
		return nil
	}
	if err := json.Unmarshal(aux.Audience, &c.Audience); err != nil || len(c.Audience) == 0 {
		return ErrOIDCInvalidToken
	}
	for _, audience := range c.Audience {
		if strings.TrimSpace(audience) == "" {
			return ErrOIDCInvalidToken
		}
	}
	return nil
}

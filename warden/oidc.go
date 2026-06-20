package warden

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

var (
	ErrOIDCInvalidToken = errors.New("warden: invalid oidc token")
	ErrOIDCNoKey        = errors.New("warden: oidc key not found")
)

type OIDCVerifier struct {
	Issuer   string
	ClientID string
	JWKSURL  string
	Client   *http.Client
	Now      func() time.Time
}

type OIDCClaims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      []string `json:"aud"`
	ExpiresAt     int64    `json:"exp"`
	NotBefore     int64    `json:"nbf,omitempty"`
	IssuedAt      int64    `json:"iat,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	Email         string   `json:"email,omitempty"`
	Name          string   `json:"name,omitempty"`
	PreferredName string   `json:"preferred_username,omitempty"`
	TenantID      string   `json:"tenant_id,omitempty"`
	Scope         string   `json:"scope,omitempty"`
}

func (v OIDCVerifier) VerifyIDToken(ctx context.Context, token, expectedNonce string) (OIDCClaims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return OIDCClaims{}, ErrOIDCInvalidToken
	}
	var header struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := decodeJWTPart(parts[0], &header); err != nil {
		return OIDCClaims{}, ErrOIDCInvalidToken
	}
	if header.Alg != "RS256" || strings.TrimSpace(header.KID) == "" {
		return OIDCClaims{}, ErrOIDCInvalidToken
	}
	var claims OIDCClaims
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return OIDCClaims{}, ErrOIDCInvalidToken
	}
	if err := v.validateClaims(claims, expectedNonce); err != nil {
		return OIDCClaims{}, err
	}
	key, err := v.fetchRSAKey(ctx, header.KID)
	if err != nil {
		return OIDCClaims{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return OIDCClaims{}, ErrOIDCInvalidToken
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return OIDCClaims{}, ErrOIDCInvalidToken
	}
	return claims, nil
}

func (v OIDCVerifier) validateClaims(claims OIDCClaims, expectedNonce string) error {
	if strings.TrimSpace(v.Issuer) == "" || claims.Issuer != strings.TrimSpace(v.Issuer) {
		return ErrOIDCInvalidToken
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return ErrOIDCInvalidToken
	}
	clientID := strings.TrimSpace(v.ClientID)
	if clientID == "" || !containsString(claims.Audience, clientID) {
		return ErrOIDCInvalidToken
	}
	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return ErrOIDCInvalidToken
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	if claims.ExpiresAt <= 0 || !now.Before(time.Unix(claims.ExpiresAt, 0)) {
		return ErrOIDCInvalidToken
	}
	if claims.NotBefore > 0 && now.Before(time.Unix(claims.NotBefore, 0)) {
		return ErrOIDCInvalidToken
	}
	if claims.IssuedAt > 0 && now.Add(5*time.Minute).Before(time.Unix(claims.IssuedAt, 0)) {
		return ErrOIDCInvalidToken
	}
	return nil
}

func (v OIDCVerifier) fetchRSAKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if strings.TrimSpace(v.JWKSURL) == "" {
		return nil, ErrOIDCNoKey
	}
	client := v.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: jwks status %s", ErrOIDCNoKey, resp.Status)
	}
	var jwks struct {
		Keys []jwkKey `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	for _, key := range jwks.Keys {
		if key.KID == kid {
			return key.rsaPublicKey()
		}
	}
	return nil, ErrOIDCNoKey
}

type jwkKey struct {
	KTY string   `json:"kty"`
	Use string   `json:"use,omitempty"`
	KID string   `json:"kid"`
	Alg string   `json:"alg,omitempty"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	X5C []string `json:"x5c,omitempty"`
}

func (k jwkKey) rsaPublicKey() (*rsa.PublicKey, error) {
	if k.KTY != "RSA" {
		return nil, ErrOIDCNoKey
	}
	if len(k.X5C) > 0 {
		der, err := base64.StdEncoding.DecodeString(k.X5C[0])
		if err != nil {
			return nil, ErrOIDCNoKey
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ErrOIDCNoKey
		}
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, ErrOIDCNoKey
		}
		return key, nil
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, ErrOIDCNoKey
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, ErrOIDCNoKey
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e == 0 {
		return nil, ErrOIDCNoKey
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func decodeJWTPart(part string, dst any) error {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (c *OIDCClaims) UnmarshalJSON(data []byte) error {
	type alias OIDCClaims
	var aux struct {
		alias
		Audience any `json:"aud"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*c = OIDCClaims(aux.alias)
	switch aud := aux.Audience.(type) {
	case string:
		c.Audience = []string{aud}
	case []any:
		for _, item := range aud {
			if s, ok := item.(string); ok {
				c.Audience = append(c.Audience, s)
			}
		}
	default:
		return ErrOIDCInvalidToken
	}
	return nil
}

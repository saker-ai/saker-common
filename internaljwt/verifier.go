package internaljwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Verifier struct {
	issuer                     string
	audience                   string
	secret                     []byte
	ttl                        time.Duration
	clockSkew                  time.Duration
	allowAuthorizationFallback bool
	now                        func() time.Time
}

type VerifierOptions struct {
	Issuer                     string
	Audience                   string
	MasterSecret               string
	TTL                        time.Duration
	ClockSkew                  time.Duration
	AllowAuthorizationFallback bool
	Now                        func() time.Time
}

func NewVerifier(opts VerifierOptions) (*Verifier, error) {
	secret := NormalizeMasterSecret(opts.MasterSecret)
	if len(secret) < 32 {
		return nil, fmt.Errorf("internaljwt: master secret must be at least 32 bytes")
	}
	if strings.TrimSpace(opts.Issuer) == "" {
		return nil, fmt.Errorf("internaljwt: issuer required")
	}
	if strings.TrimSpace(opts.Audience) == "" {
		return nil, fmt.Errorf("internaljwt: audience required")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	clockSkew := opts.ClockSkew
	if clockSkew < 0 {
		clockSkew = 0
	}
	if clockSkew == 0 {
		clockSkew = 30 * time.Second
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Verifier{
		issuer:                     strings.TrimSpace(opts.Issuer),
		audience:                   strings.TrimSpace(opts.Audience),
		secret:                     secret,
		ttl:                        ttl,
		clockSkew:                  clockSkew,
		allowAuthorizationFallback: opts.AllowAuthorizationFallback,
		now:                        now,
	}, nil
}

func (v *Verifier) VerifyRequest(r *http.Request) (*Principal, error) {
	token, err := TokenFromRequest(r, v.allowAuthorizationFallback)
	if err != nil {
		return nil, err
	}
	return v.Verify(token)
}

func (v *Verifier) Verify(token string) (*Principal, error) {
	claims, err := v.verifyClaims(token)
	if err != nil {
		return nil, err
	}
	principal := &Principal{
		TenantID:  claims.TenantID,
		OrgID:     claims.OrgID,
		Type:      claims.PrincipalType,
		ID:        claims.PrincipalID,
		Roles:     append([]string(nil), claims.Roles...),
		Scopes:    append([]string(nil), claims.Scopes...),
		SessionID: claims.SessionID,
		Source:    claims.Source,
		JWTID:     claims.JWTID,
		Claims:    claims,
	}
	if claims.Resource != nil {
		principal.ResourceType = claims.Resource.Type
		principal.ResourceID = claims.Resource.ID
	}
	return principal, nil
}

func (v *Verifier) verifyClaims(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformedToken
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrMalformedToken
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Claims{}, ErrMalformedToken
	}
	if header.Alg != signingAlgHS256 {
		return Claims{}, ErrUnsupportedAlg
	}
	signingInput := parts[0] + "." + parts[1]
	now := v.now().UTC()
	if !verifySignature(signingInput, parts[2], DeriveSecret(v.secret, now)) {
		if !InPreviousPeriodWindow(now, v.ttl+v.clockSkew) || !verifySignature(signingInput, parts[2], previousPeriodSecret(v.secret, now)) {
			return Claims{}, ErrInvalidSignature
		}
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrMalformedToken
	}
	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return Claims{}, ErrMalformedToken
	}
	if err := validateRequiredClaims(claims, v.issuer, v.audience, now, v.clockSkew); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func verifySignature(signingInput, encodedSignature string, secret []byte) bool {
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	expected := mac.Sum(nil)
	return hmac.Equal(signature, expected)
}

func validateRequiredClaims(claims Claims, issuer, audience string, now time.Time, skew time.Duration) error {
	if claims.Issuer != issuer || claims.Audience != audience || claims.Type != TypeInternalAccess || claims.Version != 1 {
		return ErrInvalidClaims
	}
	if claims.ExpiresAt <= 0 || claims.IssuedAt <= 0 || strings.TrimSpace(claims.JWTID) == "" {
		return ErrInvalidClaims
	}
	if strings.TrimSpace(claims.TenantID) == "" || strings.TrimSpace(claims.PrincipalType) == "" || strings.TrimSpace(claims.PrincipalID) == "" {
		return ErrInvalidClaims
	}
	if claims.Subject == "" || claims.Subject != claims.PrincipalID {
		return ErrInvalidClaims
	}
	if claims.Resource != nil {
		if strings.TrimSpace(claims.Resource.Type) == "" || strings.TrimSpace(claims.Resource.ID) == "" {
			return ErrInvalidClaims
		}
	}
	if now.IsZero() {
		return nil
	}
	if now.After(time.Unix(claims.ExpiresAt, 0).Add(skew)) {
		return ErrExpired
	}
	if claims.NotBefore > 0 && now.Add(skew).Before(time.Unix(claims.NotBefore, 0)) {
		return ErrNotYetValid
	}
	if now.Add(skew).Before(time.Unix(claims.IssuedAt, 0)) {
		return ErrInvalidClaims
	}
	return nil
}

func TokenFromRequest(r *http.Request, allowAuthorizationFallback bool) (string, error) {
	if r == nil {
		return "", ErrMissingToken
	}
	if token, ok := parseBearer(r.Header.Get(HeaderInternalAuthorization)); ok {
		return token, nil
	}
	if allowAuthorizationFallback {
		if token, ok := parseBearer(r.Header.Get(HeaderAuthorization)); ok {
			return token, nil
		}
	}
	return "", ErrMissingToken
}

func parseBearer(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	return token, token != ""
}

func HasScope(scopes []string, required string) bool {
	required = strings.TrimSpace(required)
	if required == "" {
		return true
	}
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}

func RequireScope(scopes []string, required string) error {
	if HasScope(scopes, required) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInsufficientScope, required)
}

func IsAuthError(err error) bool {
	return errors.Is(err, ErrMissingToken) ||
		errors.Is(err, ErrMalformedToken) ||
		errors.Is(err, ErrUnsupportedAlg) ||
		errors.Is(err, ErrInvalidSignature) ||
		errors.Is(err, ErrInvalidClaims) ||
		errors.Is(err, ErrExpired) ||
		errors.Is(err, ErrNotYetValid)
}

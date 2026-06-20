package internaljwt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const signingAlgHS256 = "HS256"

type Signer struct {
	issuer string
	secret []byte
	ttl    time.Duration
}

func NewSigner(issuer, masterSecret string, ttl time.Duration) (*Signer, error) {
	secret := NormalizeMasterSecret(masterSecret)
	if len(secret) < 32 {
		return nil, fmt.Errorf("internaljwt: master secret must be at least 32 bytes")
	}
	if strings.TrimSpace(issuer) == "" {
		return nil, fmt.Errorf("internaljwt: issuer required")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Signer{issuer: strings.TrimSpace(issuer), secret: secret, ttl: ttl}, nil
}

func (s *Signer) Sign(in SignInput) (string, Claims, error) {
	now := in.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ttl := in.TTL
	if ttl <= 0 {
		ttl = s.ttl
	}
	jti := strings.TrimSpace(in.JWTID)
	if jti == "" {
		var err error
		jti, err = randomID("jwt")
		if err != nil {
			return "", Claims{}, fmt.Errorf("generate jwt id: %w", err)
		}
	}
	issuer := strings.TrimSpace(in.Issuer)
	if issuer == "" {
		issuer = s.issuer
	}
	claims := Claims{
		Issuer:        issuer,
		Subject:       strings.TrimSpace(in.PrincipalID),
		Audience:      strings.TrimSpace(in.Audience),
		ExpiresAt:     now.Add(ttl).Unix(),
		NotBefore:     now.Unix(),
		IssuedAt:      now.Unix(),
		JWTID:         jti,
		Type:          TypeInternalAccess,
		Version:       1,
		TenantID:      strings.TrimSpace(in.TenantID),
		OrgID:         strings.TrimSpace(in.OrgID),
		PrincipalType: strings.TrimSpace(in.PrincipalType),
		PrincipalID:   strings.TrimSpace(in.PrincipalID),
		Email:         strings.TrimSpace(in.Email),
		Name:          strings.TrimSpace(in.Name),
		Handle:        strings.TrimSpace(in.Handle),
		Roles:         cleanStrings(in.Roles),
		Scopes:        cleanStrings(in.Scopes),
		Resource:      in.Resource,
		SessionID:     strings.TrimSpace(in.SessionID),
		Source:        strings.TrimSpace(in.Source),
		Actor:         in.Actor,
		Delegation:    in.Delegation,
	}
	if !in.AuthTime.IsZero() {
		claims.AuthTime = in.AuthTime.UTC().Unix()
	}
	if claims.Subject == "" {
		claims.Subject = claims.PrincipalID
	}
	if err := validateRequiredClaims(claims, issuer, claims.Audience, now, 0); err != nil {
		return "", Claims{}, err
	}
	token, err := signClaims(claims, DeriveSecret(s.secret, now))
	if err != nil {
		return "", Claims{}, err
	}
	return token, claims, nil
}

func signClaims(claims Claims, secret []byte) (string, error) {
	header := map[string]string{"alg": signingAlgHS256, "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + signature, nil
}

func randomID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

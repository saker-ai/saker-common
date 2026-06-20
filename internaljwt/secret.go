package internaljwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"
)

func NormalizeMasterSecret(secret string) []byte {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(secret); err == nil && len(decoded) >= 32 {
		return decoded
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(secret); err == nil && len(decoded) >= 32 {
		return decoded
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(secret); err == nil && len(decoded) >= 32 {
		return decoded
	}
	if decoded, err := hex.DecodeString(secret); err == nil && len(decoded) >= 32 {
		return decoded
	}
	return []byte(secret)
}

func DeriveSecret(master []byte, now time.Time) []byte {
	period := now.UTC().Format("2006-01")
	mac := hmac.New(sha256.New, master)
	_, _ = mac.Write([]byte("saker-jwt:" + period))
	return mac.Sum(nil)
}

func previousPeriodSecret(master []byte, now time.Time) []byte {
	current := now.UTC()
	previous := time.Date(current.Year(), current.Month(), 1, 0, 0, 0, 0, time.UTC).Add(-time.Nanosecond)
	return DeriveSecret(master, previous)
}

func InPreviousPeriodWindow(now time.Time, window time.Duration) bool {
	if window <= 0 {
		return false
	}
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	return !now.Before(start) && now.Before(start.Add(window))
}

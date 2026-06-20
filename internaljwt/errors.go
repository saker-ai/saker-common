package internaljwt

import "errors"

var (
	ErrMissingToken      = errors.New("internaljwt: missing token")
	ErrMalformedToken    = errors.New("internaljwt: malformed token")
	ErrUnsupportedAlg    = errors.New("internaljwt: unsupported algorithm")
	ErrInvalidSignature  = errors.New("internaljwt: invalid signature")
	ErrInvalidClaims     = errors.New("internaljwt: invalid claims")
	ErrExpired           = errors.New("internaljwt: token expired")
	ErrNotYetValid       = errors.New("internaljwt: token not yet valid")
	ErrInsufficientScope = errors.New("internaljwt: insufficient scope")
)

package warden

import (
	"context"
	"errors"
	"time"
)

var ErrOIDCUnavailable = errors.New("warden: identity provider unavailable")

func (s *Service) resolveOIDC(ctx context.Context) (*OIDCVerifier, OIDCTokenExchanger, error) {
	if s.cfg.OIDCFactory == nil {
		return s.oidcVerifier, s.tokenExchanger, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// A context-aware gate permits one discovery attempt without making waiting
	// callers ignore their own cancellation or deadlines.
	select {
	case s.oidcGate <- struct{}{}:
		defer func() { <-s.oidcGate }()
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	if s.oidcClient != nil {
		return s.oidcClient.Verifier, s.oidcClient, nil
	}
	if time.Now().Before(s.oidcRetryAfter) {
		return nil, nil, ErrOIDCUnavailable
	}
	client, err := s.cfg.OIDCFactory(ctx)
	if err != nil || client == nil || client.Verifier == nil || client.Verifier.RedirectURL != s.cfg.OIDCRedirectURL {
		s.oidcRetryAfter = time.Now().Add(2 * time.Second)
		return nil, nil, ErrOIDCUnavailable
	}
	s.oidcClient = client
	return client.Verifier, client, nil
}

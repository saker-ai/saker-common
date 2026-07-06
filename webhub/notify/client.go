// Package notify provides a Go SDK for downstream services to send notifications
// to a WebHub notification center via the WebHub /v1/notifications endpoint.
//
// Flow: downstream service holds a Warden API key → exchanges it for a Warden
// internal JWT (audience=webhub, scope=webhub:notifications:write) → POSTs the
// notification to WebHub /v1/notifications. The internal JWT is cached for the
// duration reported by Warden to avoid re-signing on every notification.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Event represents a business event notification to be sent to WebHub.
type Event struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Body          string `json:"body"`
	TenantID      string `json:"tenant_id,omitempty"`
	SourceApp     string `json:"source_app,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Href          string `json:"href,omitempty"`
	RecipientType string `json:"recipient_type,omitempty"`
	RecipientID   string `json:"recipient_id,omitempty"`
}

// Client sends notifications to a WebHub instance.
type Client struct {
	cfg          Config
	http         *http.Client
	mu           sync.Mutex
	cachedToken  string
	cachedExpiry time.Time
}

type Config struct {
	Enabled           bool
	WebHubURL         string
	WardenURL         string
	APIKey            string
	Audience          string
	Scopes            []string
	HTTPTimeout       time.Duration
	TokenSafetyMargin time.Duration
}

func NewClient(cfg Config) (*Client, error) {
	if !cfg.Enabled {
		return &Client{cfg: cfg, http: http.DefaultClient}, nil
	}
	if strings.TrimSpace(cfg.WebHubURL) == "" {
		return nil, fmt.Errorf("notify: webhub_url is required when enabled")
	}
	if strings.TrimSpace(cfg.WardenURL) == "" {
		return nil, fmt.Errorf("notify: warden_url is required when enabled")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("notify: api_key is required when enabled")
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		cfg.Audience = "webhub"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"webhub:notifications:write"}
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}
	if cfg.TokenSafetyMargin <= 0 {
		cfg.TokenSafetyMargin = 30 * time.Second
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.HTTPTimeout},
	}, nil
}

func (c *Client) Notify(ctx context.Context, event Event) error {
	if !c.cfg.Enabled {
		return nil
	}
	if strings.TrimSpace(event.Title) == "" {
		return fmt.Errorf("notify: title is required")
	}
	token, err := c.token(ctx)
	if err != nil {
		return fmt.Errorf("notify: get token: %w", err)
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("notify: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.WebHubURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("notify: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Saker-Internal-Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("notify: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("notify: webhub responded %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedToken != "" && time.Now().Add(c.cfg.TokenSafetyMargin).Before(c.cachedExpiry) {
		return c.cachedToken, nil
	}
	token, expiry, err := c.signInternalJWT(ctx)
	if err != nil {
		return "", err
	}
	c.cachedToken = token
	c.cachedExpiry = expiry
	return token, nil
}

func (c *Client) signInternalJWT(ctx context.Context) (string, time.Time, error) {
	body, err := json.Marshal(map[string]any{
		"api_key":  c.cfg.APIKey,
		"audience": c.cfg.Audience,
		"actions":  scopesToActions(c.cfg.Scopes),
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("marshal token request: %w", err)
	}
	endpoint := strings.TrimRight(c.cfg.WardenURL, "/") + "/v1/internal-jwts"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("warden token request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", time.Time{}, fmt.Errorf("warden token http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("decode token response: %w", err)
	}
	if strings.TrimSpace(out.Token) == "" {
		return "", time.Time{}, fmt.Errorf("warden returned empty token")
	}
	expiry := time.Unix(out.ExpiresAt, 0).UTC()
	if expiry.IsZero() {
		expiry = time.Now().Add(2 * time.Minute)
	}
	return out.Token, expiry, nil
}

func scopesToActions(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if idx := strings.LastIndex(s, ":"); idx >= 0 {
			s = s[idx+1:]
		}
		out = append(out, s)
	}
	return out
}

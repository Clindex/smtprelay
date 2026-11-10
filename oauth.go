package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/google/uuid"
)

// MicrosoftOAuthConfig contains identifiers and a secret reference, never a client secret.
type MicrosoftOAuthConfig struct {
	TenantID        string
	ClientID        string
	ClientSecretRef string
}

type secretResolver func(context.Context, string) (string, error)

// Initialize the SDK lazily so non-OAuth deliveries need no 1Password connection.
func onePasswordResolver() secretResolver {
	gate := make(chan struct{}, 1)
	var client *onepassword.Client
	return func(ctx context.Context, ref string) (string, error) {
		logger := slog.With("component", "onepassword")
		select {
		case gate <- struct{}{}:
		case <-ctx.Done():
			return "", ctx.Err()
		}
		defer func() { <-gate }()
		if client == nil {
			token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
			logger.DebugContext(ctx, "initializing 1Password service account client", "service_account_token_present", token != "")
			if token == "" {
				logger.ErrorContext(ctx, "1Password service account token is missing", "environment_variable", "OP_SERVICE_ACCOUNT_TOKEN")
				return "", errors.New("OP_SERVICE_ACCOUNT_TOKEN is required")
			}
			var err error
			client, err = onepassword.NewClient(ctx,
				onepassword.WithServiceAccountToken(token),
				onepassword.WithIntegrationInfo("smtprelay", "1.0.0"))
			if err != nil {
				logger.ErrorContext(ctx, "1Password service account initialization failed")
				return "", errors.New("1Password service account initialization failed")
			}
			logger.DebugContext(ctx, "1Password service account client initialized")
		}
		started := time.Now()
		logger.DebugContext(ctx, "resolving Microsoft client secret from 1Password")
		secret, err := client.Secrets().Resolve(ctx, ref)
		// SDK errors may contain sensitive context; do not propagate them into SMTP logs.
		if err != nil {
			logger.ErrorContext(ctx, "1Password client secret resolution failed", "duration", time.Since(started))
			return "", errors.New("1Password client secret resolution failed")
		}
		if secret == "" {
			logger.ErrorContext(ctx, "1Password returned an empty client secret")
			return "", errors.New("1Password returned an empty client secret")
		}
		logger.DebugContext(ctx, "Microsoft client secret resolved from 1Password", "duration", time.Since(started))
		return secret, nil
	}
}

func isOAuthAuth(authType string) bool {
	switch strings.ToLower(authType) {
	case "oauth", "oauth2", "xoauth2":
		return true
	default:
		return false
	}
}

func newMicrosoftTokenProvider(cfg MicrosoftOAuthConfig, credentials map[string]SMTPCredentials) (*microsoftTokenProvider, error) {
	if cfg == (MicrosoftOAuthConfig{}) {
		slog.Debug("automatic Microsoft OAuth disabled: global configuration is empty", "component", "microsoft_oauth")
		return nil, nil
	}
	if _, err := uuid.Parse(cfg.TenantID); err != nil {
		return nil, errors.New("microsoft_tenant_id must be a UUID")
	}
	if _, err := uuid.Parse(cfg.ClientID); err != nil {
		return nil, errors.New("microsoft_client_id must be a UUID")
	}
	parts := strings.Split(strings.TrimPrefix(cfg.ClientSecretRef, "op://"), "/")
	if !strings.HasPrefix(cfg.ClientSecretRef, "op://") || len(parts) < 3 {
		return nil, errors.New("microsoft_client_secret_ref must be an op://vault/item/field reference")
	}
	for _, part := range parts {
		if part == "" {
			return nil, errors.New("microsoft_client_secret_ref must not contain empty path segments")
		}
	}
	for key, creds := range credentials {
		creds = creds.withDefaultUsername(key)
		if !isOAuthAuth(creds.AuthType) {
			continue
		}
		if creds.Username == "" {
			return nil, fmt.Errorf("credentials %q: Microsoft OAuth requires username", key)
		}
		if creds.AccessToken != "" || creds.Password != "" {
			return nil, fmt.Errorf("credentials %q: remove accessToken and password when using global Microsoft OAuth", key)
		}
	}
	slog.Debug("automatic Microsoft OAuth configured", "component", "microsoft_oauth", "tenant_id", cfg.TenantID, "client_id", cfg.ClientID)
	return &microsoftTokenProvider{
		cfg: cfg, resolve: onePasswordResolver(),
		endpoint: "https://login.microsoftonline.com/" + cfg.TenantID + "/oauth2/v2.0/token",
		client:   &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		now:      time.Now,
	}, nil
}

type microsoftTokenProvider struct {
	cfg         MicrosoftOAuthConfig
	resolve     secretResolver
	endpoint    string
	client      *http.Client
	now         func() time.Time
	once        sync.Once
	gate        chan struct{}
	accessToken string
	refreshAt   time.Time
}

func (p *microsoftTokenProvider) Token(ctx context.Context) (string, error) {
	logger := slog.With("component", "microsoft_oauth", "tenant_id", p.cfg.TenantID, "client_id", p.cfg.ClientID)
	started := time.Now()
	stage := "waiting_for_cache"
	completed := false
	defer func() {
		if !completed {
			// Do not log raw SDK/HTTP errors, request bodies, or response bodies.
			logger.ErrorContext(ctx, "Microsoft token acquisition failed", "stage", stage, "duration", time.Since(started), "context_error", ctx.Err())
		}
	}()
	logger.DebugContext(ctx, "checking Microsoft token cache")
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Serialize refreshes across all mailboxes using the same app configuration.
	p.once.Do(func() { p.gate = make(chan struct{}, 1) })
	select {
	case p.gate <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-p.gate }()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if p.accessToken != "" && p.now().Before(p.refreshAt) {
		logger.DebugContext(ctx, "using cached Microsoft access token", "refresh_at", p.refreshAt, "refresh_in", p.refreshAt.Sub(p.now()))
		completed = true
		return p.accessToken, nil
	}
	reason := "initial_acquisition"
	if p.accessToken != "" {
		reason = "renewal_due"
	}
	logger.DebugContext(ctx, "obtaining Microsoft access token", "reason", reason)
	stage = "resolving_client_secret"
	// Re-resolve on renewal so rotating the secret in 1Password needs no restart.
	secret, err := p.resolve(ctx, p.cfg.ClientSecretRef)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"client_id": {p.cfg.ClientID}, "client_secret": {secret},
		"scope":      {"https://outlook.office365.com/.default"},
		"grant_type": {"client_credentials"},
	}
	stage = "requesting_token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("could not construct Microsoft token request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	requestID := uuid.NewString()
	req.Header.Set("client-request-id", requestID)
	req.Header.Set("return-client-request-id", "true")
	logger = logger.With("request_id", requestID)
	logger.DebugContext(ctx, "requesting Microsoft access token", "grant_type", "client_credentials", "scope", "https://outlook.office365.com/.default")
	requestedAt := p.now()
	resp, err := p.client.Do(req)
	if err != nil {
		return "", errors.New("Microsoft token request failed")
	}
	defer resp.Body.Close()
	logger = logger.With("http_status", resp.StatusCode)
	logger.DebugContext(ctx, "Microsoft token endpoint responded", "duration", time.Since(started))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Microsoft token endpoint returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	stage = "validating_token_response"
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return "", errors.New("invalid Microsoft token response")
	}
	if result.AccessToken == "" || !strings.EqualFold(result.TokenType, "Bearer") || result.ExpiresIn <= 0 || result.ExpiresIn > 86400 {
		return "", errors.New("Microsoft token response has invalid token type, lifetime, or missing token")
	}
	lifetime := time.Duration(result.ExpiresIn) * time.Second
	margin := min(2*time.Minute, lifetime/10)
	refreshAt := requestedAt.Add(lifetime - margin)
	if !p.now().Before(refreshAt) {
		return "", errors.New("Microsoft token expired during acquisition")
	}
	p.accessToken, p.refreshAt = result.AccessToken, refreshAt
	logger.DebugContext(ctx, "Microsoft access token obtained", "expires_at", requestedAt.Add(lifetime), "refresh_at", refreshAt, "expires_in_seconds", result.ExpiresIn, "duration", time.Since(started))
	completed = true
	return p.accessToken, nil
}

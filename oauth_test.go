package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evidentiq/smtprelay/v2/internal/smtpd"
	"github.com/stretchr/testify/require"
)

func TestMicrosoftTokenRenewal(t *testing.T) {
	var requests atomic.Int32
	var resolutions atomic.Int32
	now := time.Now()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("scope") != "https://outlook.office365.com/.default" || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "app" {
			t.Error("incorrect OAuth request")
		}
		if r.Form.Get("client_secret") != fmt.Sprintf("rotated-secret-%d", n) {
			t.Error("secret was not re-resolved")
		}
		fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"Bearer","expires_in":3600}`, n)
	}))
	defer server.Close()
	p := &microsoftTokenProvider{cfg: MicrosoftOAuthConfig{ClientID: "app"}, endpoint: server.URL, client: server.Client(), now: func() time.Time { return now },
		resolve: func(context.Context, string) (string, error) {
			return fmt.Sprintf("rotated-secret-%d", resolutions.Add(1)), nil
		},
	}
	// Concurrent deliveries must acquire only one token.
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			token, err := p.Token(context.Background())
			if err != nil || token != "token-1" {
				t.Errorf("Token() = %q, %v", token, err)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, requests.Load())
	now = now.Add(59 * time.Minute)
	token, err := p.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "token-2", token)
	require.EqualValues(t, 2, resolutions.Load())
}

func TestMicrosoftTokenFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"denied", 401, `{"error_description":"DO-NOT-LOG-SECRET"}`},
		{"malformed", 200, `DO-NOT-LOG-SECRET`},
		{"missing token", 200, `{"token_type":"Bearer","expires_in":3600}`},
		{"expired", 200, `{"access_token":"DO-NOT-LOG-SECRET","token_type":"Bearer","expires_in":0}`},
		{"wrong type", 200, `{"access_token":"DO-NOT-LOG-SECRET","token_type":"Basic","expires_in":3600}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer server.Close()
			p := &microsoftTokenProvider{endpoint: server.URL, client: server.Client(), now: time.Now, resolve: func(context.Context, string) (string, error) { return "secret", nil }}
			for range 2 {
				token, err := p.Token(context.Background())
				require.Error(t, err)
				require.Empty(t, token)
				require.NotContains(t, err.Error(), "DO-NOT-LOG-SECRET")
			}
		})
	}
}

func TestMicrosoftTokenResolverFailureAndCancellation(t *testing.T) {
	p := &microsoftTokenProvider{now: time.Now, resolve: func(context.Context, string) (string, error) { return "", errors.New("resolution unavailable") }}
	_, err := p.Token(context.Background())
	require.EqualError(t, err, "resolution unavailable")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = p.Token(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestTokenProviderConfiguration(t *testing.T) {
	cfg := MicrosoftOAuthConfig{TenantID: "feaae8a4-e991-4da8-b4e2-cc9d19b6f2fe", ClientID: "9e8cadb0-281d-4531-b27c-9bde7c4b8a33", ClientSecretRef: "op://vault/item/secret"}
	creds := SMTPCredentials{Username: "a@example.com", AuthType: "xoauth2"}
	r, err := newRelay(&config{microsoftOAuth: cfg, credentials: map[string]SMTPCredentials{"a": creds, "b": creds, "legacy": {AuthType: "login"}}})
	require.NoError(t, err)
	require.NotNil(t, r.tokens)
	require.Equal(t, cfg, r.tokens.cfg)
	provider, err := newMicrosoftTokenProvider(MicrosoftOAuthConfig{}, map[string]SMTPCredentials{"static": {AccessToken: "manual-token", AuthType: "xoauth2"}})
	require.NoError(t, err)
	require.Nil(t, provider)
	_, err = newMicrosoftTokenProvider(cfg, map[string]SMTPCredentials{"sender@example.com": {AuthType: "xoauth2"}})
	require.NoError(t, err)
	for _, field := range []string{"tenant", "client", "reference", "empty reference segment", "username", "static"} {
		t.Run(field, func(t *testing.T) {
			badConfig := cfg
			bad := creds
			key := "a"
			switch field {
			case "tenant":
				badConfig.TenantID = "../common"
			case "client":
				badConfig.ClientID = "invalid"
			case "reference":
				badConfig.ClientSecretRef = "plaintext-secret"
			case "empty reference segment":
				badConfig.ClientSecretRef = "op://vault//secret"
			case "username":
				bad.Username = ""
				key = ""
			case "static":
				bad.AccessToken = "old-token"
			}
			_, err := newMicrosoftTokenProvider(badConfig, map[string]SMTPCredentials{key: bad})
			require.Error(t, err)
			require.NotContains(t, err.Error(), "plaintext-secret")
		})
	}
}

func TestOnePasswordServiceAccountRequired(t *testing.T) {
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "")
	_, err := onePasswordResolver()(context.Background(), "op://vault/item/secret")
	require.EqualError(t, err, "OP_SERVICE_ACCOUNT_TOKEN is required")
}

func TestTokenFailuresLoggedAtErrorLevel(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error_description":"sensitive-response"}`)
	}))
	defer server.Close()
	p := &microsoftTokenProvider{endpoint: server.URL, client: server.Client(), now: time.Now,
		resolve: func(context.Context, string) (string, error) { return "sensitive-secret", nil },
	}
	_, err := p.Token(context.Background())
	require.Error(t, err)
	output := logs.String()
	require.Contains(t, output, `"level":"ERROR"`)
	require.Contains(t, output, `"stage":"requesting_token"`)
	require.Contains(t, output, `"http_status":401`)
	require.Contains(t, output, `"request_id"`)
	require.NotContains(t, output, "sensitive-response")
	require.NotContains(t, output, "sensitive-secret")
}

func TestTokenDebugLoggingDoesNotExposeSecrets(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	now := time.Now()
	deny := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if deny {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error_description":"sensitive-error-body"}`)
			return
		}
		fmt.Fprint(w, `{"access_token":"sensitive-access-token","token_type":"Bearer","expires_in":3600}`)
	}))
	defer server.Close()
	p := &microsoftTokenProvider{endpoint: server.URL, client: server.Client(), now: func() time.Time { return now },
		resolve: func(context.Context, string) (string, error) { return "sensitive-client-secret", nil },
	}
	_, err := p.Token(context.Background())
	require.NoError(t, err)
	_, err = p.Token(context.Background())
	require.NoError(t, err)
	now = now.Add(time.Hour)
	deny = true
	_, err = p.Token(context.Background())
	require.Error(t, err)
	output := logs.String()
	for _, expected := range []string{"initial_acquisition", "using cached Microsoft access token", "renewal_due", "Microsoft access token obtained", "refresh_at", "request_id", "Microsoft token acquisition failed", "http_status"} {
		require.Contains(t, output, expected)
	}
	for _, sensitive := range []string{"sensitive-client-secret", "sensitive-access-token", "sensitive-error-body"} {
		require.NotContains(t, output, sensitive)
	}
}

func TestTokenAcquisitionFailureDefersDelivery(t *testing.T) {
	cfg := &config{
		microsoftOAuth: MicrosoftOAuthConfig{TenantID: "feaae8a4-e991-4da8-b4e2-cc9d19b6f2fe", ClientID: "9e8cadb0-281d-4531-b27c-9bde7c4b8a33", ClientSecretRef: "op://vault/item/secret"},
		credentials:    map[string]SMTPCredentials{"default": {Username: "sender@example.com", AuthType: "xoauth2"}},
	}
	r, err := newRelay(cfg)
	require.NoError(t, err)
	r.tokens = &microsoftTokenProvider{now: time.Now, resolve: func(context.Context, string) (string, error) { return "", errors.New("secret unavailable") }}
	err = r.mailHandler(cfg)(context.Background(), smtpd.Peer{Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2525}}, smtpd.Envelope{Sender: "sender@example.com"})
	var smtpErr *textproto.Error
	require.ErrorAs(t, err, &smtpErr)
	require.Equal(t, 451, smtpErr.Code)
}

func TestTokenWaitCanBeCanceled(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	p := &microsoftTokenProvider{now: time.Now, resolve: func(ctx context.Context, _ string) (string, error) {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return "", errors.New("unavailable")
	}}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = p.Token(context.Background()) }()
	defer func() { close(release); <-done }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := p.Token(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

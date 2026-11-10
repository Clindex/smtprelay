package auth

import (
	"net/smtp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestXOAuth2AuthStart(t *testing.T) {
	t.Parallel()

	auth := XOAuth2Auth("user@example.com", "access-token", "smtp.office365.com")

	mechanism, initialResponse, err := auth.Start(&smtp.ServerInfo{
		Name: "smtp.office365.com",
		TLS:  true,
	})
	require.NoError(t, err)
	require.Equal(t, "XOAUTH2", mechanism)
	require.Equal(t, "user=user@example.com\x01auth=Bearer access-token\x01\x01", string(initialResponse))
}

func TestXOAuth2AuthRequiresTLS(t *testing.T) {
	t.Parallel()

	auth := XOAuth2Auth("user@example.com", "access-token", "smtp.office365.com")

	_, _, err := auth.Start(&smtp.ServerInfo{Name: "smtp.office365.com"})
	require.EqualError(t, err, "unencrypted connection")
}

package auth

import (
	"errors"
	"fmt"
	"net/smtp"
)

type xoauth2Auth struct {
	username, accessToken, host string
}

func XOAuth2Auth(username, accessToken, host string) smtp.Auth {
	return &xoauth2Auth{username, accessToken, host}
}

func (a *xoauth2Auth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// Must have TLS, or else localhost server.
	// Note: If TLS is not true, then we can't trust ANYTHING in ServerInfo.
	// In particular, it doesn't matter if the server advertises XOAUTH2 auth.
	// That might just be the attacker saying
	// "it's ok, you can trust me with your token."
	if !server.TLS && !isLocalhost(server.Name) {
		return "", nil, errors.New("unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	initialResponse := fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", a.username, a.accessToken)
	return "XOAUTH2", []byte(initialResponse), nil
}

func (a *xoauth2Auth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		// An empty response terminates the failed XOAUTH2 exchange.
		return []byte{}, nil
	}

	return nil, nil
}

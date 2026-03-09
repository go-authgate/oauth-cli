package tui

import (
	"errors"

	"github.com/go-authgate/sdk-go/tokenstore"
)

// ErrRefreshTokenExpired indicates the refresh token has expired or is invalid.
var ErrRefreshTokenExpired = errors.New("refresh token expired or invalid")

// TokenStorage holds persisted OAuth tokens for one client.
type TokenStorage = tokenstore.Token

// PKCEParams holds the code verifier and challenge for PKCE (RFC 7636).
type PKCEParams struct {
	Verifier  string
	Challenge string
	Method    string
}

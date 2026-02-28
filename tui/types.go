package tui

import (
	"errors"
	"time"
)

// ErrRefreshTokenExpired indicates the refresh token has expired or is invalid.
var ErrRefreshTokenExpired = errors.New("refresh token expired or invalid")

// TokenStorage holds persisted OAuth tokens for one client.
type TokenStorage struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	ClientID     string    `json:"client_id"`
}

// TokenStorageMap manages tokens for multiple clients in one file.
type TokenStorageMap struct {
	Tokens map[string]*TokenStorage `json:"tokens"`
}

// PKCEParams holds the code verifier and challenge for PKCE (RFC 7636).
type PKCEParams struct {
	Verifier  string
	Challenge string
	Method    string
}

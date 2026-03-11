package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-authgate/oauth-cli/tui"
	"github.com/go-authgate/sdk-go/credstore"

	tea "charm.land/bubbletea/v2"
	retry "github.com/appleboy/go-httpretry"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

var (
	serverURL      string
	clientID       string
	clientSecret   string
	redirectURI    string
	callbackPort   int
	scope          string
	tokenFile      string
	tokenStoreMode string
	tokenStore     credstore.Store[credstore.Token]
	configOnce     sync.Once
	retryClient    *retry.Client
	configWarnings []string

	flagServerURL    *string
	flagClientID     *string
	flagClientSecret *string
	flagRedirectURI  *string
	flagCallbackPort *int
	flagScope        *string
	flagTokenFile    *string
	flagTokenStore   *string
)

const (
	tokenExchangeTimeout     = 10 * time.Second
	tokenVerificationTimeout = 10 * time.Second
	refreshTokenTimeout      = 10 * time.Second
	maxResponseSize          = 1 << 20 // 1 MB
)

func init() {
	_ = godotenv.Load()

	flagServerURL = flag.String(
		"server-url",
		"",
		"OAuth server URL (default: http://localhost:8080 or SERVER_URL env)",
	)
	flagClientID = flag.String("client-id", "", "OAuth client ID (required, or set CLIENT_ID env)")
	flagClientSecret = flag.String(
		"client-secret",
		"",
		"OAuth client secret (confidential clients only; omit for public/PKCE clients)",
	)
	flagRedirectURI = flag.String(
		"redirect-uri",
		"",
		"Redirect URI registered with the OAuth server (default: http://localhost:CALLBACK_PORT/callback)",
	)
	flagCallbackPort = flag.Int(
		"port",
		0,
		"Local port for the callback server (default: 8888 or CALLBACK_PORT env)",
	)
	flagScope = flag.String("scope", "", "Space-separated OAuth scopes (default: \"read write\")")
	flagTokenFile = flag.String(
		"token-file",
		"",
		"Token storage file (default: .authgate-tokens.json or TOKEN_FILE env)",
	)
	flagTokenStore = flag.String(
		"token-store",
		"",
		"Token storage backend: auto, file, keyring (default: auto or TOKEN_STORE env)",
	)
}

// initConfig parses flags and initializes all configuration.
func initConfig() {
	configOnce.Do(doInitConfig)
}

func doInitConfig() {
	flag.Parse()

	serverURL = getConfig(*flagServerURL, "SERVER_URL", "http://localhost:8080")
	clientID = getConfig(*flagClientID, "CLIENT_ID", "")
	clientSecret = getConfig(*flagClientSecret, "CLIENT_SECRET", "")
	if *flagClientSecret != "" {
		configWarnings = append(configWarnings,
			"Client secret passed via command-line flag. "+
				"This may be visible in process listings. "+
				"Consider using CLIENT_SECRET env var or .env file instead.")
	}
	scope = getConfig(*flagScope, "SCOPE", "read write")
	tokenFile = getConfig(*flagTokenFile, "TOKEN_FILE", ".authgate-tokens.json")

	// Resolve callback port (int flag needs special handling).
	portStr := ""
	if *flagCallbackPort != 0 {
		portStr = strconv.Itoa(*flagCallbackPort)
	}
	portStr = getConfig(portStr, "CALLBACK_PORT", "8888")
	if _, err := fmt.Sscanf(portStr, "%d", &callbackPort); err != nil || callbackPort <= 0 {
		callbackPort = 8888
	}

	// Resolve redirect URI (default depends on port, so compute after port is known).
	defaultRedirectURI := fmt.Sprintf("http://localhost:%d/callback", callbackPort)
	redirectURI = getConfig(*flagRedirectURI, "REDIRECT_URI", defaultRedirectURI)

	// Validate SERVER_URL.
	if err := validateServerURL(serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid SERVER_URL: %v\n", err)
		os.Exit(1)
	}

	if strings.HasPrefix(strings.ToLower(serverURL), "http://") {
		configWarnings = append(configWarnings,
			"Using HTTP instead of HTTPS. Tokens will be transmitted in plaintext!")
		configWarnings = append(configWarnings,
			"This is only safe for local development. Use HTTPS in production.")
	}

	if clientID == "" {
		fmt.Println("Error: CLIENT_ID not set. Please provide it via:")
		fmt.Println("  1. Command-line flag: -client-id=<your-client-id>")
		fmt.Println("  2. Environment variable: CLIENT_ID=<your-client-id>")
		fmt.Println("  3. .env file: CLIENT_ID=<your-client-id>")
		fmt.Println("\nYou can find the client_id in the server startup logs.")
		os.Exit(1)
	}

	if _, err := uuid.Parse(clientID); err != nil {
		configWarnings = append(configWarnings,
			"CLIENT_ID doesn't appear to be a valid UUID: "+clientID)
	}

	// Build HTTP client with TLS and retry support.
	baseHTTPClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	var err error
	retryClient, err = retry.NewBackgroundClient(retry.WithHTTPClient(baseHTTPClient))
	if err != nil {
		panic(fmt.Sprintf("failed to create retry client: %v", err))
	}

	const defaultKeyringService = "authgate-oauth-cli"
	tokenStoreMode = getConfig(*flagTokenStore, "TOKEN_STORE", "auto")
	var warnings []string
	var err2 error
	tokenStore, warnings, err2 = initTokenStore(tokenStoreMode, tokenFile, defaultKeyringService)
	if err2 != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err2)
		os.Exit(1)
	}
	configWarnings = append(configWarnings, warnings...)
}

// initTokenStore creates a token store based on the given mode.
// It returns the store, any warnings, and an error if the mode is invalid.
func initTokenStore(
	mode, filePath, keyringService string,
) (credstore.Store[credstore.Token], []string, error) {
	fileStore := credstore.NewTokenFileStore(filePath)
	var warnings []string

	switch mode {
	case "file":
		return fileStore, nil, nil
	case "keyring":
		return credstore.NewTokenKeyringStore(keyringService), nil, nil
	case "auto":
		ss := credstore.DefaultTokenSecureStore(keyringService, filePath)
		if !ss.UseKeyring() {
			warnings = append(warnings,
				"OS keyring unavailable, falling back to file-based token storage")
		}
		return ss, warnings, nil
	default:
		return nil, nil, fmt.Errorf(
			"invalid token-store value: %s (must be auto, file, or keyring)",
			mode,
		)
	}
}

func getConfig(flagValue, envKey, defaultValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return getEnv(envKey, defaultValue)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func validateServerURL(rawURL string) error {
	if rawURL == "" {
		return errors.New("server URL cannot be empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https, got: %s", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("URL must include a host")
	}
	return nil
}

// isPublicClient returns true when no client secret is configured —
// i.e., this is a public client that must use PKCE.
func isPublicClient() bool {
	return clientSecret == ""
}

// -----------------------------------------------------------------------
// Token storage
// -----------------------------------------------------------------------

// ErrorResponse is an OAuth error payload.
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// tokenResponse is the JSON structure returned by /oauth/token.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// parseOAuthError attempts to extract a structured OAuth error from a non-200
// response body. Falls back to including the raw body in the error message.
func parseOAuthError(statusCode int, body []byte, action string) error {
	var errResp ErrorResponse
	if jsonErr := json.Unmarshal(body, &errResp); jsonErr == nil && errResp.Error != "" {
		return fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
	}
	return fmt.Errorf("%s failed with status %d: %s", action, statusCode, string(body))
}

// validateTokenResponse performs basic sanity checks on a token response.
func validateTokenResponse(accessToken, tokenType string, expiresIn int) error {
	if accessToken == "" {
		return errors.New("access_token is empty")
	}
	if len(accessToken) < 10 {
		return fmt.Errorf("access_token is too short (length: %d)", len(accessToken))
	}
	if expiresIn <= 0 {
		return fmt.Errorf("expires_in must be positive, got: %d", expiresIn)
	}
	if tokenType != "" && tokenType != "Bearer" {
		return fmt.Errorf("unexpected token_type: %s (expected Bearer)", tokenType)
	}
	return nil
}

// -----------------------------------------------------------------------
// Authorization Code Flow
// -----------------------------------------------------------------------

// buildAuthURL constructs the /oauth/authorize URL with all required parameters.
func buildAuthURL(state string, pkce *tui.PKCEParams) string {
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", scope)
	params.Set("state", state)
	params.Set("code_challenge", pkce.Challenge)
	params.Set("code_challenge_method", pkce.Method)

	return serverURL + "/oauth/authorize?" + params.Encode()
}

// exchangeCode exchanges an authorization code for access + refresh tokens.
func exchangeCode(ctx context.Context, code, codeVerifier string) (*tui.TokenStorage, error) {
	ctx, cancel := context.WithTimeout(ctx, tokenExchangeTimeout)
	defer cancel()

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)

	// PKCE is always enabled (defense in depth).
	data.Set("code_verifier", codeVerifier)
	if !isPublicClient() {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		serverURL+"/oauth/token",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := retryClient.DoWithContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseOAuthError(resp.StatusCode, body, "token exchange")
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if err := validateTokenResponse(
		tokenResp.AccessToken,
		tokenResp.TokenType,
		tokenResp.ExpiresIn,
	); err != nil {
		return nil, fmt.Errorf("invalid token response: %w", err)
	}

	return &tui.TokenStorage{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		ClientID:     clientID,
	}, nil
}

// -----------------------------------------------------------------------
// Token refresh
// -----------------------------------------------------------------------

func refreshAccessToken(ctx context.Context, refreshToken string) (*tui.TokenStorage, error) {
	ctx, cancel := context.WithTimeout(ctx, refreshTokenTimeout)
	defer cancel()

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)
	if !isPublicClient() {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		serverURL+"/oauth/token",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := retryClient.DoWithContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Check for expired/invalid refresh token before general error handling.
		var errResp ErrorResponse
		if jsonErr := json.Unmarshal(body, &errResp); jsonErr == nil && errResp.Error != "" {
			if errResp.Error == "invalid_grant" || errResp.Error == "invalid_token" {
				return nil, tui.ErrRefreshTokenExpired
			}
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, parseOAuthError(resp.StatusCode, body, "refresh")
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if err := validateTokenResponse(
		tokenResp.AccessToken,
		tokenResp.TokenType,
		tokenResp.ExpiresIn,
	); err != nil {
		return nil, fmt.Errorf("invalid token response: %w", err)
	}

	// Preserve the old refresh token in fixed-mode (server may not return a new one).
	newRefreshToken := tokenResp.RefreshToken
	if newRefreshToken == "" {
		newRefreshToken = refreshToken
	}

	storage := &tui.TokenStorage{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		ClientID:     clientID,
	}

	return storage, nil
}

// -----------------------------------------------------------------------
// Token verification / API demo
// -----------------------------------------------------------------------

func verifyToken(ctx context.Context, accessToken string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, tokenVerificationTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/oauth/tokeninfo", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := retryClient.DoWithContext(ctx, req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", parseOAuthError(resp.StatusCode, body, "token verification")
	}

	return string(body), nil
}

// makeAPICallWithAutoRefresh demonstrates the 401 → refresh → retry pattern.
func makeAPICallWithAutoRefresh(ctx context.Context, storage *tui.TokenStorage) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/oauth/tokeninfo", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+storage.AccessToken)

	resp, err := retryClient.DoWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Drain and close body immediately so the HTTP transport can reuse the connection.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		newStorage, err := refreshAccessToken(ctx, storage.RefreshToken)
		if err != nil {
			if err == tui.ErrRefreshTokenExpired {
				return tui.ErrRefreshTokenExpired
			}
			return fmt.Errorf("refresh failed: %w", err)
		}

		*storage = *newStorage

		req, err = http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			serverURL+"/oauth/tokeninfo",
			nil,
		)
		if err != nil {
			return fmt.Errorf("failed to create retry request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+storage.AccessToken)

		resp, err = retryClient.DoWithContext(ctx, req)
		if err != nil {
			return fmt.Errorf("retry failed: %w", err)
		}
		defer resp.Body.Close()
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API call failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	initConfig()

	clientMode := "public (PKCE)"
	if !isPublicClient() {
		clientMode = "confidential"
	}

	deps := tui.Deps{
		LoadTokens: func() (*tui.TokenStorage, error) {
			tok, err := tokenStore.Load(clientID)
			if err != nil {
				return nil, err
			}
			return &tok, nil
		},
		RefreshToken: func(ctx context.Context, refreshToken string) (*tui.TokenStorage, string, error) {
			storage, err := refreshAccessToken(ctx, refreshToken)
			if err != nil {
				return nil, "", err
			}
			saveWarning := ""
			if saveErr := tokenStore.Save(storage.ClientID, *storage); saveErr != nil {
				saveWarning = fmt.Sprintf("Warning: Failed to save refreshed tokens: %v", saveErr)
			}
			return storage, saveWarning, nil
		},
		GenerateState: generateState,
		GeneratePKCE:  GeneratePKCE,
		BuildAuthURL:  buildAuthURL,
		OpenBrowser:   openBrowser,
		StartCallback: startCallbackServer,
		ExchangeCode:  exchangeCode,
		SaveTokens: func(storage *tui.TokenStorage) error {
			return tokenStore.Save(storage.ClientID, *storage)
		},
		VerifyToken:  verifyToken,
		MakeAPICall:  makeAPICallWithAutoRefresh,
		CallbackPort: callbackPort,
	}

	p := tea.NewProgram(
		tui.NewOAuthModel(ctx, deps, clientMode, serverURL, clientID, configWarnings),
	)
	finalRaw, err := p.Run()
	if err != nil {
		stop()
		fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
		os.Exit(1)
	}
	stop()
	if m, ok := finalRaw.(tui.OAuthModel); ok && m.ExitCode != 0 {
		os.Exit(m.ExitCode)
	}
}

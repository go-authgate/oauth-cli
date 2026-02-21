# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A CLI tool that implements the OAuth 2.0 Authorization Code Flow with PKCE for authenticating with an AuthGate server. Opens the browser for user authorization, receives the callback via a local HTTP server, exchanges the code for tokens, and manages token lifecycle (storage, refresh, reuse).

Supports both public clients (PKCE-only) and confidential clients (PKCE + client secret).

## Development Commands

Build the binary:

```bash
make build          # Builds to bin/oauth-cli
go run .            # Run directly without building
```

Testing:

```bash
make test           # Run all tests with coverage
make coverage       # View coverage in browser
go test ./... -v    # Run tests verbose
go test -run TestSpecificFunction  # Run a single test
```

Linting and formatting:

```bash
make lint           # Run golangci-lint
make fmt            # Format code with golangci-lint
```

Development workflow:

```bash
make dev            # Hot reload with air (installs air if needed)
```

Other commands:

```bash
make clean          # Remove build artifacts and coverage files
make rebuild        # Clean then build
make help           # Show all available make targets
```

## Architecture

### File Organization

All code is in the main package at the repository root. No subdirectories or internal packages.

Key files:

- `main.go` - Entry point, config, token lifecycle, OAuth flow orchestration
- `callback.go` - Local HTTP server for OAuth callback handling
- `pkce.go` - PKCE code verifier/challenge generation (RFC 7636)
- `filelock.go` - File locking for concurrent token file access
- `browser.go` - Cross-platform browser opening

### Core Flow

1. **Initialization** (`initConfig`): Parse flags, load `.env`, validate config, create HTTP retry client with TLS 1.2+
2. **Token Check**: Try to load existing tokens from disk
   - Valid token → use immediately
   - Expired token → attempt refresh
   - No token or refresh fails → start Authorization Code Flow
3. **Authorization Code Flow** (`performAuthCodeFlow`):
   - Generate PKCE verifier/challenge + state (CSRF protection)
   - Open browser to `/oauth/authorize` with all params
   - Start local callback server on port 8888 (default)
   - Wait for OAuth callback with authorization code
   - Exchange code for tokens (PKCE verifier + client secret if confidential)
   - Save tokens to file with atomic write
4. **Token Exchange in Callback**: The token exchange happens **inside the HTTP callback handler** so the browser tab shows the true outcome (success/failure) rather than a premature success page
5. **Token Storage**: Multi-client JSON file with file locking for concurrent safety

### Key Design Patterns

**Context Propagation**: All HTTP requests and long-running operations accept `context.Context`. The main function uses `signal.NotifyContext` to handle SIGINT/SIGTERM gracefully.

**PKCE Always Enabled**: Even confidential clients use PKCE (defense in depth). Both `code_verifier` and `client_secret` are sent during token exchange for confidential clients.

**Token Refresh**: The `refreshAccessToken` function handles refresh token rotation (preserves old refresh token if server doesn't return a new one).

**Callback Server Lifecycle**:

- Starts before opening browser
- Validates state parameter (CSRF protection)
- Holds HTTP response open during token exchange (browser sees true outcome)
- Uses `sync.Once` to ensure exchange happens exactly once even if browser retries
- Shuts down after first callback or context cancellation

**File Locking**: Uses a separate `.lock` file to coordinate concurrent access to the token file. Implements stale lock detection (removes locks older than 30 seconds).

**HTTP Client**: Uses `github.com/appleboy/go-httpretry` for automatic retries with exponential backoff. TLS 1.2+ enforced. Warns when using HTTP (not HTTPS) for development.

### Configuration Precedence

Flag > Environment Variable > Default

All config is initialized once via `initConfig()` which sets global variables. The `configInitialized` flag prevents double initialization.

### Token Storage Format

JSON file with per-client-id tokens:

```json
{
  "tokens": {
    "client-id-uuid-here": {
      "access_token": "...",
      "refresh_token": "...",
      "token_type": "Bearer",
      "expires_at": "2026-02-19T12:00:00Z",
      "client_id": "..."
    }
  }
}
```

File written with 0600 permissions via atomic rename (write to `.tmp` then rename).

### Error Handling

- OAuth errors (e.g., `access_denied`, `invalid_grant`) are parsed from JSON responses
- `ErrRefreshTokenExpired` signals when a refresh token is invalid → triggers full re-auth
- Context cancellation checked after all blocking operations (graceful shutdown)
- Exit codes: 0 (success), 1 (error), 130 (interrupted via SIGINT)

### Security Notes

- PKCE (RFC 7636) always enabled — code verifier never leaves the client
- State parameter validated on every callback (CSRF protection)
- TLS 1.2+ enforced for all HTTPS connections
- Token file written with 0600 permissions
- Warns when SERVER_URL uses plain HTTP
- Client ID validated as UUID format (warning only)

## Testing Patterns

Tests use table-driven tests with subtests (`t.Run`). Mock HTTP servers created with `httptest.NewServer` for testing OAuth endpoints.

Key test files:

- `main_test.go` - Token storage, refresh, config validation
- `callback_test.go` - Callback server behavior, state validation, concurrent requests
- `pkce_test.go` - PKCE generation, verifier/challenge encoding
- `filelock_test.go` - Concurrent access, stale lock detection

## External Dependencies

- `github.com/joho/godotenv` - Load `.env` files
- `github.com/google/uuid` - UUID validation
- `github.com/appleboy/go-httpretry` - HTTP client with retry and backoff

## Common Modifications

**Changing callback port**: Update both `-port` flag and Redirect URI in AuthGate Admin (must match).

**Adding new OAuth endpoints**: Follow the existing pattern in `main.go` — create request with context timeout, use `retryClient.DoWithContext`, check for OAuth error responses in JSON.

**Token storage changes**: Modify `TokenStorage` struct and update `loadTokens`/`saveTokens`. The atomic write pattern (temp file + rename) should be preserved.

**Browser opening**: Platform-specific logic is in `browser.go`. Uses `xdg-open` (Linux), `open` (macOS), `rundll32` (Windows).

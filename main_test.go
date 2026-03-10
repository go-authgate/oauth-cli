package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/go-authgate/oauth-cli/tui"
	"github.com/go-authgate/sdk-go/credstore"
)

func TestValidateServerURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid http", "http://localhost:8080", false},
		{"valid https", "https://auth.example.com", false},
		{"empty", "", true},
		{"no scheme", "localhost:8080", true},
		{"bad scheme", "ftp://example.com", true},
		{"no host", "http://", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateServerURL(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateServerURL(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestGetConfig_Priority(t *testing.T) {
	t.Setenv("MYKEY", "from-env")

	// Flag value wins over env.
	if got := getConfig("from-flag", "MYKEY", "default"); got != "from-flag" {
		t.Errorf("expected flag value, got %q", got)
	}

	// Env wins over default when flag is empty.
	if got := getConfig("", "MYKEY", "default"); got != "from-env" {
		t.Errorf("expected env value, got %q", got)
	}

	// Default used when both flag and env are empty.
	t.Setenv("MYKEY", "")
	if got := getConfig("", "MYKEY", "default"); got != "default" {
		t.Errorf("expected default, got %q", got)
	}
}

func TestValidateTokenResponse(t *testing.T) {
	tests := []struct {
		name        string
		accessToken string
		tokenType   string
		expiresIn   int
		wantErr     bool
	}{
		{"valid bearer", "a-long-enough-token", "Bearer", 3600, false},
		{"valid empty type", "a-long-enough-token", "", 3600, false},
		{"empty access token", "", "Bearer", 3600, true},
		{"too short token", "short", "Bearer", 3600, true},
		{"zero expires_in", "a-long-enough-token", "Bearer", 0, true},
		{"negative expires_in", "a-long-enough-token", "Bearer", -1, true},
		{"wrong token type", "a-long-enough-token", "MAC", 3600, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTokenResponse(tc.accessToken, tc.tokenType, tc.expiresIn)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateTokenResponse() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestSaveAndLoadTokens(t *testing.T) {
	// Use a non-existent path so FileStore starts fresh (empty file causes JSON parse error).
	store := credstore.NewTokenFileStore(filepath.Join(t.TempDir(), "tokens.json"))
	const testClientID = "test-client-id"

	token := credstore.Token{
		AccessToken:  "access-token-value",
		RefreshToken: "refresh-token-value",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		ClientID:     testClientID,
	}

	if err := store.Save(testClientID, token); err != nil {
		t.Fatalf("store.Save() error: %v", err)
	}

	loaded, err := store.Load(testClientID)
	if err != nil {
		t.Fatalf("store.Load() error: %v", err)
	}

	if loaded.AccessToken != token.AccessToken {
		t.Errorf("AccessToken mismatch: got %q, want %q", loaded.AccessToken, token.AccessToken)
	}
	if loaded.RefreshToken != token.RefreshToken {
		t.Errorf("RefreshToken mismatch: got %q, want %q", loaded.RefreshToken, token.RefreshToken)
	}
	if loaded.ClientID != token.ClientID {
		t.Errorf("ClientID mismatch: got %q, want %q", loaded.ClientID, token.ClientID)
	}
}

func TestSaveTokens_MultipleClients(t *testing.T) {
	store := credstore.NewTokenFileStore(filepath.Join(t.TempDir(), "tokens-multi.json"))

	// Save tokens for two different clients.
	for _, id := range []string{"client-a", "client-b"} {
		if err := store.Save(id, credstore.Token{
			AccessToken:  "token-" + id,
			RefreshToken: "refresh-" + id,
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
			ClientID:     id,
		}); err != nil {
			t.Fatalf("store.Save(%s) error: %v", id, err)
		}
	}

	// Both clients should be loadable.
	for _, id := range []string{"client-a", "client-b"} {
		tok, err := store.Load(id)
		if err != nil {
			t.Errorf("store.Load(%s) error: %v", id, err)
			continue
		}
		if tok.AccessToken != "token-"+id {
			t.Errorf("client %s: AccessToken = %q, want %q", id, tok.AccessToken, "token-"+id)
		}
	}
}

func TestBuildAuthURL_ContainsRequiredParams(t *testing.T) {
	originalServerURL := serverURL
	originalClientID := clientID
	originalRedirectURI := redirectURI
	originalScope := scope
	t.Cleanup(func() {
		serverURL = originalServerURL
		clientID = originalClientID
		redirectURI = originalRedirectURI
		scope = originalScope
	})

	serverURL = "http://localhost:8080"
	clientID = "my-client-id"
	redirectURI = "http://localhost:8888/callback"
	scope = "read write"

	pkce := &tui.PKCEParams{
		Verifier:  "test-verifier",
		Challenge: "test-challenge",
		Method:    "S256",
	}
	state := "random-state"

	u := buildAuthURL(state, pkce)

	for _, want := range []string{
		"client_id=my-client-id",
		"redirect_uri=",
		"response_type=code",
		"scope=",
		"state=random-state",
		"code_challenge=test-challenge",
		"code_challenge_method=S256",
	} {
		if !containsSubstring(u, want) {
			t.Errorf("auth URL missing %q\nURL: %s", want, u)
		}
	}
}

func TestIsPublicClient(t *testing.T) {
	orig := clientSecret
	t.Cleanup(func() { clientSecret = orig })

	clientSecret = ""
	if !isPublicClient() {
		t.Error("expected public client when secret is empty")
	}

	clientSecret = "secret"
	if isPublicClient() {
		t.Error("expected confidential client when secret is set")
	}
}

func TestInitTokenStore_File(t *testing.T) {
	store, warnings, err := initTokenStore(
		"file",
		filepath.Join(t.TempDir(), "tokens.json"),
		"test-service",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
	if _, ok := store.(*credstore.FileStore[credstore.Token]); !ok {
		t.Errorf("expected *credstore.FileStore[credstore.Token], got %T", store)
	}
}

func TestInitTokenStore_Keyring(t *testing.T) {
	store, warnings, err := initTokenStore(
		"keyring",
		filepath.Join(t.TempDir(), "tokens.json"),
		"test-service",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
	if _, ok := store.(*credstore.KeyringStore[credstore.Token]); !ok {
		t.Errorf("expected *credstore.KeyringStore[credstore.Token], got %T", store)
	}
}

func TestInitTokenStore_Auto(t *testing.T) {
	store, warnings, err := initTokenStore(
		"auto",
		filepath.Join(t.TempDir(), "tokens.json"),
		"test-service",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secureStore, ok := store.(*credstore.SecureStore[credstore.Token])
	if !ok {
		t.Fatalf("expected *credstore.SecureStore[credstore.Token], got %T", store)
	}
	// In CI / test environments the OS keyring is typically unavailable,
	// so we expect the fallback warning. On systems with a keyring the
	// warning list will be empty — both cases are valid.
	if !secureStore.UseKeyring() {
		if len(warnings) != 1 {
			t.Errorf("expected 1 fallback warning, got %d: %v", len(warnings), warnings)
		}
	} else {
		if len(warnings) != 0 {
			t.Errorf("expected no warnings when keyring available, got %v", warnings)
		}
	}
}

func TestInitTokenStore_Invalid(t *testing.T) {
	store, _, err := initTokenStore(
		"invalid",
		filepath.Join(t.TempDir(), "tokens.json"),
		"test-service",
	)
	if err == nil {
		t.Fatal("expected error for invalid mode, got nil")
	}
	if store != nil {
		t.Errorf("expected nil store on error, got %T", store)
	}
	if !containsSubstring(err.Error(), "invalid token-store value") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// containsSubstring is a helper to avoid importing strings in tests.
func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && findSubstring(s, sub)
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

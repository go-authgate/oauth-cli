package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type serverResult struct {
	storage *TokenStorage
	err     error
}

// startCallbackServerAsync starts the callback server in a goroutine and
// returns a channel that will receive the final result (storage or error).
func startCallbackServerAsync(
	t *testing.T,
	port int,
	state string,
	exchangeFn func(ctx context.Context, code string) (*TokenStorage, error),
) chan serverResult {
	t.Helper()
	ch := make(chan serverResult, 1)
	go func() {
		storage, err := startCallbackServer(context.Background(), port, state, exchangeFn)
		ch <- serverResult{storage: storage, err: err}
	}()
	// Give the server a moment to bind.
	time.Sleep(50 * time.Millisecond)
	return ch
}

// mockExchangeFn returns an exchangeFn that succeeds with a stub TokenStorage.
func mockExchangeFn(t *testing.T) func(ctx context.Context, code string) (*TokenStorage, error) {
	t.Helper()
	return func(_ context.Context, _ string) (*TokenStorage, error) {
		return &TokenStorage{
			AccessToken:  "mock-access-token",
			RefreshToken: "mock-refresh-token",
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
		}, nil
	}
}

func TestCallbackServer_Success(t *testing.T) {
	const port = 19001
	state := "test-state-success"

	ch := startCallbackServerAsync(t, port, state, mockExchangeFn(t))

	// Simulate the browser redirect.
	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?code=mycode123&state=%s",
		port, state,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Authorization Successful") {
		t.Errorf("expected success page, got: %s", string(body))
	}

	// Check that storage is returned to the CLI.
	select {
	case result := <-ch:
		if result.err != nil {
			t.Errorf("expected no error, got: %v", result.err)
		}
		if result.storage == nil || result.storage.AccessToken != "mock-access-token" {
			t.Errorf("unexpected storage: %+v", result.storage)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_ExchangeFailure(t *testing.T) {
	const port = 19006
	state := "test-state-exchange-fail"

	failFn := func(_ context.Context, _ string) (*TokenStorage, error) {
		return nil, fmt.Errorf("server returned status 400: invalid_grant")
	}
	ch := startCallbackServerAsync(t, port, state, failFn)

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?code=badcode&state=%s",
		port, state,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Authorization Failed") {
		t.Errorf("expected failure page, got: %s", string(body))
	}
	if !strings.Contains(string(body), "invalid_grant") {
		t.Errorf("expected error detail in page, got: %s", string(body))
	}

	select {
	case result := <-ch:
		if result.err == nil {
			t.Error("expected an error, got nil")
		}
		if result.storage != nil {
			t.Errorf("expected nil storage, got: %+v", result.storage)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_StateMismatch(t *testing.T) {
	const port = 19002
	state := "expected-state"

	ch := startCallbackServerAsync(t, port, state, nil)

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?code=mycode&state=wrong-state",
		port,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Authorization Failed") {
		t.Errorf("expected failure page for state mismatch, got: %s", string(body))
	}

	select {
	case result := <-ch:
		if result.err == nil {
			t.Errorf("expected error for state mismatch, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_OAuthError(t *testing.T) {
	const port = 19003
	state := "state-for-error"

	ch := startCallbackServerAsync(t, port, state, nil)

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?error=access_denied&error_description=User+denied&state=%s",
		port, state,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Authorization Failed") {
		t.Errorf("expected failure page for access_denied, got: %s", string(body))
	}

	select {
	case result := <-ch:
		if result.err == nil {
			t.Errorf("expected error for access_denied, got nil")
		}
		if !strings.Contains(result.err.Error(), "access_denied") {
			t.Errorf("expected error to mention access_denied, got: %v", result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

// TestCallbackServer_DoubleCallback verifies that a second /callback hit while
// the first result is still in the channel does not block the handler goroutine
// forever. Before the sync.Once fix, the second goroutine could block on the
// buffered-channel send until the shutdown context timed out.
func TestCallbackServer_DoubleCallback(t *testing.T) {
	const port = 19005
	state := "test-state-double"

	ch := startCallbackServerAsync(t, port, state, mockExchangeFn(t))

	url := fmt.Sprintf("http://127.0.0.1:%d/callback?code=mycode&state=%s", port, state)

	// Fire two requests nearly simultaneously so both are in-flight before the
	// server has a chance to process the first result.
	done := make(chan error, 2)
	for range 2 {
		go func() {
			resp, err := http.Get(url) //nolint:noctx,gosec
			if err == nil {
				resp.Body.Close()
			}
			done <- err
		}()
	}

	// Both handler goroutines must finish — neither should block on the send.
	for range 2 {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("a callback handler goroutine hung on channel send")
		}
	}

	// startCallbackServer must also return promptly with a valid storage.
	select {
	case result := <-ch:
		if result.err != nil {
			t.Errorf("expected no error, got: %v", result.err)
		}
		if result.storage == nil {
			t.Error("expected non-nil storage")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_MissingCode(t *testing.T) {
	const port = 19004
	state := "state-for-missing-code"

	ch := startCallbackServerAsync(t, port, state, nil)

	// Correct state but no code parameter.
	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?state=%s",
		port, state,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	select {
	case result := <-ch:
		if result.err == nil {
			t.Errorf("expected error for missing code, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

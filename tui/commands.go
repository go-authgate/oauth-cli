package tui

import (
	"context"
	"fmt"

	tea "charm.land/bubbletea/v2"
)

func cmdLoadTokens(deps Deps) tea.Cmd {
	return func() tea.Msg {
		storage, err := deps.LoadTokens()
		return msgTokensLoaded{storage: storage, err: err}
	}
}

func cmdRefreshToken(ctx context.Context, deps Deps, refreshToken string) tea.Cmd {
	return func() tea.Msg {
		storage, err := deps.RefreshToken(ctx, refreshToken)
		return msgTokenRefreshed{storage: storage, err: err}
	}
}

func cmdSetupAuthFlow(deps Deps) tea.Cmd {
	return func() tea.Msg {
		state, err := deps.GenerateState()
		if err != nil {
			return msgAuthFlowReady{err: fmt.Errorf("failed to generate state: %w", err)}
		}
		pkce, err := deps.GeneratePKCE()
		if err != nil {
			return msgAuthFlowReady{err: fmt.Errorf("failed to generate PKCE: %w", err)}
		}
		return msgAuthFlowReady{
			authURL:      deps.BuildAuthURL(state, pkce),
			state:        state,
			pkceVerifier: pkce.Verifier,
		}
	}
}

func cmdOpenBrowser(ctx context.Context, deps Deps, u string) tea.Cmd {
	return func() tea.Msg {
		return msgBrowserOpened{browserErr: deps.OpenBrowser(ctx, u)}
	}
}

func cmdWaitCallback(ctx context.Context, deps Deps, state, verifier string) tea.Cmd {
	return func() tea.Msg {
		storage, err := deps.StartCallback(ctx, deps.CallbackPort, state,
			func(cbCtx context.Context, code string) (*TokenStorage, error) {
				return deps.ExchangeCode(cbCtx, code, verifier)
			},
		)
		if err != nil {
			return msgCallbackReceived{err: err}
		}
		saveWarning := ""
		if saveErr := deps.SaveTokens(storage); saveErr != nil {
			saveWarning = fmt.Sprintf("Warning: Failed to save tokens: %v", saveErr)
		}
		return msgCallbackReceived{storage: storage, saveWarning: saveWarning}
	}
}

func cmdVerifyToken(ctx context.Context, deps Deps, token string) tea.Cmd {
	return func() tea.Msg {
		info, err := deps.VerifyToken(ctx, token)
		return msgTokenVerified{info: info, err: err}
	}
}

func cmdAPICall(ctx context.Context, deps Deps, storage *TokenStorage) tea.Cmd {
	return func() tea.Msg {
		return msgAPICallDone{err: deps.MakeAPICall(ctx, storage)}
	}
}

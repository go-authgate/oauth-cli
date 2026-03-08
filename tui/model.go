package tui

import (
	"context"
	"errors"
	"time"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// -----------------------------------------------------------------------
// Step state machine
// -----------------------------------------------------------------------

type step int

const numMainSteps = 7

const (
	stepLoadTokens   step = 0
	stepRefreshToken step = 1
	stepAuthFlow     step = 2
	stepOpenBrowser  step = 3
	stepWaitCallback step = 4
	stepVerifyToken  step = 5
	stepAPICall      step = 6
	stepDone         step = 7
)

type stepStatus int

const (
	statusPending stepStatus = iota
	statusInProgress
	statusDone
	statusSkipped
	statusFailed
)

var stepLabels = [numMainSteps]string{
	"Check existing tokens",
	"Refresh access token",
	"Set up authorization flow",
	"Open browser",
	"Wait for browser callback",
	"Verify token",
	"API call",
}

// -----------------------------------------------------------------------
// Message types
// -----------------------------------------------------------------------

type msgTokensLoaded struct {
	storage *TokenStorage
	err     error
}

type msgTokenRefreshed struct {
	storage     *TokenStorage
	saveWarning string
	err         error
}

type msgAuthFlowReady struct {
	authURL      string
	state        string
	pkceVerifier string
	err          error
}

type msgBrowserOpened struct {
	browserErr error
}

type msgCallbackReceived struct {
	storage     *TokenStorage
	saveWarning string
	err         error
}

type msgTokenVerified struct {
	info string
	err  error
}

type msgAPICallDone struct {
	err error
}

// -----------------------------------------------------------------------
// OAuthModel
// -----------------------------------------------------------------------

// OAuthModel is the bubbletea model that drives the OAuth TUI flow.
// It is exported so main.go can type-assert the value returned by p.Run().
type OAuthModel struct {
	ctx           context.Context
	deps          Deps
	currentStep   step
	stepStatuses  [numMainSteps]stepStatus
	stepMessages  [numMainSteps]string
	storage       *TokenStorage
	authURL       string
	pkceVerifier  string
	expectedState string
	spinner       spinner.Model
	warnings      []string
	ExitCode      int
	interrupted   bool
	termWidth     int
	clientMode    string
	serverURL     string
	clientID      string
}

// NewOAuthModel creates an initialized OAuthModel ready to run.
func NewOAuthModel(
	ctx context.Context,
	deps Deps,
	clientMode, srv, cid string,
	warnings []string,
) OAuthModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("86"))
	m := OAuthModel{
		ctx:        ctx,
		deps:       deps,
		clientMode: clientMode,
		serverURL:  srv,
		clientID:   cid,
		warnings:   warnings,
		spinner:    s,
	}
	m.currentStep = stepLoadTokens
	m.stepStatuses[stepLoadTokens] = statusInProgress
	return m
}

// -----------------------------------------------------------------------
// Init
// -----------------------------------------------------------------------

// Init fires the spinner and the first async step.
func (m OAuthModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, cmdLoadTokens(m.deps))
}

// -----------------------------------------------------------------------
// Update
// -----------------------------------------------------------------------

// Update handles incoming messages and drives the OAuth flow state machine.
func (m OAuthModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.termWidth = msg.Width
		return m, nil

	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			m.ExitCode = 130
			m.interrupted = true
			return m, tea.Quit
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case msgTokensLoaded:
		m.stepStatuses[stepLoadTokens] = statusDone
		if msg.err != nil || msg.storage == nil {
			m.stepMessages[stepLoadTokens] = "No existing tokens"
			return m.startStep(stepAuthFlow, cmdSetupAuthFlow(m.deps))
		}
		if time.Now().Before(msg.storage.ExpiresAt) {
			m.stepMessages[stepLoadTokens] = "Found valid token"
			m.storage = msg.storage
			return m.startStep(
				stepVerifyToken,
				cmdVerifyToken(m.ctx, m.deps, msg.storage.AccessToken),
			)
		}
		m.stepMessages[stepLoadTokens] = "Token expired"
		m.storage = msg.storage
		return m.startStep(
			stepRefreshToken,
			cmdRefreshToken(m.ctx, m.deps, msg.storage.RefreshToken),
		)

	case msgTokenRefreshed:
		if msg.err != nil {
			if isContextCanceled(msg.err) {
				return m.quitInterrupted()
			}
			m.stepStatuses[stepRefreshToken] = statusFailed
			m.stepMessages[stepRefreshToken] = msg.err.Error()
			return m.startStep(stepAuthFlow, cmdSetupAuthFlow(m.deps))
		}
		m.stepStatuses[stepRefreshToken] = statusDone
		if msg.saveWarning != "" {
			m.stepMessages[stepRefreshToken] = msg.saveWarning
		} else {
			m.stepMessages[stepRefreshToken] = "Token refreshed"
		}
		m.storage = msg.storage
		return m.startStep(stepVerifyToken, cmdVerifyToken(m.ctx, m.deps, msg.storage.AccessToken))

	case msgAuthFlowReady:
		if msg.err != nil {
			if isContextCanceled(msg.err) {
				return m.quitInterrupted()
			}
			m.stepStatuses[stepAuthFlow] = statusFailed
			m.stepMessages[stepAuthFlow] = msg.err.Error()
			m.ExitCode = 1
			return m, tea.Quit
		}
		m.stepStatuses[stepAuthFlow] = statusDone
		m.authURL = msg.authURL
		m.expectedState = msg.state
		m.pkceVerifier = msg.pkceVerifier
		return m.startStep(stepOpenBrowser, cmdOpenBrowser(m.ctx, m.deps, msg.authURL))

	case msgBrowserOpened:
		m.stepStatuses[stepOpenBrowser] = statusDone
		if msg.browserErr != nil {
			m.stepMessages[stepOpenBrowser] = "Could not open browser — use the URL below"
		} else {
			m.stepMessages[stepOpenBrowser] = "Browser opened"
		}
		return m.startStep(
			stepWaitCallback,
			cmdWaitCallback(m.ctx, m.deps, m.expectedState, m.pkceVerifier),
		)

	case msgCallbackReceived:
		if msg.err != nil {
			if isContextCanceled(msg.err) {
				return m.quitInterrupted()
			}
			m.stepStatuses[stepWaitCallback] = statusFailed
			m.stepMessages[stepWaitCallback] = msg.err.Error()
			m.ExitCode = 1
			return m, tea.Quit
		}
		m.storage = msg.storage
		m.stepStatuses[stepWaitCallback] = statusDone
		if msg.saveWarning != "" {
			m.stepMessages[stepWaitCallback] = msg.saveWarning
		} else {
			m.stepMessages[stepWaitCallback] = "Authorization complete"
		}
		return m.startStep(stepVerifyToken, cmdVerifyToken(m.ctx, m.deps, msg.storage.AccessToken))

	case msgTokenVerified:
		if msg.err != nil {
			if isContextCanceled(msg.err) {
				return m.quitInterrupted()
			}
			// Verification failure is non-fatal — still proceed to API call.
			m.stepStatuses[stepVerifyToken] = statusFailed
			m.stepMessages[stepVerifyToken] = msg.err.Error()
		} else {
			m.stepStatuses[stepVerifyToken] = statusDone
			m.stepMessages[stepVerifyToken] = "Token valid"
		}
		return m.startStep(stepAPICall, cmdAPICall(m.ctx, m.deps, m.storage))

	case msgAPICallDone:
		if msg.err != nil {
			if isContextCanceled(msg.err) {
				return m.quitInterrupted()
			}
			if errors.Is(msg.err, ErrRefreshTokenExpired) {
				// Refresh token expired during API call — restart auth sub-steps.
				m.stepStatuses[stepAPICall] = statusFailed
				m.stepMessages[stepAPICall] = "Token expired, re-authenticating..."
				m.stepStatuses[stepAuthFlow] = statusPending
				m.stepStatuses[stepOpenBrowser] = statusPending
				m.stepStatuses[stepWaitCallback] = statusPending
				m.stepStatuses[stepVerifyToken] = statusPending
				return m.startStep(stepAuthFlow, cmdSetupAuthFlow(m.deps))
			}
			m.stepStatuses[stepAPICall] = statusFailed
			m.stepMessages[stepAPICall] = msg.err.Error()
			m.ExitCode = 1
			return m, tea.Quit
		}
		m.stepStatuses[stepAPICall] = statusDone
		m.stepMessages[stepAPICall] = "API call successful"
		m.currentStep = stepDone
		m.ExitCode = 0
		return m, tea.Quit
	}

	return m, nil
}

// startStep transitions to the given step and fires cmd.
func (m OAuthModel) startStep(s step, cmd tea.Cmd) (tea.Model, tea.Cmd) {
	m.currentStep = s
	if int(s) < numMainSteps {
		m.stepStatuses[s] = statusInProgress
	}
	return m, cmd
}

func isContextCanceled(err error) bool {
	return errors.Is(err, context.Canceled)
}

// quitInterrupted marks the model as interrupted (exit code 130) and returns tea.Quit.
func (m OAuthModel) quitInterrupted() (tea.Model, tea.Cmd) {
	m.ExitCode = 130
	m.interrupted = true
	return m, tea.Quit
}

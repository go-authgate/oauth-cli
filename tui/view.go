package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

// View renders the TUI to the terminal.
func (m OAuthModel) View() tea.View {
	var b strings.Builder

	// Header box
	b.WriteString(styleHeader.Render(
		"  OAuth 2.0 Authorization Code Flow\n" +
			fmt.Sprintf("  Mode: %-20s Server: %s", m.clientMode, m.serverURL),
	))
	b.WriteString("\n\n")

	// Warnings
	for _, w := range m.warnings {
		b.WriteString("  " + styleWarning.Render("WARNING: "+w) + "\n")
	}
	if len(m.warnings) > 0 {
		b.WriteString("\n")
	}

	// Steps — only render non-pending steps
	for i := 0; i < numMainSteps; i++ {
		status := m.stepStatuses[i]
		if status == statusPending {
			continue
		}
		label := stepLabels[i]
		subMsg := m.stepMessages[i]

		var line string
		switch status {
		case statusDone:
			line = styleStepDone.Render("  ✓ " + label)
			if subMsg != "" {
				line += "  " + styleDim.Render(subMsg)
			}
		case statusFailed:
			line = styleStepFailed.Render("  ✗ " + label)
			if subMsg != "" {
				line += ": " + styleError.Render(subMsg)
			}
		case statusSkipped:
			line = styleStepSkipped.Render("  - " + label)
		case statusInProgress:
			line = "  " + m.spinner.View() + " " + label
		}
		b.WriteString(line + "\n")
	}

	// Auth URL box — shown while waiting for browser callback
	if m.currentStep == stepWaitCallback && m.authURL != "" {
		b.WriteString("\n")
		// Reserve space for box border (2) + padding (2) + indent (2).
		avail := m.termWidth - 6
		if avail < 40 {
			avail = 74 // sensible fallback before first WindowSizeMsg
		}
		b.WriteString(styleURLBox.Render(
			"  If browser did not open, visit:\n  " + styleAuthURL.Render(wrapURL(m.authURL, avail)),
		))
		b.WriteString("\n")
	}

	// Token info box — shown on successful completion
	if m.currentStep == stepDone && m.storage != nil {
		b.WriteString("\n")
		preview := m.storage.AccessToken
		if len(preview) > 20 {
			preview = preview[:20] + "..."
		}
		expiresIn := time.Until(m.storage.ExpiresAt).Round(time.Second)
		tokenContent := styleTokenLabel.Render("Access Token:") + "  " + preview + "\n" +
			styleTokenLabel.Render("Token Type:") + "  " + m.storage.TokenType + "\n" +
			styleTokenLabel.Render("Expires In:") + "  " + expiresIn.String()
		b.WriteString(styleTokenBox.Render(
			styleTokenTitle.Render("  Token Info") + "\n\n" + tokenContent,
		))
		b.WriteString("\n")
	}

	return tea.NewView(b.String())
}

// wrapURL breaks a URL across multiple lines for terminal display.
// It prefers to break just after '?' or '&' so each query parameter starts
// on its own line; otherwise it hard-breaks at maxWidth characters.
// Continuation lines are indented by two spaces to align under the first char.
func wrapURL(u string, maxWidth int) string {
	if maxWidth <= 0 || len(u) <= maxWidth {
		return u
	}
	const indent = "\n  "
	var sb strings.Builder
	for len(u) > maxWidth {
		cut := maxWidth
		// Prefer a break just after '?' or '&' in the latter half of the line.
		for i := maxWidth - 1; i >= maxWidth/2; i-- {
			if u[i] == '?' || u[i] == '&' {
				cut = i + 1
				break
			}
		}
		sb.WriteString(u[:cut])
		sb.WriteString(indent)
		u = u[cut:]
		// Continuation lines are shorter by the indent length.
		maxWidth -= len(indent) - 1
		if maxWidth < 20 {
			maxWidth = 20
		}
	}
	sb.WriteString(u)
	return sb.String()
}

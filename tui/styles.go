package tui

import "charm.land/lipgloss/v2"

var (
	styleHeader = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("86")).
			Padding(0, 1)

	styleStepDone = lipgloss.NewStyle().
			Foreground(lipgloss.Color("42"))

	styleStepFailed = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	styleStepSkipped = lipgloss.NewStyle().
				Foreground(lipgloss.Color("240"))

	styleDim = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))

	styleWarning = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Bold(true)

	styleAuthURL = lipgloss.NewStyle().
			Foreground(lipgloss.Color("33")).
			Underline(true)

	styleURLBox = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("33")).
			Padding(0, 1)

	styleTokenBox = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("42")).
			Padding(0, 1)

	styleTokenLabel = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Width(16)

	styleTokenTitle = lipgloss.NewStyle().
			Bold(true)

	styleError = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true)
)

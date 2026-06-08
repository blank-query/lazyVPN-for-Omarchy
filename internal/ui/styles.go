package ui

import "github.com/charmbracelet/lipgloss"

var (
	// Text styles — rebuilt by rebuildStyles() after theme is loaded
	TitleStyle    lipgloss.Style
	SubtitleStyle lipgloss.Style
	SelectedStyle lipgloss.Style
	ErrorStyle    lipgloss.Style
	SuccessStyle  lipgloss.Style
	WarningStyle  lipgloss.Style
	MutedStyle    lipgloss.Style
)

func init() {
	rebuildStyles()
}

// rebuildStyles recreates all style objects from current color vars.
// Called from init() (defaults) and from InitTheme() (after theme load).
func rebuildStyles() {
	TitleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorAccent)

	SubtitleStyle = lipgloss.NewStyle().
		Foreground(ColorMuted)

	SelectedStyle = lipgloss.NewStyle().
		Foreground(ColorHighlight).
		Bold(true)

	ErrorStyle = lipgloss.NewStyle().
		Foreground(ColorDanger)

	SuccessStyle = lipgloss.NewStyle().
		Foreground(ColorSuccess)

	WarningStyle = lipgloss.NewStyle().
		Foreground(ColorWarning)

	MutedStyle = lipgloss.NewStyle().
		Foreground(ColorMuted)
}

// accentStyle returns a style using the theme accent color.
func accentStyle() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(ColorAccent)
}

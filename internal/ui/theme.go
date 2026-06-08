package ui

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Theme holds colors parsed from the Omarchy theme file.
type Theme struct {
	Accent     string
	Background string
	Foreground string
	Color0     string
	Color1     string
	Color2     string
	Color3     string
	Color8     string
	Color13    string
}

// Package-level color variables used throughout the UI.
// Set to defaults on init, overwritten by applyTheme if a theme file exists.
var (
	ColorAccent    lipgloss.Color = "69"  // Focused pane border, brand
	ColorBg        lipgloss.Color = "236" // Header/footer background
	ColorFg        lipgloss.Color = "252" // Primary text
	ColorBarBorder lipgloss.Color = "240" // Header/footer border (subtle)
	ColorDimBorder lipgloss.Color = "240" // Unfocused pane border
	ColorSuccess   lipgloss.Color = "42"  // Green
	ColorDanger    lipgloss.Color = "196" // Red
	ColorWarning   lipgloss.Color = "214" // Orange/yellow
	ColorMuted     lipgloss.Color = "241" // Dim gray
	ColorHighlight lipgloss.Color = "212" // Selected/highlighted
)

// themeFilePath can be overridden in tests.
var themeFilePath string

func defaultThemeFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "omarchy", "current", "theme", "colors.toml")
}

// InitTheme loads the Omarchy theme and applies colors.
// Call once at startup before creating UI components.
func InitTheme() {
	path := themeFilePath
	if path == "" {
		path = defaultThemeFilePath()
	}
	if path == "" {
		rebuildStyles()
		return
	}
	t := loadThemeFile(path)
	applyTheme(t)
	rebuildStyles()
}

// loadThemeFile parses a flat TOML file of key = "value" lines.
// Returns nil if the file cannot be read.
func loadThemeFile(path string) *Theme {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	kv := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// Strip surrounding quotes
		val = strings.Trim(val, `"'`)
		kv[key] = val
	}

	t := &Theme{}
	if v, ok := kv["accent"]; ok {
		t.Accent = v
	}
	if v, ok := kv["background"]; ok {
		t.Background = v
	}
	if v, ok := kv["foreground"]; ok {
		t.Foreground = v
	}
	if v, ok := kv["color0"]; ok {
		t.Color0 = v
	}
	if v, ok := kv["color1"]; ok {
		t.Color1 = v
	}
	if v, ok := kv["color2"]; ok {
		t.Color2 = v
	}
	if v, ok := kv["color3"]; ok {
		t.Color3 = v
	}
	if v, ok := kv["color8"]; ok {
		t.Color8 = v
	}
	if v, ok := kv["color13"]; ok {
		t.Color13 = v
	}

	return t
}

// applyTheme sets package-level color vars from a parsed theme.
// Nil theme is safe — all vars keep their defaults.
func applyTheme(t *Theme) {
	if t == nil {
		return
	}
	if t.Accent != "" {
		ColorAccent = lipgloss.Color(t.Accent)
	}
	if t.Background != "" {
		ColorBg = lipgloss.Color(t.Background)
	}
	if t.Foreground != "" {
		ColorFg = lipgloss.Color(t.Foreground)
	}
	if t.Color8 != "" {
		ColorBarBorder = lipgloss.Color(t.Color8)
	}
	if t.Color0 != "" {
		ColorDimBorder = lipgloss.Color(t.Color0)
	}
	if t.Color2 != "" {
		ColorSuccess = lipgloss.Color(t.Color2)
	}
	if t.Color1 != "" {
		ColorDanger = lipgloss.Color(t.Color1)
	}
	if t.Color3 != "" {
		ColorWarning = lipgloss.Color(t.Color3)
	}
	if t.Color8 != "" {
		ColorMuted = lipgloss.Color(t.Color8)
	}
	if t.Color13 != "" {
		ColorHighlight = lipgloss.Color(t.Color13)
	}
}

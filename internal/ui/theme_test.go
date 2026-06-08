package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func resetColorDefaults() {
	ColorAccent = "69"
	ColorBg = "236"
	ColorFg = "252"
	ColorBarBorder = "240"
	ColorDimBorder = "240"
	ColorSuccess = "42"
	ColorDanger = "196"
	ColorWarning = "214"
	ColorMuted = "241"
	ColorHighlight = "212"
}

func TestLoadThemeFile_ValidFull(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "colors.toml")
	content := `accent = "#7aa2f7"
background = "#1a1b26"
foreground = "#a9b1d6"
color0 = "#32344a"
color1 = "#f7768e"
color2 = "#9ece6a"
color3 = "#e0af68"
color8 = "#444b6a"
color13 = "#bb9af7"
`
	os.WriteFile(path, []byte(content), 0644)

	theme := loadThemeFile(path)
	if theme == nil {
		t.Fatal("loadThemeFile returned nil for valid file")
	}
	if theme.Accent != "#7aa2f7" {
		t.Errorf("Accent = %q, want %q", theme.Accent, "#7aa2f7")
	}
	if theme.Background != "#1a1b26" {
		t.Errorf("Background = %q, want %q", theme.Background, "#1a1b26")
	}
	if theme.Foreground != "#a9b1d6" {
		t.Errorf("Foreground = %q, want %q", theme.Foreground, "#a9b1d6")
	}
	if theme.Color0 != "#32344a" {
		t.Errorf("Color0 = %q, want %q", theme.Color0, "#32344a")
	}
	if theme.Color1 != "#f7768e" {
		t.Errorf("Color1 = %q, want %q", theme.Color1, "#f7768e")
	}
	if theme.Color2 != "#9ece6a" {
		t.Errorf("Color2 = %q, want %q", theme.Color2, "#9ece6a")
	}
	if theme.Color3 != "#e0af68" {
		t.Errorf("Color3 = %q, want %q", theme.Color3, "#e0af68")
	}
	if theme.Color8 != "#444b6a" {
		t.Errorf("Color8 = %q, want %q", theme.Color8, "#444b6a")
	}
	if theme.Color13 != "#bb9af7" {
		t.Errorf("Color13 = %q, want %q", theme.Color13, "#bb9af7")
	}
}

func TestLoadThemeFile_MissingFile(t *testing.T) {
	theme := loadThemeFile("/nonexistent/path/colors.toml")
	if theme != nil {
		t.Error("loadThemeFile should return nil for missing file")
	}
}

func TestLoadThemeFile_PartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "colors.toml")
	content := `accent = "#ff0000"
color2 = "#00ff00"
`
	os.WriteFile(path, []byte(content), 0644)

	theme := loadThemeFile(path)
	if theme == nil {
		t.Fatal("loadThemeFile returned nil for partial file")
	}
	if theme.Accent != "#ff0000" {
		t.Errorf("Accent = %q, want %q", theme.Accent, "#ff0000")
	}
	if theme.Color2 != "#00ff00" {
		t.Errorf("Color2 = %q, want %q", theme.Color2, "#00ff00")
	}
	// Unset fields should be empty
	if theme.Background != "" {
		t.Errorf("Background = %q, want empty", theme.Background)
	}
}

func TestLoadThemeFile_CommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "colors.toml")
	content := `# This is a comment
accent = "#aabbcc"

# Another comment
color1 = "#ddeeff"
`
	os.WriteFile(path, []byte(content), 0644)

	theme := loadThemeFile(path)
	if theme == nil {
		t.Fatal("loadThemeFile returned nil")
	}
	if theme.Accent != "#aabbcc" {
		t.Errorf("Accent = %q, want %q", theme.Accent, "#aabbcc")
	}
	if theme.Color1 != "#ddeeff" {
		t.Errorf("Color1 = %q, want %q", theme.Color1, "#ddeeff")
	}
}

func TestApplyTheme_Nil(t *testing.T) {
	resetColorDefaults()
	applyTheme(nil)
	if string(ColorAccent) != "69" {
		t.Errorf("ColorAccent changed from default after nil applyTheme: %q", string(ColorAccent))
	}
}

func TestApplyTheme_Full(t *testing.T) {
	resetColorDefaults()
	theme := &Theme{
		Accent:     "#7aa2f7",
		Background: "#1a1b26",
		Foreground: "#a9b1d6",
		Color0:     "#32344a",
		Color1:     "#f7768e",
		Color2:     "#9ece6a",
		Color3:     "#e0af68",
		Color8:     "#444b6a",
		Color13:    "#bb9af7",
	}
	applyTheme(theme)

	if string(ColorAccent) != "#7aa2f7" {
		t.Errorf("ColorAccent = %q, want %q", string(ColorAccent), "#7aa2f7")
	}
	if string(ColorBg) != "#1a1b26" {
		t.Errorf("ColorBg = %q, want %q", string(ColorBg), "#1a1b26")
	}
	if string(ColorFg) != "#a9b1d6" {
		t.Errorf("ColorFg = %q, want %q", string(ColorFg), "#a9b1d6")
	}
	if string(ColorBarBorder) != "#444b6a" {
		t.Errorf("ColorBarBorder = %q, want %q", string(ColorBarBorder), "#444b6a")
	}
	if string(ColorDimBorder) != "#32344a" {
		t.Errorf("ColorDimBorder = %q, want %q", string(ColorDimBorder), "#32344a")
	}
	if string(ColorSuccess) != "#9ece6a" {
		t.Errorf("ColorSuccess = %q, want %q", string(ColorSuccess), "#9ece6a")
	}
	if string(ColorDanger) != "#f7768e" {
		t.Errorf("ColorDanger = %q, want %q", string(ColorDanger), "#f7768e")
	}
	if string(ColorWarning) != "#e0af68" {
		t.Errorf("ColorWarning = %q, want %q", string(ColorWarning), "#e0af68")
	}
	if string(ColorMuted) != "#444b6a" {
		t.Errorf("ColorMuted = %q, want %q", string(ColorMuted), "#444b6a")
	}
	if string(ColorHighlight) != "#bb9af7" {
		t.Errorf("ColorHighlight = %q, want %q", string(ColorHighlight), "#bb9af7")
	}

	resetColorDefaults()
}

func TestApplyTheme_Partial(t *testing.T) {
	resetColorDefaults()
	theme := &Theme{
		Accent: "#ff0000",
		Color2: "#00ff00",
	}
	applyTheme(theme)

	if string(ColorAccent) != "#ff0000" {
		t.Errorf("ColorAccent = %q, want %q", string(ColorAccent), "#ff0000")
	}
	if string(ColorSuccess) != "#00ff00" {
		t.Errorf("ColorSuccess = %q, want %q", string(ColorSuccess), "#00ff00")
	}
	// Unset fields should keep defaults
	if string(ColorBg) != "236" {
		t.Errorf("ColorBg = %q, want default %q", string(ColorBg), "236")
	}
	if string(ColorDanger) != "196" {
		t.Errorf("ColorDanger = %q, want default %q", string(ColorDanger), "196")
	}

	resetColorDefaults()
}

func TestRebuildStyles(t *testing.T) {
	resetColorDefaults()
	ColorAccent = lipgloss.Color("#ff0000")
	ColorSuccess = lipgloss.Color("#00ff00")

	rebuildStyles()

	// TitleStyle should use the updated accent
	rendered := TitleStyle.Render("test")
	if rendered == "" {
		t.Error("TitleStyle.Render returned empty string")
	}
	// SuccessStyle should use the updated success color
	rendered = SuccessStyle.Render("ok")
	if rendered == "" {
		t.Error("SuccessStyle.Render returned empty string")
	}

	resetColorDefaults()
	rebuildStyles()
}

func TestInitTheme_MissingFile(t *testing.T) {
	resetColorDefaults()
	themeFilePath = "/nonexistent/theme/colors.toml"
	InitTheme()

	// Should keep defaults
	if string(ColorAccent) != "69" {
		t.Errorf("ColorAccent = %q, want default %q", string(ColorAccent), "69")
	}

	themeFilePath = ""
	resetColorDefaults()
	rebuildStyles()
}

func TestInitTheme_ValidFile(t *testing.T) {
	resetColorDefaults()
	dir := t.TempDir()
	path := filepath.Join(dir, "colors.toml")
	content := `accent = "#7aa2f7"
color0 = "#32344a"
color8 = "#444b6a"
`
	os.WriteFile(path, []byte(content), 0644)

	themeFilePath = path
	InitTheme()

	if string(ColorAccent) != "#7aa2f7" {
		t.Errorf("ColorAccent = %q, want %q", string(ColorAccent), "#7aa2f7")
	}
	if string(ColorDimBorder) != "#32344a" {
		t.Errorf("ColorDimBorder = %q, want %q", string(ColorDimBorder), "#32344a")
	}
	if string(ColorBarBorder) != "#444b6a" {
		t.Errorf("ColorBarBorder = %q, want %q", string(ColorBarBorder), "#444b6a")
	}

	themeFilePath = ""
	resetColorDefaults()
	rebuildStyles()
}

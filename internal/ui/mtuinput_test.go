package ui

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

func TestNewMTUInput(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	// Default config has CustomMTU = 1420
	m := NewMTUInput(cfg)
	if m.input != "1420" {
		t.Errorf("input should be pre-filled with default 1420, got %q", m.input)
	}

	// With custom value
	cfg.CustomMTU = 1400
	m = NewMTUInput(cfg)
	if m.input != "1400" {
		t.Errorf("input = %q, want '1400'", m.input)
	}
}

func TestMTUInputInit(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	if m.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestMTUInputEsc(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestMTUInputTyping(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	m.input = "" // Clear default to test typing

	// Type digits
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'0'}})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'0'}})

	if m.input != "1400" {
		t.Errorf("input = %q, want '1400'", m.input)
	}

	// Backspace
	m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	if m.input != "140" {
		t.Errorf("input after backspace = %q, want '140'", m.input)
	}

	// Ignore non-digits
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	if m.input != "140" {
		t.Errorf("input should ignore non-digits, got %q", m.input)
	}
}

func TestMTUInputSubmitEmpty(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	m.input = "" // clear

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	mi := model.(*MTUInput)
	if mi.err == "" {
		t.Error("empty input should produce error")
	}
	if !strings.Contains(mi.err, "required") {
		t.Errorf("error = %q, should mention 'required'", mi.err)
	}
}

func TestMTUInputSubmitZero(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	m.input = "0"

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	mi := model.(*MTUInput)
	if mi.err == "" {
		t.Error("zero should produce error (below 1280)")
	}
}

func TestMTUInputSubmitValid(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	m.input = "1400"

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter should return cmd")
	}

	if cfg.CustomMTU != 1400 {
		t.Errorf("CustomMTU = %d, want 1400", cfg.CustomMTU)
	}
}

func TestMTUInputSubmitTooLow(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	m.input = "1000" // below 1280

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	mi := model.(*MTUInput)
	if mi.err == "" {
		t.Error("should have error for MTU below 1280")
	}
	if !strings.Contains(mi.err, "1000") || !strings.Contains(mi.err, "below") {
		t.Errorf("error = %q, should mention value and 'below'", mi.err)
	}
}

func TestMTUInputSubmitTooHigh(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	m.input = "10000" // above 9000

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	mi := model.(*MTUInput)
	if mi.err == "" {
		t.Error("should have error for MTU above 9000")
	}
	if !strings.Contains(mi.err, "10000") || !strings.Contains(mi.err, "exceeds") {
		t.Errorf("error = %q, should mention value and 'exceeds'", mi.err)
	}
}

func TestMTUInputWindowSize(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	if m.width != 100 {
		t.Errorf("width = %d, want 100", m.width)
	}
}

func TestMTUInputView(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	view := m.View()

	if !strings.Contains(view, "Custom MTU") {
		t.Error("view should contain title")
	}
	if !strings.Contains(view, "Default: 1420") {
		t.Error("view should show default hint")
	}
	if !strings.Contains(view, "enter: save") {
		t.Error("view should contain help")
	}
}

func TestMTUInputViewWithError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	m.err = "Invalid value"

	view := m.View()
	if !strings.Contains(view, "Invalid value") {
		t.Error("view should show error message")
	}
}

func TestMTUInputViewConnected(t *testing.T) {
	mockConnected(t)

	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	view := m.View()

	if !strings.Contains(view, "Takes effect on next connection") {
		t.Error("should show note when connected")
	}
}

func TestMTUInputViewDisconnected(t *testing.T) {
	mockDisconnected(t)

	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	view := m.View()

	if strings.Contains(view, "Takes effect on next connection") {
		t.Error("should not show note when disconnected")
	}
}

func TestMTUInputBackspaceEmpty(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

	m := NewMTUInput(cfg)
	m.input = "" // Clear to test backspace on empty

	// Backspace on empty should not panic
	m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	if m.input != "" {
		t.Errorf("input should still be empty, got %q", m.input)
	}
}

func TestMTUInputBoundaryValues(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		wantMTU int
	}{
		{"1280", false, 1280}, // minimum valid
		{"1279", true, 0},     // just below minimum
		{"9000", false, 9000}, // maximum valid
		{"9001", true, 0},     // just above maximum
		{"1420", false, 1420}, // WireGuard default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.ConfigDir = t.TempDir()
			cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")

			m := NewMTUInput(cfg)
			m.input = tt.input

			model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
			mi := model.(*MTUInput)

			if tt.wantErr {
				if mi.err == "" {
					t.Errorf("expected error for input %q", tt.input)
				}
			} else {
				if mi.err != "" {
					t.Errorf("unexpected error for input %q: %s", tt.input, mi.err)
				}
				if cfg.CustomMTU != tt.wantMTU {
					t.Errorf("CustomMTU = %d, want %d", cfg.CustomMTU, tt.wantMTU)
				}
			}
		})
	}
}

package ui

import (
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

// FuzzMTUInputUpdate hammers the MTU input model with arbitrary key strings
// and arbitrary window sizes — must not panic.
func FuzzMTUInputUpdate(f *testing.F) {
	f.Add("1420", "enter")
	f.Add("", "backspace")
	f.Add("99999", "enter")
	f.Add("abc", "1")
	f.Add("0", "esc")
	f.Fuzz(func(t *testing.T, initial, key string) {
		cfg := config.DefaultConfig()
		cfg.CustomMTU = 1420
		m := NewMTUInput(cfg)
		m.input = initial
		// Window resize first
		_, _ = m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
		// Then a key
		_, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
		// And an unknown message type
		_, _ = m.Update("garbage string as msg")
	})
}

// FuzzSettingsUpdate hammers settings with arbitrary key inputs.
func FuzzSettingsUpdate(f *testing.F) {
	f.Add("up")
	f.Add("down")
	f.Add("enter")
	f.Add(" ")
	f.Add("\x00")
	f.Add("\x1b")
	f.Fuzz(func(t *testing.T, key string) {
		cfg := config.DefaultConfig()
		m := NewSettings(cfg)
		_, _ = m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
		_, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
	})
}

// FuzzDashboardUpdate hammers the dashboard model with arbitrary keys plus
// a random row position — exercises toggle paths where the recent
// auth-retry / stale-closure / LAN-cycle fixes live. Must not panic across
// arbitrary key sequences, garbage tea.Msg types, or interleaved resizes.
func FuzzDashboardUpdate(f *testing.F) {
	f.Add("\t", uint8(0))     // Tab
	f.Add("\x1b", uint8(0))   // esc
	f.Add(" ", uint8(0))      // space
	f.Add("\r", uint8(7))     // enter at row 7
	f.Add("j", uint8(3))      // down (vim-style)
	f.Add("\x00", uint8(255)) // null byte, max row
	f.Add("ü", uint8(15))     // multibyte rune
	f.Fuzz(func(t *testing.T, keys string, row uint8) {
		cfg := config.DefaultConfig()
		d := NewDashboard(cfg)
		_, _ = d.Update(tea.WindowSizeMsg{Width: 200, Height: 50})
		// Walk down `row` rows to vary cursor position
		for i := uint8(0); i < row; i++ {
			_, _ = d.Update(tea.KeyMsg{Type: tea.KeyDown})
		}
		// Then send each rune from keys as its own key event
		for _, r := range keys {
			switch r {
			case '\t':
				_, _ = d.Update(tea.KeyMsg{Type: tea.KeyTab})
			case '\r', '\n':
				_, _ = d.Update(tea.KeyMsg{Type: tea.KeyEnter})
			case '\x1b':
				_, _ = d.Update(tea.KeyMsg{Type: tea.KeyEsc})
			default:
				_, _ = d.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
			}
		}
		// Garbage message type — Update must handle unknown msg shapes
		_, _ = d.Update(struct{ X int }{X: 42})
		// View should never panic regardless of state reached
		_ = d.View()
	})
}

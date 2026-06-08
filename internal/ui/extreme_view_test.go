package ui

import (
	"fmt"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

// TestExtremeViewSizes probes each major TUI model's View() at
// pathological terminal sizes (1x1, 1x1000, 1000x1, 0x0, etc.) and
// asserts none panic. Lipgloss-based rendering is normally robust to
// width<3 / height<2 because it falls back to padding-with-spaces, but
// any path that does `width - constant` arithmetic without bounds-
// checking will panic on tiny terminals.
func TestExtremeViewSizes(t *testing.T) {
	sizes := []struct{ w, h int }{
		{1, 1}, {1, 1000}, {1000, 1}, {2, 2}, {10, 5}, {5, 100},
		{300, 24}, {24, 300}, {0, 0}, {200, 50},
		{-1, -1}, // negative, just in case
	}
	cfg := config.DefaultConfig()
	probes := []struct {
		name string
		make func() tea.Model
	}{
		{"Layout", func() tea.Model { return NewLayout() }},
		{"Dashboard", func() tea.Model { return NewDashboard(cfg) }},
		{"Settings", func() tea.Model { return NewSettings(cfg) }},
		{"MTUInput", func() tea.Model { return NewMTUInput(cfg) }},
		{"AuditView", func() tea.Model { return NewAuditView(cfg) }},
		{"HealthTargets", func() tea.Model { return NewHealthTargets(cfg) }},
		{"DNSProviderSelect", func() tea.Model { return NewDNSProviderSelect(cfg) }},
		{"ProviderSelect", func() tea.Model { return NewProviderSelect(cfg) }},
		{"AddServer", func() tea.Model { return NewAddServer(cfg) }},
		{"RenameInterface", func() tea.Model { return NewRenameInterface(cfg) }},
		{"DisconnectConfirm", func() tea.Model { return NewDisconnectConfirm(cfg) }},
		{"Speedtest", func() tea.Model { return NewSpeedtest(cfg) }},
		{"Leaktest", func() tea.Model { return NewLeaktest(cfg) }},
		{"Tutorial", func() tea.Model { return NewTutorial() }},
	}
	for _, p := range probes {
		for _, s := range sizes {
			name := fmt.Sprintf("%s_%dx%d", p.name, s.w, s.h)
			t.Run(name, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("View panicked: %v", r)
					}
				}()
				m := p.make()
				m, _ = m.Update(tea.WindowSizeMsg{Width: s.w, Height: s.h})
				_ = m.View()
			})
		}
	}
}

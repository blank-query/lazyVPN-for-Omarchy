package ui

import (
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/tools"
	tea "github.com/charmbracelet/bubbletea"
)

func TestNewDNSProviderSelectDefaults(t *testing.T) {
	cfg := &config.Config{}
	m := NewDNSProviderSelect(cfg)

	if len(m.items) != len(tools.DNSProviderRegistry) {
		t.Errorf("items len = %d, want %d", len(m.items), len(tools.DNSProviderRegistry))
	}

	// Default: powerdns and akamai selected
	for _, item := range m.items {
		isDefault := false
		for _, d := range tools.DefaultDNSProviders {
			if item.provider.ID == d {
				isDefault = true
				break
			}
		}
		if item.selected != isDefault {
			t.Errorf("provider %q selected = %v, want %v", item.provider.ID, item.selected, isDefault)
		}
	}
}

func TestNewDNSProviderSelectCustom(t *testing.T) {
	cfg := &config.Config{DNSProviders: []string{"google"}}
	m := NewDNSProviderSelect(cfg)

	for _, item := range m.items {
		expected := item.provider.ID == "google"
		if item.selected != expected {
			t.Errorf("provider %q selected = %v, want %v", item.provider.ID, item.selected, expected)
		}
	}
}

func TestDNSProviderSelectInit(t *testing.T) {
	cfg := &config.Config{}
	m := NewDNSProviderSelect(cfg)
	if m.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestDNSProviderSelectNavigation(t *testing.T) {
	cfg := &config.Config{}
	m := NewDNSProviderSelect(cfg)
	lastIdx := len(m.items) - 1

	// Move down
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = model.(*DNSProviderSelect)
	if m.cursor != 1 {
		t.Errorf("cursor = %d, want 1", m.cursor)
	}

	// Move to last item
	for i := 1; i < lastIdx; i++ {
		model, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = model.(*DNSProviderSelect)
	}
	if m.cursor != lastIdx {
		t.Errorf("cursor = %d, want %d", m.cursor, lastIdx)
	}

	// Can't go past last item
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = model.(*DNSProviderSelect)
	if m.cursor != lastIdx {
		t.Errorf("cursor = %d, want %d (clamped)", m.cursor, lastIdx)
	}

	// Move up
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = model.(*DNSProviderSelect)
	if m.cursor != lastIdx-1 {
		t.Errorf("cursor = %d, want %d", m.cursor, lastIdx-1)
	}

	// Can't go above 0
	for i := 0; i < lastIdx; i++ {
		model, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
		m = model.(*DNSProviderSelect)
	}
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0", m.cursor)
	}
}

func TestDNSProviderSelectToggle(t *testing.T) {
	cfg := &config.Config{}
	m := NewDNSProviderSelect(cfg)

	// First item (powerdns) should be selected by default
	if !m.items[0].selected {
		t.Error("powerdns should be selected by default")
	}

	// Find a non-default provider to toggle
	toggleIdx := -1
	for i, item := range m.items {
		if !item.selected {
			toggleIdx = i
			break
		}
	}
	if toggleIdx == -1 {
		t.Fatal("no unselected provider to toggle")
	}

	// Toggle on
	m.cursor = toggleIdx
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	m = model.(*DNSProviderSelect)
	if !m.items[toggleIdx].selected {
		t.Errorf("provider at index %d should be selected after toggle", toggleIdx)
	}

	// Toggle off
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	m = model.(*DNSProviderSelect)
	if m.items[toggleIdx].selected {
		t.Errorf("provider at index %d should be deselected after second toggle", toggleIdx)
	}
}

func TestDNSProviderSelectMinimumOne(t *testing.T) {
	// Start with only one provider selected
	cfg := &config.Config{DNSProviders: []string{"powerdns"}}
	m := NewDNSProviderSelect(cfg)

	// Try to deselect the only selected provider
	m.cursor = 0
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	m = model.(*DNSProviderSelect)

	// Should still be selected
	if !m.items[0].selected {
		t.Error("should not allow deselecting last provider")
	}
	if m.message != "At least one provider required" {
		t.Errorf("message = %q, want 'At least one provider required'", m.message)
	}
}

func TestDNSProviderSelectSave(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigDir:  tmpDir,
		ConfigFile: tmpDir + "/config",
	}
	m := NewDNSProviderSelect(cfg)

	// Count defaults
	defaultCount := 0
	for _, item := range m.items {
		if item.selected {
			defaultCount++
		}
	}

	// Find and select a non-default provider
	for i, item := range m.items {
		if !item.selected {
			m.cursor = i
			m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
			break
		}
	}

	// Press enter to save
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}

	// Verify config was updated
	if len(cfg.DNSProviders) != defaultCount+1 {
		t.Errorf("DNSProviders len = %d, want %d", len(cfg.DNSProviders), defaultCount+1)
	}
}

func TestDNSProviderSelectCancel(t *testing.T) {
	cfg := &config.Config{}
	m := NewDNSProviderSelect(cfg)

	// Toggle a non-default provider
	for i, item := range m.items {
		if !item.selected {
			m.cursor = i
			m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
			break
		}
	}

	// Press esc to cancel
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}

	// Config should NOT be updated (still nil = defaults)
	if cfg.DNSProviders != nil {
		t.Error("cancelling should not update config")
	}
}

func TestDNSProviderSelectWindowSize(t *testing.T) {
	cfg := &config.Config{}
	m := NewDNSProviderSelect(cfg)

	model, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = model.(*DNSProviderSelect)
	if m.width != 120 || m.height != 40 {
		t.Errorf("size = %dx%d, want 120x40", m.width, m.height)
	}
}

func TestDNSProviderSelectView(t *testing.T) {
	cfg := &config.Config{}
	m := NewDNSProviderSelect(cfg)
	view := m.View()

	if !strings.Contains(view, "DNS Providers") {
		t.Error("should contain title")
	}
	if !strings.Contains(view, "PowerDNS") {
		t.Error("should show PowerDNS")
	}
	if !strings.Contains(view, "Akamai") {
		t.Error("should show Akamai")
	}
	if !strings.Contains(view, "Google") {
		t.Error("should show Google")
	}
	if !strings.Contains(view, "DNSCrypt") {
		t.Error("should show DNSCrypt")
	}
	if !strings.Contains(view, "space: toggle") {
		t.Error("should show help text")
	}
}

func TestDNSProviderSelectViewWithMessage(t *testing.T) {
	cfg := &config.Config{DNSProviders: []string{"powerdns"}}
	m := NewDNSProviderSelect(cfg)

	// Try to deselect the only provider
	m.cursor = 0
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	m = model.(*DNSProviderSelect)

	view := m.View()
	if !strings.Contains(view, "At least one provider required") {
		t.Error("should show warning message")
	}
}

func TestDNSProviderSelectMessageClearsOnKey(t *testing.T) {
	cfg := &config.Config{DNSProviders: []string{"powerdns"}}
	m := NewDNSProviderSelect(cfg)

	// Trigger the min-1 message
	m.cursor = 0
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	m = model.(*DNSProviderSelect)
	if m.message == "" {
		t.Fatal("message should be set")
	}

	// Any key should clear the message
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = model.(*DNSProviderSelect)
	if m.message != "" {
		t.Errorf("message should be cleared after navigation, got %q", m.message)
	}
}

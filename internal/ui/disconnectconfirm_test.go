package ui

import (
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

func TestNewDisconnectConfirm(t *testing.T) {
	cfg := &config.Config{}
	dc := NewDisconnectConfirm(cfg)

	if dc.cursor != 0 {
		t.Errorf("initial cursor = %d, want 0", dc.cursor)
	}
	if len(dc.options) != 2 {
		t.Errorf("expected 2 options, got %d", len(dc.options))
	}
	if dc.options[0] != "Yes, disconnect" {
		t.Errorf("options[0] = %q", dc.options[0])
	}
	if dc.options[1] != "No, stay connected" {
		t.Errorf("options[1] = %q", dc.options[1])
	}
}

func TestDisconnectConfirmInit(t *testing.T) {
	cfg := &config.Config{}
	dc := NewDisconnectConfirm(cfg)
	if dc.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestDisconnectConfirmYKey(t *testing.T) {
	cfg := &config.Config{}
	dc := NewDisconnectConfirm(cfg)

	_, cmd := dc.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if cmd == nil {
		t.Fatal("y key should return a cmd")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.View != "disconnect-progress" {
		t.Errorf("View = %q, want disconnect-progress", sv.View)
	}
}

func TestDisconnectConfirmNKey(t *testing.T) {
	cfg := &config.Config{}
	dc := NewDisconnectConfirm(cfg)

	_, cmd := dc.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if cmd == nil {
		t.Fatal("n key should return a cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestDisconnectConfirmEsc(t *testing.T) {
	cfg := &config.Config{}
	dc := NewDisconnectConfirm(cfg)

	_, cmd := dc.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return a cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestDisconnectConfirmCursorNavigation(t *testing.T) {
	cfg := &config.Config{}
	dc := NewDisconnectConfirm(cfg)

	// Move down
	model, _ := dc.Update(tea.KeyMsg{Type: tea.KeyDown})
	dc = model.(*DisconnectConfirm)
	if dc.cursor != 1 {
		t.Errorf("after down: cursor = %d, want 1", dc.cursor)
	}

	// Move down again (should stay at 1)
	model, _ = dc.Update(tea.KeyMsg{Type: tea.KeyDown})
	dc = model.(*DisconnectConfirm)
	if dc.cursor != 1 {
		t.Errorf("at bottom: cursor = %d, want 1", dc.cursor)
	}

	// Move up
	model, _ = dc.Update(tea.KeyMsg{Type: tea.KeyUp})
	dc = model.(*DisconnectConfirm)
	if dc.cursor != 0 {
		t.Errorf("after up: cursor = %d, want 0", dc.cursor)
	}

	// Move up again (should stay at 0)
	model, _ = dc.Update(tea.KeyMsg{Type: tea.KeyUp})
	dc = model.(*DisconnectConfirm)
	if dc.cursor != 0 {
		t.Errorf("at top: cursor = %d, want 0", dc.cursor)
	}
}

func TestDisconnectConfirmEnterYes(t *testing.T) {
	cfg := &config.Config{}
	dc := NewDisconnectConfirm(cfg)

	// cursor at 0 (Yes), press enter
	_, cmd := dc.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter on Yes should return a cmd")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.View != "disconnect-progress" {
		t.Errorf("View = %q", sv.View)
	}
}

func TestDisconnectConfirmEnterNo(t *testing.T) {
	cfg := &config.Config{}
	dc := NewDisconnectConfirm(cfg)

	// Move to "No" option
	model, _ := dc.Update(tea.KeyMsg{Type: tea.KeyDown})
	dc = model.(*DisconnectConfirm)

	_, cmd := dc.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter on No should return a cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestDisconnectConfirmView(t *testing.T) {
	cfg := &config.Config{}
	dc := NewDisconnectConfirm(cfg)

	view := dc.View()
	if !strings.Contains(view, "Disconnect VPN") {
		t.Error("view should contain title")
	}
	if !strings.Contains(view, "Yes, disconnect") {
		t.Error("view should contain Yes option")
	}
	if !strings.Contains(view, "No, stay connected") {
		t.Error("view should contain No option")
	}
}

func TestDisconnectConfirmViewWithKillswitch(t *testing.T) {
	// The view checks the authoritative firewall state (not a config field).
	// Stub isFirewallActive → true for all three cases below.
	origIsActive := isFirewallActive
	isFirewallActive = func() bool { return true }
	t.Cleanup(func() { isFirewallActive = origIsActive })

	cfg := &config.Config{KillswitchAutoDisable: "true"}
	dc := NewDisconnectConfirm(cfg)

	view := dc.View()
	if !strings.Contains(view, "automatically disabled") {
		t.Errorf("killswitch auto-disable should show message, got: %s", view)
	}

	// Test "never" mode
	cfg2 := &config.Config{KillswitchAutoDisable: "never"}
	dc2 := NewDisconnectConfirm(cfg2)
	view2 := dc2.View()
	if !strings.Contains(view2, "ACTIVE") {
		t.Error("killswitch never mode should show ACTIVE warning")
	}

	// Test prompt mode (default)
	cfg3 := &config.Config{KillswitchAutoDisable: "prompt"}
	dc3 := NewDisconnectConfirm(cfg3)
	view3 := dc3.View()
	if !strings.Contains(view3, "prompted") {
		t.Error("killswitch prompt mode should show prompted message")
	}
}

func TestDisconnectConfirmViewWithServer(t *testing.T) {
	cfg := &config.Config{LastConnectedServer: "US-NY#42"}
	dc := NewDisconnectConfirm(cfg)
	view := dc.View()
	if !strings.Contains(view, "US-NY#42") {
		t.Error("view should show connected server name")
	}
}

func TestDisconnectConfirmWindowSize(t *testing.T) {
	cfg := &config.Config{}
	dc := NewDisconnectConfirm(cfg)

	model, _ := dc.Update(tea.WindowSizeMsg{Width: 80, Height: 40})
	dc = model.(*DisconnectConfirm)
	if dc.width != 80 {
		t.Errorf("width = %d, want 80", dc.width)
	}
	if dc.height != 40 {
		t.Errorf("height = %d, want 40", dc.height)
	}
}

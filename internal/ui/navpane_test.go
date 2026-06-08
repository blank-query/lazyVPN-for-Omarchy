package ui

import (
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

func TestNewNavPane(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)

	if n.cursor != NavDashboard {
		t.Errorf("initial cursor = %d, want NavDashboard (%d)", n.cursor, NavDashboard)
	}
	if !n.focused {
		t.Error("initial focused should be true")
	}
	if n.connected {
		t.Error("initial connected should be false")
	}
}

func TestNavItemConstants(t *testing.T) {
	// Verify NavItem enum values
	if NavDashboard != 0 {
		t.Errorf("NavDashboard = %d, want 0", NavDashboard)
	}
	if NavDynamic != 1 {
		t.Errorf("NavDynamic = %d, want 1", NavDynamic)
	}
	if NavServers != 2 {
		t.Errorf("NavServers = %d, want 2", NavServers)
	}
	if NavSettings != 3 {
		t.Errorf("NavSettings = %d, want 3", NavSettings)
	}
	if NavClose != 4 {
		t.Errorf("NavClose = %d, want 4", NavClose)
	}
}

func TestVisibleItemsStatic(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)

	labels, ids := n.visibleItems()

	if len(labels) != 5 {
		t.Fatalf("expected 5 labels (static nav), got %d: %v", len(labels), labels)
	}
	if len(ids) != 5 {
		t.Fatalf("expected 5 ids, got %d", len(ids))
	}

	// Verify order: Dashboard, Dynamic Servers, My Servers, Settings, Close
	expected := []string{"Dashboard", "Dynamic Servers", "My Servers", "Settings", "Close"}
	for i, want := range expected {
		if !strings.Contains(labels[i], want) {
			t.Errorf("labels[%d] = %q, should contain %q", i, labels[i], want)
		}
	}

	expectedIDs := []NavItem{NavDashboard, NavDynamic, NavServers, NavSettings, NavClose}
	for i, want := range expectedIDs {
		if ids[i] != want {
			t.Errorf("ids[%d] = %d, want %d", i, ids[i], want)
		}
	}
}

func TestVisibleItemsAlwaysStatic(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)

	// Whether connected or not, nav is always static 5 items
	n.connected = true
	labels1, _ := n.visibleItems()

	n.connected = false
	labels2, _ := n.visibleItems()

	if len(labels1) != len(labels2) {
		t.Errorf("connected labels = %d, disconnected labels = %d, should be same (static)", len(labels1), len(labels2))
	}
}

func TestCursorPos(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)

	tests := []struct {
		name   string
		cursor NavItem
		ids    []NavItem
		want   int
	}{
		{"first", NavDashboard, []NavItem{NavDashboard, NavDynamic, NavServers, NavSettings, NavClose}, 0},
		{"middle", NavServers, []NavItem{NavDashboard, NavDynamic, NavServers, NavSettings, NavClose}, 2},
		{"last", NavClose, []NavItem{NavDashboard, NavDynamic, NavServers, NavSettings, NavClose}, 4},
		{"not found defaults to 0", NavItem(99), []NavItem{NavDashboard, NavDynamic, NavServers, NavSettings, NavClose}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n.cursor = tt.cursor
			got := n.cursorPos(tt.ids)
			if got != tt.want {
				t.Errorf("cursorPos(%v) = %d, want %d", tt.ids, got, tt.want)
			}
		})
	}
}

func TestSetFocused(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)

	if !n.focused {
		t.Error("should start focused")
	}

	n.SetFocused(false)
	if n.focused {
		t.Error("should be unfocused after SetFocused(false)")
	}

	n.SetFocused(true)
	if !n.focused {
		t.Error("should be focused after SetFocused(true)")
	}
}

func TestNavPaneUpdateDownKey(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.focused = true
	n.cursor = NavDashboard

	n, cmd := n.Update(tea.KeyMsg{Type: tea.KeyDown})
	if cmd == nil {
		t.Fatal("down key should return cmd")
	}
	msg := cmd()
	sel, ok := msg.(NavSelectMsg)
	if !ok {
		t.Fatalf("expected NavSelectMsg, got %T", msg)
	}
	if sel.Item != NavDynamic {
		t.Errorf("selected = %d, want NavDynamic (%d)", sel.Item, NavDynamic)
	}
	if n.cursor != NavDynamic {
		t.Errorf("cursor = %d, want NavDynamic", n.cursor)
	}
}

func TestNavPaneUpdateUpKey(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.focused = true
	n.cursor = NavServers

	_, cmd := n.Update(tea.KeyMsg{Type: tea.KeyUp})
	if cmd == nil {
		t.Fatal("up key should return cmd")
	}
	msg := cmd()
	sel, ok := msg.(NavSelectMsg)
	if !ok {
		t.Fatalf("expected NavSelectMsg, got %T", msg)
	}
	if sel.Item != NavDynamic {
		t.Errorf("selected = %d, want NavDynamic (%d)", sel.Item, NavDynamic)
	}
}

func TestNavPaneUpdateDownKeyClamped(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.focused = true
	n.cursor = NavClose // last item

	n, cmd := n.Update(tea.KeyMsg{Type: tea.KeyDown})
	if cmd != nil {
		t.Error("down at bottom should return nil cmd")
	}
	if n.cursor != NavClose {
		t.Errorf("cursor = %d, should stay at NavClose", n.cursor)
	}
}

func TestNavPaneUpdateUpKeyClamped(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.focused = true
	n.cursor = NavDashboard // first item

	n, cmd := n.Update(tea.KeyMsg{Type: tea.KeyUp})
	if cmd != nil {
		t.Error("up at top should return nil cmd")
	}
	if n.cursor != NavDashboard {
		t.Errorf("cursor = %d, should stay at NavDashboard", n.cursor)
	}
}

func TestNavPaneUpdateEnterKey(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.focused = true
	n.cursor = NavDashboard

	n, cmd := n.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(FocusContentMsg); !ok {
		t.Errorf("expected FocusContentMsg, got %T", msg)
	}
	if n.focused {
		t.Error("should be unfocused after enter")
	}
}

func TestNavPaneUpdateEnterOnClose(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.focused = true
	n.cursor = NavClose

	_, cmd := n.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter on Close should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Errorf("expected tea.QuitMsg, got %T", msg)
	}
}

func TestNavPaneUpdateRightKeyNoOp(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.focused = true

	n, cmd := n.Update(tea.KeyMsg{Type: tea.KeyRight})
	if cmd != nil {
		t.Error("right key in nav pane should be a no-op")
	}
	if !n.focused {
		t.Error("should remain focused after right key")
	}
}

func TestNavPaneUpdateTabKeyNoOp(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.focused = true

	n, cmd := n.Update(tea.KeyMsg{Type: tea.KeyTab})
	if cmd != nil {
		t.Error("tab key in nav pane should be a no-op (handled by Layout)")
	}
	if !n.focused {
		t.Error("should remain focused after tab key")
	}
}

func TestNavPaneUpdateKeyUnfocused(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.focused = false

	_, cmd := n.Update(tea.KeyMsg{Type: tea.KeyDown})
	if cmd != nil {
		t.Error("unfocused nav should return nil cmd for keys")
	}
}

func TestNavPaneUpdateStatusUpdateMsgDisconnected(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg-test-nonexistent"}
	n := NewNavPane(cfg)

	n, _ = n.Update(StatusUpdateMsg{})
	if n.connected {
		t.Error("should not be connected with nonexistent interface")
	}
}

func TestNavPaneUpdateWindowSizeMsg(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)

	n, _ = n.Update(tea.WindowSizeMsg{Width: 200, Height: 50})

	expectedWidth := 200 / 5
	if n.width != expectedWidth {
		t.Errorf("width = %d, want %d", n.width, expectedWidth)
	}
	expectedHeight := 50 - 10
	if n.height != expectedHeight {
		t.Errorf("height = %d, want %d", n.height, expectedHeight)
	}
}

func TestNavPaneUpdateWindowSizeMsgMinWidth(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)

	n, _ = n.Update(tea.WindowSizeMsg{Width: 50, Height: 30})

	if n.width != 20 {
		t.Errorf("width = %d, want 20 (min)", n.width)
	}
}

func TestNavPaneInit(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	if n.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestNavPaneView(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.width = 30
	n.height = 20
	n.focused = true

	view := n.View()
	if view == "" {
		t.Error("view should not be empty")
	}
	if !strings.Contains(view, "Dashboard") {
		t.Error("should contain Dashboard")
	}
	if !strings.Contains(view, "Dynamic Servers") {
		t.Error("should contain Dynamic Servers")
	}
	if !strings.Contains(view, "My Servers") {
		t.Error("should contain My Servers")
	}
	if !strings.Contains(view, "Settings") {
		t.Error("should contain Settings")
	}
	if !strings.Contains(view, "Close") {
		t.Error("should contain Close")
	}
}

func TestNavPaneViewUnfocused(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.width = 30
	n.height = 20
	n.focused = false

	view := n.View()
	if view == "" {
		t.Error("unfocused view should not be empty")
	}
}

func TestNavPaneStatusUpdateMsgConnected(t *testing.T) {
	mockConnected(t)

	cfg := &config.Config{ConnectionName: "wg0"}
	n := NewNavPane(cfg)

	n, _ = n.Update(StatusUpdateMsg{})
	if !n.connected {
		t.Error("should be connected with mocked isWGConnected")
	}
}

func TestNavPaneViewSmallWidth(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.width = 10
	n.height = 20
	n.focused = true

	view := n.View()
	if view == "" {
		t.Error("small width view should not be empty")
	}
}

func TestNavPaneKillswitchWarning(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.width = 30
	n.height = 20
	n.killswitchActive = true
	n.connected = false
	n.blinkOn = true

	view := n.View()
	if !strings.Contains(view, "KS BLOCKING") {
		t.Error("should show KS BLOCKING warning when killswitch active and disconnected")
	}
}

func TestNavPaneKillswitchWarningBlinkOff(t *testing.T) {
	cfg := &config.Config{}
	n := NewNavPane(cfg)
	n.width = 30
	n.height = 20
	n.killswitchActive = true
	n.connected = false
	n.blinkOn = false

	view := n.View()
	// When blinkOn is false, warning text should be hidden (blank lines)
	if strings.Contains(view, "KS BLOCKING") {
		t.Error("should not show KS BLOCKING when blinkOn is false")
	}
}

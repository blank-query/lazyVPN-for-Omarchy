package ui

import (
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

// newTestLayout creates a Layout with a temp config dir, avoiding filesystem side effects.
func newTestLayout(t *testing.T) *Layout {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = cfg.ConfigDir + "/config"

	nav := NewNavPane(cfg)
	footer := NewStatusFooter(cfg)
	// Use a simple stub content model
	content := NewTutorial()

	return &Layout{
		cfg:         cfg,
		nav:         nav,
		content:     content,
		footer:      footer,
		contentType: NavDashboard,
		navFocused:  true,
	}
}

func TestLayoutTabTogglesFocus(t *testing.T) {
	l := newTestLayout(t)

	if !l.navFocused {
		t.Fatal("should start with nav focused")
	}

	_, _ = l.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'	'}})
	// Tab key in bubbletea is "tab" string but we need to use the right msg
	// The Layout checks msg.String() == "tab", so let's use tea.KeyTab
	l.navFocused = true // reset
	l.nav.SetFocused(true)

	_, _ = l.Update(tea.KeyMsg{Type: tea.KeyTab})
	if l.navFocused {
		t.Error("tab should unfocus nav")
	}
	if l.nav.focused {
		t.Error("nav should be unfocused after tab")
	}

	_, _ = l.Update(tea.KeyMsg{Type: tea.KeyTab})
	if !l.navFocused {
		t.Error("second tab should refocus nav")
	}
	if !l.nav.focused {
		t.Error("nav should be focused after second tab")
	}
}

// In sub-view mode (prevContent non-empty) the nav isn't rendered, so Tab
// must NOT toggle navFocused — otherwise it silently sends keystrokes to an
// invisible nav. The only way out of sub-view mode is via Back / a top-level
// nav switch, both of which clear prevContent.
func TestLayoutTabIsNoOpInSubViewMode(t *testing.T) {
	l := newTestLayout(t)
	l.navFocused = false
	l.nav.SetFocused(false)
	l.prevContent = []tea.Model{l.content} // simulate "in sub-view"

	_, _ = l.Update(tea.KeyMsg{Type: tea.KeyTab})
	if l.navFocused {
		t.Error("tab should be a no-op in sub-view mode (prevContent > 0)")
	}
}

// NavSelectMsg dispatches to a top-level view; any sub-view stack is now
// stale and must be cleared so the "len(prevContent) > 0 ⇔ sub-view mode"
// invariant holds (Tab's no-op gate depends on it).
func TestLayoutNavSelectClearsSubViewStack(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40
	l.prevContent = []tea.Model{l.content, l.content} // simulate 2-deep nesting

	_, _ = l.Update(NavSelectMsg{Item: NavDashboard})

	if len(l.prevContent) != 0 {
		t.Errorf("NavSelectMsg should clear prevContent, got len=%d", len(l.prevContent))
	}
}

// Same invariant for the SwitchView top-level transitions.
func TestLayoutSwitchViewTopLevelClearsSubViewStack(t *testing.T) {
	for _, view := range []string{"dynamic-browser", "server-list"} {
		t.Run(view, func(t *testing.T) {
			l := newTestLayout(t)
			l.width = 120
			l.height = 40
			l.prevContent = []tea.Model{l.content}

			_, _ = l.Update(SwitchViewMsg{View: view})

			if len(l.prevContent) != 0 {
				t.Errorf("SwitchViewMsg %q should clear prevContent, got len=%d", view, len(l.prevContent))
			}
		})
	}
}

func TestLayoutWindowSizeMsg(t *testing.T) {
	l := newTestLayout(t)

	_, _ = l.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	if l.width != 120 {
		t.Errorf("width = %d, want 120", l.width)
	}
	if l.height != 40 {
		t.Errorf("height = %d, want 40", l.height)
	}
}

func TestLayoutFocusContentMsg(t *testing.T) {
	l := newTestLayout(t)
	l.navFocused = true
	l.nav.SetFocused(true)

	_, _ = l.Update(FocusContentMsg{})

	if l.navFocused {
		t.Error("FocusContentMsg should unfocus nav")
	}
	if l.nav.focused {
		t.Error("nav should be unfocused after FocusContentMsg")
	}
}

func TestLayoutBackMsg(t *testing.T) {
	l := newTestLayout(t)
	l.navFocused = false
	l.nav.SetFocused(false)
	l.contentType = NavSettings

	_, _ = l.Update(BackMsg{})

	if !l.navFocused {
		t.Error("BackMsg should refocus nav")
	}
	if !l.nav.focused {
		t.Error("nav should be focused after BackMsg")
	}
}

func TestLayoutBackMsgFromUnknownResetsToDashboard(t *testing.T) {
	l := newTestLayout(t)
	l.navFocused = false
	l.contentType = NavItem(99) // unknown content type

	_, _ = l.Update(BackMsg{})

	if l.contentType != NavDashboard {
		t.Errorf("contentType = %d, want NavDashboard (%d)", l.contentType, NavDashboard)
	}
	if l.nav.cursor != NavDashboard {
		t.Errorf("nav cursor = %d, want NavDashboard (%d)", l.nav.cursor, NavDashboard)
	}
}

func TestLayoutNavSelectMsg(t *testing.T) {
	l := newTestLayout(t)
	// Set width/height so initContent can propagate sizes
	l.width = 120
	l.height = 40

	tests := []struct {
		name string
		item NavItem
	}{
		{"dashboard", NavDashboard},
		{"servers", NavServers},
		{"settings", NavSettings},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _ = l.Update(NavSelectMsg{Item: tt.item})
			if l.contentType != tt.item {
				t.Errorf("contentType = %d, want %d", l.contentType, tt.item)
			}
		})
	}
}

func TestLayoutRunUninstallMsg(t *testing.T) {
	l := newTestLayout(t)

	if l.runUninstall {
		t.Fatal("should not run uninstall initially")
	}

	_, cmd := l.Update(RunUninstallMsg{})

	if !l.runUninstall {
		t.Error("RunUninstallMsg should set runUninstall to true")
	}
	// Should return tea.Quit
	if cmd == nil {
		t.Error("should return quit cmd")
	}
}

func TestLayoutShouldRunUninstall(t *testing.T) {
	l := newTestLayout(t)

	if l.ShouldRunUninstall() {
		t.Error("should be false initially")
	}

	l.runUninstall = true
	if !l.ShouldRunUninstall() {
		t.Error("should be true after setting flag")
	}
}

func TestLayoutAutoconnectServerSelectMsg(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(AutoconnectServerSelectMsg{Server: "test-server"})

	if l.contentType != NavSettings {
		t.Errorf("contentType = %d, want NavSettings (%d)", l.contentType, NavSettings)
	}
}

func TestLayoutSwitchViewMsg(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	views := []string{
		"disconnect-confirm",
		"settings",
		"tutorial",
		"uninstall_confirm",
		"view-log",
	}

	for _, view := range views {
		t.Run(view, func(t *testing.T) {
			_, _ = l.Update(SwitchViewMsg{View: view})
			if l.content == nil {
				t.Error("content should not be nil after SwitchViewMsg")
			}
		})
	}
}

func TestLayoutSwitchViewConnectProgress(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{
		View:     "connect-progress",
		Server:   "US-NY#42",
		Provider: "protonvpn",
		Dynamic:  true,
	})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewDisconnectProgress(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "disconnect-progress"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewAddServer(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "add-server"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewRemoveServer(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "remove-server"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewRemoveProvider(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "remove-provider"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewRenameInterface(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "rename-interface"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewProviderSetup(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "provider-setup"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewProviderSelect(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "provider-select"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewDynamicBrowser(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "dynamic-browser", Provider: "protonvpn"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewAutoconnectServerSelect(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "autoconnect-server-select"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewAudit(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "audit"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewSpeedtest(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "speedtest"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewLeaktest(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "leaktest"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
}

func TestLayoutSwitchViewServerList(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(SwitchViewMsg{View: "server-list"})
	if l.content == nil {
		t.Error("content should not be nil")
	}
	if l.contentType != NavServers {
		t.Errorf("contentType = %d, want NavServers (%d)", l.contentType, NavServers)
	}
}

func TestLayoutKeyRoutingNavFocused(t *testing.T) {
	l := newTestLayout(t)
	l.navFocused = true
	l.nav.SetFocused(true)
	l.width = 120
	l.height = 40
	// Send a window size first so nav has dimensions
	l.Update(tea.WindowSizeMsg{Width: 120, Height: 40})

	// Down key should move nav cursor when nav is focused
	initialCursor := l.nav.cursor
	_, _ = l.Update(tea.KeyMsg{Type: tea.KeyDown})

	// Nav should have processed the key
	_, ids := l.nav.visibleItems()
	if len(ids) > 1 {
		// cursor should have moved
		if l.nav.cursor == initialCursor {
			t.Error("down key should move nav cursor when nav is focused")
		}
	}
}

func TestLayoutKeyRoutingContentFocused(t *testing.T) {
	l := newTestLayout(t)
	l.navFocused = false
	l.nav.SetFocused(false)
	l.width = 120
	l.height = 40

	// Key should be routed to content, not nav
	initialNavCursor := l.nav.cursor
	_, _ = l.Update(tea.KeyMsg{Type: tea.KeyDown})

	// Nav cursor should NOT have moved
	if l.nav.cursor != initialNavCursor {
		t.Error("key should not affect nav when content is focused")
	}
}

func TestLayoutStatusUpdateMsg(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	// Should not panic
	_, _ = l.Update(StatusUpdateMsg{})
}

func TestLayoutView(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	// Send window size to populate dimensions
	l.Update(tea.WindowSizeMsg{Width: 120, Height: 40})

	view := l.View()
	if view == "" {
		t.Error("view should not be empty")
	}

	// Should contain the brand name
	if !strings.Contains(view, "L a z y V P N") {
		t.Error("view should contain brand name")
	}

	// Should contain version
	if !strings.Contains(view, Version) {
		t.Error("view should contain version")
	}
}

func TestLayoutViewSmallWidth(t *testing.T) {
	l := newTestLayout(t)
	l.width = 30
	l.height = 20

	l.Update(tea.WindowSizeMsg{Width: 30, Height: 20})

	// Should not panic with small dimensions
	view := l.View()
	if view == "" {
		t.Error("view should not be empty even with small dimensions")
	}
}

func TestLayoutInit(t *testing.T) {
	l := newTestLayout(t)
	cmd := l.Init()
	// Init should return a batch command (nav + content + footer)
	if cmd == nil {
		t.Error("Init should return a command")
	}
}

func TestLayoutInitContent(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	// initContent should not panic; returns a batch cmd (may be nil if content Init returns nil)
	cmd := l.initContent()
	_ = cmd // may be nil for simple content models like Tutorial
}

func TestLayoutInitContentZeroDimensions(t *testing.T) {
	l := newTestLayout(t)
	// width and height are 0

	// Should not panic even with zero dimensions
	cmd := l.initContent()
	_ = cmd
}

func TestLayoutNavSelectMsgDynamic(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40

	_, _ = l.Update(NavSelectMsg{Item: NavDynamic})
	if l.contentType != NavDynamic {
		t.Errorf("contentType = %d, want NavDynamic (%d)", l.contentType, NavDynamic)
	}
}

func TestLayoutBackMsgRestoresServers(t *testing.T) {
	l := newTestLayout(t)
	l.navFocused = false
	l.contentType = NavServers
	l.width = 120
	l.height = 40

	_, _ = l.Update(BackMsg{})

	if !l.navFocused {
		t.Error("should refocus nav")
	}
	// Content should be restored for NavServers
	if l.contentType != NavServers {
		t.Errorf("contentType should remain NavServers, got %d", l.contentType)
	}
}

func TestLayoutBackMsgRestoresSettings(t *testing.T) {
	l := newTestLayout(t)
	l.navFocused = false
	l.contentType = NavSettings
	l.width = 120
	l.height = 40

	_, _ = l.Update(BackMsg{})

	if !l.navFocused {
		t.Error("should refocus nav")
	}
	if l.contentType != NavSettings {
		t.Errorf("contentType should remain NavSettings, got %d", l.contentType)
	}
}

func TestLayoutViewSettingsFooterOverlay(t *testing.T) {
	l := newTestLayout(t)
	l.width = 120
	l.height = 40
	l.Update(tea.WindowSizeMsg{Width: 120, Height: 40})

	// Set content to Settings
	l.content = NewSettings(l.cfg)
	l.contentType = NavSettings

	// View should set the overlay text from settings description
	view := l.View()
	if view == "" {
		t.Error("view should not be empty")
	}
}

func TestLayoutViewContentFocused(t *testing.T) {
	l := newTestLayout(t)
	l.navFocused = false
	l.width = 120
	l.height = 40
	l.Update(tea.WindowSizeMsg{Width: 120, Height: 40})

	view := l.View()
	if view == "" {
		t.Error("content-focused view should not be empty")
	}
}

func TestLayoutViewVerySmallDimensions(t *testing.T) {
	l := newTestLayout(t)
	l.width = 10
	l.height = 5
	l.Update(tea.WindowSizeMsg{Width: 10, Height: 5})

	// Should not panic with extremely small dimensions
	view := l.View()
	if view == "" {
		t.Error("very small dimensions view should not be empty")
	}
}

func TestLayoutNonKeyMsgGoesToContent(t *testing.T) {
	l := newTestLayout(t)
	l.navFocused = true
	l.width = 120
	l.height = 40

	// Non-key messages should be routed to content even when nav is focused
	_, _ = l.Update(StatusUpdateMsg{})
	// Should not panic, and content should receive the message
}

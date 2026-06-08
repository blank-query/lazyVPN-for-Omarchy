package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/firewall"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/provider"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/update"
	tea "github.com/charmbracelet/bubbletea"
)

func TestLogModeDisplay(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"accurate", "Accurate"},
		{"safe", "Safe"},
		{"", "Safe"},
		{"anything-else", "Safe"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := logModeDisplay(tt.input)
			if got != tt.want {
				t.Errorf("logModeDisplay(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMtuDisplay(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{-1, "-1"},
		{1420, "1420"},
		{1400, "1400"},
		{9000, "9000"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := mtuDisplay(tt.input)
			if got != tt.want {
				t.Errorf("mtuDisplay(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// newTestSettings creates a Settings with a temp config dir for testing.
func newTestSettings(t *testing.T) *Settings {
	t.Helper()
	// Inject no-op firewall mocks so tests never call real sudo iptables
	stubFirewall(t)
	// Inject no-op notification mocks to prevent real DBus calls
	stubNotifications(t)
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")
	return NewSettings(cfg)
}

// stubFirewall replaces all firewall function vars with no-ops for the test duration.
func stubFirewall(t *testing.T) {
	t.Helper()

	// TestMain already installs a noop UFW runner for the entire package.
	// Do NOT call SetTestMode here — and especially never SetTestMode(nil)
	// in cleanup, as that restores the real runner and undoes TestMain's safety.

	origEnable := firewallEnable
	origSimple := firewallEnableSimple
	origDisable := firewallDisable
	origDisableIPv6 := firewallDisableIPv6
	origEnableIPv6 := firewallEnableIPv6
	origEnableStealth := firewallEnableLANStealth
	origDisableStealth := firewallDisableLANStealth
	origEnableLANBlock := firewallEnableLANBlock
	origDisableLANBlock := firewallDisableLANBlock
	origIsLANBlockActive := firewallIsLANBlockActive
	origGetPhysIface := firewallGetPhysicalInterface
	origIsActive := isFirewallActive
	origSudoAuth := firewallSudoAuth
	origSetLogging := firewallSetLogging
	origGetLoggingLevel := firewallGetLoggingLevel
	firewallEnable = func(*firewall.KillswitchConfig) error { return nil }
	firewallEnableSimple = func() error { return nil }
	firewallDisable = func() error { return nil }
	firewallDisableIPv6 = func() error { return nil }
	firewallEnableIPv6 = func() error { return nil }
	firewallEnableLANStealth = func() error { return nil }
	firewallDisableLANStealth = func() error { return nil }
	firewallEnableLANBlock = func(string, string, string, string) error { return nil }
	firewallDisableLANBlock = func() error { return nil }
	firewallIsLANBlockActive = func() bool { return false }
	firewallGetPhysicalInterface = func() (string, string, error) { return "wlan0", "192.168.1.1", nil }
	isFirewallActive = func() bool { return false }
	firewallSudoAuth = func([]byte) error { return nil }
	firewallSetLogging = func(string) error { return nil }
	firewallGetLoggingLevel = func() string { return "off" }
	t.Cleanup(func() {
		firewallEnable = origEnable
		firewallEnableSimple = origSimple
		firewallDisable = origDisable
		firewallDisableIPv6 = origDisableIPv6
		firewallEnableIPv6 = origEnableIPv6
		firewallEnableLANStealth = origEnableStealth
		firewallDisableLANStealth = origDisableStealth
		firewallEnableLANBlock = origEnableLANBlock
		firewallDisableLANBlock = origDisableLANBlock
		firewallIsLANBlockActive = origIsLANBlockActive
		firewallGetPhysicalInterface = origGetPhysIface
		isFirewallActive = origIsActive
		firewallSudoAuth = origSudoAuth
		firewallSetLogging = origSetLogging
		firewallGetLoggingLevel = origGetLoggingLevel
	})
}

// stubNotifications replaces notification function vars with no-ops for test duration.
func stubNotifications(t *testing.T) {
	t.Helper()
	origError := notifyError
	origInfo := notifyInfo
	notifyError = func(string) {}
	notifyInfo = func(string, string) {}
	t.Cleanup(func() {
		notifyError = origError
		notifyInfo = origInfo
	})
}

func TestNewSettings(t *testing.T) {
	s := newTestSettings(t)

	if s.cfg == nil {
		t.Fatal("cfg should not be nil")
	}
	if len(s.items) == 0 {
		t.Error("items should not be empty")
	}
	if len(s.leftItems) == 0 {
		t.Error("leftItems should not be empty")
	}
	if len(s.rightItems) == 0 {
		t.Error("rightItems should not be empty")
	}
	if s.activeCol != 0 {
		t.Errorf("activeCol = %d, want 0", s.activeCol)
	}
}

func TestSettingsSplitColumns(t *testing.T) {
	s := newTestSettings(t)

	// Left column: Providers, Automation
	leftSections := map[string]bool{}
	for _, item := range s.leftItems {
		leftSections[item.section] = true
	}
	for _, sec := range []string{"Providers", "Automation", "Debug"} {
		if !leftSections[sec] {
			t.Errorf("left column should contain section %q", sec)
		}
	}
	if leftSections["Servers"] {
		t.Error("left column should not contain Servers (moved to right for balance)")
	}

	// Right column: Advanced, Servers
	rightSections := map[string]bool{}
	for _, item := range s.rightItems {
		rightSections[item.section] = true
	}
	for _, sec := range []string{"Advanced", "Servers"} {
		if !rightSections[sec] {
			t.Errorf("right column should contain section %q", sec)
		}
	}
	if rightSections["Debug"] {
		t.Error("right column should not contain Debug (moved to left for balance)")
	}
}

func TestSettingsActiveItems(t *testing.T) {
	s := newTestSettings(t)

	// Default is left column
	items := s.activeItems()
	if len(items) != len(s.leftItems) {
		t.Errorf("activeItems returns %d items, want %d (leftItems)", len(items), len(s.leftItems))
	}

	s.activeCol = 1
	items = s.activeItems()
	if len(items) != len(s.rightItems) {
		t.Errorf("activeItems returns %d items, want %d (rightItems)", len(items), len(s.rightItems))
	}
}

func TestSettingsActiveCursorAndSet(t *testing.T) {
	s := newTestSettings(t)

	// Left column
	s.activeCol = 0
	s.setActiveCursor(3)
	if s.activeCursor() != 3 {
		t.Errorf("activeCursor() = %d, want 3", s.activeCursor())
	}
	if s.leftCol != 3 {
		t.Errorf("leftCol = %d, want 3", s.leftCol)
	}

	// Right column
	s.activeCol = 1
	s.setActiveCursor(2)
	if s.activeCursor() != 2 {
		t.Errorf("activeCursor() = %d, want 2", s.activeCursor())
	}
	if s.rightCol != 2 {
		t.Errorf("rightCol = %d, want 2", s.rightCol)
	}
}

func TestSettingsCurrentDescription(t *testing.T) {
	s := newTestSettings(t)

	desc := s.CurrentDescription()
	if desc == "" {
		t.Error("should return description for first item")
	}

	// Move to a known item
	s.setActiveCursor(0)
	desc = s.CurrentDescription()
	if desc != s.leftItems[0].description {
		t.Errorf("description = %q, want %q", desc, s.leftItems[0].description)
	}
}

func TestSettingsCurrentDescriptionOutOfBounds(t *testing.T) {
	s := newTestSettings(t)
	s.setActiveCursor(999)
	desc := s.CurrentDescription()
	if desc != "" {
		t.Errorf("should return empty for out-of-bounds cursor, got %q", desc)
	}
}

func TestSettingsInit(t *testing.T) {
	s := newTestSettings(t)
	cmd := s.Init()
	if cmd == nil {
		t.Error("Init should return blink tick cmd")
	}
}

func TestSettingsEsc(t *testing.T) {
	s := newTestSettings(t)
	_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd != nil {
		t.Error("esc on settings (primary nav view) should not produce a command")
	}
}

func TestSettingsCursorDown(t *testing.T) {
	s := newTestSettings(t)
	s.setActiveCursor(0)

	s.Update(tea.KeyMsg{Type: tea.KeyDown})
	if s.activeCursor() != 1 {
		t.Errorf("cursor = %d, want 1", s.activeCursor())
	}
}

func TestSettingsCursorUp(t *testing.T) {
	s := newTestSettings(t)
	s.setActiveCursor(2)

	s.Update(tea.KeyMsg{Type: tea.KeyUp})
	if s.activeCursor() != 1 {
		t.Errorf("cursor = %d, want 1", s.activeCursor())
	}
}

func TestSettingsCursorUpClamped(t *testing.T) {
	s := newTestSettings(t)
	s.setActiveCursor(0)

	s.Update(tea.KeyMsg{Type: tea.KeyUp})
	if s.activeCursor() != 0 {
		t.Errorf("cursor = %d, want 0 (clamped)", s.activeCursor())
	}
}

func TestSettingsCursorDownClamped(t *testing.T) {
	s := newTestSettings(t)
	items := s.activeItems()
	last := len(items) - 1
	s.setActiveCursor(last)

	s.Update(tea.KeyMsg{Type: tea.KeyDown})
	if s.activeCursor() != last {
		t.Errorf("cursor = %d, want %d (clamped)", s.activeCursor(), last)
	}
}

func TestSettingsLeftRightColumnSwitch(t *testing.T) {
	s := newTestSettings(t)

	if s.activeCol != 0 {
		t.Fatal("should start in left column")
	}

	s.Update(tea.KeyMsg{Type: tea.KeyRight})
	if s.activeCol != 1 {
		t.Error("right key should switch to right column")
	}

	s.Update(tea.KeyMsg{Type: tea.KeyRight})
	if s.activeCol != 1 {
		t.Error("right key in right column should stay in right column")
	}

	s.Update(tea.KeyMsg{Type: tea.KeyLeft})
	if s.activeCol != 0 {
		t.Error("left key should switch to left column")
	}

	s.Update(tea.KeyMsg{Type: tea.KeyLeft})
	if s.activeCol != 0 {
		t.Error("left key in left column should stay in left column")
	}
}

func TestSettingsHome(t *testing.T) {
	s := newTestSettings(t)
	s.setActiveCursor(5)

	s.Update(tea.KeyMsg{Type: tea.KeyHome})
	if s.activeCursor() != 0 {
		t.Errorf("cursor = %d, want 0 after Home", s.activeCursor())
	}
}

func TestSettingsEnd(t *testing.T) {
	s := newTestSettings(t)
	items := s.activeItems()
	last := len(items) - 1

	s.Update(tea.KeyMsg{Type: tea.KeyEnd})
	if s.activeCursor() != last {
		t.Errorf("cursor = %d, want %d after End", s.activeCursor(), last)
	}
}

func TestSettingsWindowSize(t *testing.T) {
	s := newTestSettings(t)

	s.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	if s.width != 100 || s.height != 30 {
		t.Errorf("size = %dx%d, want 100x30", s.width, s.height)
	}
}

func TestSettingsHandleSelectionSetupProvider(t *testing.T) {
	s := newTestSettings(t)
	// Find "setup-provider" item in left column
	for i, item := range s.leftItems {
		if item.id == "setup-provider" {
			s.activeCol = 0
			s.setActiveCursor(i)
			_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if cmd == nil {
				t.Fatal("enter on setup-provider should return cmd")
			}
			msg := cmd()
			sv, ok := msg.(SwitchViewMsg)
			if !ok {
				t.Fatalf("expected SwitchViewMsg, got %T", msg)
			}
			if sv.View != "provider-setup" {
				t.Errorf("View = %q, want provider-setup", sv.View)
			}
			return
		}
	}
	t.Error("setup-provider item not found")
}

func TestSettingsHandleSelectionTutorial(t *testing.T) {
	s := newTestSettings(t)
	// Find "tutorial" item in right column (Advanced section)
	for i, item := range s.rightItems {
		if item.id == "tutorial" {
			s.activeCol = 1
			s.setActiveCursor(i)
			_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if cmd == nil {
				t.Fatal("enter on tutorial should return cmd")
			}
			msg := cmd()
			sv, ok := msg.(SwitchViewMsg)
			if !ok {
				t.Fatalf("expected SwitchViewMsg, got %T", msg)
			}
			if sv.View != "tutorial" {
				t.Errorf("View = %q, want tutorial", sv.View)
			}
			return
		}
	}
	t.Error("tutorial item not found")
}

func TestSettingsHandleSelectionUninstall(t *testing.T) {
	s := newTestSettings(t)
	for i, item := range s.rightItems {
		if item.id == "uninstall" {
			s.activeCol = 1
			s.setActiveCursor(i)
			_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if cmd == nil {
				t.Fatal("enter on uninstall should return cmd")
			}
			msg := cmd()
			sv, ok := msg.(SwitchViewMsg)
			if !ok {
				t.Fatalf("expected SwitchViewMsg, got %T", msg)
			}
			if sv.View != "uninstall_confirm" {
				t.Errorf("View = %q, want uninstall_confirm", sv.View)
			}
			return
		}
	}
	t.Error("uninstall item not found")
}

func TestSettingsHandleSelectionDebugSettings(t *testing.T) {
	s := newTestSettings(t)
	for i, item := range s.leftItems {
		if item.id == "debug-settings" {
			s.activeCol = 0
			s.setActiveCursor(i)
			_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if cmd == nil {
				t.Fatal("debug-settings should emit a cmd")
			}
			msg := cmd()
			sv, ok := msg.(SwitchViewMsg)
			if !ok {
				t.Fatalf("expected SwitchViewMsg, got %T", msg)
			}
			if sv.View != "debug-settings" {
				t.Errorf("View = %q, want debug-settings", sv.View)
			}
			return
		}
	}
	t.Error("debug-settings item not found")
}

func TestSettingsToggleAutoRecover(t *testing.T) {
	s := newTestSettings(t)
	os.MkdirAll(s.cfg.ConfigDir, 0700)
	initial := s.cfg.AutoRecover

	for i, item := range s.leftItems {
		if item.id == "auto-recover" {
			s.activeCol = 0
			s.setActiveCursor(i)
			s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if s.cfg.AutoRecover == initial {
				t.Error("auto-recover should be toggled")
			}
			return
		}
	}
	t.Error("auto-recover item not found")
}

func TestSettingsToggleAutoFailover(t *testing.T) {
	s := newTestSettings(t)
	os.MkdirAll(s.cfg.ConfigDir, 0700)
	initial := s.cfg.AutoFailover

	for i, item := range s.leftItems {
		if item.id == "auto-failover" {
			s.activeCol = 0
			s.setActiveCursor(i)
			s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if s.cfg.AutoFailover == initial {
				t.Error("auto-failover should be toggled")
			}
			return
		}
	}
	t.Error("auto-failover item not found")
}

func TestSettingsToggleAutoconnect(t *testing.T) {
	s := newTestSettings(t)
	os.MkdirAll(s.cfg.ConfigDir, 0700)
	initial := s.cfg.Autostart

	for i, item := range s.leftItems {
		if item.id == "autoconnect" {
			s.activeCol = 0
			s.setActiveCursor(i)
			s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if s.cfg.Autostart == initial {
				t.Error("autoconnect should be toggled")
			}
			return
		}
	}
	t.Error("autoconnect item not found")
}

// Log toggle tests are in debugsettings_test.go (sub-view now owns these items).

func TestSettingsCycleAutoconnectMode(t *testing.T) {
	s := newTestSettings(t)
	os.MkdirAll(s.cfg.ConfigDir, 0700)

	for i, item := range s.leftItems {
		if item.id == "autoconnect-mode" {
			s.activeCol = 0
			s.setActiveCursor(i)

			s.cfg.AutostartMode = "last_used"
			s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if s.cfg.AutostartMode != "quickest" {
				t.Errorf("expected 'quickest', got %q", s.cfg.AutostartMode)
			}

			s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if s.cfg.AutostartMode != "random" {
				t.Errorf("expected 'random', got %q", s.cfg.AutostartMode)
			}

			s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if s.cfg.AutostartMode != "specific" {
				t.Errorf("expected 'specific', got %q", s.cfg.AutostartMode)
			}

			s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if s.cfg.AutostartMode != "last_used" {
				t.Errorf("expected 'last_used', got %q", s.cfg.AutostartMode)
			}
			return
		}
	}
	t.Error("autoconnect-mode item not found")
}

// Log mode cycle test is in debugsettings_test.go (sub-view now owns this item).

func TestSettingsRefreshServersDoneMsg(t *testing.T) {
	s := newTestSettings(t)

	s.Update(refreshServersDoneMsg{message: "Refreshed 42 servers"})
	if s.statusText != "Refreshed 42 servers" {
		t.Errorf("message = %q, want 'Refreshed 42 servers'", s.statusText)
	}
}

func TestSettingsGithubOpenedMsg(t *testing.T) {
	s := newTestSettings(t)

	s.Update(githubOpenedMsg{})
	if s.statusText != "Opening GitHub in browser..." {
		t.Errorf("message = %q, want 'Opening GitHub in browser...'", s.statusText)
	}
}

func TestSettingsRenderColumn(t *testing.T) {
	s := newTestSettings(t)
	s.focused = true

	// Render left column
	result := s.renderColumn(s.leftItems, 0, true)
	if result == "" {
		t.Error("renderColumn should not return empty")
	}

	// Should contain section headers
	if !strings.Contains(result, "Providers") {
		t.Error("should contain Providers section header")
	}

	// Active cursor should show ">"
	if !strings.Contains(result, ">") {
		t.Error("active column should show cursor indicator")
	}
}

func TestSettingsRenderColumnInactive(t *testing.T) {
	s := newTestSettings(t)

	result := s.renderColumn(s.leftItems, 0, false)
	// Inactive column should not show ">" cursor
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "> ") {
			t.Error("inactive column should not show cursor")
		}
	}
}

func TestSettingsView(t *testing.T) {
	s := newTestSettings(t)
	s.width = 100
	s.height = 40

	view := s.View()
	if !strings.Contains(view, "Settings") {
		t.Error("view should contain Settings title")
	}
	if !strings.Contains(view, "enter: toggle/select") {
		t.Error("view should contain help text")
	}
}

func TestSettingsStatusInDescription(t *testing.T) {
	s := newTestSettings(t)
	s.width = 100
	s.height = 40
	s.statusText = "Debug log cleared"

	// Status text should appear via CurrentDescription, not in the view
	desc := s.CurrentDescription()
	if desc != "Debug log cleared" {
		t.Errorf("CurrentDescription() = %q, want 'Debug log cleared'", desc)
	}
	if s.StatusIsError() {
		t.Error("should not be an error")
	}

	// Error status
	s.statusText = "Error: something broke"
	s.statusIsError = true
	if !s.StatusIsError() {
		t.Error("should be an error")
	}
	desc = s.CurrentDescription()
	if desc != "Error: something broke" {
		t.Errorf("CurrentDescription() = %q, want error text", desc)
	}

	// When cleared, should return item description
	s.statusText = ""
	s.statusIsError = false
	desc = s.CurrentDescription()
	if desc == "" {
		t.Error("should return item description when no status")
	}
}

func TestSettingsViewQuitting(t *testing.T) {
	s := newTestSettings(t)
	s.quitting = true

	view := s.View()
	if view != "" {
		t.Error("quitting view should be empty")
	}
}

func TestSettingsViewDefaultWidth(t *testing.T) {
	s := newTestSettings(t)
	// width is 0, should use default of 80

	view := s.View()
	if view == "" {
		t.Error("view should not be empty with default width")
	}
}

func TestSettingsSpaceAlsoSelects(t *testing.T) {
	s := newTestSettings(t)
	os.MkdirAll(s.cfg.ConfigDir, 0700)

	// Find an action item
	for i, item := range s.leftItems {
		if item.id == "setup-provider" {
			s.activeCol = 0
			s.setActiveCursor(i)
			_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
			if cmd == nil {
				t.Fatal("space should trigger selection")
			}
			msg := cmd()
			if _, ok := msg.(SwitchViewMsg); !ok {
				t.Errorf("expected SwitchViewMsg, got %T", msg)
			}
			return
		}
	}
	t.Error("setup-provider item not found")
}

func TestSettingsHandleSelectionAddServer(t *testing.T) {
	s := newTestSettings(t)
	// Servers section lives in the right column now.
	for i, item := range s.rightItems {
		if item.id == "add-server" {
			s.activeCol = 1
			s.setActiveCursor(i)
			_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if cmd == nil {
				t.Fatal("enter should return cmd")
			}
			msg := cmd()
			sv, ok := msg.(SwitchViewMsg)
			if !ok {
				t.Fatalf("expected SwitchViewMsg, got %T", msg)
			}
			if sv.View != "add-server" {
				t.Errorf("View = %q, want add-server", sv.View)
			}
			return
		}
	}
	t.Error("add-server item not found")
}

func TestSettingsHandleSelectionRemoveServer(t *testing.T) {
	s := newTestSettings(t)
	for i, item := range s.rightItems {
		if item.id == "remove-server" {
			s.activeCol = 1
			s.setActiveCursor(i)
			_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if cmd == nil {
				t.Fatal("enter should return cmd")
			}
			msg := cmd()
			sv, ok := msg.(SwitchViewMsg)
			if !ok {
				t.Fatalf("expected SwitchViewMsg, got %T", msg)
			}
			if sv.View != "remove-server" {
				t.Errorf("View = %q, want remove-server", sv.View)
			}
			return
		}
	}
	t.Error("remove-server item not found")
}

func TestSettingsHandleSelectionRemoveProvider(t *testing.T) {
	s := newTestSettings(t)
	for i, item := range s.leftItems {
		if item.id == "remove-provider" {
			s.activeCol = 0
			s.setActiveCursor(i)
			_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if cmd == nil {
				t.Fatal("enter should return cmd")
			}
			msg := cmd()
			sv, ok := msg.(SwitchViewMsg)
			if !ok {
				t.Fatalf("expected SwitchViewMsg, got %T", msg)
			}
			if sv.View != "remove-provider" {
				t.Errorf("View = %q, want remove-provider", sv.View)
			}
			return
		}
	}
	t.Error("remove-provider item not found")
}

func TestSettingsHandleSelectionRenameInterface(t *testing.T) {
	s := newTestSettings(t)
	for i, item := range s.rightItems {
		if item.id == "rename-interface" {
			s.activeCol = 1
			s.setActiveCursor(i)
			_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if cmd == nil {
				t.Fatal("enter should return cmd")
			}
			msg := cmd()
			sv, ok := msg.(SwitchViewMsg)
			if !ok {
				t.Fatalf("expected SwitchViewMsg, got %T", msg)
			}
			if sv.View != "rename-interface" {
				t.Errorf("View = %q, want rename-interface", sv.View)
			}
			return
		}
	}
	t.Error("rename-interface item not found")
}

func TestSettingsBuildItemsSpecificMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")
	cfg.AutostartMode = "specific"
	cfg.AutostartServer = "US-NY#42"

	s := NewSettings(cfg)

	// Should include autoconnect-server item
	found := false
	for _, item := range s.items {
		if item.id == "autoconnect-server" {
			found = true
			if item.value != "US-NY#42" {
				t.Errorf("autoconnect-server value = %q, want US-NY#42", item.value)
			}
		}
	}
	if !found {
		t.Error("should include autoconnect-server when mode is specific")
	}
}

func TestSettingsBuildItemsSpecificModeNoServer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")
	cfg.AutostartMode = "specific"
	cfg.AutostartServer = ""

	s := NewSettings(cfg)

	for _, item := range s.items {
		if item.id == "autoconnect-server" {
			if item.value != "(not set)" {
				t.Errorf("autoconnect-server value = %q, want (not set)", item.value)
			}
			return
		}
	}
	t.Error("autoconnect-server item not found")
}

func TestSettingsHandleSelectionAutoconnectServer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")
	cfg.AutostartMode = "specific"
	os.MkdirAll(cfg.ConfigDir, 0700)

	s := NewSettings(cfg)

	// Find autoconnect-server in left items (Automation section)
	for i, item := range s.leftItems {
		if item.id == "autoconnect-server" {
			s.activeCol = 0
			s.setActiveCursor(i)
			_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if cmd == nil {
				t.Fatal("enter should return cmd")
			}
			msg := cmd()
			sv, ok := msg.(SwitchViewMsg)
			if !ok {
				t.Fatalf("expected SwitchViewMsg, got %T", msg)
			}
			if sv.View != "autoconnect-server-select" {
				t.Errorf("View = %q, want autoconnect-server-select", sv.View)
			}
			return
		}
	}
	t.Error("autoconnect-server item not found")
}

func TestSettingsHandleSelectionOutOfBounds(t *testing.T) {
	s := newTestSettings(t)
	s.setActiveCursor(999)

	// Should not panic
	_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
	// Out-of-bounds should return nil cmd (handleSelection early returns)
	_ = cmd
}

// TestSettingsManualUpdateCheck verifies the "Check for Updates Now" action
// runs the update check and surfaces the result as a ManualUpdateCheckMsg.
func TestSettingsManualUpdateCheck(t *testing.T) {
	s := newTestSettings(t)

	orig := checkForUpdate
	checkForUpdate = func(current string) (*update.Release, error) {
		return &update.Release{TagName: "9.9.9"}, nil
	}
	t.Cleanup(func() { checkForUpdate = orig })

	for i, item := range s.leftItems {
		if item.id != "check-updates" {
			continue
		}
		s.activeCol = 0
		s.setActiveCursor(i)
		_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
		if cmd == nil {
			t.Fatal("check-updates should return a cmd")
		}
		msg, ok := cmd().(ManualUpdateCheckMsg)
		if !ok {
			t.Fatalf("expected ManualUpdateCheckMsg, got %T", cmd())
		}
		if msg.Err != nil {
			t.Fatalf("unexpected error: %v", msg.Err)
		}
		if msg.Release == nil || msg.Release.TagName != "9.9.9" {
			t.Errorf("expected release 9.9.9, got %+v", msg.Release)
		}
		return
	}
	t.Fatal("check-updates item not found in Automation (left) column")
}

func TestSettingsHandleSelectionGitHub(t *testing.T) {
	s := newTestSettings(t)
	os.MkdirAll(s.cfg.ConfigDir, 0700)

	// Mock exec.Command so xdg-open doesn't actually open a browser
	origExec := execCommandFn
	execCommandFn = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("true") // no-op
	}
	t.Cleanup(func() { execCommandFn = origExec })

	for i, item := range s.rightItems {
		if item.id == "github" {
			s.activeCol = 1
			s.setActiveCursor(i)
			_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if cmd == nil {
				t.Fatal("enter on github should return cmd")
			}
			msg := cmd()
			if _, ok := msg.(githubOpenedMsg); !ok {
				t.Errorf("expected githubOpenedMsg, got %T", msg)
			}
			return
		}
	}
	t.Error("github item not found")
}

func TestSettingsHandleSelectionRefreshServers(t *testing.T) {
	s := newTestSettings(t)
	os.MkdirAll(s.cfg.ConfigDir, 0700)

	for i, item := range s.leftItems {
		if item.id == "refresh-servers" {
			s.activeCol = 0
			s.setActiveCursor(i)
			_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if cmd == nil {
				t.Fatal("enter on refresh-servers should return cmd")
			}
			return
		}
	}
	t.Error("refresh-servers item not found")
}

// TestSettingsHandleSelectionAutoconnectModeDefault tests cycling from default (empty) value.
func TestSettingsHandleSelectionAutoconnectModeDefault(t *testing.T) {
	s := newTestSettings(t)
	os.MkdirAll(s.cfg.ConfigDir, 0700)

	for i, item := range s.leftItems {
		if item.id == "autoconnect-mode" {
			s.activeCol = 0
			s.setActiveCursor(i)
			s.cfg.AutostartMode = "" // empty default
			s.Update(tea.KeyMsg{Type: tea.KeyEnter})
			if s.cfg.AutostartMode != "quickest" {
				t.Errorf("expected 'quickest', got %q", s.cfg.AutostartMode)
			}
			return
		}
	}
	t.Error("autoconnect-mode item not found")
}

// Log mode default test is in debugsettings_test.go (sub-view now owns this item).

// --- Mock helpers for settings tests ---

func mockFetchServers(t *testing.T, fn func(string, bool) error) {
	t.Helper()
	orig := fetchServers
	fetchServers = fn
	t.Cleanup(func() { fetchServers = orig })
}

func mockFilterProviderServers(t *testing.T, fn func(string, string) ([]provider.Server, error)) {
	t.Helper()
	orig := filterProviderServers
	filterProviderServers = fn
	t.Cleanup(func() { filterProviderServers = orig })
}

func mockConfigListProviders(t *testing.T, fn func(string) ([]string, error)) {
	t.Helper()
	orig := configListProviders
	configListProviders = fn
	t.Cleanup(func() { configListProviders = orig })
}

// TestDoRefreshServersSuccess tests the doRefreshServers command
// with mocked fetchServers, configListProviders, and filterProviderServers.
func TestDoRefreshServersSuccess(t *testing.T) {
	mockFetchServers(t, func(cacheDir string, force bool) error {
		return nil
	})
	mockConfigListProviders(t, func(configDir string) ([]string, error) {
		return []string{"protonvpn", "mullvad"}, nil
	})
	mockFilterProviderServers(t, func(cacheDir, prov string) ([]provider.Server, error) {
		return []provider.Server{
			{ServerName: "US-NY#1"},
			{ServerName: "US-NY#2"},
		}, nil
	})

	s := newTestSettings(t)
	cmd := s.doRefreshServers()
	if cmd == nil {
		t.Fatal("doRefreshServers should return a cmd")
	}

	msg := cmd()
	result, ok := msg.(refreshServersDoneMsg)
	if !ok {
		t.Fatalf("expected refreshServersDoneMsg, got %T", msg)
	}
	if !strings.Contains(result.message, "Refreshed 4 servers") {
		t.Errorf("message = %q, want to contain 'Refreshed 4 servers'", result.message)
	}
}

// TestDoRefreshServersFetchError tests doRefreshServers when fetchServers fails.
func TestDoRefreshServersFetchError(t *testing.T) {
	mockFetchServers(t, func(cacheDir string, force bool) error {
		return errForTest("fetch failed")
	})

	s := newTestSettings(t)
	cmd := s.doRefreshServers()
	msg := cmd()

	result, ok := msg.(refreshServersDoneMsg)
	if !ok {
		t.Fatalf("expected refreshServersDoneMsg, got %T", msg)
	}
	if !strings.Contains(result.message, "Error") {
		t.Errorf("message = %q, want to contain 'Error'", result.message)
	}
}

// TestManageAutoconnectDesktopFileEnable tests creating the desktop file.
func TestManageAutoconnectDesktopFileEnable(t *testing.T) {
	err := manageAutoconnectDesktopFile(true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Clean up
	homeDir, _ := os.UserHomeDir()
	desktopFile := filepath.Join(homeDir, ".config", "autostart", "lazyvpn.desktop")
	t.Cleanup(func() { os.Remove(desktopFile) })
}

// TestManageAutoconnectDesktopFileDisable tests removing the desktop file.
func TestManageAutoconnectDesktopFileDisable(t *testing.T) {
	err := manageAutoconnectDesktopFile(false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRenderedLineCount(t *testing.T) {
	items := []settingItem{
		{name: "a", section: "S1"},
		{name: "b", section: "S1"},
		{name: "c", section: "S2"},
	}
	// S1 header(1) + a(1) + b(1) + blank(1) + S2 header(1) + c(1) = 6
	got := renderedLineCount(items)
	if got != 6 {
		t.Errorf("renderedLineCount = %d, want 6", got)
	}
}

func TestRenderedLineCountEmpty(t *testing.T) {
	got := renderedLineCount(nil)
	if got != 0 {
		t.Errorf("renderedLineCount(nil) = %d, want 0", got)
	}
}

func TestCursorToLine(t *testing.T) {
	items := []settingItem{
		{name: "a", section: "S1"},
		{name: "b", section: "S1"},
		{name: "c", section: "S2"},
	}
	// S1 header = line 0, a = line 1, b = line 2, blank = line 3, S2 header = line 4, c = line 5
	tests := []struct {
		cursor int
		want   int
	}{
		{0, 1}, // item "a" is at line 1 (after S1 header)
		{1, 2}, // item "b" is at line 2
		{2, 5}, // item "c" is at line 5 (after blank + S2 header)
	}
	for _, tt := range tests {
		got := cursorToLine(items, tt.cursor)
		if got != tt.want {
			t.Errorf("cursorToLine(items, %d) = %d, want %d", tt.cursor, got, tt.want)
		}
	}
}

func TestSettingsAdjustScrollBasic(t *testing.T) {
	s := newTestSettings(t)
	s.height = 15 // small terminal: visibleLines = 15 - 5 = 10
	s.scrollOffset = 0

	// Move cursor to last item and adjust
	items := s.activeItems()
	s.setActiveCursor(len(items) - 1)
	s.adjustScroll()

	// scrollOffset should have increased to show the cursor
	curLine := cursorToLine(items, s.activeCursor())
	visible := s.visibleLines()
	if curLine >= visible && s.scrollOffset == 0 {
		t.Error("scrollOffset should increase when cursor is past visible area")
	}
}

func TestSettingsAdjustScrollNoScrollNeeded(t *testing.T) {
	s := newTestSettings(t)
	s.height = 100 // very tall terminal

	s.setActiveCursor(0)
	s.adjustScroll()
	if s.scrollOffset != 0 {
		t.Errorf("scrollOffset = %d, want 0 when all content fits", s.scrollOffset)
	}
}

func TestSettingsScrollOnCursorDown(t *testing.T) {
	s := newTestSettings(t)
	s.height = 12 // visible = 7

	// Navigate down through all items
	items := s.activeItems()
	for i := 0; i < len(items)-1; i++ {
		s.Update(tea.KeyMsg{Type: tea.KeyDown})
	}

	// Cursor should be at last item and scrollOffset adjusted
	if s.activeCursor() != len(items)-1 {
		t.Errorf("cursor = %d, want %d", s.activeCursor(), len(items)-1)
	}
	// With visible=7, there should be some scroll offset for ~14 left items
	total := renderedLineCount(items)
	if total > 7 && s.scrollOffset == 0 {
		t.Error("scrollOffset should be > 0 after scrolling down past visible area")
	}
}

func TestSettingsScrollBackUp(t *testing.T) {
	s := newTestSettings(t)
	s.height = 12 // visible = 7

	// Navigate to bottom
	items := s.activeItems()
	for i := 0; i < len(items)-1; i++ {
		s.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	savedOffset := s.scrollOffset

	// Navigate back to top
	for i := 0; i < len(items)-1; i++ {
		s.Update(tea.KeyMsg{Type: tea.KeyUp})
	}

	if s.activeCursor() != 0 {
		t.Errorf("cursor = %d, want 0", s.activeCursor())
	}
	if s.scrollOffset != 0 {
		t.Errorf("scrollOffset = %d, want 0 after scrolling back to top", s.scrollOffset)
	}
	_ = savedOffset
}

func TestSettingsHomeResetsScroll(t *testing.T) {
	s := newTestSettings(t)
	s.height = 12

	// Navigate down
	items := s.activeItems()
	for i := 0; i < len(items)-1; i++ {
		s.Update(tea.KeyMsg{Type: tea.KeyDown})
	}

	// Home
	s.Update(tea.KeyMsg{Type: tea.KeyHome})
	if s.activeCursor() != 0 {
		t.Errorf("cursor = %d, want 0 after Home", s.activeCursor())
	}
	if s.scrollOffset != 0 {
		t.Errorf("scrollOffset = %d, want 0 after Home", s.scrollOffset)
	}
}

func TestSettingsEndScrolls(t *testing.T) {
	s := newTestSettings(t)
	s.height = 12

	s.Update(tea.KeyMsg{Type: tea.KeyEnd})
	items := s.activeItems()
	if s.activeCursor() != len(items)-1 {
		t.Errorf("cursor = %d, want %d after End", s.activeCursor(), len(items)-1)
	}
}

func TestSettingsColumnSwitchAdjustsScroll(t *testing.T) {
	s := newTestSettings(t)
	s.height = 12

	// Move deep into left column
	items := s.activeItems()
	for i := 0; i < len(items)-1; i++ {
		s.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	leftOffset := s.scrollOffset

	// Switch to right column — scroll should adjust for right column cursor (at 0)
	s.Update(tea.KeyMsg{Type: tea.KeyRight})
	if s.activeCol != 1 {
		t.Fatal("should be in right column")
	}
	// Right column cursor is at 0, so scroll should reset
	if s.scrollOffset != 0 {
		t.Errorf("scrollOffset = %d, want 0 after switching to right column at cursor 0", s.scrollOffset)
	}
	_ = leftOffset
}

func TestSettingsBlinkToggle(t *testing.T) {
	s := newTestSettings(t)

	initial := s.blinkOn
	s.Update(settingsBlinkMsg{})
	if s.blinkOn == initial {
		t.Error("blinkOn should toggle on settingsBlinkMsg")
	}
	s.Update(settingsBlinkMsg{})
	if s.blinkOn != initial {
		t.Error("blinkOn should toggle back")
	}
}

func TestSettingsViewWithScroll(t *testing.T) {
	s := newTestSettings(t)
	s.width = 80
	s.height = 12 // small enough to trigger scrolling
	s.blinkOn = true

	// Move to bottom to trigger scroll
	items := s.activeItems()
	for i := 0; i < len(items)-1; i++ {
		s.Update(tea.KeyMsg{Type: tea.KeyDown})
	}

	view := s.View()
	if !strings.Contains(view, "Settings") {
		t.Error("view should contain Settings title")
	}
	// Should contain a scroll indicator (up arrow since we're at bottom)
	if !strings.Contains(view, "▲") {
		t.Error("view should contain up scroll indicator when scrolled down")
	}
}

func TestSettingsViewNoScrollIndicatorsWhenFits(t *testing.T) {
	s := newTestSettings(t)
	s.width = 80
	s.height = 100 // very tall, everything fits
	s.blinkOn = true

	view := s.View()
	if strings.Contains(view, "▲") || strings.Contains(view, "▼") {
		t.Error("should not show scroll indicators when all content fits")
	}
}

// UFW logging cycle and error tests are in debugsettings_test.go (sub-view now owns this item).

func TestSettingsBuildScrollbar(t *testing.T) {
	s := newTestSettings(t)
	s.scrollOffset = 0

	// No scrollbar when everything fits
	sb := s.buildScrollbar(20, 10)
	if sb != "" {
		t.Error("should return empty when total <= visible")
	}

	// Scrollbar when content overflows
	sb = s.buildScrollbar(10, 25)
	if sb == "" {
		t.Error("should return scrollbar when total > visible")
	}
	if !strings.Contains(sb, "█") {
		t.Error("scrollbar should contain thumb character")
	}
	if !strings.Contains(sb, "│") {
		t.Error("scrollbar should contain track character")
	}
}

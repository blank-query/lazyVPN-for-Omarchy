package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

// newTestDebugSettings creates a DebugSettings with a temp config dir for testing.
func newTestDebugSettings(t *testing.T) *DebugSettings {
	t.Helper()
	stubFirewall(t)
	stubNotifications(t)
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")
	return NewDebugSettings(cfg)
}

func TestDebugSettings_ToggleLogConnection(t *testing.T) {
	d := newTestDebugSettings(t)
	d.focused = true

	if d.cfg.LogConnection {
		t.Fatal("LogConnection should start false")
	}

	// Cursor starts at 0 (Log Connections)
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})

	if !d.cfg.LogConnection {
		t.Error("LogConnection should be true after toggle")
	}

	// Toggle again
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})

	if d.cfg.LogConnection {
		t.Error("LogConnection should be false after second toggle")
	}
}

func TestDebugSettings_ToggleLogAutorecover(t *testing.T) {
	d := newTestDebugSettings(t)
	d.focused = true

	// Move to Log Auto-Recover (index 1)
	d.Update(tea.KeyMsg{Type: tea.KeyDown})
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})

	if !d.cfg.LogAutorecover {
		t.Error("LogAutorecover should be true after toggle")
	}
}

func TestDebugSettings_ToggleLogFirewall(t *testing.T) {
	d := newTestDebugSettings(t)
	d.focused = true

	// Move to Log Firewall Events (index 2)
	d.Update(tea.KeyMsg{Type: tea.KeyDown})
	d.Update(tea.KeyMsg{Type: tea.KeyDown})
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})

	if !d.cfg.LogFirewall {
		t.Error("LogFirewall should be true after toggle")
	}
}

func TestDebugSettings_ToggleLogProvider(t *testing.T) {
	d := newTestDebugSettings(t)
	d.focused = true

	// Move to Log Provider (index 3)
	for i := 0; i < 3; i++ {
		d.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})

	if !d.cfg.LogProvider {
		t.Error("LogProvider should be true after toggle")
	}
}

func TestDebugSettings_ToggleLogAutostart(t *testing.T) {
	d := newTestDebugSettings(t)
	d.focused = true

	// Move to Log Autostart (index 4)
	for i := 0; i < 4; i++ {
		d.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})

	if !d.cfg.LogAutostart {
		t.Error("LogAutostart should be true after toggle")
	}
}

func TestDebugSettings_CycleLogMode(t *testing.T) {
	d := newTestDebugSettings(t)
	d.focused = true

	// Move to Log Mode (index 5)
	for i := 0; i < 5; i++ {
		d.Update(tea.KeyMsg{Type: tea.KeyDown})
	}

	// Default is safe
	if d.cfg.LogMode != "" && d.cfg.LogMode != "safe" {
		t.Fatalf("LogMode should default to safe, got %q", d.cfg.LogMode)
	}

	// Cycle to accurate
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if d.cfg.LogMode != "accurate" {
		t.Errorf("LogMode should be accurate, got %q", d.cfg.LogMode)
	}

	// Cycle back to safe
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if d.cfg.LogMode != "safe" {
		t.Errorf("LogMode should be safe, got %q", d.cfg.LogMode)
	}
}

// TestDebugSettings_CycleLogModeRevertsOnSaveFailure verifies that
// when cfg.Save fails, LogMode is reverted to its previous value
// rather than left at the post-cycle "accurate" value. cfg.Save is
// atomic — on failure, disk stays whatever it was — so without the
// revert, in-memory would say "accurate" while disk and the next
// process invocation see "safe", causing logs to appear less
// sanitized in this session than they actually persist as.
func TestDebugSettings_CycleLogModeRevertsOnSaveFailure(t *testing.T) {
	d := newTestDebugSettings(t)
	d.focused = true

	// Pre-set LogMode to "safe" (an explicit non-default for the test).
	d.cfg.LogMode = "safe"

	// Force Save failure by pointing ConfigDir at a regular file.
	dummyFile := d.cfg.ConfigDir + "/not-a-dir"
	if err := os.WriteFile(dummyFile, []byte("x"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	d.cfg.ConfigDir = dummyFile

	// Move to Log Mode (index 5) and press Enter.
	for i := 0; i < 5; i++ {
		d.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})

	if d.cfg.LogMode != "safe" {
		t.Errorf("LogMode = %q, want %q (Save failed → cycle should revert)",
			d.cfg.LogMode, "safe")
	}
}

func TestDebugSettings_CycleUFWLogging(t *testing.T) {
	d := newTestDebugSettings(t)
	d.focused = true

	// Track what SetLogging is called with
	var setLevel string
	origSet := firewallSetLogging
	origGet := firewallGetLoggingLevel
	firewallSetLogging = func(level string) error {
		setLevel = level
		return nil
	}
	currentLevel := "off"
	firewallGetLoggingLevel = func() string { return currentLevel }
	t.Cleanup(func() {
		firewallSetLogging = origSet
		firewallGetLoggingLevel = origGet
	})

	// Move to UFW Packet Log (index 8)
	for i := 0; i < 8; i++ {
		d.Update(tea.KeyMsg{Type: tea.KeyDown})
	}

	// Cycle from off → low
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if setLevel != "low" {
		t.Errorf("expected SetLogging(low), got %q", setLevel)
	}

	// Simulate that level is now "low"
	currentLevel = "low"
	d.items = d.buildItems()
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if setLevel != "medium" {
		t.Errorf("expected SetLogging(medium), got %q", setLevel)
	}

	// Simulate full → off
	currentLevel = "full"
	d.items = d.buildItems()
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if setLevel != "off" {
		t.Errorf("expected SetLogging(off), got %q", setLevel)
	}
}

func TestDebugSummary(t *testing.T) {
	tests := []struct {
		name string
		cfg  func() *config.Config
		want string
	}{
		{
			name: "none enabled",
			cfg:  config.DefaultConfig,
			want: "0/5 enabled",
		},
		{
			name: "two enabled",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.LogConnection = true
				c.LogFirewall = true
				return c
			},
			want: "2/5 enabled",
		},
		{
			name: "all enabled",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.LogConnection = true
				c.LogAutorecover = true
				c.LogFirewall = true
				c.LogProvider = true
				c.LogAutostart = true
				return c
			},
			want: "5/5 enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := debugSummary(tt.cfg())
			if got != tt.want {
				t.Errorf("debugSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDebugSettings_BackMsgOnEsc(t *testing.T) {
	d := newTestDebugSettings(t)
	d.focused = true

	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEscape})

	if cmd == nil {
		t.Fatal("expected cmd on esc, got nil")
	}

	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestDebugSettings_NavigationBounds(t *testing.T) {
	d := newTestDebugSettings(t)
	d.focused = true

	// Already at top, up should stay at 0
	d.Update(tea.KeyMsg{Type: tea.KeyUp})
	if d.cursor != 0 {
		t.Errorf("cursor should stay at 0, got %d", d.cursor)
	}

	// Move to bottom
	for i := 0; i < 20; i++ {
		d.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	expected := len(d.items) - 1
	if d.cursor != expected {
		t.Errorf("cursor should be at %d, got %d", expected, d.cursor)
	}

	// Another down should stay at bottom
	d.Update(tea.KeyMsg{Type: tea.KeyDown})
	if d.cursor != expected {
		t.Errorf("cursor should stay at %d, got %d", expected, d.cursor)
	}
}

func TestDebugSettings_ViewLog(t *testing.T) {
	d := newTestDebugSettings(t)
	d.focused = true

	// Move to View Debug Log (index 6)
	for i := 0; i < 6; i++ {
		d.Update(tea.KeyMsg{Type: tea.KeyDown})
	}

	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("expected SwitchViewMsg cmd for view-log")
	}

	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.View != "view-log" {
		t.Errorf("expected view-log, got %q", sv.View)
	}
}

func TestCountEnabledLogs(t *testing.T) {
	cfg := config.DefaultConfig()
	if got := countEnabledLogs(cfg); got != 0 {
		t.Errorf("default config should have 0 logs enabled, got %d", got)
	}

	cfg.LogConnection = true
	cfg.LogAutorecover = true
	cfg.LogProvider = true
	if got := countEnabledLogs(cfg); got != 3 {
		t.Errorf("expected 3 logs enabled, got %d", got)
	}
}

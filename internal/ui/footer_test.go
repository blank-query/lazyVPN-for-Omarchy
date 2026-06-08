package ui

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

func TestNewStatusFooter(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)

	if f.cfg != cfg {
		t.Error("cfg not set")
	}
	if f.connected {
		t.Error("should not be connected initially")
	}
	if f.prettyName != "" {
		t.Error("prettyName should be empty")
	}
}

func TestStatusFooterWindowSize(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)

	f, _ = f.Update(tea.WindowSizeMsg{Width: 120})
	if f.width != 120 {
		t.Errorf("width = %d, want 120", f.width)
	}
}

func TestStatusFooterViewDisconnected(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.width = 80

	view := f.View()
	if view == "" {
		t.Error("view should not be empty")
	}
	// Disconnected view should contain "DISCONNECTED"
	// (the styled text will be in the output)
}

func TestStatusFooterViewDisconnectedWithKillswitch(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.killswitch = true
	f.width = 80

	view := f.View()
	if view == "" {
		t.Error("view should not be empty")
	}
}

func TestStatusFooterViewZeroWidth(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	// Zero width should still render without panic
	view := f.View()
	if view == "" {
		t.Error("view should not be empty even with zero width")
	}
}

func TestStatusFooterInit(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	cmd := f.Init()
	if cmd == nil {
		t.Error("Init should return a command")
	}
	// Init now returns a tea.Batch of (refreshAsync, scheduleTick) so
	// the footer doesn't briefly render with stale defaults on startup.
	// tea.BatchMsg is what cmd() yields for a Batch.
	msg := cmd()
	if msg == nil {
		t.Fatal("Init cmd should yield a non-nil message")
	}
}

func TestStatusFooterViewConnected(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.connected = true
	f.prettyName = "US - New York #42"
	f.killswitch = true
	f.width = 120

	view := f.View()
	if view == "" {
		t.Error("connected view should not be empty")
	}
}

func TestStatusFooterViewConnectedNoKillswitch(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.connected = true
	f.prettyName = "test-server"
	f.width = 120

	view := f.View()
	if view == "" {
		t.Error("view should not be empty")
	}
}

func TestStatusFooterViewWithOverlayDisconnected(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.OverlayText = "Test description"
	f.width = 120

	view := f.View()
	if view == "" {
		t.Error("overlay view should not be empty")
	}
}

func TestStatusFooterViewWithOverlayConnected(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.connected = true
	f.prettyName = "US-NY#42"
	f.OverlayText = "Test description"
	f.width = 120

	view := f.View()
	if view == "" {
		t.Error("overlay view should not be empty")
	}
}

func TestStatusFooterViewWithOverlayConnectedKS(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.connected = true
	f.prettyName = "US-NY#42"
	f.killswitch = true
	f.OverlayText = "Test description"
	f.width = 120

	view := f.View()
	if view == "" {
		t.Error("overlay view should not be empty")
	}
}

func TestStatusFooterViewWithOverlayNarrow(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.connected = true
	f.prettyName = "Very Long Server Name That Takes Up Space"
	f.OverlayText = "Also a very long description text that needs lots of space"
	f.width = 40 // narrow enough to trigger truncation logic

	// Should not panic
	view := f.View()
	if view == "" {
		t.Error("narrow overlay view should not be empty")
	}
}

func TestStatusFooterViewWithOverlayVeryNarrow(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.connected = true
	f.prettyName = "Very Long Server Name"
	f.OverlayText = "A description"
	f.width = 20 // very narrow, maxLeft < 12

	// Should not panic
	view := f.View()
	if view == "" {
		t.Error("very narrow overlay view should not be empty")
	}
}

func TestStatusFooterViewWithOverlayKillswitchDisconnected(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.killswitch = true
	f.OverlayText = "Setting description"
	f.width = 120

	view := f.View()
	if view == "" {
		t.Error("killswitch overlay view should not be empty")
	}
}

func TestStatusFooterViewDisconnectedKillswitch(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.killswitch = true
	f.width = 120

	view := f.View()
	if view == "" {
		t.Error("view should not be empty")
	}
}

func TestStatusFooterUpdateStatusUpdateMsg(t *testing.T) {
	cfg := &config.Config{
		ConnectionName: "nonexistent-iface",
		ConfigDir:      t.TempDir(),
		ConfigFile:     t.TempDir() + "/config",
	}
	f := NewStatusFooter(cfg)

	f, cmd := f.Update(StatusUpdateMsg{})
	// refresh was called - since not connected, all should be cleared
	if f.connected {
		t.Error("should not be connected with nonexistent interface")
	}
	if f.prettyName != "" {
		t.Errorf("prettyName = %q, want empty", f.prettyName)
	}
	// Should return a cmd for the next tick
	if cmd == nil {
		t.Error("should return tick cmd for next update")
	}
}

func TestStatusFooterRefreshDisconnected(t *testing.T) {
	cfg := &config.Config{
		ConnectionName: "nonexistent-iface",
		ConfigDir:      t.TempDir(),
		ConfigFile:     t.TempDir() + "/config",
	}
	origIsActive := isFirewallActive
	isFirewallActive = func() bool { return true }
	t.Cleanup(func() { isFirewallActive = origIsActive })

	f := NewStatusFooter(cfg)
	// Simulate previously connected state
	f.connected = true
	f.prettyName = "old-server"

	// refresh() should detect that connection is gone
	f.refresh()

	if f.connected {
		t.Error("should not be connected after refresh")
	}
	if f.prettyName != "" {
		t.Errorf("prettyName = %q, should be cleared", f.prettyName)
	}
	// Killswitch state is read from the firewall via isFirewallActive.
	if !f.killswitch {
		t.Errorf("killswitch = %v, should be true (isFirewallActive stub returned true)", f.killswitch)
	}
}

func TestStatusFooterUpdateUnhandledMsg(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)

	// Unhandled message type should be ignored
	_, cmd := f.Update(BackMsg{})
	if cmd != nil {
		t.Error("unhandled message should return nil cmd")
	}
}

// footerTestConfig creates a config saved to a temp HOME directory so that
// Reload() (which calls Load() -> DefaultConfig()) reads from the temp dir.
// The killswitch argument drives the isFirewallActive stub — cfg no longer
// persists that field (firewall state is the source of truth).
func footerTestConfig(t *testing.T, serverName, publicIP string, killswitch bool, connectedSince time.Time) *config.Config {
	t.Helper()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origIsActive := isFirewallActive
	isFirewallActive = func() bool { return killswitch }
	t.Cleanup(func() { isFirewallActive = origIsActive })

	cfg := config.DefaultConfig() // Now uses tmpHome/.config/lazyvpn
	// Save now requires ConfigDir to exist (it no longer creates it on demand
	// — that change keeps `lazyvpn` from re-creating state after uninstall).
	if err := os.MkdirAll(cfg.ConfigDir, 0700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	cfg.ConnectionName = "wg0"
	cfg.LastConnectedServer = serverName
	cfg.LastPublicIP = publicIP
	cfg.ConnectedSince = connectedSince
	if err := cfg.Save(); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}
	return cfg
}

// TestStatusFooterRefreshConnected tests the refresh() method with isWGConnected
// mocked to return true. This exercises the connected code path (lines 66-131).
func TestStatusFooterRefreshConnected(t *testing.T) {
	mockConnected(t)

	cfg := footerTestConfig(t, "US-NY#42", "10.0.0.1", true, time.Now().Add(-5*time.Minute))
	f := NewStatusFooter(cfg)
	f.refresh()

	if !f.connected {
		t.Error("should be connected")
	}
	if f.prettyName == "" {
		t.Error("prettyName should be set")
	}
	if !f.killswitch {
		t.Error("killswitch should be true")
	}
}

// TestStatusFooterRefreshConnectedDynamic tests refresh with a dynamic server.
func TestStatusFooterRefreshConnectedDynamic(t *testing.T) {
	mockConnected(t)

	cfg := footerTestConfig(t, "dynamic:protonvpn:US-NY#42", "10.0.0.1", false, time.Now())
	f := NewStatusFooter(cfg)
	f.refresh()

	if !f.connected {
		t.Error("should be connected")
	}
	// prettyName should be based on "US-NY#42" (stripped dynamic prefix)
	if f.prettyName == "" {
		t.Error("prettyName should not be empty")
	}
}

// TestStatusFooterRefreshConnectedWithFeatures tests refresh with saved server features.
func TestStatusFooterRefreshConnectedWithFeatures(t *testing.T) {
	mockConnected(t)

	cfg := footerTestConfig(t, "dynamic:protonvpn:US-NY#42", "10.0.0.1", false, time.Now())
	cfg.LastServerFeatures = "port-forward,streaming"
	cfg.Save()
	f := NewStatusFooter(cfg)
	f.refresh()

	if !f.connected {
		t.Error("should be connected")
	}
	if f.prettyName == "" {
		t.Error("prettyName should be set with features")
	}
}

// TestStatusFooterRefreshConnectedNoConnectedSince tests when ConnectedSince is zero.
func TestStatusFooterRefreshConnectedNoConnectedSince(t *testing.T) {
	mockConnected(t)

	cfg := footerTestConfig(t, "test", "", false, time.Time{})
	f := NewStatusFooter(cfg)
	f.refresh()

	if !f.connected {
		t.Error("should be connected")
	}
}

// TestStatusFooterViewWithOverlayConnectedMediumWidth tests the overlay path where
// both sides don't fit but maxLeft >= 12 (exercises the middle truncation path).
func TestStatusFooterViewWithOverlayConnectedMediumWidth(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.connected = true
	f.prettyName = "US - New York #42 Some Long Name"
	f.killswitch = true
	f.OverlayText = "A description that is somewhat long and takes space"
	f.width = 70 // Medium width - both sides won't fit but maxLeft >= 12

	view := f.View()
	if view == "" {
		t.Error("medium width overlay view should not be empty")
	}
}

// TestStatusFooterViewWithOverlayBothFit tests the overlay path where
// both left and right content fit in the available width.
func TestStatusFooterViewWithOverlayBothFit(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.connected = true
	f.prettyName = "US-NY"
	f.OverlayText = "Short"
	f.width = 200 // Very wide - both sides fit

	view := f.View()
	if view == "" {
		t.Error("wide overlay view should not be empty")
	}
}

// TestStatusFooterViewNormalConnectedAllFields tests viewNormal with all fields populated.
func TestStatusFooterViewNormalConnectedAllFields(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.connected = true
	f.prettyName = "US - New York #42"
	f.killswitch = true
	f.width = 160

	view := f.viewNormal()
	if view == "" {
		t.Error("view should not be empty")
	}
}

// TestStatusFooterView_ExtremeWidths probes the footer's View at
// pathological widths (sub-3, zero, negative) — terminals briefly
// report tiny widths during fast resizes, and lipgloss.Width(<=0)
// can panic depending on the version. Verifies no panic across all
// state combos (connected/disconnected, killswitch on/off).
func TestStatusFooterView_ExtremeWidths(t *testing.T) {
	widths := []int{-1, 0, 1, 2, 3, 5, 10, 80}
	stateMatrix := []struct {
		connected, killswitch bool
	}{
		{false, false},
		{false, true},
		{true, false},
		{true, true},
	}
	for _, st := range stateMatrix {
		for _, w := range widths {
			t.Run(fmt.Sprintf("conn=%v_ks=%v_w=%d", st.connected, st.killswitch, w), func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("View panicked at width=%d: %v", w, r)
					}
				}()
				cfg := &config.Config{}
				f := NewStatusFooter(cfg)
				f.connected = st.connected
				f.killswitch = st.killswitch
				f.prettyName = "US-NY#42"
				f.width = w
				_ = f.View()
			})
		}
	}
}

// TestStatusFooterUpdate_DoesNotBlockOnSudo verifies the every-1s
// status tick doesn't run isFirewallActive (sudo subprocess) inline
// in Update. Pre-fix, that meant the entire TUI froze for ~50ms
// every second under any sudo slowness — 5% CPU and visible jank.
func TestStatusFooterUpdate_DoesNotBlockOnSudo(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)

	// Make every probe deliberately slow.
	slowConn := func(string) bool { time.Sleep(100 * time.Millisecond); return false }
	slowFW := func() bool { time.Sleep(100 * time.Millisecond); return false }
	origConn, origFW := isWGConnected, isFirewallActive
	isWGConnected = slowConn
	isFirewallActive = slowFW
	t.Cleanup(func() { isWGConnected = origConn; isFirewallActive = origFW })

	start := time.Now()
	f.Update(StatusUpdateMsg{})
	elapsed := time.Since(start)
	// Update must not have run the slow probes inline; it returns
	// the async tea.Cmd. With probes inline the handler would take
	// >=200ms; threshold deliberately tight.
	if elapsed > 50*time.Millisecond {
		t.Errorf("Update(StatusUpdateMsg) took %v — slow probes leaked into UI goroutine", elapsed)
	}
}

// TestStatusFooterViewNormalDisconnectedKillswitch tests viewNormal when disconnected
// with killswitch active (shows KILLSWITCH label and KS Active on right).
func TestStatusFooterViewNormalDisconnectedKillswitch(t *testing.T) {
	cfg := &config.Config{}
	f := NewStatusFooter(cfg)
	f.connected = false
	f.killswitch = true
	f.width = 120

	view := f.viewNormal()
	if view == "" {
		t.Error("view should not be empty")
	}
}

// TestFormatUptimeNegativeDuration verifies clock skew (NTP step,
// manual `date` change, DST) doesn't produce garbage like "-1h -34m
// -56s" in the dashboard. Negative durations clamp to zero.
func TestFormatUptimeNegativeDuration(t *testing.T) {
	cases := []time.Duration{
		-1 * time.Second,
		-1 * time.Minute,
		-1 * time.Hour,
		-3*time.Hour - 17*time.Minute - 42*time.Second,
		time.Duration(-1<<62), // pathological
	}
	for _, d := range cases {
		got := formatUptime(d)
		if strings.ContainsRune(got, '-') {
			t.Errorf("formatUptime(%v) = %q; contains '-' (negative leaked through clamp)", d, got)
		}
	}
}

// TestFormatUptimePositive sanity-checks the happy path didn't break.
func TestFormatUptimePositive(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{45 * time.Second, "45s"},
		{2*time.Minute + 30*time.Second, "2m 30s"},
		{1*time.Hour + 5*time.Minute + 7*time.Second, "1h 5m 7s"},
	}
	for _, c := range cases {
		if got := formatUptime(c.in); got != c.want {
			t.Errorf("formatUptime(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

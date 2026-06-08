package ui

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/daemon"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/firewall"
	tea "github.com/charmbracelet/bubbletea"
)

// dashTestConfig creates a config saved to a temp HOME so Reload() works.
// The killswitch parameter drives the isFirewallActive test hook so the
// dashboard sees the expected firewall state (config no longer persists it).
func dashTestConfig(t *testing.T, serverName, publicIP string, killswitch bool, connectedSince time.Time) *config.Config {
	t.Helper()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origIsActive := isFirewallActive
	isFirewallActive = func() bool { return killswitch }
	t.Cleanup(func() { isFirewallActive = origIsActive })

	cfg := config.DefaultConfig()
	if err := os.MkdirAll(cfg.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg.ConnectionName = "wg0"
	cfg.LastConnectedServer = serverName
	cfg.LastPublicIP = publicIP
	cfg.ConnectedSince = connectedSince
	cfg.DNSProviders = []string{"1.1.1.1", "9.9.9.9"}
	if err := cfg.Save(); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}
	return cfg
}

func TestNewDashboard(t *testing.T) {
	cfg := &config.Config{}
	d := NewDashboard(cfg)

	if d.cfg != cfg {
		t.Error("cfg not set")
	}
	if d.connected {
		t.Error("should not be connected initially")
	}
	if d.focused {
		t.Error("should not be focused initially")
	}
	if d.leftCol != 0 || d.rightCol != 0 || d.activeCol != 0 {
		t.Error("cursors should start at 0")
	}
}

func TestDashboardSetFocused(t *testing.T) {
	d := NewDashboard(&config.Config{})

	d.SetFocused(true)
	if !d.focused {
		t.Error("should be focused")
	}

	d.SetFocused(false)
	if d.focused {
		t.Error("should be unfocused")
	}
}

func TestDashboardInit(t *testing.T) {
	d := NewDashboard(&config.Config{})
	cmd := d.Init()
	if cmd == nil {
		t.Error("Init should return a batch command")
	}
}

func TestDashboardConnectedView(t *testing.T) {
	mockConnected(t)

	cfg := dashTestConfig(t, "US-NY#42", "98.76.54.32", true, time.Now().Add(-5*time.Minute))
	d := NewDashboard(cfg)
	d.width = 100
	d.height = 40
	d.focused = true

	// Trigger refresh
	d.refresh()

	if !d.connected {
		t.Fatal("should be connected")
	}
	if d.prettyName == "" {
		t.Error("prettyName should be set")
	}
	if d.publicIP != "98.76.54.32" {
		t.Errorf("publicIP = %q, want 98.76.54.32", d.publicIP)
	}
	if !d.killswitch {
		t.Error("killswitch should be true")
	}

	// Simulate daemon health update providing endpoint
	d.applyHealthState(daemon.HealthState{
		Score:    90,
		Grade:    "Excellent",
		Endpoint: "123.45.67.89:51820",
	})
	if d.endpoint == "" {
		t.Error("endpoint should be set from health state")
	}

	view := d.View()
	if view == "" {
		t.Error("connected view should not be empty")
	}
	if !strings.Contains(view, "Connected") {
		t.Error("should contain Connected status")
	}
	if !strings.Contains(view, "Disconnect") {
		t.Error("should contain Disconnect action")
	}
	if !strings.Contains(view, "Speed Test") {
		t.Error("should contain Speed Test action")
	}
}

func TestDashboardDisconnectedView(t *testing.T) {
	mockDisconnected(t)

	cfg := dashTestConfig(t, "US-NY#42", "", false, time.Time{})
	d := NewDashboard(cfg)
	d.width = 100
	d.height = 40
	d.focused = true

	d.refresh()

	if d.connected {
		t.Fatal("should not be connected")
	}

	view := d.View()
	if view == "" {
		t.Error("disconnected view should not be empty")
	}
	if !strings.Contains(view, "Disconnected") {
		t.Error("should contain Disconnected status")
	}
	// Should show Reconnect since lastServer is set
	if !strings.Contains(view, "Reconnect") {
		t.Error("should contain Reconnect action when last server exists")
	}
}

func TestDashboardDisconnectedViewKillswitch(t *testing.T) {
	mockDisconnected(t)

	cfg := dashTestConfig(t, "", "", true, time.Time{})
	d := NewDashboard(cfg)
	d.width = 100
	d.height = 40

	d.refresh()

	view := d.View()
	if !strings.Contains(view, "Killswitch Active") {
		t.Error("should contain Killswitch Active when killswitch is on and disconnected")
	}
}

func TestDashboardDisconnectedNoReconnect(t *testing.T) {
	mockDisconnected(t)

	cfg := dashTestConfig(t, "", "", false, time.Time{})
	d := NewDashboard(cfg)
	d.width = 100
	d.height = 40
	d.focused = true

	d.refresh()

	view := d.View()
	if strings.Contains(view, "Reconnect") {
		t.Error("should not contain Reconnect when no last server")
	}
}

func TestDashboardCursorNavigation(t *testing.T) {
	d := NewDashboard(&config.Config{})
	d.focused = true
	d.connected = true
	d.width = 100
	d.height = 40

	// Test left column
	leftActs := d.leftActions()
	for i := 0; i < len(leftActs)+2; i++ {
		d.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	if d.leftCol >= len(leftActs) {
		t.Errorf("leftCol = %d, should be clamped to %d", d.leftCol, len(leftActs)-1)
	}

	for i := 0; i < len(leftActs)+2; i++ {
		d.Update(tea.KeyMsg{Type: tea.KeyUp})
	}
	if d.leftCol != 0 {
		t.Errorf("leftCol = %d, should be clamped to 0", d.leftCol)
	}

	// Switch to right column
	d.Update(tea.KeyMsg{Type: tea.KeyRight})
	if d.activeCol != 1 {
		t.Error("activeCol should be 1 after right key")
	}

	rightActs := d.rightActions()
	for i := 0; i < len(rightActs)+2; i++ {
		d.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	if d.rightCol >= len(rightActs) {
		t.Errorf("rightCol = %d, should be clamped to %d", d.rightCol, len(rightActs)-1)
	}

	// Switch back to left
	d.Update(tea.KeyMsg{Type: tea.KeyLeft})
	if d.activeCol != 0 {
		t.Error("activeCol should be 0 after left key")
	}
}

func TestDashboardFocusGating(t *testing.T) {
	d := NewDashboard(&config.Config{})
	d.focused = false
	d.connected = true

	// Keys should be ignored when unfocused
	d.Update(tea.KeyMsg{Type: tea.KeyDown})
	if d.leftCol != 0 {
		t.Error("cursor should not move when unfocused")
	}
}

func TestDashboardDisconnectAction(t *testing.T) {
	d := NewDashboard(&config.Config{})
	d.focused = true
	d.connected = true
	d.activeCol = 0
	d.leftCol = 0 // Disconnect is first action when connected

	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("disconnect action should return cmd")
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

func TestDashboardReconnectAction(t *testing.T) {
	cfg := &config.Config{LastConnectedServer: "dynamic:protonvpn:US-NY#42"}
	d := NewDashboard(cfg)
	d.focused = true
	d.connected = false
	d.lastServer = "dynamic:protonvpn:US-NY#42"
	d.activeCol = 0
	d.leftCol = 0 // Reconnect is first when disconnected with lastServer

	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("reconnect action should return cmd")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.View != "connect-progress" {
		t.Errorf("View = %q, want connect-progress", sv.View)
	}
	if sv.Provider != "protonvpn" {
		t.Errorf("Provider = %q, want protonvpn", sv.Provider)
	}
	if sv.Server != "US-NY#42" {
		t.Errorf("Server = %q, want US-NY#42", sv.Server)
	}
	if !sv.Dynamic {
		t.Error("Dynamic should be true")
	}
}

func TestDashboardReconnectStaticServer(t *testing.T) {
	cfg := &config.Config{LastConnectedServer: "US-NY#42"}
	d := NewDashboard(cfg)
	d.focused = true
	d.connected = false
	d.lastServer = "US-NY#42"
	d.activeCol = 0
	d.leftCol = 0

	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("reconnect action should return cmd")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.View != "connect-progress" {
		t.Errorf("View = %q, want connect-progress", sv.View)
	}
	if sv.Server != "US-NY#42" {
		t.Errorf("Server = %q, want US-NY#42", sv.Server)
	}
	if sv.Dynamic {
		t.Error("Dynamic should be false for static server")
	}
}

func TestDashboardCycleSettings(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	cfg := config.DefaultConfig()
	cfg.BandwidthDisplay = "text"
	cfg.BandwidthUnit = "bits"
	cfg.BandwidthTotal = false
	cfg.Save()

	d := NewDashboard(cfg)
	d.focused = true
	d.connected = true
	d.activeCol = 1 // Right column for settings

	// Find bw-style action index in right column
	bwStyleIdx := findDashActionRight(d, "bw-style")
	bwUnitIdx := findDashActionRight(d, "bw-unit")
	bwTotalIdx := findDashActionRight(d, "bw-total")

	// Cycle bandwidth style: sparkline ↔ bar
	d.rightCol = bwStyleIdx
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if d.cfg.BandwidthDisplay != "bar" {
		t.Errorf("BandwidthDisplay = %q, want bar", d.cfg.BandwidthDisplay)
	}
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if d.cfg.BandwidthDisplay != "sparkline" {
		t.Errorf("BandwidthDisplay = %q, want sparkline", d.cfg.BandwidthDisplay)
	}

	// Toggle bandwidth unit: bits → bytes → bits
	d.rightCol = bwUnitIdx
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if d.cfg.BandwidthUnit != "bytes" {
		t.Errorf("BandwidthUnit = %q, want bytes", d.cfg.BandwidthUnit)
	}
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if d.cfg.BandwidthUnit != "bits" {
		t.Errorf("BandwidthUnit = %q, want bits", d.cfg.BandwidthUnit)
	}

	// Toggle session total: OFF → ON → OFF
	d.rightCol = bwTotalIdx
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !d.cfg.BandwidthTotal {
		t.Error("BandwidthTotal should be true after toggle")
	}
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if d.cfg.BandwidthTotal {
		t.Error("BandwidthTotal should be false after second toggle")
	}
}

func TestDashboardHealthFromDaemon(t *testing.T) {
	tests := []struct {
		name      string
		score     int
		grade     string
		wantGrade string
	}{
		{"excellent", 95, "Excellent", "Excellent"},
		{"good", 82, "Good", "Good"},
		{"fair", 72, "Fair", "Fair"},
		{"poor", 62, "Poor", "Poor"},
		{"bad", 30, "Bad", "Bad"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDashboard(&config.Config{})
			d.health = &daemon.HealthState{
				Score: tt.score,
				Grade: tt.grade,
			}
			if d.health.Score != tt.score {
				t.Errorf("health.Score = %d, want %d", d.health.Score, tt.score)
			}
			if d.health.Grade != tt.wantGrade {
				t.Errorf("health.Grade = %q, want %q", d.health.Grade, tt.wantGrade)
			}
		})
	}
}

func TestDashboardHealthDetail(t *testing.T) {
	d := NewDashboard(&config.Config{})
	d.connected = true
	d.focused = true
	d.width = 100
	d.height = 40
	d.health = &daemon.HealthState{
		Score:           90,
		Grade:           "Excellent",
		HandshakeScore:  100,
		DNSScore:        100,
		LatencyScore:    100,
		PacketLossScore: 100,
		HandshakeAgeSec: 30,
		LatencyMs:       45,
	}

	// Health detail should be hidden initially
	d.showHealthDetail = false
	view1 := d.View()
	if strings.Contains(view1, "Handshake:") {
		t.Error("should not show health detail when showHealthDetail is false")
	}

	// Enable detail
	d.showHealthDetail = true
	view2 := d.View()
	if !strings.Contains(view2, "Handshake:") {
		t.Error("should show handshake detail when showHealthDetail is true")
	}
	if !strings.Contains(view2, "DNS:") {
		t.Error("should show DNS detail")
	}
	if !strings.Contains(view2, "Latency:") {
		t.Error("should show latency detail")
	}
	if !strings.Contains(view2, "Packet loss:") {
		t.Error("should show packet loss detail")
	}
}

func TestDashboardStatusUpdate(t *testing.T) {
	mockConnected(t)

	cfg := dashTestConfig(t, "US-NY#42", "10.0.0.1", false, time.Now().Add(-2*time.Minute))
	d := NewDashboard(cfg)
	d.width = 100
	d.height = 40

	// StatusUpdateMsg is now async — it returns a tea.Cmd that runs the
	// slow probes off-goroutine. We have to drive the result message
	// back through Update for the cached fields to update.
	result, cmd := d.Update(StatusUpdateMsg{})
	d = result.(*Dashboard)
	if cmd == nil {
		t.Fatal("Update(StatusUpdateMsg) should return an async cmd")
	}
	snap := cmd()
	if _, ok := snap.(dashboardRefreshResultMsg); !ok {
		t.Fatalf("expected dashboardRefreshResultMsg, got %T", snap)
	}
	result, _ = d.Update(snap)
	d = result.(*Dashboard)

	if !d.connected {
		t.Error("should be connected after StatusUpdateMsg → result dispatch")
	}
	if d.prettyName == "" {
		t.Error("prettyName should be set")
	}
}

// TestDashboardStatusUpdate_DoesNotBlockOnSudo verifies the every-1s
// StatusUpdateMsg handler doesn't run isFirewallActive (sudo
// subprocess) and friends inline. Pre-fix, every tick burned ~400ms
// on the UI goroutine for the four firewall probes.
func TestDashboardStatusUpdate_DoesNotBlockOnSudo(t *testing.T) {
	mockConnected(t)

	cfg := dashTestConfig(t, "US-NY#42", "10.0.0.1", false, time.Now())
	d := NewDashboard(cfg)

	// Make every probe deliberately slow.
	slowProbe := func() bool { time.Sleep(100 * time.Millisecond); return false }
	slowConn := func(string) bool { time.Sleep(100 * time.Millisecond); return false }
	origActive, origLB, origSt, origV6 := isFirewallActive, firewallIsLANBlockActive, firewallIsLANStealthActive, firewallIsIPv6Disabled
	origConn := isWGConnected
	isFirewallActive = slowProbe
	firewallIsLANBlockActive = slowProbe
	firewallIsLANStealthActive = slowProbe
	firewallIsIPv6Disabled = slowProbe
	isWGConnected = slowConn
	t.Cleanup(func() {
		isFirewallActive = origActive
		firewallIsLANBlockActive = origLB
		firewallIsLANStealthActive = origSt
		firewallIsIPv6Disabled = origV6
		isWGConnected = origConn
	})

	start := time.Now()
	d.Update(StatusUpdateMsg{})
	elapsed := time.Since(start)
	// Update must just snapshot cfg fields and return the async cmd.
	// Five probes inline would take >=500ms; threshold deliberately tight.
	if elapsed > 50*time.Millisecond {
		t.Errorf("Update(StatusUpdateMsg) took %v — slow probes leaked into UI goroutine", elapsed)
	}
}

func TestDashboardWindowSizeMsg(t *testing.T) {
	d := NewDashboard(&config.Config{})

	result, _ := d.Update(tea.WindowSizeMsg{Width: 120, Height: 50})
	d = result.(*Dashboard)

	if d.width != 120 {
		t.Errorf("width = %d, want 120", d.width)
	}
	if d.height != 50 {
		t.Errorf("height = %d, want 50", d.height)
	}
}

func TestDashboardDaemonHealthMsg(t *testing.T) {
	d := NewDashboard(&config.Config{})
	d.connected = true

	hs := daemon.HealthState{
		Score:           85,
		Grade:           "Good",
		HandshakeScore:  100,
		DNSScore:        100,
		LatencyScore:    80,
		PacketLossScore: 60,
		LatencyMs:       120,
		RxBytes:         5000,
		TxBytes:         2000,
		StatsTimestamp:  time.Now(),
	}

	result, _ := d.Update(DaemonHealthMsg{Health: hs})
	d = result.(*Dashboard)

	if d.health == nil {
		t.Fatal("health should be set after DaemonHealthMsg")
	}
	if d.health.Score != 85 {
		t.Errorf("health.Score = %d, want 85", d.health.Score)
	}
	if d.health.Grade != "Good" {
		t.Errorf("health.Grade = %q, want Good", d.health.Grade)
	}
}

func TestDashboardDaemonDisconnectedMsg(t *testing.T) {
	d := NewDashboard(&config.Config{})
	d.connected = true

	result, cmd := d.Update(DaemonDisconnectedMsg{Err: nil})
	d = result.(*Dashboard)
	_ = d

	// Should return a retry command
	if cmd == nil {
		t.Error("DaemonDisconnectedMsg should return a retry command")
	}
}

func TestDashboardActionsConnected(t *testing.T) {
	d := NewDashboard(&config.Config{})
	d.connected = true

	left := d.leftActions()
	// disconnect + speedtest + leaktest + audit = 4
	if len(left) != 4 {
		t.Errorf("connected left actions = %d, want 4", len(left))
	}
	if left[0].id != "disconnect" {
		t.Errorf("first left action = %q, want disconnect", left[0].id)
	}

	right := d.rightActions()
	// killswitch + ks-disconnect + ipv6 + local-network + dns-providers + bw-style + bw-unit + bw-total + reset-baseline = 9
	if len(right) != 9 {
		t.Errorf("connected right actions = %d, want 9", len(right))
	}
	if right[0].id != "killswitch" {
		t.Errorf("first right action = %q, want killswitch", right[0].id)
	}
}

func TestDashboardActionsDisconnectedWithServer(t *testing.T) {
	d := NewDashboard(&config.Config{})
	d.connected = false
	d.lastServer = "US-NY#42"

	left := d.leftActions()
	// reconnect + leaktest + audit = 3
	if len(left) != 3 {
		t.Errorf("disconnected with server left actions = %d, want 3", len(left))
	}
	if left[0].id != "reconnect" {
		t.Errorf("first left action = %q, want reconnect", left[0].id)
	}

	right := d.rightActions()
	if len(right) != 9 {
		t.Errorf("disconnected right actions = %d, want 9", len(right))
	}
}

func TestDashboardActionsDisconnectedNoServer(t *testing.T) {
	d := NewDashboard(&config.Config{})
	d.connected = false
	d.lastServer = ""

	left := d.leftActions()
	// leaktest + audit = 2
	if len(left) != 2 {
		t.Errorf("disconnected no server left actions = %d, want 2", len(left))
	}
	if left[0].id != "leaktest" {
		t.Errorf("first left action = %q, want leaktest", left[0].id)
	}

	right := d.rightActions()
	if len(right) != 9 {
		t.Errorf("disconnected no server right actions = %d, want 9", len(right))
	}
}

func TestDashboardSpeedtestAction(t *testing.T) {
	d := NewDashboard(&config.Config{})
	d.focused = true
	d.connected = true
	d.activeCol = 0
	d.leftCol = 1 // Speed Test

	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("speedtest should return cmd")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.View != "speedtest" {
		t.Errorf("View = %q, want speedtest", sv.View)
	}
}

func TestDashboardLeaktestAction(t *testing.T) {
	d := NewDashboard(&config.Config{})
	d.focused = true
	d.connected = true
	d.activeCol = 0
	d.leftCol = 2 // Leak Test

	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("leaktest should return cmd")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.View != "leaktest" {
		t.Errorf("View = %q, want leaktest", sv.View)
	}
}

func TestDashboardAuditAction(t *testing.T) {
	d := NewDashboard(&config.Config{})
	d.focused = true
	d.connected = true
	d.activeCol = 0
	d.leftCol = 3 // Security Audit

	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("audit should return cmd")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.View != "audit" {
		t.Errorf("View = %q, want audit", sv.View)
	}
}

func TestDashboardApplyHealthState(t *testing.T) {
	d := NewDashboard(&config.Config{BandwidthUnit: "bits"})
	d.connected = true

	// First snapshot establishes baseline
	hs1 := daemon.HealthState{
		Score:          90,
		Grade:          "Excellent",
		RxBytes:        1000,
		TxBytes:        500,
		StatsTimestamp: time.Now().Add(-3 * time.Second),
	}
	d.applyHealthState(hs1)
	if d.health == nil {
		t.Fatal("health should be set")
	}
	if d.health.Score != 90 {
		t.Errorf("health.Score = %d, want 90", d.health.Score)
	}

	// Second snapshot computes bandwidth rate
	hs2 := daemon.HealthState{
		Score:          85,
		Grade:          "Good",
		RxBytes:        4000,
		TxBytes:        2000,
		StatsTimestamp: time.Now(),
	}
	d.applyHealthState(hs2)
	if d.rxSpeed == "" {
		t.Error("rxSpeed should be set after second snapshot")
	}
	if d.txSpeed == "" {
		t.Error("txSpeed should be set after second snapshot")
	}
}

// TestDashboardApplyHealthState_CounterRollback verifies that when
// the kernel interface counters drop below the established baseline
// (interface recreated by a server switch the TUI didn't otherwise
// observe), applyHealthState rebases to the new value rather than
// freezing rxTotal/txTotal at the old interface's last value.
func TestDashboardApplyHealthState_CounterRollback(t *testing.T) {
	d := NewDashboard(&config.Config{BandwidthUnit: "bits"})
	d.connected = true

	// Establish baseline at 1000/500.
	d.applyHealthState(daemon.HealthState{
		RxBytes: 1000, TxBytes: 500,
		StatsTimestamp: time.Now().Add(-5 * time.Second),
	})
	// Accumulate to 4000/2000 — totals should now be 3000/1500.
	d.applyHealthState(daemon.HealthState{
		RxBytes: 4000, TxBytes: 2000,
		StatsTimestamp: time.Now().Add(-3 * time.Second),
	})
	if d.rxTotal != 3000 || d.txTotal != 1500 {
		t.Fatalf("pre-rollback rxTotal/txTotal = %d/%d, want 3000/1500", d.rxTotal, d.txTotal)
	}

	// Counter rolls back (interface recreated): rx=10, tx=5.
	d.applyHealthState(daemon.HealthState{
		RxBytes: 10, TxBytes: 5,
		StatsTimestamp: time.Now().Add(-1 * time.Second),
	})
	// After rebase, totals must be zero — the new baseline IS rx=10/tx=5.
	if d.rxTotal != 0 || d.txTotal != 0 {
		t.Errorf("post-rollback rxTotal/txTotal = %d/%d, want 0/0 (rebased)", d.rxTotal, d.txTotal)
	}

	// Next snapshot at rx=100/tx=50: totals should be 90/45 (relative to
	// new baseline), proving the rebase took.
	d.applyHealthState(daemon.HealthState{
		RxBytes: 100, TxBytes: 50,
		StatsTimestamp: time.Now(),
	})
	if d.rxTotal != 90 || d.txTotal != 45 {
		t.Errorf("after rebase, rxTotal/txTotal = %d/%d, want 90/45", d.rxTotal, d.txTotal)
	}
}

// TestDashboardApplyHealthState_CounterRollback_ClearsHistoryAndSpeed
// verifies that on a counter rollback (interface recreated mid-session),
// applyHealthState clears not only the totals but also the rate-display
// strings, current-rate floats, and rate history ring buffer.
//
// Pre-fix the inline rebase only cleared hasBase / lastStats / rxTotal /
// txTotal — leaving rxSpeed / txSpeed (display labels), rxRate / txRate,
// and the rxHistory / txHistory buffer with rate values from the OLD
// interface. Sparklines and bandwidth bars would briefly show stale
// rate data mixed with new values until the 8-tick history filled.
func TestDashboardApplyHealthState_CounterRollback_ClearsHistoryAndSpeed(t *testing.T) {
	d := NewDashboard(&config.Config{BandwidthUnit: "bits"})
	d.connected = true

	// Build up some history by ticking through several health states
	// with monotonically increasing counters. After 3 ticks the rate
	// is computed twice, so histCount goes from 0 → 1 → 2.
	d.applyHealthState(daemon.HealthState{
		RxBytes: 1000, TxBytes: 500,
		StatsTimestamp: time.Now().Add(-9 * time.Second),
	})
	d.applyHealthState(daemon.HealthState{
		RxBytes: 4000, TxBytes: 2000,
		StatsTimestamp: time.Now().Add(-6 * time.Second),
	})
	d.applyHealthState(daemon.HealthState{
		RxBytes: 9000, TxBytes: 5000,
		StatsTimestamp: time.Now().Add(-3 * time.Second),
	})
	if d.histCount == 0 {
		t.Fatalf("setup: expected non-zero histCount, got %d", d.histCount)
	}
	if d.rxSpeed == "" {
		t.Fatalf("setup: expected non-empty rxSpeed, got %q", d.rxSpeed)
	}

	// Counter rollback: interface recreated, kernel counters reset.
	d.applyHealthState(daemon.HealthState{
		RxBytes: 10, TxBytes: 5,
		StatsTimestamp: time.Now(),
	})

	// Speed display strings must clear — they were computed against the
	// old interface's rates.
	if d.rxSpeed != "" {
		t.Errorf("rxSpeed = %q, want empty after rollback (stale display string)", d.rxSpeed)
	}
	if d.txSpeed != "" {
		t.Errorf("txSpeed = %q, want empty after rollback", d.txSpeed)
	}
	// Rate floats must clear — feed sparkline / bar rendering.
	if d.rxRate != 0 {
		t.Errorf("rxRate = %v, want 0 after rollback", d.rxRate)
	}
	if d.txRate != 0 {
		t.Errorf("txRate = %v, want 0 after rollback", d.txRate)
	}
	// History ring buffer must clear — sparklines would otherwise mix
	// old-interface samples with new ones.
	if d.histCount != 0 {
		t.Errorf("histCount = %d, want 0 after rollback (stale history values)", d.histCount)
	}
	if d.histIdx != 0 {
		t.Errorf("histIdx = %d, want 0 after rollback", d.histIdx)
	}
}

// TestDashboardEventSwitching_ResetsBandwidth verifies the TUI clears
// bandwidth state on EventSwitching so the brief gap between switching
// and EventConnected doesn't leave stale totals on screen.
func TestDashboardEventSwitching_ResetsBandwidth(t *testing.T) {
	d := NewDashboard(&config.Config{BandwidthUnit: "bits"})
	d.connected = true
	// Establish some totals first.
	d.applyHealthState(daemon.HealthState{
		RxBytes: 1000, TxBytes: 500,
		StatsTimestamp: time.Now().Add(-5 * time.Second),
	})
	d.applyHealthState(daemon.HealthState{
		RxBytes: 4000, TxBytes: 2000,
		StatsTimestamp: time.Now().Add(-3 * time.Second),
	})
	if d.rxTotal == 0 && d.txTotal == 0 {
		t.Fatal("setup: expected non-zero totals before switch")
	}

	// EventSwitching arrives.
	d.applyDaemonEvent(daemon.Event{Type: daemon.EventSwitching})

	if d.rxTotal != 0 || d.txTotal != 0 {
		t.Errorf("after EventSwitching, rxTotal/txTotal = %d/%d, want 0/0", d.rxTotal, d.txTotal)
	}
	if d.hasBase {
		t.Error("after EventSwitching, hasBase should be false (baseline cleared)")
	}
}

// TestDashboardEventReconnected_UpdatesPublicIPAndResetsBandwidth
// verifies that EventReconnected (broadcast by attemptRecovery on
// success) is handled the same way as EventConnected: PublicIP
// updated from the event payload, bandwidth state reset for the
// fresh interface, connected flag set true.
//
// Pre-fix the applyDaemonEvent switch had no case for EventReconnected,
// so the dashboard's d.publicIP showed the OLD IP from before recovery
// until the next StatusUpdateMsg arrived, and the bandwidth totals
// stayed stale for one health tick (until the counter-rollback rebase
// from 7bbe122 caught the kernel counter reset).
func TestDashboardEventReconnected_UpdatesPublicIPAndResetsBandwidth(t *testing.T) {
	d := NewDashboard(&config.Config{BandwidthUnit: "bits"})
	d.connected = true
	d.publicIP = "1.1.1.1" // pre-recovery IP

	// Establish bandwidth state.
	d.applyHealthState(daemon.HealthState{
		RxBytes: 1000, TxBytes: 500,
		StatsTimestamp: time.Now().Add(-5 * time.Second),
	})
	d.applyHealthState(daemon.HealthState{
		RxBytes: 4000, TxBytes: 2000,
		StatsTimestamp: time.Now().Add(-3 * time.Second),
	})
	if d.rxTotal == 0 && d.txTotal == 0 {
		t.Fatal("setup: expected non-zero totals before EventReconnected")
	}

	// EventReconnected with a new public IP.
	d.applyDaemonEvent(daemon.Event{
		Type:     daemon.EventReconnected,
		PublicIP: "2.2.2.2",
	})

	if d.publicIP != "2.2.2.2" {
		t.Errorf("publicIP = %q, want %q (EventReconnected payload not applied)",
			d.publicIP, "2.2.2.2")
	}
	if !d.connected {
		t.Error("connected should stay true after EventReconnected")
	}
	if d.rxTotal != 0 || d.txTotal != 0 {
		t.Errorf("after EventReconnected, rxTotal/txTotal = %d/%d, want 0/0",
			d.rxTotal, d.txTotal)
	}
	if d.hasBase {
		t.Error("after EventReconnected, hasBase should be false (baseline cleared for new interface)")
	}
}

// TestDashboardEventFailed_ClearsConnected verifies that EventFailed
// (and EventSwitchFailed) flip d.connected to false. The daemon
// broadcasts these when attemptRecovery exhausts retries. Pre-fix
// the cases fell through and d.connected stayed at whatever it was
// — leaving the dashboard header showing "Connected" while the
// tunnel is actually dead.
func TestDashboardEventFailed_ClearsConnected(t *testing.T) {
	for _, evtType := range []daemon.EventType{
		daemon.EventFailed,
		daemon.EventSwitchFailed,
	} {
		t.Run(string(evtType), func(t *testing.T) {
			d := NewDashboard(&config.Config{BandwidthUnit: "bits"})
			d.connected = true
			// Seed bandwidth state so we can verify it's cleared too.
			d.applyHealthState(daemon.HealthState{
				RxBytes: 1000, TxBytes: 500,
				StatsTimestamp: time.Now().Add(-3 * time.Second),
			})

			d.applyDaemonEvent(daemon.Event{Type: evtType})

			if d.connected {
				t.Errorf("after %s, d.connected should be false (tunnel is dead, even if interface lingers)", evtType)
			}
			if d.rxTotal != 0 || d.txTotal != 0 {
				t.Errorf("after %s, rxTotal/txTotal = %d/%d, want 0/0", evtType, d.rxTotal, d.txTotal)
			}
		})
	}
}

func TestDashboardRefreshDynamic(t *testing.T) {
	mockConnected(t)

	cfg := dashTestConfig(t, "dynamic:protonvpn:US-NY#42", "10.0.0.1", false, time.Now())
	d := NewDashboard(cfg)

	d.refresh()

	if !d.connected {
		t.Error("should be connected")
	}
	if d.prettyName == "" {
		t.Error("prettyName should not be empty for dynamic server")
	}
	if d.lastServer != "dynamic:protonvpn:US-NY#42" {
		t.Errorf("lastServer = %q, want dynamic:protonvpn:US-NY#42", d.lastServer)
	}
}

func TestDashboardRefreshDisconnectedClamsCursor(t *testing.T) {
	mockDisconnected(t)

	cfg := dashTestConfig(t, "", "", false, time.Time{})
	d := NewDashboard(cfg)
	d.connected = true
	d.leftCol = 6 // Was on last connected action

	d.refresh()

	left := d.leftActions()
	if d.leftCol >= len(left) {
		t.Errorf("leftCol = %d, should be clamped to < %d", d.leftCol, len(left))
	}
}

func TestDashboardOnOffLabel(t *testing.T) {
	if onOffLabel(true) != "ON" {
		t.Error("true should be ON")
	}
	if onOffLabel(false) != "OFF" {
		t.Error("false should be OFF")
	}
}

func TestDashboardBuildSparklineEmpty(t *testing.T) {
	d := NewDashboard(&config.Config{})
	spark := d.buildSparkline(d.rxHistory[:], 0, 0, ColorAccent)
	if spark == "" {
		t.Error("sparkline should not be empty even with no data")
	}
}

func TestDashboardBuildSparklineWithData(t *testing.T) {
	d := NewDashboard(&config.Config{})
	for i := 0; i < 8; i++ {
		d.rxHistory[i] = float64(i * 1000)
	}
	spark := d.buildSparkline(d.rxHistory[:], 8, 0, ColorAccent)
	if spark == "" {
		t.Error("sparkline should not be empty with data")
	}
}

func TestDashboardBuildBar(t *testing.T) {
	d := NewDashboard(&config.Config{})
	for i := 0; i < 8; i++ {
		d.rxHistory[i] = 1000
	}
	bar := d.buildBar(1000, d.rxHistory[:], 8, ColorAccent)
	if bar == "" {
		t.Error("bar should not be empty")
	}
}

func TestDashboardBuildBarNoMax(t *testing.T) {
	d := NewDashboard(&config.Config{})
	bar := d.buildBar(0, d.rxHistory[:], 0, ColorAccent)
	if bar == "" {
		t.Error("bar should not be empty even with zero values")
	}
}

func TestDashboardViewConnectedWithBandwidth(t *testing.T) {
	d := NewDashboard(&config.Config{BandwidthDisplay: "sparkline", BandwidthTotal: true})
	d.connected = true
	d.focused = true
	d.width = 100
	d.height = 40
	d.prettyName = "US - NY #42"
	d.rxSpeed = "12.4 Mbps"
	d.txSpeed = "3.1 Mbps"
	d.rxTotal = 1234567890
	d.txTotal = 345678901
	d.histCount = 4
	d.health = &daemon.HealthState{Score: 85, Grade: "Good"}

	view := d.View()
	if !strings.Contains(view, "12.4 Mbps") {
		t.Error("should show rx speed")
	}
	if !strings.Contains(view, "3.1 Mbps") {
		t.Error("should show tx speed")
	}
	if !strings.Contains(view, "Session:") {
		t.Error("should show session total when BandwidthTotal is true")
	}
}

func TestDashboardViewConnectedBarMode(t *testing.T) {
	d := NewDashboard(&config.Config{BandwidthDisplay: "bar"})
	d.connected = true
	d.width = 100
	d.height = 40
	d.rxSpeed = "5.0 Mbps"
	d.txSpeed = "1.0 Mbps"
	d.histCount = 4

	view := d.View()
	if view == "" {
		t.Error("bar mode view should not be empty")
	}
}

func TestDashboardViewConnectedTextMode(t *testing.T) {
	d := NewDashboard(&config.Config{BandwidthDisplay: "text"})
	d.connected = true
	d.width = 100
	d.height = 40
	d.rxSpeed = "5.0 Mbps"
	d.txSpeed = "1.0 Mbps"

	view := d.View()
	if view == "" {
		t.Error("text mode view should not be empty")
	}
}

func TestDashboardFormatSpeed(t *testing.T) {
	d := NewDashboard(&config.Config{BandwidthUnit: "bytes"})
	s := d.formatSpeed(1000)
	if s == "" {
		t.Error("speed should not be empty")
	}

	d.cfg.BandwidthUnit = "bits"
	s = d.formatSpeed(1000)
	if s == "" {
		t.Error("speed should not be empty for bits")
	}
}

// newTestDashboard creates a Dashboard with a temp config dir and stubs.
func newTestDashboard(t *testing.T) *Dashboard {
	t.Helper()
	stubFirewall(t)
	stubNotifications(t)
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	cfg := config.DefaultConfig()
	if err := os.MkdirAll(cfg.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg.Save()
	return NewDashboard(cfg)
}

// findDashActionRight returns the index of the action with the given id in the right column.
func findDashActionRight(d *Dashboard, id string) int {
	for i, a := range d.rightActions() {
		if a.id == id {
			return i
		}
	}
	return -1
}

func TestDashboardLeftRightColumnSwitch(t *testing.T) {
	d := newTestDashboard(t)
	d.focused = true
	d.connected = true
	d.width = 100
	d.height = 40

	// Start in left column
	if d.activeCol != 0 {
		t.Fatal("should start in left column")
	}

	// Move down in left column
	d.Update(tea.KeyMsg{Type: tea.KeyDown})
	if d.leftCol != 1 {
		t.Errorf("leftCol = %d, want 1", d.leftCol)
	}

	// Switch to right column
	d.Update(tea.KeyMsg{Type: tea.KeyRight})
	if d.activeCol != 1 {
		t.Error("should be in right column after right key")
	}
	if d.rightCol != 0 {
		t.Errorf("rightCol = %d, want 0 (independent cursor)", d.rightCol)
	}

	// Left column cursor should be preserved
	if d.leftCol != 1 {
		t.Errorf("leftCol = %d, want 1 (should be preserved)", d.leftCol)
	}

	// Move down in right column
	d.Update(tea.KeyMsg{Type: tea.KeyDown})
	if d.rightCol != 1 {
		t.Errorf("rightCol = %d, want 1", d.rightCol)
	}

	// Switch back to left
	d.Update(tea.KeyMsg{Type: tea.KeyLeft})
	if d.activeCol != 0 {
		t.Error("should be in left column after left key")
	}
	if d.leftCol != 1 {
		t.Errorf("leftCol = %d, want 1 (preserved from before)", d.leftCol)
	}

	// Left at leftmost should not change
	d.activeCol = 0
	d.Update(tea.KeyMsg{Type: tea.KeyLeft})
	if d.activeCol != 0 {
		t.Error("should stay in left column when already left")
	}

	// Right at rightmost should not change
	d.activeCol = 1
	d.Update(tea.KeyMsg{Type: tea.KeyRight})
	if d.activeCol != 1 {
		t.Error("should stay in right column when already right")
	}
}

// drainFirewallCmd executes the tea.Cmd returned by a toggle handler, then
// feeds the resulting FirewallResultMsg back into the dashboard's Update.
func drainFirewallCmd(t *testing.T, d *Dashboard, cmd tea.Cmd) {
	t.Helper()
	if cmd == nil {
		return
	}
	msg := cmd()
	if msg == nil {
		return
	}
	d.Update(msg)
}

// statefulFirewallMock wires firewallEnable/EnableSimple/Disable and
// isFirewallActive against a shared bool, so tests that drive toggles see
// refresh() report the post-op firewall state (the authoritative source)
// consistently. Returns the stateful bool pointer for assertions.
func statefulFirewallMock(t *testing.T) *bool {
	t.Helper()
	active := false
	origIsActive := isFirewallActive
	origEnable := firewallEnable
	origEnableSimple := firewallEnableSimple
	origDisable := firewallDisable
	isFirewallActive = func() bool { return active }
	firewallEnable = func(cfg *firewall.KillswitchConfig) error { active = true; return nil }
	firewallEnableSimple = func() error { active = true; return nil }
	firewallDisable = func() error { active = false; return nil }
	t.Cleanup(func() {
		isFirewallActive = origIsActive
		firewallEnable = origEnable
		firewallEnableSimple = origEnableSimple
		firewallDisable = origDisable
	})
	return &active
}

func TestDashboardKillswitchToggle(t *testing.T) {
	d := newTestDashboard(t)
	statefulFirewallMock(t) // must be AFTER newTestDashboard (stubFirewall would overwrite)
	d.focused = true
	d.connected = false
	d.activeCol = 1

	idx := findDashActionRight(d, "killswitch")
	if idx < 0 {
		t.Fatal("killswitch action not found")
	}
	d.rightCol = idx

	// Toggle ON (disconnected → EnableSimple)
	d.killswitch = false
	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if !d.killswitch {
		t.Error("Killswitch should be ON after toggle")
	}

	// Toggle OFF
	_, cmd = d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if d.killswitch {
		t.Error("Killswitch should be OFF after second toggle")
	}
}

func TestDashboardKillswitchToggleConnected(t *testing.T) {
	mockConnected(t)
	d := newTestDashboard(t)
	d.focused = true
	d.connected = true
	d.activeCol = 1
	d.cfg.LastConnectedServer = "US-NY#42"

	// Stateful mock so isFirewallActive reflects post-toggle firewall state,
	// and override firewallEnable to also flip a "called" flag for assertion.
	active := statefulFirewallMock(t)
	called := false
	origEnable := firewallEnable
	firewallEnable = func(cfg *firewall.KillswitchConfig) error {
		called = true
		*active = true
		return nil
	}
	t.Cleanup(func() { firewallEnable = origEnable })

	idx := findDashActionRight(d, "killswitch")
	d.rightCol = idx
	d.killswitch = false
	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if !d.killswitch {
		t.Error("Killswitch should be ON")
	}
	if !called {
		t.Error("firewallEnable should have been called for connected state")
	}
}

// TestDashboardFirewallReconcile verifies that the 60s reconciliation tick
// corrects cached display values for all four firewall-derived states
// (killswitch, LAN block, LAN stealth, IPv6 protection) when they drift
// from UFW. The reconcile pipeline is now async: firewallReconcileMsg
// triggers a background read, which produces firewallReconcileResultMsg,
// which actually mutates the cached fields. Tests drive both halves.
func TestDashboardFirewallReconcile(t *testing.T) {
	d := newTestDashboard(t)
	active := statefulFirewallMock(t)

	// driveReconcile fires firewallReconcileMsg, executes the async
	// read it returns, then dispatches the resulting snapshot back.
	driveReconcile := func() {
		_, batch := d.Update(firewallReconcileMsg{})
		if batch == nil {
			t.Fatal("reconcile handler should return a tea.Cmd batch")
		}
		// tea.Batch executes its children concurrently and surfaces
		// each child's Msg. We only need the firewallReconcileResultMsg.
		// In tests, calling the cmd returns one msg — for tea.Batch
		// it's a tea.BatchMsg containing the children. For simplicity,
		// call readFirewallStateAsync directly and dispatch its result.
		snap := readFirewallStateAsync()()
		if _, ok := snap.(firewallReconcileResultMsg); !ok {
			t.Fatalf("expected firewallReconcileResultMsg, got %T", snap)
		}
		d.Update(snap)
	}

	// --- Killswitch ---
	// Cached shows OFF, actual UFW shows ON — simulate outside-lazyvpn enable.
	d.killswitch = false
	*active = true
	driveReconcile()
	if !d.killswitch {
		t.Error("reconcile should set cached killswitch to match firewall (true)")
	}

	// And the reverse: cached ON, actual UFW OFF.
	d.killswitch = true
	*active = false
	driveReconcile()
	if d.killswitch {
		t.Error("reconcile should set cached killswitch to match firewall (false)")
	}

	// --- LAN block drift ---
	lanActive := false
	origLAN := firewallIsLANBlockActive
	firewallIsLANBlockActive = func() bool { return lanActive }
	t.Cleanup(func() { firewallIsLANBlockActive = origLAN })

	d.lanBlock = false
	lanActive = true
	driveReconcile()
	if !d.lanBlock {
		t.Error("reconcile should set cached lanBlock to match firewall (true)")
	}

	// --- LAN stealth drift ---
	stealthActive := false
	origStealth := firewallIsLANStealthActive
	firewallIsLANStealthActive = func() bool { return stealthActive }
	t.Cleanup(func() { firewallIsLANStealthActive = origStealth })

	d.stealthMode = false
	stealthActive = true
	driveReconcile()
	if !d.stealthMode {
		t.Error("reconcile should set cached stealthMode to match firewall (true)")
	}

	// --- IPv6 protection drift ---
	v6Disabled := false
	origV6 := firewallIsIPv6Disabled
	firewallIsIPv6Disabled = func() bool { return v6Disabled }
	t.Cleanup(func() { firewallIsIPv6Disabled = origV6 })

	d.ipv6Disabled = false
	v6Disabled = true
	driveReconcile()
	if !d.ipv6Disabled {
		t.Error("reconcile should set cached ipv6Disabled to match firewall (true)")
	}
}

// TestDashboardFirewallReconcile_DoesNotBlockUI verifies the slow
// `sudo ufw` reads happen in the background goroutine, not inline in
// Update. Without this fix Update could block for ~400ms every 60s.
func TestDashboardFirewallReconcile_DoesNotBlockUI(t *testing.T) {
	d := newTestDashboard(t)
	statefulFirewallMock(t)

	// Make every firewall probe deliberately slow to simulate a wedged
	// sudo. If the UI handler did the reads inline, Update would block.
	slowProbe := func() bool {
		time.Sleep(100 * time.Millisecond)
		return false
	}
	origActive, origLB, origSt, origV6 := isFirewallActive, firewallIsLANBlockActive, firewallIsLANStealthActive, firewallIsIPv6Disabled
	isFirewallActive = slowProbe
	firewallIsLANBlockActive = slowProbe
	firewallIsLANStealthActive = slowProbe
	firewallIsIPv6Disabled = slowProbe
	t.Cleanup(func() {
		isFirewallActive = origActive
		firewallIsLANBlockActive = origLB
		firewallIsLANStealthActive = origSt
		firewallIsIPv6Disabled = origV6
	})

	start := time.Now()
	d.Update(firewallReconcileMsg{})
	elapsed := time.Since(start)
	// Update itself must NOT have run the slow probes inline; it should
	// just return the async tea.Cmd. With 4×100ms probes inline the
	// handler would take >=400ms; threshold deliberately tight.
	if elapsed > 50*time.Millisecond {
		t.Errorf("Update(firewallReconcileMsg) took %v — slow probes leaked into UI goroutine", elapsed)
	}
}

func TestDashboardKSDisconnectCycle(t *testing.T) {
	d := newTestDashboard(t)
	d.focused = true
	d.connected = true
	d.activeCol = 1

	idx := findDashActionRight(d, "ks-disconnect")
	if idx < 0 {
		t.Fatal("ks-disconnect action not found")
	}
	d.rightCol = idx

	d.cfg.KillswitchAutoDisable = "true"
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if d.cfg.KillswitchAutoDisable != "false" {
		t.Errorf("expected 'false', got %q", d.cfg.KillswitchAutoDisable)
	}

	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if d.cfg.KillswitchAutoDisable != "never" {
		t.Errorf("expected 'never', got %q", d.cfg.KillswitchAutoDisable)
	}

	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if d.cfg.KillswitchAutoDisable != "true" {
		t.Errorf("expected 'true', got %q", d.cfg.KillswitchAutoDisable)
	}
}

// statefulIPv6Mock wires firewallDisableIPv6 / EnableIPv6 and firewallIsIPv6Disabled
// against a shared bool so refresh() reports the post-op state consistently.
func statefulIPv6Mock(t *testing.T) *bool {
	t.Helper()
	disabled := false
	origDisable := firewallDisableIPv6
	origEnable := firewallEnableIPv6
	origQuery := firewallIsIPv6Disabled
	firewallDisableIPv6 = func() error { disabled = true; return nil }
	firewallEnableIPv6 = func() error { disabled = false; return nil }
	firewallIsIPv6Disabled = func() bool { return disabled }
	t.Cleanup(func() {
		firewallDisableIPv6 = origDisable
		firewallEnableIPv6 = origEnable
		firewallIsIPv6Disabled = origQuery
	})
	return &disabled
}

func TestDashboardIPv6Toggle(t *testing.T) {
	d := newTestDashboard(t)
	statefulIPv6Mock(t)
	d.focused = true
	d.connected = true
	d.activeCol = 1

	idx := findDashActionRight(d, "ipv6-protection")
	if idx < 0 {
		t.Fatal("ipv6-protection action not found")
	}
	d.rightCol = idx

	d.ipv6Disabled = false
	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if !d.ipv6Disabled {
		t.Error("ipv6Disabled should be true after toggle")
	}

	_, cmd = d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if d.ipv6Disabled {
		t.Error("ipv6Disabled should be false after second toggle")
	}
}

// statefulLANMock wires LAN block + LAN stealth enable/disable ops against
// shared bools so refresh() reports post-op state correctly.
// Returns pointers to (lanBlock, stealth) booleans for assertions.
func statefulLANMock(t *testing.T) (*bool, *bool) {
	t.Helper()
	lanBlock := false
	stealth := false
	origEnableLB := firewallEnableLANBlock
	origDisableLB := firewallDisableLANBlock
	origIsLB := firewallIsLANBlockActive
	origEnableST := firewallEnableLANStealth
	origDisableST := firewallDisableLANStealth
	origIsST := firewallIsLANStealthActive
	origGetPhys := firewallGetPhysicalInterface
	firewallEnableLANBlock = func(string, string, string, string) error { lanBlock = true; return nil }
	firewallDisableLANBlock = func() error { lanBlock = false; return nil }
	firewallIsLANBlockActive = func() bool { return lanBlock }
	firewallEnableLANStealth = func() error { stealth = true; return nil }
	firewallDisableLANStealth = func() error { stealth = false; return nil }
	firewallIsLANStealthActive = func() bool { return stealth }
	firewallGetPhysicalInterface = func() (string, string, error) { return "wlan0", "192.168.1.1", nil }
	t.Cleanup(func() {
		firewallEnableLANBlock = origEnableLB
		firewallDisableLANBlock = origDisableLB
		firewallIsLANBlockActive = origIsLB
		firewallEnableLANStealth = origEnableST
		firewallDisableLANStealth = origDisableST
		firewallIsLANStealthActive = origIsST
		firewallGetPhysicalInterface = origGetPhys
	})
	return &lanBlock, &stealth
}

func TestDashboardLocalNetworkCycle(t *testing.T) {
	d := newTestDashboard(t)
	_, stealth := statefulLANMock(t)
	d.focused = true
	d.connected = true
	d.activeCol = 1

	idx := findDashActionRight(d, "local-network")
	if idx < 0 {
		t.Fatal("local-network action not found")
	}
	d.rightCol = idx

	// Start at Allow (both cached flags false).
	d.lanBlock = false
	d.stealthMode = false

	// Allow → Stealth
	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if d.lanBlock || !d.stealthMode {
		t.Errorf("Allow→Stealth: want lanBlock=false/stealth=true, got %v/%v",
			d.lanBlock, d.stealthMode)
	}
	if !*stealth {
		t.Error("firewallEnableLANStealth should have been called")
	}

	// Stealth → Block
	_, cmd = d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if !d.lanBlock || d.stealthMode {
		t.Errorf("Stealth→Block: want lanBlock=true/stealth=false, got %v/%v",
			d.lanBlock, d.stealthMode)
	}
	if *stealth {
		t.Error("firewallDisableLANStealth should have been called")
	}

	// Block → Allow
	_, cmd = d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if d.lanBlock || d.stealthMode {
		t.Errorf("Block→Allow: want lanBlock=false/stealth=false, got %v/%v",
			d.lanBlock, d.stealthMode)
	}
}

func TestDashboardLocalNetworkAlwaysReappliesKillswitch(t *testing.T) {
	mockConnected(t)
	d := newTestDashboard(t)
	statefulLANMock(t)
	d.focused = true
	d.connected = true
	d.activeCol = 1
	d.killswitch = true
	d.cfg.LastConnectedServer = "US-NY#42"
	// Persist to disk so refresh() → cfg.Reload() doesn't wipe it between transitions.
	// The handler now skips reapply when LastConnectedServer is empty (EnableSimple
	// state — Enable would silently break DNS).
	if err := d.cfg.Save(); err != nil {
		t.Fatalf("save cfg: %v", err)
	}

	// Track firewallEnable calls (override firewallEnable but keep isFirewallActive
	// reporting true so the cycle handler's reapply branch runs).
	enableCalls := 0
	origEnable := firewallEnable
	firewallEnable = func(*firewall.KillswitchConfig) error { enableCalls++; return nil }
	t.Cleanup(func() { firewallEnable = origEnable })

	origActive := isFirewallActive
	isFirewallActive = func() bool { return true }
	t.Cleanup(func() { isFirewallActive = origActive })

	idx := findDashActionRight(d, "local-network")
	if idx < 0 {
		t.Fatal("local-network action not found")
	}
	d.rightCol = idx

	// Start at Allow mode (cached flags both false).
	d.lanBlock = false
	d.stealthMode = false

	// Allow → Stealth: LAN block stays false, so an overly-strict reapply
	// guard would NOT fire. New code always reapplies when KS is active.
	enableCalls = 0
	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if enableCalls != 1 {
		t.Errorf("Allow→Stealth: firewallEnable called %d times, want 1", enableCalls)
	}

	// Stealth → Block
	enableCalls = 0
	_, cmd = d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if enableCalls != 1 {
		t.Errorf("Stealth→Block: firewallEnable called %d times, want 1", enableCalls)
	}

	// Block → Allow
	enableCalls = 0
	_, cmd = d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if enableCalls != 1 {
		t.Errorf("Block→Allow: firewallEnable called %d times, want 1", enableCalls)
	}
}

// TestDashboardLocalNetworkSkipsKSReapplyInSimpleState verifies the fix for
// the EnableSimple-state DNS-break bug: when killswitch was enabled before
// any connection (LastConnectedServer is ""), cycling LAN modes must NOT
// call firewallEnable — that would replace the simple killswitch with a
// "full" one whose buildKillswitchConfig returns empty DNS, breaking
// system-wide DNS resolution.
func TestDashboardLocalNetworkSkipsKSReapplyInSimpleState(t *testing.T) {
	mockConnected(t)
	d := newTestDashboard(t)
	statefulLANMock(t)
	d.focused = true
	d.connected = true
	d.activeCol = 1
	d.killswitch = true
	// Critical: LastConnectedServer is empty — never connected.
	d.cfg.LastConnectedServer = ""
	if err := d.cfg.Save(); err != nil {
		t.Fatalf("save cfg: %v", err)
	}

	enableCalls := 0
	origEnable := firewallEnable
	firewallEnable = func(*firewall.KillswitchConfig) error { enableCalls++; return nil }
	t.Cleanup(func() { firewallEnable = origEnable })

	origActive := isFirewallActive
	isFirewallActive = func() bool { return true }
	t.Cleanup(func() { isFirewallActive = origActive })

	idx := findDashActionRight(d, "local-network")
	if idx < 0 {
		t.Fatal("local-network action not found")
	}
	d.rightCol = idx
	d.lanBlock = false
	d.stealthMode = false

	// Allow → Stealth: must NOT reapply ks (would break DNS).
	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if enableCalls != 0 {
		t.Errorf("Allow→Stealth in EnableSimple state: firewallEnable called %d times, want 0", enableCalls)
	}
}

func TestDashboardLocalNetworkBlockEnablesLANBlock(t *testing.T) {
	mockConnected(t)
	d := newTestDashboard(t)
	lanBlock, _ := statefulLANMock(t)
	d.focused = true
	d.connected = true
	d.activeCol = 1
	d.cfg.ConnectionName = "wg0"

	idx := findDashActionRight(d, "local-network")
	if idx < 0 {
		t.Fatal("local-network action not found")
	}
	d.rightCol = idx

	// Start at Stealth (will go to Block next)
	d.lanBlock = false
	d.stealthMode = true

	// Stealth → Block
	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	drainFirewallCmd(t, d, cmd)
	if !*lanBlock {
		t.Error("firewallEnableLANBlock should have been called in Block mode")
	}
}

func TestDashboardDNSProvidersAction(t *testing.T) {
	d := newTestDashboard(t)
	d.focused = true
	d.connected = true
	d.activeCol = 1

	idx := findDashActionRight(d, "dns-providers")
	if idx < 0 {
		t.Fatal("dns-providers action not found")
	}
	d.rightCol = idx

	_, cmd := d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("dns-providers should return cmd")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.View != "dns-providers" {
		t.Errorf("View = %q, want dns-providers", sv.View)
	}
}

func TestDashboardKsDisconnectLabel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"true", "Auto"},
		{"", "Auto"},
		{"false", "Prompt"},
		{"never", "Never"},
	}
	for _, tt := range tests {
		if got := ksDisconnectLabel(tt.input); got != tt.want {
			t.Errorf("ksDisconnectLabel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDashboardCurrentDescription(t *testing.T) {
	d := newTestDashboard(t)
	d.connected = true

	// Normal: returns action desc
	desc := d.CurrentDescription()
	if desc == "" {
		t.Error("should return action description")
	}

	// With status text
	d.statusText = "Error: something"
	d.statusIsError = true
	desc = d.CurrentDescription()
	if desc != "Error: something" {
		t.Errorf("CurrentDescription() = %q, want 'Error: something'", desc)
	}
	if !d.StatusIsError() {
		t.Error("StatusIsError should be true")
	}
}

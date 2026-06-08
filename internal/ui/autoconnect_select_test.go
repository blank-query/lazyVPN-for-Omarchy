package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/provider"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
)

func TestFormatServerNameManual(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(string) bool
	}{
		{
			"simple manual",
			"US-NY#42",
			func(s string) bool { return s != "" && s != "US-NY#42" }, // should be pretty-printed
		},
		{
			"manual with provider",
			"Proton-US-NY#42",
			func(s string) bool { return s != "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatServerName(tt.input)
			if !tt.check(got) {
				t.Errorf("formatServerName(%q) = %q, check failed", tt.input, got)
			}
		})
	}
}

func TestFormatServerNameDynamic(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantSep  bool   // should contain the "•" separator
		wantProv string // partial match for provider display
	}{
		{"protonvpn dynamic", "dynamic:protonvpn:US-NY#42", true, "ProtonVPN"},
		{"mullvad dynamic", "dynamic:mullvad:SE#5", true, "Mullvad"},
		{"unknown provider", "dynamic:unknown:US#1", true, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatServerName(tt.input)
			if tt.wantSep && !contains(got, "•") {
				t.Errorf("formatServerName(%q) = %q, expected '•' separator", tt.input, got)
			}
		})
	}
}

func TestFormatServerNameMalformedDynamic(t *testing.T) {
	// Malformed dynamic prefix (only 2 parts) should fall through to manual parsing
	got := formatServerName("dynamic:bad")
	if got == "" {
		t.Error("malformed dynamic should still produce output")
	}
}

// Helper to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestParseServerNameIntegration(t *testing.T) {
	// Test that ParseServerName works correctly for format used in autoconnect
	info := wireguard.ParseServerName("US-NY#42")
	if info.Country == "" {
		t.Error("ParseServerName should extract country")
	}

	pretty := info.PrettyName()
	if pretty == "" {
		t.Error("PrettyName should not be empty")
	}
}

// newTestAutoconnectSelect creates an AutoconnectSelect with predefined servers.
func newTestAutoconnectSelect(t *testing.T) *AutoconnectSelect {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = cfg.ConfigDir + "/config"

	s := &AutoconnectSelect{
		cfg: cfg,
		servers: []string{
			"US-NY#1",
			"US-NY#2",
			"SE#5",
			"dynamic:protonvpn:US-CA#10",
		},
	}
	return s
}

func TestAutoconnectSelectInit(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	if s.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestAutoconnectSelectEsc(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestAutoconnectSelectCursorDown(t *testing.T) {
	s := newTestAutoconnectSelect(t)

	s.Update(tea.KeyMsg{Type: tea.KeyDown})
	if s.cursor != 1 {
		t.Errorf("cursor = %d, want 1", s.cursor)
	}

	s.Update(tea.KeyMsg{Type: tea.KeyDown})
	if s.cursor != 2 {
		t.Errorf("cursor = %d, want 2", s.cursor)
	}
}

func TestAutoconnectSelectCursorUp(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	s.cursor = 2

	s.Update(tea.KeyMsg{Type: tea.KeyUp})
	if s.cursor != 1 {
		t.Errorf("cursor = %d, want 1", s.cursor)
	}
}

func TestAutoconnectSelectCursorDownClamped(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	s.cursor = len(s.servers) - 1

	s.Update(tea.KeyMsg{Type: tea.KeyDown})
	if s.cursor != len(s.servers)-1 {
		t.Errorf("cursor = %d, should be clamped to last", s.cursor)
	}
}

func TestAutoconnectSelectCursorUpClamped(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	s.cursor = 0

	s.Update(tea.KeyMsg{Type: tea.KeyUp})
	if s.cursor != 0 {
		t.Errorf("cursor = %d, should be clamped to 0", s.cursor)
	}
}

func TestAutoconnectSelectHome(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	s.cursor = 3

	s.Update(tea.KeyMsg{Type: tea.KeyHome})
	if s.cursor != 0 {
		t.Errorf("cursor = %d, want 0 after Home", s.cursor)
	}
}

func TestAutoconnectSelectEnd(t *testing.T) {
	s := newTestAutoconnectSelect(t)

	s.Update(tea.KeyMsg{Type: tea.KeyEnd})
	if s.cursor != len(s.servers)-1 {
		t.Errorf("cursor = %d, want %d after End", s.cursor, len(s.servers)-1)
	}
}

func TestAutoconnectSelectEnter(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	s.cursor = 1

	_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter should return cmd")
	}
	msg := cmd()
	sel, ok := msg.(AutoconnectServerSelectMsg)
	if !ok {
		t.Fatalf("expected AutoconnectServerSelectMsg, got %T", msg)
	}
	if sel.Server != "US-NY#2" {
		t.Errorf("Server = %q, want US-NY#2", sel.Server)
	}
	if s.cfg.AutostartServer != "US-NY#2" {
		t.Errorf("cfg.AutostartServer = %q, want US-NY#2", s.cfg.AutostartServer)
	}
}

// TestAutoconnectSelectEnterRevertsOnSaveFailure verifies that when
// cfg.Save fails after AutostartServer is set, the in-memory value
// is reverted to the PREVIOUS value (not to ""). cfg.Save is atomic
// — on failure the on-disk value is whatever it was before — so
// resetting in-memory to "" while disk holds the old value drifts
// the TUI's view from reality and causes the daemon's autoconnect
// to keep using the old value while the TUI displays nothing
// configured.
func TestAutoconnectSelectEnterRevertsOnSaveFailure(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	// Pre-populate AutostartServer so we have a non-empty "previous"
	// value to verify against.
	s.cfg.AutostartServer = "US-NY#1"
	// Force Save to fail by pointing ConfigDir at a path that exists
	// but isn't a directory — CreateTemp inside Save fails.
	dummyFile := s.cfg.ConfigDir + "/not-a-dir"
	if err := os.WriteFile(dummyFile, []byte("x"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s.cfg.ConfigDir = dummyFile

	s.cursor = 1 // selects "US-NY#2" — different from the pre-populated value

	_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Errorf("enter should NOT return a cmd when Save fails (got %T)", cmd())
	}

	// In-memory must be reverted to the PREVIOUS value, not "".
	if s.cfg.AutostartServer != "US-NY#1" {
		t.Errorf("AutostartServer = %q, want %q (reverted to previous on Save failure)",
			s.cfg.AutostartServer, "US-NY#1")
	}
}

func TestAutoconnectSelectSpace(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	s.cursor = 0

	_, cmd := s.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	if cmd == nil {
		t.Fatal("space should return cmd")
	}
	msg := cmd()
	sel, ok := msg.(AutoconnectServerSelectMsg)
	if !ok {
		t.Fatalf("expected AutoconnectServerSelectMsg, got %T", msg)
	}
	if sel.Server != "US-NY#1" {
		t.Errorf("Server = %q, want US-NY#1", sel.Server)
	}
}

func TestAutoconnectSelectWindowSize(t *testing.T) {
	s := newTestAutoconnectSelect(t)

	s.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	if s.width != 100 || s.height != 30 {
		t.Errorf("size = %dx%d, want 100x30", s.width, s.height)
	}
}

func TestAutoconnectSelectViewEmpty(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	s := &AutoconnectSelect{cfg: cfg, servers: nil}

	view := s.View()
	if !strings.Contains(view, "Select Autoconnect Server") {
		t.Error("should contain title")
	}
	if !strings.Contains(view, "No servers available") {
		t.Error("should show no servers message")
	}
}

func TestAutoconnectSelectViewWithServers(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	s.width = 80
	s.height = 30

	view := s.View()
	if !strings.Contains(view, "Select Autoconnect Server") {
		t.Error("should contain title")
	}
	if !strings.Contains(view, "enter: select") {
		t.Error("should contain help text")
	}
}

func TestAutoconnectSelectViewCurrentSelection(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	s.cfg.AutostartServer = "US-NY#2"
	s.width = 80
	s.height = 30

	view := s.View()
	if !strings.Contains(view, "(current)") {
		t.Error("should mark current selection")
	}
}

func TestAutoconnectSelectViewMessage(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	s.message = "Server selected"
	s.width = 80
	s.height = 30

	view := s.View()
	if !strings.Contains(view, "Server selected") {
		t.Error("should show message")
	}
}

func TestAutoconnectSelectViewScrollIndicator(t *testing.T) {
	// Create enough servers to trigger scroll
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	s := &AutoconnectSelect{cfg: cfg, width: 80, height: 20}
	for i := 0; i < 50; i++ {
		s.servers = append(s.servers, "server"+strings.Repeat("x", i))
	}

	view := s.View()
	if !strings.Contains(view, "/50") {
		t.Error("should show scroll indicator with total count")
	}
}

func TestAutoconnectSelectLoadServersFromDisk(t *testing.T) {
	dir := t.TempDir()
	wgDir := filepath.Join(dir, "wireguard")
	os.MkdirAll(wgDir, 0700)

	// Create valid WireGuard configs
	confContent := "[Interface]\nPrivateKey = aGVsbG8gd29ybGQ=\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\n\n[Peer]\nPublicKey = aGVsbG8gd29ybGQ=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
	os.WriteFile(filepath.Join(wgDir, "US-NY.conf"), []byte(confContent), 0600)
	os.WriteFile(filepath.Join(wgDir, "SE.conf"), []byte(confContent), 0600)

	cfg := config.DefaultConfig()
	cfg.ConfigDir = dir
	cfg.ConfigFile = filepath.Join(dir, "config.json")

	s := NewAutoconnectSelect(cfg)
	if len(s.servers) < 2 {
		t.Errorf("servers = %d, want at least 2", len(s.servers))
	}
}

func TestAutoconnectSelectLoadServersWithProviders(t *testing.T) {
	dir := t.TempDir()
	wgDir := filepath.Join(dir, "wireguard")
	os.MkdirAll(wgDir, 0700)
	provDir := filepath.Join(dir, "providers")
	os.MkdirAll(provDir, 0700)
	cacheDir := filepath.Join(dir, "cache")
	os.MkdirAll(cacheDir, 0700)

	// Create a manual config
	confContent := "[Interface]\nPrivateKey = aGVsbG8gd29ybGQ=\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\n\n[Peer]\nPublicKey = aGVsbG8gd29ybGQ=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
	os.WriteFile(filepath.Join(wgDir, "manual.conf"), []byte(confContent), 0600)

	// Create a provider
	os.WriteFile(filepath.Join(provDir, "protonvpn.json"), []byte(`{"private_key":"test","address":"10.2.0.2/32"}`), 0600)

	// Create cached servers for the provider
	servers := []provider.Server{
		{ServerName: "US-NY#42", Country: "US", IPs: []string{"1.1.1.1"}},
	}
	data, _ := json.Marshal(servers)
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), data, 0600)

	cfg := config.DefaultConfig()
	cfg.ConfigDir = dir
	cfg.ConfigFile = filepath.Join(dir, "config.json")

	s := NewAutoconnectSelect(cfg)

	// Should have at least the manual server and the dynamic server
	foundManual := false
	foundDynamic := false
	for _, srv := range s.servers {
		if srv == "manual" {
			foundManual = true
		}
		if srv == "dynamic:protonvpn:US-NY#42" {
			foundDynamic = true
		}
	}
	if !foundManual {
		t.Error("should contain manual server")
	}
	if !foundDynamic {
		t.Error("should contain dynamic server from provider cache")
	}
}

func TestAutoconnectSelectLoadServersEmptyDir(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ConfigDir = dir
	cfg.ConfigFile = filepath.Join(dir, "config.json")

	s := NewAutoconnectSelect(cfg)
	if len(s.servers) != 0 {
		t.Errorf("servers = %d, want 0 for empty dir", len(s.servers))
	}
}

// TestAutoconnectSelectLoadServersCursorSetToCurrentServer tests that loadServers
// sets the cursor to the index matching cfg.AutostartServer.
func TestAutoconnectSelectLoadServersCursorSetToCurrentServer(t *testing.T) {
	dir := t.TempDir()
	wgDir := filepath.Join(dir, "wireguard")
	os.MkdirAll(wgDir, 0700)

	confContent := "[Interface]\nPrivateKey = aGVsbG8gd29ybGQ=\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\n\n[Peer]\nPublicKey = aGVsbG8gd29ybGQ=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
	os.WriteFile(filepath.Join(wgDir, "AA.conf"), []byte(confContent), 0600)
	os.WriteFile(filepath.Join(wgDir, "BB.conf"), []byte(confContent), 0600)
	os.WriteFile(filepath.Join(wgDir, "CC.conf"), []byte(confContent), 0600)

	cfg := config.DefaultConfig()
	cfg.ConfigDir = dir
	cfg.ConfigFile = filepath.Join(dir, "config.json")
	cfg.AutostartServer = "BB"

	s := NewAutoconnectSelect(cfg)

	// Find the index of BB in the loaded servers
	bbIdx := -1
	for i, srv := range s.servers {
		if srv == "BB" {
			bbIdx = i
			break
		}
	}
	if bbIdx == -1 {
		t.Fatal("BB not found in loaded servers")
	}
	if s.cursor != bbIdx {
		t.Errorf("cursor = %d, want %d (index of AutostartServer BB)", s.cursor, bbIdx)
	}
}

// TestAutoconnectSelectViewDefaultHeight tests View with zero height (uses default).
func TestAutoconnectSelectViewDefaultHeight(t *testing.T) {
	s := newTestAutoconnectSelect(t)
	s.width = 80
	s.height = 0 // default height

	view := s.View()
	if !strings.Contains(view, "Select Autoconnect Server") {
		t.Error("should show title with default height")
	}
}

// TestAutoconnectSelectViewSmallHeight tests View with very small height.
func TestAutoconnectSelectViewSmallHeight(t *testing.T) {
	// Create enough servers to trigger the small height path
	cfg := config.DefaultConfig()
	cfg.ConfigDir = t.TempDir()
	s := &AutoconnectSelect{cfg: cfg, width: 80, height: 10}
	for i := 0; i < 20; i++ {
		s.servers = append(s.servers, "server"+strings.Repeat("x", i))
	}

	// visibleHeight = 10 - 8 = 2, which is < 10, so it becomes 15
	view := s.View()
	if view == "" {
		t.Error("view should not be empty with small height")
	}
}

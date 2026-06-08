package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

func TestRemoveServerInit(t *testing.T) {
	rs := &RemoveServer{cfg: &config.Config{}}
	if rs.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestRemoveServerEsc(t *testing.T) {
	rs := &RemoveServer{
		cfg: &config.Config{},
		servers: []serverToRemove{
			{name: "server1"},
		},
	}
	_, cmd := rs.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestRemoveServerCursorNavigation(t *testing.T) {
	rs := &RemoveServer{
		cfg: &config.Config{},
		servers: []serverToRemove{
			{name: "a"}, {name: "b"}, {name: "c"},
		},
	}

	model, _ := rs.Update(tea.KeyMsg{Type: tea.KeyDown})
	rs = model.(*RemoveServer)
	if rs.cursor != 1 {
		t.Errorf("cursor = %d, want 1", rs.cursor)
	}

	model, _ = rs.Update(tea.KeyMsg{Type: tea.KeyDown})
	rs = model.(*RemoveServer)
	if rs.cursor != 2 {
		t.Errorf("cursor = %d, want 2", rs.cursor)
	}

	// Clamp
	model, _ = rs.Update(tea.KeyMsg{Type: tea.KeyDown})
	rs = model.(*RemoveServer)
	if rs.cursor != 2 {
		t.Errorf("cursor = %d, want 2 (clamped)", rs.cursor)
	}

	model, _ = rs.Update(tea.KeyMsg{Type: tea.KeyUp})
	rs = model.(*RemoveServer)
	if rs.cursor != 1 {
		t.Errorf("cursor = %d, want 1", rs.cursor)
	}

	// arrow keys (continued)
	model, _ = rs.Update(tea.KeyMsg{Type: tea.KeyUp})
	rs = model.(*RemoveServer)
	if rs.cursor != 0 {
		t.Errorf("cursor = %d, want 0", rs.cursor)
	}

	model, _ = rs.Update(tea.KeyMsg{Type: tea.KeyDown})
	rs = model.(*RemoveServer)
	if rs.cursor != 1 {
		t.Errorf("cursor = %d, want 1", rs.cursor)
	}
}

func TestRemoveServerToggleSelection(t *testing.T) {
	rs := &RemoveServer{
		cfg: &config.Config{},
		servers: []serverToRemove{
			{name: "a"},
		},
	}

	// Space toggles selection.
	model, _ := rs.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	rs = model.(*RemoveServer)
	if !rs.servers[0].selected {
		t.Error("should be selected after space")
	}

	model, _ = rs.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	rs = model.(*RemoveServer)
	if rs.servers[0].selected {
		t.Error("should be deselected after second space")
	}

	// Tab is reserved for pane-switching at the dashboard level — must NOT
	// toggle the checkbox here. Regression guard for the dashboard-Tab
	// vs sub-view-Tab conflict.
	model, _ = rs.Update(tea.KeyMsg{Type: tea.KeyTab})
	rs = model.(*RemoveServer)
	if rs.servers[0].selected {
		t.Error("tab should not toggle selection (reserved for pane switch)")
	}
}

func TestRemoveServerEnterAutoSelectsAndConfirms(t *testing.T) {
	rs := &RemoveServer{
		cfg: &config.Config{},
		servers: []serverToRemove{
			{name: "a"}, {name: "b"},
		},
	}

	model, _ := rs.Update(tea.KeyMsg{Type: tea.KeyEnter})
	rs = model.(*RemoveServer)
	if !rs.servers[0].selected {
		t.Error("enter should auto-select current item")
	}
	if !rs.confirmMode {
		t.Error("should enter confirm mode")
	}
}

func TestRemoveServerDKeyAlsoConfirms(t *testing.T) {
	rs := &RemoveServer{
		cfg: &config.Config{},
		servers: []serverToRemove{
			{name: "a", selected: true},
		},
	}

	model, _ := rs.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	rs = model.(*RemoveServer)
	if !rs.confirmMode {
		t.Error("d key should enter confirm mode")
	}
}

func TestRemoveServerConfirmCancel(t *testing.T) {
	rs := &RemoveServer{
		cfg:         &config.Config{},
		confirmMode: true,
		servers: []serverToRemove{
			{name: "a", selected: true},
		},
	}

	model, _ := rs.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	rs = model.(*RemoveServer)
	if rs.confirmMode {
		t.Error("n should cancel confirm mode")
	}
}

func TestRemoveServerConfirmEsc(t *testing.T) {
	rs := &RemoveServer{
		cfg:         &config.Config{},
		confirmMode: true,
		servers: []serverToRemove{
			{name: "a", selected: true},
		},
	}

	model, _ := rs.Update(tea.KeyMsg{Type: tea.KeyEscape})
	rs = model.(*RemoveServer)
	if rs.confirmMode {
		t.Error("esc should cancel confirm mode")
	}
}

func TestRemoveServerRemoveDoneMsg(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{ConfigDir: dir}

	rs := &RemoveServer{
		cfg: cfg,
		servers: []serverToRemove{
			{name: "a"}, {name: "b"},
		},
	}

	model, _ := rs.Update(removeDoneMsg{removed: 1})
	rs = model.(*RemoveServer)
	if rs.message != "Removed 1 server(s)" {
		t.Errorf("message = %q", rs.message)
	}
	if rs.cursor != 0 {
		t.Errorf("cursor = %d, want 0", rs.cursor)
	}
}

func TestRemoveServerRemoveDoneMsgSkippedConnected(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{ConfigDir: dir}

	rs := &RemoveServer{cfg: cfg, servers: []serverToRemove{{name: "a"}}}

	model, _ := rs.Update(removeDoneMsg{removed: 0, skippedConnected: true})
	rs = model.(*RemoveServer)
	if !strings.Contains(rs.message, "skipped currently connected") {
		t.Errorf("message = %q, should mention skipped connected", rs.message)
	}
}

func TestRemoveServerRemoveDoneMsgCleansConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		ConfigDir:           dir,
		LastConnectedServer: "deleted-server",
		LastPublicIP:        "1.2.3.4",
		AutostartServer:     "deleted-server",
		Favorites:           []string{"deleted-server", "keep-server"},
	}

	rs := &RemoveServer{cfg: cfg, servers: []serverToRemove{{name: "a"}}}

	rs.Update(removeDoneMsg{removed: 1, deletedNames: []string{"deleted-server"}})

	if cfg.LastConnectedServer != "" {
		t.Errorf("LastConnectedServer = %q, want empty", cfg.LastConnectedServer)
	}
	if cfg.LastPublicIP != "" {
		t.Errorf("LastPublicIP = %q, want empty", cfg.LastPublicIP)
	}
	if cfg.AutostartServer != "" {
		t.Errorf("AutostartServer = %q, want empty", cfg.AutostartServer)
	}
	if len(cfg.Favorites) != 1 || cfg.Favorites[0] != "keep-server" {
		t.Errorf("Favorites = %v, want [keep-server]", cfg.Favorites)
	}
}

func TestRemoveServerWindowSize(t *testing.T) {
	rs := &RemoveServer{cfg: &config.Config{}}
	model, _ := rs.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	rs = model.(*RemoveServer)
	if rs.width != 100 || rs.height != 30 {
		t.Errorf("size = %dx%d, want 100x30", rs.width, rs.height)
	}
}

func TestRemoveServerViewEmpty(t *testing.T) {
	rs := &RemoveServer{cfg: &config.Config{}}
	view := rs.View()
	if !strings.Contains(view, "Remove Server") {
		t.Error("should contain title")
	}
	if !strings.Contains(view, "No manual server configs") {
		t.Error("should show empty message")
	}
}

func TestRemoveServerViewWithServers(t *testing.T) {
	rs := &RemoveServer{
		cfg: &config.Config{},
		servers: []serverToRemove{
			{name: "US-NY#1"},
			{name: "DE-Berlin#5"},
		},
		width:  80,
		height: 30,
	}
	view := rs.View()
	if !strings.Contains(view, "US-NY#1") {
		t.Error("should show server name")
	}
	if !strings.Contains(view, "DE-Berlin#5") {
		t.Error("should show second server")
	}
}

func TestRemoveServerViewConfirmMode(t *testing.T) {
	rs := &RemoveServer{
		cfg:         &config.Config{},
		confirmMode: true,
		servers: []serverToRemove{
			{name: "US-NY#1", selected: true},
			{name: "DE-Berlin#5"},
		},
	}
	view := rs.View()
	if !strings.Contains(view, "Delete") {
		t.Error("should show delete prompt")
	}
	if !strings.Contains(view, "US-NY#1") {
		t.Error("should show selected server")
	}
	if !strings.Contains(view, "y: delete") {
		t.Error("should show y/n prompt")
	}
}

func TestRemoveServerDoRemove(t *testing.T) {
	dir := t.TempDir()
	// Create fake config files
	wgDir := filepath.Join(dir, "wireguard")
	os.MkdirAll(wgDir, 0700)
	filePath := filepath.Join(wgDir, "test-server.conf")
	os.WriteFile(filePath, []byte("test data"), 0600)

	cfg := &config.Config{
		ConfigDir:           dir,
		LastConnectedServer: "connected-server",
	}

	rs := &RemoveServer{
		cfg: cfg,
		servers: []serverToRemove{
			{name: "test-server", path: filePath, selected: true},
		},
	}

	cmd := rs.doRemove()
	if cmd == nil {
		t.Fatal("doRemove should return cmd")
	}
	msg := cmd()
	done, ok := msg.(removeDoneMsg)
	if !ok {
		t.Fatalf("expected removeDoneMsg, got %T", msg)
	}
	if done.removed != 1 {
		t.Errorf("removed = %d, want 1", done.removed)
	}
	if done.skippedConnected {
		t.Error("should not have skipped connected")
	}
	if len(done.deletedNames) != 1 || done.deletedNames[0] != "test-server" {
		t.Errorf("deletedNames = %v, want [test-server]", done.deletedNames)
	}
}

func TestRemoveServerDoRemoveSkipsConnected(t *testing.T) {
	dir := t.TempDir()
	wgDir := filepath.Join(dir, "wireguard")
	os.MkdirAll(wgDir, 0700)
	filePath := filepath.Join(wgDir, "connected-server.conf")
	os.WriteFile(filePath, []byte("test data"), 0600)

	cfg := &config.Config{
		ConfigDir:           dir,
		LastConnectedServer: "connected-server",
	}

	rs := &RemoveServer{
		cfg: cfg,
		servers: []serverToRemove{
			{name: "connected-server", path: filePath, selected: true},
		},
	}

	cmd := rs.doRemove()
	if cmd == nil {
		t.Fatal("doRemove should return cmd")
	}
	msg := cmd()
	done, ok := msg.(removeDoneMsg)
	if !ok {
		t.Fatalf("expected removeDoneMsg, got %T", msg)
	}
	if done.removed != 0 {
		t.Errorf("removed = %d, want 0 (should skip connected)", done.removed)
	}
	if !done.skippedConnected {
		t.Error("should have skipped connected server")
	}
}

func TestRemoveServerDoRemoveNoneSelected(t *testing.T) {
	cfg := &config.Config{ConfigDir: t.TempDir()}

	rs := &RemoveServer{
		cfg: cfg,
		servers: []serverToRemove{
			{name: "server1", path: "/fake/path", selected: false},
		},
	}

	cmd := rs.doRemove()
	if cmd == nil {
		t.Fatal("doRemove should return cmd")
	}
	msg := cmd()
	done, ok := msg.(removeDoneMsg)
	if !ok {
		t.Fatalf("expected removeDoneMsg, got %T", msg)
	}
	if done.removed != 0 {
		t.Errorf("removed = %d, want 0", done.removed)
	}
}

func TestRemoveServerConfirmYes(t *testing.T) {
	dir := t.TempDir()
	wgDir := filepath.Join(dir, "wireguard")
	os.MkdirAll(wgDir, 0700)
	filePath := filepath.Join(wgDir, "server.conf")
	os.WriteFile(filePath, []byte("data"), 0600)

	rs := &RemoveServer{
		cfg:         &config.Config{ConfigDir: dir},
		confirmMode: true,
		servers: []serverToRemove{
			{name: "server", path: filePath, selected: true},
		},
	}

	_, cmd := rs.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if cmd == nil {
		t.Fatal("y in confirm should return cmd")
	}
}

func TestRemoveServerLoadServers(t *testing.T) {
	dir := t.TempDir()
	wgDir := filepath.Join(dir, "wireguard")
	os.MkdirAll(wgDir, 0700)

	// Create valid WireGuard config files
	confContent := "[Interface]\nPrivateKey = aGVsbG8gd29ybGQ=\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\n\n[Peer]\nPublicKey = aGVsbG8gd29ybGQ=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
	os.WriteFile(filepath.Join(wgDir, "US-NY.conf"), []byte(confContent), 0600)
	os.WriteFile(filepath.Join(wgDir, "SE.conf"), []byte(confContent), 0600)

	cfg := &config.Config{ConfigDir: dir}
	rs := NewRemoveServer(cfg)

	if len(rs.servers) != 2 {
		t.Errorf("servers = %d, want 2", len(rs.servers))
	}
}

// TestRemoveServerViewWithScrolling tests the view with enough servers to trigger scrolling.
func TestRemoveServerViewWithScrolling(t *testing.T) {
	servers := make([]serverToRemove, 30)
	for i := range servers {
		servers[i] = serverToRemove{name: "server-" + strings.Repeat("x", 3)}
	}
	rs := &RemoveServer{
		cfg:     &config.Config{},
		servers: servers,
		cursor:  25, // Far enough down to trigger scrolling
		width:   80,
		height:  20,
	}
	view := rs.View()
	if view == "" {
		t.Error("view should not be empty")
	}
}

// TestRemoveServerViewWithSelectedServer tests the view with selected servers showing checkboxes.
func TestRemoveServerViewWithSelectedServer(t *testing.T) {
	rs := &RemoveServer{
		cfg: &config.Config{},
		servers: []serverToRemove{
			{name: "US-NY#1", selected: true},
			{name: "DE-Berlin#5", selected: false},
		},
		width:  80,
		height: 30,
	}
	view := rs.View()
	if !strings.Contains(view, "[x]") {
		t.Error("should show checked checkbox for selected server")
	}
}

func TestRemoveServerViewWithMessage(t *testing.T) {
	rs := &RemoveServer{
		cfg:     &config.Config{},
		message: "Removed 2 server(s)",
		servers: []serverToRemove{
			{name: "remaining"},
		},
		width:  80,
		height: 30,
	}
	view := rs.View()
	if !strings.Contains(view, "Removed 2 server(s)") {
		t.Error("should show success message")
	}
}

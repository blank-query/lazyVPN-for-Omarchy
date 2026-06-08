package ui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/daemon"
	tea "github.com/charmbracelet/bubbletea"
)

func TestNewConnectProgress(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "US-NY#42", "protonvpn", true)

	if p.progressType != ProgressConnect {
		t.Errorf("progressType = %d, want ProgressConnect", p.progressType)
	}
	if p.serverName != "US-NY#42" {
		t.Errorf("serverName = %q", p.serverName)
	}
	if p.provider != "protonvpn" {
		t.Errorf("provider = %q", p.provider)
	}
	if !p.dynamic {
		t.Error("dynamic should be true")
	}
	if p.lines == nil {
		t.Error("lines should be initialized")
	}
	if p.done {
		t.Error("should not be done initially")
	}
	if p.success {
		t.Error("should not be success initially")
	}
}

func TestNewDisconnectProgress(t *testing.T) {
	cfg := &config.Config{}
	p := NewDisconnectProgress(cfg)

	if p.progressType != ProgressDisconnect {
		t.Errorf("progressType = %d, want ProgressDisconnect", p.progressType)
	}
	if p.lines == nil {
		t.Error("lines should be initialized")
	}
}

func TestProgressSuccessAndDone(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	if p.Success() {
		t.Error("should not be success initially")
	}
	if p.Done() {
		t.Error("should not be done initially")
	}

	// Simulate completion
	model, _ := p.Update(ProgressDoneMsg{Success: true, OldIP: "1.2.3.4", NewIP: "5.6.7.8"})
	p = model.(Progress)

	if !p.Done() {
		t.Error("should be done after ProgressDoneMsg")
	}
	if !p.Success() {
		t.Error("should be success after successful ProgressDoneMsg")
	}
	if p.oldIP != "1.2.3.4" {
		t.Errorf("oldIP = %q", p.oldIP)
	}
	if p.newIP != "5.6.7.8" {
		t.Errorf("newIP = %q", p.newIP)
	}
}

func TestProgressDoneWithError(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	model, _ := p.Update(ProgressDoneMsg{Success: false, Error: fmt.Errorf("connection refused")})
	p = model.(Progress)

	if !p.Done() {
		t.Error("should be done")
	}
	if p.Success() {
		t.Error("should not be success on error")
	}
	if p.err == nil {
		t.Error("err should be set")
	}
}

func TestProgressUpdateWindowSize(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	model, _ := p.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	p = model.(Progress)
	if p.width != 120 {
		t.Errorf("width = %d", p.width)
	}
	if p.height != 40 {
		t.Errorf("height = %d", p.height)
	}
}

func TestProgressUpdateKeyWhenDone(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	// Complete the progress
	model, _ := p.Update(ProgressDoneMsg{Success: true})
	p = model.(Progress)

	// Press enter should go back
	_, cmd := p.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter when done should return a cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}

	// Press esc should also go back
	_, cmd = p.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc when done should return a cmd")
	}
	msg = cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestProgressUpdateKeyWhenNotDone(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	// Key presses when not done should be ignored
	_, cmd := p.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Error("enter when not done should not return a cmd")
	}
}

func TestProgressViewConnect(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "US-NY#42", "protonvpn", true)
	view := p.View()

	if !strings.Contains(view, "Connecting") {
		t.Error("connect view should say 'Connecting'")
	}
	if !strings.Contains(view, "US-NY#42") {
		t.Error("connect view should show server name")
	}
	if !strings.Contains(view, "protonvpn") {
		t.Error("connect view should show provider")
	}
}

func TestProgressViewDisconnect(t *testing.T) {
	cfg := &config.Config{}
	p := NewDisconnectProgress(cfg)
	view := p.View()

	if !strings.Contains(view, "Disconnecting") {
		t.Error("disconnect view should say 'Disconnecting'")
	}
}

func TestProgressViewSuccessConnect(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	model, _ := p.Update(ProgressDoneMsg{Success: true, OldIP: "1.1.1.1", NewIP: "2.2.2.2"})
	p = model.(Progress)
	view := p.View()

	if !strings.Contains(view, "Successfully connected") {
		t.Error("successful connect should show success message")
	}
	if !strings.Contains(view, "1.1.1.1") {
		t.Error("should show old IP")
	}
	if !strings.Contains(view, "2.2.2.2") {
		t.Error("should show new IP")
	}
	if !strings.Contains(view, "Press Enter") {
		t.Error("should show 'Press Enter to continue'")
	}
}

func TestProgressViewSuccessDisconnect(t *testing.T) {
	cfg := &config.Config{}
	p := NewDisconnectProgress(cfg)

	model, _ := p.Update(ProgressDoneMsg{Success: true})
	p = model.(Progress)
	view := p.View()

	if !strings.Contains(view, "Successfully disconnected") {
		t.Error("successful disconnect should show disconnect message")
	}
}

func TestProgressViewFailed(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	model, _ := p.Update(ProgressDoneMsg{Success: false, Error: fmt.Errorf("timeout")})
	p = model.(Progress)
	view := p.View()

	if !strings.Contains(view, "Failed") {
		t.Error("failed should show failure message")
	}
	if !strings.Contains(view, "timeout") {
		t.Error("should show error message")
	}
}

func TestProgressViewFailedNoError(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	model, _ := p.Update(ProgressDoneMsg{Success: false})
	p = model.(Progress)
	view := p.View()

	if !strings.Contains(view, "Operation failed") {
		t.Error("failed without error should show generic failure")
	}
}

func TestProgressStreamMsg(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	// Simulate a stream message
	updates := make(chan ProgressLine, 5)
	updates <- ProgressLine{Text: "Step 2", Success: false}
	close(updates)

	var oldIP, newIP string
	model, cmd := p.Update(progressStreamMsg{
		line:    ProgressLine{Text: "Step 1", Success: false},
		updates: updates,
		oldIP:   &oldIP,
		newIP:   &newIP,
	})
	p = model.(Progress)

	if len(p.lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(p.lines))
	}
	if p.lines[0].Text != "Step 1" {
		t.Errorf("lines[0].Text = %q", p.lines[0].Text)
	}

	// cmd should be non-nil (reads next from channel)
	if cmd == nil {
		t.Fatal("cmd should not be nil")
	}
}

func TestProgressLineStyles(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	// Add lines with different styles
	lines := []ProgressLine{
		{Text: "Normal line"},
		{Text: "Success line", Success: true},
		{Text: "Error line", Error: true},
		{Text: "Muted line", Muted: true},
	}

	for _, line := range lines {
		model, _ := p.Update(progressStreamMsg{
			line:    line,
			updates: make(chan ProgressLine),
		})
		p = model.(Progress)
	}

	if len(p.lines) != 4 {
		t.Errorf("expected 4 lines, got %d", len(p.lines))
	}

	view := p.View()
	// All text should appear in the view (may be styled)
	for _, line := range lines {
		if !strings.Contains(view, line.Text) {
			t.Errorf("view should contain %q", line.Text)
		}
	}
}

func TestProgressTypeConstants(t *testing.T) {
	if ProgressConnect != 0 {
		t.Errorf("ProgressConnect = %d, want 0", ProgressConnect)
	}
	if ProgressDisconnect != 1 {
		t.Errorf("ProgressDisconnect = %d, want 1", ProgressDisconnect)
	}
}

func TestProgressStreamMsgClosedChannel(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	// Create a closed channel
	updates := make(chan ProgressLine)
	close(updates)

	var oldIP, newIP string
	model, cmd := p.Update(progressStreamMsg{
		line:    ProgressLine{Text: "Only line", Success: true},
		updates: updates,
		oldIP:   &oldIP,
		newIP:   &newIP,
	})
	p = model.(Progress)

	if len(p.lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(p.lines))
	}

	// cmd should read from closed channel and return ProgressDoneMsg
	if cmd == nil {
		t.Fatal("cmd should not be nil")
	}
	msg := cmd()
	done, ok := msg.(ProgressDoneMsg)
	if !ok {
		t.Fatalf("expected ProgressDoneMsg, got %T", msg)
	}
	// No error lines, so success should be true
	if !done.Success {
		t.Error("should be success when no error lines")
	}
}

func TestProgressStreamMsgWithErrorLines(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	// Add an error line first
	updates1 := make(chan ProgressLine, 1)
	close(updates1)

	var oldIP, newIP string
	model, _ := p.Update(progressStreamMsg{
		line:    ProgressLine{Text: "Error occurred", Error: true},
		updates: updates1,
		oldIP:   &oldIP,
		newIP:   &newIP,
	})
	p = model.(Progress)

	// Now when channel closes, ProgressDoneMsg should have Success = false
	updates2 := make(chan ProgressLine)
	close(updates2)

	_, cmd := p.Update(progressStreamMsg{
		line:    ProgressLine{Text: "Another line"},
		updates: updates2,
		oldIP:   &oldIP,
		newIP:   &newIP,
	})

	if cmd == nil {
		t.Fatal("cmd should not be nil")
	}
	msg := cmd()
	done, ok := msg.(ProgressDoneMsg)
	if !ok {
		t.Fatalf("expected ProgressDoneMsg, got %T", msg)
	}
	if done.Success {
		t.Error("should not be success when error lines present")
	}
}

func TestProgressStreamMsgCapturesIP(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	updates := make(chan ProgressLine)
	close(updates)

	oldIP := "1.2.3.4"
	newIP := "5.6.7.8"
	_, cmd := p.Update(progressStreamMsg{
		line:    ProgressLine{Text: "Connected"},
		updates: updates,
		oldIP:   &oldIP,
		newIP:   &newIP,
	})

	if cmd == nil {
		t.Fatal("cmd should not be nil")
	}
	msg := cmd()
	done := msg.(ProgressDoneMsg)
	if done.OldIP != "1.2.3.4" {
		t.Errorf("OldIP = %q, want 1.2.3.4", done.OldIP)
	}
	if done.NewIP != "5.6.7.8" {
		t.Errorf("NewIP = %q, want 5.6.7.8", done.NewIP)
	}
}

func TestProgressViewConnectNoProvider(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "US-NY#42", "", false)
	view := p.View()

	if !strings.Contains(view, "US-NY#42") {
		t.Error("should show server name")
	}
}

func TestProgressViewSuccessNoIP(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	model, _ := p.Update(ProgressDoneMsg{Success: true})
	p = model.(Progress)
	view := p.View()

	if !strings.Contains(view, "Successfully connected") {
		t.Error("should show success")
	}
	// Should not show IP line when no IPs
	if strings.Contains(view, "Old IP") {
		t.Error("should not show IP line when no IPs")
	}
}

func TestProgressSpaceKeyWhenDone(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)
	model, _ := p.Update(ProgressDoneMsg{Success: true})
	p = model.(Progress)

	_, cmd := p.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	if cmd == nil {
		t.Fatal("space when done should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestProgressStreamMsgNilIPPointers(t *testing.T) {
	cfg := &config.Config{}
	p := NewConnectProgress(cfg, "test", "", false)

	updates := make(chan ProgressLine)
	close(updates)

	// nil IP pointers
	_, cmd := p.Update(progressStreamMsg{
		line:    ProgressLine{Text: "test"},
		updates: updates,
		oldIP:   nil,
		newIP:   nil,
	})

	if cmd == nil {
		t.Fatal("cmd should not be nil")
	}
	msg := cmd()
	done := msg.(ProgressDoneMsg)
	if done.OldIP != "" || done.NewIP != "" {
		t.Error("nil pointers should result in empty IP strings")
	}
}

// mockOsExecutable temporarily replaces osExecutable and restores on cleanup.
func mockOsExecutable(t *testing.T, fn func() (string, error)) {
	t.Helper()
	orig := osExecutable
	osExecutable = fn
	t.Cleanup(func() { osExecutable = orig })
}

// mockSpawnAndWaitForConnect temporarily replaces spawnAndWaitForConnect.
func mockSpawnAndWaitForConnect(t *testing.T, fn func(string, string, string, string, bool, daemon.ConnectCallback) (*daemon.Client, error)) {
	t.Helper()
	orig := spawnAndWaitForConnect
	spawnAndWaitForConnect = fn
	t.Cleanup(func() { spawnAndWaitForConnect = orig })
}

// mockWaitForDisconnect temporarily replaces waitForDisconnect.
func mockWaitForDisconnect(t *testing.T, fn func(string, daemon.ConnectCallback) error) {
	t.Helper()
	orig := waitForDisconnect
	waitForDisconnect = fn
	t.Cleanup(func() { waitForDisconnect = orig })
}

// mockGetPublicIP temporarily replaces getPublicIP.
func mockGetPublicIP(t *testing.T, ip string, err error) {
	t.Helper()
	orig := getPublicIP
	getPublicIP = func() (string, error) { return ip, err }
	t.Cleanup(func() { getPublicIP = orig })
}

// TestStartConnectSuccess exercises the startConnect method by mocking
// osExecutable and spawnAndWaitForConnect to simulate a successful connection.
func TestStartConnectSuccess(t *testing.T) {
	mockOsExecutable(t, func() (string, error) { return "/usr/bin/lazyvpn", nil })
	mockSpawnAndWaitForConnect(t, func(configDir, execPath, server, prov string, isDyn bool, cb daemon.ConnectCallback) (*daemon.Client, error) {
		// Simulate the daemon calling back with events
		cb(daemon.Event{Type: daemon.EventConnecting, Message: "Connecting..."})
		cb(daemon.Event{Type: daemon.EventConnected, Message: "Connected", OldIP: "1.1.1.1", PublicIP: "2.2.2.2"})
		return nil, nil
	})

	cfg := &config.Config{ConfigDir: t.TempDir()}
	p := NewConnectProgress(cfg, "US-NY#42", "protonvpn", true)
	cmd := p.startConnect()
	if cmd == nil {
		t.Fatal("startConnect should return a cmd")
	}

	msg := cmd()
	stream, ok := msg.(progressStreamMsg)
	if !ok {
		t.Fatalf("expected progressStreamMsg, got %T", msg)
	}
	if stream.line.Text != "Connecting..." {
		t.Errorf("first line = %q, want Connecting...", stream.line.Text)
	}

	// Drain remaining updates
	lines := []ProgressLine{stream.line}
	for line := range stream.updates {
		lines = append(lines, line)
	}
	if len(lines) < 2 {
		t.Errorf("expected at least 2 lines, got %d", len(lines))
	}
	// Check the connected line
	found := false
	for _, l := range lines {
		if l.Success && strings.Contains(l.Text, "Connected") {
			found = true
		}
	}
	if !found {
		t.Error("should have a success line with 'Connected'")
	}
	// Check captured IPs
	if *stream.oldIP != "1.1.1.1" {
		t.Errorf("capturedOldIP = %q, want 1.1.1.1", *stream.oldIP)
	}
	if *stream.newIP != "2.2.2.2" {
		t.Errorf("capturedNewIP = %q, want 2.2.2.2", *stream.newIP)
	}
}

// TestStartConnectExecError exercises startConnect when osExecutable fails.
func TestStartConnectExecError(t *testing.T) {
	mockOsExecutable(t, func() (string, error) { return "", fmt.Errorf("exec not found") })

	cfg := &config.Config{ConfigDir: t.TempDir()}
	p := NewConnectProgress(cfg, "test", "", false)
	cmd := p.startConnect()
	msg := cmd()

	stream, ok := msg.(progressStreamMsg)
	if !ok {
		t.Fatalf("expected progressStreamMsg, got %T", msg)
	}
	if !stream.line.Error {
		t.Error("line should be an error")
	}
	if !strings.Contains(stream.line.Text, "exec not found") {
		t.Errorf("line.Text = %q, want to contain 'exec not found'", stream.line.Text)
	}
}

// TestStartConnectDaemonError exercises startConnect when the daemon returns an error.
func TestStartConnectDaemonError(t *testing.T) {
	mockOsExecutable(t, func() (string, error) { return "/usr/bin/lazyvpn", nil })
	mockSpawnAndWaitForConnect(t, func(configDir, execPath, server, prov string, isDyn bool, cb daemon.ConnectCallback) (*daemon.Client, error) {
		cb(daemon.Event{Type: daemon.EventError, Message: "Connection refused", Error: "connection refused"})
		return nil, fmt.Errorf("connection refused")
	})

	cfg := &config.Config{ConfigDir: t.TempDir()}
	p := NewConnectProgress(cfg, "test", "", false)
	cmd := p.startConnect()
	msg := cmd()

	stream, ok := msg.(progressStreamMsg)
	if !ok {
		t.Fatalf("expected progressStreamMsg, got %T", msg)
	}
	// First line should be the error event
	if !stream.line.Error {
		t.Error("first line should be error")
	}

	// Drain and check for daemon error line
	var errLines []ProgressLine
	for line := range stream.updates {
		if line.Error {
			errLines = append(errLines, line)
		}
	}
	if len(errLines) == 0 {
		t.Error("should have error lines from daemon failure")
	}
}

// TestStartConnectEventTypes exercises all event type branches in the callback.
func TestStartConnectEventTypes(t *testing.T) {
	mockOsExecutable(t, func() (string, error) { return "/usr/bin/lazyvpn", nil })
	mockSpawnAndWaitForConnect(t, func(configDir, execPath, server, prov string, isDyn bool, cb daemon.ConnectCallback) (*daemon.Client, error) {
		cb(daemon.Event{Type: daemon.EventConnecting, Message: "Step 1"})
		cb(daemon.Event{Type: daemon.EventHealthFail, Message: "Health check failed"})
		cb(daemon.Event{Type: daemon.EventFailed, Message: "Failed", Error: "timeout"})
		cb(daemon.Event{Type: daemon.EventReconnected, Message: "Reconnected", OldIP: "3.3.3.3", PublicIP: "4.4.4.4"})
		return nil, nil
	})

	cfg := &config.Config{ConfigDir: t.TempDir()}
	p := NewConnectProgress(cfg, "test", "", false)
	cmd := p.startConnect()
	msg := cmd()

	stream := msg.(progressStreamMsg)
	var lines []ProgressLine
	lines = append(lines, stream.line)
	for line := range stream.updates {
		lines = append(lines, line)
	}

	// Should have at least 4 lines from the 4 events
	if len(lines) < 4 {
		t.Errorf("expected at least 4 lines, got %d", len(lines))
	}

	// Verify the muted line (health fail)
	foundMuted := false
	for _, l := range lines {
		if l.Muted {
			foundMuted = true
		}
	}
	if !foundMuted {
		t.Error("should have a muted line for EventHealthFail")
	}

	// Verify error line with Error field
	foundErrWithMsg := false
	for _, l := range lines {
		if l.Error && strings.Contains(l.Text, "timeout") {
			foundErrWithMsg = true
		}
	}
	if !foundErrWithMsg {
		t.Error("should have error line with 'timeout' from EventFailed")
	}
}

// TestStartDisconnectSuccess exercises the startDisconnect method.
func TestStartDisconnectSuccess(t *testing.T) {
	mockWaitForDisconnect(t, func(configDir string, cb daemon.ConnectCallback) error {
		cb(daemon.Event{Type: daemon.EventDisconnected, Message: "Disconnected"})
		return nil
	})
	mockGetPublicIP(t, "5.5.5.5", nil)

	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigDir:    tmpDir,
		ConfigFile:   tmpDir + "/config",
		LastPublicIP: "2.2.2.2",
	}

	p := NewDisconnectProgress(cfg)
	cmd := p.startDisconnect()
	if cmd == nil {
		t.Fatal("startDisconnect should return a cmd")
	}

	msg := cmd()
	stream, ok := msg.(progressStreamMsg)
	if !ok {
		t.Fatalf("expected progressStreamMsg, got %T", msg)
	}

	// First line should be the disconnect event
	if !stream.line.Success {
		t.Error("disconnect line should be success")
	}
	if !strings.Contains(stream.line.Text, "Disconnected") {
		t.Errorf("line.Text = %q, want to contain 'Disconnected'", stream.line.Text)
	}

	// Drain updates
	for range stream.updates {
	}

	// New IP should have been captured from getPublicIP mock
	if *stream.newIP != "5.5.5.5" {
		t.Errorf("newIP = %q, want 5.5.5.5", *stream.newIP)
	}
}

// TestStartDisconnectError exercises startDisconnect when the daemon errors.
func TestStartDisconnectError(t *testing.T) {
	mockWaitForDisconnect(t, func(configDir string, cb daemon.ConnectCallback) error {
		cb(daemon.Event{Type: daemon.EventError, Message: "Error", Error: "socket not found"})
		return fmt.Errorf("socket not found")
	})
	mockGetPublicIP(t, "", fmt.Errorf("no internet"))
	// Mock forceDisconnect to also fail so error lines are produced
	origForce := forceDisconnect
	forceDisconnect = func(cfg *config.Config) error {
		return fmt.Errorf("force disconnect failed")
	}
	t.Cleanup(func() { forceDisconnect = origForce })

	cfg := &config.Config{ConfigDir: t.TempDir()}
	cfg.ConfigFile = cfg.ConfigDir + "/config"

	p := NewDisconnectProgress(cfg)
	cmd := p.startDisconnect()
	msg := cmd()

	stream, ok := msg.(progressStreamMsg)
	if !ok {
		t.Fatalf("expected progressStreamMsg, got %T", msg)
	}

	// First line should be error
	if !stream.line.Error {
		t.Error("first line should be error")
	}

	// Drain and verify error line from daemon failure
	var errLines []ProgressLine
	for line := range stream.updates {
		if line.Error {
			errLines = append(errLines, line)
		}
	}
	if len(errLines) == 0 {
		t.Error("should have error lines from disconnect failure")
	}
}

// TestProgressInitConnect exercises Init() for a connect progress (calls startConnect).
func TestProgressInitConnect(t *testing.T) {
	mockOsExecutable(t, func() (string, error) { return "/usr/bin/lazyvpn", nil })
	mockSpawnAndWaitForConnect(t, func(configDir, execPath, server, prov string, isDyn bool, cb daemon.ConnectCallback) (*daemon.Client, error) {
		cb(daemon.Event{Type: daemon.EventConnected, Message: "Done"})
		return nil, nil
	})

	cfg := &config.Config{ConfigDir: t.TempDir()}
	p := NewConnectProgress(cfg, "test", "", false)
	cmd := p.Init()
	if cmd == nil {
		t.Fatal("Init should return a cmd for connect")
	}
	// Execute the command to verify it works
	msg := cmd()
	if msg == nil {
		t.Fatal("cmd should return a message")
	}
	// Drain the updates channel so the background goroutine finishes
	// before t.Cleanup restores the mock variables (avoids data race).
	if stream, ok := msg.(progressStreamMsg); ok {
		for range stream.updates {
		}
	}
}

// TestProgressInitDisconnect exercises Init() for a disconnect progress (calls startDisconnect).
func TestProgressInitDisconnect(t *testing.T) {
	mockWaitForDisconnect(t, func(configDir string, cb daemon.ConnectCallback) error {
		cb(daemon.Event{Type: daemon.EventDisconnected, Message: "Done"})
		return nil
	})
	mockGetPublicIP(t, "1.2.3.4", nil)

	cfg := &config.Config{ConfigDir: t.TempDir()}
	cfg.ConfigFile = cfg.ConfigDir + "/config"

	p := NewDisconnectProgress(cfg)
	cmd := p.Init()
	if cmd == nil {
		t.Fatal("Init should return a cmd for disconnect")
	}
	msg := cmd()
	if msg == nil {
		t.Fatal("cmd should return a message")
	}
	// Drain the updates channel so the background goroutine finishes
	// before t.Cleanup restores the mock variables (avoids data race).
	if stream, ok := msg.(progressStreamMsg); ok {
		for range stream.updates {
		}
	}
}

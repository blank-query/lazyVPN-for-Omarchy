package ui

import (
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

func TestNewRenameInterface(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)

	if m.state != RenameInput {
		t.Errorf("state = %d, want RenameInput", m.state)
	}
	if m.currentName != "wg0" {
		t.Errorf("currentName = %q", m.currentName)
	}
	if m.newName != "wg0" {
		t.Errorf("newName = %q", m.newName)
	}
}

func TestRenameInterfaceInit(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	if m.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestRenameInterfaceStateConstants(t *testing.T) {
	if RenameInput != 0 {
		t.Errorf("RenameInput = %d", RenameInput)
	}
	if RenameConfirm != 1 {
		t.Errorf("RenameConfirm = %d", RenameConfirm)
	}
	if RenameWorking != 2 {
		t.Errorf("RenameWorking = %d", RenameWorking)
	}
	if RenameDone != 3 {
		t.Errorf("RenameDone = %d", RenameDone)
	}
	if RenameError != 4 {
		t.Errorf("RenameError = %d", RenameError)
	}
}

func TestRenameInterfaceBackspace(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)

	// Backspace should remove last character
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	ri := model.(RenameInterface)
	if ri.newName != "wg" {
		t.Errorf("newName = %q, want %q", ri.newName, "wg")
	}
}

func TestRenameInterfaceTyping(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)

	// Type a character
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	ri := model.(RenameInterface)
	if ri.newName != "wg01" {
		t.Errorf("newName = %q, want %q", ri.newName, "wg01")
	}
}

func TestRenameInterfaceEmptyName(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.newName = ""

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	ri := model.(RenameInterface)
	if ri.error != "Name cannot be empty" {
		t.Errorf("error = %q", ri.error)
	}
	if ri.state != RenameInput {
		t.Error("should stay in RenameInput state")
	}
}

func TestRenameInterfaceUnchangedName(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	ri := model.(RenameInterface)
	if ri.error != "Name unchanged" {
		t.Errorf("error = %q", ri.error)
	}
}

func TestRenameInterfaceInvalidName(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.newName = "wg 0" // Space is invalid

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	ri := model.(RenameInterface)
	if !strings.Contains(ri.error, "Invalid name") {
		t.Errorf("error = %q, expected invalid name error", ri.error)
	}
}

func TestRenameInterfaceValidNameGoesToConfirm(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.newName = "lazyvpn0"

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	ri := model.(RenameInterface)
	if ri.state != RenameConfirm {
		t.Errorf("state = %d, want RenameConfirm", ri.state)
	}
	if ri.error != "" {
		t.Errorf("error = %q, should be empty", ri.error)
	}
}

func TestRenameInterfaceConfirmCancel(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.state = RenameConfirm

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	ri := model.(RenameInterface)
	if ri.state != RenameInput {
		t.Errorf("state = %d, want RenameInput", ri.state)
	}
}

func TestRenameInterfaceConfirmEsc(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.state = RenameConfirm

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	ri := model.(RenameInterface)
	if ri.state != RenameInput {
		t.Errorf("state = %d, want RenameInput", ri.state)
	}
}

func TestRenameInterfaceDoneState(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.state = RenameDone

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter in Done should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestRenameInterfaceErrorState(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.state = RenameError

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc in Error should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestRenameInterfaceEscFromInput(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestRenameInterfaceWindowSize(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	model, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	ri := model.(RenameInterface)
	if ri.width != 100 || ri.height != 30 {
		t.Errorf("size = %dx%d, want 100x30", ri.width, ri.height)
	}
}

func TestRenameInterfaceViewInput(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	view := m.View()

	if !strings.Contains(view, "Rename Interface") {
		t.Error("should contain title")
	}
	if !strings.Contains(view, "wg0") {
		t.Error("should show current name")
	}
	if !strings.Contains(view, "New name") {
		t.Error("should show input prompt")
	}
}

func TestRenameInterfaceViewError(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.error = "test error"
	view := m.View()

	if !strings.Contains(view, "test error") {
		t.Error("should show error message")
	}
}

func TestRenameInterfaceViewConfirm(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.state = RenameConfirm
	m.newName = "lazyvpn0"
	view := m.View()

	if !strings.Contains(view, "lazyvpn0") {
		t.Error("should show new name")
	}
	if !strings.Contains(view, "Confirm") {
		t.Error("should show confirm prompt")
	}
}

func TestRenameInterfaceViewDone(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.state = RenameDone
	m.newName = "lazyvpn0"
	view := m.View()

	if !strings.Contains(view, "lazyvpn0") {
		t.Error("should show new name")
	}
	if !strings.Contains(view, "Enter") {
		t.Error("should show continue prompt")
	}
}

func TestRenameInterfaceBackspaceOnEmpty(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.newName = ""

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	ri := model.(RenameInterface)
	if ri.newName != "" {
		t.Errorf("newName = %q, should stay empty", ri.newName)
	}
}

func TestRenameInterfaceRenameResultMsgWithError(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)

	model, _ := m.Update(renameResultMsg{err: errForTest("rename failed")})
	ri := model.(RenameInterface)
	if ri.state != RenameError {
		t.Errorf("state = %d, want RenameError", ri.state)
	}
	if ri.error != "rename failed" {
		t.Errorf("error = %q", ri.error)
	}
}

type errForTest string

func (e errForTest) Error() string { return string(e) }

func TestRenameInterfaceRenameResultMsgSuccess(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0", ConfigDir: t.TempDir()}
	cfg.ConfigFile = cfg.ConfigDir + "/config"
	m := NewRenameInterface(cfg)

	model, _ := m.Update(renameResultMsg{newName: "lazyvpn0"})
	ri := model.(RenameInterface)

	if ri.state != RenameDone {
		t.Errorf("state = %d, want RenameDone", ri.state)
	}
	if ri.currentName != "lazyvpn0" {
		t.Errorf("currentName = %q, want lazyvpn0", ri.currentName)
	}
	if cfg.ConnectionName != "lazyvpn0" {
		t.Errorf("cfg.ConnectionName = %q, want lazyvpn0", cfg.ConnectionName)
	}
}

// TestRenameInterfaceViewConfirmConnected tests that the confirm view shows
// a disconnect warning when isWGConnected returns true.
func TestRenameInterfaceViewConfirmConnected(t *testing.T) {
	mockConnected(t)

	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.state = RenameConfirm
	m.newName = "lazyvpn0"

	view := m.View()
	if !strings.Contains(view, "disconnected") {
		t.Error("should show disconnect warning when connected")
	}
}

// TestRenameInterfaceDoRenameNotConnected tests doRename when not connected.
func TestRenameInterfaceDoRenameNotConnected(t *testing.T) {
	mockDisconnected(t)

	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.currentName = "wg0"
	m.newName = "lazyvpn0"

	cmd := m.doRename()
	if cmd == nil {
		t.Fatal("doRename should return a command")
	}
	msg := cmd()
	result, ok := msg.(renameResultMsg)
	if !ok {
		t.Fatalf("expected renameResultMsg, got %T", msg)
	}
	if result.err != nil {
		t.Errorf("unexpected error: %v", result.err)
	}
	if result.newName != "lazyvpn0" {
		t.Errorf("newName = %q, want lazyvpn0", result.newName)
	}
}

func TestRenameInterfaceConfirmYes(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.state = RenameConfirm
	m.newName = "lazyvpn0"

	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	ri := model.(RenameInterface)
	if ri.state != RenameWorking {
		t.Errorf("state = %d, want RenameWorking", ri.state)
	}
	if cmd == nil {
		t.Error("y in confirm should return cmd")
	}
}

func TestRenameInterfaceViewWorking(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.state = RenameWorking

	view := m.View()
	if !strings.Contains(view, "Renaming") {
		t.Error("should show renaming message")
	}
}

func TestRenameInterfaceViewErrorState(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.state = RenameError
	m.error = "failed to disconnect"

	view := m.View()
	if !strings.Contains(view, "failed to disconnect") {
		t.Error("should show error message")
	}
}

func TestRenameInterfaceMaxLengthName(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}

	// 15 chars should be accepted (IFNAMSIZ - 1)
	m := NewRenameInterface(cfg)
	m.newName = "abcdefghijklmno" // exactly 15
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	ri := model.(RenameInterface)
	if ri.state != RenameConfirm {
		t.Errorf("15-char name: state = %d, want RenameConfirm", ri.state)
	}

	// 16+ chars should be rejected
	m2 := NewRenameInterface(cfg)
	m2.newName = "abcdefghijklmnop" // 16 chars
	model2, _ := m2.Update(tea.KeyMsg{Type: tea.KeyEnter})
	ri2 := model2.(RenameInterface)
	if ri2.state != RenameInput {
		t.Errorf("16-char name: state = %d, want RenameInput (rejected)", ri2.state)
	}
	if ri2.error == "" {
		t.Error("16-char name: expected error message")
	}
}

func TestRenameInterfaceSpecialCharsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		newName string
	}{
		{"space", "wg 0"},
		{"slash", "wg/0"},
		{"backslash", "wg\\0"},
		{"at sign", "wg@0"},
		{"exclamation", "wg!0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{ConnectionName: "wg0"}
			m := NewRenameInterface(cfg)
			m.newName = tt.newName

			model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
			ri := model.(RenameInterface)
			if ri.state != RenameInput {
				t.Errorf("state = %d, should stay in RenameInput for invalid char", ri.state)
			}
			if ri.error == "" {
				t.Error("should set error for invalid name")
			}
		})
	}
}

func TestRenameInterfaceDoneEsc(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.state = RenameDone

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc in Done should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestRenameInterfaceErrorEnter(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.state = RenameError

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter in Error should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

// mockWgDisconnect temporarily replaces wgDisconnect.
func mockWgDisconnect(t *testing.T, fn func(*config.Config) error) {
	t.Helper()
	orig := wgDisconnect
	wgDisconnect = fn
	t.Cleanup(func() { wgDisconnect = orig })
}

// TestDoRenameConnected exercises doRename when connected (triggers disconnect).
func TestDoRenameConnected(t *testing.T) {
	mockConnected(t)
	mockWgDisconnect(t, func(cfg *config.Config) error {
		return nil // successful disconnect
	})

	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.currentName = "wg0"
	m.newName = "lazyvpn0"

	cmd := m.doRename()
	if cmd == nil {
		t.Fatal("doRename should return a cmd")
	}
	msg := cmd()
	result, ok := msg.(renameResultMsg)
	if !ok {
		t.Fatalf("expected renameResultMsg, got %T", msg)
	}
	if result.err != nil {
		t.Errorf("unexpected error: %v", result.err)
	}
	if result.newName != "lazyvpn0" {
		t.Errorf("newName = %q, want lazyvpn0", result.newName)
	}
}

// TestDoRenameConnectedDisconnectFails exercises doRename when disconnect fails.
func TestDoRenameConnectedDisconnectFails(t *testing.T) {
	mockConnected(t)
	mockWgDisconnect(t, func(cfg *config.Config) error {
		return errForTest("disconnect failed")
	})

	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.currentName = "wg0"
	m.newName = "lazyvpn0"

	cmd := m.doRename()
	msg := cmd()
	result := msg.(renameResultMsg)
	if result.err == nil {
		t.Error("expected error from failed disconnect")
	}
	if !strings.Contains(result.err.Error(), "disconnect") {
		t.Errorf("error = %q, should contain 'disconnect'", result.err.Error())
	}
}

// TestDoRenameNotConnected exercises doRename when not connected.
func TestDoRenameNotConnected(t *testing.T) {
	mockDisconnected(t)

	cfg := &config.Config{ConnectionName: "wg0"}
	m := NewRenameInterface(cfg)
	m.currentName = "wg0"
	m.newName = "lazyvpn0"

	cmd := m.doRename()
	msg := cmd()
	result := msg.(renameResultMsg)
	if result.err != nil {
		t.Errorf("unexpected error: %v", result.err)
	}
	if result.newName != "lazyvpn0" {
		t.Errorf("newName = %q, want lazyvpn0", result.newName)
	}
}

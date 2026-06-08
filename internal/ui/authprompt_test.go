package ui

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
	tea "github.com/charmbracelet/bubbletea"
)

func TestAuthPrompt_ShowDismiss(t *testing.T) {
	var a AuthPrompt
	if a.Active() {
		t.Fatal("should not be active initially")
	}

	a.Show(func() {}, func() {})
	if !a.Active() {
		t.Fatal("should be active after Show")
	}

	a.Dismiss()
	if a.Active() {
		t.Fatal("should not be active after Dismiss")
	}
}

func TestAuthPrompt_NeedsAuth_ErrAuthRequired(t *testing.T) {
	var a AuthPrompt
	called := false
	err := fmt.Errorf("wrapped: %w", sudo.ErrAuthRequired)

	if !a.NeedsAuth(err, func() { called = true }, nil) {
		t.Fatal("NeedsAuth should return true for ErrAuthRequired")
	}
	if !a.Active() {
		t.Fatal("should be active after NeedsAuth")
	}

	// Simulate successful auth
	retryFn := a.HandleAuthResult(authResultMsg{err: nil})
	if retryFn == nil {
		t.Fatal("expected retryFn")
	}
	retryFn()
	if !called {
		t.Fatal("retry callback should have been called")
	}
}

func TestAuthPrompt_NeedsAuth_OtherError(t *testing.T) {
	var a AuthPrompt
	if a.NeedsAuth(fmt.Errorf("some other error"), nil, nil) {
		t.Fatal("NeedsAuth should return false for non-auth errors")
	}
	if a.Active() {
		t.Fatal("should not be active")
	}
}

func TestAuthPrompt_NeedsAuth_Nil(t *testing.T) {
	var a AuthPrompt
	if a.NeedsAuth(nil, nil, nil) {
		t.Fatal("NeedsAuth should return false for nil error")
	}
}

func TestAuthPrompt_HandleKey_EnterWithPassword(t *testing.T) {
	origAuth := firewallSudoAuth
	t.Cleanup(func() { firewallSudoAuth = origAuth })
	firewallSudoAuth = func(pw []byte) error {
		if string(pw) == "secret" {
			return nil
		}
		return fmt.Errorf("incorrect password")
	}

	var a AuthPrompt
	a.Show(func() {}, func() {})

	// Type password
	for _, ch := range "secret" {
		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}}
		handled, _ := a.HandleKey(msg)
		if !handled {
			t.Fatal("should handle rune input")
		}
	}

	// Press enter
	handled, cmd := a.HandleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !handled {
		t.Fatal("should handle enter")
	}
	if cmd == nil {
		t.Fatal("should return auth command")
	}
	if !a.loading {
		t.Fatal("should be loading")
	}
}

func TestAuthPrompt_HandleKey_EnterEmptyPassword(t *testing.T) {
	var a AuthPrompt
	a.Show(func() {}, func() {})

	handled, cmd := a.HandleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !handled {
		t.Fatal("should handle enter")
	}
	if cmd != nil {
		t.Fatal("should not return command for empty password")
	}
	if a.errMsg != "Password cannot be empty" {
		t.Errorf("errMsg = %q", a.errMsg)
	}
}

func TestAuthPrompt_HandleKey_Escape(t *testing.T) {
	cancelCalled := false
	var a AuthPrompt
	a.Show(func() {}, func() { cancelCalled = true })

	handled, _ := a.HandleKey(tea.KeyMsg{Type: tea.KeyEscape})
	if !handled {
		t.Fatal("should handle escape")
	}
	if a.Active() {
		t.Fatal("should dismiss on escape")
	}
	if !cancelCalled {
		t.Fatal("cancel callback should be called")
	}
}

func TestAuthPrompt_HandleKey_Backspace(t *testing.T) {
	var a AuthPrompt
	a.Show(func() {}, func() {})

	// Type some characters
	for _, ch := range "abc" {
		a.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}})
	}

	// Backspace
	handled, _ := a.HandleKey(tea.KeyMsg{Type: tea.KeyBackspace})
	if !handled {
		t.Fatal("should handle backspace")
	}
	if string(a.password) != "ab" {
		t.Errorf("password = %q after backspace, want %q", string(a.password), "ab")
	}
}

func TestAuthPrompt_HandleKey_BackspaceEmpty(t *testing.T) {
	var a AuthPrompt
	a.Show(func() {}, func() {})

	// Backspace on empty
	handled, _ := a.HandleKey(tea.KeyMsg{Type: tea.KeyBackspace})
	if !handled {
		t.Fatal("should handle backspace")
	}
	if len(a.password) != 0 {
		t.Errorf("password = %q, want empty", string(a.password))
	}
}

func TestAuthPrompt_HandleKey_IgnoredWhileLoading(t *testing.T) {
	var a AuthPrompt
	a.Show(func() {}, func() {})
	a.loading = true

	handled, cmd := a.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	if !handled {
		t.Fatal("should handle but ignore input while loading")
	}
	if cmd != nil {
		t.Fatal("should not return command while loading")
	}
}

func TestAuthPrompt_HandleKey_Inactive(t *testing.T) {
	var a AuthPrompt
	handled, _ := a.HandleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if handled {
		t.Fatal("should not handle keys when inactive")
	}
}

func TestAuthPrompt_HandleAuthResult_Success(t *testing.T) {
	retryCalled := false
	var a AuthPrompt
	a.Show(func() { retryCalled = true }, func() {})

	retryFn := a.HandleAuthResult(authResultMsg{err: nil})
	if retryFn == nil {
		t.Fatal("expected retry function")
	}
	retryFn()
	if !retryCalled {
		t.Fatal("retry should have been called")
	}
	if a.Active() {
		t.Fatal("should be dismissed after success")
	}
}

func TestAuthPrompt_HandleAuthResult_Failure(t *testing.T) {
	var a AuthPrompt
	a.Show(func() {}, func() {})
	a.password = []byte("wrong")

	retryFn := a.HandleAuthResult(authResultMsg{err: errors.New("incorrect password")})
	if retryFn != nil {
		t.Fatal("should not return retry on failure")
	}
	if !a.Active() {
		t.Fatal("should still be active after failure")
	}
	if a.errMsg != "incorrect password" {
		t.Errorf("errMsg = %q", a.errMsg)
	}
	if len(a.password) != 0 {
		t.Errorf("password should be cleared on failure, got %q", string(a.password))
	}
}

func TestAuthPrompt_View_Normal(t *testing.T) {
	var a AuthPrompt
	a.Show(func() {}, func() {})
	a.password = []byte("abc")

	view := a.View()
	if !strings.Contains(view, "Authentication Required") {
		t.Error("view should contain title")
	}
	if !strings.Contains(view, "***") {
		t.Error("view should mask password")
	}
	if !strings.Contains(view, "enter: authenticate") {
		t.Error("view should show key hints")
	}
}

func TestAuthPrompt_View_Loading(t *testing.T) {
	var a AuthPrompt
	a.Show(func() {}, func() {})
	a.loading = true

	view := a.View()
	if !strings.Contains(view, "Authenticating...") {
		t.Error("view should show loading state")
	}
	if !strings.Contains(view, "please wait...") {
		t.Error("view should show wait message")
	}
}

func TestAuthPrompt_View_Error(t *testing.T) {
	var a AuthPrompt
	a.Show(func() {}, func() {})
	a.errMsg = "incorrect password"

	view := a.View()
	if !strings.Contains(view, "incorrect password") {
		t.Error("view should show error message")
	}
}

func TestAuthPrompt_SetWidth(t *testing.T) {
	var a AuthPrompt
	a.SetWidth(40)
	if a.width != 40 {
		t.Errorf("width = %d, want 40", a.width)
	}
}

func TestAuthPrompt_HandleKey_Space(t *testing.T) {
	var a AuthPrompt
	a.Show(func() {}, func() {})

	handled, _ := a.HandleKey(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")})
	if !handled {
		t.Fatal("should handle space")
	}
	if string(a.password) != " " {
		t.Errorf("password = %q, want space", string(a.password))
	}
}

// TestAuthPrompt_PasswordGrowZerosOldBuffer verifies that when the
// password buffer's append needs to grow the backing array, the old
// array is zeroed before being orphaned. Without this, every grow
// leaves a copy of the partial password in process memory until GC.
func TestAuthPrompt_PasswordGrowZerosOldBuffer(t *testing.T) {
	var a AuthPrompt
	a.Show(func() {}, func() {})

	// Type one character to allocate the initial backing array.
	a.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("X")})
	old := a.password
	oldArray := old[:cap(old)]
	startCap := cap(a.password)

	// Type characters until we force a grow. We've forced 32 as min
	// cap in the impl, so 33 chars is enough to be sure.
	for i := 0; i < 64; i++ {
		a.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("Y")})
		if cap(a.password) != startCap {
			break
		}
	}
	if cap(a.password) == startCap {
		t.Fatalf("never triggered a grow (cap stayed at %d after 64 keys)", startCap)
	}

	// The old backing array (oldArray) must now be all zeros; the
	// "X" + however many "Y" bytes that fit in the old cap should
	// have been wiped before the grow.
	for i, b := range oldArray {
		if b != 0 {
			t.Errorf("old backing array byte %d = 0x%02x, want zero (password leaked)", i, b)
		}
	}

	// Sanity: current buffer still holds what we typed.
	if len(a.password) == 0 {
		t.Fatal("current password buffer is empty after grow")
	}
}

package ui

import (
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
)

// authResultMsg carries the result of an async sudo.Authenticate call.
type authResultMsg struct {
	err error
}

// AuthPrompt is a reusable embeddable component for sudo password prompts.
// Host models embed this and delegate key/msg handling when Active() is true.
// Uses []byte for password so the backing array can be explicitly zeroed.
type AuthPrompt struct {
	active   bool
	password []byte
	errMsg   string
	loading  bool
	retry    func()
	cancel   func()
	width    int
}

// Active returns whether the auth prompt is currently shown.
func (a *AuthPrompt) Active() bool {
	return a.active
}

// SetWidth updates the rendering width.
func (a *AuthPrompt) SetWidth(w int) {
	a.width = w
}

// Show activates the auth prompt with the given retry and cancel callbacks.
func (a *AuthPrompt) Show(retry, cancel func()) {
	a.active = true
	a.zeroPassword()
	a.errMsg = ""
	a.loading = false
	a.retry = retry
	a.cancel = cancel
}

// Dismiss hides the auth prompt and clears state.
func (a *AuthPrompt) Dismiss() {
	a.active = false
	a.zeroPassword()
	a.errMsg = ""
	a.loading = false
	a.retry = nil
	a.cancel = nil
}

// zeroPassword overwrites and clears the password buffer.
func (a *AuthPrompt) zeroPassword() {
	sudo.ZeroBytes(a.password)
	a.password = nil
}

// NeedsAuth checks if err wraps sudo.ErrAuthRequired. If so, it
// activates the prompt with the given callbacks and returns true.
func (a *AuthPrompt) NeedsAuth(err error, retry func(), cancel func()) bool {
	if err != nil && errors.Is(err, sudo.ErrAuthRequired) {
		a.Show(retry, cancel)
		return true
	}
	return false
}

// HandleKey processes a key event while the prompt is active.
// Returns (handled, cmd). If handled is true, the host model should
// return immediately with the given cmd.
func (a *AuthPrompt) HandleKey(msg tea.KeyMsg) (bool, tea.Cmd) {
	if !a.active {
		return false, nil
	}
	if a.loading {
		// Ignore all input while authentication is in progress.
		return true, nil
	}
	switch msg.String() {
	case "enter":
		if len(a.password) == 0 {
			a.errMsg = "Password cannot be empty"
			return true, nil
		}
		a.loading = true
		a.errMsg = ""
		// Copy password for the goroutine; zero the prompt's copy
		pw := make([]byte, len(a.password))
		copy(pw, a.password)
		a.zeroPassword()
		return true, func() tea.Msg {
			err := firewallSudoAuth(pw)
			sudo.ZeroBytes(pw)
			return authResultMsg{err: err}
		}
	case "esc":
		cancelFn := a.cancel
		a.Dismiss()
		if cancelFn != nil {
			cancelFn()
		}
		return true, nil
	case "backspace":
		if len(a.password) > 0 {
			// Zero the last byte before truncating
			a.password[len(a.password)-1] = 0
			a.password = a.password[:len(a.password)-1]
		}
		return true, nil
	default:
		if msg.Type == tea.KeyRunes || msg.Type == tea.KeySpace {
			b := []byte(msg.String())
			// Manual grow-and-zero: a plain append would leave the old
			// backing array (containing partial password bytes) in
			// memory until GC. We can't help the transient `b` and
			// msg.String() copies bubbletea hands us, but we can keep
			// our own buffer from leaving a trail.
			needLen := len(a.password) + len(b)
			if needLen > cap(a.password) {
				newCap := needLen * 2
				if newCap < 32 {
					newCap = 32
				}
				newPw := make([]byte, len(a.password), newCap)
				copy(newPw, a.password)
				sudo.ZeroBytes(a.password)
				a.password = newPw
			}
			a.password = append(a.password, b...)
			// Zero the transient byte slice — its backing array is now
			// orphaned and the runes are still in it.
			sudo.ZeroBytes(b)
		}
		return true, nil
	}
}

// HandleAuthResult processes an authResultMsg. If authentication succeeded,
// it returns the retry function (non-nil). The caller should invoke it.
// If authentication failed, it resets the prompt for another attempt.
func (a *AuthPrompt) HandleAuthResult(msg authResultMsg) func() {
	a.loading = false
	if msg.err != nil {
		a.errMsg = msg.err.Error()
		a.zeroPassword()
		return nil
	}
	// Auth succeeded — credentials are now cached.
	retryFn := a.retry
	a.Dismiss()
	return retryFn
}

// View renders the auth prompt overlay.
func (a *AuthPrompt) View() string {
	boxWidth := 50
	if a.width > 0 && a.width < 60 {
		boxWidth = a.width - 6
	}

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAccent).
		Padding(1, 2).
		Width(boxWidth)

	titleLine := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorAccent).
		Render("Authentication Required")

	var content strings.Builder
	content.WriteString(titleLine + "\n\n")

	if a.loading {
		content.WriteString("  Authenticating...\n")
	} else {
		dots := strings.Repeat("*", len(a.password))
		inputLine := fmt.Sprintf("  Password: %s", dots+"\u2588")
		content.WriteString(inputLine + "\n")
	}

	if a.errMsg != "" {
		content.WriteString("\n" + ErrorStyle.Render("  "+a.errMsg))
	}

	if a.loading {
		content.WriteString("\n\n" + MutedStyle.Render("  please wait..."))
	} else {
		content.WriteString("\n\n" + MutedStyle.Render("  enter: authenticate  esc: cancel"))
	}

	return boxStyle.Render(content.String()) + "\n"
}

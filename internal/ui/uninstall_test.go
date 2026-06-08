package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNewUninstallConfirm(t *testing.T) {
	m := NewUninstallConfirm()
	if m.selected != 0 {
		t.Errorf("selected = %d, want 0 (Cancel)", m.selected)
	}
}

func TestUninstallConfirmInit(t *testing.T) {
	m := NewUninstallConfirm()
	cmd := m.Init()
	if cmd != nil {
		t.Error("Init should return nil")
	}
}

func TestUninstallConfirmNavigateLeft(t *testing.T) {
	m := NewUninstallConfirm()
	m.selected = 1
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	uc := model.(UninstallConfirm)
	if uc.selected != 0 {
		t.Errorf("selected = %d, want 0", uc.selected)
	}
}

func TestUninstallConfirmNavigateRight(t *testing.T) {
	m := NewUninstallConfirm()
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRight})
	uc := model.(UninstallConfirm)
	if uc.selected != 1 {
		t.Errorf("selected = %d, want 1", uc.selected)
	}
}

func TestUninstallConfirmTab(t *testing.T) {
	m := NewUninstallConfirm()
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	uc := model.(UninstallConfirm)
	if uc.selected != 1 {
		t.Errorf("first tab: selected = %d, want 1", uc.selected)
	}

	model, _ = uc.Update(tea.KeyMsg{Type: tea.KeyTab})
	uc = model.(UninstallConfirm)
	if uc.selected != 0 {
		t.Errorf("second tab: selected = %d, want 0", uc.selected)
	}
}

func TestUninstallConfirmEscBack(t *testing.T) {
	m := NewUninstallConfirm()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestUninstallConfirmNBack(t *testing.T) {
	m := NewUninstallConfirm()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if cmd == nil {
		t.Fatal("n should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestUninstallConfirmYShortcut(t *testing.T) {
	m := NewUninstallConfirm()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if cmd == nil {
		t.Fatal("y should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(RunUninstallMsg); !ok {
		t.Errorf("expected RunUninstallMsg, got %T", msg)
	}
}

func TestUninstallConfirmEnterCancel(t *testing.T) {
	m := NewUninstallConfirm()
	m.selected = 0 // Cancel
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter on Cancel should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestUninstallConfirmEnterConfirm(t *testing.T) {
	m := NewUninstallConfirm()
	m.selected = 1 // Confirm
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter on Confirm should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(RunUninstallMsg); !ok {
		t.Errorf("expected RunUninstallMsg, got %T", msg)
	}
}

func TestUninstallConfirmWindowSize(t *testing.T) {
	m := NewUninstallConfirm()
	model, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	uc := model.(UninstallConfirm)
	if uc.width != 120 || uc.height != 40 {
		t.Errorf("size = %dx%d, want 120x40", uc.width, uc.height)
	}
}

func TestUninstallConfirmView(t *testing.T) {
	m := NewUninstallConfirm()
	m.width = 80
	m.height = 30
	view := m.View()

	if !strings.Contains(view, "Uninstall LazyVPN") {
		t.Error("should contain title")
	}
	if !strings.Contains(view, "WARNING") {
		t.Error("should contain warning")
	}
	if !strings.Contains(view, "Cancel") {
		t.Error("should contain Cancel button")
	}
	if !strings.Contains(view, "Uninstall") {
		t.Error("should contain Uninstall button")
	}
}

func TestUninstallConfirmViewConfirmSelected(t *testing.T) {
	m := NewUninstallConfirm()
	m.selected = 1 // Uninstall button selected
	m.width = 80
	m.height = 30

	view := m.View()
	if !strings.Contains(view, "Uninstall") {
		t.Error("should contain Uninstall button")
	}
	if !strings.Contains(view, "Cancel") {
		t.Error("should contain Cancel button")
	}
}

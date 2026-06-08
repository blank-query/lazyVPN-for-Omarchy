package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNewTutorial(t *testing.T) {
	tut := NewTutorial()
	if len(tut.pages) == 0 {
		t.Fatal("tutorial should have pages")
	}
	if tut.current != 0 {
		t.Errorf("initial page = %d, want 0", tut.current)
	}
	// First page should be Welcome
	if tut.pages[0].title != "Welcome" {
		t.Errorf("first page title = %q, want Welcome", tut.pages[0].title)
	}
}

func TestTutorialInit(t *testing.T) {
	tut := NewTutorial()
	cmd := tut.Init()
	if cmd != nil {
		t.Error("Init should return nil")
	}
}

func TestTutorialNavigateForward(t *testing.T) {
	tut := NewTutorial()
	numPages := len(tut.pages)

	// Navigate forward through all pages
	for i := 0; i < numPages-1; i++ {
		model, _ := tut.Update(tea.KeyMsg{Type: tea.KeyRight})
		tut = model.(Tutorial)
		if tut.current != i+1 {
			t.Errorf("after %d right presses: current = %d, want %d", i+1, tut.current, i+1)
		}
	}

	// At last page, pressing right should trigger BackMsg (returns cmd)
	_, cmd := tut.Update(tea.KeyMsg{Type: tea.KeyRight})
	if cmd == nil {
		t.Error("pressing right on last page should return a cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestTutorialNavigateBackward(t *testing.T) {
	tut := NewTutorial()

	// Move to page 2
	model, _ := tut.Update(tea.KeyMsg{Type: tea.KeyRight})
	tut = model.(Tutorial)
	model, _ = tut.Update(tea.KeyMsg{Type: tea.KeyRight})
	tut = model.(Tutorial)
	if tut.current != 2 {
		t.Fatalf("current = %d, want 2", tut.current)
	}

	// Navigate back
	model, _ = tut.Update(tea.KeyMsg{Type: tea.KeyLeft})
	tut = model.(Tutorial)
	if tut.current != 1 {
		t.Errorf("after left: current = %d, want 1", tut.current)
	}

	// At first page, pressing left should stay at 0
	model, _ = tut.Update(tea.KeyMsg{Type: tea.KeyLeft})
	tut = model.(Tutorial)
	model, _ = tut.Update(tea.KeyMsg{Type: tea.KeyLeft})
	tut = model.(Tutorial)
	if tut.current != 0 {
		t.Errorf("should stay at 0, got %d", tut.current)
	}
}

func TestTutorialEsc(t *testing.T) {
	tut := NewTutorial()
	_, cmd := tut.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return a cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestTutorialHomeEnd(t *testing.T) {
	tut := NewTutorial()
	numPages := len(tut.pages)

	// Go to end
	model, _ := tut.Update(tea.KeyMsg{Type: tea.KeyEnd})
	tut = model.(Tutorial)
	if tut.current != numPages-1 {
		t.Errorf("after end: current = %d, want %d", tut.current, numPages-1)
	}

	// Go to home
	model, _ = tut.Update(tea.KeyMsg{Type: tea.KeyHome})
	tut = model.(Tutorial)
	if tut.current != 0 {
		t.Errorf("after home: current = %d, want 0", tut.current)
	}
}

func TestTutorialWindowSize(t *testing.T) {
	tut := NewTutorial()
	model, _ := tut.Update(tea.WindowSizeMsg{Width: 100, Height: 50})
	tut = model.(Tutorial)
	if tut.width != 100 {
		t.Errorf("width = %d, want 100", tut.width)
	}
	if tut.height != 50 {
		t.Errorf("height = %d, want 50", tut.height)
	}
}

func TestTutorialView(t *testing.T) {
	tut := NewTutorial()
	view := tut.View()

	// Should contain the first page title
	if !strings.Contains(view, "Welcome") {
		t.Error("view should contain 'Welcome'")
	}
	// Should contain page indicator
	if !strings.Contains(view, "1/") {
		t.Error("view should contain page indicator '1/'")
	}
	// Should contain navigation hints
	if !strings.Contains(view, "next") {
		t.Error("view should contain 'next'")
	}
}

func TestTutorialViewLastPage(t *testing.T) {
	tut := NewTutorial()
	numPages := len(tut.pages)

	// Navigate to last page
	for i := 0; i < numPages-1; i++ {
		model, _ := tut.Update(tea.KeyMsg{Type: tea.KeyRight})
		tut = model.(Tutorial)
	}

	view := tut.View()
	// Last page should show "finish" instead of "next"
	if !strings.Contains(view, "finish") {
		t.Error("last page should show 'finish'")
	}
}

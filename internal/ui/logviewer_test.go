package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

func TestReadLastLines(t *testing.T) {
	dir := t.TempDir()

	t.Run("file does not exist", func(t *testing.T) {
		lines := readLastLines(filepath.Join(dir, "nonexistent"), 10)
		if len(lines) != 1 || lines[0] != "(No log file exists)" {
			t.Errorf("got %v", lines)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(dir, "empty.log")
		os.WriteFile(path, []byte{}, 0644)
		lines := readLastLines(path, 10)
		if len(lines) != 1 || lines[0] != "(Log file is empty)" {
			t.Errorf("got %v", lines)
		}
	})

	t.Run("fewer lines than max", func(t *testing.T) {
		path := filepath.Join(dir, "short.log")
		os.WriteFile(path, []byte("line1\nline2\nline3\n"), 0644)
		lines := readLastLines(path, 10)
		if len(lines) != 3 {
			t.Errorf("expected 3 lines, got %d: %v", len(lines), lines)
		}
	})

	t.Run("more lines than max", func(t *testing.T) {
		path := filepath.Join(dir, "long.log")
		var content strings.Builder
		for i := 0; i < 20; i++ {
			content.WriteString("line\n")
		}
		os.WriteFile(path, []byte(content.String()), 0644)
		lines := readLastLines(path, 5)
		if len(lines) != 5 {
			t.Errorf("expected 5 lines, got %d", len(lines))
		}
	})

	t.Run("exact max", func(t *testing.T) {
		path := filepath.Join(dir, "exact.log")
		os.WriteFile(path, []byte("a\nb\nc\n"), 0644)
		lines := readLastLines(path, 3)
		if len(lines) != 3 {
			t.Errorf("expected 3 lines, got %d", len(lines))
		}
	})
}

// TestReadLastLinesPreservesAfterOversizedLine verifies that the log
// viewer does not silently hide log lines that come after a single
// >64KB line.
//
// Pre-fix: bufio.Scanner's default 64KB max-token buffer caused Scan()
// to terminate at the oversized line; readLastLines returned the
// "last 100 lines" from a partial slice that ended BEFORE the
// oversized one, hiding all subsequent log entries from the user.
func TestReadLastLinesPreservesAfterOversizedLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.log")

	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString("filler-pre\n")
	}
	// 100KB line — exceeds the default 64KB scanner buffer.
	b.WriteString(strings.Repeat("A", 100*1024))
	b.WriteString("\n")
	for i := 0; i < 50; i++ {
		b.WriteString("filler-post\n")
	}
	b.WriteString("POST-OVERSIZE-MARKER\n")
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	lines := readLastLines(path, 100)

	found := false
	for _, l := range lines {
		if strings.Contains(l, "POST-OVERSIZE-MARKER") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("readLastLines silently hid lines that came after an oversized line — POST-OVERSIZE-MARKER not present in returned 'last 100 lines'")
	}
}

func TestLogViewerVisibleLines(t *testing.T) {
	tests := []struct {
		name   string
		height int
		want   int
	}{
		{"zero height returns default", 0, 20},
		{"small height returns minimum", 8, 5},
		{"very small height returns minimum", 3, 5},
		{"normal height", 30, 24},
		{"large height", 50, 44},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := LogViewer{height: tt.height}
			got := m.visibleLines()
			if got != tt.want {
				t.Errorf("visibleLines() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestLogViewerUpdate(t *testing.T) {
	lines := make([]string, 50)
	for i := range lines {
		lines[i] = "log line"
	}
	cfg := &config.Config{}

	t.Run("scroll down", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: lines, height: 20}
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		lv := model.(LogViewer)
		if lv.scroll != 1 {
			t.Errorf("scroll = %d, want 1", lv.scroll)
		}
	})

	t.Run("scroll up from top stays at 0", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: lines, scroll: 0}
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
		lv := model.(LogViewer)
		if lv.scroll != 0 {
			t.Errorf("scroll = %d, want 0", lv.scroll)
		}
	})

	t.Run("scroll up from middle", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: lines, scroll: 5, height: 20}
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
		lv := model.(LogViewer)
		if lv.scroll != 4 {
			t.Errorf("scroll = %d, want 4", lv.scroll)
		}
	})

	t.Run("home key", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: lines, scroll: 20, height: 20}
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyHome})
		lv := model.(LogViewer)
		if lv.scroll != 0 {
			t.Errorf("scroll = %d, want 0", lv.scroll)
		}
	})

	t.Run("end key", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: lines, scroll: 0, height: 20}
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnd})
		lv := model.(LogViewer)
		// maxScroll = 50 - 14 = 36
		if lv.scroll != 36 {
			t.Errorf("scroll = %d, want 36", lv.scroll)
		}
	})

	t.Run("pgdown", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: lines, scroll: 0, height: 20}
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
		lv := model.(LogViewer)
		if lv.scroll != 10 {
			t.Errorf("scroll = %d, want 10", lv.scroll)
		}
	})

	t.Run("pgup", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: lines, scroll: 15, height: 20}
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyPgUp})
		lv := model.(LogViewer)
		if lv.scroll != 5 {
			t.Errorf("scroll = %d, want 5", lv.scroll)
		}
	})

	t.Run("pgup clamps to 0", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: lines, scroll: 3, height: 20}
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyPgUp})
		lv := model.(LogViewer)
		if lv.scroll != 0 {
			t.Errorf("scroll = %d, want 0", lv.scroll)
		}
	})

	t.Run("esc returns BackMsg", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: lines}
		_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
		if cmd == nil {
			t.Fatal("expected cmd")
		}
		msg := cmd()
		if _, ok := msg.(BackMsg); !ok {
			t.Errorf("expected BackMsg, got %T", msg)
		}
	})

	t.Run("window size", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: lines}
		model, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
		lv := model.(LogViewer)
		if lv.width != 100 || lv.height != 30 {
			t.Errorf("size = %dx%d, want 100x30", lv.width, lv.height)
		}
	})

	t.Run("few lines no over-scroll", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: []string{"a", "b"}, height: 20}
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		lv := model.(LogViewer)
		if lv.scroll != 0 {
			t.Errorf("scroll = %d, want 0 (fewer lines than visible)", lv.scroll)
		}
	})
}

func TestLogViewerView(t *testing.T) {
	cfg := &config.Config{}

	t.Run("basic view", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: []string{"hello", "world"}, width: 80, height: 20}
		view := m.View()
		if !strings.Contains(view, "Debug Log") {
			t.Error("should contain title")
		}
		if !strings.Contains(view, "hello") {
			t.Error("should contain log line")
		}
	})

	t.Run("scroll indicator shown when needed", func(t *testing.T) {
		lines := make([]string, 50)
		for i := range lines {
			lines[i] = "line"
		}
		m := LogViewer{cfg: cfg, lines: lines, width: 80, height: 20}
		view := m.View()
		if !strings.Contains(view, "Line") {
			t.Error("should show scroll position indicator")
		}
	})

	t.Run("long lines truncated", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: []string{strings.Repeat("x", 200)}, width: 50, height: 20}
		view := m.View()
		if view == "" {
			t.Error("view should not be empty")
		}
	})

	t.Run("pgdown clamps to max scroll", func(t *testing.T) {
		lines := make([]string, 50)
		for i := range lines {
			lines[i] = "line"
		}
		m := LogViewer{cfg: cfg, lines: lines, scroll: 35, height: 20}
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
		lv := model.(LogViewer)
		// maxScroll = 50 - 14 = 36, scroll + 10 = 45 > 36
		if lv.scroll != 36 {
			t.Errorf("scroll = %d, want 36 (clamped to max)", lv.scroll)
		}
	})

	t.Run("end key with few lines", func(t *testing.T) {
		m := LogViewer{cfg: cfg, lines: []string{"a", "b"}, height: 20}
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnd})
		lv := model.(LogViewer)
		if lv.scroll != 0 {
			t.Errorf("scroll = %d, want 0 (fewer lines than visible)", lv.scroll)
		}
	})
}

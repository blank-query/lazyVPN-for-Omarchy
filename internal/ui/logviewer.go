package ui

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

// LogViewer displays the debug log
type LogViewer struct {
	cfg    *config.Config
	lines  []string
	scroll int
	width  int
	height int
}

// NewLogViewer creates a new log viewer
func NewLogViewer(cfg *config.Config) LogViewer {
	logFile := filepath.Join(cfg.ConfigDir, "debug.log")
	lines := readLastLines(logFile, 100)

	return LogViewer{
		cfg:   cfg,
		lines: lines,
	}
}

func readLastLines(path string, maxLines int) []string {
	file, err := os.Open(path)
	if err != nil {
		return []string{"(No log file exists)"}
	}
	defer file.Close()

	var allLines []string
	scanner := bufio.NewScanner(file)
	// Raise buffer cap to 1MB so a single oversized log line (sanitized
	// HTTP body, long subprocess stderr, stack trace) doesn't trip
	// bufio.ErrTooLong and cause the viewer to silently show only lines
	// from BEFORE the oversized one as the "last 100 lines."
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		allLines = append(allLines, scanner.Text())
	}

	if len(allLines) == 0 {
		return []string{"(Log file is empty)"}
	}

	// Return last N lines
	if len(allLines) > maxLines {
		return allLines[len(allLines)-maxLines:]
	}
	return allLines
}

func (m LogViewer) Init() tea.Cmd {
	return nil
}

func (m LogViewer) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, func() tea.Msg { return BackMsg{} }
		case "up":
			if m.scroll > 0 {
				m.scroll--
			}
		case "down":
			maxScroll := len(m.lines) - m.visibleLines()
			if maxScroll < 0 {
				maxScroll = 0
			}
			if m.scroll < maxScroll {
				m.scroll++
			}
		case "home":
			m.scroll = 0
		case "end":
			maxScroll := len(m.lines) - m.visibleLines()
			if maxScroll < 0 {
				maxScroll = 0
			}
			m.scroll = maxScroll
		case "pgup":
			m.scroll -= 10
			if m.scroll < 0 {
				m.scroll = 0
			}
		case "pgdown":
			m.scroll += 10
			maxScroll := len(m.lines) - m.visibleLines()
			if maxScroll < 0 {
				maxScroll = 0
			}
			if m.scroll > maxScroll {
				m.scroll = maxScroll
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m LogViewer) visibleLines() int {
	if m.height == 0 {
		return 20
	}
	visible := m.height - 6
	if visible < 5 {
		visible = 5
	}
	return visible
}

func (m LogViewer) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("Debug Log") + "\n\n")

	visible := m.visibleLines()
	end := m.scroll + visible
	if end > len(m.lines) {
		end = len(m.lines)
	}

	for i := m.scroll; i < end; i++ {
		line := m.lines[i]
		// Truncate long lines
		if m.width > 7 && len(line) > m.width-4 {
			line = line[:m.width-7] + "..."
		}
		b.WriteString("  " + line + "\n")
	}

	// Scroll indicator
	if len(m.lines) > visible {
		b.WriteString("\n" + MutedStyle.Render("  "+strings.Repeat("─", 40)))
		b.WriteString("\n" + MutedStyle.Render("  Line "+strconv.Itoa(m.scroll+1)+"-"+strconv.Itoa(end)+" of "+strconv.Itoa(len(m.lines))))
	}

	b.WriteString("\n\n" + MutedStyle.Render("  up/down: scroll  home/end: top/bottom  esc: back"))

	return b.String()
}

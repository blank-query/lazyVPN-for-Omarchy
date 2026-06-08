package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

type debugItem struct {
	id          string
	name        string
	value       string
	description string
	isToggle    bool
	isAction    bool
}

// DebugSettings is a sub-view for debug logging and UFW packet log settings.
type DebugSettings struct {
	items      []debugItem
	cursor     int
	cfg        *config.Config
	width      int
	height     int
	message    string
	messageErr bool
	focused    bool
}

// SetFocused sets the focus state for cursor visibility.
func (m *DebugSettings) SetFocused(focused bool) {
	m.focused = focused
}

// NewDebugSettings creates a new debug settings sub-view.
func NewDebugSettings(cfg *config.Config) *DebugSettings {
	d := &DebugSettings{cfg: cfg}
	d.items = d.buildItems()
	return d
}

func (m *DebugSettings) buildItems() []debugItem {
	cfg := m.cfg

	onOff := func(b bool) string {
		if b {
			return "ON"
		}
		return "OFF"
	}

	return []debugItem{
		{id: "log-connection", name: "Log Connections", value: onOff(cfg.LogConnection), description: "Log connection events", isToggle: true},
		{id: "log-autorecover", name: "Log Auto-Recover", value: onOff(cfg.LogAutorecover), description: "Log auto-recover daemon events", isToggle: true},
		{id: "log-firewall", name: "Log Firewall Events", value: onOff(cfg.LogFirewall), description: "Log killswitch/firewall events", isToggle: true},
		{id: "log-provider", name: "Log Provider", value: onOff(cfg.LogProvider), description: "Log provider detection and config parsing", isToggle: true},
		{id: "log-autostart", name: "Log Autostart", value: onOff(cfg.LogAutostart), description: "Log boot-time autoconnect decisions", isToggle: true},
		{id: "log-mode", name: "Log Mode", value: logModeDisplay(cfg.LogMode), description: "Safe: redacts IPs/keys | Accurate: full details"},
		{id: "view-log", name: "View Debug Log", value: "", description: "Show recent log entries", isAction: true},
		{id: "clear-log", name: "Clear Debug Log", value: "", description: "Delete all debug logs", isAction: true},
		{id: "ufw-logging", name: "UFW Packet Log", value: firewallGetLoggingLevel(), description: "off → low → medium → high → full"},
	}
}

func (m *DebugSettings) Init() tea.Cmd {
	return nil
}

func (m *DebugSettings) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		m.message = ""
		m.messageErr = false
		switch msg.String() {
		case "esc":
			return m, func() tea.Msg { return BackMsg{} }
		case "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case "enter", " ":
			return m.handleSelection()
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m *DebugSettings) handleSelection() (tea.Model, tea.Cmd) {
	if m.cursor >= len(m.items) {
		return m, nil
	}

	item := m.items[m.cursor]

	switch item.id {
	case "log-connection":
		// Flip then Save; on Save failure flip back so in-memory matches
		// the (unchanged) on-disk state. cfg.Save is atomic — without
		// the revert, in-memory says "toggled" while disk says "old
		// value" and the toggle silently un-toggles on TUI restart.
		// Same drift class as 9b3ede7 / 11ec77f / etc.
		m.cfg.LogConnection = !m.cfg.LogConnection
		if err := m.cfg.Save(); err != nil {
			m.cfg.LogConnection = !m.cfg.LogConnection
		}
	case "log-autorecover":
		m.cfg.LogAutorecover = !m.cfg.LogAutorecover
		if err := m.cfg.Save(); err != nil {
			m.cfg.LogAutorecover = !m.cfg.LogAutorecover
		}
	case "log-firewall":
		m.cfg.LogFirewall = !m.cfg.LogFirewall
		if err := m.cfg.Save(); err != nil {
			m.cfg.LogFirewall = !m.cfg.LogFirewall
		}
	case "log-provider":
		m.cfg.LogProvider = !m.cfg.LogProvider
		if err := m.cfg.Save(); err != nil {
			m.cfg.LogProvider = !m.cfg.LogProvider
		}
	case "log-autostart":
		m.cfg.LogAutostart = !m.cfg.LogAutostart
		if err := m.cfg.Save(); err != nil {
			m.cfg.LogAutostart = !m.cfg.LogAutostart
		}
	case "log-mode":
		prev := m.cfg.LogMode
		if m.cfg.LogMode == "safe" || m.cfg.LogMode == "" {
			m.cfg.LogMode = "accurate"
		} else {
			m.cfg.LogMode = "safe"
		}
		if err := m.cfg.Save(); err != nil {
			m.cfg.LogMode = prev
		}
	case "view-log":
		return m, func() tea.Msg {
			return SwitchViewMsg{View: "view-log"}
		}
	case "clear-log":
		logFile := filepath.Join(m.cfg.ConfigDir, "debug.log")
		if err := os.Remove(logFile); err != nil && !os.IsNotExist(err) {
			m.message = "Failed to clear log"
			m.messageErr = true
			notifyError(m.message)
		} else {
			m.message = "Debug log cleared"
			notifyInfo("LazyVPN", m.message)
		}
	case "ufw-logging":
		levels := []string{"off", "low", "medium", "high", "full"}
		current := firewallGetLoggingLevel()
		next := levels[0]
		for i, l := range levels {
			if l == current {
				next = levels[(i+1)%len(levels)]
				break
			}
		}
		if err := firewallSetLogging(next); err != nil {
			m.message = fmt.Sprintf("Error: %v", err)
			m.messageErr = true
		}
	}

	m.items = m.buildItems()
	return m, nil
}

func (m *DebugSettings) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("Debug & Logs") + "\n\n")

	for i, item := range m.items {
		cursor := "  "
		if i == m.cursor && m.focused {
			cursor = "> "
		}

		value := ""
		if item.value != "" {
			value = fmt.Sprintf(" [%s]", item.value)
		}

		name := item.name + value
		if m.focused && i == m.cursor {
			name = SelectedStyle.Render(name)
		}
		b.WriteString(cursor + name + "\n")

		// Show description for selected item
		if i == m.cursor {
			b.WriteString("    " + MutedStyle.Render(item.description) + "\n")
		}
	}

	if m.message != "" {
		style := SuccessStyle
		if m.messageErr {
			style = ErrorStyle
		}
		b.WriteString("\n" + style.Render("  "+m.message) + "\n")
	}

	b.WriteString("\n" + MutedStyle.Render("  enter: toggle/select  esc: back"))

	return b.String()
}

// CurrentDescription returns the description of the currently selected item,
// or a status message if one is set.
func (m *DebugSettings) CurrentDescription() string {
	if m.message != "" {
		return m.message
	}
	if m.cursor < len(m.items) {
		return m.items[m.cursor].description
	}
	return ""
}

// StatusIsError returns true when the current status message is an error.
func (m *DebugSettings) StatusIsError() bool {
	return m.message != "" && m.messageErr
}

// debugSummary returns a string like "2/5 enabled" counting how many
// of the 5 log booleans are ON.
func debugSummary(cfg *config.Config) string {
	count := countEnabledLogs(cfg)
	return fmt.Sprintf("%d/5 enabled", count)
}

// countEnabledLogs returns the number of enabled debug log booleans.
func countEnabledLogs(cfg *config.Config) int {
	count := 0
	if cfg.LogConnection {
		count++
	}
	if cfg.LogAutorecover {
		count++
	}
	if cfg.LogFirewall {
		count++
	}
	if cfg.LogProvider {
		count++
	}
	if cfg.LogAutostart {
		count++
	}
	return count
}

package ui

import (
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	htPingTarget = iota
	htDNSHost
	htAddPing
	htResetDefaults
)

type healthTargetItem struct {
	itemType int
	value    string
}

// HealthTargets is a sub-view for editing health check ping targets and DNS probe host.
type HealthTargets struct {
	cfg     *config.Config
	items   []healthTargetItem
	cursor  int
	editing bool
	editBuf string
	message string
	width   int
	height  int
	focused bool
}

// SetFocused sets the focus state for cursor visibility.
func (m *HealthTargets) SetFocused(focused bool) {
	m.focused = focused
}

// NewHealthTargets creates a new health targets editor.
func NewHealthTargets(cfg *config.Config) *HealthTargets {
	m := &HealthTargets{cfg: cfg}
	m.rebuildItems()
	return m
}

func (m *HealthTargets) rebuildItems() {
	m.items = nil
	for _, t := range m.cfg.PingTargets {
		m.items = append(m.items, healthTargetItem{itemType: htPingTarget, value: t})
	}
	m.items = append(m.items, healthTargetItem{itemType: htAddPing, value: "+ Add ping target"})
	m.items = append(m.items, healthTargetItem{itemType: htDNSHost, value: m.cfg.DNSProbeHost})
	m.items = append(m.items, healthTargetItem{itemType: htResetDefaults})
	if m.cursor >= len(m.items) {
		m.cursor = len(m.items) - 1
	}
}

func (m *HealthTargets) Init() tea.Cmd {
	return nil
}

func (m *HealthTargets) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.editing {
			return m.updateEditing(msg)
		}
		return m.updateNormal(msg)
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}
	return m, nil
}

func (m *HealthTargets) updateNormal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.message = ""
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
	case "enter":
		item := m.items[m.cursor]
		switch item.itemType {
		case htPingTarget:
			m.editing = true
			m.editBuf = item.value
		case htDNSHost:
			m.editing = true
			m.editBuf = item.value
		case htAddPing:
			m.editing = true
			m.editBuf = ""
		case htResetDefaults:
			// Snapshot previous values for revert-on-Save-failure.
			// Both fields mutate; both need to revert if disk save fails.
			prevPing := append([]string(nil), m.cfg.PingTargets...)
			prevHost := m.cfg.DNSProbeHost
			m.cfg.PingTargets = []string{"8.8.8.8:53", "1.1.1.1:53"}
			m.cfg.DNSProbeHost = "cloudflare.com"
			if err := m.cfg.Save(); err != nil {
				m.cfg.PingTargets = prevPing
				m.cfg.DNSProbeHost = prevHost
				m.message = "Failed to save"
			} else {
				m.message = "Reset to defaults"
			}
			m.rebuildItems()
			m.cursor = 0
		}
	case "d", "backspace":
		if m.cursor < len(m.items) && m.items[m.cursor].itemType == htPingTarget {
			if len(m.cfg.PingTargets) <= 1 {
				m.message = "At least one ping target required"
				return m, nil
			}
			// Remove the ping target at this index
			idx := m.cursor
			prev := append([]string(nil), m.cfg.PingTargets...)
			m.cfg.PingTargets = append(m.cfg.PingTargets[:idx], m.cfg.PingTargets[idx+1:]...)
			if err := m.cfg.Save(); err != nil {
				m.cfg.PingTargets = prev
				m.message = "Failed to save"
			}
			m.rebuildItems()
		}
	}
	return m, nil
}

func (m *HealthTargets) updateEditing(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.editing = false
		m.editBuf = ""
		m.message = ""
	case "enter":
		val := strings.TrimSpace(m.editBuf)
		if val == "" {
			m.message = "Value cannot be empty"
			return m, nil
		}
		item := m.items[m.cursor]
		// Snapshot previous values for revert-on-Save-failure. Capture
		// both PingTargets (slice) and DNSProbeHost (string) so any
		// branch's mutation can revert.
		prevPing := append([]string(nil), m.cfg.PingTargets...)
		prevHost := m.cfg.DNSProbeHost
		switch item.itemType {
		case htPingTarget:
			m.cfg.PingTargets[m.cursor] = val
		case htDNSHost:
			m.cfg.DNSProbeHost = val
		case htAddPing:
			m.cfg.PingTargets = append(m.cfg.PingTargets, val)
		}
		if err := m.cfg.Save(); err != nil {
			m.cfg.PingTargets = prevPing
			m.cfg.DNSProbeHost = prevHost
			m.message = "Failed to save"
		}
		m.editing = false
		m.editBuf = ""
		m.rebuildItems()
	case "backspace":
		if len(m.editBuf) > 0 {
			m.editBuf = m.editBuf[:len(m.editBuf)-1]
		}
	default:
		if msg.Type == tea.KeyRunes {
			m.editBuf += string(msg.Runes)
		}
	}
	return m, nil
}

func (m *HealthTargets) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("Health Check Targets") + "\n\n")
	b.WriteString(MutedStyle.Render("  Targets used by the daemon to check VPN connectivity.") + "\n")
	b.WriteString(MutedStyle.Render("  Ping targets are tried in order via TCP dial.") + "\n\n")

	inputStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAccent).
		Padding(0, 1).
		Width(40)

	wroteSection := false
	for i, item := range m.items {
		cursor := "  "
		if i == m.cursor && m.focused {
			cursor = "> "
		}

		switch item.itemType {
		case htPingTarget:
			if !wroteSection {
				b.WriteString(MutedStyle.Render("  Ping Targets") + "\n")
				wroteSection = true
			}
			if m.editing && i == m.cursor {
				display := m.editBuf + "\u2588"
				b.WriteString("  " + inputStyle.Render(display) + "\n")
			} else if i == m.cursor {
				b.WriteString(cursor + SelectedStyle.Render(item.value) + "\n")
			} else {
				b.WriteString(cursor + item.value + "\n")
			}
		case htAddPing:
			if m.editing && i == m.cursor {
				display := m.editBuf + "\u2588"
				b.WriteString("  " + inputStyle.Render(display) + "\n")
			} else {
				label := item.value
				if i == m.cursor {
					label = SelectedStyle.Render(label)
				} else {
					label = MutedStyle.Render(label)
				}
				b.WriteString(cursor + label + "\n")
			}
		case htDNSHost:
			b.WriteString("\n" + MutedStyle.Render("  DNS Probe Host") + "\n")
			if m.editing && i == m.cursor {
				display := m.editBuf + "\u2588"
				b.WriteString("  " + inputStyle.Render(display) + "\n")
			} else if i == m.cursor {
				b.WriteString(cursor + SelectedStyle.Render(item.value) + "\n")
			} else {
				b.WriteString(cursor + item.value + "\n")
			}
		case htResetDefaults:
			label := "Reset to Defaults"
			if i == m.cursor {
				label = SelectedStyle.Render(label)
			} else {
				label = MutedStyle.Render(label)
			}
			b.WriteString("\n" + cursor + label + "\n")
		}
	}

	if m.message != "" {
		b.WriteString("\n" + WarningStyle.Render("  "+m.message) + "\n")
	}

	if m.editing {
		b.WriteString("\n" + MutedStyle.Render("  enter: confirm  esc: cancel"))
	} else {
		b.WriteString("\n" + MutedStyle.Render("  enter: edit  d: delete  esc: save & back"))
	}

	return b.String()
}

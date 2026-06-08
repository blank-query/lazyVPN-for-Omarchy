package ui

import (
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

// DisconnectConfirm shows a confirmation dialog before disconnecting
type DisconnectConfirm struct {
	cfg     *config.Config
	cursor  int
	options []string
	width   int
	height  int
	focused bool
}

// SetFocused sets the focus state for cursor visibility.
func (m *DisconnectConfirm) SetFocused(focused bool) {
	m.focused = focused
}

// NewDisconnectConfirm creates a new disconnect confirmation view
func NewDisconnectConfirm(cfg *config.Config) *DisconnectConfirm {
	return &DisconnectConfirm{
		cfg:     cfg,
		cursor:  0,
		options: []string{"Yes, disconnect", "No, stay connected"},
	}
}

func (m *DisconnectConfirm) Init() tea.Cmd {
	return nil
}

func (m *DisconnectConfirm) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "y", "Y":
			// Quick disconnect with Y key
			return m, func() tea.Msg { return SwitchViewMsg{View: "disconnect-progress"} }
		case "n", "N", "esc":
			// Cancel
			return m, func() tea.Msg { return BackMsg{} }
		case "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down":
			if m.cursor < len(m.options)-1 {
				m.cursor++
			}
		case "enter":
			if m.cursor == 0 {
				// Confirmed disconnect
				return m, func() tea.Msg { return SwitchViewMsg{View: "disconnect-progress"} }
			}
			// Cancelled
			return m, func() tea.Msg { return BackMsg{} }
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m *DisconnectConfirm) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("Disconnect VPN?") + "\n\n")

	// Warning about killswitch. Source of truth is UFW, not config.
	if isFirewallActive() {
		switch m.cfg.KillswitchAutoDisable {
		case "true":
			b.WriteString(MutedStyle.Render("  Killswitch will be automatically disabled.") + "\n")
		case "never":
			b.WriteString(WarningStyle.Render("  ⚠ Killswitch will remain ACTIVE - all traffic will be blocked!") + "\n")
		default:
			b.WriteString(MutedStyle.Render("  You will be prompted about killswitch.") + "\n")
		}
		b.WriteString("\n")
	}

	// Server name
	if m.cfg.LastConnectedServer != "" {
		b.WriteString(MutedStyle.Render("  Server: "+m.cfg.LastConnectedServer) + "\n\n")
	}

	// Options
	for i, opt := range m.options {
		cursor := "  "
		if i == m.cursor && m.focused {
			cursor = "> "
		}

		line := opt
		if i == m.cursor {
			line = SelectedStyle.Render(line)
		}

		b.WriteString(cursor + line + "\n")
	}

	b.WriteString("\n" + MutedStyle.Render("  y: yes  n: no  enter: select"))

	return b.String()
}

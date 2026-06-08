package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// MTUInput is a view for setting a custom MTU value
type MTUInput struct {
	cfg   *config.Config
	input string
	err   string
	width int
}

// NewMTUInput creates a new MTU input view
func NewMTUInput(cfg *config.Config) *MTUInput {
	return &MTUInput{
		cfg:   cfg,
		input: strconv.Itoa(cfg.CustomMTU),
	}
}

func (m *MTUInput) Init() tea.Cmd {
	return nil
}

func (m *MTUInput) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, func() tea.Msg { return BackMsg{} }
		case "enter":
			return m.handleSubmit()
		case "backspace":
			if len(m.input) > 0 {
				m.input = m.input[:len(m.input)-1]
				m.err = ""
			}
		default:
			if msg.Type == tea.KeyRunes {
				for _, r := range msg.Runes {
					if r >= '0' && r <= '9' {
						m.input += string(r)
						m.err = ""
					}
				}
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
	}
	return m, nil
}

func (m *MTUInput) handleSubmit() (tea.Model, tea.Cmd) {
	if m.input == "" {
		m.err = "MTU value required"
		return m, nil
	}

	// Parse and validate
	mtu, err := strconv.Atoi(m.input)
	if err != nil {
		m.err = "Invalid number"
		return m, nil
	}

	// WireGuard MTU valid range: 1280 (IPv6 minimum) to 9000 (jumbo frames)
	if mtu < 1280 {
		m.err = fmt.Sprintf("%d is below minimum (1280)", mtu)
		return m, nil
	}
	if mtu > 9000 {
		m.err = fmt.Sprintf("%d exceeds maximum (9000)", mtu)
		return m, nil
	}

	// Save the previous value so we can restore on Save failure.
	// cfg.Save is atomic — on failure the on-disk value is whatever it
	// was before. Without the revert the in-memory value would say
	// "new MTU" while disk and the next process invocation see the old
	// MTU, and the user thinks their change took effect.
	prev := m.cfg.CustomMTU
	m.cfg.CustomMTU = mtu
	if err := m.cfg.Save(); err != nil {
		m.cfg.CustomMTU = prev
		m.err = fmt.Sprintf("Failed to save: %v", err)
		return m, nil
	}

	return m, func() tea.Msg { return SwitchViewMsg{View: "settings"} }
}

func (m *MTUInput) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("Custom MTU") + "\n\n")

	// Default hint. Newlines must live OUTSIDE the styled render — lipgloss
	// pads each line in the styled input to the longest line's width, so a
	// trailing "\n\n" produces invisible space-runs that shift whatever is
	// concatenated after them.
	b.WriteString(MutedStyle.Render("  Default: 1420") + "\n\n")

	// Input field. The rendered box is multi-line (top border, content,
	// bottom border) — concatenating "  " in front only indents the first
	// line, leaving the other two flush against the panel edge. Split and
	// prefix each line so the box aligns as a block.
	inputStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAccent).
		Padding(0, 1).
		Width(20)

	display := m.input + "\u2588" // cursor block
	for _, line := range strings.Split(inputStyle.Render(display), "\n") {
		b.WriteString("  " + line + "\n")
	}

	// Error message
	if m.err != "" {
		b.WriteString("\n" + ErrorStyle.Render("  "+m.err) + "\n")
	}

	// Note about when it takes effect
	if isWGConnected(m.cfg.ConnectionName) {
		b.WriteString("\n" + MutedStyle.Render("  Note: Takes effect on next connection") + "\n")
	}

	// Help
	b.WriteString("\n" + MutedStyle.Render("  enter: save  esc: cancel"))

	return b.String()
}

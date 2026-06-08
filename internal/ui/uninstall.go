package ui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// UninstallConfirm is a confirmation dialog for uninstalling
type UninstallConfirm struct {
	width    int
	height   int
	selected int // 0 = Cancel, 1 = Confirm
}

// NewUninstallConfirm creates a new uninstall confirmation dialog
func NewUninstallConfirm() UninstallConfirm {
	return UninstallConfirm{
		selected: 0, // Default to Cancel for safety
	}
}

func (m UninstallConfirm) Init() tea.Cmd {
	return nil
}

func (m UninstallConfirm) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "n":
			return m, func() tea.Msg { return BackMsg{} }
		case "left":
			m.selected = 0
		case "right":
			m.selected = 1
		case "tab":
			m.selected = (m.selected + 1) % 2
		case "y":
			// Shortcut to confirm
			return m, func() tea.Msg { return RunUninstallMsg{} }
		case "enter":
			if m.selected == 1 {
				return m, func() tea.Msg { return RunUninstallMsg{} }
			}
			return m, func() tea.Msg { return BackMsg{} }
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m UninstallConfirm) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("Uninstall LazyVPN") + "\n\n")

	b.WriteString(ErrorStyle.Render("  WARNING: This will permanently remove:") + "\n\n")
	b.WriteString("    • All VPN configurations and credentials\n")
	b.WriteString("    • Provider settings and cached server lists\n")
	b.WriteString("    • Firewall rules and killswitch settings\n")
	b.WriteString("    • Desktop integrations (keybindings, status bar, app launcher)\n")
	b.WriteString("    • Sudoers configuration\n")
	b.WriteString("    • The LazyVPN binary itself\n")
	b.WriteString("\n")

	b.WriteString("  You will be prompted for additional cleanup options:\n")
	b.WriteString("    • Delete WireGuard config files\n")
	b.WriteString("    • Clean VPN-related system logs\n")
	b.WriteString("    • Clean shell history\n")
	b.WriteString("\n\n")

	b.WriteString("  Are you sure you want to uninstall?\n\n")

	// Buttons
	var cancelBtn, confirmBtn string
	if m.selected == 0 {
		cancelBtn = SelectedStyle.Render("[ Cancel ]")
		confirmBtn = MutedStyle.Render("[ Uninstall ]")
	} else {
		cancelBtn = MutedStyle.Render("[ Cancel ]")
		confirmBtn = ErrorStyle.Render("[ Uninstall ]")
	}

	b.WriteString("  " + cancelBtn + "    " + confirmBtn + "\n\n")

	b.WriteString(MutedStyle.Render("  ←/→: select  enter: confirm  esc: cancel"))

	return b.String()
}

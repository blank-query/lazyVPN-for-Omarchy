package ui

import (
	"fmt"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/update"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// NavItem represents a navigation menu item
type NavItem int

const (
	NavDashboard NavItem = iota
	NavDynamic
	NavServers
	NavSettings
	NavClose
	NavUpdate // Only visible when an update is available
)

var navItemsBase = []string{"󰕮 Dashboard", "󰖂 Dynamic Servers", "󰒍 My Servers", "󰒓 Settings", "󰅖 Close"}

// NavPane is the left navigation pane
type NavPane struct {
	cfg              *config.Config
	cursor           NavItem
	focused          bool
	width            int
	height           int
	connected        bool
	killswitchActive bool // killswitch is blocking traffic
	blinkOn          bool // blink toggle for warning text
	updateAvailable  *update.Release
}

// NavSelectMsg is sent when a nav item is selected
type NavSelectMsg struct {
	Item NavItem
}

// NewNavPane creates a new navigation pane
func NewNavPane(cfg *config.Config) *NavPane {
	return &NavPane{
		cfg:     cfg,
		cursor:  NavDashboard,
		focused: true,
	}
}

// visibleItems returns the nav labels and their NavItem values.
// NavUpdate appears at the top only when an update is available.
func (n *NavPane) visibleItems() ([]string, []NavItem) {
	var items []string
	var ids []NavItem

	if n.updateAvailable != nil {
		label := fmt.Sprintf("⬆ Update %s", n.updateAvailable.TagName)
		items = append(items, label)
		ids = append(ids, NavUpdate)
	}

	items = append(items, navItemsBase...)
	ids = append(ids, NavDashboard, NavDynamic, NavServers, NavSettings, NavClose)
	return items, ids
}

func (n *NavPane) Init() tea.Cmd {
	return nil
}

func (n *NavPane) Update(msg tea.Msg) (*NavPane, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if !n.focused {
			return n, nil
		}
		_, ids := n.visibleItems()
		switch msg.String() {
		case "down":
			curPos := n.cursorPos(ids)
			if curPos < len(ids)-1 {
				n.cursor = ids[curPos+1]
				return n, func() tea.Msg { return NavSelectMsg{Item: n.cursor} }
			}
		case "up":
			curPos := n.cursorPos(ids)
			if curPos > 0 {
				n.cursor = ids[curPos-1]
				return n, func() tea.Msg { return NavSelectMsg{Item: n.cursor} }
			}
		case "enter":
			if n.cursor == NavClose {
				return n, tea.Quit
			}
			// Move focus to content pane
			n.focused = false
			return n, func() tea.Msg { return FocusContentMsg{} }
		}
	case StatusUpdateMsg:
		n.connected = isWGConnected(n.cfg.ConnectionName)
		n.killswitchActive = isFirewallActive()
		if n.killswitchActive && !n.connected {
			n.blinkOn = !n.blinkOn
		} else {
			n.blinkOn = false
		}
	case tea.WindowSizeMsg:
		n.width = msg.Width / 5 // 20% of width
		if n.width < 20 {
			n.width = 20
		}
		n.height = msg.Height - 10 // header(3) + footer(3) + border(2) + gaps(2) = 10
	}
	return n, nil
}

// cursorPos returns the index of n.cursor in the visible ids list
func (n *NavPane) cursorPos(ids []NavItem) int {
	for i, id := range ids {
		if id == n.cursor {
			return i
		}
	}
	return 0
}

func (n *NavPane) SetFocused(focused bool) {
	n.focused = focused
}

// SetUpdateAvailable sets the release info for the update banner.
func (n *NavPane) SetUpdateAvailable(rel *update.Release) {
	n.updateAvailable = rel
}

func (n *NavPane) View() string {
	var b strings.Builder

	// Nav items
	labels, ids := n.visibleItems()
	// Full content width inside the container (subtract padding on each side)
	barWidth := n.width - 2
	if barWidth < 18 {
		barWidth = 18
	}

	for i, item := range labels {
		isUpdateItem := ids[i] == NavUpdate

		if ids[i] == n.cursor {
			if n.focused {
				focusedStyle := lipgloss.NewStyle().
					Bold(true).
					Reverse(true).
					Width(barWidth)
				b.WriteString(focusedStyle.Render(" ▸ "+item) + "\n")
			} else {
				unfocusedStyle := lipgloss.NewStyle().
					Bold(true).
					Foreground(ColorMuted)
				b.WriteString("  " + unfocusedStyle.Render(item) + "\n")
			}
		} else if isUpdateItem {
			updateStyle := lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorAccent)
			b.WriteString("  " + updateStyle.Render(item) + "\n")
		} else {
			b.WriteString("  " + item + "\n")
		}

		// Visual separator after update banner
		if isUpdateItem {
			b.WriteString(MutedStyle.Render("  ────────────") + "\n")
		}

		// Visual separator before Close
		if ids[i] == NavSettings {
			b.WriteString(MutedStyle.Render("  ────────────") + "\n")
		}
	}

	b.WriteString("\n" + MutedStyle.Render("  Tab ⇄ switch pane") + "\n")

	// Warning when killswitch is blocking with no VPN (always occupy 3 lines to prevent layout jump)
	if n.killswitchActive && !n.connected {
		if n.blinkOn {
			warnStyle := lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorDanger)
			b.WriteString("\n" + warnStyle.Render("  󰒘 KS BLOCKING") + "\n")
			b.WriteString(warnStyle.Render("  No VPN active") + "\n")
		} else {
			b.WriteString("\n\n\n")
		}
	}

	borderColor := ColorDimBorder
	if n.focused {
		borderColor = ColorAccent
	}
	containerStyle := lipgloss.NewStyle().
		Width(n.width).
		Height(n.height).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(1, 1)

	return containerStyle.Render(b.String())
}

// FocusContentMsg signals to focus the content pane
type FocusContentMsg struct{}

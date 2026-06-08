package ui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/provider"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
)

// AutoconnectServerSelectMsg is sent when a server is selected for autoconnect
type AutoconnectServerSelectMsg struct {
	Server string
}

// AutoconnectSelect is a server selector for autoconnect
type AutoconnectSelect struct {
	servers []string
	cursor  int
	cfg     *config.Config
	width   int
	height  int
	message string
	focused bool
}

// SetFocused sets the focus state for cursor visibility.
func (m *AutoconnectSelect) SetFocused(focused bool) {
	m.focused = focused
}

// NewAutoconnectSelect creates a new autoconnect server selector
func NewAutoconnectSelect(cfg *config.Config) *AutoconnectSelect {
	s := &AutoconnectSelect{cfg: cfg}
	s.loadServers()
	return s
}

func (m *AutoconnectSelect) loadServers() {
	// Load manual servers
	wgDir := filepath.Join(m.cfg.ConfigDir, "wireguard")
	configs, _ := wireguard.ListConfigs(wgDir)
	for _, cfg := range configs {
		m.servers = append(m.servers, cfg.Name)
	}

	// Load dynamic servers from all providers
	providers, _ := config.ListProviders(m.cfg.ConfigDir)
	cacheDir := filepath.Join(m.cfg.ConfigDir, "cache")
	for _, prov := range providers {
		servers, err := provider.LoadProviderServers(cacheDir, prov)
		if err == nil {
			for _, srv := range servers {
				m.servers = append(m.servers, "dynamic:"+prov+":"+srv.Name())
			}
		}
	}

	// Set cursor to current selection if exists
	if m.cfg.AutostartServer != "" {
		for i, srv := range m.servers {
			if srv == m.cfg.AutostartServer {
				m.cursor = i
				break
			}
		}
	}
}

func (m *AutoconnectSelect) Init() tea.Cmd {
	return nil
}

func (m *AutoconnectSelect) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, func() tea.Msg { return BackMsg{} }
		case "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down":
			if m.cursor < len(m.servers)-1 {
				m.cursor++
			}
		case "enter", " ":
			if m.cursor < len(m.servers) {
				selected := m.servers[m.cursor]
				// Save the previous value so we can restore on Save
				// failure. The earlier code reverted to "" — but Save
				// is atomic, so on failure the on-disk value is still
				// whatever it was before. Resetting in-memory to "" while
				// disk holds the old value drifts the TUI's view from
				// reality (and the daemon's autoconnect still uses the
				// old value).
				prev := m.cfg.AutostartServer
				m.cfg.AutostartServer = selected
				if err := m.cfg.Save(); err != nil {
					m.cfg.AutostartServer = prev
					return m, nil
				}
				return m, func() tea.Msg {
					return AutoconnectServerSelectMsg{Server: selected}
				}
			}
		case "home":
			m.cursor = 0
		case "end":
			if len(m.servers) > 0 {
				m.cursor = len(m.servers) - 1
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m *AutoconnectSelect) View() string {
	var b strings.Builder

	title := TitleStyle.Render("Select Autoconnect Server")
	b.WriteString(title + "\n\n")

	if len(m.servers) == 0 {
		b.WriteString(MutedStyle.Render("  No servers available.") + "\n")
		b.WriteString(MutedStyle.Render("  Import a WireGuard config or set up a provider first.") + "\n")
		b.WriteString("\n" + MutedStyle.Render("  esc: back"))
		return b.String()
	}

	// Calculate visible area
	height := m.height
	if height == 0 {
		height = 24
	}
	visibleHeight := height - 8
	if visibleHeight < 10 {
		visibleHeight = 15
	}

	// Calculate scroll offset
	start := 0
	if m.cursor >= visibleHeight {
		start = m.cursor - visibleHeight + 1
	}
	end := start + visibleHeight
	if end > len(m.servers) {
		end = len(m.servers)
	}

	for i := start; i < end; i++ {
		server := m.servers[i]
		displayName := formatServerName(server)

		cursor := "  "
		if i == m.cursor && m.focused {
			cursor = "> "
			displayName = SelectedStyle.Render(displayName)
		}

		// Mark current selection
		if server == m.cfg.AutostartServer {
			displayName = displayName + MutedStyle.Render(" (current)")
		}

		b.WriteString(cursor + displayName + "\n")
	}

	// Scroll indicator
	if len(m.servers) > visibleHeight {
		b.WriteString(MutedStyle.Render(fmt.Sprintf("\n  %s[%d/%d]", strings.Repeat(" ", 20), m.cursor+1, len(m.servers))))
	}

	if m.message != "" {
		b.WriteString("\n" + SuccessStyle.Render("  "+m.message) + "\n")
	}

	b.WriteString("\n" + MutedStyle.Render("  enter: select  esc: back"))

	return b.String()
}

// formatServerName formats a server name for display using pretty names
func formatServerName(name string) string {
	if strings.HasPrefix(name, "dynamic:") {
		parts := strings.SplitN(name, ":", 3)
		if len(parts) == 3 {
			info := wireguard.ParseServerName(parts[2])
			pretty := info.PrettyName()
			displayName := provider.ProviderDisplayNames[parts[1]]
			if displayName == "" {
				displayName = parts[1]
			}
			return pretty + " • " + displayName
		}
	}
	info := wireguard.ParseServerName(name)
	return info.PrettyName()
}

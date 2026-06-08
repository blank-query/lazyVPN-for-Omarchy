package ui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/security"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
)

type serverToRemove struct {
	name     string
	path     string
	selected bool
}

// RemoveServer handles removing manual WireGuard configs
type RemoveServer struct {
	servers     []serverToRemove
	cursor      int
	cfg         *config.Config
	width       int
	height      int
	confirmMode bool
	message     string
	removed     int
	focused     bool
}

// SetFocused sets the focus state for cursor visibility.
func (m *RemoveServer) SetFocused(focused bool) {
	m.focused = focused
}

// NewRemoveServer creates a new remove server view
func NewRemoveServer(cfg *config.Config) *RemoveServer {
	rs := &RemoveServer{cfg: cfg}
	rs.loadServers()
	return rs
}

func (m *RemoveServer) loadServers() {
	wgDir := filepath.Join(m.cfg.ConfigDir, "wireguard")
	configs, _ := wireguard.ListConfigs(wgDir)

	for _, cfg := range configs {
		m.servers = append(m.servers, serverToRemove{
			name: cfg.Name,
			path: cfg.Path,
		})
	}
}

func (m *RemoveServer) Init() tea.Cmd {
	return nil
}

func (m *RemoveServer) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.confirmMode {
			switch msg.String() {
			case "y", "Y":
				return m, m.doRemove()
			case "n", "N", "esc":
				m.confirmMode = false
				return m, nil
			}
			return m, nil
		}

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
		case " ":
			if len(m.servers) > 0 && m.cursor < len(m.servers) {
				m.servers[m.cursor].selected = !m.servers[m.cursor].selected
			}
		case "enter", "d":
			// Count selected
			selected := 0
			for _, s := range m.servers {
				if s.selected {
					selected++
				}
			}
			if selected == 0 && len(m.servers) > 0 && m.cursor < len(m.servers) {
				// If none selected, select current
				m.servers[m.cursor].selected = true
				selected = 1
			}
			if selected > 0 {
				m.confirmMode = true
			}
		}

	case removeDoneMsg:
		m.removed = msg.removed
		m.message = fmt.Sprintf("Removed %d server(s)", msg.removed)
		if msg.skippedConnected {
			m.message += " (skipped currently connected server)"
		}
		// Clean up stale config references (safe: runs in single-threaded Update)
		if len(msg.deletedNames) > 0 {
			deletedSet := make(map[string]bool)
			for _, name := range msg.deletedNames {
				deletedSet[name] = true
			}
			changed := false
			if deletedSet[m.cfg.LastConnectedServer] {
				m.cfg.LastConnectedServer = ""
				m.cfg.LastPublicIP = ""
				changed = true
			}
			if deletedSet[m.cfg.AutostartServer] {
				m.cfg.AutostartServer = ""
				changed = true
			}
			var newFavs []string
			for _, f := range m.cfg.Favorites {
				if !deletedSet[f] {
					newFavs = append(newFavs, f)
				}
			}
			if len(newFavs) != len(m.cfg.Favorites) {
				m.cfg.Favorites = newFavs
				changed = true
			}
			if changed {
				if err := m.cfg.Save(); err != nil {
					m.message = "Warning: failed to save config"
				}
			}
		}
		// Reload list
		m.servers = nil
		m.loadServers()
		m.cursor = 0
		if len(m.servers) == 0 {
			return m, func() tea.Msg { return BackMsg{} }
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

type removeDoneMsg struct {
	removed          int
	skippedConnected bool
	deletedNames     []string
}

func (m *RemoveServer) doRemove() tea.Cmd {
	// Capture cfg values before entering goroutine to avoid racing on shared pointer
	connectedServer := m.cfg.LastConnectedServer
	cowFS := m.cfg.IsCOWFilesystem()
	var toDelete []string
	var deletedNames []string
	skippedConnected := false

	for _, s := range m.servers {
		if !s.selected {
			continue
		}
		// Protect the currently connected server from deletion
		if s.name == connectedServer {
			skippedConnected = true
			continue
		}
		toDelete = append(toDelete, s.path)
		deletedNames = append(deletedNames, s.name)
	}

	return func() tea.Msg {
		if len(toDelete) > 0 {
			// Configs contain private keys; delete with the tool appropriate
			// for the filesystem (shred on ext4/xfs, rm on CoW).
			security.DeleteForFS(cowFS)(toDelete, security.NoSudo)
		}
		return removeDoneMsg{removed: len(toDelete), skippedConnected: skippedConnected, deletedNames: deletedNames}
	}
}

func (m *RemoveServer) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("Remove Server") + "\n\n")

	if len(m.servers) == 0 {
		b.WriteString(MutedStyle.Render("  No manual server configs found.") + "\n")
		b.WriteString("\n" + MutedStyle.Render("  esc: back"))
		return b.String()
	}

	if m.confirmMode {
		selected := 0
		for _, s := range m.servers {
			if s.selected {
				selected++
			}
		}
		b.WriteString(ErrorStyle.Render(fmt.Sprintf("  Delete %d server(s)? This cannot be undone.", selected)) + "\n\n")
		b.WriteString("  Selected:\n")
		for _, s := range m.servers {
			if s.selected {
				b.WriteString(fmt.Sprintf("    - %s\n", s.name))
			}
		}
		b.WriteString("\n" + MutedStyle.Render("  y: delete  n: cancel"))
		return b.String()
	}

	b.WriteString("  Space: toggle  Enter/d: delete selected\n\n")

	if m.message != "" {
		b.WriteString(SuccessStyle.Render("  "+m.message) + "\n\n")
	}

	// Calculate visible area (default to 24 if height not yet set)
	height := m.height
	if height == 0 {
		height = 24
	}
	visibleHeight := height - 10
	if visibleHeight < 5 {
		visibleHeight = 15
	}

	start := 0
	if m.cursor >= visibleHeight {
		start = m.cursor - visibleHeight + 1
	}
	end := start + visibleHeight
	if end > len(m.servers) {
		end = len(m.servers)
	}

	for i := start; i < end; i++ {
		s := m.servers[i]

		cursor := "  "
		if i == m.cursor && m.focused {
			cursor = "> "
		}

		checkbox := "[ ]"
		if s.selected {
			checkbox = "[x]"
		}

		line := fmt.Sprintf("%s%s %s", cursor, checkbox, s.name)
		if i == m.cursor && m.focused {
			line = SelectedStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}

	// Scroll indicator
	if len(m.servers) > visibleHeight {
		b.WriteString("\n" + MutedStyle.Render(fmt.Sprintf("  %d/%d servers", m.cursor+1, len(m.servers))))
	}

	b.WriteString("\n\n" + MutedStyle.Render("  esc: back"))

	return b.String()
}

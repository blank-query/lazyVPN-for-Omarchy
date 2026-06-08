package ui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/provider"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/security"
	tea "github.com/charmbracelet/bubbletea"
)

type providerToRemove struct {
	name     string
	display  string
	selected bool
}

// RemoveProvider handles removing VPN provider credentials and cache
type RemoveProvider struct {
	providers   []providerToRemove
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
func (m *RemoveProvider) SetFocused(focused bool) {
	m.focused = focused
}

// NewRemoveProvider creates a new remove provider view
func NewRemoveProvider(cfg *config.Config) *RemoveProvider {
	rp := &RemoveProvider{cfg: cfg}
	rp.loadProviders()
	return rp
}

func (m *RemoveProvider) loadProviders() {
	providers, _ := config.ListProviders(m.cfg.ConfigDir)
	for _, p := range providers {
		displayName := provider.ProviderDisplayNames[p]
		if displayName == "" {
			displayName = p
		}
		m.providers = append(m.providers, providerToRemove{
			name:    p,
			display: displayName,
		})
	}
}

func (m *RemoveProvider) Init() tea.Cmd {
	return nil
}

func (m *RemoveProvider) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			if m.cursor < len(m.providers)-1 {
				m.cursor++
			}
		case " ":
			if len(m.providers) > 0 && m.cursor < len(m.providers) {
				m.providers[m.cursor].selected = !m.providers[m.cursor].selected
			}
		case "enter", "d":
			selected := 0
			for _, p := range m.providers {
				if p.selected {
					selected++
				}
			}
			if selected == 0 && len(m.providers) > 0 && m.cursor < len(m.providers) {
				m.providers[m.cursor].selected = true
				selected = 1
			}
			if selected > 0 {
				m.confirmMode = true
			}
		}

	case removeProviderDoneMsg:
		m.removed = msg.removed
		m.message = fmt.Sprintf("Removed %d provider(s)", msg.removed)
		if msg.skippedConnected {
			m.message += " (skipped currently connected provider)"
		}
		// Clean up favorites referencing deleted providers
		if len(msg.deletedNames) > 0 {
			m.cleanupFavorites(msg.deletedNames)
		}
		// Reload list
		m.providers = nil
		m.loadProviders()
		m.cursor = 0
		if len(m.providers) == 0 {
			return m, func() tea.Msg { return BackMsg{} }
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

type removeProviderDoneMsg struct {
	removed          int
	skippedConnected bool
	deletedNames     []string
}

func (m *RemoveProvider) doRemove() tea.Cmd {
	connectedServer := m.cfg.LastConnectedServer
	configDir := m.cfg.ConfigDir

	var toDelete []string
	skippedConnected := false

	for _, p := range m.providers {
		if !p.selected {
			continue
		}
		// Don't delete provider if currently connected to one of its servers
		if strings.HasPrefix(connectedServer, "dynamic:"+p.name+":") {
			skippedConnected = true
			continue
		}
		toDelete = append(toDelete, p.name)
	}

	// Capture favorites for cleanup
	favorites := make([]string, len(m.cfg.Favorites))
	copy(favorites, m.cfg.Favorites)

	cowFS := m.cfg.IsCOWFilesystem()
	return func() tea.Msg {
		removed := 0
		var deleted []string
		deleteFn := security.DeleteForFS(cowFS)
		for _, provName := range toDelete {
			// Provider files contain the private key; delete with the tool
			// appropriate for the filesystem (shred on ext4/xfs, rm on CoW).
			provFile := filepath.Join(configDir, "providers", provName+".json")
			deleteFn([]string{provFile}, security.NoSudo)
			if err := config.DeleteProvider(configDir, provName); err == nil {
				removed++
				deleted = append(deleted, provName)
			}
		}

		return removeProviderDoneMsg{removed: removed, skippedConnected: skippedConnected, deletedNames: deleted}
	}
}

// cleanupFavorites removes favorites referencing deleted providers
func (m *RemoveProvider) cleanupFavorites(deletedProviders []string) {
	deletedSet := make(map[string]bool)
	for _, p := range deletedProviders {
		deletedSet[p] = true
	}

	var newFavs []string
	for _, f := range m.cfg.Favorites {
		keep := true
		if strings.HasPrefix(f, "dynamic:") {
			parts := strings.SplitN(f, ":", 3)
			if len(parts) == 3 && deletedSet[parts[1]] {
				keep = false
			}
		}
		if keep {
			newFavs = append(newFavs, f)
		}
	}

	if len(newFavs) != len(m.cfg.Favorites) {
		// Snapshot previous Favorites for revert-on-Save-failure
		// (deep copy — `prev := m.cfg.Favorites` would alias the
		// backing array). Without revert, in-memory Favorites drops
		// the stale entries while disk keeps them; next process
		// invocation re-loads the stale favorites pointing at
		// providers that no longer exist.
		prev := append([]string(nil), m.cfg.Favorites...)
		m.cfg.Favorites = newFavs
		if err := m.cfg.Save(); err != nil {
			m.cfg.Favorites = prev
		}
	}
}

func (m *RemoveProvider) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("Remove Provider") + "\n\n")

	if len(m.providers) == 0 {
		b.WriteString(MutedStyle.Render("  No providers configured.") + "\n")
		b.WriteString("\n" + MutedStyle.Render("  esc: back"))
		return b.String()
	}

	if m.confirmMode {
		selected := 0
		var names []string
		for _, p := range m.providers {
			if p.selected {
				selected++
				names = append(names, p.display)
			}
		}
		b.WriteString(ErrorStyle.Render(fmt.Sprintf("  Delete %d provider(s)? This removes credentials and cached servers.", selected)) + "\n\n")
		b.WriteString("  Selected:\n")
		for _, name := range names {
			b.WriteString(fmt.Sprintf("    - %s\n", name))
		}
		b.WriteString("\n" + MutedStyle.Render("  y: delete  n: cancel"))
		return b.String()
	}

	b.WriteString("  Space: toggle  Enter/d: delete selected\n\n")

	if m.message != "" {
		b.WriteString(SuccessStyle.Render("  "+m.message) + "\n\n")
	}

	for i, p := range m.providers {
		cursor := "  "
		if i == m.cursor && m.focused {
			cursor = "> "
		}

		checkbox := "[ ]"
		if p.selected {
			checkbox = "[x]"
		}

		line := fmt.Sprintf("%s%s %s", cursor, checkbox, p.display)
		if i == m.cursor && m.focused {
			line = SelectedStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}

	b.WriteString("\n\n" + MutedStyle.Render("  esc: back"))

	return b.String()
}

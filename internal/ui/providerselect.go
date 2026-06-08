package ui

import (
	"fmt"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/provider"
	tea "github.com/charmbracelet/bubbletea"
)

type providerItem struct {
	name        string
	displayName string
	serverCount int
}

// ProviderSelect allows selecting a VPN provider
type ProviderSelect struct {
	providers []providerItem
	cursor    int
	cfg       *config.Config
	width     int
	height    int
	focused   bool
}

// SetFocused sets the focus state for cursor visibility.
func (m *ProviderSelect) SetFocused(focused bool) {
	m.focused = focused
}

// NewProviderSelect creates a new provider selector
func NewProviderSelect(cfg *config.Config) *ProviderSelect {
	providers, _ := config.ListProviders(cfg.ConfigDir)

	items := make([]providerItem, 0, len(providers))
	for _, p := range providers {
		displayName := provider.ProviderDisplayNames[p]
		if displayName == "" {
			displayName = p
		}

		// Count cached servers
		serverCount := 0
		servers, err := config.LoadServerCache(cfg.ConfigDir, p)
		if err == nil {
			serverCount = len(servers)
		}

		items = append(items, providerItem{
			name:        p,
			displayName: displayName,
			serverCount: serverCount,
		})
	}

	return &ProviderSelect{
		providers: items,
		cfg:       cfg,
	}
}

func (m *ProviderSelect) Init() tea.Cmd {
	return nil
}

func (m *ProviderSelect) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			if m.cursor < len(m.providers)-1 {
				m.cursor++
			}
		case "enter":
			if len(m.providers) > 0 && m.cursor < len(m.providers) {
				selected := m.providers[m.cursor]
				return m, func() tea.Msg {
					return SwitchViewMsg{
						View:     "dynamic-browser",
						Provider: selected.name,
					}
				}
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m *ProviderSelect) View() string {
	var b strings.Builder

	title := TitleStyle.Render("Select Provider")
	b.WriteString(title + "\n\n")

	if len(m.providers) == 0 {
		b.WriteString(MutedStyle.Render("  No providers configured.") + "\n")
		b.WriteString(MutedStyle.Render("  Go to Settings to add a provider.") + "\n")
	} else {
		for i, p := range m.providers {
			cursor := "  "
			if i == m.cursor && m.focused {
				cursor = "> "
			}

			serverInfo := ""
			if p.serverCount > 0 {
				serverInfo = fmt.Sprintf(" (%d servers)", p.serverCount)
			}

			line := p.displayName + serverInfo
			if i == m.cursor && m.focused {
				line = SelectedStyle.Render(line)
			}

			b.WriteString(cursor + line + "\n")
		}
	}

	b.WriteString("\n" + MutedStyle.Render("  enter: select  esc: back"))

	return b.String()
}

// Selected returns the selected provider name
func (m *ProviderSelect) Selected() string {
	if m.cursor < len(m.providers) {
		return m.providers[m.cursor].name
	}
	return ""
}

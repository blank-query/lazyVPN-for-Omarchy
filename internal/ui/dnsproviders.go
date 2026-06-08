package ui

import (
	"fmt"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/tools"
	tea "github.com/charmbracelet/bubbletea"
)

type dnsProviderItem struct {
	provider tools.DNSProvider
	selected bool
}

// DNSProviderSelect is a multi-select screen for choosing DNS reflection providers.
type DNSProviderSelect struct {
	items   []dnsProviderItem
	cursor  int
	cfg     *config.Config
	width   int
	height  int
	message string
	focused bool
}

// SetFocused sets the focus state for cursor visibility.
func (m *DNSProviderSelect) SetFocused(focused bool) {
	m.focused = focused
}

// NewDNSProviderSelect creates a new DNS provider selection view.
func NewDNSProviderSelect(cfg *config.Config) *DNSProviderSelect {
	enabled := cfg.DNSProviders
	if len(enabled) == 0 {
		enabled = tools.DefaultDNSProviders
	}
	enabledSet := make(map[string]bool, len(enabled))
	for _, id := range enabled {
		enabledSet[id] = true
	}

	var items []dnsProviderItem
	for _, p := range tools.DNSProviderRegistry {
		items = append(items, dnsProviderItem{
			provider: p,
			selected: enabledSet[p.ID],
		})
	}

	return &DNSProviderSelect{
		items: items,
		cfg:   cfg,
	}
}

func (m *DNSProviderSelect) Init() tea.Cmd {
	return nil
}

func (m *DNSProviderSelect) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
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
		case " ":
			if m.cursor < len(m.items) {
				if m.items[m.cursor].selected {
					// Check min-1 guard
					count := 0
					for _, it := range m.items {
						if it.selected {
							count++
						}
					}
					if count <= 1 {
						m.message = "At least one provider required"
						return m, nil
					}
				}
				m.items[m.cursor].selected = !m.items[m.cursor].selected
			}
		case "enter":
			// Save selected providers
			var selected []string
			for _, it := range m.items {
				if it.selected {
					selected = append(selected, it.provider.ID)
				}
			}
			// Snapshot previous DNSProviders for revert-on-Save-failure.
			// cfg.Save is atomic — on failure the on-disk value stays
			// whatever it was; without revert, in-memory holds the new
			// selection while next process Load reverts to the old one.
			// Deep-copy because append may share underlying array.
			prev := append([]string(nil), m.cfg.DNSProviders...)
			m.cfg.DNSProviders = selected
			if err := m.cfg.Save(); err != nil {
				m.cfg.DNSProviders = prev
			}
			return m, func() tea.Msg { return BackMsg{} }
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m *DNSProviderSelect) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("DNS Providers") + "\n\n")
	b.WriteString(MutedStyle.Render("  Choose which DNS reflection services to query during leak tests.") + "\n")
	b.WriteString(MutedStyle.Render("  All selected providers are queried in parallel.") + "\n\n")

	for i, item := range m.items {
		cursor := "  "
		if i == m.cursor && m.focused {
			cursor = "> "
		}

		checkbox := "[ ]"
		if item.selected {
			checkbox = "[x]"
		}

		line := fmt.Sprintf("%s%s %-12s %s", cursor, checkbox, item.provider.Name, MutedStyle.Render(item.provider.Description))
		if i == m.cursor {
			line = fmt.Sprintf("%s%s %s %s", cursor, checkbox,
				SelectedStyle.Render(item.provider.Name),
				MutedStyle.Render(item.provider.Description))
		}
		b.WriteString(line + "\n")
	}

	if m.message != "" {
		b.WriteString("\n" + WarningStyle.Render("  "+m.message) + "\n")
	}

	b.WriteString("\n" + MutedStyle.Render("  space: toggle  enter: save  esc: cancel"))

	return b.String()
}

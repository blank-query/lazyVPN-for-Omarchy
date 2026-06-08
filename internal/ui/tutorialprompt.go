package ui

import (
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

// TutorialPrompt asks new users if they want to read the tutorial.
type TutorialPrompt struct {
	cfg         *config.Config
	yesSelected bool
	width       int
	height      int
}

func NewTutorialPrompt(cfg *config.Config) *TutorialPrompt {
	return &TutorialPrompt{
		cfg:         cfg,
		yesSelected: true,
	}
}

func (m *TutorialPrompt) Init() tea.Cmd {
	return nil
}

func (m *TutorialPrompt) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "left", "right":
			m.yesSelected = !m.yesSelected
		case "enter":
			// Revert TutorialSeen on Save failure so the prompt fires
			// again next launch (rather than disk saying "unseen" while
			// memory says "seen", suppressing future prompts only for
			// this session).
			m.cfg.TutorialSeen = true
			if err := m.cfg.Save(); err != nil {
				m.cfg.TutorialSeen = false
			}
			if m.yesSelected {
				return m, func() tea.Msg {
					return SwitchViewMsg{View: "tutorial"}
				}
			}
			return m, func() tea.Msg { return BackMsg{} }
		case "esc":
			m.cfg.TutorialSeen = true
			if err := m.cfg.Save(); err != nil {
				m.cfg.TutorialSeen = false
			}
			return m, func() tea.Msg { return BackMsg{} }
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m *TutorialPrompt) View() string {
	var b strings.Builder
	width := m.width
	if width == 0 {
		width = 60
	}

	b.WriteString("\n\n")
	b.WriteString(CenterText(TitleStyle.Render("Welcome to LazyVPN!"), width) + "\n\n")
	b.WriteString(CenterText("Would you like to read the tutorial?", width) + "\n\n")

	var yes, no string
	if m.yesSelected {
		yes = SelectedStyle.Render("[Yes]")
		no = MutedStyle.Render(" No ")
	} else {
		yes = MutedStyle.Render(" Yes ")
		no = SelectedStyle.Render("[No]")
	}

	b.WriteString(CenterText(yes+"   "+no, width) + "\n")

	return b.String()
}

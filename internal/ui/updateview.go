package ui

import (
	"fmt"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/update"
	tea "github.com/charmbracelet/bubbletea"
)

// RunUpdateMsg signals the layout to execute the update.
type RunUpdateMsg struct {
	Release *update.Release
}

// UpdateResultMsg carries the result of an update attempt.
type UpdateResultMsg struct {
	Err error
}

// UpdateView shows release notes and a confirm/cancel dialog.
type UpdateView struct {
	release        *update.Release
	currentVersion string
	selected       int // 0 = Cancel, 1 = Update
	width          int
	height         int
	scrollOffset   int
	updating       bool // true while download is in progress
}

// NewUpdateView creates a new update confirmation dialog.
func NewUpdateView(release *update.Release, currentVersion string) *UpdateView {
	return &UpdateView{
		release:        release,
		currentVersion: currentVersion,
		selected:       0, // Default to Cancel for safety
	}
}

func (m *UpdateView) Init() tea.Cmd {
	return nil
}

func (m *UpdateView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.updating {
		if msg, ok := msg.(UpdateResultMsg); ok {
			if msg.Err != nil {
				m.updating = false
				return m, nil
			}
			// Success — quit TUI so user restarts with new version
			return m, tea.Quit
		}
		return m, nil
	}

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
		case "up":
			if m.scrollOffset > 0 {
				m.scrollOffset--
			}
		case "down":
			m.scrollOffset++
		case "y":
			m.updating = true
			return m, func() tea.Msg {
				return RunUpdateMsg{Release: m.release}
			}
		case "enter":
			if m.selected == 1 {
				m.updating = true
				return m, func() tea.Msg {
					return RunUpdateMsg{Release: m.release}
				}
			}
			return m, func() tea.Msg { return BackMsg{} }
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m *UpdateView) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("Update Available") + "\n\n")

	if m.updating {
		b.WriteString("  Downloading and installing update...\n")
		return b.String()
	}

	// Version info
	b.WriteString(fmt.Sprintf("  Current:  %s\n", m.currentVersion))
	b.WriteString(fmt.Sprintf("  Latest:   %s\n", accentStyle().Render(m.release.TagName)))
	if m.release.PublishedAt != "" {
		b.WriteString(fmt.Sprintf("  Released: %s\n", m.release.PublishedAt))
	}
	b.WriteString("\n")

	// Release notes
	if m.release.Body != "" {
		b.WriteString(MutedStyle.Render("  ─── Release Notes ───") + "\n\n")

		// Word-wrap and display release notes with scroll
		lines := strings.Split(m.release.Body, "\n")
		var wrapped []string
		noteWidth := m.width - 6
		if noteWidth < 40 {
			noteWidth = 40
		}
		for _, line := range lines {
			if len(line) == 0 {
				wrapped = append(wrapped, "")
			} else {
				wrapped = append(wrapped, WrapText(line, noteWidth))
			}
		}

		// Apply scroll
		if m.scrollOffset >= len(wrapped) {
			m.scrollOffset = max(0, len(wrapped)-1)
		}
		// How many lines fit for release notes
		// header(4) + version(4) + separator(2) + buttons(4) + help(2) = 16 lines overhead
		maxNoteLines := m.height - 16
		if maxNoteLines < 4 {
			maxNoteLines = 4
		}

		end := m.scrollOffset + maxNoteLines
		if end > len(wrapped) {
			end = len(wrapped)
		}
		visible := wrapped[m.scrollOffset:end]
		for _, line := range visible {
			b.WriteString("  " + line + "\n")
		}

		if end < len(wrapped) {
			b.WriteString(MutedStyle.Render(fmt.Sprintf("  ... %d more lines (↓ to scroll)", len(wrapped)-end)) + "\n")
		}
	} else {
		b.WriteString(MutedStyle.Render("  No release notes available.") + "\n")
	}

	b.WriteString("\n")

	// No asset warning
	if m.release.AssetURL == "" {
		b.WriteString(ErrorStyle.Render("  No binary available for download.") + "\n")
		b.WriteString(MutedStyle.Render("  Visit GitHub to download manually.") + "\n\n")
		b.WriteString("  " + MutedStyle.Render("[ Cancel ]") + "\n\n")
		b.WriteString(MutedStyle.Render("  esc: cancel"))
		return b.String()
	}

	// Buttons. Labelled "Install" (not "Update") to match the Settings
	// 2-state action wording — this dialog is the install confirmation.
	var cancelBtn, updateBtn string
	if m.selected == 0 {
		cancelBtn = SelectedStyle.Render("[ Cancel ]")
		updateBtn = MutedStyle.Render("[ Install ]")
	} else {
		cancelBtn = MutedStyle.Render("[ Cancel ]")
		updateBtn = accentStyle().Render("[ Install ]")
	}

	b.WriteString("  " + cancelBtn + "    " + updateBtn + "\n\n")
	b.WriteString(MutedStyle.Render("  ←/→: select  enter: confirm  esc: cancel"))

	return b.String()
}

package ui

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
	tea "github.com/charmbracelet/bubbletea"
)

type RenameState int

const (
	RenameInput RenameState = iota
	RenameConfirm
	RenameWorking
	RenameDone
	RenameError
)

type RenameInterface struct {
	cfg         *config.Config
	state       RenameState
	currentName string
	newName     string
	error       string
	sudoersNote string // non-fatal sudoers warning shown on RenameDone
	auth        AuthPrompt
	width       int
	height      int
}

func NewRenameInterface(cfg *config.Config) RenameInterface {
	return RenameInterface{
		cfg:         cfg,
		state:       RenameInput,
		currentName: cfg.ConnectionName,
		newName:     cfg.ConnectionName,
	}
}

func (m RenameInterface) Init() tea.Cmd {
	return nil
}

type renameResultMsg struct {
	err     error
	newName string
}

type sudoersRefreshMsg struct {
	err error
}

func (m RenameInterface) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Handle auth prompt when active
	if m.auth.Active() {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			handled, cmd := m.auth.HandleKey(msg)
			if handled {
				return m, cmd
			}
		case authResultMsg:
			if retryFn := m.auth.HandleAuthResult(msg); retryFn != nil {
				retryFn()
				// Auth succeeded — retry sudoers refresh
				return m, m.doSudoersRefresh()
			}
			return m, nil
		case tea.WindowSizeMsg:
			m.width = msg.Width
			m.height = msg.Height
			m.auth.SetWidth(msg.Width)
		}
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case RenameInput:
			switch msg.String() {
			case "esc":
				return m, func() tea.Msg { return BackMsg{} }
			case "enter":
				if m.newName == "" {
					m.error = "Name cannot be empty"
					return m, nil
				}
				if m.newName == m.currentName {
					m.error = "Name unchanged"
					return m, nil
				}
				// Validate name
				if len(m.newName) > 15 {
					m.error = "Name too long (max 15 characters)"
					return m, nil
				}
				validName := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
				if !validName.MatchString(m.newName) {
					m.error = "Invalid name. Use only letters, numbers, dash, underscore, dot"
					return m, nil
				}
				if isExistingInterface(m.newName) {
					m.error = fmt.Sprintf("'%s' is an existing network interface", m.newName)
					return m, nil
				}
				m.error = ""
				m.state = RenameConfirm
			case "backspace":
				if len(m.newName) > 0 {
					// Use runes to properly handle multi-byte Unicode characters
					runes := []rune(m.newName)
					m.newName = string(runes[:len(runes)-1])
				}
			default:
				if len(msg.String()) == 1 {
					m.newName += msg.String()
				}
			}

		case RenameConfirm:
			switch msg.String() {
			case "y", "Y":
				m.state = RenameWorking
				return m, m.doRename()
			case "n", "N", "esc":
				m.state = RenameInput
			}

		case RenameDone, RenameError:
			if msg.String() == "enter" || msg.String() == "esc" {
				return m, func() tea.Msg { return BackMsg{} }
			}
		}

	case renameResultMsg:
		if msg.err != nil {
			m.state = RenameError
			m.error = msg.err.Error()
		} else {
			// Snapshot previous ConnectionName so we can revert on
			// Save failure. cfg.Save is atomic — on failure the
			// on-disk ConnectionName stays whatever it was, so without
			// the revert in-memory says "renamed" while the next
			// process Load reverts to the old name. The user sees
			// the error message but the in-memory cfg would otherwise
			// silently mislead any continued in-session use (e.g.,
			// connect attempts using the not-yet-persisted new name).
			prev := m.cfg.ConnectionName
			m.cfg.ConnectionName = msg.newName
			if err := m.cfg.Save(); err != nil {
				m.cfg.ConnectionName = prev
				m.state = RenameError
				m.error = fmt.Sprintf("failed to save config: %v", err)
			} else {
				m.state = RenameDone
				m.currentName = msg.newName
				// Refresh sudoers to scope entries to the new interface name
				return m, m.doSudoersRefresh()
			}
		}

	case sudoersRefreshMsg:
		if msg.err != nil {
			if errors.Is(msg.err, sudo.ErrAuthRequired) {
				// Need password — show auth prompt, retry after success
				m.auth.Show(func() {}, func() {
					// Cancelled — show warning but don't block rename
					m.sudoersNote = "Sudoers not updated. Run 'lazyvpn install' and select Repair."
				})
				return m, nil
			}
			// Non-auth error — warn but don't block
			m.sudoersNote = fmt.Sprintf("Sudoers update failed: %v", msg.err)
		}
		// Success or non-fatal failure — stay on RenameDone

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.auth.SetWidth(msg.Width)
	}

	return m, nil
}

func (m RenameInterface) doRename() tea.Cmd {
	currentName := m.currentName
	newName := m.newName
	cfg := m.cfg

	return func() tea.Msg {
		// If connected, disconnect first
		// Native netlink creates interfaces on-demand, so we just need to
		// disconnect and the next connect will use the new name
		if isWGConnected(currentName) {
			if err := wgDisconnect(cfg); err != nil {
				return renameResultMsg{err: fmt.Errorf("failed to disconnect: %w", err)}
			}
		}

		return renameResultMsg{newName: newName}
	}
}

func (m RenameInterface) doSudoersRefresh() tea.Cmd {
	newName := m.currentName // already updated by renameResultMsg handler
	cowFilesystem := m.cfg.IsCOWFilesystem()
	sudoersInstalled := m.cfg.SudoersInstalled
	return func() tea.Msg {
		// Respect the user's install-time choice. Use the config flag rather
		// than os.Stat-ing /etc/sudoers.d/lazyvpn directly: the parent dir is
		// 0750 root:root on Arch/modern systemd, so stat from a non-root user
		// fails with EACCES — we can't distinguish "exists" from "absent" via
		// stat. cfg.SudoersInstalled is set true only after the installer
		// successfully wrote the file.
		if !sudoersInstalled {
			return sudoersRefreshMsg{} // user declined sudoers, nothing to refresh
		}
		execPath, err := osExecutable()
		if err != nil {
			return sudoersRefreshMsg{err: fmt.Errorf("could not determine binary path: %w", err)}
		}
		return sudoersRefreshMsg{err: refreshSudoers(execPath, newName, cowFilesystem)}
	}
}

func (m RenameInterface) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("Rename Interface") + "\n\n")
	b.WriteString(fmt.Sprintf("  Current name: %s\n\n", m.currentName))

	// Auth prompt overlay
	if m.auth.Active() {
		b.WriteString(m.auth.View())
		return b.String()
	}

	switch m.state {
	case RenameInput:
		b.WriteString(fmt.Sprintf("  New name: %s█\n", m.newName))
		if m.error != "" {
			b.WriteString("\n" + ErrorStyle.Render("  "+m.error) + "\n")
		}
		b.WriteString("\n" + MutedStyle.Render("  Type new name, Enter to confirm"))

	case RenameConfirm:
		b.WriteString(fmt.Sprintf("  Rename to: %s\n\n", SelectedStyle.Render(m.newName)))
		if isWGConnected(m.currentName) {
			b.WriteString(MutedStyle.Render("  Note: VPN will be disconnected during rename") + "\n\n")
		}
		b.WriteString("  Confirm rename? [y/n]\n")

	case RenameWorking:
		b.WriteString("  Renaming interface...\n")

	case RenameDone:
		b.WriteString(SuccessStyle.Render(fmt.Sprintf("  Interface renamed to: %s", m.newName)) + "\n\n")
		if m.sudoersNote != "" {
			b.WriteString(MutedStyle.Render("  "+m.sudoersNote) + "\n\n")
		}
		b.WriteString("  Press Enter to continue\n")

	case RenameError:
		b.WriteString(ErrorStyle.Render("  Error: "+m.error) + "\n\n")
		b.WriteString("  Press Enter to go back\n")
	}

	b.WriteString("\n" + MutedStyle.Render("  esc: cancel"))

	return b.String()
}

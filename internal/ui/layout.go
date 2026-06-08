package ui

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/firewall"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/logger"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/update"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// UpdateAvailableMsg signals that a new version was found.
type UpdateAvailableMsg struct {
	Release *update.Release
}

// ManualUpdateCheckMsg is the result of a user-triggered "Check for Updates Now"
// (vs. the silent daily auto-check). Carries the result so the UI can report
// "update available", "up to date", or an error explicitly.
type ManualUpdateCheckMsg struct {
	Release *update.Release
	Err     error
}

// LoggingActiveMsg signals that debug/UFW logging is active at startup.
type LoggingActiveMsg struct {
	Summary string
}

// checkForUpdate is injectable for testing.
var checkForUpdate = update.Check

// Version is set by the main package at startup.
var Version = "dev"

// Layout is the 3-pane master-detail layout
type Layout struct {
	cfg          *config.Config
	nav          *NavPane
	content      tea.Model
	prevContent  []tea.Model // stack of saved parent views for sub-view navigation
	footer       *StatusFooter
	contentType  NavItem
	navFocused   bool
	width        int
	height       int
	runUninstall bool
}

// NewLayout creates a new 3-pane layout
func NewLayout() *Layout {
	cfg, err := configLoad()
	if err != nil {
		log.Printf("lazyvpn: warning: failed to load config, using defaults: %v", err)
	}

	// Set up firewall logging callback
	log := logger.New(cfg)
	firewall.SetLogFunc(func(format string, args ...interface{}) {
		log.Log(logger.Firewall, format, args...)
	})

	// LAN stealth state persists via UFW (ufw.service re-applies rules on boot).
	// UFW is the source of truth — nothing for the TUI to re-apply on launch.

	// Default to Dashboard view, or tutorial prompt on first run
	var content tea.Model
	contentType := NavDashboard
	if !cfg.TutorialSeen {
		content = NewTutorialPrompt(cfg)
	} else {
		content = NewDashboard(cfg)
	}

	nav := NewNavPane(cfg)
	navFocused := true
	if !cfg.TutorialSeen {
		navFocused = false
		nav.SetFocused(false)
	}

	return &Layout{
		cfg:         cfg,
		nav:         nav,
		content:     content,
		footer:      NewStatusFooter(cfg),
		contentType: contentType,
		navFocused:  navFocused,
	}
}

func (l *Layout) Init() tea.Cmd {
	cmds := []tea.Cmd{
		l.nav.Init(),
		l.content.Init(),
		l.footer.Init(),
	}

	// Background logging check: alert if any debug logs or UFW packet log are active
	cmds = append(cmds, func() tea.Msg {
		count := countEnabledLogs(l.cfg)
		ufwLevel := firewallGetLoggingLevel()
		if count == 0 && ufwLevel == "off" {
			return nil
		}
		var parts []string
		if count > 0 {
			parts = append(parts, fmt.Sprintf("%d debug log(s)", count))
		}
		if ufwLevel != "off" {
			parts = append(parts, fmt.Sprintf("UFW packet log: %s", ufwLevel))
		}
		return LoggingActiveMsg{Summary: strings.Join(parts, ", ") + " active"}
	})

	// Background update check: only if user opted in and cooldown (24h) expired
	if l.cfg.AutoCheckUpdates && time.Now().Unix()-l.cfg.LastUpdateCheck > 86400 {
		cmds = append(cmds, func() tea.Msg {
			rel, err := checkForUpdate(Version)
			if err != nil || rel == nil {
				return nil
			}
			return UpdateAvailableMsg{Release: rel}
		})
		// Revert LastUpdateCheck on Save failure so next session retries
		// the check rather than thinking 24h hasn't elapsed yet (which
		// would happen if the in-memory bump persisted but disk didn't
		// — fresh Load would read the old value, but only AFTER the
		// current process exits; during this session the in-memory
		// state would prevent retries before the next 24h tick).
		prev := l.cfg.LastUpdateCheck
		l.cfg.LastUpdateCheck = time.Now().Unix()
		if err := l.cfg.Save(); err != nil {
			l.cfg.LastUpdateCheck = prev
		}
	}

	return tea.Batch(cmds...)
}

func (l *Layout) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab":
			// Sub-view mode renders content full-width with no nav pane,
			// so toggling navFocused would silently route subsequent
			// keystrokes to an invisible nav. Make Tab a no-op when there's
			// no nav to switch to.
			if len(l.prevContent) > 0 {
				return l, nil
			}
			l.navFocused = !l.navFocused
			l.nav.SetFocused(l.navFocused)
			l.setContentFocused(!l.navFocused)
			return l, nil
		}

	case tea.WindowSizeMsg:
		l.width = msg.Width
		l.height = msg.Height

		// Propagate to children
		navUpdated, navCmd := l.nav.Update(msg)
		l.nav = navUpdated
		cmds = append(cmds, navCmd)

		// Resize content with remaining width
		contentWidth, contentHeight := l.contentDimensions()
		contentMsg := tea.WindowSizeMsg{Width: contentWidth, Height: contentHeight}
		contentUpdated, contentCmd := l.content.Update(contentMsg)
		l.content = contentUpdated
		cmds = append(cmds, contentCmd)

		footerUpdated, footerCmd := l.footer.Update(msg)
		l.footer = footerUpdated
		cmds = append(cmds, footerCmd)

		return l, tea.Batch(cmds...)

	case NavSelectMsg:
		// Close doesn't switch content
		if msg.Item == NavClose {
			return l, nil
		}
		// Update opens as a sub-view (with Back support)
		if msg.Item == NavUpdate && l.nav.updateAvailable != nil {
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewUpdateView(l.nav.updateAvailable, Version)
			l.navFocused = false
			l.nav.SetFocused(false)
			l.setContentFocused(true)
			return l, l.initContent()
		}
		// Top-level nav switch — clear any sub-view stack so the
		// invariant "len(prevContent) > 0 ⇔ in sub-view mode" holds.
		// Without this, choosing a top-level nav item from anywhere
		// other than the nav itself would leave stale parents on the
		// stack and trap Tab in its sub-view-mode no-op forever.
		l.prevContent = nil
		l.contentType = msg.Item
		switch msg.Item {
		case NavDashboard:
			l.content = NewDashboard(l.cfg)
		case NavServers:
			l.content = NewMyServersBrowser(l.cfg)
		case NavDynamic:
			l.content = NewDynamicServerBrowser(l.cfg, "")
		case NavSettings:
			l.content = NewSettings(l.cfg)
		}
		return l, l.initContent()

	case FocusContentMsg:
		l.navFocused = false
		l.nav.SetFocused(false)
		l.setContentFocused(true)
		return l, nil

	case BackMsg:
		if len(l.prevContent) > 0 {
			// Restore saved parent view with cursor state intact
			l.content = l.prevContent[len(l.prevContent)-1]
			l.prevContent = l.prevContent[:len(l.prevContent)-1]
			// Rebuild items to reflect any config changes made in sub-view
			if s, ok := l.content.(*Settings); ok {
				s.cfg.Reload()
				s.items = s.buildItems()
				s.splitColumns()
			}
			// If returning to a no-providers browser after provider setup,
			// replace it with a fresh browser that will load the new provider
			if sb, ok := l.content.(*ServerBrowser); ok && sb.noProviders {
				l.content = NewDynamicServerBrowser(l.cfg, "")
				return l, l.initContent()
			}
			if d, ok := l.content.(*Dashboard); ok {
				d.refresh()
			}
			// Stay in content pane — user was interacting with content, not nav
			l.navFocused = false
			l.nav.SetFocused(false)
			l.setContentFocused(true)
			// Send resize so restored view has correct dimensions
			// (sub-view mode uses different sizing than normal pane mode)
			if l.width > 0 && l.height > 0 {
				w, h := l.contentDimensions()
				updated, cmd := l.content.Update(tea.WindowSizeMsg{Width: w, Height: h})
				l.content = updated
				return l, cmd
			}
			return l, nil
		}
		// No saved content — fall through to fresh-create (top-level back)
		l.navFocused = true
		l.nav.SetFocused(true)
		l.setContentFocused(false)
		switch l.contentType {
		case NavDashboard:
			l.content = NewDashboard(l.cfg)
		case NavServers:
			l.content = NewMyServersBrowser(l.cfg)
		case NavDynamic:
			l.content = NewDynamicServerBrowser(l.cfg, "")
		case NavSettings:
			l.content = NewSettings(l.cfg)
		default:
			l.contentType = NavDashboard
			l.nav.cursor = NavDashboard
			l.content = NewDashboard(l.cfg)
		}
		return l, l.initContent()

	case StatusUpdateMsg:
		// Update all components
		navUpdated, navCmd := l.nav.Update(msg)
		l.nav = navUpdated
		cmds = append(cmds, navCmd)

		footerUpdated, footerCmd := l.footer.Update(msg)
		l.footer = footerUpdated
		cmds = append(cmds, footerCmd)

		// Propagate to content view (e.g., dashboard needs this to refresh)
		contentUpdated, contentCmd := l.content.Update(msg)
		l.content = contentUpdated
		cmds = append(cmds, contentCmd)

		return l, tea.Batch(cmds...)

	case LoggingActiveMsg:
		l.footer.OverlayText = "Logging active: " + msg.Summary
		l.footer.OverlayIsError = false
		return l, nil

	case UpdateAvailableMsg:
		l.nav.SetUpdateAvailable(msg.Release)
		return l, nil

	case ManualUpdateCheckMsg:
		if msg.Err != nil {
			l.footer.OverlayText = "Update check failed: " + msg.Err.Error()
			l.footer.OverlayIsError = true
			return l, nil
		}
		if msg.Release != nil {
			l.nav.SetUpdateAvailable(msg.Release)
			l.footer.OverlayText = "Update available: " + msg.Release.TagName + " — run 'lazyvpn update' to install"
			l.footer.OverlayIsError = false
			return l, nil
		}
		l.footer.OverlayText = "You're on the latest version (" + Version + ")"
		l.footer.OverlayIsError = false
		return l, nil

	case RunUpdateMsg:
		rel := msg.Release
		return l, func() tea.Msg {
			binaryPath, err := osExecutable()
			if err != nil {
				return UpdateResultMsg{Err: err}
			}
			if err := update.Apply(rel, binaryPath); err != nil {
				return UpdateResultMsg{Err: err}
			}
			return UpdateResultMsg{}
		}

	case UpdateResultMsg:
		if msg.Err != nil {
			// Route error to the update view if it's the current content
			contentUpdated, contentCmd := l.content.Update(msg)
			l.content = contentUpdated
			return l, contentCmd
		}
		// Success — quit so user restarts with new version
		return l, tea.Quit

	case RunUninstallMsg:
		l.runUninstall = true
		return l, tea.Quit

	case AutoconnectServerSelectMsg:
		// Server selected for autoconnect - go back to settings
		if len(l.prevContent) > 0 {
			l.content = l.prevContent[len(l.prevContent)-1]
			l.prevContent = l.prevContent[:len(l.prevContent)-1]
			if s, ok := l.content.(*Settings); ok {
				s.cfg.Reload()
				s.items = s.buildItems()
				s.splitColumns()
			}
			l.contentType = NavSettings
			l.navFocused = false
			l.nav.SetFocused(false)
			l.setContentFocused(true)
			return l, nil
		}
		l.content = NewSettings(l.cfg)
		l.contentType = NavSettings
		return l, l.initContent()

	case SwitchViewMsg:
		switch msg.View {
		// Top-level nav switches — no push (full view replacement)
		case "connect-progress":
			l.prevContent = nil
			l.contentType = NavDashboard
			l.nav.cursor = NavDashboard
			l.content = NewConnectProgress(l.cfg, msg.Server, msg.Provider, msg.Dynamic)
			return l, l.initContent()
		case "disconnect-confirm":
			l.prevContent = nil
			l.content = NewDisconnectConfirm(l.cfg)
			return l, l.initContent()
		case "disconnect-progress":
			l.prevContent = nil
			l.content = NewDisconnectProgress(l.cfg)
			return l, l.initContent()
		case "settings":
			// Return to settings from sub-view — pop saved state if available
			if len(l.prevContent) > 0 {
				l.content = l.prevContent[len(l.prevContent)-1]
				l.prevContent = l.prevContent[:len(l.prevContent)-1]
				if s, ok := l.content.(*Settings); ok {
					s.cfg.Reload()
					s.items = s.buildItems()
					s.splitColumns()
				}
				l.contentType = NavSettings
				l.navFocused = false
				l.nav.SetFocused(false)
				l.setContentFocused(true)
				return l, nil
			}
			l.content = NewSettings(l.cfg)
			l.contentType = NavSettings
			return l, l.initContent()
		case "dynamic-browser":
			// Top-level transition — clear stack to maintain the sub-view
			// invariant (see NavSelectMsg comment).
			l.prevContent = nil
			l.contentType = NavDynamic
			l.content = NewDynamicServerBrowser(l.cfg, msg.Provider)
			return l, l.initContent()
		case "server-list":
			// Top-level transition — clear stack.
			l.prevContent = nil
			l.content = NewMyServersBrowser(l.cfg)
			l.contentType = NavServers
			return l, l.initContent()

		// Sub-views — push current content before switching
		case "provider-setup":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewProviderSetup(l.cfg)
			return l, l.initContent()
		case "provider-select":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewProviderSelect(l.cfg)
			return l, l.initContent()
		case "add-server":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewAddServer(l.cfg)
			return l, l.initContent()
		case "remove-server":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewRemoveServer(l.cfg)
			return l, l.initContent()
		case "remove-provider":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewRemoveProvider(l.cfg)
			return l, l.initContent()
		case "rename-interface":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewRenameInterface(l.cfg)
			return l, l.initContent()
		case "tutorial":
			if _, isPrompt := l.content.(*TutorialPrompt); isPrompt {
				l.prevContent = append(l.prevContent, NewDashboard(l.cfg))
			} else {
				l.prevContent = append(l.prevContent, l.content)
			}
			l.content = NewTutorial()
			return l, l.initContent()
		case "uninstall_confirm":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewUninstallConfirm()
			return l, l.initContent()
		case "autoconnect-server-select":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewAutoconnectSelect(l.cfg)
			return l, l.initContent()
		case "audit":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewAuditView(l.cfg)
			return l, l.initContent()
		case "speedtest":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewSpeedtest(l.cfg)
			return l, l.initContent()
		case "leaktest":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewLeaktest(l.cfg)
			return l, l.initContent()
		case "dns-providers":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewDNSProviderSelect(l.cfg)
			return l, l.initContent()
		case "view-log":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewLogViewer(l.cfg)
			return l, l.initContent()
		case "mtu-input":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewMTUInput(l.cfg)
			return l, l.initContent()
		case "health-targets":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewHealthTargets(l.cfg)
			return l, l.initContent()
		case "debug-settings":
			l.prevContent = append(l.prevContent, l.content)
			l.content = NewDebugSettings(l.cfg)
			return l, l.initContent()
		}
	}

	// Route key input to focused pane; all other messages (async results) go to content
	if _, isKey := msg.(tea.KeyMsg); isKey {
		if l.navFocused {
			navUpdated, navCmd := l.nav.Update(msg)
			l.nav = navUpdated
			cmds = append(cmds, navCmd)
		} else {
			contentUpdated, contentCmd := l.content.Update(msg)
			l.content = contentUpdated
			cmds = append(cmds, contentCmd)
		}
	} else {
		contentUpdated, contentCmd := l.content.Update(msg)
		l.content = contentUpdated
		cmds = append(cmds, contentCmd)
	}

	return l, tea.Batch(cmds...)
}

func (l *Layout) View() string {
	// Header bar with border
	brandStyle := lipgloss.NewStyle().
		Foreground(ColorAccent).
		Background(ColorBg).
		Bold(true)

	versionStyle := lipgloss.NewStyle().
		Foreground(ColorMuted).
		Background(ColorBg)

	bgStyle := lipgloss.NewStyle().Background(ColorBg)

	spacedBrand := "L a z y V P N"
	brandRendered := brandStyle.Render(spacedBrand)
	versionRendered := versionStyle.Render(Version)

	brandW := lipgloss.Width(brandRendered)
	versionW := lipgloss.Width(versionRendered)

	// Inner width: total width - 2 (border) - 2 (padding)
	innerWidth := l.width - 4
	if innerWidth < 20 {
		innerWidth = 20
	}

	// Center brand, right-align version
	leftPad := (innerWidth - brandW) / 2
	if leftPad < 0 {
		leftPad = 0
	}
	gapAfterBrand := innerWidth - leftPad - brandW - versionW
	if gapAfterBrand < 1 {
		gapAfterBrand = 1
	}

	headerContent := bgStyle.Render(strings.Repeat(" ", leftPad)) + brandRendered + bgStyle.Render(strings.Repeat(" ", gapAfterBrand)) + versionRendered

	headerStyle := lipgloss.NewStyle().
		Background(ColorBg).
		Padding(0, 1).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(ColorBarBorder).
		Width(l.width - 2)

	headerView := headerStyle.Render(headerContent)

	// Sub-view mode: full-width content, no nav or footer
	if len(l.prevContent) > 0 {
		contentView := l.content.View()

		// Full width: total - border(2)
		fullWidth := l.width - 2
		if fullWidth < 20 {
			fullWidth = 20
		}
		// header(3) + gap(1) + content border(2) = 6
		fullHeight := l.height - 6
		if fullHeight < 1 {
			fullHeight = 1
		}
		contentStyle := lipgloss.NewStyle().
			Width(fullWidth).
			Height(fullHeight).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(ColorAccent).
			Padding(1, 1)

		maxLines := fullHeight - 2
		if maxLines > 0 {
			lines := strings.Split(contentView, "\n")
			if len(lines) > maxLines {
				contentView = strings.Join(lines[:maxLines], "\n")
			}
		}

		return lipgloss.JoinVertical(
			lipgloss.Left,
			headerView,
			"",
			contentStyle.Render(contentView),
		)
	}

	// Normal mode: nav + content side by side with footer
	navView := l.nav.View()
	contentView := l.content.View()

	// Content pane — full box border, accent when focused, dim when nav focused
	contentBorderColor := ColorDimBorder
	if !l.navFocused {
		contentBorderColor = ColorAccent
	}
	// nav border(2) + content border(2) + gap(1) = 5
	contentWidth := l.width - l.nav.width - 5
	if contentWidth < 20 {
		contentWidth = 20
	}
	// header(3) + footer(3) + pane border(2) + vertical gaps(2) = 10
	paneHeight := l.height - 10
	contentStyle := lipgloss.NewStyle().
		Width(contentWidth).
		Height(paneHeight).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(contentBorderColor).
		Padding(1, 1)

	// Truncate content to fit within the pane so the border is never pushed off
	maxContentLines := paneHeight - 2 // Height minus vertical padding
	if maxContentLines > 0 {
		lines := strings.Split(contentView, "\n")
		if len(lines) > maxContentLines {
			contentView = strings.Join(lines[:maxContentLines], "\n")
		}
	}

	mainArea := lipgloss.JoinHorizontal(
		lipgloss.Top,
		navView,
		" ", // gap between panes
		contentStyle.Render(contentView),
	)

	// Set footer overlay for views that provide descriptions
	if dp, ok := l.content.(descriptionProvider); ok {
		l.footer.OverlayText = dp.CurrentDescription()
		l.footer.OverlayIsError = dp.StatusIsError()
	} else {
		l.footer.OverlayText = ""
		l.footer.OverlayIsError = false
	}

	// Footer at bottom
	footerView := l.footer.View()

	return lipgloss.JoinVertical(
		lipgloss.Left,
		headerView,
		"",
		mainArea,
		"",
		footerView,
	)
}

// contentDimensions returns the width and height available for the content view.
// In sub-view mode (prevContent non-empty), content gets full width (no nav/footer).
func (l *Layout) contentDimensions() (int, int) {
	if len(l.prevContent) > 0 {
		// Full width: total - content border(2) - content padding(2)
		w := l.width - 4
		if w < 1 {
			w = 1
		}
		// Full height: total - header(3) - gap(1) - content border(2) - content padding(2)
		h := l.height - 8
		if h < 1 {
			h = 1
		}
		return w, h
	}
	// Normal pane mode: nav border(2) + content border(2) + gap(1) + content padding(2) = 7
	w := l.width - l.nav.width - 7
	if w < 1 {
		w = 1
	}
	// header(3) + footer(3) + pane border(2) + vertical gaps(2) + content padding(2) = 12
	h := l.height - 12
	if h < 1 {
		h = 1
	}
	return w, h
}

// initContent sends the current dimensions to the content view and calls Init()
func (l *Layout) initContent() tea.Cmd {
	l.setContentFocused(!l.navFocused)
	var cmds []tea.Cmd
	if l.width > 0 && l.height > 0 {
		contentWidth, contentHeight := l.contentDimensions()
		sizeMsg := tea.WindowSizeMsg{Width: contentWidth, Height: contentHeight}
		updated, cmd := l.content.Update(sizeMsg)
		l.content = updated
		cmds = append(cmds, cmd)
	}
	cmds = append(cmds, l.content.Init())
	return tea.Batch(cmds...)
}

// setContentFocused propagates focus state to content views that support it.
func (l *Layout) setContentFocused(focused bool) {
	type focusable interface{ SetFocused(bool) }
	if f, ok := l.content.(focusable); ok {
		f.SetFocused(focused)
	}
}

// ShouldRunUninstall returns true if uninstall should run after exit
func (l *Layout) ShouldRunUninstall() bool {
	return l.runUninstall
}

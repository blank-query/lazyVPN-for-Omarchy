package ui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/tools"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// settingsBlinkMsg is a dedicated blink tick for settings scroll arrows.
type settingsBlinkMsg struct{}

// execCommandFn is injectable for testing to prevent xdg-open from opening browsers.
var execCommandFn = exec.Command

type settingItem struct {
	id          string
	name        string
	value       string
	description string
	section     string
	isToggle    bool
	isAction    bool // opens another view
}

// leftSections defines which sections go in the left column
// leftSections are the section names that render in the left column.
// "Servers" moved to the right column to balance line counts: with it on
// the left, left was 15 lines vs right 10 — enough to trigger the scroll
// fallback at 30-line terminals. Right now the split is ~11 vs ~14, close
// enough to fit without scrolling at typical sizes.
var leftSections = []string{"Providers", "Automation", "Debug"}

type Settings struct {
	items         []settingItem
	leftItems     []settingItem
	rightItems    []settingItem
	leftCol       int // cursor index within left column
	rightCol      int // cursor index within right column
	activeCol     int // 0 = left, 1 = right
	cfg           *config.Config
	width         int
	height        int
	statusText    string
	statusIsError bool
	quitting      bool

	// Scroll state
	scrollOffset int  // first visible rendered line index
	blinkOn      bool // blink toggle for scroll arrows

	// Focus tracking — hides cursor when nav pane has focus
	focused bool

	// Auth prompt — shown when a firewall operation
	// returns ErrAuthRequired (user has no sudoers file).
	auth AuthPrompt
}

func NewSettings(cfg *config.Config) *Settings {
	s := &Settings{cfg: cfg}
	s.items = s.buildItems()
	s.splitColumns()
	return s
}

func (m *Settings) splitColumns() {
	leftSet := make(map[string]bool)
	for _, s := range leftSections {
		leftSet[s] = true
	}
	m.leftItems = nil
	m.rightItems = nil
	for _, item := range m.items {
		if leftSet[item.section] {
			m.leftItems = append(m.leftItems, item)
		} else {
			m.rightItems = append(m.rightItems, item)
		}
	}
	// Clamp cursors
	if m.leftCol >= len(m.leftItems) {
		m.leftCol = max(0, len(m.leftItems)-1)
	}
	if m.rightCol >= len(m.rightItems) {
		m.rightCol = max(0, len(m.rightItems)-1)
	}
}

func (m *Settings) activeItems() []settingItem {
	if m.activeCol == 0 {
		return m.leftItems
	}
	return m.rightItems
}

func (m *Settings) activeCursor() int {
	if m.activeCol == 0 {
		return m.leftCol
	}
	return m.rightCol
}

func (m *Settings) setActiveCursor(v int) {
	if m.activeCol == 0 {
		m.leftCol = v
	} else {
		m.rightCol = v
	}
}

// visibleLines returns how many rendered lines fit in the viewport.
func (m *Settings) visibleLines() int {
	// title(1) + blank(1) + up_arrow(1) + down_arrow(1) + help(1) + blank before help(1) + padding(1) = 7 overhead
	v := m.height - 7
	if v < 4 {
		v = 4
	}
	return v
}

// renderedLineCount returns the total rendered lines for a column,
// including section headers and blank separator lines.
func renderedLineCount(items []settingItem) int {
	if len(items) == 0 {
		return 0
	}
	lines := 0
	currentSection := ""
	for i, item := range items {
		if item.section != currentSection {
			currentSection = item.section
			if i > 0 {
				lines++ // blank line before section
			}
			lines++ // section header
		}
		lines++ // item line
	}
	return lines
}

// cursorToLine maps a cursor index within a column's items to a
// rendered line number (0-based), accounting for section headers and blanks.
func cursorToLine(items []settingItem, cursor int) int {
	line := 0
	currentSection := ""
	for i, item := range items {
		if item.section != currentSection {
			currentSection = item.section
			if i > 0 {
				line++ // blank line
			}
			line++ // section header
		}
		if i == cursor {
			return line
		}
		line++
	}
	return line
}

// adjustScroll updates scrollOffset after a cursor movement using page-jump logic.
func (m *Settings) adjustScroll() {
	items := m.activeItems()
	if len(items) == 0 {
		return
	}
	visible := m.visibleLines()
	total := renderedLineCount(items)
	if total <= visible {
		m.scrollOffset = 0
		return
	}
	cur := cursorToLine(items, m.activeCursor())

	if cur >= m.scrollOffset+visible {
		// Cursor below visible — jump forward one page
		m.scrollOffset = cur - (cur % visible)
		maxOffset := total - visible
		if m.scrollOffset > maxOffset {
			m.scrollOffset = maxOffset
		}
	}
	if cur < m.scrollOffset {
		// Cursor above visible — jump back
		m.scrollOffset = cur - (cur % visible)
	}
	if m.scrollOffset < 0 {
		m.scrollOffset = 0
	}
}

func (m *Settings) buildItems() []settingItem {
	cfg := m.cfg

	// Status values
	onOff := func(b bool) string {
		if b {
			return "ON"
		}
		return "OFF"
	}

	acMode := "Last Used"
	acServer := ""
	switch cfg.AutostartMode {
	case "quickest":
		acMode = "Fastest"
	case "random":
		acMode = "Random"
	case "specific":
		acMode = "Specific"
		if cfg.AutostartServer != "" {
			acServer = cfg.AutostartServer
		} else {
			acServer = "(not set)"
		}
	}

	// Count providers
	providers, _ := config.ListProviders(cfg.ConfigDir)
	providerCount := "None"
	if len(providers) > 0 {
		providerCount = fmt.Sprintf("%d", len(providers))
	}

	// Count manual servers
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	servers, _ := wireguard.ListConfigs(wgDir)
	serverCount := "None"
	if len(servers) > 0 {
		serverCount = fmt.Sprintf("%d", len(servers))
	}

	items := []settingItem{
		// Dynamic Server Providers
		{id: "setup-provider", name: "Set Up Provider", value: providerCount, description: "Add or manage provider credentials", section: "Providers", isAction: true},
		{id: "refresh-servers", name: "Refresh Server List", value: "", description: "Re-download servers from providers", section: "Providers", isAction: true},
		{id: "remove-provider", name: "Remove Provider", value: "", description: "Delete provider credentials and cached servers", section: "Providers", isAction: true},

		// Automation
		{id: "autoconnect", name: "Autoconnect on Startup", value: onOff(cfg.Autostart), description: "Connect to VPN when system boots", section: "Automation", isToggle: true},
		{id: "autoconnect-mode", name: "AC Startup Server", value: acMode, description: "Which server to use for autoconnect", section: "Automation"},
	}

	// Add specific server selector only when mode is "specific"
	if cfg.AutostartMode == "specific" {
		items = append(items, settingItem{id: "autoconnect-server", name: "  Select Server", value: acServer, description: "Choose specific server for autoconnect", section: "Automation", isAction: true})
	}

	items = append(items, []settingItem{
		{id: "auto-recover", name: "Auto-Recover Connection", value: onOff(cfg.AutoRecover), description: "Reconnect if connection drops", section: "Automation", isToggle: true},
		{id: "auto-failover", name: "Auto-Failover", value: onOff(cfg.AutoFailover), description: "Try new server if current one fails", section: "Automation", isToggle: true},
		{id: "auto-check-updates", name: "Auto-Check Updates", value: onOff(cfg.AutoCheckUpdates), description: "Check for new versions daily (disabled by default)", section: "Automation", isToggle: true},
		{id: "check-updates", name: "Check for Updates Now", value: "", description: "Check GitHub for a newer release right now", section: "Automation", isAction: true},

		// Manual Servers
		{id: "add-server", name: "Import WireGuard Config", value: serverCount, description: "Manually add a server config", section: "Servers", isAction: true},
		{id: "remove-server", name: "Remove Server", value: "", description: "Delete a manual server config", section: "Servers", isAction: true},

		// Debug & Logs
		{id: "debug-settings", name: "Debug & Logs", value: debugSummary(cfg), description: "Log toggles, log mode, UFW packet logging", section: "Debug", isAction: true},

		// Advanced
		{id: "health-targets", name: "Health Check Targets", value: fmt.Sprintf("%d ping, %s", len(cfg.PingTargets), cfg.DNSProbeHost), description: "Configure daemon health check endpoints", section: "Advanced", isAction: true},
		{id: "rename-interface", name: "WireGuard Interface", value: cfg.ConnectionName, description: "Change the network interface name", section: "Advanced", isAction: true},
		{id: "custom-mtu", name: "Custom MTU", value: mtuDisplay(cfg.CustomMTU), description: "WireGuard MTU (default 1420)", section: "Advanced", isAction: true},
		{id: "tutorial", name: "Show Tutorial", value: "", description: "Learn how to use LazyVPN", section: "Advanced", isAction: true},
		{id: "github", name: "Show GitHub", value: "", description: "Open project page for help or issues", section: "Advanced", isAction: true},
		{id: "uninstall", name: "Uninstall LazyVPN", value: "", description: "Remove LazyVPN and all settings", section: "Advanced", isAction: true},
	}...)

	return items
}

// CurrentDescription returns a status message if one is set,
// otherwise the description of the currently selected item.
func (m *Settings) CurrentDescription() string {
	if m.statusText != "" {
		return m.statusText
	}
	items := m.activeItems()
	cursor := m.activeCursor()
	if cursor < len(items) {
		return items[cursor].description
	}
	return ""
}

// StatusIsError returns true when the current status message is an error.
func (m *Settings) StatusIsError() bool {
	return m.statusText != "" && m.statusIsError
}

// SetFocused sets whether the settings pane has input focus.
func (m *Settings) SetFocused(focused bool) {
	m.focused = focused
}

func (m *Settings) Init() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return settingsBlinkMsg{}
	})
}

func (m *Settings) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Handle auth prompt input and async results
	if m.auth.Active() {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			handled, cmd := m.auth.HandleKey(msg)
			if handled {
				if !m.auth.Active() {
					// Cancelled — rebuild items to reflect reverted state
					m.statusText = ""
					m.statusIsError = false
					m.items = m.buildItems()
					m.splitColumns()
				}
				return m, cmd
			}
		case authResultMsg:
			if retryFn := m.auth.HandleAuthResult(msg); retryFn != nil {
				retryFn()
				m.items = m.buildItems()
				m.splitColumns()
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
	case ManualUpdateCheckMsg:
		// Result of "Check for Updates Now". statusText feeds CurrentDescription,
		// which the footer renders — so this is what the user actually sees.
		if msg.Err != nil {
			m.statusText = "Update check failed: " + msg.Err.Error()
			m.statusIsError = true
			return m, nil
		}
		if msg.Release != nil {
			m.statusText = "Update available: " + msg.Release.TagName + " — run 'lazyvpn update' to install"
			m.statusIsError = false
			rel := msg.Release
			// Also raise the nav banner (handled in Layout).
			return m, func() tea.Msg { return UpdateAvailableMsg{Release: rel} }
		}
		m.statusText = "You're on the latest version (" + Version + ")"
		m.statusIsError = false
		return m, nil
	case tea.KeyMsg:
		m.statusText = ""
		m.statusIsError = false
		switch msg.String() {
		case "up":
			cur := m.activeCursor()
			if cur > 0 {
				m.setActiveCursor(cur - 1)
				m.adjustScroll()
			}
		case "down":
			cur := m.activeCursor()
			items := m.activeItems()
			if cur < len(items)-1 {
				m.setActiveCursor(cur + 1)
				m.adjustScroll()
			}
		case "left":
			if m.activeCol == 1 {
				m.activeCol = 0
				m.adjustScroll()
			}
		case "right":
			if m.activeCol == 0 {
				m.activeCol = 1
				m.adjustScroll()
			}
		case "enter", " ":
			return m.handleSelection()
		case "home":
			m.setActiveCursor(0)
			m.adjustScroll()
		case "end":
			items := m.activeItems()
			if len(items) > 0 {
				m.setActiveCursor(len(items) - 1)
				m.adjustScroll()
			}
		}

	case refreshServersDoneMsg:
		m.statusText = msg.message
		m.statusIsError = strings.HasPrefix(msg.message, "Error")
		if m.statusIsError {
			notifyError(m.statusText)
		} else {
			notifyInfo("LazyVPN", m.statusText)
		}
		m.items = m.buildItems()
		m.splitColumns()
	case githubOpenedMsg:
		m.statusText = "Opening GitHub in browser..."
		notifyInfo("LazyVPN", m.statusText)

	case settingsBlinkMsg:
		m.blinkOn = !m.blinkOn
		return m, tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
			return settingsBlinkMsg{}
		})

	case StatusUpdateMsg:
		// no-op for blink (handled by settingsBlinkMsg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.adjustScroll()
	}

	return m, nil
}

type refreshServersDoneMsg struct {
	message string
}

func (m *Settings) handleSelection() (tea.Model, tea.Cmd) {
	items := m.activeItems()
	cursor := m.activeCursor()
	if cursor >= len(items) {
		return m, nil
	}

	item := items[cursor]

	switch item.id {
	// Actions that switch views
	case "setup-provider":
		return m, func() tea.Msg {
			return SwitchViewMsg{View: "provider-setup"}
		}
	case "add-server":
		return m, func() tea.Msg {
			return SwitchViewMsg{View: "add-server"}
		}
	case "remove-server":
		return m, func() tea.Msg {
			return SwitchViewMsg{View: "remove-server"}
		}
	case "remove-provider":
		return m, func() tea.Msg {
			return SwitchViewMsg{View: "remove-provider"}
		}
	case "tutorial":
		return m, func() tea.Msg {
			return SwitchViewMsg{View: "tutorial"}
		}
	case "github":
		return m, m.openGitHub()
	case "rename-interface":
		return m, func() tea.Msg {
			return SwitchViewMsg{View: "rename-interface"}
		}
	case "custom-mtu":
		return m, func() tea.Msg {
			return SwitchViewMsg{View: "mtu-input"}
		}
	case "health-targets":
		return m, func() tea.Msg {
			return SwitchViewMsg{View: "health-targets"}
		}
	// Actions that do something in-place
	case "refresh-servers":
		return m, m.doRefreshServers()

	// Toggles
	case "autoconnect":
		m.cfg.Autostart = !m.cfg.Autostart
		if err := m.cfg.Save(); err != nil {
			m.cfg.Autostart = !m.cfg.Autostart
			m.statusText = "Failed to save config"
			m.statusIsError = true
			break
		}
		// Create or remove the XDG autostart desktop file
		if err := manageAutoconnectDesktopFile(m.cfg.Autostart); err != nil {
			m.statusText = fmt.Sprintf("Error: desktop file: %v", err)
			m.statusIsError = true
			notifyError(m.statusText)
		}
	case "auto-recover":
		m.cfg.AutoRecover = !m.cfg.AutoRecover
		if err := m.cfg.Save(); err != nil {
			m.cfg.AutoRecover = !m.cfg.AutoRecover
			m.statusText = "Failed to save config"
			m.statusIsError = true
		}
	case "auto-failover":
		m.cfg.AutoFailover = !m.cfg.AutoFailover
		if err := m.cfg.Save(); err != nil {
			m.cfg.AutoFailover = !m.cfg.AutoFailover
			m.statusText = "Failed to save config"
			m.statusIsError = true
		}
	case "auto-check-updates":
		m.cfg.AutoCheckUpdates = !m.cfg.AutoCheckUpdates
		if err := m.cfg.Save(); err != nil {
			m.cfg.AutoCheckUpdates = !m.cfg.AutoCheckUpdates
			m.statusText = "Failed to save config"
			m.statusIsError = true
		}
	case "check-updates":
		// Manual, on-demand update check. Result is reported via the footer
		// overlay (ManualUpdateCheckMsg handled in Layout) — reuses the same
		// checkForUpdate path the daily auto-check uses.
		m.statusText = "Checking for updates..."
		m.statusIsError = false
		return m, func() tea.Msg {
			rel, err := checkForUpdate(Version)
			return ManualUpdateCheckMsg{Release: rel, Err: err}
		}
	case "debug-settings":
		return m, func() tea.Msg {
			return SwitchViewMsg{View: "debug-settings"}
		}

	// Cycle options
	case "autoconnect-mode":
		prev := m.cfg.AutostartMode
		switch m.cfg.AutostartMode {
		case "last_used", "":
			m.cfg.AutostartMode = "quickest"
		case "quickest":
			m.cfg.AutostartMode = "random"
		case "random":
			m.cfg.AutostartMode = "specific"
		case "specific":
			m.cfg.AutostartMode = "last_used"
		}
		if err := m.cfg.Save(); err != nil {
			m.cfg.AutostartMode = prev
			m.statusText = "Failed to save config"
			m.statusIsError = true
		}
	case "autoconnect-server":
		// Navigate to server selector for specific autoconnect server
		return m, func() tea.Msg {
			return SwitchViewMsg{View: "autoconnect-server-select"}
		}
	// Other
	case "uninstall":
		return m, func() tea.Msg {
			return SwitchViewMsg{View: "uninstall_confirm"}
		}
	}

	// Rebuild items to reflect changes
	m.items = m.buildItems()
	m.splitColumns()
	return m, nil
}

func (m *Settings) doRefreshServers() tea.Cmd {
	return func() tea.Msg {
		cacheDir := filepath.Join(m.cfg.ConfigDir, "cache")

		// Fetch from gluetun
		if err := fetchServers(cacheDir, true); err != nil {
			return refreshServersDoneMsg{message: fmt.Sprintf("Error: %s", err)}
		}

		// Filter for each provider
		providers, _ := configListProviders(m.cfg.ConfigDir)
		total := 0
		for _, p := range providers {
			servers, err := filterProviderServers(cacheDir, p)
			if err == nil {
				total += len(servers)
			}
		}

		return refreshServersDoneMsg{message: fmt.Sprintf("Refreshed %d servers", total)}
	}
}

func logModeDisplay(mode string) string {
	if mode == "accurate" {
		return "Accurate"
	}
	return "Safe"
}

func mtuDisplay(mtu int) string {
	return fmt.Sprintf("%d", mtu)
}

func bwDisplayMode(mode string) string {
	if mode == "bar" {
		return "Bar"
	}
	return "Sparkline"
}

func bwUnitDisplay(unit string) string {
	if unit == "bytes" {
		return "KB/s"
	}
	return "Kbps"
}

// localNetworkMode returns the display label ("Allow"/"Stealth"/"Block") for the
// current LAN rule state. Derived from UFW-backed cached flags.
func localNetworkMode(lanBlock, stealth bool) string {
	if stealth {
		return "Stealth"
	}
	if lanBlock {
		return "Block"
	}
	return "Allow"
}

// localNetworkDescription returns the description text for the current LAN mode.
func localNetworkDescription(lanBlock, stealth bool) string {
	if stealth {
		return "Stealth: outbound LAN works, inbound blocked (coffee shop mode)"
	}
	if lanBlock {
		return "Block: all LAN traffic blocked (coffee shop mode)"
	}
	return "Allow: full LAN access (printers, file shares, etc.)"
}

func dnsProviderSummary(cfg *config.Config) string {
	providers := cfg.DNSProviders
	if len(providers) == 0 {
		providers = tools.DefaultDNSProviders
	}
	return fmt.Sprintf("%d selected", len(providers))
}

type githubOpenedMsg struct{}

func (m *Settings) openGitHub() tea.Cmd {
	return func() tea.Msg {
		cmd := execCommandFn("xdg-open", "https://github.com/blank-query/lazyVPN-for-Omarchy")
		if err := cmd.Start(); err == nil {
			go cmd.Wait() // reap child process to avoid zombie
		}
		return githubOpenedMsg{}
	}
}

// manageAutoconnectDesktopFile creates or removes the XDG autostart desktop file.
// When enabled, the desktop environment will run "lazyvpn boot" at login.
func manageAutoconnectDesktopFile(enable bool) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	autostartDir := filepath.Join(homeDir, ".config", "autostart")
	desktopFile := filepath.Join(autostartDir, "lazyvpn.desktop")

	if !enable {
		// Remove desktop file
		if err := os.Remove(desktopFile); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	// Create autostart directory
	if err := os.MkdirAll(autostartDir, 0755); err != nil {
		return err
	}

	// Find the lazyvpn binary path
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	// Create desktop file
	content := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=LazyVPN Autostart
Exec="%s" boot
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
`, execPath)

	return os.WriteFile(desktopFile, []byte(content), 0644)
}

func (m *Settings) renderColumn(items []settingItem, cursor int, isActive bool) string {
	// Build all rendered lines first
	var lines []string
	currentSection := ""
	for i, item := range items {
		if item.section != currentSection {
			currentSection = item.section
			if i > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, MutedStyle.Render("───")+" "+accentStyle().Render(currentSection)+" "+MutedStyle.Render("───"))
		}

		prefix := "  "
		if m.focused && isActive && i == cursor {
			prefix = "> "
		}

		value := ""
		if item.value != "" {
			value = fmt.Sprintf(" [%s]", item.value)
		}

		name := item.name + value
		if m.focused && isActive && i == cursor {
			name = SelectedStyle.Render(name)
		}
		lines = append(lines, prefix+name)
	}

	// Apply scroll window
	visible := m.visibleLines()
	start := m.scrollOffset
	if start > len(lines) {
		start = len(lines)
	}
	end := start + visible
	if end > len(lines) {
		end = len(lines)
	}
	sliced := lines[start:end]

	var b strings.Builder
	for _, line := range sliced {
		b.WriteString(line + "\n")
	}
	return b.String()
}

func (m *Settings) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	title := TitleStyle.Render("Settings")
	b.WriteString(title + "\n\n")

	// Auth prompt overlay
	if m.auth.Active() {
		b.WriteString(m.auth.View())
		return b.String()
	}

	// Calculate column width. Clamp pathological sizes (terminals can briefly
	// report 0/1/2 cols during a fast resize, and tests may probe negatives)
	// so the arithmetic below stays non-negative — without this, line 769's
	// strings.Repeat(" ", colWidth-2) panics with "negative Repeat count" on
	// any width < 7.
	totalWidth := m.width
	if totalWidth < 16 {
		totalWidth = 80 // fall back to a sane default — actual rendering will overflow but won't crash
	}
	colWidth := (totalWidth - 6) / 2 // 6 for separator/padding + scrollbar

	// Determine scroll state
	activeItems := m.activeItems()
	total := renderedLineCount(activeItems)
	visible := m.visibleLines()
	hasAbove := m.scrollOffset > 0
	hasBelow := total > visible && m.scrollOffset+visible < total

	// Up arrow indicator (always render same content; toggle color to prevent layout jump)
	if hasAbove {
		arrowStyle := accentStyle()
		if !m.blinkOn {
			arrowStyle = lipgloss.NewStyle().Foreground(ColorBg)
		}
		b.WriteString(MutedStyle.Render(strings.Repeat(" ", colWidth-2)) + " " + arrowStyle.Render("▲") + "\n")
	}

	// Render both columns
	leftContent := m.renderColumn(m.leftItems, m.leftCol, m.activeCol == 0)
	rightContent := m.renderColumn(m.rightItems, m.rightCol, m.activeCol == 1)

	// Build scrollbar track
	scrollbar := m.buildScrollbar(visible, total)

	// Style columns
	leftStyle := lipgloss.NewStyle().Width(colWidth)
	rightStyle := lipgloss.NewStyle().Width(colWidth).PaddingLeft(2)

	// Join columns horizontally with scrollbar
	columns := lipgloss.JoinHorizontal(
		lipgloss.Top,
		leftStyle.Render(leftContent),
		rightStyle.Render(rightContent),
		scrollbar,
	)

	b.WriteString(columns)

	// Down arrow indicator (always render same content; toggle color to prevent layout jump)
	if hasBelow {
		arrowStyle := accentStyle()
		if !m.blinkOn {
			arrowStyle = lipgloss.NewStyle().Foreground(ColorBg)
		}
		// columns from JoinHorizontal doesn't end with \n, so add one to prevent
		// the arrow from appending to the last column line (which causes overflow).
		b.WriteString("\n" + MutedStyle.Render(strings.Repeat(" ", colWidth-2)) + " " + arrowStyle.Render("▼") + "\n")
	}

	// Help
	b.WriteString("\n" + MutedStyle.Render("  enter: toggle/select  ←/→: switch column"))

	return b.String()
}

// buildScrollbar renders a vertical scrollbar track with a thumb.
func (m *Settings) buildScrollbar(visible, total int) string {
	if total <= visible || visible <= 0 {
		return ""
	}

	trackHeight := visible
	if trackHeight < 1 {
		trackHeight = 1
	}

	// Calculate thumb size and position
	thumbSize := max(1, (visible*trackHeight)/total)
	thumbPos := (m.scrollOffset * trackHeight) / total
	if thumbPos+thumbSize > trackHeight {
		thumbPos = trackHeight - thumbSize
	}

	var b strings.Builder
	trackStyle := lipgloss.NewStyle().Foreground(ColorDimBorder)
	thumbStyle := lipgloss.NewStyle().Foreground(ColorMuted)

	for i := 0; i < trackHeight; i++ {
		if i > 0 {
			b.WriteString("\n")
		}
		if i >= thumbPos && i < thumbPos+thumbSize {
			b.WriteString(thumbStyle.Render(" █"))
		} else {
			b.WriteString(trackStyle.Render(" │"))
		}
	}
	return b.String()
}

package ui

import (
	"strconv"
	"strings"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
)

type tutorialPage struct {
	title   string
	content string
}

// Tutorial shows the interactive tutorial
type Tutorial struct {
	pages   []tutorialPage
	current int
	width   int
	height  int
}

// NewTutorial creates a new tutorial view
func NewTutorial() Tutorial {
	return Tutorial{
		pages: []tutorialPage{
			{
				title: "Welcome",
				content: `Welcome to LazyVPN!

LazyVPN is a WireGuard VPN manager built for Omarchy Linux. It replaces manual WireGuard
configuration with a fast, keyboard-driven interface. Here's what you can do:

  - Connect to VPN providers like ProtonVPN, Mullvad, IVPN, NordVPN, and more
  - Browse thousands of servers and filter by feature, country, or latency
  - Protect yourself with a UFW-based killswitch that blocks all non-VPN traffic
  - Auto-reconnect and failover keep you connected without intervention
  - Test for DNS and IP leaks, run speed tests, and audit your security

This tutorial walks you through the essentials. Use arrow keys to navigate pages.`,
			},
			{
				title: "Main Menu",
				content: `The left sidebar has four sections. Arrow keys move between them; Enter opens the view.


  DASHBOARD           Real-time connection status, health grade, bandwidth graphs,
                      and quick toggles for killswitch, IPv6, LAN mode, and more.

  DYNAMIC SERVERS     Browse your provider's full server network. Filter by P2P, Tor,
                      Streaming, Secure Core, or Free tier. Test latency and connect.

  MY SERVERS          Your personal server list: favorited servers from the dynamic
                      browser plus any WireGuard configs you've imported manually.

  SETTINGS            Provider setup, automation, debug & logs sub-view, advanced
                      options, and this tutorial.


The footer bar always shows connection status, server name, bandwidth, and killswitch state.
Press Tab to switch focus between the sidebar and the content pane.`,
			},
			{
				title: "Dynamic Server List",
				content: `The Dynamic Server List gives you live access to every server your provider offers.
Authenticate once with a single config file, then browse everything.


  FILTER KEYS (toggle on/off)                    ACTION KEYS

    1  P2P / Port Forward                          6  Random — connect to random server
    2  Tor — servers with Tor routing               7  Quickest — measure latency, auto-connect
    3  MultiHop / Secure Core                       8  Latency Test — ping all visible servers
    4  Streaming — optimized for video              9  Favorite — add/remove from My Servers
    5  Free — free-tier servers                     0  Cycle Provider — multi-provider filter


  NAVIGATION

    Up/Down arrows     move through the list       Enter    connect to selected server
    Type to search     live filter by name/country  Esc      clear search or go back`,
			},
			{
				title: "My Servers",
				content: `My Servers is your personal collection, combining two sources into one list.


  FAVORITED SERVERS                               MANUAL CONFIGS

    Servers you've starred from the Dynamic         WireGuard .conf files you've imported
    Server List. Press 'f' in the server            manually. Useful for servers not in your
    browser to toggle a favorite. Favorites         provider's dynamic list, or for providers
    appear at the top of the list with a            we don't support yet. Import them from
    star icon for quick access.                     Settings > Import WireGuard Config.


Select any server and press Enter to connect. Favorites and manual configs are shown
together, sorted with favorites first.`,
			},
			{
				title: "Killswitch & Protection",
				content: `The killswitch blocks ALL internet traffic unless you're connected to the VPN.
If the VPN drops unexpectedly, your real IP is never exposed.


  KILLSWITCH [On/Off]                       Master toggle. When on, you're protected.

  KS ON DISCONNECT [Auto/Prompt/Never]      What happens when you manually disconnect:
                                              Auto   — killswitch turns off automatically
                                              Prompt — asks you each time
                                              Never  — stays on (blocks all internet)

  LOCAL NETWORK [Allow/Stealth/Block]       Controls LAN access while killswitch is active:
                                              Allow   — full LAN access (printers, NAS, shares)
                                              Stealth — blocks inbound LAN, allows outbound
                                              Block   — blocks all LAN traffic both directions

  IPv6 LEAK PROTECTION [On/Off]             Disables IPv6 to prevent leaks that bypass the VPN.`,
			},
			{
				title: "Automation",
				content: `LazyVPN can keep you connected automatically so you never browse unprotected.


  AUTOCONNECT ON STARTUP [On/Off]           Connect automatically when your system boots.

  STARTUP SERVER                            Which server to connect to on boot:
    [Last Used/Fastest/Random/Specific]       Last Used — reconnect to previous server
                                              Fastest  — test latency, pick the quickest
                                              Random   — pick randomly from all servers
                                              Specific — always connect to a chosen server

  AUTO-RECOVER [On/Off]                     Background daemon monitors your connection every
                                            5 seconds. If it drops, reconnects automatically.

  AUTO-FAILOVER [On/Off]                    If the current server fails repeatedly, switches
                                            to the next best server automatically.

  AUTO-CHECK UPDATES [On/Off]               Checks GitHub for new releases once per day.
                                            Disabled by default. Nothing installs without
                                            your confirmation. You can also run
                                            'lazyvpn update' from the terminal.

  HEALTH CHECK TARGETS                      The daemon pings configurable endpoints to
    Settings > Advanced                     check connectivity. Change them in Settings >
                                            Advanced > Health Check Targets.


Tip: Enable Killswitch + Autoconnect + Auto-Recover for always-on protection.`,
			},
			{
				title: "Provider Setup",
				content: `LazyVPN works with any VPN provider that supports WireGuard. Set up takes about 30 seconds.


  SUPPORTED PROVIDERS

    ProtonVPN (verified, has free tier)        Mullvad            IVPN
    NordVPN                                    Surfshark          Windscribe
    AirVPN                                     FastestVPN


  HOW TO SET UP

    1. Download a single WireGuard config file from your VPN provider's website
    2. Open LazyVPN > Settings > Set Up Provider
    3. Select the config file from your Downloads folder
    4. LazyVPN extracts your credentials and detects your provider automatically
    5. The full server list downloads immediately and refreshes every 24 hours


Your private key and credentials are stored locally in ~/.config/lazyvpn/providers/
with 600 permissions (read/write only by you). They are never sent anywhere.`,
			},
			{
				title: "Tips & Tricks",
				content: `A few things that make LazyVPN nicer to use day-to-day:


  FAVORITES             Star servers you use often with 'f'. They appear at the top of
                        My Servers for quick access.

  QUICKEST              Latency changes throughout the day. Use key '7' in the dynamic
                        browser to auto-measure and connect to the fastest server.

  LOGGING ALERT         If debug logging or UFW packet logging is still active when you
                        launch LazyVPN, the footer bar shows a reminder. Open Settings >
                        Debug & Logs to review and disable.

  LEAK TESTING          Run a leak test after connecting (Dashboard > Leak Test) to verify
                        your DNS and IP aren't exposed. The ISP baseline is captured on
                        first connect and used for comparison.

  SPEED TEST            Dashboard > Speed Test runs a 10MB download test through the VPN.

  SECURITY AUDIT        Dashboard > Security Audit checks killswitch, DNS, IPv6, and more.


  KEYBOARD SHORTCUTS

    Arrow keys     Navigate                Tab        Switch sidebar <-> content
    Enter          Select / connect        Esc        Go back
    q              Quit LazyVPN            1-9, 0     Server browser hotkeys`,
			},
			{
				title: "You're Ready!",
				content: `That covers the essentials. Here's what to do next:


  1.  SET UP YOUR PROVIDER          Settings > Set Up Provider — one config file is all you need.

  2.  BROWSE SERVERS                Go to Dynamic Servers and explore your provider's network.

  3.  FAVORITE A FEW                Press 'f' on servers you like. They'll appear in My Servers.

  4.  ENABLE KILLSWITCH             Dashboard > Killswitch On — blocks traffic if VPN drops.

  5.  ENABLE AUTOCONNECT            Settings > Autoconnect On — stay connected on boot.


  Need help? Check the README or open an issue:
  https://github.com/blank-query/lazyVPN-for-Omarchy


  Enjoy your private browsing!`,
			},
		},
	}
}

func (m Tutorial) Init() tea.Cmd {
	return nil
}

func (m Tutorial) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, func() tea.Msg { return BackMsg{} }
		case "left":
			if m.current > 0 {
				m.current--
			}
		case "right", "enter", " ":
			if m.current < len(m.pages)-1 {
				m.current++
			} else {
				return m, func() tea.Msg { return BackMsg{} }
			}
		case "home":
			m.current = 0
		case "end":
			m.current = len(m.pages) - 1
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m Tutorial) View() string {
	var b strings.Builder

	page := m.pages[m.current]
	width := m.width
	if width <= 0 {
		width = 80
	}

	// Title with page number
	pageIndicator := strings.Repeat(".", m.current+1) +
		strings.Repeat(" ", len(m.pages)-m.current-1) +
		" " + strconv.Itoa(m.current+1) + "/" + strconv.Itoa(len(m.pages))
	b.WriteString(CenterText(TitleStyle.Render(page.title)+"  "+MutedStyle.Render(pageIndicator), width) + "\n\n")

	// Content - center as a block (preserves internal alignment)
	lines := strings.Split(page.content, "\n")
	maxLen := 0
	for _, line := range lines {
		if l := utf8.RuneCountInString(line); l > maxLen {
			maxLen = l
		}
	}
	leftPad := (width - maxLen) / 2
	if leftPad < 0 {
		leftPad = 0
	}
	pad := strings.Repeat(" ", leftPad)
	for _, line := range lines {
		b.WriteString(pad + line + "\n")
	}

	// Navigation
	b.WriteString("\n")
	nav := ""
	if m.current > 0 {
		nav += "<- prev  "
	} else {
		nav += "         "
	}
	if m.current < len(m.pages)-1 {
		nav += "next ->  "
	} else {
		nav += "finish   "
	}
	b.WriteString(CenterText(MutedStyle.Render(nav), width))

	return b.String()
}

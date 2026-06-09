package ui

import (
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/daemon"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/firewall"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/logger"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/netlink"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Dashboard is the primary landing view showing connection status,
// bandwidth, health monitoring, and quick actions.
type Dashboard struct {
	cfg       *config.Config
	connected bool
	focused   bool
	activeCol int // 0 = left, 1 = right
	leftCol   int // cursor within left column
	rightCol  int // cursor within right column
	width     int
	height    int

	// Live connection data (refreshed every StatusUpdateMsg)
	prettyName string
	publicIP   string
	endpoint   string
	dnsServers string
	uptime     string
	killswitch bool

	stealthMode  bool
	lanBlock     bool
	ipv6Disabled bool

	// Bandwidth — computed from successive daemon HealthState snapshots
	rxSpeed   string
	txSpeed   string
	rxRate    float64
	txRate    float64
	rxHistory [8]float64
	txHistory [8]float64
	histIdx   int
	histCount int
	lastStats *netlink.InterfaceStats // last snapshot for rate calculation

	// Session totals
	baseRxBytes uint64
	baseTxBytes uint64
	hasBase     bool
	rxTotal     uint64
	txTotal     uint64

	// Health — driven by daemon HealthState
	health           *daemon.HealthState
	showHealthDetail bool

	// Daemon client for receiving health updates
	daemonClient *daemon.Client

	// Disconnected state
	lastServer   string
	lastUptime   string
	lastTransfer string

	// Auth prompt for firewall operations requiring sudo
	auth          AuthPrompt
	firewallBusy  bool // true while an async firewall op is in flight
	statusText    string
	statusIsError bool

	// Pending firewall retry/undo, stashed when an op fails with auth-required.
	// On auth success, authResultMsg dispatches retryOp from a goroutine that
	// returns a FirewallResultMsg — keeping all dashboard-state mutation in the
	// Update loop. Without this, the retry callback passed to AuthPrompt would
	// run inside a tea.Cmd goroutine and mutate dashboard fields directly.
	pendingRetry func() error
	pendingUndo  func()
}

// NewDashboard creates a new Dashboard view.
func NewDashboard(cfg *config.Config) *Dashboard {
	return &Dashboard{cfg: cfg}
}

// SetFocused sets the focus state for cursor visibility.
func (d *Dashboard) SetFocused(focused bool) {
	d.focused = focused
}

func (d *Dashboard) Init() tea.Cmd {
	// Seed cached firewall-derived state from the authoritative source (UFW).
	d.killswitch = isFirewallActive()
	d.stealthMode = firewallIsLANStealthActive()
	d.lanBlock = firewallIsLANBlockActive()
	d.ipv6Disabled = firewallIsIPv6Disabled()
	return tea.Batch(
		d.connectToDaemon(),
		scheduleFirewallReconcile(),
	)
}

// scheduleFirewallReconcile schedules the next firewall-state reconciliation
// tick. Called from Init() and from the reconcile handler to re-arm.
func scheduleFirewallReconcile() tea.Cmd {
	return tea.Tick(firewallReconcileInterval, func(time.Time) tea.Msg {
		return firewallReconcileMsg{}
	})
}

// firewallReconcileResultMsg carries the four firewall state flags
// freshly read from UFW. Reading them runs four `sudo ufw` subprocess
// calls — when done synchronously inside Update they froze the UI for
// ~400ms every reconcile interval. The producer side runs in a
// background tea.Cmd; this message delivers the result back to Update
// for cheap diff-and-set work.
type firewallReconcileResultMsg struct {
	killswitch   bool
	lanBlock     bool
	stealthMode  bool
	ipv6Disabled bool
}

// readFirewallStateAsync runs the four UFW probes in a background
// goroutine (tea.Cmd) and returns the snapshot via firewallReconcileResultMsg.
func readFirewallStateAsync() tea.Cmd {
	return func() tea.Msg {
		return firewallReconcileResultMsg{
			killswitch:   isFirewallActive(),
			lanBlock:     firewallIsLANBlockActive(),
			stealthMode:  firewallIsLANStealthActive(),
			ipv6Disabled: firewallIsIPv6Disabled(),
		}
	}
}

// dashboardRefreshFields is the snapshot of cfg fields the async
// refresh needs. Captured on the UI goroutine to avoid racing
// concurrent cfg writers (the footer's parallel cfg.Reload, daemon
// SaveConnectionState).
type dashboardRefreshFields struct {
	connName   string
	lastIP     string
	lastServer string
}

// dashboardRefreshResultMsg carries everything the StatusUpdateMsg
// handler needs to update the dashboard's cached display state.
type dashboardRefreshResultMsg struct {
	connected    bool
	killswitch   bool
	stealthMode  bool
	lanBlock     bool
	ipv6Disabled bool
}

// dashboardRefreshAsync runs the slow netlink + UFW probes in a
// background goroutine using the pre-snapshotted fields.
func dashboardRefreshAsync(f dashboardRefreshFields) tea.Cmd {
	return func() tea.Msg {
		return dashboardRefreshResultMsg{
			connected:    isWGConnected(f.connName),
			killswitch:   isFirewallActive(),
			stealthMode:  firewallIsLANStealthActive(),
			lanBlock:     firewallIsLANBlockActive(),
			ipv6Disabled: firewallIsIPv6Disabled(),
		}
	}
}

// connectToDaemon creates a daemon client, reads the initial STATUS event,
// and returns a DaemonConnectedMsg or DaemonDisconnectedMsg.
func (d *Dashboard) connectToDaemon() tea.Cmd {
	return func() tea.Msg {
		client := daemon.NewClient(d.cfg.ConfigDir)
		if err := client.Connect(); err != nil {
			return DaemonDisconnectedMsg{Err: err}
		}
		// Read initial STATUS event
		event, err := client.ReadEvent()
		if err != nil {
			client.Close()
			return DaemonDisconnectedMsg{Err: err}
		}
		return DaemonConnectedMsg{Event: *event, Client: client}
	}
}

// listenForDaemonEvents blocks until the next daemon event arrives.
func (d *Dashboard) listenForDaemonEvents() tea.Cmd {
	client := d.daemonClient
	if client == nil {
		return nil
	}
	return func() tea.Msg {
		event, err := client.ReadEventWithTimeout(0) // no timeout — block until event
		if err != nil {
			return DaemonDisconnectedMsg{Err: err}
		}
		if event.Type == daemon.EventHealthState && event.Health != nil {
			return DaemonHealthMsg{Health: *event.Health, Client: client}
		}
		// For other event types, wrap as connected msg for state updates
		return DaemonConnectedMsg{Event: *event, Client: client}
	}
}

// leftActions returns actions for the left column (things you do).
func (d *Dashboard) leftActions() []dashboardAction {
	if d.connected {
		return []dashboardAction{
			{id: "disconnect", label: "Disconnect", desc: "Disconnect from VPN"},
			{id: "speedtest", label: "Speed Test", desc: "Test VPN connection speed"},
			{id: "leaktest", label: "Leak Test", desc: "Check for DNS and IP leaks"},
			{id: "audit", label: "Security Audit", desc: "Full security audit of VPN connection"},
		}
	}
	var acts []dashboardAction
	if d.lastServer != "" {
		acts = append(acts, dashboardAction{id: "reconnect", label: "Reconnect", desc: "Reconnect to last server"})
	}
	acts = append(acts,
		dashboardAction{id: "leaktest", label: "Leak Test", desc: "Check for DNS and IP leaks"},
		dashboardAction{id: "audit", label: "Security Audit", desc: "Full security audit of VPN connection"},
	)
	return acts
}

// rightActions returns settings for the right column (things you toggle/configure).
func (d *Dashboard) rightActions() []dashboardAction {
	return []dashboardAction{
		{id: "killswitch", label: "Killswitch", value: onOffLabel(d.killswitch), desc: "Block all traffic if VPN disconnects"},
		{id: "ks-disconnect", label: "KS on Disconnect", value: ksDisconnectLabel(d.cfg.KillswitchAutoDisable), desc: "Killswitch behavior when you disconnect"},
		{id: "ipv6-protection", label: "IPv6", value: ipv6Label(d.ipv6Disabled), desc: "Blocks the IPv6 stack system-wide (persists across reboot). Recommended for most users."},
		{id: "local-network", label: "Local Network", value: localNetworkMode(d.lanBlock, d.stealthMode), desc: localNetworkDescription(d.lanBlock, d.stealthMode)},
		{id: "dns-providers", label: "DNS Providers", value: dnsProviderSummary(d.cfg), desc: "Choose which DNS services to query during leak test"},
		{id: "bw-style", label: "Bandwidth Style", value: bwDisplayMode(d.cfg.BandwidthDisplay), desc: "Switch bandwidth display mode"},
		{id: "bw-unit", label: "Bandwidth Unit", value: bwUnitDisplay(d.cfg.BandwidthUnit), desc: "Switch between KB/s and Kbps"},
		{id: "bw-total", label: "Show Session Total", value: onOffLabel(d.cfg.BandwidthTotal), desc: "Show total bytes transferred this session"},
		{id: "reset-baseline", label: "Reset ISP Baseline", value: baselineStatus(d.cfg), desc: "Clear ISP fingerprint so next connect re-captures it"},
	}
}

// activeActions returns left or right actions based on activeCol.
func (d *Dashboard) activeActions() []dashboardAction {
	if d.activeCol == 0 {
		return d.leftActions()
	}
	return d.rightActions()
}

func (d *Dashboard) activeCursor() int {
	if d.activeCol == 0 {
		return d.leftCol
	}
	return d.rightCol
}

func (d *Dashboard) setActiveCursor(v int) {
	if d.activeCol == 0 {
		d.leftCol = v
	} else {
		d.rightCol = v
	}
}

type dashboardAction struct {
	id    string
	label string
	value string // displayed right-aligned for settings-type actions
	desc  string // shown in description area
}

func onOffLabel(b bool) string {
	if b {
		return "ON"
	}
	return "OFF"
}

// ipv6Label maps the internal "is the v6 stack disabled?" flag to the
// user-facing toggle. "Blocked" understates the kernel-level disable
// (it's not just a packet filter) but tests cleaner with non-power
// users who'd otherwise toggle "Enabled" expecting a feature.
func ipv6Label(disabled bool) string {
	if disabled {
		return "Blocked"
	}
	return "Allowed"
}

func baselineStatus(cfg *config.Config) string {
	if cfg.BaselineIP != "" {
		return cfg.BaselineIP
	}
	return "Not set"
}

func ksDisconnectLabel(v string) string {
	switch v {
	case "false":
		return "Prompt"
	case "never":
		return "Never"
	default:
		return "Auto"
	}
}

// CurrentDescription returns status text if set, else the selected action's description.
func (d *Dashboard) CurrentDescription() string {
	if d.firewallBusy {
		return "Applying..."
	}
	if d.statusText != "" {
		return d.statusText
	}
	acts := d.activeActions()
	cur := d.activeCursor()
	if cur < len(acts) {
		return acts[cur].desc
	}
	return ""
}

// StatusIsError returns true when the current status message is an error.
func (d *Dashboard) StatusIsError() bool {
	return d.statusText != "" && d.statusIsError
}

func (d *Dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Handle auth prompt input and async results
	if d.auth.Active() {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			handled, cmd := d.auth.HandleKey(msg)
			if handled {
				if !d.auth.Active() {
					// Cancelled
					d.statusText = ""
					d.statusIsError = false
				}
				return d, cmd
			}
		case authResultMsg:
			if retryFn := d.auth.HandleAuthResult(msg); retryFn != nil {
				// retryFn from AuthPrompt is a no-op (see FirewallResultMsg
				// handler — we register dummy callbacks). The real retry op is
				// stashed in d.pendingRetry; dispatch it as a tea.Cmd that
				// returns a FirewallResultMsg so the result is processed
				// inside Update (no goroutine-side state mutation).
				_ = retryFn
				retryOp := d.pendingRetry
				undoOp := d.pendingUndo
				d.pendingRetry = nil
				d.pendingUndo = nil
				if retryOp == nil {
					return d, nil
				}
				d.firewallBusy = true
				return d, func() tea.Msg {
					return FirewallResultMsg{Err: retryOp(), Retry: retryOp, Undo: undoOp}
				}
			}
			return d, nil
		case tea.WindowSizeMsg:
			d.width = msg.Width
			d.height = msg.Height
			d.auth.SetWidth(msg.Width)
		}
		return d, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if !d.focused {
			return d, nil
		}
		d.statusText = ""
		d.statusIsError = false
		switch msg.String() {
		case "up":
			cur := d.activeCursor()
			if cur > 0 {
				d.setActiveCursor(cur - 1)
			}
		case "down":
			cur := d.activeCursor()
			acts := d.activeActions()
			if cur < len(acts)-1 {
				d.setActiveCursor(cur + 1)
			}
		case "left":
			if d.activeCol == 1 {
				d.activeCol = 0
			}
		case "right":
			if d.activeCol == 0 {
				d.activeCol = 1
			}
		case "enter", " ":
			acts := d.activeActions()
			cur := d.activeCursor()
			if cur < len(acts) {
				return d.handleAction(acts[cur])
			}
		}

	case StatusUpdateMsg:
		// The same StatusUpdateMsg that drives the footer also wakes
		// the dashboard. d.refresh() runs cfg.Reload + isWGConnected +
		// 4 'sudo ufw' subprocess calls inline (~400ms total) — at 1Hz
		// that's a major UI freeze. Snapshot cfg fields here, then
		// hand the slow probes off to a background tea.Cmd.
		f := dashboardRefreshFields{
			connName:   d.cfg.ConnectionName,
			lastIP:     d.cfg.LastPublicIP,
			lastServer: d.cfg.LastConnectedServer,
		}
		return d, dashboardRefreshAsync(f)

	case dashboardRefreshResultMsg:
		d.applyDashboardRefresh(msg)

	case DaemonConnectedMsg:
		// Stale client check — ignore events from a previous daemon connection.
		// Close the stale client's socket so we don't leak the fd; the previous
		// owner of d.daemonClient is the only intended reader.
		if msg.Client != nil && d.daemonClient != nil && msg.Client != d.daemonClient {
			msg.Client.Close()
			return d, nil
		}
		if msg.Client != nil {
			d.daemonClient = msg.Client
		}
		d.applyDaemonEvent(msg.Event)
		return d, d.listenForDaemonEvents()

	case DaemonHealthMsg:
		if msg.Client != nil && d.daemonClient != nil && msg.Client != d.daemonClient {
			msg.Client.Close()
			return d, nil
		}
		d.applyHealthState(msg.Health)
		return d, d.listenForDaemonEvents()

	case DaemonDisconnectedMsg:
		d.daemonClient = nil
		// Refresh state — daemon may have died, interface may be gone.
		// Use the async path (same as StatusUpdateMsg) so the 4 sudo
		// ufw probes + netlink + cfg.Reload (~400ms total) don't block
		// the UI goroutine while we're trying to recover. The sync
		// d.refresh() call here was the last remaining inline-slow-
		// probe site after the StatusUpdateMsg refactor.
		f := dashboardRefreshFields{
			connName:   d.cfg.ConnectionName,
			lastIP:     d.cfg.LastPublicIP,
			lastServer: d.cfg.LastConnectedServer,
		}
		// Retry daemon connection after 3 seconds AND kick off the
		// async refresh in parallel.
		return d, tea.Batch(
			dashboardRefreshAsync(f),
			tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
				return retryDaemonConnectMsg{}
			}),
		)

	case retryDaemonConnectMsg:
		return d, d.connectToDaemon()

	case firewallReconcileMsg:
		// Belt-and-suspenders: re-read firewall state and flag any divergence
		// from our cached values. Catches out-of-band changes (e.g., someone
		// running `ufw reset` in a terminal, or sysctl changes by hand).
		// The four sudo ufw subprocess calls are slow (~400ms total) and
		// MUST run off the UI goroutine — kicked into a tea.Cmd that
		// returns firewallReconcileResultMsg back here for the diff/notify
		// pass.
		return d, tea.Batch(readFirewallStateAsync(), scheduleFirewallReconcile())

	case firewallReconcileResultMsg:
		d.applyReconcileResult(msg)
		return d, nil

	case FirewallResultMsg:
		d.firewallBusy = false
		if msg.Err != nil {
			retryOp := msg.Retry
			undoOp := msg.Undo
			if d.auth.NeedsAuth(msg.Err, func() {
				// Dummy: actual retry runs from authResultMsg in Update
				// (see d.pendingRetry), keeping state mutation off the
				// goroutine path.
			}, func() {
				// Auth cancelled — runs synchronously from HandleKey in
				// Update, so direct mutation is safe here.
				if undoOp != nil {
					undoOp()
				}
				d.pendingRetry = nil
				d.pendingUndo = nil
				d.refresh()
			}) {
				d.pendingRetry = retryOp
				d.pendingUndo = undoOp
				return d, nil
			}
			if undoOp != nil {
				undoOp()
			}
			d.statusText = fmt.Sprintf("Error: %v", msg.Err)
			d.statusIsError = true
		}
		d.refresh()
		return d, nil

	case tea.WindowSizeMsg:
		d.width = msg.Width
		d.height = msg.Height
	}

	return d, nil
}

func (d *Dashboard) handleAction(act dashboardAction) (tea.Model, tea.Cmd) {
	switch act.id {
	case "disconnect":
		return d, func() tea.Msg {
			return SwitchViewMsg{View: "disconnect-progress"}
		}
	case "reconnect":
		lastServer := d.cfg.LastConnectedServer
		if strings.HasPrefix(lastServer, "dynamic:") {
			parts := strings.SplitN(lastServer, ":", 3)
			if len(parts) == 3 {
				return d, func() tea.Msg {
					return SwitchViewMsg{View: "connect-progress", Server: parts[2], Provider: parts[1], Dynamic: true}
				}
			}
		}
		return d, func() tea.Msg {
			return SwitchViewMsg{View: "connect-progress", Server: lastServer}
		}
	case "speedtest":
		return d, func() tea.Msg { return SwitchViewMsg{View: "speedtest"} }
	case "leaktest":
		return d, func() tea.Msg { return SwitchViewMsg{View: "leaktest"} }
	case "audit":
		return d, func() tea.Msg { return SwitchViewMsg{View: "audit"} }

	// Protection
	case "killswitch":
		return d.handleKillswitchToggle()
	case "ks-disconnect":
		prev := d.cfg.KillswitchAutoDisable
		switch d.cfg.KillswitchAutoDisable {
		case "true", "":
			d.cfg.KillswitchAutoDisable = "false"
		case "false":
			d.cfg.KillswitchAutoDisable = "never"
		case "never":
			d.cfg.KillswitchAutoDisable = "true"
		}
		if err := d.cfg.Save(); err != nil {
			d.cfg.KillswitchAutoDisable = prev
			d.statusText = "Failed to save config"
			d.statusIsError = true
		}
	case "ipv6-protection":
		return d.handleIPv6Toggle()
	case "local-network":
		return d.handleLocalNetworkCycle()
	case "dns-providers":
		return d, func() tea.Msg { return SwitchViewMsg{View: "dns-providers"} }

	// Display
	case "bw-style":
		prev := d.cfg.BandwidthDisplay
		if d.cfg.BandwidthDisplay == "bar" {
			d.cfg.BandwidthDisplay = "sparkline"
		} else {
			d.cfg.BandwidthDisplay = "bar"
		}
		if err := d.cfg.Save(); err != nil {
			d.cfg.BandwidthDisplay = prev
			d.statusText = "Failed to save config"
			d.statusIsError = true
		}
	case "bw-unit":
		prev := d.cfg.BandwidthUnit
		if d.cfg.BandwidthUnit == "bytes" {
			d.cfg.BandwidthUnit = "bits"
		} else {
			d.cfg.BandwidthUnit = "bytes"
		}
		if err := d.cfg.Save(); err != nil {
			d.cfg.BandwidthUnit = prev
			d.statusText = "Failed to save config"
			d.statusIsError = true
		}
	case "bw-total":
		d.cfg.BandwidthTotal = !d.cfg.BandwidthTotal
		if err := d.cfg.Save(); err != nil {
			d.cfg.BandwidthTotal = !d.cfg.BandwidthTotal
			d.statusText = "Failed to save config"
			d.statusIsError = true
		}
	case "reset-baseline":
		prevIP := d.cfg.BaselineIP
		prevOrg := d.cfg.BaselineOrg
		prevDNS := d.cfg.BaselineDNS
		d.cfg.BaselineIP = ""
		d.cfg.BaselineOrg = ""
		d.cfg.BaselineDNS = nil
		if err := d.cfg.Save(); err != nil {
			d.cfg.BaselineIP = prevIP
			d.cfg.BaselineOrg = prevOrg
			d.cfg.BaselineDNS = prevDNS
			d.statusText = "Failed to save config"
			d.statusIsError = true
		} else {
			d.statusText = "ISP baseline cleared — next connect will re-capture"
		}
	}
	return d, nil
}

func (d *Dashboard) handleKillswitchToggle() (tea.Model, tea.Cmd) {
	if d.firewallBusy {
		return d, nil
	}
	enable := !d.killswitch
	// Optimistically flip the cached display; FirewallResultMsg will
	// reconcile from UFW after the op completes (on error we revert).
	d.killswitch = enable
	d.firewallBusy = true

	// Capture state for the goroutine
	connected := isWGConnected(d.cfg.ConnectionName)
	var ksCfg *firewall.KillswitchConfig
	if connected && enable {
		ksCfg = d.buildKillswitchConfig()
	}

	doOp := func() error {
		if enable {
			if connected {
				return firewallEnable(ksCfg)
			}
			return firewallEnableSimple()
		}
		return firewallDisable()
	}
	undoOp := func() {
		d.killswitch = !enable
	}

	return d, func() tea.Msg {
		err := doOp()
		return FirewallResultMsg{Err: err, Undo: undoOp, Retry: doOp}
	}
}

// applyReconcileResult diffs the freshly-read firewall snapshot against
// the cached display flags and notifies on out-of-band drift. Runs on
// the UI goroutine but is now a cheap field comparison + maybe-notify;
// the slow `sudo ufw` reads happen in readFirewallStateAsync.
func (d *Dashboard) applyReconcileResult(snap firewallReconcileResultMsg) {
	log := logger.New(d.cfg)

	if snap.killswitch != d.killswitch {
		log.Log(logger.Connection, "Killswitch state changed outside lazyvpn: cached=%v, firewall=%v — reconciling", d.killswitch, snap.killswitch)
		if snap.killswitch {
			notifyInfo("LazyVPN", "Killswitch was enabled outside lazyvpn")
		} else {
			notifyInfo("LazyVPN", "Killswitch was disabled outside lazyvpn")
		}
		d.killswitch = snap.killswitch
	}
	if snap.lanBlock != d.lanBlock {
		log.Log(logger.Connection, "LAN block state changed outside lazyvpn: cached=%v, firewall=%v — reconciling", d.lanBlock, snap.lanBlock)
		d.lanBlock = snap.lanBlock
	}
	if snap.stealthMode != d.stealthMode {
		log.Log(logger.Connection, "LAN stealth state changed outside lazyvpn: cached=%v, firewall=%v — reconciling", d.stealthMode, snap.stealthMode)
		d.stealthMode = snap.stealthMode
	}
	if snap.ipv6Disabled != d.ipv6Disabled {
		log.Log(logger.Connection, "IPv6 protection state changed outside lazyvpn: cached=%v, firewall=%v — reconciling", d.ipv6Disabled, snap.ipv6Disabled)
		if snap.ipv6Disabled {
			notifyInfo("LazyVPN", "IPv6 leak protection was enabled outside lazyvpn")
		} else {
			notifyInfo("LazyVPN", "IPv6 leak protection was disabled outside lazyvpn")
		}
		d.ipv6Disabled = snap.ipv6Disabled
	}
}

func (d *Dashboard) handleIPv6Toggle() (tea.Model, tea.Cmd) {
	if d.firewallBusy {
		return d, nil
	}
	disable := !d.ipv6Disabled
	// Optimistically flip the cached display; FirewallResultMsg will
	// reconcile from UFW after the op completes (on error we revert).
	d.ipv6Disabled = disable
	d.firewallBusy = true

	doOp := func() error {
		if disable {
			return firewallDisableIPv6()
		}
		return firewallEnableIPv6()
	}
	undoOp := func() {
		d.ipv6Disabled = !disable
	}

	return d, func() tea.Msg {
		err := doOp()
		return FirewallResultMsg{Err: err, Undo: undoOp, Retry: doOp}
	}
}

func (d *Dashboard) handleLocalNetworkCycle() (tea.Model, tea.Cmd) {
	if d.firewallBusy {
		return d, nil
	}
	// Cycle: Allow → Stealth → Block → Allow.
	// Cached flags d.lanBlock and d.stealthMode reflect the UFW rules.
	prevLanBlock, prevStealth := d.lanBlock, d.stealthMode
	var newLanBlock, newStealth bool
	switch {
	case prevStealth: // Stealth → Block
		newLanBlock, newStealth = true, false
	case !prevLanBlock: // Allow → Stealth
		newLanBlock, newStealth = false, true
	default: // Block → Allow
		newLanBlock, newStealth = false, false
	}
	// Optimistically flip the cache; FirewallResultMsg reconciles on error.
	d.lanBlock, d.stealthMode = newLanBlock, newStealth
	d.firewallBusy = true

	// Capture state for goroutine. Snapshot LastConnectedServer too —
	// without it, the doOp closure would re-read d.cfg.LastConnectedServer
	// at retry time, which can drift if d.refresh() ran cfg.Reload()
	// between dispatch and retry. A drift from "" → real-server would
	// flip the ksActive guard true while ksCfg's Endpoint/DNS are still
	// empty (since ksCfg was captured at dispatch time), corrupting the
	// killswitch with a "full" config missing the actual endpoint allow.
	connName := d.cfg.ConnectionName
	connected := isWGConnected(connName)
	ksActive := isFirewallActive()
	lastConnServer := d.cfg.LastConnectedServer

	// Pre-compute params needed by goroutine
	var ksCfg *firewall.KillswitchConfig
	var vpnIface, endpoint, gw, dns string
	if ksActive || newLanBlock {
		ksCfg = d.buildKillswitchConfig()
	}
	if newLanBlock {
		if connected {
			vpnIface = connName
			endpoint = ksCfg.Endpoint
			dns = ksCfg.DNS
		}
		_, gw, _ = firewallGetPhysicalInterface()
	}

	undoOp := func() {
		d.lanBlock, d.stealthMode = prevLanBlock, prevStealth
	}

	// Allow is now an explicit rule set (tag la), not the absence of rules —
	// so transitions into/out of Allow toggle it like the other two modes.
	prevAllow := !prevLanBlock && !prevStealth
	newAllow := !newLanBlock && !newStealth

	doOp := func() error {
		// LAN allow rules (explicit full-access mode)
		if newAllow && !prevAllow {
			if err := firewallEnableLANAllow(); err != nil {
				return err
			}
		} else if !newAllow && prevAllow {
			if err := firewallDisableLANAllow(); err != nil {
				return err
			}
		}

		// Stealth rules
		if newStealth && !prevStealth {
			if err := firewallEnableLANStealth(); err != nil {
				return err
			}
		} else if !newStealth && prevStealth {
			if err := firewallDisableLANStealth(); err != nil {
				return err
			}
		}

		// LAN block rules
		if newLanBlock && !prevLanBlock {
			if err := firewallEnableLANBlock(vpnIface, endpoint, gw, dns); err != nil {
				return err
			}
		} else if !newLanBlock && prevLanBlock {
			if err := firewallDisableLANBlock(); err != nil {
				return err
			}
		}

		// Re-apply the killswitch when active so its physical-interface reject
		// is re-appended AFTER the LAN rules we just changed. The new LAN
		// allow-out rules land at higher UFW rule numbers than the old reject;
		// re-emitting the killswitch deletes that reject and re-adds it last, so
		// LAN egress (lower-numbered) wins by first-match again. Without this,
		// switching modes while the killswitch is on would let the stale reject
		// shadow the fresh LAN rules.
		// Skip when no server has been connected yet — we're in EnableSimple
		// state (no DNS/endpoint allow rules, and no reject to reorder), and
		// calling Enable here with the empty ksCfg would replace the simple
		// killswitch with a "full" one missing DNS allow rules, breaking
		// system-wide DNS resolution. Use the captured lastConnServer
		// (snapshotted at dispatch time, alongside ksCfg) so the guard and the
		// config are evaluated against the same point-in-time state.
		if ksActive && lastConnServer != "" {
			if err := firewallEnable(ksCfg); err != nil {
				return err
			}
		}

		return nil
	}

	return d, func() tea.Msg {
		err := doOp()
		return FirewallResultMsg{Err: err, Undo: undoOp, Retry: doOp}
	}
}

// buildKillswitchConfig creates a KillswitchConfig from the current state.
// The killswitch owns leak prevention only; LAN handling lives entirely in the
// independent Local Network layer (la/st/lb tags), so no LAN flags here.
func (d *Dashboard) buildKillswitchConfig() *firewall.KillswitchConfig {
	ksCfg := &firewall.KillswitchConfig{
		InterfaceName: d.cfg.ConnectionName,
	}
	lastServer := d.cfg.LastConnectedServer
	if strings.HasPrefix(lastServer, "dynamic:") {
		parts := strings.SplitN(lastServer, ":", 3)
		if len(parts) == 3 {
			providerCfg, err := config.LoadProvider(d.cfg.ConfigDir, parts[1])
			if err == nil {
				// Zero the loaded PrivateKey on return — we only need
				// DNS here; the key load is incidental. Without ZeroKey
				// the key bytes linger on heap until GC.
				defer providerCfg.ZeroKey()
				ksCfg.DNS = providerCfg.DNS
			}
			serverData, err := config.LoadServerFromCache(d.cfg.ConfigDir, parts[1], parts[2])
			if err == nil && serverData.IP != "" {
				ksCfg.Endpoint = serverData.IP
			}
		}
	} else if lastServer != "" {
		wgDir := filepath.Join(d.cfg.ConfigDir, "wireguard")
		wgCfg, _ := wireguard.LoadConfig(wgDir, lastServer)
		if wgCfg != nil {
			// Mirror the dynamic-server LoadProvider site above. We
			// only need DNS + Endpoint; PrivateKey + PresharedKey
			// were decoded incidentally and would otherwise linger
			// on heap until GC.
			defer wgCfg.ZeroKeys()
			ksCfg.DNS = wgCfg.DNS
			ksCfg.Endpoint = wgCfg.EndpointIP()
		}
	}
	return ksCfg
}

// applyDashboardRefresh handles a dashboardRefreshResultMsg from the
// async refresh path. Cheap field-set + the same connected/disconnected
// fork that refresh() does, but without any I/O — runs on the UI
// goroutine.
func (d *Dashboard) applyDashboardRefresh(snap dashboardRefreshResultMsg) {
	d.connected = snap.connected
	d.killswitch = snap.killswitch
	d.stealthMode = snap.stealthMode
	d.lanBlock = snap.lanBlock
	d.ipv6Disabled = snap.ipv6Disabled

	if d.connected {
		d.publicIP = d.cfg.LastPublicIP
		d.lastServer = d.cfg.LastConnectedServer
		d.refreshConnectedDisplay()
	} else {
		d.prettyName = ""
		d.publicIP = ""
		d.endpoint = ""
		d.dnsServers = ""
		d.resetBandwidthState()
		d.uptime = ""
		d.health = nil
		d.lastServer = d.cfg.LastConnectedServer

		// Clamp cursors if actions changed
		if left := d.leftActions(); d.leftCol >= len(left) {
			d.leftCol = max(0, len(left)-1)
		}
		if right := d.rightActions(); d.rightCol >= len(right) {
			d.rightCol = max(0, len(right)-1)
		}
	}
}

func (d *Dashboard) refresh() {
	d.cfg.Reload()

	connName := d.cfg.ConnectionName
	d.connected = isWGConnected(connName)
	// Firewall-derived display flags: UFW is the source of truth.
	d.killswitch = isFirewallActive()
	d.stealthMode = firewallIsLANStealthActive()
	d.lanBlock = firewallIsLANBlockActive()
	d.ipv6Disabled = firewallIsIPv6Disabled()

	if d.connected {
		d.publicIP = d.cfg.LastPublicIP
		d.lastServer = d.cfg.LastConnectedServer
		d.refreshConnectedDisplay()
	} else {
		// Disconnected
		d.prettyName = ""
		d.publicIP = ""
		d.endpoint = ""
		d.dnsServers = ""
		d.resetBandwidthState()
		d.uptime = ""
		d.health = nil
		d.lastServer = d.cfg.LastConnectedServer

		// Clamp cursors if actions changed
		if left := d.leftActions(); d.leftCol >= len(left) {
			d.leftCol = max(0, len(left)-1)
		}
		if right := d.rightActions(); d.rightCol >= len(right) {
			d.rightCol = max(0, len(right)-1)
		}
	}
}

// retryDaemonConnectMsg triggers a daemon reconnection attempt after a delay.
type retryDaemonConnectMsg struct{}

// applyHealthState updates dashboard display fields from a daemon HealthState snapshot.
func (d *Dashboard) applyHealthState(hs daemon.HealthState) {
	d.health = &hs

	// Update endpoint from health state
	if hs.Endpoint != "" {
		d.endpoint = hs.Endpoint
	}

	// Compute bandwidth rates from successive snapshots
	if hs.StatsTimestamp.IsZero() {
		return
	}
	newStats := &netlink.InterfaceStats{
		RxBytes:   hs.RxBytes,
		TxBytes:   hs.TxBytes,
		RxPackets: hs.RxPackets,
		TxPackets: hs.TxPackets,
		Timestamp: hs.StatsTimestamp,
	}

	// Counter rollback (interface recreated, daemon reconnected without
	// us seeing EventSwitching, etc.) — rebase on the new value rather
	// than freezing totals at the old interface's last known value.
	//
	// Use the full resetBandwidthState helper rather than an inline
	// partial reset. The previous inline only cleared hasBase /
	// lastStats / rxTotal / txTotal but left rxSpeed / txSpeed (display
	// strings) and the rxHistory / txHistory ring buffer untouched —
	// sparklines and bars would show stale rate data from the old
	// interface for up to 8 ticks. The helper drops the speed labels
	// and the history too, keeping the displayed state consistent
	// with the rebased counters.
	if d.hasBase && (newStats.RxBytes < d.baseRxBytes || newStats.TxBytes < d.baseTxBytes) {
		d.resetBandwidthState()
	}
	if !d.hasBase {
		d.baseRxBytes = newStats.RxBytes
		d.baseTxBytes = newStats.TxBytes
		d.hasBase = true
	}
	if newStats.RxBytes >= d.baseRxBytes {
		d.rxTotal = newStats.RxBytes - d.baseRxBytes
	}
	if newStats.TxBytes >= d.baseTxBytes {
		d.txTotal = newStats.TxBytes - d.baseTxBytes
	}

	if d.lastStats != nil {
		duration := newStats.Timestamp.Sub(d.lastStats.Timestamp).Seconds()
		if duration > 0 {
			var rxRate, txRate float64
			if newStats.RxBytes >= d.lastStats.RxBytes {
				rxRate = float64(newStats.RxBytes-d.lastStats.RxBytes) / duration
			}
			if newStats.TxBytes >= d.lastStats.TxBytes {
				txRate = float64(newStats.TxBytes-d.lastStats.TxBytes) / duration
			}
			d.rxSpeed = d.formatSpeed(rxRate)
			d.txSpeed = d.formatSpeed(txRate)
			d.rxRate = rxRate
			d.txRate = txRate

			d.rxHistory[d.histIdx] = rxRate
			d.txHistory[d.histIdx] = txRate
			d.histIdx = (d.histIdx + 1) % 8
			if d.histCount < 8 {
				d.histCount++
			}
		}
	}
	d.lastStats = newStats

	// Save last session info for disconnected state display
	d.lastUptime = d.uptime
	d.lastTransfer = fmt.Sprintf("▼ %s  ▲ %s",
		netlink.FormatBytes(float64(d.rxTotal)),
		netlink.FormatBytes(float64(d.txTotal)))
}

// applyDaemonEvent handles STATUS/CONNECTED/DISCONNECTED/FAILED events.
func (d *Dashboard) applyDaemonEvent(event daemon.Event) {
	switch event.Type {
	case daemon.EventStatus:
		isConn := event.DaemonState == daemon.StateConnected || event.DaemonState == daemon.StateUnhealthy
		d.connected = isConn
		if event.Server != "" {
			d.cfg.LastConnectedServer = event.Server
		}
		if event.PublicIP != "" {
			d.publicIP = event.PublicIP
		}
		d.killswitch = event.KillswitchActive

		if isConn {
			d.refreshConnectedDisplay()
		}

		if event.Health != nil {
			d.applyHealthState(*event.Health)
		}

	case daemon.EventConnected:
		d.connected = true
		if event.PublicIP != "" {
			d.publicIP = event.PublicIP
		}
		// New interface (fresh connect or reconnect-to-same) means
		// kernel counters start from zero. Without resetting bandwidth
		// state, the >= guards in applyHealthState would freeze totals
		// at the previous interface's last value and rate at zero.
		d.resetBandwidthState()
		d.refreshConnectedDisplay()

	case daemon.EventReconnected:
		// Daemon recovered (attemptRecovery success). Same shape as
		// EventConnected: fresh interface means counters reset and the
		// PublicIP probably moved. The applyHealthState rebase from
		// 7bbe122 handles the kernel-counter rollback on the next
		// health tick, but the display would otherwise show the old
		// PublicIP and stale rate sparkline for that tick.
		d.connected = true
		if event.PublicIP != "" {
			d.publicIP = event.PublicIP
		}
		d.resetBandwidthState()
		d.refreshConnectedDisplay()

	case daemon.EventSwitching:
		// Switch tears down the current interface and brings up a new
		// one. Reset bandwidth state proactively so the next health
		// snapshot rebaselines from zero rather than displaying stale
		// totals from the old server until the user disconnects.
		d.resetBandwidthState()

	case daemon.EventDisconnected:
		d.connected = false
		d.health = nil
		d.resetBandwidthState()
		d.killswitch = event.KillswitchActive

	case daemon.EventFailed, daemon.EventSwitchFailed:
		// Daemon exhausted recovery and entered StateFailed (or
		// StateSwitchFailed). The interface may technically still
		// exist but the tunnel is dead — same UI state as
		// disconnected. Pre-fix this case fell through with no
		// handling, leaving d.connected = true (stale "Connected"
		// in the header) until the user explicitly requested a
		// status refresh.
		d.connected = false
		d.health = nil
		d.resetBandwidthState()

	case daemon.EventHealthState:
		if event.Health != nil {
			d.applyHealthState(*event.Health)
		}
	}

	// Update last server for reconnect action
	d.lastServer = d.cfg.LastConnectedServer
}

// refreshConnectedDisplay updates display fields from config (server name, uptime, etc.)
func (d *Dashboard) refreshConnectedDisplay() {
	serverRaw := d.cfg.LastConnectedServer
	serverName := serverRaw
	if strings.HasPrefix(serverName, "dynamic:") {
		parts := strings.SplitN(serverName, ":", 3)
		if len(parts) == 3 {
			serverName = parts[2]
		}
	}
	info := wireguard.ParseServerName(serverName)
	if len(info.Services) == 0 && d.cfg.LastServerFeatures != "" {
		parts := strings.Split(d.cfg.LastServerFeatures, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				info.Services = append(info.Services, p)
			}
		}
	}
	d.prettyName = info.PrettyName()

	// DNS servers — read from WireGuard config or provider config
	d.dnsServers = ""
	if strings.HasPrefix(serverRaw, "dynamic:") {
		parts := strings.SplitN(serverRaw, ":", 3)
		if len(parts) == 3 {
			provName := parts[1]
			// Zero the loaded PrivateKey on return — only need DNS here.
			// Lift out of if-init so the defer fires at function exit
			// rather than dying with the if-body's scope.
			provCfg, err := config.LoadProvider(d.cfg.ConfigDir, provName)
			if err == nil {
				defer provCfg.ZeroKey()
				if provCfg.DNS != "" {
					d.dnsServers = provCfg.DNS
				}
			}
			if d.dnsServers == "" {
				if dns, ok := config.ProviderDNS[provName]; ok {
					d.dnsServers = dns
				}
			}
		}
	} else {
		wgDir := filepath.Join(d.cfg.ConfigDir, "wireguard")
		// Lifted out of if-init so the deferred ZeroKeys runs at
		// function exit rather than dying with the if-body's scope.
		// Same reason the LoadProvider site above was lifted.
		wgCfg, err := wireguard.LoadConfig(wgDir, serverRaw)
		if err == nil {
			defer wgCfg.ZeroKeys()
			if wgCfg.DNS != "" {
				d.dnsServers = wgCfg.DNS
			}
		}
	}

	// Uptime
	if !d.cfg.ConnectedSince.IsZero() {
		d.uptime = formatUptime(time.Since(d.cfg.ConnectedSince))
	}
}

// resetBandwidthState clears bandwidth tracking state.
func (d *Dashboard) resetBandwidthState() {
	d.rxSpeed = ""
	d.txSpeed = ""
	d.rxRate = 0
	d.txRate = 0
	d.histIdx = 0
	d.histCount = 0
	d.lastStats = nil
	d.hasBase = false
	d.rxTotal = 0
	d.txTotal = 0
}

func (d *Dashboard) formatSpeed(bytesPerSec float64) string {
	if d.cfg.BandwidthUnit == "bytes" {
		return netlink.FormatBytesPerSec(bytesPerSec)
	}
	return netlink.FormatBitsPerSec(bytesPerSec)
}

func (d *Dashboard) View() string {
	var b strings.Builder

	// Auth prompt overlay
	if d.auth.Active() {
		b.WriteString(d.auth.View())
		return b.String()
	}

	if d.connected {
		d.viewConnected(&b)
	} else {
		d.viewDisconnected(&b)
	}

	return b.String()
}

func (d *Dashboard) viewConnected(b *strings.Builder) {
	// Status line
	statusStyle := lipgloss.NewStyle().Foreground(ColorSuccess).Bold(true)
	b.WriteString(statusStyle.Render("  🟢 Connected to ") + d.prettyName + "\n\n")

	// Info grid
	colWidth := 12
	valWidth := 25
	col := func(label, val string) string {
		return MutedStyle.Render(Pad(label, colWidth)) + Pad(val, valWidth)
	}

	// Get short server name for display
	serverShort := d.cfg.LastConnectedServer
	if strings.HasPrefix(serverShort, "dynamic:") {
		parts := strings.SplitN(serverShort, ":", 3)
		if len(parts) == 3 {
			serverShort = parts[2]
		}
	}

	b.WriteString("  " + col("Server", serverShort) + col("Public IP", d.publicIP) + "\n")
	b.WriteString("  " + col("Endpoint", d.endpoint) + col("DNS", d.dnsServers) + "\n")

	// Transfer totals
	transfer := fmt.Sprintf("▼ %s  ▲ %s",
		netlink.FormatBytes(float64(d.rxTotal)),
		netlink.FormatBytes(float64(d.txTotal)))
	b.WriteString("  " + col("Uptime", d.uptime) + col("Transfer", transfer) + "\n")

	b.WriteString("\n")

	// Bandwidth display
	if d.rxSpeed != "" {
		dlStyle := lipgloss.NewStyle().Foreground(ColorAccent)
		ulStyle := lipgloss.NewStyle().Foreground(ColorWarning)

		if d.cfg.BandwidthDisplay == "bar" {
			rxBar := d.buildBar(d.rxRate, d.rxHistory[:], d.histCount, ColorAccent)
			txBar := d.buildBar(d.txRate, d.txHistory[:], d.histCount, ColorWarning)
			b.WriteString("  " + dlStyle.Render("▼") + " " + d.rxSpeed + "  " + rxBar + "\n")
			b.WriteString("  " + ulStyle.Render("▲") + " " + d.txSpeed + "  " + txBar + "\n")
		} else {
			rxSpark := d.buildSparkline(d.rxHistory[:], d.histCount, d.histIdx, ColorAccent)
			txSpark := d.buildSparkline(d.txHistory[:], d.histCount, d.histIdx, ColorWarning)
			b.WriteString("  " + dlStyle.Render("▼") + " " + d.rxSpeed + "  " + rxSpark + "\n")
			b.WriteString("  " + ulStyle.Render("▲") + " " + d.txSpeed + "  " + txSpark + "\n")
		}

		if d.cfg.BandwidthTotal && (d.rxTotal > 0 || d.txTotal > 0) {
			total := netlink.FormatBytes(float64(d.rxTotal + d.txTotal))
			b.WriteString("  " + MutedStyle.Render("Session: "+total) + "\n")
		}

		b.WriteString("\n")
	}

	// Health bar
	d.renderHealth(b)

	// Separator
	b.WriteString("\n  " + MutedStyle.Render(strings.Repeat("─", 38)) + "\n\n")

	// Actions
	d.renderActions(b)
}

func (d *Dashboard) viewDisconnected(b *strings.Builder) {
	statusStyle := lipgloss.NewStyle().Foreground(ColorDanger).Bold(true)
	if d.killswitch {
		statusStyle = lipgloss.NewStyle().Foreground(ColorWarning).Bold(true)
		b.WriteString(statusStyle.Render("  🟡 Killswitch Active — Disconnected") + "\n")
	} else {
		b.WriteString(statusStyle.Render("  🔴 Disconnected") + "\n")
	}
	if d.stealthMode {
		stealthStyle := lipgloss.NewStyle().Foreground(ColorAccent)
		b.WriteString("  " + stealthStyle.Render("🛡 Stealth active") + "\n")
	}
	if d.lanBlock {
		blockStyle := lipgloss.NewStyle().Foreground(ColorAccent)
		b.WriteString("  " + blockStyle.Render("🚫 LAN Block active") + "\n")
	}
	b.WriteString("\n")

	// Show last session info if available
	if d.lastServer != "" {
		serverName := d.lastServer
		if strings.HasPrefix(serverName, "dynamic:") {
			parts := strings.SplitN(serverName, ":", 3)
			if len(parts) == 3 {
				serverName = parts[2]
			}
		}
		info := wireguard.ParseServerName(serverName)
		b.WriteString("  " + MutedStyle.Render("Last server: ") + info.PrettyName() + "\n")
		if d.lastUptime != "" {
			b.WriteString("  " + MutedStyle.Render("Session:     ") + d.lastUptime)
			if d.lastTransfer != "" {
				b.WriteString("  " + d.lastTransfer)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	// Separator
	b.WriteString("  " + MutedStyle.Render(strings.Repeat("─", 38)) + "\n\n")

	// Actions
	d.renderActions(b)
}

func (d *Dashboard) renderHealth(b *strings.Builder) {
	if !d.connected || d.health == nil {
		return
	}

	hs := d.health
	filled := hs.Score / 10
	if filled > 10 {
		filled = 10
	}

	var barColor lipgloss.Color
	switch {
	case hs.Score >= 80:
		barColor = ColorSuccess
	case hs.Score >= 50:
		barColor = ColorWarning
	default:
		barColor = ColorDanger
	}

	// Render the bar as background-painted cells rather than █/░ glyphs.
	// At small font sizes the glyph height differences (▁ through █) are
	// indistinguishable — `▁` is literally a 1px stripe at the bottom of
	// the cell, visually identical to an underscore. Background fills are
	// painted by the terminal itself across the full cell, independent of
	// glyph shape and font size.
	filledStyle := lipgloss.NewStyle().Background(barColor)
	// ColorMuted is theme-mapped to Color8 (bright black), which stays
	// distinct from the terminal background. ColorDimBorder maps to
	// Color0, which most themes set equal to the background — invisible.
	emptyStyle := lipgloss.NewStyle().Background(ColorMuted)

	bar := filledStyle.Render(strings.Repeat(" ", filled)) +
		emptyStyle.Render(strings.Repeat(" ", 10-filled))

	labelStyle := lipgloss.NewStyle().Foreground(barColor).Bold(true)

	indicators := ""
	if d.killswitch {
		ksStyle := lipgloss.NewStyle().Foreground(ColorSuccess)
		indicators += "  " + ksStyle.Render("🔒 Killswitch")
	}
	if d.stealthMode {
		stealthStyle := lipgloss.NewStyle().Foreground(ColorAccent)
		indicators += "  " + stealthStyle.Render("🛡 Stealth")
	}
	if d.lanBlock {
		blockStyle := lipgloss.NewStyle().Foreground(ColorAccent)
		indicators += "  " + blockStyle.Render("🚫 LAN Block")
	}

	latencyStr := ""
	if hs.LatencyMs > 0 {
		latencyStr = fmt.Sprintf("  %dms", hs.LatencyMs)
	}
	b.WriteString("  " + MutedStyle.Render("Health       ") + bar + " " + labelStyle.Render(hs.Grade) + MutedStyle.Render(latencyStr) + indicators + "\n")

	if d.showHealthDetail {
		d.renderHealthDetail(b)
	}
}

func (d *Dashboard) renderHealthDetail(b *strings.Builder) {
	if d.health == nil {
		return
	}
	hs := d.health

	scoreIndicator := func(score int) string {
		if score >= 80 {
			return SuccessStyle.Render("✓")
		}
		if score >= 50 {
			return lipgloss.NewStyle().Foreground(ColorWarning).Render("~")
		}
		return ErrorStyle.Render("✗")
	}

	// Handshake
	hsAge := "n/a"
	if hs.HandshakeAgeSec > 0 {
		hsAge = fmt.Sprintf("%s ago", formatUptime(time.Duration(hs.HandshakeAgeSec*float64(time.Second))))
	}
	b.WriteString("  " + MutedStyle.Render("             ") +
		scoreIndicator(hs.HandshakeScore) + fmt.Sprintf(" Handshake: %s (%d)", hsAge, hs.HandshakeScore) + "\n")

	// DNS
	dnsInfo := "ok"
	if hs.DNSConsecFails > 0 {
		dnsInfo = fmt.Sprintf("%d fails", hs.DNSConsecFails)
	}
	b.WriteString("  " + MutedStyle.Render("             ") +
		scoreIndicator(hs.DNSScore) + fmt.Sprintf(" DNS: %s (%d)", dnsInfo, hs.DNSScore) + "\n")

	// Latency
	latInfo := "n/a"
	if hs.LatencyMs > 0 {
		latInfo = fmt.Sprintf("%dms", hs.LatencyMs)
	}
	b.WriteString("  " + MutedStyle.Render("             ") +
		scoreIndicator(hs.LatencyScore) + fmt.Sprintf(" Latency: %s (%d)", latInfo, hs.LatencyScore) + "\n")

	// Packet loss
	var lossInfo string
	if hs.PacketLossPct > 0 || hs.PacketLossScore < 100 {
		lossInfo = fmt.Sprintf("%.0f%%", hs.PacketLossPct)
	} else {
		lossInfo = "0%"
	}
	b.WriteString("  " + MutedStyle.Render("             ") +
		scoreIndicator(hs.PacketLossScore) + fmt.Sprintf(" Packet loss: %s (%d)", lossInfo, hs.PacketLossScore) + "\n")
}

func (d *Dashboard) renderActions(b *strings.Builder) {
	colWidth := d.width / 2
	if colWidth < 30 {
		colWidth = 30
	}

	left := d.renderActionColumn(d.leftActions(), d.leftCol, d.activeCol == 0, colWidth)
	right := d.renderActionColumn(d.rightActions(), d.rightCol, d.activeCol == 1, colWidth)

	leftStyle := lipgloss.NewStyle().Width(colWidth)
	rightStyle := lipgloss.NewStyle().Width(colWidth)

	columns := lipgloss.JoinHorizontal(lipgloss.Top,
		leftStyle.Render(left),
		rightStyle.Render(right),
	)
	b.WriteString(columns)
}

func (d *Dashboard) renderActionColumn(acts []dashboardAction, cursor int, isActive bool, colWidth int) string {
	var b strings.Builder
	for i, act := range acts {
		prefix := "  "
		if d.focused && isActive && i == cursor {
			prefix = "> "
		}

		line := act.label
		if act.value != "" {
			gap := colWidth - 4 - len(act.label) - len(act.value) // 4 = prefix(2) + margin(2)
			if gap < 2 {
				gap = 2
			}
			line += strings.Repeat(" ", gap) + act.value
		}

		if d.focused && isActive && i == cursor {
			line = SelectedStyle.Render(line)
		}

		b.WriteString(prefix + line + "\n")
	}
	return b.String()
}

// Sparkline and bar rendering.
//
// We render bandwidth as a row of background-painted cells rather than the
// classic ▁▂▃▄▅▆▇█ glyph stack. The block-elements glyphs encode value via
// glyph height inside a single cell (e.g. `▁` is a 1-pixel stripe at the
// bottom of the cell); at terminal font sizes commonly in use, the height
// differences between adjacent levels are imperceptible — `▁▂▃` all look
// like the same thin baseline, indistinguishable from an underscore even
// when the font renders them faithfully. Background fills sidestep this:
// the terminal paints the entire cell, full-cell-height, regardless of the
// glyph contained in it. The result is readable at any font size.

func (d *Dashboard) buildSparkline(history []float64, count, writeIdx int, accent lipgloss.Color) string {
	fill := lipgloss.NewStyle().Background(accent)
	empty := lipgloss.NewStyle().Background(ColorMuted)

	if count == 0 {
		return empty.Render(strings.Repeat(" ", 8))
	}

	maxVal := 0.0
	for i := 0; i < count; i++ {
		if history[i] > maxVal {
			maxVal = history[i]
		}
	}

	var b strings.Builder
	n := 8
	start := writeIdx - count
	if start < 0 {
		start += 8
	}
	for i := 0; i < n; i++ {
		idx := (start + i) % 8
		// Cells beyond the recorded history, and any cell whose sample
		// is zero, render dim. Anything with non-zero rate renders
		// accent-coloured, giving the 8-cell row a binary "activity vs
		// no activity" pattern that's legible at any font size.
		if i >= count || maxVal == 0 || history[idx] == 0 {
			b.WriteString(empty.Render(" "))
		} else {
			b.WriteString(fill.Render(" "))
		}
	}
	return b.String()
}

func (d *Dashboard) buildBar(current float64, history []float64, count int, accent lipgloss.Color) string {
	// Seed with current so the very first tick (count==0) still scales
	// against something — otherwise the bar shows empty even when the
	// speed line displays a non-zero rate.
	maxVal := current
	for i := 0; i < count; i++ {
		if history[i] > maxVal {
			maxVal = history[i]
		}
	}

	filled := 0
	if maxVal > 0 {
		filled = int(math.Round(current / maxVal * 8))
		if filled > 8 {
			filled = 8
		}
	}

	fill := lipgloss.NewStyle().Background(accent)
	empty := lipgloss.NewStyle().Background(ColorMuted)
	return fill.Render(strings.Repeat(" ", filled)) + empty.Render(strings.Repeat(" ", 8-filled))
}

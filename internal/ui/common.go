package ui

import (
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/daemon"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/firewall"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/latency"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/notify"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/provider"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/tools"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/util"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
	"github.com/charmbracelet/lipgloss"
)

// isWGConnected is an injectable function for wireguard.IsConnected.
// Tests can replace it to simulate connected/disconnected states.
var isWGConnected = wireguard.IsConnected

// Injectable functions for external dependencies used across multiple UI components.
// Tests can replace these to avoid real I/O.

var osExecutable = os.Executable

var spawnAndWaitForConnect = daemon.SpawnAndWaitForConnect
var waitForDisconnect = daemon.WaitForDisconnect
var isDaemonRunning = daemon.IsDaemonRunning
var forceDisconnect = wireguard.ForceDisconnect

var getPublicIP = util.GetPublicIP

// isExistingInterface checks if a name matches an existing network interface.
func isExistingInterface(name string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return true
		}
	}
	return false
}

var pingServer = latency.PingServer
var pingServerUnprivileged = latency.PingServerUnprivileged
var probePing = latency.ProbePing
var probePingUnprivileged = latency.ProbePingUnprivileged

var fetchServers = provider.FetchServers
var filterProviderServers = provider.FilterProviderServers
var loadProviderServers = provider.LoadProviderServers

var newLeakTest = tools.NewLeakTest // func([]string, string, string, []string) *tools.LeakTest
var testMTU = tools.TestMTU
var testKillswitch = tools.TestKillswitch

var notifyError = notify.Error
var notifyInfo = notify.Info

var isFirewallActive = firewall.IsActive
var firewallEnable = firewall.Enable
var firewallEnableSimple = firewall.EnableSimple
var firewallDisable = firewall.Disable
var firewallDisableIPv6 = firewall.DisableIPv6
var firewallEnableIPv6 = firewall.EnableIPv6
var firewallEnableLANStealth = firewall.EnableLANStealth
var firewallDisableLANStealth = firewall.DisableLANStealth
var firewallEnableLANBlock = firewall.EnableLANBlock // func(vpnInterface, endpoint, gateway, dns string) error
var firewallDisableLANBlock = firewall.DisableLANBlock
var firewallEnableLANAllow = firewall.EnableLANAllow
var firewallDisableLANAllow = firewall.DisableLANAllow
var firewallIsLANBlockActive = firewall.IsLANBlockActive
var firewallIsLANStealthActive = firewall.IsLANStealthActive
var firewallIsIPv6Disabled = firewall.IsIPv6Disabled
var firewallGetPhysicalInterface = firewall.GetPhysicalInterface
var firewallSetLogging = firewall.SetLogging
var firewallGetLoggingLevel = firewall.GetLoggingLevel

var firewallSudoAuth = sudo.Authenticate

var wgDisconnect = wireguard.Disconnect

var refreshSudoers = sudo.InstallSudoers

var configLoad = config.Load
var configListProviders = config.ListProviders

// BackMsg signals to go back to previous view
type BackMsg struct{}

// RefreshMsg signals to refresh current view
type RefreshMsg struct{}

// SwitchViewMsg signals to switch to a different view
type SwitchViewMsg struct {
	View     string
	Server   string
	Provider string
	Dynamic  bool
}

// ErrorMsg carries an error to display
type ErrorMsg struct {
	Err error
}

// SuccessMsg carries a success message
type SuccessMsg struct {
	Message string
}

// StatusUpdateMsg carries a status update during operations
type StatusUpdateMsg struct{}

// ConnectionCompleteMsg signals connection completed
type ConnectionCompleteMsg struct {
	Success bool
	Server  string
	IP      string
	Error   error
}

// DisconnectionCompleteMsg signals disconnection completed
type DisconnectionCompleteMsg struct {
	Success bool
	Error   error
}

// RunUninstallMsg signals the TUI should exit to run uninstall
type RunUninstallMsg struct{}

// Truncate truncates a string to max runes with ellipsis
func Truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	if max <= 1 {
		return string([]rune(s)[:max])
	}
	return string([]rune(s)[:max-1]) + "…"
}

// Pad pads a string to a minimum visual width (rune count)
func Pad(s string, min int) string {
	runeCount := utf8.RuneCountInString(s)
	if runeCount >= min {
		return s
	}
	return s + strings.Repeat(" ", min-runeCount)
}

// CenterText centers text within a given width (ANSI-aware visual width)
func CenterText(s string, width int) string {
	visWidth := lipgloss.Width(s)
	if visWidth >= width {
		return s
	}
	padding := (width - visWidth) / 2
	return strings.Repeat(" ", padding) + s
}

// WrapText wraps text at word boundaries (uses rune count for proper Unicode handling)
func WrapText(s string, width int) string {
	if width <= 0 {
		return s
	}

	var result strings.Builder
	words := strings.Fields(s)
	lineLen := 0

	for i, word := range words {
		wordLen := utf8.RuneCountInString(word)
		if i > 0 {
			if lineLen+1+wordLen > width {
				result.WriteString("\n")
				lineLen = 0
			} else {
				result.WriteString(" ")
				lineLen++
			}
		}
		result.WriteString(word)
		lineLen += wordLen
	}

	return result.String()
}

// TruncateLines returns at most maxLines lines from s.
// If s has fewer lines, it is returned unchanged.
func TruncateLines(s string, maxLines int) string {
	if maxLines <= 0 {
		return ""
	}
	lines := strings.SplitN(s, "\n", maxLines+1)
	if len(lines) <= maxLines {
		return s
	}
	return strings.Join(lines[:maxLines], "\n")
}

// descriptionProvider is implemented by views that supply footer overlay text.
type descriptionProvider interface {
	CurrentDescription() string
	StatusIsError() bool
}

// DaemonHealthMsg carries a health state update from the daemon.
type DaemonHealthMsg struct {
	Health daemon.HealthState
	Client *daemon.Client
}

// DaemonConnectedMsg carries the initial status event from the daemon.
type DaemonConnectedMsg struct {
	Event  daemon.Event
	Client *daemon.Client
}

// firewallReconcileMsg is the periodic tick that re-queries the firewall
// for killswitch / LAN block / LAN stealth / IPv6-protection state. Since
// lazyvpn treats UFW as the source of truth for all four, this tick is our
// belt-and-suspenders against state drift (e.g., someone running `ufw reset`
// in another terminal).
type firewallReconcileMsg struct{}

// firewallReconcileInterval is how often the dashboard re-checks UFW state
// against its cached display values. Toggle operations update the cache
// immediately; this tick catches drift from outside-lazyvpn changes.
const firewallReconcileInterval = 60 * time.Second

// DaemonDisconnectedMsg signals that the daemon connection was lost.
type DaemonDisconnectedMsg struct {
	Err error
}

// FirewallResultMsg signals the completion of an async firewall operation.
type FirewallResultMsg struct {
	Err   error
	Undo  func()       // rollback config on failure
	Retry func() error // re-attempt the firewall operation (for auth retry)
}

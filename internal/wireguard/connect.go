package wireguard

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/firewall"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/logger"
	netlinkpkg "github.com/blank-query/lazyVPN-for-Omarchy/internal/netlink"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/security"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/util"
	"github.com/godbus/dbus/v5"
)

// dbusCallTimeout caps every systemd-resolved DBus call. Without this,
// a wedged resolved (a documented-but-rare condition) would freeze any
// connect/disconnect/recover path that touches DNS, taking the daemon
// with it. Five seconds is far more than a healthy local-bus call
// needs (sub-millisecond) and short enough to surface as a recoverable
// error rather than an apparent hang.
const dbusCallTimeout = 5 * time.Second

// dbusCall invokes obj.CallWithContext with the standard timeout and
// returns the error from the call. If the context expires first,
// returns a wrapped context.DeadlineExceeded so callers can distinguish
// hang-on-resolved from a real DBus error.
func dbusCall(obj dbus.BusObject, method string, args ...interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbusCallTimeout)
	defer cancel()
	call := obj.CallWithContext(ctx, method, 0, args...)
	if call.Err != nil {
		return call.Err
	}
	if ctx.Err() != nil {
		return fmt.Errorf("dbus %s: %w", method, ctx.Err())
	}
	return nil
}

// dbusConnectTimeout bounds dbus.ConnectSystemBus. The library function
// does Dial + Auth + Hello synchronously with NO built-in timeout —
// same shape as the session-bus hang fixed in 0950f2a for notify.Send.
// A wedged system bus daemon would freeze any connect/disconnect path
// that touches DNS configuration (systemd-resolved RevertLink /
// SetLinkDNS), taking the daemon's main goroutine with it past
// SIGTERM.
const dbusConnectTimeout = 5 * time.Second

// connectSystemBusBounded wraps dbus.ConnectSystemBus in a goroutine
// + select-with-timeout so a wedged Auth/Hello can't freeze the
// caller. On timeout the worker goroutine leaks (bounded per-call,
// acceptable given the alternative is blocking the daemon).
//
// Same goroutine-leak tradeoff as notify.Send's bounded wrapper.
// Signature matches dbus.ConnectSystemBus's variadic opts so test
// stubs assigning to dbusConnectSystemBus don't need to change.
func connectSystemBusBounded(opts ...dbus.ConnOption) (*dbus.Conn, error) {
	type result struct {
		conn *dbus.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := dbus.ConnectSystemBus(opts...)
		ch <- result{conn: conn, err: err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-time.After(dbusConnectTimeout):
		return nil, fmt.Errorf("dbus connect timed out after %s — system bus may be wedged", dbusConnectTimeout)
	}
}

// Function variables for testing - replaced by test stubs
var (
	netlinkDeleteLinkInterface    = netlinkpkg.DeleteLinkInterface
	netlinkDeleteSplitRoutes      = netlinkpkg.DeleteSplitRoutes
	netlinkDeleteHostRoute        = netlinkpkg.DeleteHostRoute
	netlinkGetDefaultGateway      = netlinkpkg.GetDefaultGateway
	netlinkAddHostRoute           = netlinkpkg.AddHostRoute
	netlinkAddSplitRoutes         = netlinkpkg.AddSplitRoutes
	netlinkInterfaceExists        = netlinkpkg.InterfaceExists
	netlinkLinkByName             = netlinkpkg.LinkByName
	netlinkGetDeviceInfo          = netlinkpkg.GetDeviceInfo
	firewallIsActive              = firewall.IsActive
	firewallEnable                = firewall.Enable
	firewallUpdate                = firewall.Update
	firewallEnableSimple          = firewall.EnableSimple
	firewallDisable               = firewall.Disable
	utilGetPublicIPv4             = util.GetPublicIPv4
	utilGetPublicIPInfo           = util.GetPublicIPInfo // returns (ip, org, error)
	utilGetPublicIPv4WithRetry    = util.GetPublicIPv4WithRetry
	utilGetPublicIPv6             = util.GetPublicIPv6
	utilCheckIPv6Leak             = util.CheckIPv6Leak
	utilWaitForConnectivity       = util.WaitForConnectivity
	utilCheckInternetConnectivity = util.CheckInternetConnectivity
	isConnectedFunc               = IsConnected
	disconnectFunc                = Disconnect
	configureDNSFunc              = configureDNS
	unconfigureDNSFunc            = unconfigureDNS
	configLoadProvider            = config.LoadProvider
	configLoadServerFromCache     = config.LoadServerFromCache
	timeSleep                     = time.Sleep
	dbusConnectSystemBus          = connectSystemBusBounded
	configureDNSviaDbusFunc       = configureDNSviaDbus
	configureDNSviaResolvectlFunc = configureDNSviaResolvectl
	execCommand                   = exec.Command
	getPhysicalInterface          = firewall.GetPhysicalInterface
	firewallEnableLANBlock        = firewall.EnableLANBlock // func(vpnInterface, endpoint, gateway, dns string) error
	firewallIsLANBlockActive      = firewall.IsLANBlockActive
	firewallIsLANStealthActive    = firewall.IsLANStealthActive
	firewallIsIPv6Disabled        = firewall.IsIPv6Disabled
	captureBaselineDNS            = defaultCaptureBaselineDNS
)

const (
	defaultMTU                 = 1420 // WireGuard standard MTU
	defaultPersistentKeepalive = 25   // seconds
	connectivityCheckRetries   = 5    // retries for WaitForConnectivity
	ipVerifyRetries            = 3    // retries for GetPublicIPv4WithRetry
)

// ConnectionStatus represents the status of a connection attempt
type ConnectionStatus struct {
	Stage      string
	Success    bool
	Warning    bool
	Danger     bool // red styling for non-fatal issues (e.g., IPv6 leak)
	Error      error
	OldIP      string
	NewIP      string
	ServerName string
}

// StatusCallback is called with status updates during connection
type StatusCallback func(status ConnectionStatus)

// Connect establishes a VPN connection to the specified server
func Connect(cfg *config.Config, server *Server, callback StatusCallback) error {
	// Use GetConnectionName for consistency with ForceDisconnect
	// (ec4dc59). Connect is currently only called from the daemon's
	// main goroutine in production (doConnect, attemptRecovery,
	// attemptFailover), so the direct read was race-free today —
	// but routing through the locked accessor keeps the invariant
	// from quietly breaking if a future change reaches Connect from
	// a different goroutine.
	connName := cfg.GetConnectionName()
	wgCfg := server.Config
	log := logger.New(cfg)

	// Defense-in-depth: guarantee key material is zeroed regardless of
	// the return path. The explicit zeros at the parse sites (line ~184
	// for PrivateKey, ~199 for PresharedKey) cover the success path,
	// but a runtime panic between here and there would leave the keys
	// in memory until GC. These defers idempotently re-zero (no-op if
	// already wiped) and run even on panic.
	defer security.ZeroBytes(wgCfg.PrivateKey)
	defer security.ZeroBytes(wgCfg.PresharedKey)

	log.Log(logger.Connection, "Starting connection to %s", wgCfg.Name)

	// Get current public IP and ISP org before connecting
	callback(ConnectionStatus{Stage: "Checking current IP..."})
	oldIP, oldOrg, _ := utilGetPublicIPInfo()
	if oldIP == "" {
		// Fallback to simple IPv4 lookup if ipinfo.io fails
		oldIP, _ = utilGetPublicIPv4()
	}
	log.Log(logger.Connection, "Current IP: %s (%s)", oldIP, oldOrg)

	// Capture baseline DNS resolvers before VPN changes them
	baselineDNS := captureBaselineDNS()
	log.Log(logger.Connection, "Baseline DNS: %v", baselineDNS)

	// Store real IP for phantom connection detection, and capture ISP baseline
	// on first connect (before any VPN is up). Reconnects keep the original baseline.
	// RecordBaselineCapture takes cfg.mu.Lock around the writes so concurrent
	// Logger.Log -> LoggerView reads from other goroutines (handleClient) don't
	// race the bare assignment we used to do here.
	if oldIP != "" && !isConnectedFunc(connName) {
		cfg.RecordBaselineCapture(oldIP, oldOrg, baselineDNS)
	}

	// CRITICAL: Update killswitch rules BEFORE disconnecting/connecting
	// If killswitch is active and we don't allow the new endpoint,
	// the connection attempt will be blocked by our own firewall.
	// Authority on killswitch state is UFW, not config — check the firewall.
	if firewallIsActive() {
		callback(ConnectionStatus{Stage: "Updating firewall for new server..."})

		ksCfg := &firewall.KillswitchConfig{
			InterfaceName: connName,
			DNS:           wgCfg.DNS,
			Endpoint:      wgCfg.EndpointIP(),
			// LAN outbound: allowed unless LAN Block is active (Allow + Stealth).
			AllowLocalNetwork: !firewallIsLANBlockActive(),
			// LAN inbound: Allow mode only (not Stealth, not Block).
			AllowLANInbound: !firewallIsLANBlockActive() && !firewallIsLANStealthActive(),
		}

		if err := firewallUpdate(ksCfg); err != nil {
			// Log but continue - connection might still work if killswitch was not actually blocking
			callback(ConnectionStatus{Stage: fmt.Sprintf("Warning: failed to update firewall: %v", err)})
			log.Log(logger.Connection, "Firewall update failed: %v", err)
		} else {
			callback(ConnectionStatus{Stage: "Firewall updated for new endpoint"})
			log.Log(logger.Connection, "Firewall updated for endpoint %s", wgCfg.EndpointIP())
		}
	}

	// Disconnect existing connection if any
	if isConnectedFunc(connName) {
		callback(ConnectionStatus{Stage: "Disconnecting current connection..."})
		if err := disconnectFunc(cfg); err != nil {
			callback(ConnectionStatus{Stage: fmt.Sprintf("Disconnect warning: %v", err), Warning: true})
		}
	}

	// Create WireGuard interface using native netlink
	callback(ConnectionStatus{Stage: "Creating WireGuard interface..."})

	// Parse private key, then zero source bytes
	privateKey, err := netlinkpkg.ParsePrivateKey(wgCfg.PrivateKey)
	security.ZeroBytes(wgCfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	// Zero our local stack copy on return. The wgInterface struct
	// below copies privateKey into a separate heap allocation; that
	// copy is zeroed by the deferred wipe right after wgInterface is
	// created. Without these the parsed key bytes linger in memory
	// past Connect's return until GC reclaims them.
	defer security.ZeroBytes(privateKey[:])

	// Parse public key
	publicKey, err := netlinkpkg.ParsePublicKey(wgCfg.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// Parse optional preshared key, then zero source bytes
	var presharedKey *netlinkpkg.Key
	if len(wgCfg.PresharedKey) > 0 {
		psk, err := netlinkpkg.ParsePrivateKey(wgCfg.PresharedKey)
		security.ZeroBytes(wgCfg.PresharedKey)
		if err != nil {
			return fmt.Errorf("invalid preshared key: %w", err)
		}
		// `psk` escapes to heap because we take &psk for presharedKey.
		// Zero it on return — same defense-in-depth as privateKey
		// above. The matching wgInterface.Peer.PresharedKey wipe
		// lives in the wgInterface defer below.
		defer security.ZeroBytes(psk[:])
		presharedKey = &psk
	}

	// Parse endpoint
	endpoint, err := netlinkpkg.ParseEndpoint(wgCfg.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}

	// Parse AllowedIPs
	allowedIPs := wgCfg.AllowedIPs
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0,::/0"
	}
	allowedIPNets, err := netlinkpkg.ParseAllowedIPs(allowedIPs)
	if err != nil {
		return fmt.Errorf("invalid allowed IPs: %w", err)
	}

	// Parse address
	hostIP, ipnet, err := parseAddress(wgCfg.Address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	// Use the host IP (not network address) with the parsed mask.
	// net.ParseCIDR masks the IP to the network address in IPNet,
	// but we need the actual host IP for the interface.
	hostNet := net.IPNet{IP: hostIP, Mask: ipnet.Mask}

	wgInterface := &netlinkpkg.WireGuardInterface{
		Name:       connName,
		PrivateKey: privateKey,
		Address:    hostNet,
		Peer: netlinkpkg.WireGuardPeer{
			PublicKey:           publicKey,
			PresharedKey:        presharedKey,
			Endpoint:            endpoint,
			AllowedIPs:          allowedIPNets,
			PersistentKeepalive: time.Duration(wgCfg.PersistentKeepalive) * time.Second,
		},
	}
	// Zero the heap-resident wgInterface key fields on return.
	// Constructing wgInterface above COPIED privateKey (a 32-byte
	// value type) into wgInterface.PrivateKey, and wgInterface lives
	// past the local privateKey/psk defers. After the kernel has
	// received the keys via wgInterface.ConfigureInterface, our
	// in-memory copies are no longer needed — wipe them.
	defer func() {
		security.ZeroBytes(wgInterface.PrivateKey[:])
		if wgInterface.Peer.PresharedKey != nil {
			security.ZeroBytes(wgInterface.Peer.PresharedKey[:])
		}
	}()

	// Delete existing interface if any
	wgInterface.Delete()

	// Create the interface
	if err := wgInterface.CreateInterface(); err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}

	// Configure WireGuard peer
	callback(ConnectionStatus{Stage: "Configuring WireGuard tunnel..."})
	if err := wgInterface.ConfigureInterface(); err != nil {
		wgInterface.Delete()
		return fmt.Errorf("failed to configure interface: %w", err)
	}

	// Assign IP address
	callback(ConnectionStatus{Stage: "Assigning IP address..."})
	if err := wgInterface.AssignAddress(); err != nil {
		wgInterface.Delete()
		return fmt.Errorf("failed to assign address: %w", err)
	}

	// Set MTU from user config (default 1420). Non-fatal if the kernel
	// rejects it (e.g., link not yet up); surface a callback warning so
	// the user knows the configured MTU didn't apply.
	mtu := cfg.CustomMTU
	if err := wgInterface.SetMTU(mtu); err != nil {
		callback(ConnectionStatus{Stage: fmt.Sprintf("Warning: MTU %d not applied: %v", mtu, err), Warning: true})
		log.Log(logger.Connection, "SetMTU(%d) failed: %v", mtu, err)
	}

	// Bring up the interface
	callback(ConnectionStatus{Stage: "Bringing up VPN interface..."})
	if err := wgInterface.BringUp(); err != nil {
		wgInterface.Delete()
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	// Configure DNS via resolvconf or systemd-resolved.
	// DNS failure is fatal: without proper DNS, queries leak outside the tunnel.
	callback(ConnectionStatus{Stage: "Configuring DNS..."})
	if err := configureDNSFunc(connName, wgCfg.DNS); err != nil {
		log.Log(logger.Connection, "DNS configuration failed: %v", err)
		cleanupFailedConnectionWithLog(connName, wgCfg.EndpointIP(), log)
		return fmt.Errorf("DNS configuration failed (queries would leak): %w", err)
	}

	// Wait for interface to initialize
	timeSleep(time.Second)

	// Configure routes
	callback(ConnectionStatus{Stage: "Configuring routes..."})
	if err := configureRoutes(connName, wgCfg.EndpointIP()); err != nil {
		log.Log(logger.Connection, "Route configuration failed: %v", err)
		cleanupFailedConnectionWithLog(connName, wgCfg.EndpointIP(), log)
		return fmt.Errorf("failed to configure routes: %w", err)
	}

	// Verify connection
	callback(ConnectionStatus{Stage: "Verifying connection..."})

	// Check internet connectivity
	if !utilWaitForConnectivity(connectivityCheckRetries, time.Second) {
		cleanupFailedConnectionWithLog(connName, wgCfg.EndpointIP(), log)
		return fmt.Errorf("no internet connectivity after connection")
	}

	// Verify IP changed (retry with fallback services to avoid EOF false failures)
	newIP, err := utilGetPublicIPv4WithRetry(ipVerifyRetries)
	if err != nil {
		cleanupFailedConnectionWithLog(connName, wgCfg.EndpointIP(), log)
		return fmt.Errorf("failed to verify public IP: %w", err)
	}

	if oldIP != "" && newIP == oldIP {
		cleanupFailedConnectionWithLog(connName, wgCfg.EndpointIP(), log)
		log.Log(logger.Connection, "Connection failed: IP unchanged (%s)", oldIP)
		return fmt.Errorf("IP unchanged - traffic not routing through VPN")
	}

	// Check for IPv6 leak if IPv6 should be disabled.
	// Firewall rules are the source of truth — not a persisted preference.
	if firewallIsIPv6Disabled() {
		if ipv6, leaking := utilCheckIPv6Leak(); leaking {
			callback(ConnectionStatus{Stage: fmt.Sprintf("IPv6 leak detected (%s)", ipv6), Danger: true})
			log.Log(logger.Connection, "IPv6 leak detected: %s", ipv6)
		} else {
			callback(ConnectionStatus{Stage: "IPv6 confirmed blocked", Success: true})
			log.Log(logger.Connection, "IPv6 confirmed blocked")
		}
	} else {
		if ipv6, err := utilGetPublicIPv6(); err == nil && ipv6 != "" {
			callback(ConnectionStatus{Stage: fmt.Sprintf("IPv6: %s", ipv6)})
		} else {
			callback(ConnectionStatus{Stage: "IPv6 unavailable (not required)", Warning: true})
		}
	}

	// Re-apply LAN block rules if Block mode is active — endpoint/DNS may have
	// changed on reconnect. UFW rule presence is the source of truth.
	if firewallIsLANBlockActive() {
		_, gw, _ := getPhysicalInterface()
		if err := firewallEnableLANBlock(connName, wgCfg.EndpointIP(), gw, wgCfg.DNS); err != nil {
			callback(ConnectionStatus{Stage: fmt.Sprintf("Warning: LAN block failed: %v", err)})
			log.Log(logger.Connection, "LAN block failed: %v", err)
		} else {
			log.Log(logger.Connection, "LAN block re-applied (Block mode active)")
		}
	}

	// LAN stealth doesn't depend on endpoint — if the rules are in place they stay
	// in place. Nothing to re-apply here; firewall is the source of truth.

	// Update config with connection info under cfg.mu.Lock — cfg.LastPublicIP
	// is read concurrently via LoggerView from handleClient goroutines, so
	// bare assignment from this main-goroutine path raced that read.
	// RecordConnectSuccess routes through SaveConnectionState (not Save):
	// daemon's in-memory cfg can be stale on user-pref fields (TUI may have
	// edited KillswitchAutoDisable / Autostart* / etc since daemon started),
	// so writing the whole struct would clobber those edits.
	if err := cfg.RecordConnectSuccess(server.Config.Name, newIP, time.Now()); err != nil {
		log.Log(logger.Connection, "Warning: failed to save config: %v", err)
	}

	log.Log(logger.Connection, "Connected successfully to %s (IP: %s -> %s)", wgCfg.Name, oldIP, newIP)

	callback(ConnectionStatus{
		Stage:      "Connected",
		Success:    true,
		OldIP:      oldIP,
		NewIP:      newIP,
		ServerName: server.DisplayName(),
	})

	return nil
}

// configureRoutes sets up routing for the VPN connection
// Returns error only for critical failures; non-critical route errors are logged but don't fail
func configureRoutes(connName string, endpointIP string) error {
	// Get current default gateway. Best-effort: missing default route is
	// fine here (e.g., starting under an active killswitch with all
	// outbound denied) — we'll skip the host-route step below and rely on
	// the killswitch-allow-endpoint rule to reach the WG handshake.
	gateway, iface, _ := netlinkGetDefaultGateway()

	// Add route to VPN endpoint through original gateway so handshake
	// traffic bypasses the VPN tunnel itself. Best-effort: the
	// killswitch may be active and rejecting non-allowed routes —
	// WireGuard can sometimes still establish without this explicit
	// pinned route.
	//
	// Pre-emptively delete any stale host route to this endpoint
	// before adding the new one. A prior connect that crashed mid-flight
	// (daemon SIGKILL, power loss) may have left a route pointing at
	// the gateway from that session. Without the explicit delete, the
	// AddHostRoute below would EEXIST and we silently keep the stale
	// gateway — making the WG handshake try to route through a
	// gateway that may no longer be reachable (different network
	// since the crash, etc.).
	//
	// DeleteHostRoute is best-effort: a missing route is fine, and
	// perm-fallback failures (no NOPASSWD for arbitrary `ip route del
	// <host>`) are tolerated. Users with CAP_NET_ADMIN (the common
	// case after install) get the cleanup via netlink directly.
	if gateway != "" && endpointIP != "" && iface != "" {
		_ = netlinkDeleteHostRoute(endpointIP)
		_ = netlinkAddHostRoute(endpointIP, gateway, iface)
	}

	// Route all traffic through VPN using split routes (the wg-quick approach).
	// 0.0.0.0/1 + 128.0.0.0/1 are more specific than any default route (0.0.0.0/0),
	// so they always take priority regardless of existing default route metrics.
	//
	// EEXIST is benign here: it means the route already exists from a
	// previous connect that left state behind (daemon crashed mid-flight,
	// previous version's residue, etc.). The route is what we wanted —
	// proceed.
	//
	// Use typed errors.Is(syscall.EEXIST) for the netlink path AND the
	// "file exists" substring fallback for the sudo-ip-route-add path,
	// whose stderr "RTNETLINK answers: File exists" doesn't carry the
	// errno (it's wrapped in fmt.Errorf with %s, not %w of an Errno).
	if err := netlinkAddSplitRoutes(connName); err != nil {
		if !errors.Is(err, syscall.EEXIST) && !strings.Contains(strings.ToLower(err.Error()), "file exists") {
			return fmt.Errorf("failed to add VPN routes: %w", err)
		}
	}

	return nil
}

// cleanupFailedConnection removes network configuration after a failed connection.
// Cleans up the endpoint host route, split routes, the WireGuard interface, and
// DNS settings. endpointIP may be empty when cleanup runs before routes were
// configured (e.g., DNS setup failure) — in that case the host-route delete is
// a no-op.
func cleanupFailedConnection(connName, endpointIP string) {
	cleanupFailedConnectionWithLog(connName, endpointIP, nil)
}

// cleanupFailedConnectionWithLog is the testable variant of
// cleanupFailedConnection. It optionally logs cleanup failures via the
// provided logger so a failed killswitch refresh (which would leave a
// stale endpoint-specific allow rule that could reach the wrong server)
// surfaces in debug.log instead of being silently discarded. The
// no-logger overload preserves the original signature for callers that
// don't have a logger handy.
func cleanupFailedConnectionWithLog(connName, endpointIP string, log *logger.Logger) {
	if endpointIP != "" {
		netlinkDeleteHostRoute(endpointIP)
	}
	netlinkDeleteSplitRoutes(connName)
	// Failed-connection cleanup: no caller-facing callback to surface
	// the DNS revert error, but log it if we have a logger. Silent
	// failure here leaves the user's resolver pointing at the
	// now-deleted VPN interface's DNS server — debug.log surfaces the
	// cause when they investigate broken resolution after a failed
	// connect.
	if err := unconfigureDNSFunc(connName); err != nil && log != nil {
		log.Log(logger.Connection, "Warning: post-failure DNS revert failed (%v) — user may need 'sudo resolvectl revert %s'", err, connName)
	}
	netlinkDeleteLinkInterface(connName)

	// If the killswitch is active, the failed connect may have left an
	// endpoint-specific allow rule behind from the firewallUpdate near the
	// top of Connect. Refresh to the simple killswitch so we don't keep a
	// stale allow for an endpoint we never finished connecting to. If the
	// refresh fails, log it — silently swallowing means a stale
	// endpoint-allow rule could let traffic reach a previously-tried
	// endpoint while the user thinks the killswitch is fully sealed.
	if firewallIsActive() {
		if err := firewallEnableSimple(); err != nil && log != nil {
			log.Log(logger.Connection, "Warning: post-failure killswitch refresh failed: %v — stale endpoint-allow rule may persist", err)
		}
	}
}

// parseAddress parses an address like "10.2.0.2/32" into IP and net
// Handles comma-separated multi-address configs (e.g., "10.2.0.2/32, fd00::2/128")
// by using the first address.
func parseAddress(addr string) (net.IP, *net.IPNet, error) {
	// Handle comma-separated addresses: use the first one
	if idx := strings.Index(addr, ","); idx >= 0 {
		addr = strings.TrimSpace(addr[:idx])
	}

	// Handle address without prefix
	if !strings.Contains(addr, "/") {
		// Determine if IPv4 or IPv6
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP address: %s", addr)
		}
		if ip.To4() != nil {
			addr = addr + "/32"
		} else {
			addr = addr + "/128"
		}
	}
	return net.ParseCIDR(addr)
}

// dnsEntry is a DBus struct for SetLinkDNS: signature (iay) = address family + address bytes
type dnsEntry struct {
	Family  int32
	Address []byte
}

// domainEntry is a DBus struct for SetLinkDomains: signature (sb) = domain + routing-only flag
type domainEntry struct {
	Domain      string
	RoutingOnly bool
}

// configureDNS sets up DNS via systemd-resolved.
// Tries DBus first; falls back to resolvectl via sudo (sudoers grants NOPASSWD).
// Always runs demotePhysicalDNSDefaultRoute afterwards — systemd-resolved's
// DBus SetLinkDefaultRoute silently fails for NetworkManager-managed links
// (polkit denies unprivileged modification), leaving the physical interface
// as +DefaultRoute and leaking DNS queries to the ISP. Running the demote
// via sudo resolvectl is the only reliable way to actually demote it.
// Supports comma-separated DNS addresses (e.g., "10.2.0.1, 10.2.0.2")
func configureDNS(ifaceName string, dns string) error {
	if dns == "" {
		return nil
	}

	// Parse and validate DNS addresses up front
	var dnsAddrs []string
	for _, dnsAddr := range strings.Split(dns, ",") {
		dnsAddr = strings.TrimSpace(dnsAddr)
		if dnsAddr == "" {
			continue
		}
		if net.ParseIP(dnsAddr) == nil {
			continue
		}
		dnsAddrs = append(dnsAddrs, dnsAddr)
	}
	if len(dnsAddrs) == 0 {
		return fmt.Errorf("no valid DNS addresses in: %s", dns)
	}

	// Try DBus first for the main DNS setup (fast path, no sudo prompt)
	dbusErr := configureDNSviaDbusFunc(ifaceName, dnsAddrs)
	if dbusErr != nil {
		// DBus failed (likely polkit auth) — fall back to resolvectl via sudo.
		// resolvectl path demotes the physical interface itself, so we're done.
		return configureDNSviaResolvectlFunc(ifaceName, dnsAddrs)
	}

	// DBus succeeded for the VPN link, but its per-link SetLinkDefaultRoute
	// call on the physical interface silently fails for NM-managed devices.
	// Force the demote via sudo resolvectl so DNS queries don't leak.
	demotePhysicalDNSDefaultRoute()
	return nil
}

// demotePhysicalDNSDefaultRoute sets the physical interface's DNS default-route
// to false via sudo resolvectl. Exported as a var so tests can stub it.
//
// Bounded with the runWithKillTimeout helper — same rationale as
// restorePhysicalDefaultRoute's resolvectl fallback: a wedged sudo
// or resolvectl would otherwise hang the connect path here.
var demotePhysicalDNSDefaultRoute = func() {
	physIface, _, _ := getPhysicalInterface()
	if physIface == "" {
		return
	}
	cmd := execCommand("sudo", "-n", "resolvectl", "default-route", physIface, "false")
	runWithKillTimeout(cmd, 5*time.Second)
}

// configureDNSviaDbus sets DNS using the systemd-resolved DBus API directly
func configureDNSviaDbus(ifaceName string, dnsAddrs []string) error {
	link, err := netlinkLinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}
	ifaceIndex := int32(link.Attrs().Index)

	conn, err := dbusConnectSystemBus()
	if err != nil {
		return fmt.Errorf("failed to connect to system bus: %w", err)
	}
	defer conn.Close()

	var dnsServers []dnsEntry
	for _, addr := range dnsAddrs {
		ip := net.ParseIP(addr)
		var family int32
		var addrBytes []byte
		if ip.To4() != nil {
			family = 2 // AF_INET
			addrBytes = ip.To4()
		} else {
			family = 10 // AF_INET6
			addrBytes = ip.To16()
		}
		dnsServers = append(dnsServers, dnsEntry{Family: family, Address: addrBytes})
	}

	obj := conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")

	if err := dbusCall(obj, "org.freedesktop.resolve1.Manager.SetLinkDNS", ifaceIndex, dnsServers); err != nil {
		return fmt.Errorf("failed to set DNS: %w", err)
	}

	domains := []domainEntry{{"~.", true}}
	_ = dbusCall(obj, "org.freedesktop.resolve1.Manager.SetLinkDomains", ifaceIndex, domains)

	// Mark VPN interface as the DNS default route
	_ = dbusCall(obj, "org.freedesktop.resolve1.Manager.SetLinkDefaultRoute", ifaceIndex, true)

	// Remove default route from physical interface to prevent DNS leak fallback
	physIface, _, _ := getPhysicalInterface()
	if physIface != "" {
		physLink, err := netlinkLinkByName(physIface)
		if err == nil {
			physIndex := int32(physLink.Attrs().Index)
			_ = dbusCall(obj, "org.freedesktop.resolve1.Manager.SetLinkDefaultRoute", physIndex, false)
		}
	}

	return nil
}

// configureDNSviaResolvectl sets DNS using the resolvectl CLI with sudo.
// The sudoers file grants NOPASSWD for "resolvectl dns *" and "resolvectl domain *".
//
// Every subprocess is bounded with runWithKillTimeout — a wedged sudo
// or resolvectl would otherwise hang the connect path here. The
// primary 'resolvectl dns' call also captures output for IsAuthError;
// the rest are fire-and-forget best-effort follow-ups.
func configureDNSviaResolvectl(ifaceName string, dnsAddrs []string) error {
	// sudo -n resolvectl dns <iface> <addr1> <addr2> ...
	args := append([]string{"-n", "resolvectl", "dns", ifaceName}, dnsAddrs...)
	cmd := execCommand("sudo", args...)
	out, err := captureWithKillTimeout(cmd, 10*time.Second)
	if err != nil {
		if sudo.IsAuthError(out) {
			return fmt.Errorf("resolvectl dns failed: %w", sudo.ErrAuthRequired)
		}
		return fmt.Errorf("resolvectl dns failed: %w: %s", err, string(out))
	}

	// Non-fatal best-effort follow-ups — domain routing, default-route
	// on VPN, default-route off on physical. Each bounded so a wedged
	// resolvectl can't hang the connect path.
	runWithKillTimeout(execCommand("sudo", "-n", "resolvectl", "domain", ifaceName, "~."), 5*time.Second)
	runWithKillTimeout(execCommand("sudo", "-n", "resolvectl", "default-route", ifaceName, "true"), 5*time.Second)
	physIface, _, _ := getPhysicalInterface()
	if physIface != "" {
		runWithKillTimeout(execCommand("sudo", "-n", "resolvectl", "default-route", physIface, "false"), 5*time.Second)
	}

	return nil
}

// captureWithKillTimeout is the CombinedOutput variant of
// runWithKillTimeout — same goroutine-watcher pattern, but returns
// the captured output for IsAuthError checks.
//
// Inlines CombinedOutput's body (a shared bytes.Buffer wired to
// Stdout+Stderr) so we can capture cmd.Process AFTER Start has
// written it but BEFORE the watcher reads it. The naive version
// races cmd.Start's write to cmd.Process — surfaced by the matching
// test in internal/security.
func captureWithKillTimeout(cmd *exec.Cmd, d time.Duration) ([]byte, error) {
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	proc := cmd.Process

	done := make(chan struct{})
	go func() {
		select {
		case <-time.After(d):
			proc.Kill()
		case <-done:
		}
	}()
	err := cmd.Wait()
	close(done)
	return b.Bytes(), err
}

// unconfigureDNS removes DNS configuration and restores physical
// interface DNS default route. Tries DBus RevertLink first; falls back
// to resolvectl revert via sudo. Returns an error if both paths fail —
// callers should surface this since the user is left with DNS still
// pointing at the now-defunct VPN interface and won't know to run
// `sudo resolvectl revert <iface>` manually otherwise.
func unconfigureDNS(ifaceName string) error {
	// Try DBus first
	link, err := netlinkLinkByName(ifaceName)
	if err != nil {
		// Interface doesn't exist — still try to restore physical
		// interface default route, then we're done.
		restorePhysicalDefaultRoute()
		return nil
	}
	ifaceIndex := int32(link.Attrs().Index)

	var dbusErr error
	conn, err := dbusConnectSystemBus()
	if err == nil {
		obj := conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
		dbusErr = dbusCall(obj, "org.freedesktop.resolve1.Manager.RevertLink", ifaceIndex)
		conn.Close()
		if dbusErr == nil {
			restorePhysicalDefaultRoute()
			return nil
		}
	} else {
		dbusErr = err
	}

	// Fall back to resolvectl via sudo. Bounded — a wedged sudo or
	// resolvectl would otherwise hang the disconnect path here.
	if err := runWithKillTimeout(execCommand("sudo", "-n", "resolvectl", "revert", ifaceName), 5*time.Second); err != nil {
		// Both paths failed — restore physical default route anyway
		// (best-effort) and report so the caller can warn the user.
		restorePhysicalDefaultRoute()
		return fmt.Errorf("DNS revert: dbus failed (%v) and sudo resolvectl revert failed (%w)", dbusErr, err)
	}
	restorePhysicalDefaultRoute()
	return nil
}

// restorePhysicalDefaultRoute re-enables the physical interface as a DNS default route.
// Called during disconnect to undo the DNS leak prevention from connect.
func restorePhysicalDefaultRoute() {
	physIface, _, _ := getPhysicalInterface()
	if physIface == "" {
		return
	}

	// Try DBus first
	physLink, err := netlinkLinkByName(physIface)
	if err != nil {
		return
	}
	physIndex := int32(physLink.Attrs().Index)

	conn, err := dbusConnectSystemBus()
	if err == nil {
		obj := conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
		callErr := dbusCall(obj, "org.freedesktop.resolve1.Manager.SetLinkDefaultRoute", physIndex, true)
		conn.Close()
		if callErr == nil {
			return
		}
	}

	// Fall back to resolvectl. Best-effort with a watcher: a wedged
	// resolvectl (rare but documented post-suspend on some distros)
	// would otherwise hang the disconnect path. Use the goroutine-
	// watcher pattern (rather than exec.CommandContext) to preserve
	// the existing execCommand var stubbing in tests.
	cmd := execCommand("sudo", "-n", "resolvectl", "default-route", physIface, "true")
	runWithKillTimeout(cmd, 5*time.Second)
}

// runWithKillTimeout runs cmd via Start+Wait but kills it if it
// takes longer than d. Returns whatever Wait returned.
//
// Captures cmd.Process to a local AFTER Start() writes it but
// BEFORE the watcher reads it — the previous "Run + watcher reads
// cmd.Process" version had a doc comment claiming "no race in
// production" that turned out to be wrong: cmd.Start's write to
// cmd.Process is concurrent with the watcher's read by Go's memory
// model, and the runtime race detector flags it any time the
// timeout actually fires. (Surfaced by the matching test in
// internal/security.)
func runWithKillTimeout(cmd *exec.Cmd, d time.Duration) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	proc := cmd.Process

	done := make(chan struct{})
	go func() {
		select {
		case <-time.After(d):
			proc.Kill()
		case <-done:
		}
	}()
	err := cmd.Wait()
	close(done)
	return err
}

// defaultCaptureBaselineDNS captures the current system DNS resolvers.
// Parses resolvectl dns output first, falls back to /etc/resolv.conf.
// Filters out 127.0.0.53 (systemd-resolved stub resolver).
func defaultCaptureBaselineDNS() []string {
	var resolvers []string

	// Try resolvectl dns first. Bounded by 5s — a hung resolvectl
	// (kernel-side dbus issue, post-suspend regression) would otherwise
	// freeze the entire first-connect path here. CommandContext is the
	// canonical pattern for capturing output AND bounding wall-clock;
	// no test stub for this call site, so direct use is fine.
	resolvectlCtx, resolvectlCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer resolvectlCancel()
	out, err := exec.CommandContext(resolvectlCtx, "resolvectl", "dns").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			for _, word := range strings.Fields(line) {
				if net.ParseIP(word) != nil && word != "127.0.0.53" {
					resolvers = append(resolvers, word)
				}
			}
		}
	}

	// Fallback to /etc/resolv.conf if resolvectl returned nothing
	if len(resolvers) == 0 {
		data, err := os.ReadFile("/etc/resolv.conf")
		if err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "nameserver") {
					fields := strings.Fields(line)
					if len(fields) >= 2 && net.ParseIP(fields[1]) != nil && fields[1] != "127.0.0.53" {
						resolvers = append(resolvers, fields[1])
					}
				}
			}
		}
	}

	return resolvers
}

// ConnectDynamic connects using a dynamic server from the cache
func ConnectDynamic(cfg *config.Config, provider string, serverName string, callback StatusCallback) error {
	// Load provider credentials
	providerCfg, err := configLoadProvider(cfg.ConfigDir, provider)
	if err != nil {
		return fmt.Errorf("failed to load provider config: %w", err)
	}
	defer providerCfg.ZeroKey()

	// Load server from cache
	serverData, err := configLoadServerFromCache(cfg.ConfigDir, provider, serverName)
	if err != nil {
		return fmt.Errorf("failed to load server from cache: %w", err)
	}
	if serverData.IP == "" {
		return fmt.Errorf("server %s has no IP address in cache — try refreshing the server list", serverName)
	}

	// Build a synthetic WireGuard config (copy key to avoid aliasing providerCfg)
	privKeyCopy := make([]byte, len(providerCfg.PrivateKey))
	copy(privKeyCopy, providerCfg.PrivateKey)
	wgCfg := &Config{
		Name:                fmt.Sprintf("dynamic:%s:%s", provider, serverName),
		PrivateKey:          privKeyCopy,
		PublicKey:           serverData.PublicKey,
		Endpoint:            fmt.Sprintf("%s:%d", serverData.IP, providerCfg.Port),
		Address:             providerCfg.Address,
		DNS:                 providerCfg.DNS,
		AllowedIPs:          "0.0.0.0/0,::/0",
		PersistentKeepalive: defaultPersistentKeepalive,
	}

	server := &Server{
		Config: wgCfg,
		Info: &ServerInfo{
			Name:     serverName,
			Country:  serverData.Country,
			City:     serverData.City,
			Provider: provider,
		},
	}

	return Connect(cfg, server, callback)
}

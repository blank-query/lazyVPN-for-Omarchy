package wireguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/logger"
)

// DisconnectStatus represents the status of a disconnection attempt
type DisconnectStatus struct {
	Stage                  string
	Success                bool
	Error                  error
	BeforeIP               string
	AfterIP                string
	KillswitchActive       bool
	PhantomConnection      bool // VPN was already dead
	KillswitchAutoDisabled bool // Killswitch was auto-disabled
	KillswitchPromptNeeded bool // User needs to decide about killswitch
	KillswitchKeptActive   bool // Killswitch kept active (never mode)
}

// DisconnectCallback is called with status updates during disconnection
type DisconnectCallback func(status DisconnectStatus)

// Disconnect terminates the VPN connection
func Disconnect(cfg *config.Config) error {
	return DisconnectWithCallback(cfg, nil)
}

// DisconnectWithCallback terminates the VPN connection with status callbacks
func DisconnectWithCallback(cfg *config.Config, callback DisconnectCallback) error {
	// Use GetConnectionName for consistency with Connect /
	// ForceDisconnect. DisconnectWithCallback is currently only
	// invoked from main-goroutine contexts (TUI Update,
	// daemon.doDisconnect), but the locked accessor pre-emptively
	// covers any future cross-goroutine reach.
	connName := cfg.GetConnectionName()
	log := logger.New(cfg)

	if callback == nil {
		callback = func(s DisconnectStatus) {}
	}

	log.Log(logger.Connection, "Starting disconnection")

	// Stop connection daemon if running (ignore errors - might not be running)
	if err := stopConnectionDaemon(cfg.ConfigDir); err == nil {
		log.Log(logger.Connection, "Stopped connection daemon")
	}

	// Check if connected
	if !isConnectedFunc(connName) {
		log.Log(logger.Connection, "Not connected - nothing to disconnect")
		callback(DisconnectStatus{Stage: "Not connected", Success: true})
		return nil
	}

	// Get current public IP before disconnecting
	callback(DisconnectStatus{Stage: "Checking current IP..."})
	beforeIP, _ := utilGetPublicIPv4()
	log.Log(logger.Connection, "Current IP before disconnect: %s", beforeIP)

	callback(DisconnectStatus{Stage: "Disconnecting..."})

	// Capture the peer endpoint IP before teardown — connect.go added a host
	// route for it via the ISP gateway so handshake traffic bypasses the
	// tunnel. Without this lookup the route survives disconnect, leaking one
	// stale entry per connect/disconnect cycle.
	var endpointIP string
	if dev, err := netlinkGetDeviceInfo(connName); err == nil && dev != nil && len(dev.Peers) > 0 {
		if ep := dev.Peers[0].Endpoint; ep != nil {
			endpointIP = ep.IP.String()
		}
	}

	// LAN Block rules (lazyvpn:lb tag) are NOT removed here. UFW is the
	// source of truth for LAN-block state — there's no persisted "preference"
	// bit; the rules themselves carry the state. Stale per-endpoint rules
	// (-o wg0, -d <endpoint>) are harmless once the interface is gone, and
	// Connect() re-applies them with fresh params when reconnecting.

	// Remove DNS configuration first. Tries DBus then sudo resolvectl;
	// if both fail the user's resolver still points at the VPN, so warn
	// loudly and tell them how to recover. We don't abort the
	// disconnect — there's still useful cleanup downstream.
	if err := unconfigureDNSFunc(connName); err != nil {
		callback(DisconnectStatus{
			Stage: fmt.Sprintf("Warning: DNS revert failed (%v) — run 'sudo resolvectl revert %s' to fix", err, connName),
		})
		log.Log(logger.Connection, "DNS revert failed: %v", err)
	}

	// Clean up routes
	callback(DisconnectStatus{Stage: "Cleaning up routes..."})
	if err := netlinkDeleteSplitRoutes(connName); err != nil {
		log.Log(logger.Connection, "Warning: route cleanup failed: %v", err)
	}
	if endpointIP != "" {
		if err := netlinkDeleteHostRoute(endpointIP); err != nil {
			log.Log(logger.Connection, "Warning: endpoint host route cleanup failed: %v", err)
		}
	}

	// Delete the interface directly via netlink
	callback(DisconnectStatus{Stage: "Removing WireGuard interface..."})
	if err := netlinkDeleteLinkInterface(connName); err != nil {
		log.Log(logger.Connection, "Warning: interface delete failed: %v", err)
	}

	// Interface is gone — ensure config always reflects "disconnected"
	// even if verification below fails. ClearConnectionState locks c.mu
	// around the writes (sleepWakeListener / handleClient goroutines may
	// be reading these fields via LoggerView) and routes through
	// SaveConnectionState which preserves user-pref fields against stale
	// daemon in-memory state.
	//
	// clearLastServer=true matches the explicit-disconnect contract:
	// LastConnectedServer (and LastServerFeatures, which describes the
	// same connection) are wiped so autoconnect (mode=last_used) does
	// NOT try to resume on next launch. ForceDisconnect's path passes
	// false to preserve that anchor.
	defer func() {
		if err := cfg.ClearConnectionState(true); err != nil {
			log.Log(logger.Connection, "Warning: failed to save config: %v", err)
		}
	}()

	// Verify disconnection
	callback(DisconnectStatus{Stage: "Verifying disconnection..."})
	timeSleep(2 * time.Second)

	// Check if killswitch is blocking — UFW is the source of truth for
	// killswitch state (there's no persisted "preference" bit anymore).
	killswitchBlocking := firewallIsActive()

	if killswitchBlocking {
		// Killswitch active - verify traffic is blocked
		afterIP, err := utilGetPublicIPv4()
		if err == nil && afterIP != "" {
			// Got IP when killswitch should block - failure
			return fmt.Errorf("killswitch enabled but traffic not blocked (IP: %s)", afterIP)
		}

		// Handle killswitch auto-disable based on config setting
		status := DisconnectStatus{
			Stage:            "Disconnected",
			Success:          true,
			KillswitchActive: true,
		}

		switch cfg.KillswitchAutoDisable {
		case "true", "":
			// Auto-disable killswitch
			if err := firewallDisable(); err != nil {
				log.Log(logger.Connection, "Failed to auto-disable killswitch: %v", err)
			} else {
				log.Log(logger.Connection, "Killswitch auto-disabled after disconnect")
				status.KillswitchAutoDisabled = true
				status.KillswitchActive = false
			}
		case "false":
			// User needs to decide - signal the UI
			status.KillswitchPromptNeeded = true
			log.Log(logger.Connection, "Killswitch still active - user prompt needed")
		case "never":
			// Keep killswitch active intentionally
			status.KillswitchKeptActive = true
			log.Log(logger.Connection, "Killswitch kept active (never auto-disable)")
		}

		callback(status)
	} else {
		// Killswitch not active - IP should have changed
		afterIP, err := utilGetPublicIPv4()
		if err != nil {
			// Can't verify but VPN is already torn down — treat as success
			log.Log(logger.Connection, "Could not verify IP after disconnect: %v", err)
			callback(DisconnectStatus{
				Stage:   "Disconnected",
				Success: true,
			})
			return nil
		}

		phantomConnection := false
		if afterIP == beforeIP {
			// IP didn't change - check for phantom connection
			if cfg.RealPublicIP == "" || beforeIP == cfg.RealPublicIP {
				// No baseline or IP matches real IP — VPN was already dead
				phantomConnection = true
			} else {
				return fmt.Errorf("IP unchanged after disconnect - may still be connected")
			}
		}

		callback(DisconnectStatus{
			Stage:             "Disconnected",
			Success:           true,
			BeforeIP:          beforeIP,
			AfterIP:           afterIP,
			PhantomConnection: phantomConnection,
		})

		if phantomConnection {
			log.Log(logger.Connection, "Disconnected (phantom connection detected)")
		} else {
			log.Log(logger.Connection, "Disconnected successfully (IP: %s -> %s)", beforeIP, afterIP)
		}
	}

	return nil
}

// ForceDisconnect forcefully removes the connection without verification
func ForceDisconnect(cfg *config.Config) error {
	// Take ConnectionName under cfg.mu.RLock — ForceDisconnect is
	// called from the daemon's sleepWakeListener (its own goroutine)
	// while the main goroutine may be running cfg.Reload which
	// rewrites ConnectionName under cfg.mu.Lock. Direct read would
	// race that write. Same fix as 78d4ef0's helper, applied at
	// this function's entry so the protection survives across the
	// call chain.
	//
	// cfg.ConfigDir below is intentionally NOT routed through a
	// getter: it's set at Load time and never modified by Reload
	// (see config.Reload's doc comment), so concurrent reads of it
	// are race-free without sync.
	connName := cfg.GetConnectionName()

	// Stop connection daemon if running
	stopConnectionDaemon(cfg.ConfigDir)

	// Capture endpoint IP before teardown so the host route gets cleaned up.
	var endpointIP string
	if dev, err := netlinkGetDeviceInfo(connName); err == nil && dev != nil && len(dev.Peers) > 0 {
		if ep := dev.Peers[0].Endpoint; ep != nil {
			endpointIP = ep.IP.String()
		}
	}

	// Remove DNS configuration. ForceDisconnect runs from daemon
	// SIGTERM and switch paths — no live status callback, but log so a
	// failure shows up in debug.log when the user investigates.
	if err := unconfigureDNSFunc(connName); err != nil {
		log := logger.New(cfg)
		log.Log(logger.Connection, "ForceDisconnect: DNS revert failed (%v) — user may need 'sudo resolvectl revert %s'", err, connName)
	}

	// Delete routes
	netlinkDeleteSplitRoutes(connName)
	if endpointIP != "" {
		netlinkDeleteHostRoute(endpointIP)
	}

	// Delete the interface directly via netlink
	if netlinkInterfaceExists(connName) {
		netlinkDeleteLinkInterface(connName)
	}

	// Clear session-state fields but PRESERVE LastConnectedServer.
	// ForceDisconnect runs from the daemon's terminate handler on system
	// shutdown SIGTERM as well as `lazyvpn daemon stop`; in both cases the
	// user almost certainly wants autoconnect (mode=last_used) to resume the
	// same server on next launch. Explicit user-disconnect via the TUI goes
	// through DisconnectWithCallback, which still clears LastConnectedServer.
	//
	// ClearConnectionState locks c.mu around the field writes so the in-memory
	// state changes don't race a concurrent LoggerView read (the main goroutine
	// can be logging while we run on sleepWakeListener's goroutine). Save is
	// best-effort: if ConfigDir was already removed (uninstall race — daemon's
	// signal handler runs ForceDisconnect AFTER Step 16 deleted the dir), Save
	// returns nil silently by design.
	cfg.ClearConnectionState(false)

	return nil
}

// stopConnectionDaemon stops the connection daemon by sending SIGTERM
// Avoids import cycle by not importing the daemon package
// Won't kill itself if called from within the daemon
func stopConnectionDaemon(configDir string) error {
	pidFile := filepath.Join(configDir, ".daemon.pid")
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return err // Not running
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}

	// Don't kill ourselves if we ARE the daemon
	if pid == os.Getpid() {
		return nil
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	// Send SIGTERM
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return err
	}

	// Wait for the daemon to exit before continuing. Real-world ForceDisconnect
	// inside the daemon's signal handler runs sudo resolvectl + netlink ops +
	// firewall.Disable, easily exceeding 3s under sudo/netlink latency. Poll
	// up to 10s, then SIGKILL as a backstop — silently leaving the daemon
	// alive lets it race the caller's subsequent route/interface teardown.
	for i := 0; i < 100; i++ { // 10 seconds max
		timeSleep(100 * time.Millisecond)
		if err := process.Signal(syscall.Signal(0)); err != nil {
			// Process exited — safe to remove PID file
			os.Remove(pidFile)
			return nil
		}
	}

	// Daemon ignored SIGTERM. Force-kill so callers don't continue with a
	// live daemon racing them for the WG interface and firewall state.
	process.Signal(syscall.SIGKILL)
	timeSleep(500 * time.Millisecond)
	os.Remove(pidFile)
	return fmt.Errorf("daemon (PID %d) did not respond to SIGTERM within 10s, sent SIGKILL", pid)
}

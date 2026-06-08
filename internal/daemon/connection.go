package daemon

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/firewall"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/logger"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/netlink"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/notify"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/provider"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/util"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"

	"github.com/godbus/dbus/v5"
	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ConnectionDaemon manages VPN connections and health monitoring
type ConnectionDaemon struct {
	cfg     *config.Config
	log     *logger.Logger
	state   DaemonState
	stateMu sync.RWMutex

	// Connection info
	currentServer   string
	currentProvider string
	isDynamic       bool
	publicIP        string
	connectedSince  time.Time

	// For switch/retry - track previous connection
	prevServer   string
	prevProvider string
	prevDynamic  bool

	// lastFailureMessage holds the most recent failure reason for any clients
	// that connect AFTER the EventFailed broadcast was sent. Without this, a
	// fast-failing initial connect (e.g. corrupt provider JSON parses in <1ms)
	// can broadcast EventFailed before the spawning CLI's socket attaches —
	// the CLI would only see EventStatus with no error info and wait the full
	// connectFlowReadTimeout. sendStatus replays this to late-connecting clients.
	lastFailureMessage string

	// Health monitoring
	health                  *healthTracker
	consecutiveBadTicks     int
	badTicksForRecovery     int
	reconnectScoreThreshold int
	retryCount              int
	maxRetries              int
	consecHeavyFails        int // consecutive heavy ticks where both ping+DNS fail
	lightTickInterval       time.Duration
	heavyTickInterval       time.Duration

	// Socket server
	listener net.Listener
	clients  map[net.Conn]*sync.Mutex // per-conn write mutex
	clientMu sync.Mutex

	// Control channels
	stopCh    chan struct{}
	stopOnce  sync.Once
	commandCh chan Command

	// Initial command to execute on startup (optional)
	initialCmd *Command

	// Pluggable dependencies (nil = use real implementations)
	connector VPNConnector  // nil = use real wireguard calls
	healthChk HealthChecker // nil = use real ping/DNS
}

// NewConnectionDaemon creates a new connection daemon
func NewConnectionDaemon(cfg *config.Config) *ConnectionDaemon {
	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	badTicks := cfg.MaxHealthFails
	if badTicks <= 0 {
		badTicks = 3
	}

	threshold := cfg.ReconnectThreshold
	if threshold <= 0 {
		threshold = 40
	}

	// Light tick: prefer LightTickInterval, fall back to HealthCheckInterval
	lightSec := cfg.LightTickInterval
	if lightSec <= 0 {
		lightSec = cfg.HealthCheckInterval
	}
	if lightSec <= 0 {
		lightSec = 3
	}

	heavySec := cfg.HeavyTickInterval
	if heavySec <= 0 {
		heavySec = 15
	}

	return &ConnectionDaemon{
		cfg:                     cfg,
		log:                     logger.New(cfg),
		state:                   StateIdle,
		health:                  newHealthTracker(),
		clients:                 make(map[net.Conn]*sync.Mutex),
		maxRetries:              maxRetries,
		badTicksForRecovery:     badTicks,
		reconnectScoreThreshold: threshold,
		lightTickInterval:       time.Duration(lightSec) * time.Second,
		heavyTickInterval:       time.Duration(heavySec) * time.Second,
		stopCh:                  make(chan struct{}),
		commandCh:               make(chan Command, defaultCommandChBuffer),
	}
}

const defaultCommandChBuffer = 10

// SetConnector sets a custom VPN connector (for testing).
// When non-nil, the daemon uses this instead of real wireguard calls.
func (d *ConnectionDaemon) SetConnector(c VPNConnector) { d.connector = c }

// SetHealthChecker sets a custom health checker (for testing).
// When non-nil, the daemon uses this instead of real TCP pings.
func (d *ConnectionDaemon) SetHealthChecker(h HealthChecker) { d.healthChk = h }

// Run starts the daemon - this is the main entry point
func (d *ConnectionDaemon) Run() error {
	pidPath := PidPath(d.cfg.ConfigDir)

	// Atomically create PID file to prevent two daemons from starting.
	// O_CREATE|O_EXCL fails if the file already exists.
	pidData := []byte(strconv.Itoa(os.Getpid()))
	f, err := os.OpenFile(pidPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		// File exists — check if the PID points to OUR binary. A bare
		// signal-0 liveness check would false-positive on a recycled PID
		// that now belongs to an unrelated process, refusing the fresh
		// spawn with "daemon already running (PID <firefox>)".
		if existingPid := readPidFile(pidPath); existingPid > 0 && existingPid != os.Getpid() {
			if IsLazyvpnPid(existingPid) {
				return fmt.Errorf("daemon already running (PID %d)", existingPid)
			}
		}
		// Stale PID file — remove and retry
		os.Remove(pidPath)
		f, err = os.OpenFile(pidPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to create PID file: %w", err)
		}
	}
	if _, err := f.Write(pidData); err != nil {
		f.Close()
		os.Remove(pidPath)
		return fmt.Errorf("failed to write PID file: %w", err)
	}
	f.Close()
	// Set up cleanup() now so every error path below removes both the
	// pid file AND any partially-set-up socket. Pre-fix the chmod
	// failure path (line below) explicitly closed the listener but
	// left the socket FILE on disk — cleanup() would have removed
	// it, but the cleanup defer wasn't installed until after chmod
	// succeeded. Also collapses the prior `defer os.Remove(pidPath)`
	// into the same path so there's a single removal at function
	// exit instead of two consecutive defers (eliminating the
	// sub-microsecond race window between them).
	//
	// cleanup() is idempotent and safe with a nil listener / empty
	// clients map — both checked at its entry — so calling it from
	// any return point below is harmless.
	defer d.cleanup()

	// Start socket server
	socketPath := SocketPath(d.cfg.ConfigDir)
	// Remove stale socket (safe — we verified the old process is dead above)
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	d.listener = listener

	// Set socket permissions to owner-only (prevent other local users from controlling daemon)
	if err := os.Chmod(socketPath, 0600); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	d.log.Log(logger.Connection, "Connection daemon started (PID: %d)", os.Getpid())

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)

	// Accept clients in background
	go d.acceptClients()

	// Listen for sleep/wake signals from systemd-logind
	go d.sleepWakeListener()

	// Process initial command if set (before entering main loop)
	if d.initialCmd != nil {
		d.handleCommand(*d.initialCmd)
		d.initialCmd = nil
	}

	// Main loop — staggered health tickers
	lightTicker := time.NewTicker(d.lightTickInterval)
	heavyTicker := time.NewTicker(d.heavyTickInterval)
	defer lightTicker.Stop()
	defer heavyTicker.Stop()

	for {
		select {
		case <-d.stopCh:
			d.log.Log(logger.Connection, "Daemon received stop signal")
			return nil

		case sig := <-sigCh:
			d.log.Log(logger.Connection, "Daemon received signal: %v", sig)
			// If a tunnel is up, tear it down before exiting. Users invoking
			// `lazyvpn daemon stop` expect the VPN off — without this, wg0
			// persists after the daemon exits and the CLI's "VPN disconnected"
			// confirmation is a lie.
			//
			// Use ForceDisconnect (no IP-verification HTTP, no 2s sleep) since
			// we're on our way out and the normal verifying path would easily
			// exceed the CLI's wait window. We still honor KillswitchAutoDisable.
			d.stateMu.RLock()
			connected := d.state == StateConnected || d.state == StateUnhealthy
			d.stateMu.RUnlock()
			if connected {
				d.log.Log(logger.Connection, "Terminating: fast teardown of active connection before exit")
				if d.connector != nil {
					d.connector.ForceDisconnect(d.cfg)
				} else {
					wireguard.ForceDisconnect(d.cfg)
				}
				// Honor killswitch auto-disable preference (the only firewall
				// state that changes on graceful disconnect). Reload user prefs
				// first so we read the current on-disk KillswitchAutoDisable —
				// the TUI may have edited it since the daemon started, and the
				// in-memory copy would otherwise be stale (e.g. user set Never
				// expecting reboot to keep the killswitch up).
				if err := d.cfg.ReloadUserPrefs(); err != nil {
					d.log.Log(logger.Connection, "Warning: ReloadUserPrefs at terminate failed: %v", err)
				}
				if firewall.IsActive() {
					switch d.cfg.KillswitchAutoDisable {
					case "true", "":
						if err := firewall.Disable(); err != nil {
							d.log.Log(logger.Connection, "Failed to auto-disable killswitch: %v", err)
						}
					}
				}
			}
			// Carry final killswitch state so attached TUIs don't show a
			// stale indicator after this broadcast. The IPC doDisconnect
			// path already sets this; the SIGTERM path used to leave it
			// at the zero-value (false), overwriting the dashboard's
			// d.killswitch in applyDaemonEvent. With KillswitchAutoDisable
			// off, the killswitch survives termination but the TUI would
			// flip its indicator to "off" until the next status refresh.
			d.broadcastEvent(Event{
				Type:             EventDisconnected,
				Timestamp:        time.Now(),
				Message:          "Daemon terminated",
				KillswitchActive: firewall.IsActive(),
			})
			d.stop() // Close stopCh so acceptClients exits cleanly
			return nil

		case cmd := <-d.commandCh:
			d.handleCommand(cmd)

		case <-lightTicker.C:
			d.lightHealthTick()

		case <-heavyTicker.C:
			d.heavyHealthTick()
		}
	}
}

// acceptClients accepts incoming client connections
func (d *ConnectionDaemon) acceptClients() {
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			select {
			case <-d.stopCh:
				return
			default:
				// Listener was closed (e.g., cleanup ran before stopCh)
				if errors.Is(err, net.ErrClosed) {
					return
				}
				d.log.Log(logger.Connection, "Accept error: %v", err)
				continue
			}
		}
		go d.handleClient(conn)
	}
}

// handleClient handles a single client connection
func (d *ConnectionDaemon) handleClient(conn net.Conn) {
	connMu := &sync.Mutex{}
	d.clientMu.Lock()
	d.clients[conn] = connMu
	d.clientMu.Unlock()

	defer func() {
		d.clientMu.Lock()
		delete(d.clients, conn)
		remaining := len(d.clients)
		d.clientMu.Unlock()
		conn.Close()

		// Catch the M5-style stuck daemon: after a failed initial/switch
		// connect, the spawning CLI stays attached past exitIfOrphaned's
		// hard 3s grace window (its event-read timeout is much longer),
		// so the orphan check never trips. When that single client finally
		// times out and disconnects here, the daemon would otherwise live
		// forever holding socket+pid file. Re-trigger orphan exit on
		// last-client-gone if state is terminal-failed.
		if remaining == 0 {
			d.stateMu.RLock()
			st := d.state
			d.stateMu.RUnlock()
			if st == StateFailed || st == StateSwitchFailed {
				d.log.Log(logger.Connection, "Last client disconnected in state %s — daemon exiting", st)
				d.stop()
			}
		}
	}()

	// Send current status immediately
	d.sendStatus(conn)

	// Read commands
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return // Client disconnected
		}

		var cmd Command
		if err := json.Unmarshal([]byte(line), &cmd); err != nil {
			d.log.Log(logger.Connection, "Invalid command from client: %v", err)
			continue
		}

		if err := cmd.Validate(); err != nil {
			d.log.Log(logger.Connection, "Invalid command: %v", err)
			d.sendToClient(conn, Event{
				Type:      EventError,
				Timestamp: time.Now(),
				Error:     err.Error(),
				Message:   "Invalid command",
			})
			continue
		}

		// Handle status command directly
		if cmd.Type == CmdStatus {
			d.sendStatus(conn)
			continue
		}

		// Queue other commands. Non-blocking — a flooding client must
		// not stall the read loop. If the queue is full, surface to
		// the originating client so the TUI doesn't sit waiting for an
		// event that will never arrive (the previous "log and drop"
		// left the client hanging on connectFlowReadTimeout).
		select {
		case d.commandCh <- cmd:
		default:
			d.log.Log(logger.Connection, "Command queue full, dropping: %v", cmd.Type)
			d.sendToClient(conn, Event{
				Type:      EventError,
				Timestamp: time.Now(),
				Error:     "daemon busy",
				Message:   fmt.Sprintf("Daemon command queue full — %s dropped, retry in a moment", cmd.Type),
			})
		}
	}
}

// sendStatus sends current status to a specific client
func (d *ConnectionDaemon) sendStatus(conn net.Conn) {
	// Snapshot all daemon state under RLock; firewall.IsActive() runs
	// `sudo -n ufw status` (a subprocess) and must NOT be called while
	// holding the lock — otherwise any state writer (setState, doConnect,
	// etc.) blocks for the duration of the sudo call.
	// User-prefs snapshot taken under cfg.mu.RLock — these fields are
	// written by ReloadUserPrefs / Reload on the main goroutine, and
	// sendStatus runs in handleClient goroutines. A direct read of
	// d.cfg.AutoRecover here races those writes. Take the snapshot
	// BEFORE entering stateMu's critical section so the cfg lock is
	// never held for longer than the field copy.
	prefs := d.cfg.UserPrefsView()

	d.stateMu.RLock()
	var hs *HealthState
	if d.state == StateConnected || d.state == StateUnhealthy {
		snapshot := d.health.computeScore()
		hs = &snapshot
	}
	status := Status{
		State:          d.state,
		Connected:      d.state == StateConnected || d.state == StateUnhealthy,
		Server:         d.currentServer,
		Provider:       d.currentProvider,
		PublicIP:       d.publicIP,
		ConnectedSince: d.connectedSince,
		RetryCount:     d.retryCount,
		AutoReconnect:  prefs.AutoRecover,
		AutoFailover:   prefs.AutoFailover,
		Health:         hs,
	}
	d.stateMu.RUnlock()
	status.KillswitchActive = firewall.IsActive()

	event := Event{
		Type:             EventStatus,
		Timestamp:        time.Now(),
		Server:           status.Server,
		Provider:         status.Provider,
		PublicIP:         status.PublicIP,
		DaemonState:      status.State,
		KillswitchActive: status.KillswitchActive,
		Health:           hs,
	}

	d.sendToClient(conn, event)

	// Replay the most recent failure to late-connecting clients. A CLI like
	// `lazyvpn random` can dial the socket microseconds AFTER the daemon's
	// fast-failing initialCmd already broadcast EventFailed to an empty
	// client map. Without this replay the client only sees EventStatus
	// (not terminal in SpawnAndWaitForConnect's switch) and waits the full
	// connectFlowReadTimeout (~120s) for an event that never arrives.
	//
	// SwitchFailed needs its own event type because the TUI's switch-recovery
	// flow keys off EventSwitchFailed to offer a "go back to previous server"
	// option — sending EventFailed instead would silently strip the recovery
	// affordance from any TUI that reconnects to a daemon mid-switch-failure.
	if status.State == StateFailed || status.State == StateSwitchFailed {
		d.stateMu.RLock()
		failMsg := d.lastFailureMessage
		prevServer := d.prevServer
		prevProvider := d.prevProvider
		prevDynamic := d.prevDynamic
		d.stateMu.RUnlock()
		if failMsg != "" {
			ev := Event{
				Timestamp: time.Now(),
				Error:     failMsg,
				Server:    status.Server,
				Provider:  status.Provider,
			}
			if status.State == StateSwitchFailed {
				ev.Type = EventSwitchFailed
				ev.Message = "Switch failed"
				ev.PrevServer = prevServer
				ev.PrevProvider = prevProvider
				ev.PrevDynamic = prevDynamic
			} else {
				ev.Type = EventFailed
				ev.Message = "Connection failed"
			}
			d.sendToClient(conn, ev)
		}
	}
}

// sendToClient sends an event to a specific client.
// If the write fails (e.g., broken pipe), the client is removed from the
// client map so subsequent broadcasts/sends don't retry a dead connection.
// The connection itself is NOT closed here — handleClient's deferred cleanup
// owns the conn's lifecycle. Closing early would abort handleClient's reader
// goroutine and drop any buffered commands the peer sent before disconnecting.
func (d *ConnectionDaemon) sendToClient(conn net.Conn, event Event) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	data = append(data, '\n')

	// Acquire per-connection write mutex to prevent interleaved writes
	d.clientMu.Lock()
	mu, ok := d.clients[conn]
	d.clientMu.Unlock()
	if !ok {
		return // connection already removed
	}

	mu.Lock()
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, writeErr := conn.Write(data)
	conn.SetWriteDeadline(time.Time{}) // clear deadline
	mu.Unlock()
	if writeErr != nil {
		d.log.Log(logger.Connection, "Failed to send to client: %v", writeErr)
		d.clientMu.Lock()
		delete(d.clients, conn)
		d.clientMu.Unlock()
	}
}

// broadcastEvent sends an event to all connected clients
func (d *ConnectionDaemon) broadcastEvent(event Event) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	data = append(data, '\n')

	// Snapshot under the lock and write outside it. Each Write has a 5s
	// deadline; with N slow clients this could otherwise hold clientMu for
	// up to N×5s, blocking the main loop and any handleClient goroutines
	// that need clientMu to look up their per-conn mutex.
	d.clientMu.Lock()
	snapshot := make(map[net.Conn]*sync.Mutex, len(d.clients))
	for conn, mu := range d.clients {
		snapshot[conn] = mu
	}
	d.clientMu.Unlock()

	var dead []net.Conn
	for conn, mu := range snapshot {
		mu.Lock()
		conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, writeErr := conn.Write(data)
		conn.SetWriteDeadline(time.Time{}) // clear deadline
		mu.Unlock()
		if writeErr != nil {
			dead = append(dead, conn)
		}
	}

	if len(dead) > 0 {
		d.clientMu.Lock()
		for _, conn := range dead {
			delete(d.clients, conn)
		}
		d.clientMu.Unlock()
		// Force-close failed writers. handleClient's reader has no read
		// deadline, so a client that timed out on write would otherwise
		// stay blocked in ReadString forever. handleClient's deferred
		// Close runs again — that second Close is a benign no-op at the
		// OS level (and handleClient's read loop returns silently on
		// ErrClosed, so no log noise).
		for _, conn := range dead {
			conn.Close()
		}
	}
}

// handleCommand processes a command from a client
func (d *ConnectionDaemon) handleCommand(cmd Command) {
	switch cmd.Type {
	case CmdConnect:
		d.doConnect(cmd.Server, cmd.Provider, cmd.IsDynamic, false)
	case CmdDisconnect:
		d.doDisconnect()
	case CmdSwitch:
		d.doSwitch(cmd.Server, cmd.Provider, cmd.IsDynamic)
	}
}

// doConnect performs a VPN connection.
// Daemon broadcasts events; the TUI is what actually prompts the user.
//   isSwitch=true:  on failure, broadcasts EventSwitchFailed (TUI offers retry/previous/disconnect).
//   isSwitch=false: on failure, broadcasts EventFailed       (TUI offers retry/disconnect; or
//                   if no client is attached, exitIfOrphaned terminates the daemon).
func (d *ConnectionDaemon) doConnect(serverName, provider string, isDynamic bool, isSwitch bool) {
	d.setState(StateConnecting)
	d.broadcastEvent(Event{
		Type:      EventConnecting,
		Timestamp: time.Now(),
		Server:    serverName,
		Provider:  provider,
		Message:   "Connecting...",
	})

	var err error
	var server *wireguard.Server
	var connOldIP, connNewIP string

	connectCallback := func(s wireguard.ConnectionStatus) {
		if s.OldIP != "" {
			connOldIP = s.OldIP
		}
		if s.NewIP != "" {
			connNewIP = s.NewIP
		}
		event := Event{
			Type:      EventConnecting,
			Timestamp: time.Now(),
			Message:   s.Stage,
		}
		if s.Success {
			event.Hint = "success"
		} else if s.Danger {
			event.Hint = "error"
		} else if s.Warning {
			event.Hint = "warning"
		}
		d.broadcastEvent(event)
	}

	if d.connector != nil {
		err = d.connector.Connect(d.cfg, serverName, provider, isDynamic, connectCallback)
	} else if isDynamic {
		err = wireguard.ConnectDynamic(d.cfg, provider, serverName, connectCallback)
	} else {
		wgDir := filepath.Join(d.cfg.ConfigDir, "wireguard")
		wgCfg, loadErr := wireguard.LoadConfig(wgDir, serverName)
		if loadErr != nil {
			err = loadErr
		} else {
			server = wireguard.NewServer(wgCfg)
			err = wireguard.Connect(d.cfg, server, connectCallback)
		}
	}

	if err != nil {
		notify.Error(fmt.Sprintf("Connection failed: %v", err))

		if isSwitch {
			// Switch failed - offer retry/previous/disconnect
			d.setState(StateSwitchFailed)
			d.stateMu.Lock()
			d.lastFailureMessage = err.Error()
			d.stateMu.Unlock()
			d.stateMu.RLock()
			event := Event{
				Type:         EventSwitchFailed,
				Timestamp:    time.Now(),
				Error:        err.Error(),
				Server:       serverName,
				Provider:     provider,
				Message:      "Switch failed",
				PrevServer:   d.prevServer,
				PrevProvider: d.prevProvider,
				PrevDynamic:  d.prevDynamic,
			}
			d.stateMu.RUnlock()
			d.broadcastEvent(event)
		} else {
			// Initial connection failed - offer retry/disconnect
			d.setState(StateFailed)
			d.stateMu.Lock()
			d.lastFailureMessage = err.Error()
			d.stateMu.Unlock()
			d.broadcastEvent(Event{
				Type:      EventFailed,
				Timestamp: time.Now(),
				Error:     err.Error(),
				Server:    serverName,
				Provider:  provider,
				Message:   "Connection failed",
			})
		}
		// If no TUI client is attached there's nobody to send a retry/disconnect
		// command — the daemon would otherwise become a zombie. Start a grace
		// window (in a goroutine so we don't block the main loop from running)
		// to let a freshly-spawned TUI finish dialing; if no client attaches in
		// that window, exit.
		go d.exitIfOrphaned(orphanExitGrace)
		// Otherwise wait for user choice (retry/previous/disconnect)
		return
	}

	// Connection succeeded — save feature flags for footer display.
	// Compute the features string locally, then route through the
	// SetLastServerFeatures setter so the write takes cfg.mu.Lock —
	// SaveConnectionState invocations from the sleepWakeListener path
	// (wake-during-connect) read LastServerFeatures under c.mu.Lock and
	// the prior bare assignment raced that read.
	var features string
	if isDynamic {
		serverData, err := config.LoadServerFromCache(d.cfg.ConfigDir, provider, serverName)
		if err == nil {
			var feats []string
			if serverData.PortForward {
				feats = append(feats, "p2p")
			}
			if serverData.Tor {
				feats = append(feats, "tor")
			}
			if serverData.SecureCore {
				feats = append(feats, "securecore")
			}
			if serverData.Stream {
				feats = append(feats, "streaming")
			}
			if serverData.Free {
				feats = append(feats, "free")
			}
			features = strings.Join(feats, ",")
		}
	} else if server != nil && server.Info != nil {
		features = strings.Join(server.Info.Services, ",")
	}
	if err := d.cfg.SetLastServerFeatures(features); err != nil {
		// Connect succeeded but persisting the new server name / features
		// failed. Surface so the next daemon start doesn't think we're
		// still on the previous server. SaveConnectionState (not Save) so
		// stale daemon cfg doesn't clobber user prefs (KillswitchAutoDisable,
		// Autostart*, log toggles, etc.) that the TUI may have edited.
		d.log.Log(logger.Connection, "Warning: cfg.SaveConnectionState after connect failed: %v", err)
	}

	d.stateMu.Lock()
	d.currentServer = serverName
	d.currentProvider = provider
	d.isDynamic = isDynamic
	d.publicIP = d.cfg.LastPublicIP
	d.connectedSince = time.Now()
	d.consecutiveBadTicks = 0
	d.retryCount = 0
	d.health.reset()
	// Clear previous server info
	d.prevServer = ""
	d.prevProvider = ""
	d.prevDynamic = false
	// Clear stale failure message so a future status reply doesn't replay
	// an old EventFailed to a freshly connecting client.
	d.lastFailureMessage = ""
	d.stateMu.Unlock()

	d.setState(StateConnected)
	d.broadcastEvent(Event{
		Type:      EventConnected,
		Timestamp: time.Now(),
		Server:    serverName,
		Provider:  provider,
		PublicIP:  connNewIP,
		OldIP:     connOldIP,
		Message:   "Connected",
	})

	notify.Connected(serverName)
}

// doDisconnect performs a VPN disconnection
func (d *ConnectionDaemon) doDisconnect() {
	d.setState(StateDisconnecting)
	d.broadcastEvent(Event{
		Type:      EventDisconnecting,
		Timestamp: time.Now(),
		Message:   "Disconnecting...",
	})

	// Refresh user-pref fields from disk before disconnect — DisconnectWithCallback
	// switches on cfg.KillswitchAutoDisable to decide whether to auto-clear the
	// killswitch, and the daemon's in-memory copy may be stale if the TUI edited
	// that setting since the daemon started.
	if err := d.cfg.ReloadUserPrefs(); err != nil {
		d.log.Log(logger.Connection, "Warning: ReloadUserPrefs before disconnect failed: %v", err)
	}

	var err error
	var killswitchStillActive bool
	if d.connector != nil {
		err = d.connector.Disconnect(d.cfg)
	} else {
		err = wireguard.DisconnectWithCallback(d.cfg, func(s wireguard.DisconnectStatus) {
			d.broadcastEvent(Event{
				Type:      EventDisconnecting,
				Timestamp: time.Now(),
				Message:   s.Stage,
			})
			if s.KillswitchActive {
				killswitchStillActive = true
			}
		})
	}

	if err != nil {
		d.broadcastEvent(Event{
			Type:      EventError,
			Timestamp: time.Now(),
			Error:     err.Error(),
			Message:   "Disconnect error",
		})
	}

	d.broadcastEvent(Event{
		Type:             EventDisconnected,
		Timestamp:        time.Now(),
		Message:          "Disconnected",
		KillswitchActive: killswitchStillActive,
	})

	notify.Disconnected()

	if killswitchStillActive {
		notify.KillswitchBlocking("VPN disconnected")
	}

	// Exit daemon after disconnect
	d.stop()
}

// doSwitch switches to a different server
func (d *ConnectionDaemon) doSwitch(serverName, provider string, isDynamic bool) {
	// Store previous server info before switching
	d.stateMu.Lock()
	d.prevServer = d.currentServer
	d.prevProvider = d.currentProvider
	d.prevDynamic = d.isDynamic
	d.stateMu.Unlock()

	d.broadcastEvent(Event{
		Type:      EventSwitching,
		Timestamp: time.Now(),
		Server:    serverName,
		Provider:  provider,
		Message:   "Switching servers...",
	})

	// Disconnect current (but don't exit daemon)
	if d.connector != nil {
		d.connector.ForceDisconnect(d.cfg)
	} else {
		wireguard.ForceDisconnect(d.cfg)
	}

	// Connect to new (isSwitch=true for proper failure handling)
	d.doConnect(serverName, provider, isDynamic, true)
}

// Injectable functions for wgctrl/netlink (overridden in tests)
var getDeviceInfoFn = func(name string) (*wgtypes.Device, error) {
	return netlink.GetDeviceInfo(name)
}

var getInterfaceStatsFn = netlink.GetInterfaceStats

var interfaceExistsFn = netlink.InterfaceExists

// clearPeersFn drops all peers from the kernel's WireGuard interface, used by
// prepareForSleep to invalidate the handshake state before the system
// suspends. Exposed as a var so tests can stub it.
var clearPeersFn = netlink.ClearPeers

// verifyPublicIPFn fetches the current public IPv4 via HTTPS. Exposed as a var
// so the lightHealthTick StateFailed-recovery shortcut can mock it during
// tests. The shortcut uses this to confirm traffic actually flows through the
// VPN (public IP differs from captured ISP baseline) before broadcasting
// EventReconnected — addresses issue #7's post-sleep half where a stale-but-
// recent kernel handshake would otherwise pass the IsConnected check and
// fake-report a working connection.
var verifyPublicIPFn = func() (string, error) {
	return util.GetPublicIPv4WithRetry(1)
}

// lightHealthTick runs every lightTickInterval.
// Reads wgctrl device info + netlink stats, updates tracker, computes/broadcasts health.
func (d *ConnectionDaemon) lightHealthTick() {
	d.stateMu.RLock()
	state := d.state
	server := d.currentServer
	d.stateMu.RUnlock()

	// When in Failed state, check if the interface came back up.
	// IsConnected alone can't be trusted: after a sleep/wake, the kernel may
	// still carry a stale-but-<3min LastHandshakeTime on wg0's peer, which
	// would make IsConnected return true for a tunnel that's actually dead —
	// causing a silent-leak "fake reconnected" event (issue #7). So we also
	// confirm public traffic is really going out through the VPN by checking
	// the current public IP is not the captured ISP baseline.
	if state == StateFailed {
		isConn := false
		if d.connector != nil {
			isConn = d.connector.IsConnected(d.cfg.ConnectionName)
		} else {
			isConn = wireguard.IsConnected(d.cfg.ConnectionName)
		}
		if !isConn {
			return
		}
		// Real verify before claiming reconnected.
		currentIP, verifyErr := verifyPublicIPFn()
		if verifyErr != nil {
			d.log.Log(logger.Autorecover, "Failed-state shortcut: public IP lookup failed (%v) — staying FAILED", verifyErr)
			return
		}
		if d.cfg.BaselineIP != "" && currentIP == d.cfg.BaselineIP {
			d.log.Log(logger.Autorecover, "Failed-state shortcut: public IP %s == ISP baseline — tunnel not routing, staying FAILED", currentIP)
			return
		}
		d.log.Log(logger.Autorecover, "Interface detected as up while in FAILED state (verified IP: %s) - resuming monitoring", currentIP)
		d.stateMu.Lock()
		d.consecutiveBadTicks = 0
		d.retryCount = 0
		d.health.reset()
		d.publicIP = currentIP
		d.stateMu.Unlock()
		d.setState(StateConnected)
		d.broadcastEvent(Event{
			Type:      EventReconnected,
			Timestamp: time.Now(),
			Server:    server,
			PublicIP:  currentIP,
			Message:   "Connection restored (manual reconnect detected)",
		})
		return
	}

	// Only check health when connected
	if state != StateConnected && state != StateUnhealthy {
		return
	}

	connName := d.cfg.ConnectionName

	// If the interface is gone, immediately trigger recovery
	if !interfaceExistsFn(connName) {
		d.log.Log(logger.Autorecover, "Interface %s disappeared", connName)
		d.stateMu.Lock()
		d.consecutiveBadTicks = d.badTicksForRecovery
		server := d.currentServer
		prov := d.currentProvider
		isDyn := d.isDynamic
		d.stateMu.Unlock()
		d.setState(StateUnhealthy)
		notify.ConnectionLost()
		d.attemptRecovery(server, prov, isDyn)
		return
	}

	// Read wgctrl device info
	device, err := getDeviceInfoFn(connName)
	if err == nil && len(device.Peers) > 0 {
		peer := device.Peers[0]
		d.stateMu.Lock()
		d.health.recordHandshake(peer.LastHandshakeTime)
		if peer.Endpoint != nil {
			d.health.recordEndpoint(peer.Endpoint.String())
		}
		d.stateMu.Unlock()
	}

	// Read netlink stats
	stats, err := getInterfaceStatsFn(connName)
	if err == nil && stats != nil {
		d.stateMu.Lock()
		d.health.recordStats(stats.RxBytes, stats.TxBytes, stats.RxPackets, stats.TxPackets, stats.Timestamp)
		d.stateMu.Unlock()
	}

	// Compute and broadcast health state
	d.stateMu.RLock()
	hs := d.health.computeScore()
	d.stateMu.RUnlock()

	d.broadcastEvent(Event{
		Type:      EventHealthState,
		Timestamp: time.Now(),
		Health:    &hs,
	})

	// Check score-based recovery
	d.checkScoreBasedRecovery(hs)
}

// heavyHealthTick runs every heavyTickInterval.
// Performs TCP ping (with RTT measurement) + DNS probe.
func (d *ConnectionDaemon) heavyHealthTick() {
	d.stateMu.RLock()
	state := d.state
	d.stateMu.RUnlock()

	if state != StateConnected && state != StateUnhealthy {
		return
	}

	// TCP ping with latency measurement
	var pingOk bool
	var latencyMs int
	if d.healthChk != nil {
		pingOk, latencyMs = d.healthChk.PingCheck()
	} else {
		pingOk, latencyMs = d.timedPingEndpoint()
	}

	d.stateMu.Lock()
	d.health.recordPing(pingOk, latencyMs)
	d.stateMu.Unlock()

	// DNS probe
	var dnsOk bool
	if d.healthChk != nil {
		dnsOk = d.healthChk.DNSCheck()
	} else {
		dnsOk = d.dnsProbe()
	}

	d.stateMu.Lock()
	d.health.recordDNS(dnsOk)

	// Track consecutive heavy tick failures for fast dead-tunnel detection.
	// If both ping AND DNS fail twice in a row (~30s), the tunnel is dead.
	if !pingOk && !dnsOk {
		d.consecHeavyFails++
	} else {
		d.consecHeavyFails = 0
	}
	consecFails := d.consecHeavyFails
	server := d.currentServer
	prov := d.currentProvider
	isDyn := d.isDynamic
	d.stateMu.Unlock()

	if consecFails >= 2 {
		d.log.Log(logger.Autorecover, "Ping and DNS failed %d consecutive heavy ticks — tunnel dead", consecFails)
		d.stateMu.Lock()
		d.consecHeavyFails = 0
		d.stateMu.Unlock()
		d.setState(StateUnhealthy)
		notify.ConnectionLost()
		d.attemptRecovery(server, prov, isDyn)
	}
}

// checkScoreBasedRecovery replaces the old consecutive-ping-failure logic.
// If the composite score stays below the threshold for N consecutive light ticks,
// trigger recovery.
func (d *ConnectionDaemon) checkScoreBasedRecovery(hs HealthState) {
	d.stateMu.Lock()
	if hs.Score < d.reconnectScoreThreshold {
		d.consecutiveBadTicks++
	} else {
		wasUnhealthy := d.state == StateUnhealthy || d.consecutiveBadTicks > 0
		if wasUnhealthy {
			d.consecutiveBadTicks = 0
			d.state = StateConnected
		}
		d.stateMu.Unlock()
		if wasUnhealthy {
			d.broadcastEvent(Event{
				Type:      EventHealthy,
				Timestamp: time.Now(),
				Health:    &hs,
			})
		}
		return
	}
	badTicks := d.consecutiveBadTicks
	server := d.currentServer
	prov := d.currentProvider
	isDyn := d.isDynamic
	d.stateMu.Unlock()

	d.log.Log(logger.Autorecover, "Health score %d (threshold %d), bad ticks %d/%d",
		hs.Score, d.reconnectScoreThreshold, badTicks, d.badTicksForRecovery)

	d.broadcastEvent(Event{
		Type:        EventHealthFail,
		Timestamp:   time.Now(),
		HealthFails: badTicks,
		MaxFails:    d.badTicksForRecovery,
		Message:     fmt.Sprintf("Health degraded (%d/%d)", badTicks, d.badTicksForRecovery),
		Health:      &hs,
	})

	if badTicks >= d.badTicksForRecovery {
		d.setState(StateUnhealthy)
		notify.ConnectionLost()
		d.attemptRecovery(server, prov, isDyn)
	}
}

// timedPingEndpoint performs a TCP ping and returns success + latency in ms.
func (d *ConnectionDaemon) timedPingEndpoint() (bool, int) {
	connName := d.cfg.ConnectionName

	iface, err := interfaceByNameFn(connName)
	if err != nil {
		return false, 0
	}
	addrs, err := interfaceAddrsFn(iface)
	if err != nil || len(addrs) == 0 {
		return false, 0
	}

	var localAddr string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			localAddr = ipnet.IP.String()
			break
		}
	}
	if localAddr == "" {
		return false, 0
	}

	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(localAddr)},
		Timeout:   pingPerHostTimeout,
	}

	targets := d.cfg.PingTargets
	deadline := time.Now().Add(pingTotalDeadline)

	for _, target := range targets {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, 0
		}
		timeout := pingPerHostTimeout
		if remaining < timeout {
			timeout = remaining
		}
		dialer.Timeout = timeout

		start := time.Now()
		conn, err := dialFn(dialer, "tcp", target)
		if err == nil {
			latency := int(time.Since(start).Milliseconds())
			conn.Close()
			return true, latency
		}
	}
	return false, 0
}

// dnsProbe resolves the configured DNS probe host with a 3s timeout.
func (d *ConnectionDaemon) dnsProbe() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true}
	_, err := resolver.LookupHost(ctx, d.cfg.DNSProbeHost)
	return err == nil
}

// attemptRecovery tries to recover the connection
func (d *ConnectionDaemon) attemptRecovery(server, provider string, isDynamic bool) {
	if err := d.cfg.Reload(); err != nil {
		d.log.Log(logger.Autorecover, "Config reload failed (using cached): %v", err)
	}

	if !d.cfg.AutoRecover {
		d.log.Log(logger.Autorecover, "Auto-recover disabled, marking as failed")
		d.setState(StateFailed)
		d.broadcastEvent(Event{
			Type:      EventFailed,
			Timestamp: time.Now(),
			Message:   "Connection lost, auto-recover disabled",
		})
		notify.ReconnectFailed()
		if firewall.IsActive() {
			notify.KillswitchBlocking("VPN connection lost — auto-recover disabled")
		}
		return
	}

	d.setState(StateRetrying)
	d.stateMu.Lock()
	d.retryCount++
	d.consecutiveBadTicks = 0 // reset bad ticks on recovery attempt
	retries := d.retryCount
	d.stateMu.Unlock()

	d.log.Log(logger.Autorecover, "Reconnect attempt %d/%d", retries, d.maxRetries)
	d.broadcastEvent(Event{
		Type:       EventRetrying,
		Timestamp:  time.Now(),
		RetryCount: retries,
		MaxRetries: d.maxRetries,
		Message:    fmt.Sprintf("Reconnecting (%d/%d)...", retries, d.maxRetries),
	})

	// Attempt reconnect
	var err error
	if d.connector != nil {
		err = d.connector.Connect(d.cfg, server, provider, isDynamic, func(s wireguard.ConnectionStatus) {})
	} else if isDynamic {
		err = wireguard.ConnectDynamic(d.cfg, provider, server, func(s wireguard.ConnectionStatus) {})
	} else {
		wgDir := filepath.Join(d.cfg.ConfigDir, "wireguard")
		wgCfg, loadErr := wireguard.LoadConfig(wgDir, server)
		if loadErr != nil {
			err = loadErr
		} else {
			serverObj := wireguard.NewServer(wgCfg)
			err = wireguard.Connect(d.cfg, serverObj, func(s wireguard.ConnectionStatus) {})
		}
	}

	if err == nil {
		d.log.Log(logger.Autorecover, "Reconnect successful")
		d.stateMu.Lock()
		d.consecutiveBadTicks = 0
		d.retryCount = 0
		d.health.reset()
		d.publicIP = d.cfg.LastPublicIP
		reconnectIP := d.publicIP
		d.stateMu.Unlock()
		d.setState(StateConnected)
		d.broadcastEvent(Event{
			Type:      EventReconnected,
			Timestamp: time.Now(),
			Server:    server,
			PublicIP:  reconnectIP,
			Message:   "Reconnected",
		})
		notify.Reconnected()
		return
	}

	d.log.Log(logger.Autorecover, "Reconnect attempt %d failed: %v", retries, err)

	if retries >= d.maxRetries {
		// Exhausted retries
		if d.cfg.AutoFailover {
			d.attemptFailover()
		} else {
			d.setState(StateFailed)
			d.broadcastEvent(Event{
				Type:      EventFailed,
				Timestamp: time.Now(),
				Message:   "Reconnect failed, failover disabled",
			})
			notify.ReconnectFailed()
			if firewall.IsActive() {
				notify.KillswitchBlocking("VPN reconnection failed")
			}
		}
	} else {
		// Return to Unhealthy so health ticks resume and can re-trigger
		// recovery after badTicksForRecovery consecutive bad ticks
		d.setState(StateUnhealthy)
	}
}

// failoverCandidate represents a server available for failover
type failoverCandidate struct {
	name       string
	providerID string
	isDynamic  bool
}

// isSameServer reports whether the given failover candidate refers to
// the same server identity as the (curSrv, curProv, curDyn) tuple.
// Manual configs are identified by name + isDynamic=false; dynamic
// servers by (name, providerID, isDynamic=true). Comparing on name
// alone over-skips: the same name can exist across both manual configs
// and dynamic providers, or across two different dynamic providers.
func isSameServer(c failoverCandidate, curSrv, curProv string, curDyn bool) bool {
	if c.isDynamic != curDyn {
		return false
	}
	if c.name != curSrv {
		return false
	}
	if curDyn && c.providerID != curProv {
		return false
	}
	return true
}

// shuffleCandidates does a Fisher-Yates shuffle using crypto/rand for
// the index source. If the OS RNG is unavailable for any swap, that
// swap is skipped — failover should still proceed (we only lose some
// randomness on the affected element). Same threat model as the
// crypto-random server pickers in latency / serverbrowser.
func shuffleCandidates(s []failoverCandidate) {
	for i := len(s) - 1; i > 0; i-- {
		n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			continue
		}
		j := int(n.Int64())
		s[i], s[j] = s[j], s[i]
	}
}

// attemptFailover tries to connect to a different server
// Includes both manual WireGuard configs and dynamic provider servers
func (d *ConnectionDaemon) attemptFailover() {
	d.setState(StateFailover)
	d.log.Log(logger.Autorecover, "Attempting failover")
	d.broadcastEvent(Event{
		Type:      EventRetrying,
		Timestamp: time.Now(),
		Message:   "Attempting failover to different server...",
	})
	notify.Failover()

	// Build pool of failover candidates from all sources
	var candidates []failoverCandidate

	// Source 1: Manual WireGuard configs
	wgDir := filepath.Join(d.cfg.ConfigDir, "wireguard")
	configs, err := wireguard.ListConfigs(wgDir)
	if err == nil {
		for _, cfg := range configs {
			if cfg.ParseError != "" {
				continue
			}
			candidates = append(candidates, failoverCandidate{
				name:      cfg.Name,
				isDynamic: false,
			})
		}
	}

	// Source 2: Dynamic provider servers
	providers, _ := config.ListProviders(d.cfg.ConfigDir)
	cacheDir := filepath.Join(d.cfg.ConfigDir, "cache")
	for _, prov := range providers {
		servers, err := provider.LoadProviderServers(cacheDir, prov)
		if err != nil {
			continue
		}
		for _, srv := range servers {
			candidates = append(candidates, failoverCandidate{
				name:       srv.Name(),
				providerID: prov,
				isDynamic:  true,
			})
		}
	}

	if len(candidates) == 0 {
		d.log.Log(logger.Autorecover, "No servers available for failover")
		d.setState(StateFailed)
		d.broadcastEvent(Event{
			Type:      EventFailed,
			Timestamp: time.Now(),
			Message:   "No servers available for failover",
		})
		notify.ReconnectFailed()
		if firewall.IsActive() {
			notify.KillswitchBlocking("VPN failover failed — no servers available")
		}
		return
	}

	// Partition candidates into priority tiers:
	//   Tier 1: Favorited servers (in cfg.Favorites) — tried first
	//   Tier 2: Manual WireGuard configs (not favorited)
	//   Tier 3: Dynamic provider servers (not favorited)
	favSet := make(map[string]struct{}, len(d.cfg.Favorites))
	for _, f := range d.cfg.Favorites {
		favSet[f] = struct{}{}
	}

	var favCandidates, manualCandidates, dynamicCandidates []failoverCandidate
	for _, c := range candidates {
		// Build the favorites key matching the format used by the server browser
		favKey := c.name
		if c.isDynamic {
			favKey = "dynamic:" + c.providerID + ":" + c.name
		}
		if _, ok := favSet[favKey]; ok {
			favCandidates = append(favCandidates, c)
		} else if !c.isDynamic {
			manualCandidates = append(manualCandidates, c)
		} else {
			dynamicCandidates = append(dynamicCandidates, c)
		}
	}

	// Shuffle within each tier for randomness. Uses crypto/rand because
	// failover server selection is a privacy decision — same rationale
	// as latency.GetRandomServer / serverbrowser's Random key.
	// math/rand's seeded PRNG can be replayed by an observer who sees
	// a few prior selections; crypto/rand can't. Cost is one getrandom
	// syscall per swap, which is fine for the small candidate lists
	// failover deals with.
	shuffleCandidates(favCandidates)
	shuffleCandidates(manualCandidates)
	shuffleCandidates(dynamicCandidates)

	// Concatenate: favorites first, then manual, then dynamic
	candidates = append(favCandidates, manualCandidates...)
	candidates = append(candidates, dynamicCandidates...)

	// Capture full current-server identity under lock — comparing only by
	// name is incomplete when manual configs and dynamic providers share
	// names ("US-NY#42" can exist as both a Proton manual config and a
	// Mullvad dynamic entry, for example) or when multiple providers
	// have similarly-named servers. Pre-fix the failover loop would
	// silently skip valid same-name-but-different-server candidates.
	d.stateMu.RLock()
	curSrv := d.currentServer
	curProv := d.currentProvider
	curDyn := d.isDynamic
	d.stateMu.RUnlock()

	// Try each server (except the one we're currently on)
	for _, candidate := range candidates {
		if isSameServer(candidate, curSrv, curProv, curDyn) {
			continue
		}

		d.log.Log(logger.Autorecover, "Trying failover to %s (dynamic=%v)", candidate.name, candidate.isDynamic)

		var connectErr error
		if d.connector != nil {
			connectErr = d.connector.Connect(d.cfg, candidate.name, candidate.providerID, candidate.isDynamic, func(s wireguard.ConnectionStatus) {})
		} else if candidate.isDynamic {
			connectErr = wireguard.ConnectDynamic(d.cfg, candidate.providerID, candidate.name, func(s wireguard.ConnectionStatus) {})
		} else {
			wgCfg, loadErr := wireguard.LoadConfig(wgDir, candidate.name)
			if loadErr != nil {
				d.log.Log(logger.Autorecover, "Failover to %s failed (load): %v", candidate.name, loadErr)
				continue
			}
			server := wireguard.NewServer(wgCfg)
			connectErr = wireguard.Connect(d.cfg, server, func(s wireguard.ConnectionStatus) {})
		}

		if connectErr == nil {
			d.log.Log(logger.Autorecover, "Failover successful to %s", candidate.name)
			d.stateMu.Lock()
			d.currentServer = candidate.name
			d.currentProvider = candidate.providerID
			d.isDynamic = candidate.isDynamic
			d.consecutiveBadTicks = 0
			d.retryCount = 0
			d.health.reset()
			d.publicIP = d.cfg.LastPublicIP
			failoverIP := d.publicIP
			d.stateMu.Unlock()
			d.setState(StateConnected)
			d.broadcastEvent(Event{
				Type:      EventReconnected,
				Timestamp: time.Now(),
				Server:    candidate.name,
				PublicIP:  failoverIP,
				Message:   "Failover successful",
			})
			notify.FailoverSuccess(candidate.name)
			return
		}

		d.log.Log(logger.Autorecover, "Failover to %s failed: %v", candidate.name, connectErr)
	}

	// All failover attempts failed
	d.setState(StateFailed)
	d.broadcastEvent(Event{
		Type:      EventFailed,
		Timestamp: time.Now(),
		Message:   "All failover attempts failed",
	})
	notify.ReconnectFailed()
	if firewall.IsActive() {
		notify.KillswitchBlocking("VPN failover failed — all servers exhausted")
	}
}

const (
	pingPerHostTimeout = 3 * time.Second
	pingTotalDeadline  = 5 * time.Second
	writeTimeout       = 5 * time.Second
	// orphanExitGrace is the maximum time the daemon waits after a failed
	// connect for a sustained-empty client-map window before declaring itself
	// orphaned. Bumped to 3s (from 2s) so there's always a 500ms+ gap between
	// Waybar polls (2s cadence) observable inside the window.
	orphanExitGrace = 3 * time.Second
	// orphanPollInterval is how often exitIfOrphaned samples the client map.
	orphanPollInterval = 100 * time.Millisecond
	// orphanEmptyRequired is the number of consecutive empty samples needed to
	// declare orphan. 5 samples at 100ms = 500ms of continuous emptiness.
	// Waybar's ~30ms connection window can never span 500ms of samples.
	orphanEmptyRequired = 5
)

// dialFn is the function used for TCP health checks via a bound dialer.
// It defaults to calling dialer.Dial but can be overridden in tests.
var dialFn = func(dialer *net.Dialer, network, address string) (net.Conn, error) {
	return dialer.Dial(network, address)
}

// interfaceByNameFn looks up a network interface by name.
// It defaults to net.InterfaceByName but can be overridden in tests.
var interfaceByNameFn = net.InterfaceByName

// interfaceAddrsFn returns the addresses for a network interface.
// It defaults to calling iface.Addrs() but can be overridden in tests.
var interfaceAddrsFn = func(iface *net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

// connectSystemBusFunc is the type of the system-bus dialer.
type connectSystemBusFunc func() (*dbus.Conn, error)

// connectSystemBusV holds the current dialer behind atomic.Value so tests
// can swap it without racing concurrent reads from sleepWakeListener
// goroutines that earlier tests left running. The race detector flags a
// plain `var connectSystemBus = func ...` swap against a still-alive
// listener's read, even when the listener is about to exit (its read
// happened-before the new write but the goroutine hasn't joined yet).
// Tests call setConnectSystemBus(); listener calls getConnectSystemBus().
var connectSystemBusV atomic.Value

// dbusConnectTimeout bounds dbus.ConnectSystemBus. The library call
// does Dial + Auth + Hello synchronously with no built-in timeout —
// a wedged system bus daemon would freeze sleepWakeListener at
// startup, silently breaking the sleep/wake recovery path. Same
// rationale as cb38d82's wrapper in internal/wireguard and 0950f2a's
// in internal/notify.
const dbusConnectTimeout = 5 * time.Second

func init() {
	connectSystemBusV.Store(connectSystemBusFunc(func() (*dbus.Conn, error) {
		// Bound via goroutine + select-with-timeout. On timeout the
		// worker goroutine leaks (bounded per-call). The sleep/wake
		// listener calls this exactly once at daemon startup, so
		// the leak is at most one goroutine per daemon process —
		// acceptable.
		type result struct {
			conn *dbus.Conn
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			conn, err := dbus.ConnectSystemBus()
			ch <- result{conn: conn, err: err}
		}()
		select {
		case r := <-ch:
			return r.conn, r.err
		case <-time.After(dbusConnectTimeout):
			return nil, fmt.Errorf("dbus connect timed out after %s — system bus may be wedged", dbusConnectTimeout)
		}
	}))
}

func getConnectSystemBus() connectSystemBusFunc {
	return connectSystemBusV.Load().(connectSystemBusFunc)
}

func setConnectSystemBus(fn connectSystemBusFunc) {
	connectSystemBusV.Store(fn)
}

// sleepWakeNICTimeout is how long to poll for the NIC after wake.
const sleepWakeNICTimeout = 10

// prepareForSleep is invoked when systemd-logind signals PrepareForSleep=true.
// Flipping the daemon out of Connected before the system suspends is what
// prevents issue #7 ("Fake connection status when recovering from sleep"):
// without this, waybar/TUI keep showing CONNECTED across the sleep window, and
// on wake a stale-but-recent handshake can make lightHealthTick's recovery
// shortcut broadcast EventReconnected without re-verifying — a dangerous
// silent-leak state when killswitch is off. Clearing the recorded handshake
// also primes the recovery path to seek a fresh handshake instead of trusting
// the cached timestamp from before sleep.
func (d *ConnectionDaemon) prepareForSleep() {
	d.stateMu.Lock()
	state := d.state
	// Only act if the daemon currently considers itself connected — otherwise
	// the state transition would be noise (or worse, misleading UI churn for
	// a daemon that's idle / connecting / already failed).
	if state != StateConnected && state != StateUnhealthy {
		d.stateMu.Unlock()
		return
	}
	d.health.reset()
	d.stateMu.Unlock()

	// Snapshot ConnectionName under cfg.mu.RLock — we run on the
	// sleepWakeListener goroutine and the main goroutine may be running
	// cfg.Reload concurrently (attemptRecovery -> cfg.Reload). Direct
	// read would race the Reload's write (stateMu does NOT synchronize
	// with cfg.mu). Take the snapshot AFTER releasing stateMu so the
	// two locks aren't held simultaneously and lock-ordering hygiene
	// stays simple. Sibling fix to forceDisconnectIfInterfaceExists.
	connName := d.cfg.GetConnectionName()

	// Drop kernel-side peers so wgctrl reports an empty peer list on wake —
	// prevents wireguard.IsConnected() from returning true based on a
	// stale-but-<3min LastHandshakeTime that survived the suspend.
	if err := clearPeersFn(connName); err != nil {
		d.log.Log(logger.Connection, "prepareForSleep: clear peers failed: %v", err)
	}

	d.setState(StateUnhealthy)
	d.broadcastEvent(Event{
		Type:      EventHealthFail,
		Timestamp: time.Now(),
		Message:   "System suspending — VPN state unknown until wake",
	})
}

// sleepWakeListener monitors systemd-logind's PrepareForSleep signal.
// On wake (PrepareForSleep=false), it triggers VPN reconnection.
// If D-Bus is unavailable (container, no logind), it logs and returns gracefully.
func (d *ConnectionDaemon) sleepWakeListener() {
	conn, err := getConnectSystemBus()()
	if err != nil {
		d.log.Log(logger.Connection, "Sleep/wake listener: D-Bus system bus unavailable (%v), degrading gracefully", err)
		return
	}
	defer conn.Close()

	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath("/org/freedesktop/login1"),
		dbus.WithMatchInterface("org.freedesktop.login1.Manager"),
		dbus.WithMatchMember("PrepareForSleep"),
	); err != nil {
		d.log.Log(logger.Connection, "Sleep/wake listener: failed to add signal match (%v), degrading gracefully", err)
		return
	}

	sigCh := make(chan *dbus.Signal, 4)
	conn.Signal(sigCh)
	defer conn.RemoveSignal(sigCh)

	d.log.Log(logger.Connection, "Sleep/wake listener started")

	for {
		select {
		case <-d.stopCh:
			return
		case sig, ok := <-sigCh:
			if !ok {
				return
			}
			if sig.Name != "org.freedesktop.login1.Manager.PrepareForSleep" {
				continue
			}
			if len(sig.Body) < 1 {
				continue
			}
			sleeping, ok := sig.Body[0].(bool)
			if !ok {
				continue
			}

			if sleeping {
				d.log.Log(logger.Connection, "System going to sleep")
				d.prepareForSleep()
				continue
			}

			// Waking up
			d.log.Log(logger.Connection, "System woke from sleep")

			d.stateMu.RLock()
			state := d.state
			d.stateMu.RUnlock()

			switch state {
			case StateConnected, StateUnhealthy, StateFailed:
				// Worth attempting recovery
			default:
				d.log.Log(logger.Connection, "Sleep/wake: state is %s, no reconnect needed", state)
				continue
			}

			notify.Info("LazyVPN", "Woke from sleep, reconnecting...")

			// Wait for NIC to come back (DHCP, etc.)
			nicReady := false
			for i := 0; i < sleepWakeNICTimeout; i++ {
				if iface, _, err := firewall.GetPhysicalInterface(); err == nil && iface != "" {
					d.log.Log(logger.Connection, "Sleep/wake: NIC ready (%s) after %ds", iface, i+1)
					nicReady = true
					break
				}
				select {
				case <-d.stopCh:
					return
				case <-time.After(time.Second):
				}
			}
			if !nicReady {
				d.log.Log(logger.Connection, "Sleep/wake: NIC not ready after %ds, attempting reconnect anyway", sleepWakeNICTimeout)
			}

			// Tear down the stale VPN interface before reconnecting.
			// After sleep, wg0 exists but the handshake is dead. The
			// normal disconnect path fails because IP verification
			// can't reach the internet through the dead tunnel.
			d.forceDisconnectIfInterfaceExists("Sleep/wake")

			// Reset retry count and prime state for immediate recovery.
			// The next health tick will trigger attemptRecovery which
			// creates a fresh connection.
			d.stateMu.Lock()
			d.retryCount = 0
			d.consecutiveBadTicks = d.badTicksForRecovery
			d.stateMu.Unlock()
			d.setState(StateUnhealthy)
		}
	}
}

// forceDisconnectIfInterfaceExists runs ForceDisconnect via the
// injected connector (preferred — test-mockable) or directly via
// the wireguard package. Used by the sleep/wake wake-up handler to
// tear down the stale post-suspend tunnel. The other ForceDisconnect
// call sites (terminate handler, switch path) follow the same
// pattern; consolidating them through this helper keeps the test
// injection point consistent.
func (d *ConnectionDaemon) forceDisconnectIfInterfaceExists(reason string) {
	// Snapshot ConnectionName under cfg.mu.RLock — this function is
	// called from sleepWakeListener (its own goroutine), and the main
	// goroutine may be running cfg.Reload concurrently. Direct read
	// would race the Reload's write. The cfg pointer passed to
	// ForceDisconnect below still has unsynchronized internal reads
	// (cfg.ConfigDir, etc.); narrow scope here covers only the read
	// at THIS function's entry, which is the one the race detector
	// surfaced via TestForceDisconnectIfInterfaceExists_RaceWithReload.
	connName := d.cfg.GetConnectionName()
	if !interfaceExistsFn(connName) {
		return
	}
	d.log.Log(logger.Connection, "%s: tearing down stale interface %s", reason, connName)
	if d.connector != nil {
		d.connector.ForceDisconnect(d.cfg)
		return
	}
	wireguard.ForceDisconnect(d.cfg)
}

// setState updates the daemon state
func (d *ConnectionDaemon) setState(state DaemonState) {
	d.stateMu.Lock()
	d.state = state
	d.stateMu.Unlock()
}

// stop signals the daemon to stop (safe to call multiple times)
func (d *ConnectionDaemon) stop() {
	d.stopOnce.Do(func() {
		close(d.stopCh)
	})
}

// exitIfOrphaned stops the daemon if no long-lived TUI client is attached.
// Polls the client map every orphanPollInterval and tracks consecutive empty
// observations; if the map is continuously empty for at least orphanEmptyRequired
// polls within `grace`, the daemon is declared orphaned and stops.
//
// The consecutive-empty requirement exists because the Omarchy Waybar integration
// connects every ~2s via QuickStatus for ~30ms — a naive "any non-empty count
// means a TUI is attached" check gets fooled by those blips. Waybar can't sustain
// a connection across several consecutive polls; a real TUI can. Called after a
// failed connect attempt to prevent zombie daemons when no real TUI is watching.
func (d *ConnectionDaemon) exitIfOrphaned(grace time.Duration) {
	deadline := time.Now().Add(grace)
	consecutiveEmpty := 0
	for time.Now().Before(deadline) {
		d.clientMu.Lock()
		count := len(d.clients)
		d.clientMu.Unlock()

		if count == 0 {
			consecutiveEmpty++
			if consecutiveEmpty >= orphanEmptyRequired {
				d.log.Log(logger.Connection, "Failed connect with no attached clients — daemon exiting")
				d.stop()
				return
			}
		} else {
			consecutiveEmpty = 0
		}

		select {
		case <-d.stopCh:
			return
		case <-time.After(orphanPollInterval):
		}
	}
	// Grace window expired without hitting the sustained-empty threshold —
	// a long-lived client (real TUI) must be attached; stay alive.
}

// cleanup removes socket and PID files. Also closes any still-attached
// client connections so handleClient goroutines unblock from their
// ReadString and can exit via their defers — without this, goroutines
// stay blocked until the OS tears down the process FDs, which is not
// observable as a leak in process-exit time but blocks the goleak test
// in long-lived test runs.
func (d *ConnectionDaemon) cleanup() {
	if d.listener != nil {
		d.listener.Close()
	}
	d.clientMu.Lock()
	for conn := range d.clients {
		conn.Close()
	}
	d.clientMu.Unlock()
	os.Remove(SocketPath(d.cfg.ConfigDir))
	os.Remove(PidPath(d.cfg.ConfigDir))
	d.log.Log(logger.Connection, "Daemon cleanup complete")
}

// readPidFile reads a PID from the given file path. Returns 0 on any error.
func readPidFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}

// RunWithConnect starts daemon and immediately connects to specified server
func RunWithConnect(cfg *config.Config, server, provider string, isDynamic bool) error {
	d := NewConnectionDaemon(cfg)

	// Set initial command to be executed once main loop starts
	d.initialCmd = &Command{
		Type:      CmdConnect,
		Server:    server,
		Provider:  provider,
		IsDynamic: isDynamic,
	}

	return d.Run()
}

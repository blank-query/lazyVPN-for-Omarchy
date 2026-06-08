package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	socketDialTimeout     = 5 * time.Second
	socketSpawnIterations = 50                     // number of retries waiting for socket
	socketSpawnInterval   = 100 * time.Millisecond // delay between retries
	// daemonStopWaitIter × socketSpawnInterval = total grace for daemon exit.
	// The SIGTERM path runs ForceDisconnect (sudo resolvectl revert + 4×netlink
	// route delete + interface delete) AND firewall.Disable (ufw rule cleanup +
	// default policy reset). On a real system that chain takes 1–10s depending
	// on sudo/netlink latency. 5s caused false "did not exit" errors on a real
	// VM run; 15s gives realistic headroom.
	daemonStopWaitIter = 150
)

// spawnDaemonFn is the function used to spawn a daemon process.
// It defaults to the real implementation but can be overridden in tests.
var spawnDaemonFn = spawnDaemonReal

// signalProcessFn abstracts sending a signal to a process (for testing StopDaemon).
var signalProcessFn = func(pid int, sig os.Signal) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(sig)
}

// Client communicates with the connection daemon
type Client struct {
	configDir   string
	conn        net.Conn
	reader      *bufio.Reader
	mu          sync.Mutex
	dialTimeout time.Duration // 0 = default (socketDialTimeout)

	// Event callbacks (protected by eventMu)
	onEvent func(Event)
	eventMu sync.RWMutex
}

// SetDialTimeout overrides the default 5s socket dial timeout for the
// next Connect call. Use a tighter timeout in best-effort callers
// (waybar, status CLI) so a wedged daemon does not stall the caller.
func (c *Client) SetDialTimeout(d time.Duration) {
	c.dialTimeout = d
}

// NewClient creates a new daemon client
func NewClient(configDir string) *Client {
	return &Client{
		configDir: configDir,
	}
}

// Connect connects to the daemon socket
func (c *Client) Connect() error {
	socketPath := SocketPath(c.configDir)
	timeout := c.dialTimeout
	if timeout == 0 {
		timeout = socketDialTimeout
	}
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return fmt.Errorf("daemon not running: %w", err)
	}

	c.conn = conn
	c.reader = bufio.NewReader(conn)
	return nil
}

// Close closes the connection to the daemon
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// IsConnected returns true if connected to daemon
func (c *Client) IsConnected() bool {
	return c.conn != nil
}

// SetEventHandler sets the callback for receiving events
func (c *Client) SetEventHandler(handler func(Event)) {
	c.eventMu.Lock()
	c.onEvent = handler
	c.eventMu.Unlock()
}

// defaultReadTimeout is the default deadline for reading a single event.
const defaultReadTimeout = 30 * time.Second

// connectFlowReadTimeout is the per-event deadline used during the initial
// SpawnAndWaitForConnect handshake. It must be longer than the longest silent
// gap the daemon can produce while verifying a new connection (WG handshake
// wait + public-IP probe retries can exceed 30s when the upstream is slow).
// Exposed as a var so tests can shorten it.
var connectFlowReadTimeout = 120 * time.Second

// ReadEvent reads a single event from the daemon.
// Applies a default 30-second read timeout to prevent indefinite blocking.
func (c *Client) ReadEvent() (*Event, error) {
	return c.ReadEventWithTimeout(defaultReadTimeout)
}

// ReadEventWithTimeout reads a single event with a custom timeout.
// A zero timeout means no deadline.
func (c *Client) ReadEventWithTimeout(timeout time.Duration) (*Event, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	if timeout > 0 {
		c.conn.SetReadDeadline(time.Now().Add(timeout))
		defer c.conn.SetReadDeadline(time.Time{}) // clear deadline after read
	}

	line, err := c.reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	var event Event
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return nil, fmt.Errorf("invalid event: %w", err)
	}

	return &event, nil
}

// Listen listens for events and calls the event handler
// This blocks until the connection is closed
func (c *Client) Listen() error {
	for {
		event, err := c.ReadEvent()
		if err != nil {
			return err
		}

		c.eventMu.RLock()
		handler := c.onEvent
		c.eventMu.RUnlock()

		if handler != nil {
			handler(*event)
		}
	}
}

// SendCommand sends a command to the daemon.
//
// Sets a 5s write deadline so a wedged daemon-side read (kernel send
// buffer full, daemon paused but socket alive) can't freeze the TUI
// caller indefinitely. The daemon side already deadlines its
// broadcasts via SetWriteDeadline in sendToClient/broadcastEvent;
// the client side should mirror to avoid asymmetric hang potential.
func (c *Client) SendCommand(cmd Command) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	data, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	defer c.conn.SetWriteDeadline(time.Time{}) // clear deadline after write
	_, err = c.conn.Write(append(data, '\n'))
	return err
}

// RequestStatus requests current status from daemon
func (c *Client) RequestStatus() error {
	return c.SendCommand(Command{Type: CmdStatus})
}

// RequestConnect asks daemon to connect to a server
func (c *Client) RequestConnect(server, provider string, isDynamic bool) error {
	return c.SendCommand(Command{
		Type:      CmdConnect,
		Server:    server,
		Provider:  provider,
		IsDynamic: isDynamic,
	})
}

// RequestDisconnect asks daemon to disconnect
func (c *Client) RequestDisconnect() error {
	return c.SendCommand(Command{Type: CmdDisconnect})
}

// RequestSwitch asks daemon to switch to a different server
func (c *Client) RequestSwitch(server, provider string, isDynamic bool) error {
	return c.SendCommand(Command{
		Type:      CmdSwitch,
		Server:    server,
		Provider:  provider,
		IsDynamic: isDynamic,
	})
}

// IsDaemonRunning checks if the daemon is running. Beyond a bare "PID
// exists and receives signals", it also verifies the PID actually points
// to our binary via /proc/<pid>/exe — otherwise a recycled PID would be
// reported as a live daemon, blocking fresh spawns or causing the
// uninstaller to SIGTERM an unrelated process.
func IsDaemonRunning(configDir string) bool {
	pidPath := PidPath(configDir)
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return false
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return false
	}

	return IsLazyvpnPid(pid)
}

// IsLazyvpnPid returns true iff the given PID points to our binary.
// Exported so the uninstaller can verify identity before SIGTERM.
// Replaceable in tests (see isLazyvpnPidDefault for the real logic).
var IsLazyvpnPid = isLazyvpnPidDefault

// isLazyvpnPidDefault checks /proc/<pid>/exe against /proc/self/exe to
// tell a live daemon apart from a recycled PID that now belongs to some
// other process.
//
// If we can't determine our own exe path (rare — os.Executable errors),
// we fall back to a bare signal-0 liveness check to avoid breaking on
// systems where /proc isn't available or readable. The false-positive
// risk there is the same as the pre-fix behavior, which is acceptable
// as a degraded mode.
func isLazyvpnPidDefault(pid int) bool {
	ourExe, err := os.Executable()
	if err != nil {
		// Fall back to bare liveness check (pre-fix behavior).
		process, findErr := os.FindProcess(pid)
		if findErr != nil {
			return false
		}
		return process.Signal(syscall.Signal(0)) == nil
	}
	// /proc/<pid>/exe is a symlink to the binary's realpath.
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		// Either the PID is dead (ENOENT) or we lack permission
		// (EACCES on processes owned by other users). Either way,
		// not our daemon.
		return false
	}
	// Compare realpath-to-realpath to avoid symlink mismatches (e.g.
	// ourExe may be ~/.local/bin/lazyvpn while /proc exe resolves to
	// that same file via a different symlink chain).
	ourRealpath, err := os.Readlink("/proc/self/exe")
	if err != nil {
		// /proc/self/exe should always be readable for the current
		// process, but if not, compare against ourExe directly.
		ourRealpath = ourExe
	}
	return sameExePath(target, ourRealpath)
}

// sameExePath compares two /proc/*/exe readlink results, accounting
// for the kernel's "<path> (deleted)" suffix that appears after the
// binary has been unlinked-but-mapped (which is what `lazyvpn update`
// does via atomic rename). Without stripping the suffix, every CLI
// invocation after an update would conclude the running daemon isn't
// ours and try to spawn a duplicate (which then fails on the EXCL pid
// file lock and surfaces as a confusing error).
func sameExePath(a, b string) bool {
	return strings.TrimSuffix(a, " (deleted)") == strings.TrimSuffix(b, " (deleted)")
}

// SpawnDaemon starts the daemon process
func SpawnDaemon(execPath string, args ...string) error {
	return spawnDaemonFn(execPath, args...)
}

// spawnDaemonReal is the real implementation of SpawnDaemon.
//
// The daemon runs in its own session (Setsid:true) so signals to the
// TUI's process group don't kill it. We explicitly Wait() on it from a
// background goroutine — Release() alone leaves the daemon as a zombie
// in the TUI's process table when it exits, because the OS keeps the
// parent-child relationship even though Go has dropped its handle. A
// double-fork would reparent to init, but a single reaper goroutine is
// simpler and equally correct: as long as the TUI is alive it cleans
// up; if the TUI exits first init takes over reaping anyway.
func spawnDaemonReal(execPath string, args ...string) error {
	cmd := exec.Command(execPath, args...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_ = cmd.Wait()
	}()
	return nil
}

// SpawnAndConnect spawns the daemon and connects to it
func SpawnAndConnect(configDir string, execPath string, args ...string) (*Client, error) {
	// Spawn daemon
	if err := SpawnDaemon(execPath, args...); err != nil {
		return nil, fmt.Errorf("failed to spawn daemon: %w", err)
	}

	// Wait for socket to be ready
	socketPath := SocketPath(configDir)
	var client *Client

	for i := 0; i < socketSpawnIterations; i++ {
		time.Sleep(socketSpawnInterval)

		if _, err := os.Stat(socketPath); err == nil {
			client = NewClient(configDir)
			if err := client.Connect(); err == nil {
				return client, nil
			}
		}
	}

	return nil, fmt.Errorf("daemon failed to start (socket not ready)")
}

// StopDaemon stops the running daemon. Treats `lazyvpn daemon stop` as an
// explicit user disconnect: first sends CmdDisconnect via the IPC socket so
// the disconnect goes through the user-disconnect path (which clears
// LastConnectedServer — autoconnect-last-used should NOT silently
// reconnect after the user explicitly stopped). Only after that — or if the
// IPC dial fails — does it fall back to SIGTERM, which goes through the
// shutdown path (preserves LastConnectedServer for system-reboot autoconnect).
func StopDaemon(configDir string) error {
	pidPath := PidPath(configDir)
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return fmt.Errorf("daemon not running")
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("invalid PID file")
	}

	// Try the clean disconnect-then-stop path first. If anything in the IPC
	// path fails (socket gone, daemon unresponsive), fall through to the
	// SIGTERM path so we still kill the daemon.
	if client := NewClient(configDir); client.Connect() == nil {
		// Best-effort: send disconnect, briefly drain events to let the
		// disconnect flow run (which clears LastConnectedServer in
		// DisconnectWithCallback's defer). The disconnect can take a few
		// seconds (resolvectl + netlink + IP verify); don't block forever.
		_ = client.RequestDisconnect()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			ev, err := client.ReadEventWithTimeout(time.Until(deadline))
			if err != nil {
				break
			}
			if ev.Type == EventDisconnected {
				break
			}
		}
		client.Close()
	}

	if err := signalProcessFn(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to stop daemon: %w", err)
	}

	// Wait for process to exit
	exited := false
	for i := 0; i < daemonStopWaitIter; i++ {
		time.Sleep(socketSpawnInterval)
		if signalProcessFn(pid, syscall.Signal(0)) != nil {
			exited = true
			break // Process exited
		}
	}

	// Only clean up files if the process actually exited
	if exited {
		os.Remove(pidPath)
		os.Remove(SocketPath(configDir))
	} else {
		return fmt.Errorf("daemon did not exit after SIGTERM (PID %d)", pid)
	}

	return nil
}

// QuickStatus gets status without maintaining a connection
// Returns nil if daemon is not running
func QuickStatus(configDir string) (*Event, error) {
	client := NewClient(configDir)
	if err := client.Connect(); err != nil {
		return nil, err
	}
	defer client.Close()

	// First event is always EventStatus (sendStatus runs immediately on
	// client connect). In StateFailed/StateSwitchFailed the daemon sends
	// a follow-up EventFailed/EventSwitchFailed; QuickStatus only reads
	// the first one and discards the replay — fine for waybar polling
	// where only the snapshot matters.
	event, err := client.ReadEvent()
	if err != nil {
		return nil, err
	}

	return event, nil
}

// ConnectCallback is called with connection events during spawn
type ConnectCallback func(event Event)

// SpawnAndWaitForConnect spawns the daemon, connects, and monitors until connected or failed
// Returns the client if successful (still connected for ongoing monitoring)
func SpawnAndWaitForConnect(configDir, execPath, server, provider string, isDynamic bool, callback ConnectCallback) (*Client, error) {
	// Reject malformed args before spawning a daemon process. A dynamic
	// connect with no provider would otherwise spawn the daemon, fail
	// deep in configLoadProvider's empty-name check, and surface as an
	// opaque error several layers down. The IPC Command.Validate also
	// rejects this, but initialCmd doesn't go through Validate — guard
	// at the spawn point so the error path is symmetric for both
	// dispatch routes.
	if isDynamic && provider == "" {
		return nil, fmt.Errorf("provider required for dynamic server connect")
	}
	if server == "" {
		return nil, fmt.Errorf("server name required")
	}

	// Build daemon args
	args := []string{"daemon", "run", server}
	if provider != "" {
		args = append(args, "--provider", provider)
	}
	if isDynamic {
		args = append(args, "--dynamic")
	}

	// Spawn daemon and connect
	client, err := SpawnAndConnect(configDir, execPath, args...)
	if err != nil {
		return nil, err
	}

	// Monitor events until connected or failed. Use the longer connect-flow
	// timeout here — verify/handshake phases can stay silent well past 30s.
	for {
		event, err := client.ReadEventWithTimeout(connectFlowReadTimeout)
		if err != nil {
			client.Close()
			return nil, fmt.Errorf("lost connection to daemon: %w", err)
		}

		// Send to callback
		if callback != nil {
			callback(*event)
		}

		// Check terminal states
		switch event.Type {
		case EventConnected:
			// Connection successful - return client for ongoing monitoring
			return client, nil
		case EventStatus:
			// The initial sendStatus on attach delivers EventStatus,
			// not EventConnected. If the daemon's connect succeeded
			// BEFORE we attached (rare but possible — fast manual
			// connects, or anything that skips the typical multi-
			// second handshake) we'd otherwise wait connectFlowReadTimeout
			// (~120s) for an EventConnected that already fired into an
			// empty client map. EventFailed has lastFailureMessage
			// replay; success doesn't, so we recognize StateConnected
			// in the status snapshot as a terminal "connected" signal.
			if event.DaemonState == StateConnected {
				return client, nil
			}
		case EventFailed, EventError:
			// Connection failed
			client.Close()
			if event.Error != "" {
				return nil, fmt.Errorf("%s", event.Error)
			}
			return nil, fmt.Errorf("connection failed")
		case EventDisconnected:
			// Daemon exited
			client.Close()
			return nil, fmt.Errorf("daemon exited unexpectedly")
		}
	}
}

// WaitForDisconnect sends disconnect and waits for confirmation
func WaitForDisconnect(configDir string, callback ConnectCallback) error {
	client := NewClient(configDir)
	if err := client.Connect(); err != nil {
		return err
	}
	defer client.Close()

	// Send disconnect command
	if err := client.RequestDisconnect(); err != nil {
		return err
	}

	// Wait for disconnected event
	for {
		event, err := client.ReadEvent()
		if err != nil {
			// Connection closed means daemon exited (which is expected)
			return nil
		}

		if callback != nil {
			callback(*event)
		}

		if event.Type == EventDisconnected {
			return nil
		}
	}
}

package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
)

// startTestServer starts a daemon socket server using the real handleClient logic.
// Returns the daemon, socket path, and a cleanup function.
func startTestServer(t *testing.T) (*ConnectionDaemon, string) {
	t.Helper()
	cfg := testConfig(t)
	d := NewConnectionDaemon(cfg)

	socketPath := filepath.Join(cfg.ConfigDir, "test.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	d.listener = listener

	// Accept clients in background
	go d.acceptClients()

	t.Cleanup(func() {
		d.stop()
		listener.Close()
		os.Remove(socketPath)
	})

	return d, socketPath
}

// connectTestClient dials the test socket and returns a client connection.
func connectTestClient(t *testing.T, socketPath string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, bufio.NewReader(conn)
}

// readEvent reads a single JSON event from the connection.
func readEvent(t *testing.T, reader *bufio.Reader) Event {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("readEvent: %v", err)
	}
	var event Event
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		t.Fatalf("unmarshal event: %v (line=%q)", err, line)
	}
	return event
}

// sendCommand writes a JSON command to the connection.
func sendCommand(t *testing.T, conn net.Conn, cmd Command) {
	t.Helper()
	data, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("marshal cmd: %v", err)
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		t.Fatalf("write cmd: %v", err)
	}
}

func TestIntegrationStatusOnConnect(t *testing.T) {
	_, socketPath := startTestServer(t)
	_, reader := connectTestClient(t, socketPath)

	// First event should be a STATUS event (sent immediately on connect)
	event := readEvent(t, reader)
	if event.Type != EventStatus {
		t.Errorf("first event type = %q, want %q", event.Type, EventStatus)
	}
}

func TestIntegrationStatusCommand(t *testing.T) {
	d, socketPath := startTestServer(t)
	conn, reader := connectTestClient(t, socketPath)

	// Consume initial status
	readEvent(t, reader)

	// Set some state on the daemon
	d.stateMu.Lock()
	d.state = StateConnected
	d.currentServer = "US-NY#42"
	d.currentProvider = "protonvpn"
	d.publicIP = "1.2.3.4"
	d.stateMu.Unlock()

	// Request status
	sendCommand(t, conn, Command{Type: CmdStatus})

	event := readEvent(t, reader)
	if event.Type != EventStatus {
		t.Fatalf("expected STATUS, got %q", event.Type)
	}
	if event.Server != "US-NY#42" {
		t.Errorf("Server = %q, want US-NY#42", event.Server)
	}
	if event.Provider != "protonvpn" {
		t.Errorf("Provider = %q, want protonvpn", event.Provider)
	}
	if event.PublicIP != "1.2.3.4" {
		t.Errorf("PublicIP = %q, want 1.2.3.4", event.PublicIP)
	}
}

func TestIntegrationInvalidCommandValidation(t *testing.T) {
	_, socketPath := startTestServer(t)
	conn, reader := connectTestClient(t, socketPath)

	// Consume initial status
	readEvent(t, reader)

	// Send connect without server (should fail validation)
	sendCommand(t, conn, Command{Type: CmdConnect})

	event := readEvent(t, reader)
	if event.Type != EventError {
		t.Fatalf("expected ERROR for invalid command, got %q", event.Type)
	}
	if event.Error == "" {
		t.Error("error field should not be empty")
	}
}

func TestIntegrationUnknownCommandType(t *testing.T) {
	_, socketPath := startTestServer(t)
	conn, reader := connectTestClient(t, socketPath)

	// Consume initial status
	readEvent(t, reader)

	// Send unknown command type
	sendCommand(t, conn, Command{Type: "bogus"})

	event := readEvent(t, reader)
	if event.Type != EventError {
		t.Fatalf("expected ERROR for unknown command, got %q", event.Type)
	}
}

func TestIntegrationMalformedJSON(t *testing.T) {
	_, socketPath := startTestServer(t)
	conn, reader := connectTestClient(t, socketPath)

	// Consume initial status
	readEvent(t, reader)

	// Send malformed JSON — the server should not crash, just ignore it
	conn.Write([]byte("this is not json\n"))

	// Send a valid status command after the malformed one to verify the connection still works
	sendCommand(t, conn, Command{Type: CmdStatus})

	event := readEvent(t, reader)
	if event.Type != EventStatus {
		t.Fatalf("expected STATUS after malformed JSON, got %q", event.Type)
	}
}

func TestIntegrationBroadcastToMultipleClients(t *testing.T) {
	d, socketPath := startTestServer(t)

	// Connect two clients
	conn1, reader1 := connectTestClient(t, socketPath)
	conn2, reader2 := connectTestClient(t, socketPath)
	_ = conn1
	_ = conn2

	// Consume initial status events
	readEvent(t, reader1)
	readEvent(t, reader2)

	// Broadcast an event
	d.broadcastEvent(Event{
		Type:      EventConnected,
		Timestamp: time.Now(),
		Server:    "SE#5",
		Message:   "Connected",
	})

	// Both clients should receive the event
	e1 := readEvent(t, reader1)
	e2 := readEvent(t, reader2)

	if e1.Type != EventConnected {
		t.Errorf("client1 event type = %q, want CONNECTED", e1.Type)
	}
	if e1.Server != "SE#5" {
		t.Errorf("client1 server = %q", e1.Server)
	}
	if e2.Type != EventConnected {
		t.Errorf("client2 event type = %q, want CONNECTED", e2.Type)
	}
	if e2.Server != "SE#5" {
		t.Errorf("client2 server = %q", e2.Server)
	}
}

func TestIntegrationConcurrentClients(t *testing.T) {
	_, socketPath := startTestServer(t)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
			if err != nil {
				t.Errorf("concurrent dial: %v", err)
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			// Should receive initial status
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Errorf("concurrent read: %v", err)
				return
			}
			var event Event
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Errorf("concurrent unmarshal: %v", err)
				return
			}
			if event.Type != EventStatus {
				t.Errorf("concurrent client: first event = %q, want STATUS", event.Type)
			}
		}()
	}
	wg.Wait()
}

func TestIntegrationClientDisconnectCleanup(t *testing.T) {
	d, socketPath := startTestServer(t)

	conn, reader := connectTestClient(t, socketPath)
	readEvent(t, reader) // consume initial status

	// Verify client is registered
	time.Sleep(50 * time.Millisecond) // let handleClient finish registering
	d.clientMu.Lock()
	initialCount := len(d.clients)
	d.clientMu.Unlock()
	if initialCount != 1 {
		t.Errorf("expected 1 client, got %d", initialCount)
	}

	// Close the client connection
	conn.Close()

	// Give the server goroutine time to detect the close
	time.Sleep(100 * time.Millisecond)

	// After broadcasting, dead clients should be cleaned up
	d.broadcastEvent(Event{Type: EventHealthy, Timestamp: time.Now()})
	time.Sleep(50 * time.Millisecond)

	d.clientMu.Lock()
	finalCount := len(d.clients)
	d.clientMu.Unlock()

	if finalCount != 0 {
		t.Errorf("expected 0 clients after disconnect, got %d", finalCount)
	}
}

// TestSendToClientCleansDeadClient verifies that sendToClient removes a client
// from d.clients after a write error, mirroring broadcastEvent behavior.
// Bug: before fix, sendToClient logged but did NOT Close/delete dead clients,
// causing infinite broken-pipe retry loops (see memory/bug_daemon_tui_socket.md).
//
// Uses a socketpair inserted directly into d.clients (bypassing handleClient's
// own cleanup path) so only sendToClient's behavior is under test.
func TestSendToClientCleansDeadClient(t *testing.T) {
	cfg := testConfig(t)
	d := NewConnectionDaemon(cfg)

	server, client := net.Pipe()
	mu := &sync.Mutex{}
	d.clientMu.Lock()
	d.clients[server] = mu
	d.clientMu.Unlock()

	// Close the peer so any write to `server` returns an error.
	client.Close()

	// Also close the server side so net.Pipe's Write returns ErrClosedPipe
	// immediately instead of blocking (net.Pipe has no buffer).
	server.Close()

	d.sendToClient(server, Event{Type: EventHealthy, Timestamp: time.Now()})

	d.clientMu.Lock()
	remaining := len(d.clients)
	d.clientMu.Unlock()
	if remaining != 0 {
		t.Errorf("dead client not cleaned up by sendToClient: %d clients remain", remaining)
	}
}

// TestPrepareForSleepClearsConnectedState is a regression guard for issue #7:
// "Fake connection status when recovering from sleep/hibernation". Before this
// fix, `sleepWakeListener`'s PrepareForSleep=true path just logged and left
// daemon state untouched — waybar/TUI kept showing CONNECTED across sleep,
// then on wake the recovery path could fire EventReconnected off a stale
// handshake without re-verifying, leaving the user think they were connected
// while traffic actually leaked outside the tunnel.
//
// The fix: on PrepareForSleep=true, immediately drop to StateUnhealthy, clear
// the recorded handshake, and broadcast so UI updates before sleep.
func TestPrepareForSleepClearsConnectedState(t *testing.T) {
	d, _, _ := testDaemon(t)
	d.stateMu.Lock()
	d.state = StateConnected
	d.currentServer = "US-NY#42"
	d.health.recordHandshake(time.Now().Add(-30 * time.Second))
	d.stateMu.Unlock()

	d.prepareForSleep()

	d.stateMu.RLock()
	gotState := d.state
	gotHandshake := d.health.lastHandshake
	d.stateMu.RUnlock()

	if gotState != StateUnhealthy {
		t.Errorf("state after prepareForSleep = %s, want %s", gotState, StateUnhealthy)
	}
	if !gotHandshake.IsZero() {
		t.Errorf("handshake after prepareForSleep = %v, want zero (so daemon seeks a fresh handshake on wake)", gotHandshake)
	}
}

// TestPrepareForSleepClearsKernelPeer verifies that the kernel's
// WireGuard peer list is emptied before sleep. Clearing only our internal
// health tracker isn't enough — on wake, wireguard.IsConnected() reads the
// kernel's LastHandshakeTime directly via wgctrl, and a stale-but-<3min
// handshake would make it report connected. Dropping the peer makes the
// kernel report an empty peer list so IsConnected returns false.
func TestPrepareForSleepClearsKernelPeer(t *testing.T) {
	d, _, _ := testDaemon(t)
	d.stateMu.Lock()
	d.state = StateConnected
	d.stateMu.Unlock()

	origClear := clearPeersFn
	t.Cleanup(func() { clearPeersFn = origClear })
	var gotIface string
	called := false
	clearPeersFn = func(name string) error {
		called = true
		gotIface = name
		return nil
	}

	d.prepareForSleep()

	if !called {
		t.Fatal("clearPeersFn should have been called so kernel handshake is invalidated pre-sleep")
	}
	if gotIface != d.cfg.ConnectionName {
		t.Errorf("clearPeersFn iface = %q, want %q", gotIface, d.cfg.ConnectionName)
	}
}

// TestLightHealthTickFailedShortcutVerifiesBeforeReconnect is the post-sleep
// half of issue #7: even with pre-sleep handshake clearing, the lightHealthTick
// StateFailed-recovery shortcut must not broadcast EventReconnected based on
// kernel state alone. A stale handshake + interface-up can make IsConnected
// return true while traffic actually leaks to the ISP. The shortcut must run
// a real IP verify (current public IP != baseline ISP IP) before declaring
// reconnected.
func TestLightHealthTickFailedShortcutVerifiesBeforeReconnect(t *testing.T) {
	d, mc, _ := testDaemon(t)
	mc.isConnResult = true // pretend the kernel says "connected"

	d.cfg.BaselineIP = "73.251.160.112" // ISP baseline
	d.stateMu.Lock()
	d.state = StateFailed
	d.currentServer = "US-NY#42"
	d.stateMu.Unlock()

	origVerify := verifyPublicIPFn
	t.Cleanup(func() { verifyPublicIPFn = origVerify })
	// Simulate traffic leaking outside the tunnel — public IP == baseline
	verifyPublicIPFn = func() (string, error) {
		return "73.251.160.112", nil
	}

	d.lightHealthTick()

	d.stateMu.RLock()
	gotState := d.state
	d.stateMu.RUnlock()
	if gotState == StateConnected {
		t.Error("shortcut broadcast Reconnected despite public IP matching baseline (leak) — verify is missing")
	}
}

// TestLightHealthTickFailedShortcutReconnectsOnRealVerify confirms the happy
// path: kernel connected + public IP changed from baseline → real reconnect.
func TestLightHealthTickFailedShortcutReconnectsOnRealVerify(t *testing.T) {
	d, mc, _ := testDaemon(t)
	mc.isConnResult = true

	d.cfg.BaselineIP = "73.251.160.112"
	d.stateMu.Lock()
	d.state = StateFailed
	d.currentServer = "US-NY#42"
	d.stateMu.Unlock()

	origVerify := verifyPublicIPFn
	t.Cleanup(func() { verifyPublicIPFn = origVerify })
	verifyPublicIPFn = func() (string, error) {
		return "185.247.68.99", nil // VPN exit IP, differs from baseline
	}

	d.lightHealthTick()

	d.stateMu.RLock()
	gotState := d.state
	d.stateMu.RUnlock()
	if gotState != StateConnected {
		t.Errorf("state after real verify-passing shortcut = %s, want %s", gotState, StateConnected)
	}
}

// TestLightHealthTickFailedShortcutVerifyError covers the path where
// verifyPublicIPFn returns an error (no network, DNS down, ipinfo
// unreachable). The daemon MUST stay in StateFailed rather than
// claiming the manual reconnect succeeded — claiming reconnected
// without verifying would silently fake-recover into the broken
// state IsConnected lies about (issue #7's post-sleep half).
//
// Sibling to TestLightHealthTickFailedShortcutVerifiesBeforeReconnect
// (covers baseline-match path) and ...ReconnectsOnRealVerify (covers
// happy path). This one covers the verify-itself-failed path.
func TestLightHealthTickFailedShortcutVerifyError(t *testing.T) {
	d, mc, _ := testDaemon(t)
	mc.isConnResult = true // kernel says connected

	d.cfg.BaselineIP = "73.251.160.112"
	d.stateMu.Lock()
	d.state = StateFailed
	d.currentServer = "US-NY#42"
	d.stateMu.Unlock()

	origVerify := verifyPublicIPFn
	t.Cleanup(func() { verifyPublicIPFn = origVerify })
	verifyPublicIPFn = func() (string, error) {
		return "", fmt.Errorf("network unreachable")
	}

	d.lightHealthTick()

	d.stateMu.RLock()
	gotState := d.state
	d.stateMu.RUnlock()
	if gotState != StateFailed {
		t.Errorf("state after verify-error shortcut = %s, want %s (must stay Failed when verify can't confirm)", gotState, StateFailed)
	}
}

// TestPrepareForSleepActsOnUnhealthy verifies prepareForSleep fires
// the action path when state is StateUnhealthy, not just StateConnected.
// The early-return guard is:
//
//   if state != StateConnected && state != StateUnhealthy { return }
//
// Without this test, a regression that simplified the guard to
// `state != StateConnected` would silently make Unhealthy connections
// retain their state across sleep — the exact issue #7 scenario but
// for the (common) case of a degraded connection going into suspend
// instead of a fully-healthy one. TestPrepareForSleepClearsConnectedState
// only covers the StateConnected case.
func TestPrepareForSleepActsOnUnhealthy(t *testing.T) {
	d, _, _ := testDaemon(t)
	d.stateMu.Lock()
	d.state = StateUnhealthy
	d.currentServer = "US-NY#42"
	d.health.recordHandshake(time.Now().Add(-30 * time.Second))
	d.stateMu.Unlock()

	d.prepareForSleep()

	d.stateMu.RLock()
	gotState := d.state
	gotHandshake := d.health.lastHandshake
	d.stateMu.RUnlock()

	if gotState != StateUnhealthy {
		t.Errorf("state after prepareForSleep from Unhealthy = %s, want %s", gotState, StateUnhealthy)
	}
	// Critical: action path must run — handshake must be cleared.
	// If it ran, lastHandshake is zero. If guard wrongly early-returned,
	// the handshake stays at the recordHandshake value above.
	if !gotHandshake.IsZero() {
		t.Errorf("handshake after prepareForSleep from Unhealthy = %v, want zero (action path didn't run — guard regression?)", gotHandshake)
	}
}

// TestPrepareForSleepNoOpWhenNotConnected ensures the sleep handler doesn't
// spuriously mark an already-disconnected daemon as Unhealthy.
func TestPrepareForSleepNoOpWhenNotConnected(t *testing.T) {
	d, _, _ := testDaemon(t)
	d.stateMu.Lock()
	d.state = StateIdle
	d.stateMu.Unlock()

	d.prepareForSleep()

	d.stateMu.RLock()
	gotState := d.state
	d.stateMu.RUnlock()
	if gotState != StateIdle {
		t.Errorf("state after prepareForSleep while idle = %s, want %s (no-op)", gotState, StateIdle)
	}
}

// TestSpawnAndWaitForConnectUsesConnectFlowTimeout verifies Bug 3:
// SpawnAndWaitForConnect's per-event read must respect connectFlowReadTimeout
// (not the default 30s), so verify/handshake gaps >30s don't spuriously error.
// By shrinking the timeout and producing a silent gap longer than it, we prove
// the loop is actually calling ReadEventWithTimeout(connectFlowReadTimeout)
// rather than ReadEvent() (which uses the 30s default).
func TestSpawnAndWaitForConnectUsesConnectFlowTimeout(t *testing.T) {
	origTimeout := connectFlowReadTimeout
	connectFlowReadTimeout = 200 * time.Millisecond
	t.Cleanup(func() { connectFlowReadTimeout = origTimeout })

	stubNotify(t)
	cfg := testConfig(t)

	mc := &mockConnector{}
	mc.connectFunc = func(c *config.Config, server, provider string, isDynamic bool, callback func(wireguard.ConnectionStatus)) error {
		// Silent gap longer than the shrunken connectFlowReadTimeout.
		time.Sleep(600 * time.Millisecond)
		if callback != nil {
			callback(wireguard.ConnectionStatus{Stage: "Connected", Success: true, NewIP: "10.0.0.1"})
		}
		return nil
	}

	origSpawn := spawnDaemonFn
	spawnDaemonFn = func(execPath string, args ...string) error {
		d := NewConnectionDaemon(cfg)
		d.SetConnector(mc)
		d.SetHealthChecker(newMockHealthChecker())
		runDone := make(chan struct{})
		go func() { d.Run(); close(runDone) }()
		go func() {
			time.Sleep(50 * time.Millisecond)
			d.commandCh <- Command{
				Type:      CmdConnect,
				Server:    "US-NY#42",
				Provider:  "protonvpn",
				IsDynamic: true,
			}
		}()
		t.Cleanup(func() { d.stop(); <-runDone })
		return nil
	}
	t.Cleanup(func() { spawnDaemonFn = origSpawn })

	_, err := SpawnAndWaitForConnect(cfg.ConfigDir, "/fake/exec", "US-NY#42", "protonvpn", true, nil)
	if err == nil {
		t.Fatal("expected timeout error, got nil (timeout not applied to SpawnAndWaitForConnect loop?)")
	}
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("expected timeout-style error, got: %v", err)
	}
}

// TestConnectFlowReadTimeoutLongEnough is a regression guard for Bug 3's root
// cause — the read deadline must exceed a realistic verify/handshake gap.
// VM observations showed 30s was too short; anything under a minute should
// not be considered safe.
func TestConnectFlowReadTimeoutLongEnough(t *testing.T) {
	if connectFlowReadTimeout < 60*time.Second {
		t.Errorf("connectFlowReadTimeout = %v, must be >= 60s to tolerate verify-phase gaps", connectFlowReadTimeout)
	}
}

// TestDaemonExitsDespiteWaybarPoller verifies Bug 2's robustness against the
// Waybar integration, which opens short-lived QuickStatus connections every ~2s.
// A naive "any client attached means stay alive" check gets fooled by Waybar's
// ~30ms connection blips, causing the daemon to become a zombie on machines
// running the Omarchy desktop. The fix is to require a sustained empty-client
// window before declaring orphan (waybar can't sustain a connection across
// several polls; a real TUI can).
func TestDaemonExitsDespiteWaybarPoller(t *testing.T) {
	d, mc, _ := testDaemon(t)
	mc.connectErr = fmt.Errorf("mock: handshake failed")

	d.initialCmd = &Command{
		Type:      CmdConnect,
		Server:    "US-NY#42",
		Provider:  "protonvpn",
		IsDynamic: true,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- d.Run() }()

	socketPath := SocketPath(d.cfg.ConfigDir)
	waitForSocket(t, socketPath, 3*time.Second)

	// Fake-waybar: poll every 200ms with a brief ~30ms connection each time.
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(200 * time.Millisecond):
			}
			conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
			if err != nil {
				return // socket gone — daemon exited
			}
			reader := bufio.NewReader(conn)
			reader.ReadString('\n') // initial status event
			time.Sleep(30 * time.Millisecond)
			conn.Close()
		}
	}()

	select {
	case runErr := <-errCh:
		close(done)
		if runErr != nil {
			t.Errorf("Run returned error: %v", runErr)
		}
	case <-time.After(orphanExitGrace + 3*time.Second):
		close(done)
		d.stop()
		<-errCh
		t.Fatal("daemon did not exit with waybar-style poller attached")
	}
}

// TestDaemonExitsWhenLastClientLeavesAfterFailedConnect is the regression
// guard for the M5-stuck-daemon bug: when a CLI client (e.g. `lazyvpn random`)
// triggers an initial connect that fails, it stays attached past
// orphanExitGrace's hard 3s window (its event-read deadline is much longer),
// so the existing exitIfOrphaned check never fires. When that lone client
// finally disconnects, the daemon must recognise it has nothing to do and
// exit — not stay alive forever holding the socket+pid file.
//
// Without the fix, this test hangs until the test framework's deadline.
func TestDaemonExitsWhenLastClientLeavesAfterFailedConnect(t *testing.T) {
	d, mc, _ := testDaemon(t)
	mc.connectErr = fmt.Errorf("mock: provider parse failed")

	d.initialCmd = &Command{
		Type:      CmdConnect,
		Server:    "US-NY#42",
		Provider:  "protonvpn",
		IsDynamic: true,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- d.Run() }()

	socketPath := SocketPath(d.cfg.ConfigDir)
	waitForSocket(t, socketPath, 3*time.Second)

	// Simulate the spawning CLI: connect, hold the connection past
	// orphanExitGrace (defeating the existing 3s window), then disconnect.
	conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Stay attached well past orphanExitGrace so the existing window doesn't
	// trigger exit while we're connected.
	time.Sleep(orphanExitGrace + 500*time.Millisecond)
	conn.Close()

	// After our disconnect, the new check in handleClient's defer should
	// see remaining=0 + StateFailed and trigger d.stop().
	select {
	case runErr := <-errCh:
		if runErr != nil {
			t.Errorf("Run returned error: %v", runErr)
		}
	case <-time.After(2 * time.Second):
		d.stop()
		<-errCh
		t.Fatal("daemon did not exit after last client disconnected in StateFailed")
	}
}

// TestDaemonExitsOnFailedConnectWithNoClients verifies Bug 2:
// when an initial connection attempt fails and no TUI client is attached,
// the daemon must exit rather than become a zombie awaiting user input.
func TestDaemonExitsOnFailedConnectWithNoClients(t *testing.T) {
	d, mc, _ := testDaemon(t)
	mc.connectErr = fmt.Errorf("mock: handshake failed")

	d.initialCmd = &Command{
		Type:      CmdConnect,
		Server:    "US-NY#42",
		Provider:  "protonvpn",
		IsDynamic: true,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- d.Run() }()

	// No client ever attaches. Daemon should recognise it's an orphan and exit
	// after the grace window elapses.
	select {
	case runErr := <-errCh:
		if runErr != nil {
			t.Errorf("Run returned error: %v", runErr)
		}
	case <-time.After(orphanExitGrace + 2*time.Second):
		d.stop()
		t.Fatal("daemon did not exit after failed connect with no clients")
	}
}

func TestIntegrationReadPidFileHelper(t *testing.T) {
	tmpDir := t.TempDir()

	// No file
	if pid := readPidFile(filepath.Join(tmpDir, "nope")); pid != 0 {
		t.Errorf("expected 0 for missing file, got %d", pid)
	}

	// Invalid content
	path := filepath.Join(tmpDir, "pid")
	os.WriteFile(path, []byte("abc"), 0600)
	if pid := readPidFile(path); pid != 0 {
		t.Errorf("expected 0 for invalid content, got %d", pid)
	}

	// Valid PID
	os.WriteFile(path, []byte("12345\n"), 0600)
	if pid := readPidFile(path); pid != 12345 {
		t.Errorf("expected 12345, got %d", pid)
	}
}

func TestIntegrationReadEventWithTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Server accepts but sends nothing
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Hold connection open but don't send anything
		time.Sleep(5 * time.Second)
	}()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}

	c := NewClient(tmpDir)
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	defer c.Close()

	// ReadEventWithTimeout should fail after the short timeout
	start := time.Now()
	_, err = c.ReadEventWithTimeout(200 * time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > 2*time.Second {
		t.Errorf("timeout took too long: %v", elapsed)
	}
}

// TestStopDaemon_SendsDisconnectFirst is the regression guard for commit
// 1c083a0: explicit `lazyvpn daemon stop` (CLI) must dial the IPC socket
// and send CmdDisconnect FIRST so doDisconnect runs and clears
// LastConnectedServer (the user-disconnect contract). Only after that
// (or if IPC fails) should it fall through to SIGTERM.
//
// Without this path, `daemon stop` would route through the SIGTERM/
// ForceDisconnect path which preserves LastConnectedServer (correct for
// system-shutdown but wrong for explicit user-stop — autoconnect would
// silently reconnect on next launch).
func TestStopDaemon_SendsDisconnectFirst(t *testing.T) {
	d, mc, _ := testDaemon(t)
	mc.connectErr = nil

	d.initialCmd = &Command{
		Type:      CmdConnect,
		Server:    "US-NY#42",
		Provider:  "protonvpn",
		IsDynamic: true,
	}

	runDone := make(chan struct{})
	go func() { d.Run(); close(runDone) }()

	socketPath := SocketPath(d.cfg.ConfigDir)
	waitForSocket(t, socketPath, 3*time.Second)

	// Give the initial connect a moment to land in StateConnected so the
	// terminate handler's `connected` check would otherwise route through
	// ForceDisconnect (preserve LastConnectedServer). The IPC disconnect
	// path should fire first and transition to StateDisconnecting/Idle,
	// making the SIGTERM-time check skip ForceDisconnect entirely.
	time.Sleep(150 * time.Millisecond)

	// StopDaemon needs a PID file to look up; point it at our own PID
	// (we won't actually be signalled because we stub signalProcessFn).
	pidPath := PidPath(d.cfg.ConfigDir)
	os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600)

	// Stub SIGTERM so we don't signal the test runner. Trigger d.stop()
	// when SIGTERM arrives so Run() returns; report "process exited" on
	// the signal-0 liveness check so StopDaemon's wait loop succeeds.
	origSignal := signalProcessFn
	signalProcessFn = func(pid int, sig os.Signal) error {
		if sig == syscall.SIGTERM {
			d.stop()
		}
		if sig == syscall.Signal(0) {
			return fmt.Errorf("process not found")
		}
		return nil
	}
	t.Cleanup(func() { signalProcessFn = origSignal })

	disconnectsBefore := mc.disconnectCalls

	if err := StopDaemon(d.cfg.ConfigDir); err != nil {
		<-runDone
		t.Fatalf("StopDaemon: %v", err)
	}

	<-runDone

	mc.mu.Lock()
	defer mc.mu.Unlock()
	if mc.disconnectCalls <= disconnectsBefore {
		t.Errorf("Disconnect was not called (calls=%d, before=%d) — StopDaemon's IPC-disconnect-first path didn't fire",
			mc.disconnectCalls, disconnectsBefore)
	}
}

// TestDaemon_NoGoroutineLeaks runs a representative daemon lifecycle —
// spawn → connect → stop — and after Run() returns, verifies no goroutines
// from this package are still alive. The daemon spawns several long-running
// goroutines (acceptClients, sleepWakeListener, exitIfOrphaned, the dbus
// signal listener) that all need to terminate when stopCh closes; this test
// catches any that don't.
//
// goleak's IgnoreCurrent baseline excludes the test runtime's own goroutines
// + anything a sibling test (e.g. the stubNotify dbus connection) might have
// started before this one. We're only catching new leaks introduced by the
// daemon-under-test below.
func TestDaemon_NoGoroutineLeaks(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreCurrent(),
		// The dbus session-bus connection used by sleepWakeListener spawns
		// its own reader goroutine that holds a reference past Conn.Close.
		// It's a library quirk, not a daemon leak.
		goleak.IgnoreAnyFunction("github.com/godbus/dbus/v5.(*Conn).inWorker"),
		goleak.IgnoreAnyFunction("github.com/godbus/dbus/v5.(*Conn).outWorker"),
	)

	d, mc, _ := testDaemon(t)
	mc.connectErr = nil // success path

	d.initialCmd = &Command{
		Type:      CmdConnect,
		Server:    "US-NY#42",
		Provider:  "protonvpn",
		IsDynamic: true,
	}

	runDone := make(chan struct{})
	go func() {
		d.Run()
		close(runDone)
	}()

	socketPath := SocketPath(d.cfg.ConfigDir)
	waitForSocket(t, socketPath, 3*time.Second)

	// Attach a client briefly so the daemon goes through a realistic
	// connect → status broadcast → client disconnect cycle.
	conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err != nil {
		d.stop()
		<-runDone
		t.Fatalf("dial: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	conn.Close()

	d.stop()
	select {
	case <-runDone:
	case <-time.After(3 * time.Second):
		t.Fatal("daemon Run() did not return after stop()")
	}

	// Give acceptClients / health tickers / sleepWakeListener a beat to
	// exit cleanly before goleak samples.
	time.Sleep(100 * time.Millisecond)
}

// TestDaemon_CleanupClosesAttachedClients verifies that when the daemon
// is stopped while a client is still attached, the cleanup path closes
// the client's connection so its handleClient goroutine unblocks from
// ReadString and exits cleanly. Without the cleanup-side close the
// goroutine stays parked until the OS tears down the process FDs —
// invisible in production exit but caught by goleak in long test runs.
func TestDaemon_CleanupClosesAttachedClients(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreCurrent(),
		goleak.IgnoreAnyFunction("github.com/godbus/dbus/v5.(*Conn).inWorker"),
		goleak.IgnoreAnyFunction("github.com/godbus/dbus/v5.(*Conn).outWorker"),
	)

	d, mc, _ := testDaemon(t)
	mc.connectErr = nil

	d.initialCmd = &Command{
		Type:      CmdConnect,
		Server:    "US-NY#42",
		Provider:  "protonvpn",
		IsDynamic: true,
	}

	runDone := make(chan struct{})
	go func() {
		d.Run()
		close(runDone)
	}()

	socketPath := SocketPath(d.cfg.ConfigDir)
	waitForSocket(t, socketPath, 3*time.Second)

	conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err != nil {
		d.stop()
		<-runDone
		t.Fatalf("dial: %v", err)
	}
	// IMPORTANT: don't `defer conn.Close()` — defers run LIFO, so the
	// client-side close would fire before goleak's verify defer (which
	// was registered first) and unblock handleClient from outside the
	// daemon's cleanup path, defeating the test. Use t.Cleanup instead,
	// which runs after all defers have completed and after goleak.
	t.Cleanup(func() { conn.Close() })

	// Drain initial status so handleClient is parked in ReadString.
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	io.ReadAll(io.LimitReader(conn, 4096))
	conn.SetReadDeadline(time.Time{})

	// Now stop daemon WITHOUT the client disconnecting first. cleanup()
	// must close our conn so the daemon-side handleClient goroutine can
	// exit. If it doesn't, goleak flags the leaked goroutine.
	d.stop()
	select {
	case <-runDone:
	case <-time.After(3 * time.Second):
		t.Fatal("daemon Run() did not return after stop()")
	}
	time.Sleep(150 * time.Millisecond)
}

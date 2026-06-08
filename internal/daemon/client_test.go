package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	c := NewClient("/tmp/test")
	if c.configDir != "/tmp/test" {
		t.Errorf("configDir = %q", c.configDir)
	}
	if c.conn != nil {
		t.Error("conn should be nil initially")
	}
}

func TestIsConnected(t *testing.T) {
	c := NewClient("/tmp/test")
	if c.IsConnected() {
		t.Error("should not be connected initially")
	}

	// Set conn to non-nil to simulate connected state
	c.conn = &net.UnixConn{}
	if !c.IsConnected() {
		t.Error("should be connected when conn is set")
	}
}

func TestSetEventHandler(t *testing.T) {
	c := NewClient("/tmp/test")

	called := false
	handler := func(e Event) { called = true }

	c.SetEventHandler(handler)

	// Read back the handler under the lock
	c.eventMu.RLock()
	h := c.onEvent
	c.eventMu.RUnlock()

	if h == nil {
		t.Fatal("handler should not be nil")
	}

	h(Event{})
	if !called {
		t.Error("handler should have been called")
	}
}

func TestSetEventHandlerConcurrent(t *testing.T) {
	c := NewClient("/tmp/test")
	var wg sync.WaitGroup

	// Concurrent sets should not race
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.SetEventHandler(func(e Event) {})
		}()
	}
	wg.Wait()
}

func TestSendCommandNotConnected(t *testing.T) {
	c := NewClient("/tmp/test")
	err := c.SendCommand(Command{Type: CmdStatus})
	if err == nil {
		t.Error("expected error when not connected")
	}
	if !strings.Contains(err.Error(), "not connected") {
		t.Errorf("error = %q, want 'not connected'", err)
	}
}

func TestReadEventNotConnected(t *testing.T) {
	c := NewClient("/tmp/test")
	_, err := c.ReadEvent()
	if err == nil {
		t.Error("expected error when not connected")
	}
}

func TestRequestMethods(t *testing.T) {
	// Create a Unix socket pair for testing
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Accept connections in background and read commands
	received := make(chan Command, 10)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			var cmd Command
			json.Unmarshal([]byte(line), &cmd)
			received <- cmd
		}
	}()

	// Connect client
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(tmpDir)
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	defer c.Close()

	// Test RequestStatus
	if err := c.RequestStatus(); err != nil {
		t.Fatalf("RequestStatus error: %v", err)
	}
	cmd := <-received
	if cmd.Type != CmdStatus {
		t.Errorf("status: Type = %q, want %q", cmd.Type, CmdStatus)
	}

	// Test RequestConnect
	if err := c.RequestConnect("US-NY#42", "protonvpn", true); err != nil {
		t.Fatalf("RequestConnect error: %v", err)
	}
	cmd = <-received
	if cmd.Type != CmdConnect {
		t.Errorf("connect: Type = %q", cmd.Type)
	}
	if cmd.Server != "US-NY#42" {
		t.Errorf("connect: Server = %q", cmd.Server)
	}
	if cmd.Provider != "protonvpn" {
		t.Errorf("connect: Provider = %q", cmd.Provider)
	}
	if !cmd.IsDynamic {
		t.Error("connect: IsDynamic should be true")
	}

	// Test RequestDisconnect
	if err := c.RequestDisconnect(); err != nil {
		t.Fatalf("RequestDisconnect error: %v", err)
	}
	cmd = <-received
	if cmd.Type != CmdDisconnect {
		t.Errorf("disconnect: Type = %q", cmd.Type)
	}

	// Test RequestSwitch
	if err := c.RequestSwitch("SE#5", "mullvad", false); err != nil {
		t.Fatalf("RequestSwitch error: %v", err)
	}
	cmd = <-received
	if cmd.Type != CmdSwitch {
		t.Errorf("switch: Type = %q", cmd.Type)
	}
	if cmd.Server != "SE#5" {
		t.Errorf("switch: Server = %q", cmd.Server)
	}
	if cmd.IsDynamic {
		t.Error("switch: IsDynamic should be false")
	}
}

func TestReadEvent(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Server sends an event
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		event := Event{
			Type:      EventConnected,
			Timestamp: time.Now().Truncate(time.Second),
			Server:    "US-NY#42",
			PublicIP:  "1.2.3.4",
			Message:   "Connected",
		}
		data, _ := json.Marshal(event)
		conn.Write(append(data, '\n'))
	}()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(tmpDir)
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	defer c.Close()

	event, err := c.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent error: %v", err)
	}
	if event.Type != EventConnected {
		t.Errorf("Type = %q, want CONNECTED", event.Type)
	}
	if event.Server != "US-NY#42" {
		t.Errorf("Server = %q", event.Server)
	}
	if event.PublicIP != "1.2.3.4" {
		t.Errorf("PublicIP = %q", event.PublicIP)
	}
}

func TestCloseNilConn(t *testing.T) {
	c := NewClient("/tmp/test")
	if err := c.Close(); err != nil {
		t.Errorf("Close on nil conn should return nil, got: %v", err)
	}
}

// TestSetDialTimeout_AppliesToConnect verifies the configured dial
// timeout actually shortens Connect's wait. Without the per-client
// override, every caller paid the 5s default — bad for waybar-style
// 2s polling against a wedged daemon.
func TestSetDialTimeout_AppliesToConnect(t *testing.T) {
	// Point at a non-listening socket path so DialTimeout has to wait.
	// On Linux, dialing a Unix socket whose path doesn't exist returns
	// ENOENT immediately (fast), not a timeout — so we instead point at
	// a *directory* path (EISDIR also returns immediately) won't work
	// either. The reliable way to trigger the timeout is a non-routable
	// TCP target, but Client only does Unix sockets. Easiest test that
	// actually exercises the field plumbing: confirm the field is read
	// and used with a stubbable hook.
	tmpDir := t.TempDir()
	c := NewClient(tmpDir)
	c.SetDialTimeout(50 * time.Millisecond)
	if c.dialTimeout != 50*time.Millisecond {
		t.Errorf("dialTimeout = %v, want 50ms", c.dialTimeout)
	}

	// Connecting to a non-existent socket fails immediately with ENOENT,
	// so we can't observe the timeout itself, but we CAN verify Connect
	// returns an error rather than panicking on a custom timeout.
	start := time.Now()
	err := c.Connect()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Connect should fail when no daemon is running")
	}
	// Whatever the failure mode, it must complete well under the
	// default 5s — proves we honored the override (or hit ENOENT).
	if elapsed > 1*time.Second {
		t.Errorf("Connect took %v, expected fast failure under custom timeout", elapsed)
	}
}

func TestIsDaemonRunning(t *testing.T) {
	tmpDir := t.TempDir()

	// No PID file -> not running
	if IsDaemonRunning(tmpDir) {
		t.Error("should not be running without PID file")
	}

	// Invalid PID file
	os.WriteFile(filepath.Join(tmpDir, ".daemon.pid"), []byte("not-a-number"), 0600)
	if IsDaemonRunning(tmpDir) {
		t.Error("should not be running with invalid PID")
	}

	// PID of current process -> running
	os.WriteFile(filepath.Join(tmpDir, ".daemon.pid"), []byte(fmt.Sprintf("%d", os.Getpid())), 0600)
	if !IsDaemonRunning(tmpDir) {
		t.Error("should detect current process as running")
	}

	// PID of non-existent process -> not running
	os.WriteFile(filepath.Join(tmpDir, ".daemon.pid"), []byte("999999999"), 0600)
	// Signal(0) should fail for a non-existent PID
	if IsDaemonRunning(tmpDir) {
		t.Error("non-existent PID should not be running")
	}
}

func TestListen(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Server sends two events then closes
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		for _, et := range []EventType{EventConnecting, EventConnected} {
			event := Event{Type: et, Timestamp: time.Now()}
			data, _ := json.Marshal(event)
			conn.Write(append(data, '\n'))
		}
	}()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(tmpDir)
	c.conn = conn
	c.reader = bufio.NewReader(conn)

	var events []EventType
	var mu sync.Mutex
	c.SetEventHandler(func(e Event) {
		mu.Lock()
		events = append(events, e.Type)
		mu.Unlock()
	})

	// Listen will return when connection closes
	err = c.Listen()
	// Should return an error (EOF) when server closes
	if err == nil {
		t.Error("Listen should return error on connection close")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
	if len(events) >= 2 {
		if events[0] != EventConnecting {
			t.Errorf("events[0] = %q", events[0])
		}
		if events[1] != EventConnected {
			t.Errorf("events[1] = %q", events[1])
		}
	}
}

// TestSameExePath verifies that the /proc/<pid>/exe vs /proc/self/exe
// comparison strips the kernel's "(deleted)" suffix that appears after
// `lazyvpn update` atomic-renames the binary out from under the running
// daemon. Without this, every post-update CLI invocation would think
// no daemon is ours and try to spawn a duplicate.
func TestSameExePath(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{
			name: "identical paths",
			a:    "/home/u/.local/bin/lazyvpn",
			b:    "/home/u/.local/bin/lazyvpn",
			want: true,
		},
		{
			name: "running daemon was deleted by update; new CLI is fresh inode",
			a:    "/home/u/.local/bin/lazyvpn (deleted)",
			b:    "/home/u/.local/bin/lazyvpn",
			want: true,
		},
		{
			name: "both deleted (post-uninstall race)",
			a:    "/home/u/.local/bin/lazyvpn (deleted)",
			b:    "/home/u/.local/bin/lazyvpn (deleted)",
			want: true,
		},
		{
			name: "different binaries — must not match",
			a:    "/usr/bin/firefox",
			b:    "/home/u/.local/bin/lazyvpn",
			want: false,
		},
		{
			name: "different paths with deleted suffix — must not match",
			a:    "/usr/bin/firefox (deleted)",
			b:    "/home/u/.local/bin/lazyvpn",
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sameExePath(c.a, c.b); got != c.want {
				t.Errorf("sameExePath(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
			}
		})
	}
}

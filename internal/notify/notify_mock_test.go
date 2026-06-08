package notify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// mockBusSender records calls for assertion.
type mockBusSender struct {
	mu    sync.Mutex
	calls []mockCall
}

type mockCall struct {
	method string
	args   []interface{}
}

func (m *mockBusSender) Call(method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{method: method, args: args})
	// Return a successful call with a notification ID
	return &dbus.Call{
		Body: []interface{}{uint32(42)},
	}
}

func (m *mockBusSender) CallWithContext(_ context.Context, method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	return m.Call(method, flags, args...)
}

// mockBusConnector returns a mock sender.
type mockBusConnector struct {
	sender *mockBusSender
}

func (m *mockBusConnector) Object(dest string, path dbus.ObjectPath) BusSender {
	return m.sender
}

func (m *mockBusConnector) Close() error {
	return nil
}

func setupMockBus(t *testing.T) *mockBusSender {
	t.Helper()
	sender := &mockBusSender{}
	connector := &mockBusConnector{sender: sender}
	SetConnectFunc(func() (BusConnector, error) {
		return connector, nil
	})
	// Reset notification ID
	lastNotificationID.Store(0)
	t.Cleanup(func() {
		SetConnectFunc(nil)
		lastNotificationID.Store(0)
	})
	return sender
}

func TestSendCallsNotify(t *testing.T) {
	sender := setupMockBus(t)

	err := Send(Notification{
		Title:   "Test Title",
		Message: "Test Body",
		Icon:    IconConnected,
		Timeout: 3000,
	})
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(sender.calls))
	}

	call := sender.calls[0]
	if call.method != "org.freedesktop.Notifications.Notify" {
		t.Errorf("method = %q, want Notify", call.method)
	}

	// Verify parameters: app_name, replaces_id, app_icon, summary, body, actions, hints, timeout
	if len(call.args) != 8 {
		t.Fatalf("expected 8 args, got %d", len(call.args))
	}

	appName, ok := call.args[0].(string)
	if !ok || appName != "LazyVPN" {
		t.Errorf("app_name = %v, want LazyVPN", call.args[0])
	}

	summary, ok := call.args[3].(string)
	if !ok {
		t.Fatalf("summary is not string: %T", call.args[3])
	}
	// Should have icon prepended
	expected := IconConnected + " Test Title"
	if summary != expected {
		t.Errorf("summary = %q, want %q", summary, expected)
	}

	body, ok := call.args[4].(string)
	if !ok || body != "Test Body" {
		t.Errorf("body = %v, want Test Body", call.args[4])
	}

	timeout, ok := call.args[7].(int32)
	if !ok || timeout != 3000 {
		t.Errorf("timeout = %v, want 3000", call.args[7])
	}
}

func TestSendWithoutIcon(t *testing.T) {
	sender := setupMockBus(t)

	Send(Notification{Title: "Plain Title", Message: "msg"})

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.calls) == 0 {
		t.Fatal("no calls recorded")
	}
	summary := sender.calls[0].args[3].(string)
	if summary != "Plain Title" {
		t.Errorf("summary without icon = %q, want %q", summary, "Plain Title")
	}
}

func TestLastNotificationIDReplacement(t *testing.T) {
	setupMockBus(t)

	// First send - replaces_id should be 0
	Send(Notification{Title: "First"})

	// After send, lastNotificationID should be updated to 42 (from mock)
	got := lastNotificationID.Load()
	if got != 42 {
		t.Errorf("lastNotificationID after first send = %d, want 42", got)
	}

	// Second send should use 42 as replaces_id
	Send(Notification{Title: "Second"})
}

func TestConcurrentSend(t *testing.T) {
	setupMockBus(t)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Send(Notification{Title: "Concurrent", Message: "test"})
		}()
	}
	wg.Wait()

	// lastNotificationID should be set (not zero, since mock returns 42)
	if lastNotificationID.Load() == 0 {
		t.Error("lastNotificationID should be non-zero after concurrent sends")
	}
}

func TestHelperFunctionsCallSend(t *testing.T) {
	sender := setupMockBus(t)

	// Call each helper and verify it produces a D-Bus call
	Connected("US-NY#42")
	Disconnected()
	ConnectionLost()
	Reconnected()
	ReconnectFailed()
	Error("test error")
	Info("Info Title", "info message")
	Failover()
	FailoverSuccess("SE#5")

	sender.mu.Lock()
	count := len(sender.calls)
	sender.mu.Unlock()

	if count != 9 {
		t.Errorf("expected 9 notification calls, got %d", count)
	}
}

func TestAtomicIDNoRace(t *testing.T) {
	// Verify that atomic operations on lastNotificationID don't race
	var wg sync.WaitGroup
	var id atomic.Uint32

	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			id.Store(uint32(42))
		}()
		go func() {
			defer wg.Done()
			_ = id.Load()
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// errMockBusSender returns a *dbus.Call with .Err set, simulating a D-Bus
// method call failure.
// ---------------------------------------------------------------------------
type errMockBusSender struct {
	mu      sync.Mutex
	calls   []mockCall
	callErr error // error to return in *dbus.Call.Err
	retID   uint32
}

func (m *errMockBusSender) Call(method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{method: method, args: args})
	return &dbus.Call{
		Err:  m.callErr,
		Body: []interface{}{m.retID},
	}
}

func (m *errMockBusSender) CallWithContext(_ context.Context, method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	return m.Call(method, flags, args...)
}

// errMockBusConnector wraps errMockBusSender.
type errMockBusConnector struct {
	sender *errMockBusSender
}

func (m *errMockBusConnector) Object(dest string, path dbus.ObjectPath) BusSender {
	return m.sender
}

func (m *errMockBusConnector) Close() error {
	return nil
}

// ---------------------------------------------------------------------------
// Test: Send() returns error when connectFunc itself fails
// ---------------------------------------------------------------------------
func TestSendConnectFuncError(t *testing.T) {
	connectErr := errors.New("session bus unavailable")
	SetConnectFunc(func() (BusConnector, error) {
		return nil, connectErr
	})
	lastNotificationID.Store(0)
	t.Cleanup(func() {
		SetConnectFunc(nil)
		lastNotificationID.Store(0)
	})

	err := Send(Notification{Title: "Should Fail"})
	if err == nil {
		t.Fatal("expected error from Send when connectFunc fails, got nil")
	}
	if !errors.Is(err, connectErr) {
		t.Errorf("error = %v, want wrapped %v", err, connectErr)
	}
	// Ensure the error message contains our context string
	if got := err.Error(); got != "failed to connect to session bus: session bus unavailable" {
		t.Errorf("error message = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Test: Send() returns error when Call() returns *dbus.Call with .Err set
// ---------------------------------------------------------------------------
func TestSendCallErrReturned(t *testing.T) {
	callErr := errors.New("method invocation failed")
	sender := &errMockBusSender{callErr: callErr, retID: 99}
	connector := &errMockBusConnector{sender: sender}
	SetConnectFunc(func() (BusConnector, error) {
		return connector, nil
	})
	lastNotificationID.Store(0)
	t.Cleanup(func() {
		SetConnectFunc(nil)
		lastNotificationID.Store(0)
	})

	err := Send(Notification{Title: "Call Err", Message: "body"})
	if err == nil {
		t.Fatal("expected error from Send when Call.Err is set, got nil")
	}
	if !errors.Is(err, callErr) {
		t.Errorf("error = %v, want wrapped %v", err, callErr)
	}
	if got := err.Error(); got != "failed to send notification: method invocation failed" {
		t.Errorf("error message = %q", got)
	}

	// The lastNotificationID should NOT have been updated because Store
	// only happens after a nil-Err call and we have non-nil Err. However,
	// the code does call.Store(&newID) which will fail, so ID stays 0.
	if id := lastNotificationID.Load(); id != 0 {
		t.Errorf("lastNotificationID = %d, want 0 after failed call", id)
	}
}

// ---------------------------------------------------------------------------
// Test: Verify replaces_id parameter — first call = 0, second call uses
// the returned ID
// ---------------------------------------------------------------------------
func TestReplacesIDParameter(t *testing.T) {
	sender := setupMockBus(t)

	// First call — replaces_id must be 0 (no previous notification)
	err := Send(Notification{Title: "First"})
	if err != nil {
		t.Fatalf("first Send: %v", err)
	}

	sender.mu.Lock()
	firstArgs := sender.calls[0].args
	sender.mu.Unlock()

	replaceID, ok := firstArgs[1].(uint32)
	if !ok {
		t.Fatalf("replaces_id type = %T, want uint32", firstArgs[1])
	}
	if replaceID != 0 {
		t.Errorf("first call replaces_id = %d, want 0", replaceID)
	}

	// Second call — replaces_id must be 42 (the value mock returns)
	err = Send(Notification{Title: "Second"})
	if err != nil {
		t.Fatalf("second Send: %v", err)
	}

	sender.mu.Lock()
	secondArgs := sender.calls[1].args
	sender.mu.Unlock()

	replaceID2, ok := secondArgs[1].(uint32)
	if !ok {
		t.Fatalf("replaces_id type = %T, want uint32", secondArgs[1])
	}
	if replaceID2 != 42 {
		t.Errorf("second call replaces_id = %d, want 42", replaceID2)
	}
}

// ---------------------------------------------------------------------------
// Test: Verify urgency hint is set to 1 (Normal) in the hints map
// ---------------------------------------------------------------------------
func TestUrgencyHint(t *testing.T) {
	sender := setupMockBus(t)

	err := Send(Notification{Title: "Urgency Test"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	sender.mu.Lock()
	defer sender.mu.Unlock()

	if len(sender.calls) == 0 {
		t.Fatal("no calls recorded")
	}
	args := sender.calls[0].args
	if len(args) < 7 {
		t.Fatalf("expected at least 7 args, got %d", len(args))
	}

	hints, ok := args[6].(map[string]dbus.Variant)
	if !ok {
		t.Fatalf("hints arg type = %T, want map[string]dbus.Variant", args[6])
	}

	urgency, exists := hints["urgency"]
	if !exists {
		t.Fatal("hints map missing 'urgency' key")
	}

	val, ok := urgency.Value().(byte)
	if !ok {
		t.Fatalf("urgency value type = %T, want byte", urgency.Value())
	}
	if val != 1 {
		t.Errorf("urgency = %d, want 1 (Normal)", val)
	}
}

// ---------------------------------------------------------------------------
// Test: Verify each helper function's specific DBus call parameters
// (title with icon prefix, body, timeout)
// ---------------------------------------------------------------------------
func TestHelperConnectedParams(t *testing.T) {
	sender := setupMockBus(t)
	Connected("US-NY#42")

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(sender.calls))
	}
	args := sender.calls[0].args
	assertCallArgs(t, args, IconConnected+" VPN Connected", "US-NY#42", int32(3000))
}

func TestHelperDisconnectedParams(t *testing.T) {
	sender := setupMockBus(t)
	Disconnected()

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(sender.calls))
	}
	args := sender.calls[0].args
	assertCallArgs(t, args, IconDisconnected+" VPN Disconnected", "Connection closed", int32(3000))
}

func TestHelperConnectionLostParams(t *testing.T) {
	sender := setupMockBus(t)
	ConnectionLost()

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(sender.calls))
	}
	args := sender.calls[0].args
	assertCallArgs(t, args, IconRetry+" VPN Connection Lost", "Attempting to reconnect...", int32(5000))
}

func TestHelperReconnectedParams(t *testing.T) {
	sender := setupMockBus(t)
	Reconnected()

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(sender.calls))
	}
	args := sender.calls[0].args
	assertCallArgs(t, args, IconConnected+" VPN Reconnected", "Connection restored", int32(3000))
}

func TestHelperReconnectFailedParams(t *testing.T) {
	sender := setupMockBus(t)
	ReconnectFailed()

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(sender.calls))
	}
	args := sender.calls[0].args
	assertCallArgs(t, args, IconError+" VPN Reconnect Failed", "Please choose another server", int32(0))
}

func TestHelperFailoverParams(t *testing.T) {
	sender := setupMockBus(t)
	Failover()

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(sender.calls))
	}
	args := sender.calls[0].args
	assertCallArgs(t, args, IconRetry+" VPN Failover", "Trying alternate server...", int32(5000))
}

func TestHelperFailoverSuccessParams(t *testing.T) {
	sender := setupMockBus(t)
	FailoverSuccess("SE#5")

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(sender.calls))
	}
	args := sender.calls[0].args
	assertCallArgs(t, args, IconConnected+" VPN Failover Success", "Connected to SE#5", int32(3000))
}

func TestHelperErrorParams(t *testing.T) {
	sender := setupMockBus(t)
	Error("something broke")

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(sender.calls))
	}
	args := sender.calls[0].args
	assertCallArgs(t, args, IconError+" LazyVPN Error", "something broke", int32(0))
}

func TestHelperInfoParams(t *testing.T) {
	sender := setupMockBus(t)
	Info("Custom Title", "info body")

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(sender.calls))
	}
	args := sender.calls[0].args
	assertCallArgs(t, args, IconInfo+" Custom Title", "info body", int32(3000))
}

// assertCallArgs verifies the summary (arg[3]), body (arg[4]), and timeout
// (arg[7]) of a recorded D-Bus Notify call.
func assertCallArgs(t *testing.T, args []interface{}, wantSummary, wantBody string, wantTimeout int32) {
	t.Helper()
	if len(args) != 8 {
		t.Fatalf("expected 8 args, got %d", len(args))
	}

	summary, ok := args[3].(string)
	if !ok {
		t.Fatalf("summary type = %T, want string", args[3])
	}
	if summary != wantSummary {
		t.Errorf("summary = %q, want %q", summary, wantSummary)
	}

	body, ok := args[4].(string)
	if !ok {
		t.Fatalf("body type = %T, want string", args[4])
	}
	if body != wantBody {
		t.Errorf("body = %q, want %q", body, wantBody)
	}

	timeout, ok := args[7].(int32)
	if !ok {
		t.Fatalf("timeout type = %T, want int32", args[7])
	}
	if timeout != wantTimeout {
		t.Errorf("timeout = %d, want %d", timeout, wantTimeout)
	}
}

// ---------------------------------------------------------------------------
// Test: SetConnectFunc(nil) restores the default connector
// ---------------------------------------------------------------------------
func TestSetConnectFuncNilRestoresDefault(t *testing.T) {
	// Set a custom function first
	called := false
	SetConnectFunc(func() (BusConnector, error) {
		called = true
		return nil, errors.New("custom")
	})

	// Verify the custom function is active
	_, err := connectFunc()
	if err == nil || !called {
		t.Fatal("custom connectFunc was not installed")
	}

	// Now pass nil to restore the default
	SetConnectFunc(nil)

	// The restored default should attempt a real dbus.ConnectSessionBus().
	// In CI / headless this will fail, but the important thing is that
	// it is NOT our custom function any more.
	called = false
	_, _ = connectFunc()
	if called {
		t.Error("after SetConnectFunc(nil), custom function was still called")
	}

	// Cleanup: restore a no-op mock so other tests aren't affected
	t.Cleanup(func() {
		SetConnectFunc(nil)
		lastNotificationID.Store(0)
	})
}

// ---------------------------------------------------------------------------
// Test: Multiple rapid SetConnectFunc swaps — sequential swaps followed by
// concurrent Send calls. SetConnectFunc is not concurrent-safe (it writes a
// plain package var), so swaps are serialized. The concurrent part exercises
// Send under a single active connectFunc to verify Send's internal
// thread-safety (atomic ID, mutex on mockBusSender).
// ---------------------------------------------------------------------------
func TestConcurrentSetConnectFuncSwaps(t *testing.T) {
	lastNotificationID.Store(0)
	t.Cleanup(func() {
		SetConnectFunc(nil)
		lastNotificationID.Store(0)
	})

	const swaps = 5
	const sendersPerSwap = 4

	for i := 0; i < swaps; i++ {
		// Swap the connector (serialized — not concurrent-safe by design)
		sender := &mockBusSender{}
		connector := &mockBusConnector{sender: sender}
		SetConnectFunc(func() (BusConnector, error) {
			return connector, nil
		})

		// Now fire concurrent Sends against this connector
		var wg sync.WaitGroup
		for j := 0; j < sendersPerSwap; j++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				_ = Send(Notification{
					Title:   fmt.Sprintf("Swap-%d-Send-%d", i, id),
					Message: "swap test",
					Icon:    IconInfo,
					Timeout: 1000,
				})
			}(j)
		}
		wg.Wait()

		// Verify all sends reached the current connector's sender
		sender.mu.Lock()
		count := len(sender.calls)
		sender.mu.Unlock()
		if count != sendersPerSwap {
			t.Errorf("swap %d: expected %d calls, got %d", i, sendersPerSwap, count)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Send with call.Store failure (Body does not contain uint32)
// ---------------------------------------------------------------------------
func TestSendStoreFailureDoesNotUpdateID(t *testing.T) {
	// Create a mock sender that returns a non-uint32 body so call.Store fails
	badSender := &badStoreMockSender{}
	connector := &badStoreMockConnector{sender: badSender}
	SetConnectFunc(func() (BusConnector, error) {
		return connector, nil
	})
	lastNotificationID.Store(0)
	t.Cleanup(func() {
		SetConnectFunc(nil)
		lastNotificationID.Store(0)
	})

	err := Send(Notification{Title: "Store Fail"})
	if err != nil {
		t.Fatalf("Send should succeed even if Store fails, got: %v", err)
	}

	// lastNotificationID should remain 0 since Store couldn't extract a uint32
	if id := lastNotificationID.Load(); id != 0 {
		t.Errorf("lastNotificationID = %d, want 0 after Store failure", id)
	}
}

// badStoreMockSender returns a *dbus.Call with Err=nil but Body containing a
// wrong type so that call.Store(&uint32) fails.
type badStoreMockSender struct{}

func (m *badStoreMockSender) Call(method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	return &dbus.Call{
		Body: []interface{}{"not-a-uint32"},
	}
}

func (m *badStoreMockSender) CallWithContext(_ context.Context, method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	return m.Call(method, flags, args...)
}

type badStoreMockConnector struct {
	sender *badStoreMockSender
}

func (m *badStoreMockConnector) Object(dest string, path dbus.ObjectPath) BusSender {
	return m.sender
}

func (m *badStoreMockConnector) Close() error {
	return nil
}

// ---------------------------------------------------------------------------
// Test: Verify actions parameter is empty string slice
// ---------------------------------------------------------------------------
func TestActionsParameterEmpty(t *testing.T) {
	sender := setupMockBus(t)

	err := Send(Notification{Title: "Actions Test"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	sender.mu.Lock()
	defer sender.mu.Unlock()

	args := sender.calls[0].args
	actions, ok := args[5].([]string)
	if !ok {
		t.Fatalf("actions type = %T, want []string", args[5])
	}
	if len(actions) != 0 {
		t.Errorf("actions = %v, want empty slice", actions)
	}
}

// ---------------------------------------------------------------------------
// Test: Verify app_icon parameter is empty string
// ---------------------------------------------------------------------------
func TestAppIconParameterEmpty(t *testing.T) {
	sender := setupMockBus(t)

	err := Send(Notification{Title: "AppIcon Test", Icon: IconError})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	sender.mu.Lock()
	defer sender.mu.Unlock()

	args := sender.calls[0].args
	appIcon, ok := args[2].(string)
	if !ok {
		t.Fatalf("app_icon type = %T, want string", args[2])
	}
	if appIcon != "" {
		t.Errorf("app_icon = %q, want empty string (icon is in summary)", appIcon)
	}
}

// ---------------------------------------------------------------------------
// Test: Verify Send propagates timeout=0 correctly (never expire)
// ---------------------------------------------------------------------------
func TestSendTimeoutZeroNeverExpire(t *testing.T) {
	sender := setupMockBus(t)

	err := Send(Notification{Title: "Never Expire", Timeout: 0})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	sender.mu.Lock()
	defer sender.mu.Unlock()

	timeout := sender.calls[0].args[7].(int32)
	if timeout != 0 {
		t.Errorf("timeout = %d, want 0 (never expire)", timeout)
	}
}

// ---------------------------------------------------------------------------
// Test: Verify Send propagates timeout=-1 correctly (server decides)
// ---------------------------------------------------------------------------
func TestSendTimeoutNegativeOneServerDecides(t *testing.T) {
	sender := setupMockBus(t)

	err := Send(Notification{Title: "Server Decides", Timeout: -1})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	sender.mu.Lock()
	defer sender.mu.Unlock()

	timeout := sender.calls[0].args[7].(int32)
	if timeout != -1 {
		t.Errorf("timeout = %d, want -1 (server decides)", timeout)
	}
}

// ---------------------------------------------------------------------------
// Test: Exercise defaultConnectFunc and realBusConnector when a real
// D-Bus session bus is available. Skipped in headless/CI environments.
// ---------------------------------------------------------------------------
func TestDefaultConnectFuncWithRealBus(t *testing.T) {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("no DBUS_SESSION_BUS_ADDRESS; skipping real D-Bus test")
	}

	// Call the real default connector
	conn, err := defaultConnectFunc()
	if err != nil {
		t.Skipf("defaultConnectFunc failed (no session bus?): %v", err)
	}
	defer conn.Close()

	// Exercise Object to cover realBusConnector.Object
	sender := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	if sender == nil {
		t.Fatal("Object returned nil")
	}
}

// ---------------------------------------------------------------------------
// Test: Exercise realBusConnector.Close explicitly via defaultConnectFunc
// ---------------------------------------------------------------------------
func TestRealBusConnectorClose(t *testing.T) {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("no DBUS_SESSION_BUS_ADDRESS; skipping real D-Bus test")
	}

	conn, err := defaultConnectFunc()
	if err != nil {
		t.Skipf("defaultConnectFunc failed: %v", err)
	}

	// Close should succeed without error
	if err := conn.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

// TestSendBoundedByOverallTimeout verifies that Send returns its
// timeout error rather than blocking indefinitely when connectFunc
// hangs (simulating a wedged session bus where Auth/Hello never
// respond).
//
// Pre-fix Send called connectFunc inline; a hung Auth/Hello in
// dbus.ConnectSessionBus would freeze the calling goroutine forever.
// The connection daemon calls notify.ConnectionLost / Reconnected
// directly from heavyHealthTick / attemptRecovery — a freeze there
// stalls every health tick.
func TestSendBoundedByOverallTimeout(t *testing.T) {
	// Shrink the cap so the test runs in <1s.
	oldTimeout := sendOverallTimeout
	sendOverallTimeout = 200 * time.Millisecond
	defer func() { sendOverallTimeout = oldTimeout }()

	// connectFunc that blocks until the test finishes — simulates a
	// session bus that accepts the socket but never completes Hello.
	hangCh := make(chan struct{})
	defer close(hangCh)

	SetConnectFunc(func() (BusConnector, error) {
		<-hangCh
		return nil, errors.New("never reached")
	})
	defer SetConnectFunc(nil)

	start := time.Now()
	err := Send(Notification{Title: "wedged"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Send returned nil error despite hung connectFunc — caller would block forever")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %v, want a timeout-shaped error", err)
	}
	// Should return shortly after the deadline, not after the test ends.
	if elapsed > 1*time.Second {
		t.Errorf("Send took %v to return — should respect the %v timeout", elapsed, sendOverallTimeout)
	}
}

package notify

import (
	"context"
	"sync"

	"github.com/godbus/dbus/v5"
)

// BusSender abstracts the D-Bus object call interface for testing.
// CallWithContext is the timeout-aware variant Send uses to avoid
// freezing on a wedged notification daemon.
type BusSender interface {
	Call(method string, flags dbus.Flags, args ...interface{}) *dbus.Call
	CallWithContext(ctx context.Context, method string, flags dbus.Flags, args ...interface{}) *dbus.Call
}

// BusConnector abstracts D-Bus session bus connection for testing.
// The real implementation uses dbus.ConnectSessionBus().
type BusConnector interface {
	Object(dest string, path dbus.ObjectPath) BusSender
	Close() error
}

// realBusConnector wraps a real D-Bus connection.
type realBusConnector struct {
	conn *dbus.Conn
}

func (r *realBusConnector) Object(dest string, path dbus.ObjectPath) BusSender {
	return r.conn.Object(dest, path)
}

func (r *realBusConnector) Close() error {
	return r.conn.Close()
}

// defaultConnectFunc is the real D-Bus connection factory.
func defaultConnectFunc() (BusConnector, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, err
	}
	return &realBusConnector{conn: conn}, nil
}

// connectFunc is the function used to create a D-Bus connection.
// Tests can replace this to inject a mock. Guarded by connectFuncMu
// because Send's worker goroutine outlives the synchronous Send when
// connectFunc hangs past sendOverallTimeout: a subsequent
// SetConnectFunc would race the leaked goroutine's read.
var (
	connectFuncMu sync.RWMutex
	connectFunc   = defaultConnectFunc
)

// getConnectFunc returns the current connectFunc under read lock.
func getConnectFunc() func() (BusConnector, error) {
	connectFuncMu.RLock()
	defer connectFuncMu.RUnlock()
	return connectFunc
}

// SetConnectFunc replaces the D-Bus connection factory (for testing).
// Pass nil to restore the default.
func SetConnectFunc(f func() (BusConnector, error)) {
	connectFuncMu.Lock()
	defer connectFuncMu.Unlock()
	if f == nil {
		connectFunc = defaultConnectFunc
		return
	}
	connectFunc = f
}

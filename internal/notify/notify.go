package notify

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
)

// notifyCallTimeout caps the DBus Notify call. A wedged notification
// daemon (rare but documented for some compositors after sleep/wake)
// would otherwise freeze whichever lazyvpn process is firing the
// notification — including the connection daemon.
const notifyCallTimeout = 3 * time.Second

// sendOverallTimeout bounds the entire Send() pipeline including
// connectFunc (Dial + Auth + Hello). dbus.ConnectSessionBus's Auth
// and Hello are synchronous DBus method calls with no built-in
// timeout: if the session bus daemon accepts the socket but never
// responds (PAM stall, session-bus death-loop, the rare bus-daemon
// hang after sleep/wake), connectFunc hangs forever. The daemon's
// main goroutine calls notify.ConnectionLost / Reconnected directly
// from heavyHealthTick and attemptRecovery — a hung notification
// would otherwise stall every health tick.
//
// 3s past notifyCallTimeout (so we have margin for the connectFunc
// portion of the work after Send hands off to the bus call). 6s
// total cap is well above healthy session-bus latency (<50ms) and
// short enough to surface as a recoverable error rather than a
// noticeable freeze.
//
// Var (not const) so tests can shrink it to exercise the timeout
// path without waiting 6 real seconds.
var sendOverallTimeout = 6 * time.Second

// Icons for different notification types (Nerd Font icons)
const (
	IconConnected    = "󰖂" // VPN connected
	IconDisconnected = "󰖃" // VPN disconnected
	IconError        = "󰀦" // Error
	IconInfo         = "󰋼" // Info
	IconRetry        = "󰑐" // Retry/reconnecting
	IconKillswitch   = "󰒘" // Shield/killswitch
)

// Category for notification grouping
type Category int

const (
	CategoryConnection Category = iota
	CategoryKillswitch
	CategoryDaemon
	CategoryError
	CategoryInfo
)

// Notification represents a desktop notification
type Notification struct {
	Title    string
	Message  string
	Icon     string
	Timeout  int32 // milliseconds, -1 = server decides, 0 = never expire
	Category Category
}

// lastNotificationID tracks the last notification ID for replacement (atomic for thread safety)
var lastNotificationID atomic.Uint32

// Send sends a desktop notification via DBus (org.freedesktop.Notifications).
//
// The whole pipeline is wrapped in a goroutine + select-with-timeout so
// a wedged session bus (Dial + Auth + Hello can each hang forever
// without any built-in deadline) cannot stall the caller. Callers
// commonly invoke Send from the connection daemon's main goroutine; a
// stall there freezes every subsequent health tick.
//
// On timeout we return the deadline error and leak the worker
// goroutine. The leak is bounded per-call (1 goroutine per Send that
// times out) and acceptable: a permanently wedged session bus is rare,
// and the alternative — blocking the daemon — is worse.
func Send(n Notification) error {
	resultCh := make(chan error, 1)
	go func() {
		resultCh <- sendSync(n)
	}()
	select {
	case err := <-resultCh:
		return err
	case <-time.After(sendOverallTimeout):
		return fmt.Errorf("notify timed out after %s — session bus may be wedged", sendOverallTimeout)
	}
}

// sendSync is the original synchronous Send body. Exposed via Send's
// goroutine wrapper so a wedged DBus connection can't stall the
// caller — see Send for the rationale.
func sendSync(n Notification) error {
	conn, err := getConnectFunc()()
	if err != nil {
		return fmt.Errorf("failed to connect to session bus: %w", err)
	}
	defer conn.Close()

	// Build title with icon
	title := n.Title
	if n.Icon != "" {
		title = fmt.Sprintf("%s %s", n.Icon, n.Title)
	}

	// Notification hints
	hints := map[string]dbus.Variant{
		"urgency": dbus.MakeVariant(byte(1)), // Normal urgency
	}

	// Per freedesktop spec: -1 = server decides, 0 = never expire, >0 = ms
	// Callers must set Timeout explicitly. Default int32 zero = "never expire".
	timeout := n.Timeout

	// Get current notification ID atomically
	replaceID := lastNotificationID.Load()

	// Call org.freedesktop.Notifications.Notify
	// Parameters: app_name, replaces_id, app_icon, summary, body, actions, hints, timeout
	obj := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	ctx, cancel := context.WithTimeout(context.Background(), notifyCallTimeout)
	defer cancel()
	call := obj.CallWithContext(
		ctx,
		"org.freedesktop.Notifications.Notify",
		0,
		"LazyVPN",  // app_name
		replaceID,  // replaces_id (replace previous notification)
		"",         // app_icon (empty = use default)
		title,      // summary
		n.Message,  // body
		[]string{}, // actions
		hints,      // hints
		timeout,    // timeout in ms
	)

	if call.Err != nil {
		return fmt.Errorf("failed to send notification: %w", call.Err)
	}

	// Store the returned notification ID for future replacement (atomically)
	var newID uint32
	if err := call.Store(&newID); err == nil {
		lastNotificationID.Store(newID)
	}

	return nil
}

// Quick helper functions for common notification types

// Connected sends a VPN connected notification
func Connected(serverName string) {
	Send(Notification{
		Title:    "VPN Connected",
		Message:  serverName,
		Icon:     IconConnected,
		Timeout:  3000,
		Category: CategoryConnection,
	})
}

// Disconnected sends a VPN disconnected notification
func Disconnected() {
	Send(Notification{
		Title:    "VPN Disconnected",
		Message:  "Connection closed",
		Icon:     IconDisconnected,
		Timeout:  3000,
		Category: CategoryConnection,
	})
}

// ConnectionLost sends a notification when connection is lost unexpectedly
func ConnectionLost() {
	Send(Notification{
		Title:    "VPN Connection Lost",
		Message:  "Attempting to reconnect...",
		Icon:     IconRetry,
		Timeout:  5000,
		Category: CategoryDaemon,
	})
}

// Reconnected sends a notification when auto-recover succeeds
func Reconnected() {
	Send(Notification{
		Title:    "VPN Reconnected",
		Message:  "Connection restored",
		Icon:     IconConnected,
		Timeout:  3000,
		Category: CategoryDaemon,
	})
}

// ReconnectFailed sends a notification when reconnection fails
func ReconnectFailed() {
	Send(Notification{
		Title:    "VPN Reconnect Failed",
		Message:  "Please choose another server",
		Icon:     IconError,
		Timeout:  0, // Never expire (per freedesktop spec)
		Category: CategoryError,
	})
}

// KillswitchBlocking sends a notification when VPN is down but killswitch is still
// blocking all traffic. Never auto-dismisses so the user understands why they have
// no internet and knows how to fix it.
func KillswitchBlocking(reason string) {
	Send(Notification{
		Title:    "Internet Blocked",
		Message:  reason + "\nConnect to a server or disable killswitch to restore internet.",
		Icon:     IconKillswitch,
		Timeout:  0, // Never expire
		Category: CategoryKillswitch,
	})
}

// Error sends an error notification
func Error(message string) {
	Send(Notification{
		Title:    "LazyVPN Error",
		Message:  message,
		Icon:     IconError,
		Timeout:  0, // Never expire (per freedesktop spec)
		Category: CategoryError,
	})
}

// Info sends an informational notification
func Info(title, message string) {
	Send(Notification{
		Title:    title,
		Message:  message,
		Icon:     IconInfo,
		Timeout:  3000,
		Category: CategoryInfo,
	})
}

// Failover sends a notification when failing over to another server
func Failover() {
	Send(Notification{
		Title:    "VPN Failover",
		Message:  "Trying alternate server...",
		Icon:     IconRetry,
		Timeout:  5000,
		Category: CategoryDaemon,
	})
}

// FailoverSuccess sends a notification when failover succeeds
func FailoverSuccess(serverName string) {
	Send(Notification{
		Title:    "VPN Failover Success",
		Message:  fmt.Sprintf("Connected to %s", serverName),
		Icon:     IconConnected,
		Timeout:  3000,
		Category: CategoryDaemon,
	})
}

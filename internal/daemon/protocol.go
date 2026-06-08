package daemon

import (
	"fmt"
	"path/filepath"
	"time"
)

// Command types sent from client to daemon
type CommandType string

const (
	CmdConnect    CommandType = "connect"
	CmdDisconnect CommandType = "disconnect"
	CmdSwitch     CommandType = "switch"
	CmdStatus     CommandType = "status"
)

// Command is a message sent from client to daemon
type Command struct {
	Type      CommandType `json:"type"`
	Server    string      `json:"server,omitempty"`     // For connect/switch: server name
	Provider  string      `json:"provider,omitempty"`   // For dynamic servers: provider name
	IsDynamic bool        `json:"is_dynamic,omitempty"` // True if using dynamic server
}

// Validate checks that the command has all required fields for its type.
func (c *Command) Validate() error {
	switch c.Type {
	case CmdConnect, CmdSwitch:
		if c.Server == "" {
			return fmt.Errorf("server required for %s command", c.Type)
		}
		// Dynamic-server commands need a provider — without one, the
		// daemon would otherwise enter StateConnecting, broadcast
		// EventConnecting, then fail deep in ConnectDynamic ->
		// configLoadProvider's empty-name check, surfacing as an
		// opaque error several layers down.
		if c.IsDynamic && c.Provider == "" {
			return fmt.Errorf("provider required for dynamic %s command", c.Type)
		}
	case CmdDisconnect, CmdStatus:
		// no additional fields required
	default:
		return fmt.Errorf("unknown command type: %q", c.Type)
	}
	return nil
}

// EventType represents daemon status events
type EventType string

const (
	EventConnecting    EventType = "CONNECTING"
	EventConnected     EventType = "CONNECTED"
	EventHealthy       EventType = "HEALTHY"
	EventHealthFail    EventType = "HEALTH_FAIL"
	EventHealthState   EventType = "HEALTH_STATE" // Periodic health snapshot
	EventRetrying      EventType = "RETRYING"
	EventReconnected   EventType = "RECONNECTED"
	EventFailed        EventType = "FAILED"
	EventSwitching     EventType = "SWITCHING"
	EventSwitchFailed  EventType = "SWITCH_FAILED" // Switch failed, awaiting user choice
	EventDisconnecting EventType = "DISCONNECTING"
	EventDisconnected  EventType = "DISCONNECTED"
	EventError         EventType = "ERROR"
	EventStatus        EventType = "STATUS" // Response to status command
)

// HealthState is a snapshot of all health monitoring data.
// Broadcast periodically by the daemon as EventHealthState.
type HealthState struct {
	// Per-factor scores (0-100)
	HandshakeScore  int `json:"handshake_score"`
	DNSScore        int `json:"dns_score"`
	LatencyScore    int `json:"latency_score"`
	PacketLossScore int `json:"packet_loss_score"`

	// Raw values
	HandshakeAgeSec float64 `json:"handshake_age_sec"`
	LatencyMs       int     `json:"latency_ms"`
	PacketLossPct   float64 `json:"packet_loss_pct"`
	DNSConsecFails  int     `json:"dns_consec_fails"`

	// Network stats
	RxBytes        uint64    `json:"rx_bytes"`
	TxBytes        uint64    `json:"tx_bytes"`
	RxPackets      uint64    `json:"rx_packets"`
	TxPackets      uint64    `json:"tx_packets"`
	StatsTimestamp time.Time `json:"stats_timestamp"`

	// WireGuard peer info
	Endpoint      string    `json:"endpoint,omitempty"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`

	// Composite
	Score int    `json:"score"` // 0-100
	Grade string `json:"grade"` // "Excellent", "Good", "Fair", "Poor", "Bad"
}

// Event is a message sent from daemon to client
type Event struct {
	Type        EventType `json:"type"`
	Timestamp   time.Time `json:"timestamp"`
	Message     string    `json:"message,omitempty"`
	Server      string    `json:"server,omitempty"`
	Provider    string    `json:"provider,omitempty"`
	PublicIP    string    `json:"public_ip,omitempty"`
	OldIP       string    `json:"old_ip,omitempty"`
	Latency     int       `json:"latency,omitempty"`      // ms
	HealthFails int       `json:"health_fails,omitempty"` // current fail count
	MaxFails    int       `json:"max_fails,omitempty"`    // max before action
	RetryCount  int       `json:"retry_count,omitempty"`
	MaxRetries  int       `json:"max_retries,omitempty"`
	Error       string    `json:"error,omitempty"`
	// For switch failures - previous server info
	PrevServer   string `json:"prev_server,omitempty"`
	PrevProvider string `json:"prev_provider,omitempty"`
	PrevDynamic  bool   `json:"prev_dynamic,omitempty"`
	// For status responses
	DaemonState      DaemonState `json:"daemon_state,omitempty"`
	KillswitchActive bool        `json:"killswitch_active,omitempty"`
	// Styling hint for progress lines ("success", "warning")
	Hint string `json:"hint,omitempty"`
	// Health snapshot (for EventHealthState and EventStatus)
	Health *HealthState `json:"health,omitempty"`
}

// DaemonState represents the daemon's current state
type DaemonState string

const (
	StateIdle          DaemonState = "IDLE"          // Not connected (shouldn't happen much)
	StateConnecting    DaemonState = "CONNECTING"    // Connection in progress
	StateConnected     DaemonState = "CONNECTED"     // Connected and healthy
	StateUnhealthy     DaemonState = "UNHEALTHY"     // Connected but health checks failing
	StateRetrying      DaemonState = "RETRYING"      // Attempting reconnect
	StateFailover      DaemonState = "FAILOVER"      // Attempting failover to different server
	StateFailed        DaemonState = "FAILED"        // All recovery attempts exhausted
	StateSwitchFailed  DaemonState = "SWITCH_FAILED" // Switch failed, awaiting user choice
	StateDisconnecting DaemonState = "DISCONNECTING" // Disconnect in progress
)

// Status is a full status snapshot (response to status command)
type Status struct {
	State            DaemonState  `json:"state"`
	Connected        bool         `json:"connected"`
	Server           string       `json:"server,omitempty"`
	Provider         string       `json:"provider,omitempty"`
	PublicIP         string       `json:"public_ip,omitempty"`
	ConnectedSince   time.Time    `json:"connected_since,omitempty"`
	Latency          int          `json:"latency,omitempty"`
	HealthFails      int          `json:"health_fails"`
	RetryCount       int          `json:"retry_count"`
	AutoReconnect    bool         `json:"auto_reconnect"`
	AutoFailover     bool         `json:"auto_failover"`
	KillswitchActive bool         `json:"killswitch_active"`
	Health           *HealthState `json:"health,omitempty"`
}

// SocketPath returns the path to the daemon socket
func SocketPath(configDir string) string {
	return filepath.Join(configDir, ".daemon.sock")
}

// PidPath returns the path to the daemon PID file
func PidPath(configDir string) string {
	return filepath.Join(configDir, ".daemon.pid")
}

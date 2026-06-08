package daemon

import (
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
)

// HealthChecker abstracts health check operations for testing.
type HealthChecker interface {
	PingCheck() (ok bool, latencyMs int)
	DNSCheck() bool
}

// VPNConnector abstracts VPN connect/disconnect operations for testing.
type VPNConnector interface {
	Connect(cfg *config.Config, server, provider string, isDynamic bool, callback func(wireguard.ConnectionStatus)) error
	Disconnect(cfg *config.Config) error
	ForceDisconnect(cfg *config.Config)
	IsConnected(connName string) bool
}

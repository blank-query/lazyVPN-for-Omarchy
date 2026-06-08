package ui

import (
	"os"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/firewall"
)

// noopUFW is a no-op mock for firewall.UFWRunner used in UI tests.
type noopUFW struct{}

func (n *noopUFW) Run(args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == "status" {
		if len(args) > 1 && args[1] == "verbose" {
			return []byte("Status: active\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n"), nil
		}
		return []byte("Status: active\n"), nil
	}
	if len(args) > 1 && args[0] == "show" {
		return []byte(""), nil
	}
	return nil, nil
}

func TestMain(m *testing.M) {
	// Inject no-op UFW runner for all UI tests so they never
	// call real sudo ufw commands.
	firewall.SetTestMode(&noopUFW{})
	os.Exit(m.Run())
}

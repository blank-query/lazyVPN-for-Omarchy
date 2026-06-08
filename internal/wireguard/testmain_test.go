package wireguard

import (
	"os"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/firewall"
)

func TestMain(m *testing.M) {
	// Install no-op UFW runner for ALL wireguard tests.
	// This is the last line of defense — even if a test forgets to stub
	// a function-level var like firewallEnableLANBlock, the underlying
	// firewall.EnableLANBlock call will hit this noop runner instead of
	// executing real sudo ufw commands.
	firewall.SetTestMode(firewall.NoopRunner{})
	os.Exit(m.Run())
}

package firewall

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Install no-op UFW runner for ALL firewall tests.
	// This is the safety net — even if a test forgets to call setupMock,
	// the underlying runUFW will hit this noop instead of executing
	// real sudo ufw commands.
	SetTestMode(NoopRunner{})
	os.Exit(m.Run())
}

// TestSetTestModeNilPanics guards the foot-gun: SetTestMode(nil) used to
// silently restore the live UFW runner, which is exactly the wrong thing
// to do in a test cleanup (a forgotten "reset to nil" once leaked ~18
// lazyvpn:lb rules into the host firewall). The function now panics — if
// this test ever fails, the foot-gun has come back.
func TestSetTestModeNilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("SetTestMode(nil) should panic, got no panic")
		}
		// Restore the noop runner so other tests aren't affected.
		SetTestMode(NoopRunner{})
	}()
	SetTestMode(nil)
}

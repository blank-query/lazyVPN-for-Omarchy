package sudo

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Safety net: replace all func vars that run real sudo/getcap/setcap
	// commands so no test accidentally executes privileged operations.
	Authenticate = func([]byte) error { return nil }
	ProbeCache = func() bool { return false }
	ProbeCapabilities = func(string) bool { return false }
	SetCapabilities = func(string) error { return nil }

	os.Exit(m.Run())
}

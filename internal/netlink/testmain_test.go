package netlink

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	// Safety net: install a mock netlink runner so no test accidentally
	// makes real netlink syscalls (which would fail with EPERM and then
	// fall through to sudo ip/wg commands).
	SetNetlinkRunner(newMockNL())

	// Replace execCommand with a harmless no-op so any sudo fallback
	// that somehow fires just runs /bin/true.
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("true")
	}

	os.Exit(m.Run())
}

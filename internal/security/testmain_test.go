package security

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	// Safety net: replace execCommand so no test accidentally runs
	// real shred, sudo rm, systemctl, or journalctl commands.
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("true")
	}

	os.Exit(m.Run())
}

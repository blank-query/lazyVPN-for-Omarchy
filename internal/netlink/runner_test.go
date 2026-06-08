package netlink

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestRunCmdWithTimeout_ReturnsOutputOnSuccess pins the happy-path:
// a command that finishes within the timeout returns its stdout/stderr
// merged in the byte slice and a nil error. This is the baseline; the
// timeout test below relies on this branch NOT firing for control.
func TestRunCmdWithTimeout_ReturnsOutputOnSuccess(t *testing.T) {
	cmd := exec.Command("sh", "-c", "printf hello-stdout && printf hello-stderr 1>&2")
	out, err := runCmdWithTimeout(cmd, 5*time.Second)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "hello-stdout") || !strings.Contains(got, "hello-stderr") {
		t.Errorf("merged output missing expected content, got %q", got)
	}
}

// TestRunCmdWithTimeout_KillsAndReturnsTimeoutError covers the timeout
// branch of runCmdWithTimeout. A `sleep 5` capped at 200ms MUST be
// killed and the wrapping error MUST mention "timed out" so callers
// (and the user) can distinguish a wedged sudo from a sudo that just
// returned a non-zero exit code.
//
// This branch was untested. A regression where the timeout fired but
// the wrapped error didn't bubble up would leave the daemon retrying
// silently against a wedged subprocess (e.g. the documented
// post-suspend resolvectl hang).
//
// Test ceiling guard: total wall-clock must be << the actual sleep
// duration, otherwise the kill didn't fire.
func TestRunCmdWithTimeout_KillsAndReturnsTimeoutError(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	start := time.Now()
	_, err := runCmdWithTimeout(cmd, 200*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil — Kill or wrap path didn't fire")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error doesn't mention timeout: %v", err)
	}
	// Sleep was 5s, timeout was 200ms. Allow generous slack for slow CI
	// (channel scheduling, signal delivery), but cap well below the
	// natural completion time.
	if elapsed > 2*time.Second {
		t.Errorf("elapsed = %v — Kill didn't fire promptly", elapsed)
	}
}

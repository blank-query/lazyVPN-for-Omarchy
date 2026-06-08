package sudo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ErrAuthRequired is returned when sudo needs a password but we're
// running in non-interactive mode (-n). The TUI should catch this,
// show a password prompt, call Authenticate(), and retry.
var ErrAuthRequired = errors.New("sudo authentication required")

// SetCLocale appends LC_ALL=C to the command's Env so any caller that
// later inspects stderr/output for English error strings (IsAuthError,
// "operation not permitted", "incorrect password", "No such file") gets
// stable, locale-independent text. Without it, a French/German/etc.
// system returns translated messages and the matchers miss — auth-error
// recovery flows never trigger and users see generic "command failed"
// for what should have been an interactive password prompt.
//
// nil Env is preserved as "inherit parent environ" by seeding from
// os.Environ() before the append; callers that pre-set cmd.Env (e.g. a
// test fake propagating GO_WANT_HELPER_PROCESS) are not clobbered.
func SetCLocale(cmd *exec.Cmd) {
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Env = append(cmd.Env, "LC_ALL=C")
}

// IsAuthError checks if sudo output indicates a password is required.
func IsAuthError(output []byte) bool {
	s := string(output)
	return strings.Contains(s, "a password is required") ||
		strings.Contains(s, "a terminal is required") ||
		strings.Contains(s, "no tty present") ||
		strings.Contains(s, "askpass") ||
		strings.Contains(s, "sudo: a password") ||
		strings.Contains(s, "sudo: a terminal")
}

// Authenticate caches sudo credentials by piping the provided
// password to "sudo -S -v". After success, subsequent "sudo -n" commands
// within the cache timeout (typically 5 minutes) will not need a password.
//
// Takes []byte so the caller can zero the password after use.
// This is injectable for testing.
//
// Bounded with a context timeout. Without it, a wedged sudo (NSS hang,
// pam stuck) would freeze the TUI's auth prompt path forever — the
// goroutine spawned by HandleKey waits inline for the result, so the
// whole UI hangs.
var Authenticate = func(password []byte) error {
	// Build stdin data: password + newline. Zero the copy after use.
	stdinData := make([]byte, len(password)+1)
	copy(stdinData, password)
	stdinData[len(stdinData)-1] = '\n'
	defer ZeroBytes(stdinData)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-S", "-v")
	cmd.Stdin = bytes.NewReader(stdinData)
	SetCLocale(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("sudo authentication timed out — sudo may be wedged")
		}
		outStr := string(out)
		if strings.Contains(outStr, "incorrect password") ||
			strings.Contains(outStr, "Sorry") ||
			strings.Contains(outStr, "Authentication failure") {
			return fmt.Errorf("incorrect password")
		}
		return fmt.Errorf("authentication failed: %w", err)
	}
	return nil
}

// ZeroBytes overwrites every byte in the slice with zero.
// runtime.KeepAlive prevents the compiler from eliding the stores.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// ProbeCache checks whether sudo credentials are currently cached
// by running "sudo -n true". Returns true if the command succeeds
// (credentials are cached or NOPASSWD is configured).
//
// Bounded with 5s — a wedged sudo without a bound would freeze every
// caller (install flow, TUI startup, status footer). 'sudo -n true'
// completes in <50ms healthy.
var ProbeCache = func() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "true").Run() == nil
}

// ProbeCapabilities checks whether the given executable has
// CAP_NET_ADMIN file capabilities set. Uses getcap(8) which
// does not require elevated privileges. Bounded with 5s — getcap is
// nearly instant; a stuck filesystem (NFS unreachable) is the only
// realistic hang scenario.
var ProbeCapabilities = func(execPath string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getcap", execPath).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "cap_net_admin")
}

// SetCapabilities sets CAP_NET_ADMIN and CAP_NET_RAW file capabilities
// on the given executable using "sudo -n setcap". This requires either
// cached sudo credentials or a NOPASSWD sudoers entry for setcap.
// File capabilities persist on the executable and apply to any process
// that execs it, regardless of tty or session.
//
// Bounded with 10s — same rationale as the other sudo helpers.
var SetCapabilities = func(execPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-n", "setcap", "cap_net_admin,cap_net_raw+ep", execPath)
	SetCLocale(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("setcap timed out — sudo may be wedged")
		}
		if IsAuthError(out) {
			return ErrAuthRequired
		}
		return fmt.Errorf("setcap failed: %w", err)
	}
	return nil
}

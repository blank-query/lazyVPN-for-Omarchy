package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
)

// ErrAuthRequired is re-exported from the sudo package for backward compatibility.
var ErrAuthRequired = sudo.ErrAuthRequired

// SudoAuthenticate is re-exported from the sudo package for backward compatibility.
var SudoAuthenticate = sudo.Authenticate

// UFWRunner abstracts UFW operations for testing.
type UFWRunner interface {
	Run(args ...string) ([]byte, error)
}

// defaultUFWRunner runs UFW via sudo -n.
type defaultUFWRunner struct{}

func (d *defaultUFWRunner) Run(args ...string) ([]byte, error) {
	sudoArgs := append([]string{"-n", "ufw"}, args...)
	// Bound every UFW invocation. This is the foundation of all
	// firewall operations (killswitch, LAN block, IPv6 protection,
	// IsActive polling). A wedged sudo (rare: NSS hang, sched issue,
	// pam stuck) without a bound would freeze the daemon's main
	// goroutine for every connect/recover/disconnect — past SIGTERM,
	// since the goroutine can't return to the select. 10s is generous
	// for healthy sudo+ufw (typically <100ms) and short enough to
	// surface as a recoverable error rather than an apparent hang.
	ctx, cancel := context.WithTimeout(context.Background(), ufwCallTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", sudoArgs...)
	// LC_ALL=C ensures sudo's auth-required messages stay in English so
	// IsAuthError can match them. Without this, a French/German/etc.
	// system returns translated text and the auth-recovery prompt flow
	// (TUI catches ErrAuthRequired and shows the password prompt)
	// silently breaks for the entire UFW path — every killswitch /
	// LAN block operation looks like a generic command failure.
	sudo.SetCLocale(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("ufw call timed out after %s — sudo may be wedged: %s", ufwCallTimeout, strings.TrimSpace(string(out)))
	}
	if err != nil && sudo.IsAuthError(out) {
		return out, ErrAuthRequired
	}
	if err != nil {
		return out, fmt.Errorf("running [sudo ufw %s]: %w: %s", strings.Join(args, " "), err, string(out))
	}
	return out, nil
}

// ufwCallTimeout caps every defaultUFWRunner.Run invocation. See
// the comment above for rationale.
var ufwCallTimeout = 10 * time.Second

// runUFW is the global UFW runner. Tests replace this via SetTestMode.
var runUFW UFWRunner = &defaultUFWRunner{}

// NoopRunner is a UFW runner that does nothing. It can be used by tests in
// other packages (via SetTestMode) to guarantee that no real ufw commands
// are executed, even if the UI-level function stubs are somehow bypassed.
type NoopRunner struct{}

func (NoopRunner) Run(args ...string) ([]byte, error) { return nil, nil }

// SetTestMode replaces the global UFW runner with a mock for testing.
// Calling with nil panics — silently restoring the default runner mid-test
// would re-enable real `sudo ufw` invocations and could mutate the host
// firewall (which has happened: a forgotten SetTestMode(nil) in a cleanup
// left ~18 lazyvpn:lb rules in the live firewall). To deliberately reset
// for tests that genuinely want a noop, pass NoopRunner{}.
func SetTestMode(mock UFWRunner) {
	if mock == nil {
		panic("firewall.SetTestMode(nil) is forbidden — pass NoopRunner{} to reset; nil would silently restore the live UFW runner")
	}
	runUFW = mock
}

// deleteRulesByTag parses `ufw show added` and deletes all rules matching the given tag.
func deleteRulesByTag(tag string) error {
	out, err := runUFW.Run("show", "added")
	if err != nil {
		return fmt.Errorf("ufw show added: %w", err)
	}

	var firstErr error
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "comment '"+tag+"'") {
			continue
		}

		// Lines from "ufw show added" look like:
		//   ufw allow out on lo comment 'lazyvpn:ks'
		// We need to pass the args after "ufw" to "ufw delete".
		// Note: "ufw show added" wraps comment values in single quotes,
		// but "ufw delete" rejects comments containing quotes, so we
		// must strip them.
		if !strings.HasPrefix(line, "ufw ") {
			continue
		}
		ruleArgs := line[4:] // strip "ufw " prefix
		fields := strings.Fields(ruleArgs)
		for i, f := range fields {
			fields[i] = strings.Trim(f, "'")
		}
		deleteArgs := append([]string{"delete"}, fields...)
		if _, err := runUFW.Run(deleteArgs...); err != nil {
			log("Warning: failed to delete rule %q: %v", line, err)
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to delete rule %q: %w", line, err)
			}
		}
	}
	return firstErr
}

// hasRulesWithTag checks if any UFW rules exist with the given tag.
func hasRulesWithTag(tag string) bool {
	out, err := runUFW.Run("show", "added")
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "comment '"+tag+"'")
}

// getDefaultOutgoingPolicy parses `ufw status verbose` and returns the default
// outgoing policy ("allow", "deny", "reject", or "" on error).
func getDefaultOutgoingPolicy() string {
	out, err := runUFW.Run("status", "verbose")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		// Look for line like: "Default: deny (incoming), deny (outgoing), disabled (routed)"
		if strings.HasPrefix(line, "Default:") {
			// Find the outgoing policy
			parts := strings.Split(line, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.Contains(part, "(outgoing)") {
					// Extract policy word before "(outgoing)"
					fields := strings.Fields(part)
					for i, f := range fields {
						if f == "(outgoing)" && i > 0 {
							return fields[i-1]
						}
					}
				}
			}
		}
	}
	return ""
}

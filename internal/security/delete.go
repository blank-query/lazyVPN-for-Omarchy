package security

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
)

// execCommand is replaceable in tests to avoid running real shred/rm.
var execCommand = exec.Command

// deleteCmdTimeout caps every shred/rm invocation. lazyvpn-deleted
// files are all small (<64KB), so 60s is generous for shred passes
// plus any sudo prompt overhead. Without this bound a wedged sudo
// or stuck filesystem would freeze the uninstaller indefinitely.
var deleteCmdTimeout = 60 * time.Second

// runWithKillTimeout runs cmd via Start+Wait but kills the subprocess
// if it exceeds d. Mirrors the helpers in netlink and wireguard
// packages — preserves the existing execCommand var stubbing in tests
// (rather than switching to exec.CommandContext which would require
// updating multi-helper test fakes).
//
// Used by the delete pipeline (shred/rm) and CleanJournalLogs
// (systemctl stop/start). Error message is intentionally generic so
// multiple callers can wrap it without leaking implementation detail
// of the underlying subprocess.
//
// Inlines CombinedOutput's body (a shared bytes.Buffer wired to
// Stdout+Stderr) so we can capture cmd.Process AFTER Start has
// written it but BEFORE the watcher goroutine reads it. CombinedOutput
// hides this seam; without it the watcher races cmd.Start's write to
// cmd.Process — a race the runtime's race detector flags any time the
// timeout actually fires.
func runWithKillTimeout(cmd *exec.Cmd, d time.Duration) ([]byte, error) {
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// cmd.Process is written by Start (above) and never re-assigned
	// after that, so capturing it now is race-free regardless of when
	// the watcher reads.
	proc := cmd.Process

	done := make(chan struct{})
	var timedOut atomic.Bool
	go func() {
		select {
		case <-time.After(d):
			timedOut.Store(true)
			proc.Kill()
		case <-done:
		}
	}()
	err := cmd.Wait()
	close(done)
	if err != nil && timedOut.Load() {
		return b.Bytes(), fmt.Errorf("subprocess timed out after %s — sudo or backing service may be wedged", d)
	}
	return b.Bytes(), err
}

// Outcome categorizes what happened to a single file during a delete attempt.
type Outcome int

const (
	// Deleted means the file was successfully removed.
	Deleted Outcome = iota
	// NotPresent means the file didn't exist when we tried to remove it.
	// This is not an error; it's a distinct outcome so callers can render it
	// differently from a successful delete.
	NotPresent
	// Failed means the delete attempt did not succeed for a reason other
	// than the file being absent. The DeleteEvent's Err carries details.
	Failed
)

// DeleteEvent records a single attempt against a single file.
type DeleteEvent struct {
	Path    string
	Mode    string // "shred" | "sudo-shred" | "rm" | "sudo-rm"
	Outcome Outcome
	Err     error // non-nil only when Outcome == Failed
}

// DeleteResult aggregates every event from one call and their totals.
// Invariant: Deleted + NotPresent + Failed == len(Events).
type DeleteResult struct {
	Deleted    int
	NotPresent int
	Failed     int
	Events     []DeleteEvent
}

// SudoMode selects how a privileged command is invoked. Callers pick the mode
// appropriate to the context; retry paths typically escalate from SudoSilent
// to SudoInteractive.
type SudoMode int

const (
	// NoSudo runs the command directly, no sudo wrapping.
	NoSudo SudoMode = iota
	// SudoSilent runs `sudo -n <cmd>`. Succeeds only when a NOPASSWD entry
	// covers the exact command, or when sudo has a fresh cached timestamp.
	// Fails immediately with an auth error otherwise — no prompt.
	SudoSilent
	// SudoInteractive runs `sudo <cmd>` (no -n). Sudo follows its own policy:
	// prompts for password if the sudoers entry requires one, runs silently
	// if NOPASSWD covers the command. The password prompt goes to /dev/tty,
	// so captured stdout/stderr remain clean.
	SudoInteractive
)

// SecureDelete attempts to overwrite then unlink each file using `shred -u`.
// This is the appropriate tool on traditional filesystems (ext4, xfs) where
// writes land on the same physical blocks as the original data.
//
// On copy-on-write filesystems (btrfs, ZFS), shred writes new extents while
// the original content remains on disk — callers should use PlainDelete
// instead on those filesystems. DeleteForFS picks the correct function.
//
// The function is pure: it does not prompt, it does not fall back, and it
// does not emit output. Failed attempts produce Failed events carrying the
// command's stderr; callers are responsible for surfacing failures to users.
func SecureDelete(files []string, mode SudoMode) DeleteResult {
	result := DeleteResult{}
	for _, f := range files {
		e := shredOne(f, mode)
		appendEvent(&result, e)
	}
	return result
}

// PlainDelete attempts to unlink each file using `rm`. On copy-on-write
// filesystems this is LazyVPN's primary delete path; on traditional
// filesystems it's available as the fallback when SecureDelete fails.
//
// Semantics match SecureDelete: pure, no fallback, no output. Per-file
// events record Deleted, NotPresent, or Failed.
func PlainDelete(files []string, mode SudoMode) DeleteResult {
	result := DeleteResult{}
	for _, f := range files {
		e := rmOne(f, mode)
		appendEvent(&result, e)
	}
	return result
}

// DeleteFunc is the signature shared by SecureDelete and PlainDelete. Handy
// for callers that hold the chosen function in a variable after consulting
// DeleteForFS.
type DeleteFunc = func([]string, SudoMode) DeleteResult

// DeleteForFS picks the appropriate primary delete function for a filesystem.
// Callers resolve this once at the top of their flow and call the returned
// function thereafter, so the CoW/non-CoW decision lives in a single place
// per-operation rather than being repeated at every call site.
func DeleteForFS(cowFilesystem bool) DeleteFunc {
	if cowFilesystem {
		return PlainDelete
	}
	return SecureDelete
}

// shredOne runs `shred -u <path>` in the requested mode and returns one event.
func shredOne(path string, mode SudoMode) DeleteEvent {
	cmd, label := buildCmd("shred", []string{"-u", path}, mode)
	return classify(cmd, path, label)
}

// rmOne runs `rm <path>` in the requested mode and returns one event.
// The `-f` flag is deliberately omitted so `rm` reports missing files via
// stderr ("No such file"). This lets us classify NotPresent distinctly from
// Deleted; with `-f`, both would exit 0 and we'd lose the signal.
func rmOne(path string, mode SudoMode) DeleteEvent {
	cmd, label := buildCmd("rm", []string{path}, mode)
	return classify(cmd, path, label)
}

// buildCmd constructs the exec.Cmd for a tool invocation at the given mode
// and returns the command plus the human-readable Mode label (for events).
//
// LC_ALL=C is forced so classify() can match "No such file" reliably —
// without it, French/German/etc. locales translate the error message and
// NotPresent gets misclassified as Failed.
func buildCmd(tool string, args []string, mode SudoMode) (*exec.Cmd, string) {
	var cmd *exec.Cmd
	var label string
	switch mode {
	case SudoSilent:
		prefix := []string{"-n", tool}
		cmd = execCommand("sudo", append(prefix, args...)...)
		label = "sudo-" + tool
	case SudoInteractive:
		prefix := []string{tool}
		cmd = execCommand("sudo", append(prefix, args...)...)
		label = "sudo-" + tool
	default: // NoSudo
		cmd = execCommand(tool, args...)
		label = tool
	}
	// Append LC_ALL=C without clobbering any pre-set env (test fakes set
	// GO_WANT_HELPER_PROCESS via cmd.Env). exec.Cmd treats nil Env as "use
	// the parent's environ"; preserve that semantics by seeding from
	// os.Environ() when Env is nil.
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Env = append(cmd.Env, "LC_ALL=C")
	return cmd, label
}

// classify runs the command, interprets the outcome, and returns a single
// DeleteEvent. The classification rules:
//
//   - Exit 0 → Deleted.
//   - Non-zero exit whose combined output contains "No such file" → NotPresent.
//   - Any other non-zero exit → Failed, with Err carrying the trimmed output
//     so the caller can render it for bug reports.
//
// This attempt-and-interpret approach avoids an os.Stat precheck, which
// would fail with EACCES on files in directories we can't traverse (e.g.
// /etc/sudoers.d/ at 0750) and get silently mis-classified as NotPresent.
// Letting the deletion tool itself report its findings is uniform across
// every path and permission combination.
//
// Bounded with a wall-clock watcher: a wedged sudo (or, for shred, a
// stuck filesystem) without a bound would freeze the uninstaller
// indefinitely. lazyvpn-deleted files are all small (<64KB), so 60s
// is generous for shred + sudo prompt overhead.
func classify(cmd *exec.Cmd, path, modeLabel string) DeleteEvent {
	out, err := runWithKillTimeout(cmd, deleteCmdTimeout)
	if err == nil {
		return DeleteEvent{Path: path, Mode: modeLabel, Outcome: Deleted}
	}
	if bytes.Contains(out, []byte("No such file")) {
		return DeleteEvent{Path: path, Mode: modeLabel, Outcome: NotPresent}
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		msg = err.Error()
	}
	return DeleteEvent{
		Path:    path,
		Mode:    modeLabel,
		Outcome: Failed,
		Err:     fmt.Errorf("%s", msg),
	}
}

// appendEvent records an event and updates the matching counter.
func appendEvent(r *DeleteResult, e DeleteEvent) {
	r.Events = append(r.Events, e)
	switch e.Outcome {
	case Deleted:
		r.Deleted++
	case NotPresent:
		r.NotPresent++
	case Failed:
		r.Failed++
	}
}

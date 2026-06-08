package security

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- TestHelperProcess pattern for exec.Command mocking ---
//
// Each fakeExecCommand* helper returns an exec.Command that, when invoked,
// re-executes the test binary with -test.run=TestHelperProcess. The helper
// process reads env vars to decide exit code and stderr output, then exits.
// This lets tests simulate real command behavior without running shred/rm.

// fakeExecCommandSuccess returns a fake exec.Command that exits 0.
func fakeExecCommandSuccess(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "HELPER_EXIT_CODE=0")
	return cmd
}

// fakeExecCommandFail returns a fake exec.Command that exits 1.
func fakeExecCommandFail(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "HELPER_EXIT_CODE=1")
	return cmd
}

// fakeExecCommandWithStderr returns a factory producing fake exec.Commands
// that write the given stderr text and exit with the given code. Used to
// simulate tool output like shred's "No such file" message.
func fakeExecCommandWithStderr(exitCode int, stderrText string) func(string, ...string) *exec.Cmd {
	return func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = append(os.Environ(),
			"GO_WANT_HELPER_PROCESS=1",
			fmt.Sprintf("HELPER_EXIT_CODE=%d", exitCode),
			"HELPER_STDERR="+stderrText,
		)
		return cmd
	}
}

// TestHelperProcess is the helper process that fake exec commands invoke.
// Exits based on HELPER_EXIT_CODE, optionally writing HELPER_STDERR first.
// Not a real test — only runs when GO_WANT_HELPER_PROCESS=1.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if s := os.Getenv("HELPER_STDERR"); s != "" {
		fmt.Fprint(os.Stderr, s)
	}
	if code, err := strconv.Atoi(os.Getenv("HELPER_EXIT_CODE")); err == nil && code != 0 {
		os.Exit(code)
	}
	os.Exit(0)
}

// setExecCommand replaces execCommand for a test and schedules cleanup.
func setExecCommand(t *testing.T, fn func(string, ...string) *exec.Cmd) {
	t.Helper()
	orig := execCommand
	execCommand = fn
	t.Cleanup(func() { execCommand = orig })
}

// --- SudoMode + buildCmd tests ---

func TestBuildCmdNoSudo(t *testing.T) {
	var captured []string
	setExecCommand(t, func(name string, args ...string) *exec.Cmd {
		captured = append([]string{name}, args...)
		return fakeExecCommandSuccess(name, args...)
	})

	shredOne("/tmp/foo", NoSudo)

	want := []string{"shred", "-u", "/tmp/foo"}
	if !reflect.DeepEqual(captured, want) {
		t.Errorf("NoSudo command = %v, want %v", captured, want)
	}
}

func TestBuildCmdSudoSilent(t *testing.T) {
	var captured []string
	setExecCommand(t, func(name string, args ...string) *exec.Cmd {
		captured = append([]string{name}, args...)
		return fakeExecCommandSuccess(name, args...)
	})

	shredOne("/etc/foo", SudoSilent)

	want := []string{"sudo", "-n", "shred", "-u", "/etc/foo"}
	if !reflect.DeepEqual(captured, want) {
		t.Errorf("SudoSilent command = %v, want %v", captured, want)
	}
}

func TestBuildCmdSudoInteractive(t *testing.T) {
	var captured []string
	setExecCommand(t, func(name string, args ...string) *exec.Cmd {
		captured = append([]string{name}, args...)
		return fakeExecCommandSuccess(name, args...)
	})

	shredOne("/etc/foo", SudoInteractive)

	want := []string{"sudo", "shred", "-u", "/etc/foo"}
	if !reflect.DeepEqual(captured, want) {
		t.Errorf("SudoInteractive command = %v, want %v", captured, want)
	}
}

func TestBuildCmdPlainRmNoSudo(t *testing.T) {
	var captured []string
	setExecCommand(t, func(name string, args ...string) *exec.Cmd {
		captured = append([]string{name}, args...)
		return fakeExecCommandSuccess(name, args...)
	})

	rmOne("/tmp/foo", NoSudo)

	want := []string{"rm", "/tmp/foo"}
	if !reflect.DeepEqual(captured, want) {
		t.Errorf("NoSudo rm command = %v, want %v", captured, want)
	}
}

func TestBuildCmdPlainRmSudoSilent(t *testing.T) {
	var captured []string
	setExecCommand(t, func(name string, args ...string) *exec.Cmd {
		captured = append([]string{name}, args...)
		return fakeExecCommandSuccess(name, args...)
	})

	rmOne("/etc/foo", SudoSilent)

	want := []string{"sudo", "-n", "rm", "/etc/foo"}
	if !reflect.DeepEqual(captured, want) {
		t.Errorf("SudoSilent rm command = %v, want %v", captured, want)
	}
}

// --- SecureDelete outcome tests ---

func TestSecureDeleteSingleFileDeleted(t *testing.T) {
	setExecCommand(t, fakeExecCommandSuccess)

	r := SecureDelete([]string{"/tmp/file"}, NoSudo)

	if r.Deleted != 1 || r.NotPresent != 0 || r.Failed != 0 {
		t.Errorf("counters = %d/%d/%d, want 1/0/0", r.Deleted, r.NotPresent, r.Failed)
	}
	if len(r.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(r.Events))
	}
	e := r.Events[0]
	if e.Outcome != Deleted || e.Mode != "shred" || e.Path != "/tmp/file" {
		t.Errorf("event = %+v, want Deleted shred /tmp/file", e)
	}
	if e.Err != nil {
		t.Errorf("Err = %v on Deleted, want nil", e.Err)
	}
}

func TestSecureDeleteFileNotPresent(t *testing.T) {
	setExecCommand(t, fakeExecCommandWithStderr(1, "shred: cannot open '/tmp/missing' for writing: No such file or directory\n"))

	r := SecureDelete([]string{"/tmp/missing"}, NoSudo)

	if r.NotPresent != 1 || r.Deleted != 0 || r.Failed != 0 {
		t.Errorf("counters = %d/%d/%d, want 0/1/0", r.Deleted, r.NotPresent, r.Failed)
	}
	if r.Events[0].Outcome != NotPresent {
		t.Errorf("outcome = %v, want NotPresent", r.Events[0].Outcome)
	}
	if r.Events[0].Err != nil {
		t.Errorf("Err = %v on NotPresent, want nil", r.Events[0].Err)
	}
}

func TestSecureDeleteGenuineFailure(t *testing.T) {
	setExecCommand(t, fakeExecCommandWithStderr(1, "shred: /tmp/locked: failed to open for writing: Device or resource busy\n"))

	r := SecureDelete([]string{"/tmp/locked"}, NoSudo)

	if r.Failed != 1 || r.Deleted != 0 || r.NotPresent != 0 {
		t.Errorf("counters = %d/%d/%d, want 0/0/1", r.Deleted, r.NotPresent, r.Failed)
	}
	e := r.Events[0]
	if e.Outcome != Failed {
		t.Errorf("outcome = %v, want Failed", e.Outcome)
	}
	if e.Err == nil {
		t.Fatal("Err = nil on Failed, want non-nil")
	}
	if !strings.Contains(e.Err.Error(), "Device or resource busy") {
		t.Errorf("Err should contain stderr text, got: %v", e.Err)
	}
}

func TestSecureDeleteBatchMixedOutcomes(t *testing.T) {
	call := 0
	setExecCommand(t, func(name string, args ...string) *exec.Cmd {
		call++
		switch call {
		case 1:
			return fakeExecCommandSuccess(name, args...)
		case 2:
			return fakeExecCommandWithStderr(1, "shred: No such file\n")(name, args...)
		default:
			return fakeExecCommandWithStderr(1, "shred: I/O error\n")(name, args...)
		}
	})

	r := SecureDelete([]string{"/tmp/a", "/tmp/b", "/tmp/c"}, NoSudo)

	if r.Deleted != 1 || r.NotPresent != 1 || r.Failed != 1 {
		t.Errorf("counters = %d/%d/%d, want 1/1/1", r.Deleted, r.NotPresent, r.Failed)
	}
	if r.Deleted+r.NotPresent+r.Failed != len(r.Events) {
		t.Errorf("counter/event invariant broken: %d+%d+%d vs len=%d",
			r.Deleted, r.NotPresent, r.Failed, len(r.Events))
	}
	if r.Events[0].Path != "/tmp/a" || r.Events[1].Path != "/tmp/b" || r.Events[2].Path != "/tmp/c" {
		t.Errorf("events out of order: %v", r.Events)
	}
}

func TestSecureDeleteEmptyInput(t *testing.T) {
	setExecCommand(t, func(name string, args ...string) *exec.Cmd {
		t.Errorf("execCommand should not be called for empty input")
		return fakeExecCommandSuccess(name, args...)
	})

	r := SecureDelete(nil, NoSudo)

	if r.Deleted != 0 || r.NotPresent != 0 || r.Failed != 0 || len(r.Events) != 0 {
		t.Errorf("empty result = %+v, want all zero", r)
	}
}

func TestSecureDeleteSudoModeLabels(t *testing.T) {
	cases := []struct {
		mode      SudoMode
		wantLabel string
	}{
		{NoSudo, "shred"},
		{SudoSilent, "sudo-shred"},
		{SudoInteractive, "sudo-shred"},
	}
	for _, c := range cases {
		setExecCommand(t, fakeExecCommandSuccess)
		r := SecureDelete([]string{"/tmp/x"}, c.mode)
		if r.Events[0].Mode != c.wantLabel {
			t.Errorf("mode %v → label %q, want %q", c.mode, r.Events[0].Mode, c.wantLabel)
		}
	}
}

// --- PlainDelete outcome tests ---

func TestPlainDeleteSingleFileDeleted(t *testing.T) {
	setExecCommand(t, fakeExecCommandSuccess)

	r := PlainDelete([]string{"/tmp/file"}, NoSudo)

	if r.Deleted != 1 {
		t.Errorf("Deleted = %d, want 1", r.Deleted)
	}
	if r.Events[0].Mode != "rm" {
		t.Errorf("Mode = %q, want %q", r.Events[0].Mode, "rm")
	}
}

func TestPlainDeleteFileNotPresent(t *testing.T) {
	setExecCommand(t, fakeExecCommandWithStderr(1, "rm: cannot remove '/tmp/missing': No such file or directory\n"))

	r := PlainDelete([]string{"/tmp/missing"}, NoSudo)

	if r.NotPresent != 1 {
		t.Errorf("NotPresent = %d, want 1", r.NotPresent)
	}
}

func TestPlainDeleteGenuineFailure(t *testing.T) {
	setExecCommand(t, fakeExecCommandWithStderr(1, "rm: cannot remove '/tmp/readonly': Permission denied\n"))

	r := PlainDelete([]string{"/tmp/readonly"}, NoSudo)

	if r.Failed != 1 {
		t.Errorf("Failed = %d, want 1", r.Failed)
	}
	if r.Events[0].Err == nil {
		t.Fatal("Err = nil on Failed")
	}
	if !strings.Contains(r.Events[0].Err.Error(), "Permission denied") {
		t.Errorf("Err should contain stderr, got: %v", r.Events[0].Err)
	}
}

func TestPlainDeleteSudoModeLabels(t *testing.T) {
	cases := []struct {
		mode      SudoMode
		wantLabel string
	}{
		{NoSudo, "rm"},
		{SudoSilent, "sudo-rm"},
		{SudoInteractive, "sudo-rm"},
	}
	for _, c := range cases {
		setExecCommand(t, fakeExecCommandSuccess)
		r := PlainDelete([]string{"/tmp/x"}, c.mode)
		if r.Events[0].Mode != c.wantLabel {
			t.Errorf("mode %v → label %q, want %q", c.mode, r.Events[0].Mode, c.wantLabel)
		}
	}
}

// --- DeleteForFS dispatcher tests ---

func TestDeleteForFSCoW(t *testing.T) {
	setExecCommand(t, fakeExecCommandSuccess)
	fn := DeleteForFS(true)
	r := fn([]string{"/tmp/x"}, NoSudo)
	if r.Events[0].Mode != "rm" {
		t.Errorf("CoW dispatch produced Mode %q, want %q (PlainDelete)", r.Events[0].Mode, "rm")
	}
}

func TestDeleteForFSNonCoW(t *testing.T) {
	setExecCommand(t, fakeExecCommandSuccess)
	fn := DeleteForFS(false)
	r := fn([]string{"/tmp/x"}, NoSudo)
	if r.Events[0].Mode != "shred" {
		t.Errorf("non-CoW dispatch produced Mode %q, want %q (SecureDelete)", r.Events[0].Mode, "shred")
	}
}

// --- classify / runDelete edge cases ---

func TestClassifyBlankStderrFallsBackToErrString(t *testing.T) {
	// Exit non-zero, no stderr output. classify should still produce a Failed
	// event with a non-nil Err so the caller has something to report.
	setExecCommand(t, fakeExecCommandFail)

	r := SecureDelete([]string{"/tmp/x"}, NoSudo)

	if r.Failed != 1 {
		t.Errorf("Failed = %d, want 1", r.Failed)
	}
	if r.Events[0].Err == nil {
		t.Fatal("Err = nil on Failed with blank stderr, want non-nil")
	}
}

func TestClassifyNotPresentTakesPrecedenceOverExitCode(t *testing.T) {
	// Any exit code with "No such file" in stderr is NotPresent, not Failed.
	setExecCommand(t, fakeExecCommandWithStderr(2, "shred: /tmp/x: No such file or directory\n"))

	r := SecureDelete([]string{"/tmp/x"}, NoSudo)

	if r.NotPresent != 1 {
		t.Errorf("NotPresent = %d, want 1 (stderr mentions 'No such file')", r.NotPresent)
	}
}

// --- Outcome enum invariant ---

func TestOutcomeEnumValues(t *testing.T) {
	if Deleted != 0 || NotPresent != 1 || Failed != 2 {
		t.Errorf("Outcome enum values changed: Deleted=%d NotPresent=%d Failed=%d",
			Deleted, NotPresent, Failed)
	}
}

// --- DeleteFunc signature compatibility ---

func TestDeleteFuncAssignability(t *testing.T) {
	// Ensures SecureDelete and PlainDelete both satisfy DeleteFunc.
	var _ DeleteFunc = SecureDelete
	var _ DeleteFunc = PlainDelete
	var _ DeleteFunc = DeleteForFS(true)
	var _ DeleteFunc = DeleteForFS(false)
}

// --- Sanity: ensure we didn't accidentally re-introduce deps ---

func TestEventFailedCarriesError(t *testing.T) {
	setExecCommand(t, fakeExecCommandWithStderr(1, "something went wrong\n"))
	r := SecureDelete([]string{"/tmp/x"}, NoSudo)
	if r.Events[0].Outcome != Failed {
		t.Fatal("expected Failed")
	}
	var pathErr *os.PathError
	if errors.As(r.Events[0].Err, &pathErr) {
		t.Errorf("Err unexpectedly wraps PathError: %v", pathErr)
	}
}

// TestRunWithKillTimeout_KillsHungSubprocess verifies that
// runWithKillTimeout actually kills a wedged subprocess and returns
// the timeout error rather than waiting forever. This is the
// foundation of the security package's resilience to wedged sudo /
// systemctl / shred — every CleanJournalLogs and SecureDelete call
// relies on this helper to bound subprocess wall-clock time.
func TestRunWithKillTimeout_KillsHungSubprocess(t *testing.T) {
	// `sleep 30` will outlive our 200ms deadline. The helper should
	// kill it and return a timeout-shaped error.
	cmd := exec.Command("sleep", "30")

	start := time.Now()
	_, err := runWithKillTimeout(cmd, 200*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil — runWithKillTimeout did not kill the hung subprocess")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %v, want a timeout-shaped error", err)
	}
	// Should return shortly after the 200ms deadline. Generous slack
	// for goroutine scheduling + subprocess kill, but well under 30s.
	if elapsed > 2*time.Second {
		t.Errorf("runWithKillTimeout took %v to return — subprocess wasn't killed promptly", elapsed)
	}
}

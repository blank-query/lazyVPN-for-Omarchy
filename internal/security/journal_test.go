package security

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
)

// --- Shared test helpers ---

// mockDeleteAllSucceed is a DeleteFunc that records every call and reports
// every file as Deleted. Useful for tests that don't care about delete
// semantics, only that deleteFn is wired through.
func mockDeleteAllSucceed(files []string, mode SudoMode) DeleteResult {
	r := DeleteResult{}
	for _, f := range files {
		r.Events = append(r.Events, DeleteEvent{
			Path:    f,
			Mode:    "mock",
			Outcome: Deleted,
		})
		r.Deleted++
	}
	return r
}

// --- filterHistoryLines tests ---

func TestFilterHistoryLinesRemovesLazyVPN(t *testing.T) {
	lines := []string{
		"ls -la",
		"lazyvpn-connect server1",
		"echo hello",
		"LAZYVPN_CONFIG=foo",
	}
	got := filterHistoryLines(lines, "wg-lazyvpn")
	want := []string{"ls -la", "echo hello"}
	assertStringSliceEqual(t, got, want)
}

func TestFilterHistoryLinesRemovesWireguard(t *testing.T) {
	lines := []string{
		"git status",
		"sudo wg show",
		"wireguard config test",
		"cat /etc/wireguard/wg0.conf",
	}
	got := filterHistoryLines(lines, "wg-lazyvpn")
	want := []string{"git status", "sudo wg show"}
	assertStringSliceEqual(t, got, want)
}

func TestFilterHistoryLinesRemovesInterfaceName(t *testing.T) {
	lines := []string{
		"ip link show",
		"ip link show wg-lazyvpn",
		"networkctl status wg-lazyvpn",
		"systemctl restart nginx",
	}
	got := filterHistoryLines(lines, "wg-lazyvpn")
	want := []string{"ip link show", "systemctl restart nginx"}
	assertStringSliceEqual(t, got, want)
}

func TestFilterHistoryLinesRemovesProviderConf(t *testing.T) {
	lines := []string{
		"vim notes.txt",
		"cat proton-us.conf",
		"cp mullvad-se.conf /tmp/",
		"nano ivpn-config.conf",
		"cat airvpn-au.conf",
		"cat nord-us.conf",
		"cp surfshark-uk.conf /tmp/",
		"nano windscribe-de.conf",
		"cat fastestvpn-jp.conf",
		"cat random.conf",
		"cat config.json",
		"echo proton is a service",
	}
	got := filterHistoryLines(lines, "wg-lazyvpn")
	want := []string{
		"vim notes.txt",
		"cat random.conf",
		"cat config.json",
		"echo proton is a service",
	}
	assertStringSliceEqual(t, got, want)
}

func TestFilterHistoryLinesKeepsUnrelated(t *testing.T) {
	lines := []string{
		"cd /home/user",
		"git commit -m 'fix bug'",
		"make build",
		"docker compose up -d",
		"ssh user@host",
	}
	got := filterHistoryLines(lines, "wg-lazyvpn")
	if len(got) != len(lines) {
		t.Errorf("length mismatch: got %d, want %d", len(got), len(lines))
	}
}

func TestFilterHistoryLinesEmptyInput(t *testing.T) {
	got := filterHistoryLines([]string{}, "wg-lazyvpn")
	if got != nil {
		t.Errorf("expected nil for empty input, got %v", got)
	}
}

func TestFilterHistoryLinesNilInput(t *testing.T) {
	got := filterHistoryLines(nil, "wg-lazyvpn")
	if got != nil {
		t.Errorf("expected nil for nil input, got %v", got)
	}
}

// Defense-in-depth regression: with interfaceName == "", the unguarded
// strings.Contains(lower, "") returned true for every line — wiping the
// user's entire shell history. Current callers always pass a non-empty
// connName (config.validate resets it to "wg0" if empty), but this is
// rm -rf-grade behavior if any future code path ever drops that
// invariant. The sibling scanJournalForVPN already guards via
// `(ifaceLower != "" && ...)` — make filterHistoryLines symmetric.
func TestFilterHistoryLines_EmptyInterfaceNameDoesNotNukeEverything(t *testing.T) {
	lines := []string{
		"cd /home/user",
		"git commit -m 'fix bug'",
		"make build",
		"docker compose up -d",
		"ssh user@host",
	}
	got := filterHistoryLines(lines, "")
	if len(got) != len(lines) {
		t.Fatalf("empty interfaceName wiped %d/%d unrelated lines", len(lines)-len(got), len(lines))
	}
	// VPN-related lines should still be filtered even with no interface name.
	mixed := []string{"cd /tmp", "lazyvpn random", "git status", "wireguard noise"}
	got2 := filterHistoryLines(mixed, "")
	if len(got2) != 2 {
		t.Errorf("expected 2 surviving lines (cd, git), got %d: %v", len(got2), got2)
	}
}

func TestFilterHistoryLinesAllMatch(t *testing.T) {
	lines := []string{
		"lazyvpn-connect",
		"wireguard status",
		"ip link set wg-lazyvpn up",
	}
	got := filterHistoryLines(lines, "wg-lazyvpn")
	if got != nil {
		t.Errorf("expected nil when all lines filtered, got %v", got)
	}
}

func TestFilterHistoryLinesSingleCleanLine(t *testing.T) {
	lines := []string{"echo hello"}
	got := filterHistoryLines(lines, "wg-lazyvpn")
	want := []string{"echo hello"}
	assertStringSliceEqual(t, got, want)
}

func TestFilterHistoryLinesInterfaceNameCaseMismatch(t *testing.T) {
	lines := []string{
		"ip link show WG-LAZYVPN",
		"ip link show Wg-LazyVPN",
	}
	got := filterHistoryLines(lines, "wg-lazyvpn")
	if len(got) != 0 {
		t.Errorf("expected case-insensitive match on interface, got %v", got)
	}
}

func TestFilterHistoryLinesCustomInterfaceName(t *testing.T) {
	lines := []string{
		"ip link show myinterface0",
		"ping google.com",
		"systemctl status myinterface0",
	}
	got := filterHistoryLines(lines, "myinterface0")
	want := []string{"ping google.com"}
	assertStringSliceEqual(t, got, want)
}

func TestFilterHistoryLinesEmptyLines(t *testing.T) {
	lines := []string{
		"echo hello",
		"",
		"echo world",
		"",
	}
	got := filterHistoryLines(lines, "wg-lazyvpn")
	assertStringSliceEqual(t, got, lines)
}

func TestFilterHistoryLinesProviderNameInsideConfOnly(t *testing.T) {
	lines := []string{
		"proton bridge start",
		"mullvad api check",
		"ivpn status",
	}
	got := filterHistoryLines(lines, "wg-lazyvpn")
	assertStringSliceEqual(t, got, lines)
}

// --- cleanHistoryFiles tests ---

func TestCleanHistoryFilesWithVPNCommands(t *testing.T) {
	setExecCommand(t, fakeExecCommandSuccess)

	tmpDir := t.TempDir()
	histFile := filepath.Join(tmpDir, ".bash_history")
	content := strings.Join([]string{
		"git status",
		"lazyvpn-connect us-east",
		"wireguard show all",
		"echo hello world",
		"cat proton-us.conf",
		"make build",
	}, "\n")
	os.WriteFile(histFile, []byte(content), 0600)

	cleaned, skipped := cleanHistoryFiles([]string{histFile}, "wg-lazyvpn")

	if cleaned != 1 {
		t.Errorf("cleaned = %d, want 1", cleaned)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}

	result, err := os.ReadFile(histFile)
	if err != nil {
		t.Fatalf("failed to read cleaned file: %v", err)
	}
	resultLines := strings.Split(string(result), "\n")
	expected := []string{"git status", "echo hello world", "make build"}
	assertStringSliceEqual(t, resultLines, expected)
}

func TestCleanHistoryFilesNoVPNCommands(t *testing.T) {
	tmpDir := t.TempDir()
	histFile := filepath.Join(tmpDir, ".zsh_history")
	content := strings.Join([]string{
		"cd /home/user",
		"git push origin main",
		"docker build .",
	}, "\n")
	os.WriteFile(histFile, []byte(content), 0600)

	cleaned, skipped := cleanHistoryFiles([]string{histFile}, "wg-lazyvpn")

	if cleaned != 0 {
		t.Errorf("cleaned = %d, want 0", cleaned)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

func TestCleanHistoryFilesNoFilesExist(t *testing.T) {
	cleaned, skipped := cleanHistoryFiles([]string{
		"/nonexistent/.bash_history",
		"/nonexistent/.zsh_history",
	}, "wg-lazyvpn")

	if cleaned != 0 {
		t.Errorf("cleaned = %d, want 0", cleaned)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
}

func TestCleanHistoryFilesMultipleFiles(t *testing.T) {
	setExecCommand(t, fakeExecCommandSuccess)

	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, ".bash_history")
	os.WriteFile(f1, []byte("lazyvpn-connect\ngit status"), 0600)
	f2 := filepath.Join(tmpDir, ".zsh_history")
	os.WriteFile(f2, []byte("echo hello\nls -la"), 0600)

	cleaned, skipped := cleanHistoryFiles([]string{f1, f2}, "wg-lazyvpn")

	if cleaned != 1 {
		t.Errorf("cleaned = %d, want 1", cleaned)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

func TestCleanHistoryFilesEmptyList(t *testing.T) {
	cleaned, skipped := cleanHistoryFiles([]string{}, "wg-lazyvpn")
	if cleaned != 0 || skipped != 0 {
		t.Errorf("expected 0,0 for empty list, got %d,%d", cleaned, skipped)
	}
}

// TestCleanHistoryFilesAtomicReplacePreservesContent ensures the rewrite
// step replaces the history file atomically. After clean, the user's
// non-VPN history must still be readable — no window where the file is
// gone (the previous deleteFn-then-rename order had this hole).
func TestCleanHistoryFilesAtomicReplacePreservesContent(t *testing.T) {
	tmpDir := t.TempDir()
	histFile := filepath.Join(tmpDir, ".bash_history")
	original := "git status\nlazyvpn connect\nls -la\nlazyvpn disconnect\necho hello\n"
	os.WriteFile(histFile, []byte(original), 0600)

	cleanHistoryFiles([]string{histFile}, "lazyvpn")

	got, err := os.ReadFile(histFile)
	if err != nil {
		t.Fatalf("history file should exist after rewrite: %v", err)
	}
	if strings.Contains(string(got), "lazyvpn") {
		t.Errorf("history still contains lazyvpn lines after clean: %q", string(got))
	}
	for _, want := range []string{"git status", "ls -la", "echo hello"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("expected non-VPN line %q to survive, full content: %q", want, string(got))
		}
	}
	// No leftover .tmp sidecar.
	if _, err := os.Stat(histFile + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".tmp sidecar should not remain after successful rename")
	}
}

// TestCleanHistoryFiles_UnreadableFileSilentlySkipped documents current
// behavior when a history-file path passes os.Stat (exists) but os.ReadFile
// fails — typically because the path is a directory, has perms 0000, or
// is a special file. The function continues without incrementing either
// counter — the user gets neither "cleaned" nor "skipped" for that path.
//
// This pins the silent-continue branch as intentional behavior. A future
// refactor that turned this into a fatal error would silently break the
// uninstaller for users whose history file is permission-locked. If the
// behavior should change to "count as skipped" or "log a warning",
// update this test to enforce the new contract — that's the point.
//
// Triggered by passing a directory as the history path: os.Stat sees
// it exists, os.ReadFile returns "is a directory" error.
func TestCleanHistoryFiles_UnreadableFileSilentlySkipped(t *testing.T) {
	tmpDir := t.TempDir()
	fakeHist := filepath.Join(tmpDir, ".bash_history")
	if err := os.MkdirAll(fakeHist, 0755); err != nil {
		t.Fatal(err)
	}

	cleaned, skipped := cleanHistoryFiles([]string{fakeHist}, "wg-lazyvpn")

	if cleaned != 0 {
		t.Errorf("cleaned = %d, want 0 (unreadable file should not count as cleaned)", cleaned)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0 (current behavior is silent-continue, not skip)", skipped)
	}
}

// --- CleanShellHistory wrapper test ---

func TestCleanShellHistoryWrapper(t *testing.T) {
	// CleanShellHistory resolves home-dir paths and delegates. May process
	// zero files on systems without any shell history; we just verify it
	// runs to completion.
	setExecCommand(t, fakeExecCommandSuccess)
	CleanShellHistory("wg-test-interface")
}

// --- CleanJournalLogs helpers ---

func setJournalBaseDirs(t *testing.T, dirs []string) {
	t.Helper()
	orig := journalBaseDirs
	journalBaseDirs = dirs
	t.Cleanup(func() { journalBaseDirs = orig })
}

func setReadMachineID(t *testing.T, id string, err error) {
	t.Helper()
	orig := readMachineIDFunc
	readMachineIDFunc = func() ([]byte, error) {
		return []byte(id + "\n"), err
	}
	t.Cleanup(func() { readMachineIDFunc = orig })
}

// captureStdout runs fn while capturing its stdout output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	fn()

	w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = oldStdout
	return string(out)
}

// TestHelperProcessJournalctl outputs VPN-flagged content to simulate
// journalctl finding LazyVPN evidence.
func TestHelperProcessJournalctl(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_JOURNALCTL") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, "Jan 01 12:00:00 host lazyvpn-connect[1234]: connecting to server")
	os.Exit(0)
}

// TestHelperProcessJournalctlClean outputs non-VPN content.
func TestHelperProcessJournalctlClean(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_JOURNALCTL_CLEAN") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, "Jan 01 12:00:00 host systemd[1]: Started nginx.service")
	os.Exit(0)
}

// TestHelperProcessJournalctlIfaceOnly outputs content that mentions
// ONLY the interface name (no lazyvpn / wireguard substrings) — for
// the iface-match arm of scanJournalForVPN's disjunction.
func TestHelperProcessJournalctlIfaceOnly(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_JOURNALCTL_IFACE_ONLY") != "1" {
		return
	}
	// No "lazyvpn" or "wireguard" — only "wg0" (the iface).
	fmt.Fprintln(os.Stdout, "Jan 01 12:00:00 host kernel: wg0: link becomes ready")
	os.Exit(0)
}

// --- CleanJournalLogs tests ---

func TestCleanJournalLogsMachineIDFails(t *testing.T) {
	setReadMachineID(t, "", fmt.Errorf("no machine-id"))
	setExecCommand(t, fakeExecCommandSuccess)

	res, err := CleanJournalLogs("wg-lazyvpn", mockDeleteAllSucceed, SudoInteractive)
	if err == nil {
		t.Fatal("expected error from failed machine-id read")
	}
	if !strings.Contains(err.Error(), "failed to read machine-id") {
		t.Errorf("unexpected error: %v", err)
	}
	if res.WithEvidence != 0 {
		t.Errorf("WithEvidence = %d, want 0", res.WithEvidence)
	}
}

func TestCleanJournalLogsJournalDirNotFound(t *testing.T) {
	setReadMachineID(t, "nonexistent-for-test", nil)
	setJournalBaseDirs(t, []string{"/var/log/journal-nonexistent"})
	setExecCommand(t, fakeExecCommandSuccess)

	res, err := CleanJournalLogs("wg-lazyvpn", mockDeleteAllSucceed, SudoInteractive)
	if err == nil {
		t.Fatal("expected error for journal directory not found")
	}
	if !strings.Contains(err.Error(), "journal directory not found") {
		t.Errorf("unexpected error: %v", err)
	}
	if res.WithEvidence != 0 {
		t.Errorf("WithEvidence = %d, want 0", res.WithEvidence)
	}
}

func TestCleanJournalLogsEmptyJournalDir(t *testing.T) {
	tmpDir := t.TempDir()
	machineID := "test-empty-dir"
	os.MkdirAll(filepath.Join(tmpDir, machineID), 0755)

	setReadMachineID(t, machineID, nil)
	setJournalBaseDirs(t, []string{tmpDir})
	setExecCommand(t, fakeExecCommandSuccess)

	output := captureStdout(t, func() {
		res, err := CleanJournalLogs("wg-test", mockDeleteAllSucceed, SudoInteractive)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if res.Scanned != 0 || res.WithEvidence != 0 {
			t.Errorf("empty dir result = %+v, want all zero", res)
		}
	})

	if !strings.Contains(output, "No journal files found") {
		t.Errorf("expected 'No journal files found' in output, got: %s", output)
	}
}

// TestCleanJournalLogsAuthErrorOnStop verifies that when the user's
// system lacks the NOPASSWD sudoers entry for `systemctl stop
// systemd-journald`, the failure surfaces as sudo.ErrAuthRequired
// rather than a generic "exit status 1". Pre-fix, the systemctl
// commands used cmd.Run() which discards output, making IsAuthError
// impossible to apply.
func TestCleanJournalLogsAuthErrorOnStop(t *testing.T) {
	tmpDir := t.TempDir()
	machineID := "test-auth-fail"
	journalDir := filepath.Join(tmpDir, machineID)
	os.MkdirAll(journalDir, 0755)
	os.WriteFile(filepath.Join(journalDir, "system.journal"), []byte("fake"), 0644)

	setReadMachineID(t, machineID, nil)
	setJournalBaseDirs(t, []string{tmpDir})

	setExecCommand(t, func(command string, args ...string) *exec.Cmd {
		allArgs := append([]string{command}, args...)

		// journalctl returns VPN-tagged output so we proceed to the
		// systemctl stop step.
		for _, a := range allArgs {
			if a == "journalctl" {
				cs := []string{"-test.run=TestHelperProcessJournalctl", "--"}
				cs = append(cs, allArgs...)
				cmd := exec.Command(os.Args[0], cs...)
				cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_JOURNALCTL=1")
				return cmd
			}
		}

		// systemctl stop fails with sudo's English auth-required text.
		isStop := false
		for i, a := range allArgs {
			if a == "systemctl" && i+1 < len(allArgs) && allArgs[i+1] == "stop" {
				isStop = true
				break
			}
		}
		if isStop {
			cs := []string{"-test.run=TestHelperProcess", "--", command}
			cs = append(cs, args...)
			cmd := exec.Command(os.Args[0], cs...)
			cmd.Env = append(os.Environ(),
				"GO_WANT_HELPER_PROCESS=1",
				"HELPER_EXIT_CODE=1",
				"HELPER_STDERR=sudo: a password is required",
			)
			return cmd
		}

		return fakeExecCommandSuccess(command, args...)
	})

	_ = captureStdout(t, func() {
		_, err := CleanJournalLogs("wg-lazyvpn", mockDeleteAllSucceed, SudoInteractive)
		if err == nil {
			t.Fatal("expected error when systemctl stop fails")
		}
		if !errors.Is(err, sudo.ErrAuthRequired) {
			t.Errorf("expected sudo.ErrAuthRequired wrapped in error, got: %v", err)
		}
		if !strings.Contains(err.Error(), "sudoers") {
			t.Errorf("error should mention sudoers; got: %v", err)
		}
	})
}

func TestCleanJournalLogsWithVPNEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	machineID := "test-vpn-evidence"
	journalDir := filepath.Join(tmpDir, machineID)
	os.MkdirAll(journalDir, 0755)

	os.WriteFile(filepath.Join(journalDir, "system.journal"), []byte("fake"), 0644)
	os.WriteFile(filepath.Join(journalDir, "user.journal"), []byte("fake"), 0644)
	os.WriteFile(filepath.Join(journalDir, "clean.journal"), []byte("fake"), 0644)

	setReadMachineID(t, machineID, nil)
	setJournalBaseDirs(t, []string{tmpDir})

	setExecCommand(t, func(command string, args ...string) *exec.Cmd {
		allArgs := append([]string{command}, args...)
		isJournalctl := false
		var journalFile string
		for _, a := range allArgs {
			if a == "journalctl" {
				isJournalctl = true
			}
			if strings.HasPrefix(a, "--file=") {
				journalFile = a
			}
		}

		if isJournalctl {
			if strings.Contains(journalFile, "clean.journal") {
				cs := []string{"-test.run=TestHelperProcessJournalctlClean", "--"}
				cs = append(cs, allArgs...)
				cmd := exec.Command(os.Args[0], cs...)
				cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_JOURNALCTL_CLEAN=1")
				return cmd
			}
			cs := []string{"-test.run=TestHelperProcessJournalctl", "--"}
			cs = append(cs, allArgs...)
			cmd := exec.Command(os.Args[0], cs...)
			cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_JOURNALCTL=1")
			return cmd
		}
		return fakeExecCommandSuccess(command, args...)
	})

	var deletedPaths []string
	captureDelete := func(files []string, mode SudoMode) DeleteResult {
		deletedPaths = append(deletedPaths, files...)
		if mode != SudoInteractive {
			t.Errorf("journal delete should use SudoInteractive, got %v", mode)
		}
		return mockDeleteAllSucceed(files, mode)
	}

	_ = captureStdout(t, func() {
		res, err := CleanJournalLogs("wg-lazyvpn", captureDelete, SudoInteractive)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if res.Scanned != 3 {
			t.Errorf("Scanned = %d, want 3", res.Scanned)
		}
		if res.WithEvidence != 2 {
			t.Errorf("WithEvidence = %d, want 2", res.WithEvidence)
		}
		if res.Clean != 1 {
			t.Errorf("Clean = %d, want 1", res.Clean)
		}
		if res.Delete.Deleted != 2 {
			t.Errorf("Delete.Deleted = %d, want 2", res.Delete.Deleted)
		}
	})

	if len(deletedPaths) != 2 {
		t.Errorf("deleteFn captured %d paths, want 2", len(deletedPaths))
	}
	for _, p := range deletedPaths {
		if strings.Contains(p, "clean.journal") {
			t.Errorf("clean.journal should not have been sent to deleteFn: %v", deletedPaths)
		}
	}
}

func TestCleanJournalLogsNoVPNEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	machineID := "test-no-vpn"
	journalDir := filepath.Join(tmpDir, machineID)
	os.MkdirAll(journalDir, 0755)
	os.WriteFile(filepath.Join(journalDir, "system.journal"), []byte("fake"), 0644)

	setReadMachineID(t, machineID, nil)
	setJournalBaseDirs(t, []string{tmpDir})
	setExecCommand(t, func(command string, args ...string) *exec.Cmd {
		allArgs := append([]string{command}, args...)
		for _, a := range allArgs {
			if a == "journalctl" {
				cs := []string{"-test.run=TestHelperProcessJournalctlClean", "--"}
				cs = append(cs, allArgs...)
				cmd := exec.Command(os.Args[0], cs...)
				cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_JOURNALCTL_CLEAN=1")
				return cmd
			}
		}
		return fakeExecCommandSuccess(command, args...)
	})

	deleteCalled := false
	noDelete := func(files []string, mode SudoMode) DeleteResult {
		deleteCalled = true
		return mockDeleteAllSucceed(files, mode)
	}

	_ = captureStdout(t, func() {
		res, err := CleanJournalLogs("wg-lazyvpn", noDelete, SudoInteractive)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if res.WithEvidence != 0 {
			t.Errorf("WithEvidence = %d, want 0", res.WithEvidence)
		}
		if res.Clean != 1 {
			t.Errorf("Clean = %d, want 1", res.Clean)
		}
	})

	if deleteCalled {
		t.Error("deleteFn should not be called when no VPN evidence is found")
	}
}

// --- Helper ---

func assertStringSliceEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("length mismatch: got %d, want %d\ngot:  %v\nwant: %v", len(got), len(want), got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("line %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// TestCleanHistoryFilesPreservesFishHistory verifies fish_history is
// skipped untouched. Fish stores history as YAML (- cmd: / when: pairs);
// line-by-line filtering would remove the cmd line and orphan the when
// line, corrupting the entire history. Until we add a YAML-aware fish
// scrubber, the safe behavior is to leave fish files alone and tell
// the user how to clean them manually.
func TestCleanHistoryFilesPreservesFishHistory(t *testing.T) {
	tmpDir := t.TempDir()
	fishHist := filepath.Join(tmpDir, "fish_history")
	original := strings.Join([]string{
		"- cmd: ls",
		"  when: 1700000000",
		"- cmd: lazyvpn random",
		"  when: 1700000001",
		"- cmd: git status",
		"  when: 1700000002",
		"",
	}, "\n")
	if err := os.WriteFile(fishHist, []byte(original), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	cleaned, skipped := cleanHistoryFiles([]string{fishHist}, "wg-lazyvpn")
	if cleaned != 0 {
		t.Errorf("cleaned = %d, want 0 (fish must be skipped, not edited)", cleaned)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}

	// File must be byte-for-byte identical — no rewrite happened.
	got, err := os.ReadFile(fishHist)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(got) != original {
		t.Errorf("fish history was modified; before:\n%s\nafter:\n%s", original, string(got))
	}
}

// TestHelperProcessJournalctlHuge emits a huge volume of non-matching
// data followed by a single VPN-tagged line. Used to verify the
// streaming scanner finds the match without buffering the whole
// output (pre-fix, cmd.Output() would slurp ~64MB before the bytes.Contains
// hit, then bytes.ToLower would double it).
func TestHelperProcessJournalctlHuge(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_JOURNALCTL_HUGE") != "1" {
		return
	}
	// 64MB of non-matching lines.
	filler := strings.Repeat("x", 1024)
	for i := 0; i < 64*1024; i++ {
		fmt.Fprintln(os.Stdout, filler)
	}
	// Then the match.
	fmt.Fprintln(os.Stdout, "Jan 01 12:00:00 host wireguard[1]: handshake")
	os.Exit(0)
}

// TestScanJournalForVPN_StreamsLargeOutput verifies the per-file
// scanner finds VPN evidence in a 64MB stream without slurping it
// all into memory. Pre-fix the function used cmd.Output() + bytes.ToLower
// which would peak at ~128MB per file (one file, one scan, this test).
// On a real 4GB rotated journal that's ~8GB peak — uninstaller OOM'd
// on small machines.
func TestScanJournalForVPN_StreamsLargeOutput(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessJournalctlHuge", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_JOURNALCTL_HUGE=1")
	if !scanJournalForVPN(cmd, "wg0") {
		t.Error("scanJournalForVPN should have found 'wireguard' in the streamed output")
	}
}

// TestScanJournalForVPN_IfaceNameMatches verifies the third arm of
// scanJournalForVPN's match disjunction:
//
//   if bytes.Contains(lower, []byte("lazyvpn")) ||
//      bytes.Contains(lower, []byte("wireguard")) ||
//      (ifaceLower != "" && bytes.Contains(lower, []byte(ifaceLower))) {
//
// Both "lazyvpn" and "wireguard" arms are covered by
// TestScanJournalForVPN_StreamsLargeOutput. The interface-match arm
// (gated on non-empty ifaceLower) was untested. A regression that
// dropped it would silently miss interface-only journal entries like
// kernel "wg0: link becomes ready" — incomplete scrubbing during
// uninstall.
//
// Sibling to filterHistoryLines' iface-match defense (and its
// non-empty guard at TestFilterHistoryLines_EmptyInterfaceName).
func TestScanJournalForVPN_IfaceNameMatches(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessJournalctlIfaceOnly", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_JOURNALCTL_IFACE_ONLY=1")
	if !scanJournalForVPN(cmd, "wg0") {
		t.Error("scanJournalForVPN should match on interface name alone (third arm of disjunction)")
	}
}

// TestScanJournalForVPN_NoMatch verifies negative path: clean output
// returns false.
func TestScanJournalForVPN_NoMatch(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessJournalctlClean", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_JOURNALCTL_CLEAN=1")
	if scanJournalForVPN(cmd, "wg0") {
		t.Error("scanJournalForVPN should not match clean output")
	}
}

// TestCleanHistoryFilesIgnoresPredictableTempPath verifies that the
// history rewrite uses an unpredictable temp file path (via
// os.CreateTemp) rather than the predictable "<histFile>.tmp" path
// the previous implementation used.
//
// Pre-fix scenario: an attacker who can drop a symlink at
// ~/.bash_history.tmp BEFORE `lazyvpn uninstall` runs would have
// os.WriteFile follow the symlink and truncate the symlink's target
// (limited to files writable as the user, but real CWE-377/378).
//
// We reproduce the attack: pre-place a regular file at the
// predictable .bash_history.tmp path and verify it is NOT touched
// after cleanHistoryFiles runs. With the fix, CreateTemp picks a
// random ".bash_history.tmp.<N>" path that doesn't collide.
func TestCleanHistoryFilesIgnoresPredictableTempPath(t *testing.T) {
	setExecCommand(t, fakeExecCommandSuccess)

	tmpDir := t.TempDir()
	histFile := filepath.Join(tmpDir, ".bash_history")
	// Real bash history with VPN entries that need cleaning.
	if err := os.WriteFile(histFile, []byte("git status\nlazyvpn connect us\nls\n"), 0600); err != nil {
		t.Fatalf("seed history: %v", err)
	}

	// Attacker pre-places the predictable temp path with bait content.
	// Pre-fix the WriteFile would O_TRUNC|O_WRONLY this file and
	// overwrite the bait. With the fix, CreateTemp writes elsewhere
	// and the bait is preserved.
	bait := []byte("attacker-controlled bait — must not be overwritten")
	predictable := histFile + ".tmp"
	if err := os.WriteFile(predictable, bait, 0600); err != nil {
		t.Fatalf("seed predictable temp: %v", err)
	}

	cleaned, _ := cleanHistoryFiles([]string{histFile}, "wg-lazyvpn")
	if cleaned != 1 {
		t.Fatalf("cleaned = %d, want 1 (history should still be cleaned)", cleaned)
	}

	// Bait file at the predictable path is untouched.
	got, err := os.ReadFile(predictable)
	if err != nil {
		t.Fatalf("predictable file disappeared: %v", err)
	}
	if string(got) != string(bait) {
		t.Fatalf("predictable temp path was overwritten — symlink-attack vector still present:\n  got  %q\n  want %q", got, bait)
	}

	// Cleaned history file has the VPN entry removed.
	cleanedContent, err := os.ReadFile(histFile)
	if err != nil {
		t.Fatalf("read cleaned history: %v", err)
	}
	if strings.Contains(string(cleanedContent), "lazyvpn") {
		t.Errorf("cleaned history still contains 'lazyvpn': %q", cleanedContent)
	}
}

// TestProviderKeywords_ContentsPinned locks the exact provider tokens
// used for shell-history scrubbing. The list drives containsProviderConf
// — when an uninstaller scrubs history, lines containing "<provider>
// + .conf" get removed.
//
// A regression that DROPPED a keyword would leave traces of that
// provider's .conf usage in history after uninstall — a privacy
// failure since the whole point of CleanShellHistory is to leave no
// breadcrumb the user ever used a specific VPN provider.
//
// A regression that ADDED a non-provider keyword (e.g. "foo") would
// over-scrub unrelated lines mentioning "foo*.conf" — false-positive
// data loss for the user.
//
// Sibling pattern to 6885299 (privateCIDRs pin) — list-contents
// security contracts where missing/extra entries are silent failures
// (false negatives → privacy leak; false positives → user data loss).
func TestProviderKeywords_ContentsPinned(t *testing.T) {
	want := []string{
		"proton", "mullvad", "ivpn", "airvpn",
		"nord", "surfshark", "windscribe", "fastestvpn",
	}
	if len(providerKeywords) != len(want) {
		t.Fatalf("len(providerKeywords) = %d, want %d (provider added/removed?)", len(providerKeywords), len(want))
	}
	for i, w := range want {
		if providerKeywords[i] != w {
			t.Errorf("providerKeywords[%d] = %q, want %q", i, providerKeywords[i], w)
		}
	}
}

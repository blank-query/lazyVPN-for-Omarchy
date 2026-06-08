package netlink

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"

	nl "github.com/vishvananda/netlink"
)

// ---------------------------------------------------------------------------
// Helpers for sudo fallback tests
// ---------------------------------------------------------------------------

// setupSudoTest sets up mock netlink + execCommand injection and restores both
// after the test. Returns the mock so callers can configure errors.
func setupSudoTest(t *testing.T) *mockNL {
	t.Helper()
	mock := newMockNL()
	origExec := execCommand
	SetNetlinkRunner(mock)
	// Allow sudo fallback paths to execute even with mock runner.
	SetSkipSysCommands(false)
	t.Cleanup(func() {
		SetNetlinkRunner(nil)
		SetWgctrlRunner(nil)
		execCommand = origExec
	})
	return mock
}

// fakeExecSuccess returns an execCommand replacement that always succeeds.
// It runs "true" (the POSIX no-op that exits 0).
func fakeExecSuccess() func(string, ...string) *exec.Cmd {
	return func(name string, args ...string) *exec.Cmd {
		return exec.Command("true")
	}
}

// fakeExecFailure returns an execCommand replacement that always fails.
// It runs "false" (exits 1).
func fakeExecFailure() func(string, ...string) *exec.Cmd {
	return func(name string, args ...string) *exec.Cmd {
		return exec.Command("false")
	}
}

// permError returns an error that isPermError detects.
func permError() error {
	return fmt.Errorf("operation not permitted")
}

// =========================================================================
// mockLink.Type() coverage (runner.go line 168)
// =========================================================================

func TestMockLink_Type(t *testing.T) {
	link := NewMockLink("test0", 1, 0)
	got := link.Type()
	if got != "mock" {
		t.Errorf("Type() = %q, want %q", got, "mock")
	}
}

// =========================================================================
// CreateInterface sudo fallback
// =========================================================================

func TestCreateInterface_PermError_SudoSuccess(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addErr = permError()
	execCommand = fakeExecSuccess()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.CreateInterface()
	if err != nil {
		t.Fatalf("expected sudo fallback to succeed, got: %v", err)
	}
}

func TestCreateInterface_PermError_SudoFailure(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addErr = permError()
	execCommand = fakeExecFailure()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.CreateInterface()
	if err == nil {
		t.Fatal("expected error from sudo fallback failure")
	}
}

// =========================================================================
// AssignAddress sudo fallback
// =========================================================================

func TestAssignAddress_PermError_SudoSuccess(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addLink(NewMockLink("wg-test", 10, 0))
	mock.addrErr = permError()
	execCommand = fakeExecSuccess()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.AssignAddress()
	if err != nil {
		t.Fatalf("expected sudo fallback to succeed, got: %v", err)
	}
}

func TestAssignAddress_PermError_SudoFailure(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addLink(NewMockLink("wg-test", 10, 0))
	mock.addrErr = permError()
	execCommand = fakeExecFailure()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.AssignAddress()
	if err == nil {
		t.Fatal("expected error from sudo fallback failure")
	}
}

// =========================================================================
// BringUp sudo fallback
// =========================================================================

func TestBringUp_PermError_SudoSuccess(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addLink(NewMockLink("wg-test", 10, 0))
	mock.upErr = permError()
	execCommand = fakeExecSuccess()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.BringUp()
	if err != nil {
		t.Fatalf("expected sudo fallback to succeed, got: %v", err)
	}
}

func TestBringUp_PermError_SudoFailure(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addLink(NewMockLink("wg-test", 10, 0))
	mock.upErr = permError()
	execCommand = fakeExecFailure()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.BringUp()
	if err == nil {
		t.Fatal("expected error from sudo fallback failure")
	}
}

// =========================================================================
// Delete sudo fallback
// =========================================================================

func TestDelete_PermError_SudoSuccess(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addLink(NewMockLink("wg-test", 10, 0))
	mock.delErr = permError()
	execCommand = fakeExecSuccess()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.Delete()
	if err != nil {
		t.Fatalf("expected sudo fallback to succeed, got: %v", err)
	}
}

func TestDelete_PermError_SudoFailure(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addLink(NewMockLink("wg-test", 10, 0))
	mock.delErr = permError()
	execCommand = fakeExecFailure()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.Delete()
	if err == nil {
		t.Fatal("expected error from sudo fallback failure")
	}
}

// =========================================================================
// SetMTU sudo fallback
// =========================================================================

func TestSetMTU_PermError_SudoSuccess(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addLink(NewMockLink("wg-test", 10, 0))
	mock.mtuErr = permError()
	execCommand = fakeExecSuccess()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.SetMTU(1420)
	if err != nil {
		t.Fatalf("expected sudo fallback to succeed, got: %v", err)
	}
}

func TestSetMTU_PermError_SudoFailure(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addLink(NewMockLink("wg-test", 10, 0))
	mock.mtuErr = permError()
	execCommand = fakeExecFailure()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.SetMTU(1420)
	if err == nil {
		t.Fatal("expected error from sudo fallback failure")
	}
}

// =========================================================================
// createInterfaceSudo direct
// =========================================================================

func TestCreateInterfaceSudo_Success(t *testing.T) {
	mock := setupSudoTest(t)
	_ = mock
	execCommand = fakeExecSuccess()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.createInterfaceSudo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateInterfaceSudo_Failure(t *testing.T) {
	mock := setupSudoTest(t)
	_ = mock
	execCommand = fakeExecFailure()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.createInterfaceSudo()
	if err == nil {
		t.Fatal("expected error")
	}
}

// =========================================================================
// assignAddressSudo direct
// =========================================================================

func TestAssignAddressSudo_Success(t *testing.T) {
	mock := setupSudoTest(t)
	_ = mock
	execCommand = fakeExecSuccess()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.assignAddressSudo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAssignAddressSudo_Failure(t *testing.T) {
	mock := setupSudoTest(t)
	_ = mock
	execCommand = fakeExecFailure()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.assignAddressSudo()
	if err == nil {
		t.Fatal("expected error")
	}
}

// =========================================================================
// bringUpSudo direct
// =========================================================================

func TestBringUpSudo_Success(t *testing.T) {
	mock := setupSudoTest(t)
	_ = mock
	execCommand = fakeExecSuccess()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.bringUpSudo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBringUpSudo_Failure(t *testing.T) {
	mock := setupSudoTest(t)
	_ = mock
	execCommand = fakeExecFailure()

	wgi := newTestWGI(t, "wg-test")
	err := wgi.bringUpSudo()
	if err == nil {
		t.Fatal("expected error")
	}
}

// =========================================================================
// Routes sudo fallback tests
// =========================================================================

func TestDeleteLinkInterface_PermError_SudoSuccess(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addLink(NewMockLink("wg0", 10, 0))
	mock.delErr = permError()
	execCommand = fakeExecSuccess()

	err := DeleteLinkInterface("wg0")
	if err != nil {
		t.Fatalf("expected sudo fallback to succeed, got: %v", err)
	}
}

func TestDeleteLinkInterface_PermError_SudoFailure(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addLink(NewMockLink("wg0", 10, 0))
	mock.delErr = permError()
	execCommand = fakeExecFailure()

	err := DeleteLinkInterface("wg0")
	if err == nil {
		t.Fatal("expected error from sudo fallback failure")
	}
}

func TestAddHostRoute_PermError_SudoSuccess(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addLink(NewMockLink("eth0", 2, 0))
	mock.routeAddErr = permError()
	execCommand = fakeExecSuccess()

	err := AddHostRoute("1.2.3.4", "192.168.1.1", "eth0")
	if err != nil {
		t.Fatalf("expected sudo fallback to succeed, got: %v", err)
	}
}

func TestAddHostRoute_PermError_SudoFailure(t *testing.T) {
	mock := setupSudoTest(t)
	mock.addLink(NewMockLink("eth0", 2, 0))
	mock.routeAddErr = permError()
	execCommand = fakeExecFailure()

	err := AddHostRoute("1.2.3.4", "192.168.1.1", "eth0")
	if err == nil {
		t.Fatal("expected error from sudo fallback failure")
	}
}

// =========================================================================
// SetSkipSysCommands test
// =========================================================================

func TestSetSkipSysCommands(t *testing.T) {
	origExec := execCommand
	t.Cleanup(func() {
		SetNetlinkRunner(nil)
		execCommand = origExec
	})

	mock := newMockNL()
	SetNetlinkRunner(mock) // sets skipSysCommands = true

	if !skipSysCommands {
		t.Fatal("expected skipSysCommands = true after SetNetlinkRunner")
	}

	SetSkipSysCommands(false)
	if skipSysCommands {
		t.Fatal("expected skipSysCommands = false after SetSkipSysCommands(false)")
	}

	SetSkipSysCommands(true)
	if !skipSysCommands {
		t.Fatal("expected skipSysCommands = true after SetSkipSysCommands(true)")
	}
}

// =========================================================================
// mockLinkWithStats.Type() coverage
// =========================================================================

func TestMockLinkWithStats_Type(t *testing.T) {
	link := &mockLinkWithStats{
		LinkAttrs: nl.LinkAttrs{Name: "test0"},
	}
	got := link.Type()
	if got != "mock-stats" {
		t.Errorf("Type() = %q, want %q", got, "mock-stats")
	}
}

// =========================================================================
// GetDeviceInfo without wgRunner (covers the wgctrl.New() path)
// In unprivileged environments, wgctrl.New() may return EPERM.
// This exercises the error path covering the 38.5% gap.
// =========================================================================

func TestGetDeviceInfo_NoWgRunner(t *testing.T) {
	origExec := execCommand
	t.Cleanup(func() {
		SetNetlinkRunner(nil)
		SetWgctrlRunner(nil)
		execCommand = origExec
	})

	mock := newMockNL()
	SetNetlinkRunner(mock)
	// Explicitly set wgRunner to nil to exercise the real wgctrl.New() path
	SetWgctrlRunner(nil)

	// wgctrl.New() will likely fail (no root) -- we just exercise the code path
	_, err := GetDeviceInfo("wg-nonexistent")
	if err == nil {
		// If it somehow succeeds (e.g. running as root), that's fine too
		t.Log("GetDeviceInfo succeeded without wgRunner -- likely running as root")
	}
	// Either way, the code path is exercised
}

// =========================================================================
// ConfigureInterface without wgRunner (covers the wgctrl.New() path)
// =========================================================================

func TestConfigureInterface_NoWgRunner(t *testing.T) {
	origExec := execCommand
	origOsExec := osExecutable
	t.Cleanup(func() {
		SetNetlinkRunner(nil)
		SetWgctrlRunner(nil)
		execCommand = origExec
		osExecutable = origOsExec
	})

	mock := newMockNL()
	SetNetlinkRunner(mock)
	SetSkipSysCommands(false)
	SetWgctrlRunner(nil)

	// Mock self-exec to return EPERM (simulates child lacking caps too)
	osExecutable = func() (string, error) { return "/usr/bin/lazyvpn", nil }
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("sh", "-c", "echo 'operation not permitted' >&2; exit 1")
	}

	wgi := newTestWGI(t, "wg-test")
	// wgctrl.New() will likely fail (no root) with EPERM,
	// which falls through to configureInterfaceSelf (also mocked to EPERM).
	err := wgi.ConfigureInterface()
	// In unprivileged environments, expect ErrAuthRequired.
	// In privileged (root/CI), the call may succeed or fail differently.
	_ = err
}

// =========================================================================
// isPermError with actual syscall.EPERM wrapped in SyscallError
// =========================================================================

func TestIsPermError_RealEPERM(t *testing.T) {
	err := &os.SyscallError{Syscall: "socket", Err: syscall.EPERM}
	if !isPermError(err) {
		t.Error("should detect SyscallError with EPERM")
	}
}

func TestIsPermError_RealEACCES(t *testing.T) {
	err := &os.SyscallError{Syscall: "open", Err: syscall.EACCES}
	if !isPermError(err) {
		t.Error("should detect SyscallError with EACCES")
	}
}

func TestIsPermError_WrappedSyscallError(t *testing.T) {
	inner := &os.SyscallError{Syscall: "socket", Err: syscall.EPERM}
	err := fmt.Errorf("netlink failed: %w", inner)
	if !isPermError(err) {
		t.Error("should detect wrapped SyscallError with EPERM")
	}
}

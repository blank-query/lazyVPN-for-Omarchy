package netlink

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
	nl "github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// NetlinkRunner abstracts vishvananda/netlink calls for testing.
type NetlinkRunner interface {
	LinkByName(name string) (nl.Link, error)
	LinkByIndex(index int) (nl.Link, error)
	LinkAdd(link nl.Link) error
	LinkDel(link nl.Link) error
	LinkSetUp(link nl.Link) error
	LinkSetMTU(link nl.Link, mtu int) error
	AddrAdd(link nl.Link, addr *nl.Addr) error
	RouteAdd(route *nl.Route) error
	RouteDel(route *nl.Route) error
	RouteList(link nl.Link, family int) ([]nl.Route, error)
}

// WgctrlRunner abstracts wgctrl operations for testing.
type WgctrlRunner interface {
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Device(name string) (*wgtypes.Device, error)
	Close() error
}

// realNetlinkRunner wraps the real vishvananda/netlink package functions.
type realNetlinkRunner struct{}

func (r *realNetlinkRunner) LinkByName(name string) (nl.Link, error) {
	return nl.LinkByName(name)
}

func (r *realNetlinkRunner) LinkByIndex(index int) (nl.Link, error) {
	return nl.LinkByIndex(index)
}

func (r *realNetlinkRunner) LinkAdd(link nl.Link) error {
	return nl.LinkAdd(link)
}

func (r *realNetlinkRunner) LinkDel(link nl.Link) error {
	return nl.LinkDel(link)
}

func (r *realNetlinkRunner) LinkSetUp(link nl.Link) error {
	return nl.LinkSetUp(link)
}

func (r *realNetlinkRunner) LinkSetMTU(link nl.Link, mtu int) error {
	return nl.LinkSetMTU(link, mtu)
}

func (r *realNetlinkRunner) AddrAdd(link nl.Link, addr *nl.Addr) error {
	return nl.AddrAdd(link, addr)
}

func (r *realNetlinkRunner) RouteAdd(route *nl.Route) error {
	return nl.RouteAdd(route)
}

func (r *realNetlinkRunner) RouteDel(route *nl.Route) error {
	return nl.RouteDel(route)
}

func (r *realNetlinkRunner) RouteList(link nl.Link, family int) ([]nl.Route, error) {
	return nl.RouteList(link, family)
}

// execCommand is the function used to create exec.Cmd instances.
// Tests can replace this to intercept sudo calls.
var execCommand = exec.Command

// runSudoCmd is the helper for the sudo-fallback paths in this package.
// It wraps execCommand + sudo.SetCLocale + CombinedOutput so the output
// stays in English for sudo.IsAuthError to match. Without LC_ALL=C, a
// non-English system would return translated "password required" text
// and IsAuthError would miss — every sudo-fallback site (route add,
// link delete, etc.) would surface a generic command failure instead
// of triggering the auth-prompt recovery flow.
//
// Bounded with a wall-clock watcher: a wedged sudo / ip / kernel
// netlink call without a bound would freeze the daemon's main
// goroutine inside doConnect — past SIGTERM, since signals can't be
// processed until the goroutine returns to the select. 10s is
// generous for healthy local sysadmin syscalls. Same goroutine-
// watcher pattern as configureInterfaceSelf — preserves the
// execCommand var stubbing in tests.
func runSudoCmd(args ...string) ([]byte, error) {
	cmd := execCommand(args[0], args[1:]...)
	sudo.SetCLocale(cmd)
	return runCmdWithTimeout(cmd, sudoCallTimeout)
}

// sudoCallTimeout caps every runSudoCmd invocation. See the comment
// above for rationale.
var sudoCallTimeout = 10 * time.Second

// runCmdWithTimeout runs cmd via Start+Wait but kills the subprocess
// if it exceeds d. Returns whatever Wait returned alongside the
// captured combined output.
//
// Inlines CombinedOutput's body (a shared bytes.Buffer wired to
// Stdout+Stderr) so we can capture cmd.Process AFTER Start has
// written it but BEFORE the watcher goroutine reads it. The naive
// version (watcher reads cmd.Process directly) races cmd.Start's
// write to that field — a race the runtime's race detector flags
// any time the timeout actually fires (proven by the matching test
// in internal/security).
func runCmdWithTimeout(cmd *exec.Cmd, d time.Duration) ([]byte, error) {
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// cmd.Process is written by Start (above) and never re-assigned,
	// so capturing it here is race-free regardless of when the
	// watcher reads.
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
		return b.Bytes(), fmt.Errorf("subprocess timed out after %s — sudo or ip may be wedged", d)
	}
	return b.Bytes(), err
}

// nlRunner and wgRunner are the current runners.
// Tests can replace these via SetNetlinkRunner / SetWgctrlRunner.
var (
	nlRunner        NetlinkRunner
	wgRunner        WgctrlRunner
	skipSysCommands bool // when true, skip exec.Command fallbacks
)

func init() {
	nlRunner = &realNetlinkRunner{}
}

// SetNetlinkRunner replaces the global netlink runner (for testing).
// Pass nil to restore the default.
func SetNetlinkRunner(r NetlinkRunner) {
	if r == nil {
		nlRunner = &realNetlinkRunner{}
		skipSysCommands = false
	} else {
		nlRunner = r
		skipSysCommands = true
	}
}

// SetSkipSysCommands overrides the skipSysCommands flag (for testing).
// This allows tests to enable sudo fallback paths even when using a mock runner.
func SetSkipSysCommands(skip bool) {
	skipSysCommands = skip
}

// SetWgctrlRunner replaces the global wgctrl runner (for testing).
// Pass nil to restore the default.
func SetWgctrlRunner(r WgctrlRunner) {
	if r == nil {
		wgRunner = nil
	} else {
		wgRunner = r
	}
}

// getStatsFromProcFile is a variable to allow overriding the proc path in tests.
var procNetDevPath = "/proc/net/dev"

// --- Helper for route functions to use nlRunner ---

func nlLinkByName(name string) (nl.Link, error) {
	return nlRunner.LinkByName(name)
}

func nlLinkByIndex(index int) (nl.Link, error) {
	return nlRunner.LinkByIndex(index)
}

func nlLinkAdd(link nl.Link) error {
	return nlRunner.LinkAdd(link)
}

func nlLinkDel(link nl.Link) error {
	return nlRunner.LinkDel(link)
}

func nlLinkSetUp(link nl.Link) error {
	return nlRunner.LinkSetUp(link)
}

func nlLinkSetMTU(link nl.Link, mtu int) error {
	return nlRunner.LinkSetMTU(link, mtu)
}

func nlAddrAdd(link nl.Link, addr *nl.Addr) error {
	return nlRunner.AddrAdd(link, addr)
}

func nlRouteAdd(route *nl.Route) error {
	return nlRunner.RouteAdd(route)
}

func nlRouteDel(route *nl.Route) error {
	return nlRunner.RouteDel(route)
}

func nlRouteList(link nl.Link, family int) ([]nl.Route, error) {
	return nlRunner.RouteList(link, family)
}

// mockLink is a minimal Link implementation for testing.
type mockLink struct {
	nl.LinkAttrs
}

func (m *mockLink) Attrs() *nl.LinkAttrs { return &m.LinkAttrs }
func (m *mockLink) Type() string         { return "mock" }

// NewMockLink creates a mock link for testing (exported for other packages).
func NewMockLink(name string, index int, flags net.Flags) nl.Link {
	return &mockLink{
		LinkAttrs: nl.LinkAttrs{
			Name:  name,
			Index: index,
			Flags: flags,
		},
	}
}

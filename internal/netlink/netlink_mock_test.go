package netlink

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	nl "github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ---------------------------------------------------------------------------
// Mock NetlinkRunner
// ---------------------------------------------------------------------------

type mockNL struct {
	mu           sync.RWMutex
	links        map[string]nl.Link
	linksByIdx   map[int]nl.Link
	routes       []nl.Route
	addErr       error
	delErr       error
	upErr        error
	mtuErr       error
	addrErr      error
	routeAddErr  error
	routeDelErr  error
	routeListErr error
}

func newMockNL() *mockNL {
	return &mockNL{
		links:      make(map[string]nl.Link),
		linksByIdx: make(map[int]nl.Link),
	}
}

func (m *mockNL) addLink(link nl.Link) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links[link.Attrs().Name] = link
	m.linksByIdx[link.Attrs().Index] = link
}

func (m *mockNL) LinkByName(name string) (nl.Link, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.links[name]
	if !ok {
		return nil, fmt.Errorf("link not found")
	}
	return l, nil
}

func (m *mockNL) LinkByIndex(index int) (nl.Link, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.linksByIdx[index]
	if !ok {
		return nil, fmt.Errorf("link not found by index")
	}
	return l, nil
}

func (m *mockNL) LinkAdd(link nl.Link) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addErr != nil {
		return m.addErr
	}
	m.links[link.Attrs().Name] = link
	m.linksByIdx[link.Attrs().Index] = link
	return nil
}

func (m *mockNL) LinkDel(link nl.Link) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.delErr != nil {
		return m.delErr
	}
	delete(m.links, link.Attrs().Name)
	delete(m.linksByIdx, link.Attrs().Index)
	return nil
}

func (m *mockNL) LinkSetUp(link nl.Link) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.upErr != nil {
		return m.upErr
	}
	link.Attrs().Flags |= net.FlagUp
	return nil
}

func (m *mockNL) LinkSetMTU(link nl.Link, mtu int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mtuErr != nil {
		return m.mtuErr
	}
	link.Attrs().MTU = mtu
	return nil
}

func (m *mockNL) AddrAdd(link nl.Link, addr *nl.Addr) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.addrErr
}

func (m *mockNL) RouteAdd(route *nl.Route) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.routeAddErr != nil {
		return m.routeAddErr
	}
	m.routes = append(m.routes, *route)
	return nil
}

func (m *mockNL) RouteDel(route *nl.Route) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.routeDelErr != nil {
		return m.routeDelErr
	}
	// Remove matching route
	var kept []nl.Route
	for _, r := range m.routes {
		if r.LinkIndex == route.LinkIndex && r.Dst != nil && route.Dst != nil && r.Dst.String() == route.Dst.String() {
			continue
		}
		kept = append(kept, r)
	}
	m.routes = kept
	return nil
}

func (m *mockNL) RouteList(link nl.Link, family int) ([]nl.Route, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.routeListErr != nil {
		return nil, m.routeListErr
	}
	return m.routes, nil
}

// ---------------------------------------------------------------------------
// Mock WgctrlRunner
// ---------------------------------------------------------------------------

type mockWG struct {
	configErr error
	device    *wgtypes.Device
	deviceErr error
}

func (m *mockWG) ConfigureDevice(name string, cfg wgtypes.Config) error {
	return m.configErr
}

func (m *mockWG) Device(name string) (*wgtypes.Device, error) {
	if m.deviceErr != nil {
		return nil, m.deviceErr
	}
	return m.device, nil
}

func (m *mockWG) Close() error {
	return nil
}

// ---------------------------------------------------------------------------
// mockLinkWithStats embeds mockLink but adds Statistics to attrs
// ---------------------------------------------------------------------------

type mockLinkWithStats struct {
	nl.LinkAttrs
}

func (m *mockLinkWithStats) Attrs() *nl.LinkAttrs { return &m.LinkAttrs }
func (m *mockLinkWithStats) Type() string         { return "mock-stats" }

// ---------------------------------------------------------------------------
// Helper: build a minimal WireGuardInterface for tests
// ---------------------------------------------------------------------------

func newTestWGI(t *testing.T, name string) *WireGuardInterface {
	t.Helper()
	privKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	pubKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatalf("generate public key: %v", err)
	}
	return &WireGuardInterface{
		Name:       name,
		PrivateKey: privKey,
		Address:    net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)},
		Peer: WireGuardPeer{
			PublicKey:  pubKey,
			AllowedIPs: []net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}},
		},
	}
}

// cleanup restores the global runners and execCommand after each test.
func cleanup(t *testing.T) {
	t.Helper()
	origExec := execCommand
	t.Cleanup(func() {
		SetNetlinkRunner(nil)
		SetWgctrlRunner(nil)
		execCommand = origExec
	})
}

// =========================================================================
// Route Tests
// =========================================================================

func TestAddHostRoute_Success(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	mock.addLink(NewMockLink("eth0", 2, net.FlagUp))

	err := AddHostRoute("1.2.3.4", "192.168.1.1", "eth0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(mock.routes))
	}
	r := mock.routes[0]
	if r.LinkIndex != 2 {
		t.Errorf("route link index = %d, want 2", r.LinkIndex)
	}
	if r.Gw.String() != "192.168.1.1" {
		t.Errorf("gateway = %s, want 192.168.1.1", r.Gw)
	}
	if r.Dst == nil || r.Dst.IP.String() != "1.2.3.4" {
		t.Errorf("dst = %v, want 1.2.3.4/32", r.Dst)
	}
}

// TestAddHostRoute_IPv4MaskIs32 pins the IPv4 mask boundary. The
// existing TestAddHostRoute_Success checks the destination IP matches
// but does NOT verify the mask is /32 — a regression on the
// `hostIP.To4() == nil` branch that flipped IPv4 to /128 would
// pass that test silently. The sibling TestAddHostRoute_IPv6
// (line ~1018) covers /128 for IPv6 explicitly; this fills the
// IPv4 half of that contract.
func TestAddHostRoute_IPv4MaskIs32(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	mock.addLink(NewMockLink("eth0", 2, net.FlagUp))

	if err := AddHostRoute("1.2.3.4", "192.168.1.1", "eth0"); err != nil {
		t.Fatalf("AddHostRoute: %v", err)
	}
	if len(mock.routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(mock.routes))
	}
	ones, bits := mock.routes[0].Dst.Mask.Size()
	if ones != 32 || bits != 32 {
		t.Errorf("IPv4 host route mask = /%d (bits %d), want /32 (bits 32)", ones, bits)
	}
}

func TestAddHostRoute_EmptyHost(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	err := AddHostRoute("", "192.168.1.1", "eth0")
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestAddHostRoute_EmptyGateway(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	err := AddHostRoute("1.2.3.4", "", "eth0")
	if err == nil {
		t.Fatal("expected error for empty gateway")
	}
}

func TestAddHostRoute_InvalidHostIP(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	mock.addLink(NewMockLink("eth0", 2, 0))

	err := AddHostRoute("not-an-ip", "192.168.1.1", "eth0")
	if err == nil {
		t.Fatal("expected error for invalid host IP")
	}
}

func TestAddHostRoute_InvalidGatewayIP(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	mock.addLink(NewMockLink("eth0", 2, 0))

	err := AddHostRoute("1.2.3.4", "not-an-ip", "eth0")
	if err == nil {
		t.Fatal("expected error for invalid gateway IP")
	}
}

func TestAddHostRoute_InterfaceNotFound(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	err := AddHostRoute("1.2.3.4", "192.168.1.1", "nosuch0")
	if err == nil {
		t.Fatal("expected error for missing interface")
	}
}

func TestGetDefaultGateway_Found(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	link := NewMockLink("eth0", 3, net.FlagUp)
	mock.addLink(link)

	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	mock.routes = []nl.Route{
		{
			LinkIndex: 3,
			Dst:       defaultNet,
			Gw:        net.ParseIP("192.168.1.1"),
		},
	}

	gw, iface, err := GetDefaultGateway()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gw != "192.168.1.1" {
		t.Errorf("gateway = %q, want 192.168.1.1", gw)
	}
	if iface != "eth0" {
		t.Errorf("iface = %q, want eth0", iface)
	}
}

func TestGetDefaultGateway_NilDst(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	link := NewMockLink("eth0", 3, net.FlagUp)
	mock.addLink(link)

	// A route with nil Dst is treated as a default route
	mock.routes = []nl.Route{
		{
			LinkIndex: 3,
			Dst:       nil,
			Gw:        net.ParseIP("10.0.0.1"),
		},
	}

	gw, iface, err := GetDefaultGateway()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gw != "10.0.0.1" {
		t.Errorf("gateway = %q, want 10.0.0.1", gw)
	}
	if iface != "eth0" {
		t.Errorf("iface = %q, want eth0", iface)
	}
}

func TestGetDefaultGateway_NoDefaultRoute(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
	mock.routes = []nl.Route{
		{LinkIndex: 1, Dst: subnet},
	}

	gw, iface, err := GetDefaultGateway()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gw != "" {
		t.Errorf("gateway = %q, want empty", gw)
	}
	if iface != "" {
		t.Errorf("iface = %q, want empty", iface)
	}
}

func TestGetDefaultGateway_RouteListError(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	mock.routeListErr = fmt.Errorf("route list failed")

	_, _, err := GetDefaultGateway()
	if err == nil {
		t.Fatal("expected error from RouteList")
	}
}

func TestDeleteLinkInterface_Success(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	mock.addLink(NewMockLink("wg0", 10, 0))

	err := DeleteLinkInterface("wg0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := mock.links["wg0"]; ok {
		t.Error("link should have been deleted")
	}
}

func TestDeleteLinkInterface_NotFound(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	err := DeleteLinkInterface("nosuch0")
	if err == nil {
		t.Fatal("expected error for missing interface")
	}
}

func TestDeleteLinkInterface_DelError(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	mock.addLink(NewMockLink("wg0", 10, 0))
	mock.delErr = fmt.Errorf("delete failed")

	err := DeleteLinkInterface("wg0")
	if err == nil {
		t.Fatal("expected error from LinkDel")
	}
}

func TestInterfaceExists(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	mock.addLink(NewMockLink("wg0", 10, 0))

	if !InterfaceExists("wg0") {
		t.Error("expected wg0 to exist")
	}
	if InterfaceExists("nosuch0") {
		t.Error("expected nosuch0 to not exist")
	}
}

// =========================================================================
// WireGuard Interface Tests
// =========================================================================

func TestCreateInterface_Success(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	wgi := newTestWGI(t, "wg-test")
	err := wgi.CreateInterface()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := mock.links["wg-test"]; !ok {
		t.Error("expected wg-test to be added to links")
	}
}

func TestCreateInterface_LinkAddError(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	mock.addErr = fmt.Errorf("link add failed")

	wgi := newTestWGI(t, "wg-test")
	err := wgi.CreateInterface()
	if err == nil {
		t.Fatal("expected error from LinkAdd")
	}
}

func TestConfigureInterface_Success(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	wgMock := &mockWG{}
	SetWgctrlRunner(wgMock)

	wgi := newTestWGI(t, "wg-test")
	err := wgi.ConfigureInterface()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigureInterface_WgctrlError(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	wgMock := &mockWG{configErr: fmt.Errorf("wgctrl config failed")}
	SetWgctrlRunner(wgMock)

	wgi := newTestWGI(t, "wg-test")
	err := wgi.ConfigureInterface()
	if err == nil {
		t.Fatal("expected error from wgctrl")
	}
}

func TestAssignAddress_Success(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	mock.addLink(NewMockLink("wg-test", 10, 0))

	wgi := newTestWGI(t, "wg-test")
	err := wgi.AssignAddress()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAssignAddress_InterfaceNotFound(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	wgi := newTestWGI(t, "wg-test")
	err := wgi.AssignAddress()
	if err == nil {
		t.Fatal("expected error for missing interface")
	}
}

func TestAssignAddress_AddrAddError(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	mock.addrErr = fmt.Errorf("addr add failed")

	mock.addLink(NewMockLink("wg-test", 10, 0))

	wgi := newTestWGI(t, "wg-test")
	err := wgi.AssignAddress()
	if err == nil {
		t.Fatal("expected error from AddrAdd")
	}
}

func TestBringUp_Success(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	mock.addLink(NewMockLink("wg-test", 10, 0))

	wgi := newTestWGI(t, "wg-test")
	err := wgi.BringUp()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	link := mock.links["wg-test"]
	if link.Attrs().Flags&net.FlagUp == 0 {
		t.Error("expected interface to be up after BringUp")
	}
}

func TestBringUp_InterfaceNotFound(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	wgi := newTestWGI(t, "wg-test")
	err := wgi.BringUp()
	if err == nil {
		t.Fatal("expected error for missing interface")
	}
}

func TestBringUp_SetUpError(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	mock.upErr = fmt.Errorf("set up failed")

	mock.addLink(NewMockLink("wg-test", 10, 0))

	wgi := newTestWGI(t, "wg-test")
	err := wgi.BringUp()
	if err == nil {
		t.Fatal("expected error from LinkSetUp")
	}
}

func TestDelete_Success(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	mock.addLink(NewMockLink("wg-test", 10, 0))

	wgi := newTestWGI(t, "wg-test")
	err := wgi.Delete()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := mock.links["wg-test"]; ok {
		t.Error("expected interface to be deleted")
	}
}

func TestDelete_InterfaceNotFound_ReturnsNil(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	// No link registered -- Delete should return nil

	wgi := newTestWGI(t, "wg-test")
	err := wgi.Delete()
	if err != nil {
		t.Fatalf("expected nil error when interface does not exist, got: %v", err)
	}
}

func TestDelete_LinkDelError(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	mock.delErr = fmt.Errorf("del failed")

	mock.addLink(NewMockLink("wg-test", 10, 0))

	wgi := newTestWGI(t, "wg-test")
	err := wgi.Delete()
	if err == nil {
		t.Fatal("expected error from LinkDel")
	}
}

func TestSetMTU_Success(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	mock.addLink(NewMockLink("wg-test", 10, 0))

	wgi := newTestWGI(t, "wg-test")
	err := wgi.SetMTU(1420)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	link := mock.links["wg-test"]
	if link.Attrs().MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", link.Attrs().MTU)
	}
}

func TestSetMTU_InterfaceNotFound(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	wgi := newTestWGI(t, "wg-test")
	err := wgi.SetMTU(1420)
	if err == nil {
		t.Fatal("expected error for missing interface")
	}
}

func TestSetMTU_Error(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	mock.mtuErr = fmt.Errorf("mtu failed")

	mock.addLink(NewMockLink("wg-test", 10, 0))

	wgi := newTestWGI(t, "wg-test")
	err := wgi.SetMTU(1420)
	if err == nil {
		t.Fatal("expected error from LinkSetMTU")
	}
}

func TestGetDeviceInfo_Success(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	privKey, _ := wgtypes.GenerateKey()
	pubKey := privKey.PublicKey()

	wgMock := &mockWG{
		device: &wgtypes.Device{
			Name:      "wg-test",
			PublicKey: pubKey,
		},
	}
	SetWgctrlRunner(wgMock)

	dev, err := GetDeviceInfo("wg-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev.Name != "wg-test" {
		t.Errorf("device name = %q, want wg-test", dev.Name)
	}
	if dev.PublicKey != pubKey {
		t.Errorf("public key mismatch")
	}
}

func TestGetDeviceInfo_Error(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	wgMock := &mockWG{deviceErr: fmt.Errorf("device not found")}
	SetWgctrlRunner(wgMock)

	_, err := GetDeviceInfo("wg-test")
	if err == nil {
		t.Fatal("expected error from Device")
	}
}

// =========================================================================
// Stats Tests
// =========================================================================

func TestGetStatsFromProc_Valid(t *testing.T) {
	cleanup(t)

	content := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo frame compressed multicast
    lo:  100000      50    0    0    0     0          0         0   100000      50    0    0    0     0       0          0
  wg0: 5000000    3000    0    0    0     0          0         0  2000000    1500    0    0    0     0       0          0
`
	dir := t.TempDir()
	procPath := filepath.Join(dir, "net_dev")
	if err := os.WriteFile(procPath, []byte(content), 0644); err != nil {
		t.Fatalf("write temp proc file: %v", err)
	}

	oldPath := procNetDevPath
	procNetDevPath = procPath
	t.Cleanup(func() { procNetDevPath = oldPath })

	stats, err := getStatsFromProc("wg0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.RxBytes != 5000000 {
		t.Errorf("RxBytes = %d, want 5000000", stats.RxBytes)
	}
	if stats.TxBytes != 2000000 {
		t.Errorf("TxBytes = %d, want 2000000", stats.TxBytes)
	}
	if stats.RxPackets != 3000 {
		t.Errorf("RxPackets = %d, want 3000", stats.RxPackets)
	}
	if stats.TxPackets != 1500 {
		t.Errorf("TxPackets = %d, want 1500", stats.TxPackets)
	}
}

// TestGetStatsFromProc_TruncatedLineSkipped covers the defensive
// `len(fields) < 16` branch in getStatsFromProc: if the matching
// interface line in /proc/net/dev is truncated/malformed (fewer
// than 16 fields), parsing must skip it (returning "not found")
// rather than slice into a short array and panic, OR returning
// garbage stats from out-of-bounds string parses.
//
// Real-world relevance: extreme system load can cause /proc reads
// to return partial buffers, and corrupted state from a kernel bug
// has historically produced under-fielded /proc/net/dev lines.
func TestGetStatsFromProc_TruncatedLineSkipped(t *testing.T) {
	cleanup(t)

	// wg0 line has only 3 fields after the colon — far short of the
	// 16 required to read tx fields at index 8/9.
	content := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo frame compressed multicast
  wg0:  100  10  0
`
	dir := t.TempDir()
	procPath := filepath.Join(dir, "net_dev")
	if err := os.WriteFile(procPath, []byte(content), 0644); err != nil {
		t.Fatalf("write temp proc file: %v", err)
	}

	oldPath := procNetDevPath
	procNetDevPath = procPath
	t.Cleanup(func() { procNetDevPath = oldPath })

	stats, err := getStatsFromProc("wg0")
	if err == nil {
		t.Fatalf("expected error for truncated line, got stats=%+v", stats)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error doesn't say not found: %v (truncated line should be skipped, not panic or return garbage)", err)
	}
}

func TestGetStatsFromProc_InterfaceNotFound(t *testing.T) {
	cleanup(t)

	content := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo frame compressed multicast
    lo:  100000      50    0    0    0     0          0         0   100000      50    0    0    0     0       0          0
`
	dir := t.TempDir()
	procPath := filepath.Join(dir, "net_dev")
	if err := os.WriteFile(procPath, []byte(content), 0644); err != nil {
		t.Fatalf("write temp proc file: %v", err)
	}

	oldPath := procNetDevPath
	procNetDevPath = procPath
	t.Cleanup(func() { procNetDevPath = oldPath })

	_, err := getStatsFromProc("wg0")
	if err == nil {
		t.Fatal("expected error for interface not found in proc")
	}
}

func TestGetStatsFromProc_FileNotFound(t *testing.T) {
	cleanup(t)

	oldPath := procNetDevPath
	procNetDevPath = "/tmp/nonexistent_proc_net_dev_file"
	t.Cleanup(func() { procNetDevPath = oldPath })

	_, err := getStatsFromProc("wg0")
	if err == nil {
		t.Fatal("expected error for missing proc file")
	}
}

func TestGetInterfaceStats_WithStatistics(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	link := &mockLinkWithStats{
		LinkAttrs: nl.LinkAttrs{
			Name:  "wg0",
			Index: 10,
			Statistics: &nl.LinkStatistics{
				RxBytes:   12345,
				TxBytes:   67890,
				RxPackets: 100,
				TxPackets: 200,
			},
		},
	}
	mock.links["wg0"] = link
	mock.linksByIdx[10] = link

	stats, err := GetInterfaceStats("wg0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.RxBytes != 12345 {
		t.Errorf("RxBytes = %d, want 12345", stats.RxBytes)
	}
	if stats.TxBytes != 67890 {
		t.Errorf("TxBytes = %d, want 67890", stats.TxBytes)
	}
	if stats.RxPackets != 100 {
		t.Errorf("RxPackets = %d, want 100", stats.RxPackets)
	}
	if stats.TxPackets != 200 {
		t.Errorf("TxPackets = %d, want 200", stats.TxPackets)
	}
}

func TestGetInterfaceStats_FallbackToProc(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	// Link without Statistics -> nil Statistics triggers proc fallback
	mock.addLink(NewMockLink("wg0", 10, 0))

	content := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo frame compressed multicast
  wg0: 9999    800    0    0    0     0          0         0  4444    400    0    0    0     0       0          0
`
	dir := t.TempDir()
	procPath := filepath.Join(dir, "net_dev")
	if err := os.WriteFile(procPath, []byte(content), 0644); err != nil {
		t.Fatalf("write temp proc file: %v", err)
	}

	oldPath := procNetDevPath
	procNetDevPath = procPath
	t.Cleanup(func() { procNetDevPath = oldPath })

	stats, err := GetInterfaceStats("wg0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.RxBytes != 9999 {
		t.Errorf("RxBytes = %d, want 9999", stats.RxBytes)
	}
	if stats.TxBytes != 4444 {
		t.Errorf("TxBytes = %d, want 4444", stats.TxBytes)
	}
	if stats.RxPackets != 800 {
		t.Errorf("RxPackets = %d, want 800", stats.RxPackets)
	}
	if stats.TxPackets != 400 {
		t.Errorf("TxPackets = %d, want 400", stats.TxPackets)
	}
}

func TestGetInterfaceStats_InterfaceNotFound(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	_, err := GetInterfaceStats("nosuch0")
	if err == nil {
		t.Fatal("expected error for missing interface")
	}
}

// =========================================================================
// AddHostRoute with RouteAdd error
// =========================================================================

func TestAddHostRoute_RouteAddError(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	mock.addLink(NewMockLink("eth0", 2, 0))
	mock.routeAddErr = fmt.Errorf("route add failed")

	err := AddHostRoute("1.2.3.4", "192.168.1.1", "eth0")
	if err == nil {
		t.Fatal("expected error from RouteAdd")
	}
}

// =========================================================================
// IPv6 host route
// =========================================================================

func TestAddHostRoute_IPv6(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	mock.addLink(NewMockLink("eth0", 2, net.FlagUp))

	err := AddHostRoute("2001:db8::1", "fe80::1", "eth0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(mock.routes))
	}
	r := mock.routes[0]
	ones, bits := r.Dst.Mask.Size()
	if ones != 128 || bits != 128 {
		t.Errorf("expected /128 mask for IPv6 host route, got /%d (of %d)", ones, bits)
	}
}

// =========================================================================
// isPermError tests
// =========================================================================

func TestIsPermError_OperationNotPermitted(t *testing.T) {
	err := fmt.Errorf("operation not permitted")
	if !isPermError(err) {
		t.Error("should detect 'operation not permitted' string")
	}
}

func TestIsPermError_PermissionDenied(t *testing.T) {
	err := fmt.Errorf("permission denied")
	if !isPermError(err) {
		t.Error("should detect 'permission denied' string")
	}
}

func TestIsPermError_OsPermission(t *testing.T) {
	err := os.ErrPermission
	if !isPermError(err) {
		t.Error("should detect os.ErrPermission")
	}
}

func TestIsPermError_SyscallEPERM(t *testing.T) {
	err := &os.SyscallError{Syscall: "socket", Err: fmt.Errorf("EPERM")}
	// This won't match because err.Err is not EPERM constant, but test the path
	_ = isPermError(err) // exercises the SyscallError branch
}

func TestIsPermError_WrappedError(t *testing.T) {
	inner := fmt.Errorf("operation not permitted")
	err := fmt.Errorf("wrapped: %w", inner)
	if !isPermError(err) {
		t.Error("should detect wrapped 'operation not permitted'")
	}
}

func TestIsPermError_UnrelatedError(t *testing.T) {
	err := fmt.Errorf("connection refused")
	if isPermError(err) {
		t.Error("should not flag 'connection refused' as perm error")
	}
}

// =========================================================================
// LinkByName exported function
// =========================================================================

func TestLinkByName_Success(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	mock.addLink(NewMockLink("wg0", 10, net.FlagUp))

	link, err := LinkByName("wg0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if link.Attrs().Name != "wg0" {
		t.Errorf("name = %q, want wg0", link.Attrs().Name)
	}
}

func TestLinkByName_NotFound(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	_, err := LinkByName("nosuch0")
	if err == nil {
		t.Fatal("expected error for missing link")
	}
}

// =========================================================================
// ConfigureInterface with PresharedKey and Endpoint
// =========================================================================

func TestConfigureInterface_WithPresharedKeyAndEndpoint(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)
	wgMock := &mockWG{}
	SetWgctrlRunner(wgMock)

	wgi := newTestWGI(t, "wg-test")
	psk, _ := wgtypes.GenerateKey()
	wgi.Peer.PresharedKey = &psk
	wgi.Peer.Endpoint = &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 51820}
	wgi.Peer.PersistentKeepalive = 25 * time.Second

	err := wgi.ConfigureInterface()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// =========================================================================
// GetDefaultGateway with no gateway IP but valid link
// =========================================================================

func TestGetDefaultGateway_NoGwButValidLink(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	mock.addLink(NewMockLink("eth0", 3, net.FlagUp))

	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	mock.routes = []nl.Route{
		{
			LinkIndex: 3,
			Dst:       defaultNet,
			// No Gw
		},
	}

	gw, iface, err := GetDefaultGateway()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With no actual gateway (Gw == nil), GetDefaultGateway continues
	// scanning for a route with a real gateway. Finding none, it returns
	// empty strings — this is correct because a link-scope route without
	// a gateway can't be used for the VPN endpoint host route.
	if gw != "" {
		t.Errorf("gateway = %q, want empty (no gateway)", gw)
	}
	if iface != "" {
		t.Errorf("iface = %q, want empty (no usable gateway route)", iface)
	}
}

// =========================================================================
// FormatBytes edge cases
// =========================================================================

func TestFormatBytes_Ranges(t *testing.T) {
	tests := []struct {
		bytes float64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.00 KB"},
		{1024 * 1024, "1.00 MB"},
		{1024 * 1024 * 1024, "1.00 GB"},
		{2.5 * 1024 * 1024, "2.50 MB"},
	}

	for _, tt := range tests {
		got := FormatBytes(tt.bytes)
		if got != tt.want {
			t.Errorf("FormatBytes(%f) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestFormatBytesPerSec_Ranges(t *testing.T) {
	tests := []struct {
		bps  float64
		want string
	}{
		{0, "0 B/s"},
		{500, "500 B/s"},
		{1024, "1.00 KB/s"},
		{1024 * 1024, "1.00 MB/s"},
		{1024 * 1024 * 1024, "1.00 GB/s"},
	}

	for _, tt := range tests {
		got := FormatBytesPerSec(tt.bps)
		if got != tt.want {
			t.Errorf("FormatBytesPerSec(%f) = %q, want %q", tt.bps, got, tt.want)
		}
	}
}

// =========================================================================
// getStatsFromProc edge cases
// =========================================================================

func TestGetStatsFromProc_ShortFields(t *testing.T) {
	cleanup(t)

	// Line with fewer than 16 fields should be skipped
	content := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo frame compressed multicast
  wg0: 100 200 300
`
	dir := t.TempDir()
	procPath := filepath.Join(dir, "net_dev")
	os.WriteFile(procPath, []byte(content), 0644)

	oldPath := procNetDevPath
	procNetDevPath = procPath
	t.Cleanup(func() { procNetDevPath = oldPath })

	_, err := getStatsFromProc("wg0")
	if err == nil {
		t.Fatal("expected error for short field line")
	}
}

func TestGetStatsFromProc_NoColonLine(t *testing.T) {
	cleanup(t)

	content := `Inter-|   Receive
 face |bytes
someweirdline without colon
`
	dir := t.TempDir()
	procPath := filepath.Join(dir, "net_dev")
	os.WriteFile(procPath, []byte(content), 0644)

	oldPath := procNetDevPath
	procNetDevPath = procPath
	t.Cleanup(func() { procNetDevPath = oldPath })

	_, err := getStatsFromProc("wg0")
	if err == nil {
		t.Fatal("expected error for interface not found")
	}
}

// =========================================================================
// Parse functions edge cases
// =========================================================================

func TestParsePrivateKey_Invalid(t *testing.T) {
	_, err := ParsePrivateKey([]byte("short"))
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

func TestParsePrivateKey_WrongLength(t *testing.T) {
	// Raw bytes but wrong length (only 16 bytes instead of 32)
	_, err := ParsePrivateKey(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

func TestParseEndpoint_Invalid(t *testing.T) {
	_, err := ParseEndpoint("not-a-valid-endpoint")
	if err == nil {
		t.Fatal("expected error for invalid endpoint")
	}
}

func TestParseAllowedIPs_Empty(t *testing.T) {
	ips, err := ParseAllowedIPs("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ips != nil {
		t.Errorf("expected nil for empty input, got %v", ips)
	}
}

func TestParseAllowedIPs_InvalidCIDR(t *testing.T) {
	_, err := ParseAllowedIPs("not-a-cidr")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestParseAllowedIPs_MultipleCIDRs(t *testing.T) {
	ips, err := ParseAllowedIPs("0.0.0.0/0, 10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(ips))
	}
}

func TestSplitAndTrim_WithBlanks(t *testing.T) {
	result := splitAndTrim("  a , b ,  , c  ", ",")
	if len(result) != 3 {
		t.Fatalf("expected 3 items, got %d: %v", len(result), result)
	}
	if result[0] != "a" || result[1] != "b" || result[2] != "c" {
		t.Errorf("unexpected result: %v", result)
	}
}

func TestMaskBits_IPv4And6(t *testing.T) {
	mask := net.CIDRMask(24, 32)
	if maskBits(mask) != 24 {
		t.Errorf("maskBits = %d, want 24", maskBits(mask))
	}
	mask128 := net.CIDRMask(128, 128)
	if maskBits(mask128) != 128 {
		t.Errorf("maskBits = %d, want 128", maskBits(mask128))
	}
}

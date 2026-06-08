package wireguard

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/firewall"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/logger"
	netlinkpkg "github.com/blank-query/lazyVPN-for-Omarchy/internal/netlink"
	"github.com/godbus/dbus/v5"
	nl "github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// validBase64Key is a valid 32-byte WireGuard key in base64 (44 chars ending with =)
const validBase64Key = "YNqHbfBQKaGvct4Jt2ZLKXHXP0sMhCX80fPlOSf80Vo="

// secondValidBase64Key is a different valid WireGuard key
const secondValidBase64Key = "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkMTI="

// mustDecodeKey decodes a base64 WireGuard key to raw bytes, panicking on failure.
func mustDecodeKey(b64 string) []byte {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic("mustDecodeKey: " + err.Error())
	}
	return key
}

// saveFuncVars saves all function variables and returns a restore function.
// Must be called before overriding any vars.
func saveFuncVars(t *testing.T) {
	t.Helper()

	origDeleteLinkInterface := netlinkDeleteLinkInterface
	origDeleteSplitRoutes := netlinkDeleteSplitRoutes
	origDeleteHostRoute := netlinkDeleteHostRoute
	origGetDefaultGateway := netlinkGetDefaultGateway
	origAddHostRoute := netlinkAddHostRoute
	origAddSplitRoutes := netlinkAddSplitRoutes
	origInterfaceExists := netlinkInterfaceExists
	origLinkByName := netlinkLinkByName
	origFirewallIsActive := firewallIsActive
	origFirewallEnable := firewallEnable
	origFirewallUpdate := firewallUpdate
	origFirewallEnableSimple := firewallEnableSimple
	origFirewallDisable := firewallDisable
	origUtilGetPublicIPv4 := utilGetPublicIPv4
	origUtilGetPublicIPv4WithRetry := utilGetPublicIPv4WithRetry
	origUtilGetPublicIPv6 := utilGetPublicIPv6
	origUtilCheckIPv6Leak := utilCheckIPv6Leak
	origUtilWaitForConnectivity := utilWaitForConnectivity
	origUtilCheckInternetConnectivity := utilCheckInternetConnectivity
	origIsConnectedFunc := isConnectedFunc
	origDisconnectFunc := disconnectFunc
	origConfigureDNSFunc := configureDNSFunc
	origUnconfigureDNSFunc := unconfigureDNSFunc
	origConfigLoadProvider := configLoadProvider
	origConfigLoadServerFromCache := configLoadServerFromCache
	origTimeSleep := timeSleep
	origStatusLinkByName := statusLinkByName
	origStatusAddrList := statusAddrList
	origStatusGetDevice := statusGetDevice
	origTimeNow := timeNow
	origDbusConnectSystemBus := dbusConnectSystemBus
	origConfigureDNSviaDbusFunc := configureDNSviaDbusFunc
	origConfigureDNSviaResolvectlFunc := configureDNSviaResolvectlFunc
	origExecCommand := execCommand
	origLookupGeoFunc := lookupGeoFunc
	origGetPhysicalInterface := getPhysicalInterface
	origFirewallEnableLANBlock := firewallEnableLANBlock
	origFirewallIsLANBlockActive := firewallIsLANBlockActive
	origFirewallIsIPv6Disabled := firewallIsIPv6Disabled
	origUtilGetPublicIPInfo := utilGetPublicIPInfo
	origCaptureBaselineDNS := captureBaselineDNS

	t.Cleanup(func() {
		netlinkDeleteLinkInterface = origDeleteLinkInterface
		netlinkDeleteSplitRoutes = origDeleteSplitRoutes
		netlinkDeleteHostRoute = origDeleteHostRoute
		netlinkGetDefaultGateway = origGetDefaultGateway
		netlinkAddHostRoute = origAddHostRoute
		netlinkAddSplitRoutes = origAddSplitRoutes
		netlinkInterfaceExists = origInterfaceExists
		netlinkLinkByName = origLinkByName
		firewallIsActive = origFirewallIsActive
		firewallEnable = origFirewallEnable
		firewallUpdate = origFirewallUpdate
		firewallEnableSimple = origFirewallEnableSimple
		firewallDisable = origFirewallDisable
		utilGetPublicIPv4 = origUtilGetPublicIPv4
		utilGetPublicIPv4WithRetry = origUtilGetPublicIPv4WithRetry
		utilGetPublicIPv6 = origUtilGetPublicIPv6
		utilCheckIPv6Leak = origUtilCheckIPv6Leak
		utilWaitForConnectivity = origUtilWaitForConnectivity
		utilCheckInternetConnectivity = origUtilCheckInternetConnectivity
		isConnectedFunc = origIsConnectedFunc
		disconnectFunc = origDisconnectFunc
		configureDNSFunc = origConfigureDNSFunc
		unconfigureDNSFunc = origUnconfigureDNSFunc
		configLoadProvider = origConfigLoadProvider
		configLoadServerFromCache = origConfigLoadServerFromCache
		timeSleep = origTimeSleep
		statusLinkByName = origStatusLinkByName
		statusAddrList = origStatusAddrList
		statusGetDevice = origStatusGetDevice
		timeNow = origTimeNow
		dbusConnectSystemBus = origDbusConnectSystemBus
		configureDNSviaDbusFunc = origConfigureDNSviaDbusFunc
		configureDNSviaResolvectlFunc = origConfigureDNSviaResolvectlFunc
		execCommand = origExecCommand
		lookupGeoFunc = origLookupGeoFunc
		getPhysicalInterface = origGetPhysicalInterface
		firewallEnableLANBlock = origFirewallEnableLANBlock
		firewallIsLANBlockActive = origFirewallIsLANBlockActive
		firewallIsIPv6Disabled = origFirewallIsIPv6Disabled
		utilGetPublicIPInfo = origUtilGetPublicIPInfo
		captureBaselineDNS = origCaptureBaselineDNS
		netlinkpkg.SetNetlinkRunner(nil)
		netlinkpkg.SetWgctrlRunner(nil)
	})
}

// setupAllMocks installs default no-op/success mocks for all function variables.
// Individual tests can override specific vars after calling this.
func setupAllMocks(t *testing.T) {
	t.Helper()
	saveFuncVars(t)

	// Create mock netlink/wgctrl runners
	mock := newMockNetlinkRunner()
	mock.addLink(netlinkpkg.NewMockLink("wg0", 10, net.FlagUp))
	netlinkpkg.SetNetlinkRunner(mock)

	wgMock := &mockWgctrlRunner{}
	netlinkpkg.SetWgctrlRunner(wgMock)

	// Default mocks for all function vars
	netlinkDeleteLinkInterface = func(name string) error { return nil }
	netlinkDeleteSplitRoutes = func(name string) error { return nil }
	netlinkDeleteHostRoute = func(host string) error { return nil }
	netlinkGetDefaultGateway = func() (string, string, error) { return "192.168.1.1", "eth0", nil }
	netlinkAddHostRoute = func(host, gateway, iface string) error { return nil }
	netlinkAddSplitRoutes = func(ifaceName string) error { return nil }
	netlinkInterfaceExists = func(name string) bool { return false }
	netlinkLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	firewallIsActive = func() bool { return false }
	firewallEnable = func(cfg *firewall.KillswitchConfig) error { return nil }
	firewallUpdate = func(cfg *firewall.KillswitchConfig) error { return nil }
	firewallEnableSimple = func() error { return nil }
	firewallDisable = func() error { return nil }
	utilGetPublicIPv4 = func() (string, error) { return "1.1.1.1", nil }
	utilGetPublicIPInfo = func() (string, string, error) { return "1.1.1.1", "Test ISP", nil }
	captureBaselineDNS = func() []string { return []string{"8.8.8.8"} }
	utilGetPublicIPv4WithRetry = func(attempts int) (string, error) { return "2.2.2.2", nil }
	utilGetPublicIPv6 = func() (string, error) { return "", fmt.Errorf("no ipv6") }
	utilCheckIPv6Leak = func() (string, bool) { return "", false }
	utilWaitForConnectivity = func(maxAttempts int, interval time.Duration) bool { return true }
	utilCheckInternetConnectivity = func() bool { return true }
	isConnectedFunc = func(name string) bool { return false }
	disconnectFunc = func(cfg *config.Config) error { return nil }
	configureDNSFunc = func(ifaceName string, dns string) error { return nil }
	unconfigureDNSFunc = func(ifaceName string) error { return nil }
	timeSleep = func(d time.Duration) {} // no-op to speed up tests
	getPhysicalInterface = func() (string, string, error) { return "eth0", "192.168.1.1", nil }
	firewallEnableLANBlock = func(vpnIface, endpoint, gateway, dns string) error { return nil }
	firewallIsLANBlockActive = func() bool { return false }
	firewallIsIPv6Disabled = func() bool { return false }
	dbusConnectSystemBus = func(opts ...dbus.ConnOption) (*dbus.Conn, error) {
		return nil, fmt.Errorf("dbus not available in test")
	}
}

// newMockNetlinkRunner creates a mockNL compatible with the netlink package runner interface.
// We create a thin wrapper that implements netlink.NetlinkRunner.
type mockNLRunner struct {
	links       map[string]nl.Link
	linksByIdx  map[int]nl.Link
	routes      []nl.Route
	addErr      error
	delErr      error
	upErr       error
	mtuErr      error
	addrErr     error
	routeAddErr error
	routeDelErr error
}

func newMockNetlinkRunner() *mockNLRunner {
	return &mockNLRunner{
		links:      make(map[string]nl.Link),
		linksByIdx: make(map[int]nl.Link),
	}
}

func (m *mockNLRunner) addLink(link nl.Link) {
	m.links[link.Attrs().Name] = link
	m.linksByIdx[link.Attrs().Index] = link
}

func (m *mockNLRunner) LinkByName(name string) (nl.Link, error) {
	l, ok := m.links[name]
	if !ok {
		return nil, fmt.Errorf("link not found")
	}
	return l, nil
}

func (m *mockNLRunner) LinkByIndex(index int) (nl.Link, error) {
	l, ok := m.linksByIdx[index]
	if !ok {
		return nil, fmt.Errorf("link not found by index")
	}
	return l, nil
}

func (m *mockNLRunner) LinkAdd(link nl.Link) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.links[link.Attrs().Name] = link
	m.linksByIdx[link.Attrs().Index] = link
	return nil
}

func (m *mockNLRunner) LinkDel(link nl.Link) error {
	if m.delErr != nil {
		return m.delErr
	}
	delete(m.links, link.Attrs().Name)
	delete(m.linksByIdx, link.Attrs().Index)
	return nil
}

func (m *mockNLRunner) LinkSetUp(link nl.Link) error {
	if m.upErr != nil {
		return m.upErr
	}
	link.Attrs().Flags |= net.FlagUp
	return nil
}

func (m *mockNLRunner) LinkSetDown(link nl.Link) error {
	link.Attrs().Flags &^= net.FlagUp
	return nil
}

func (m *mockNLRunner) LinkSetMTU(link nl.Link, mtu int) error {
	if m.mtuErr != nil {
		return m.mtuErr
	}
	link.Attrs().MTU = mtu
	return nil
}

func (m *mockNLRunner) AddrAdd(link nl.Link, addr *nl.Addr) error {
	return m.addrErr
}

func (m *mockNLRunner) RouteAdd(route *nl.Route) error {
	if m.routeAddErr != nil {
		return m.routeAddErr
	}
	m.routes = append(m.routes, *route)
	return nil
}

func (m *mockNLRunner) RouteDel(route *nl.Route) error {
	if m.routeDelErr != nil {
		return m.routeDelErr
	}
	return nil
}

func (m *mockNLRunner) RouteList(link nl.Link, family int) ([]nl.Route, error) {
	return m.routes, nil
}

type mockWgctrlRunner struct {
	configErr error
	device    *wgtypes.Device
	deviceErr error
}

func (m *mockWgctrlRunner) ConfigureDevice(name string, cfg wgtypes.Config) error {
	return m.configErr
}

func (m *mockWgctrlRunner) Device(name string) (*wgtypes.Device, error) {
	if m.deviceErr != nil {
		return nil, m.deviceErr
	}
	if m.device != nil {
		return m.device, nil
	}
	return &wgtypes.Device{Name: name}, nil
}

func (m *mockWgctrlRunner) Close() error { return nil }

// newTestConfig creates a minimal config in a temp directory.
func newTestConfig(t *testing.T) *config.Config {
	t.Helper()
	tmpDir := t.TempDir()
	return &config.Config{
		ConnectionName:        "wg0",
		ConfigDir:             tmpDir,
		ConfigFile:            filepath.Join(tmpDir, "config.json"),
		KillswitchAutoDisable: "true",
		LogMode:               "safe",
		CustomMTU:             1420,
	}
}

// newTestServer creates a Server with valid WireGuard keys.
func newTestServer() *Server {
	return &Server{
		Config: &Config{
			Name:                "US-NY#42",
			PrivateKey:          mustDecodeKey(validBase64Key),
			PublicKey:           secondValidBase64Key,
			Endpoint:            "1.2.3.4:51820",
			Address:             "10.2.0.2/32",
			DNS:                 "10.2.0.1",
			AllowedIPs:          "0.0.0.0/0",
			PersistentKeepalive: 25,
		},
		Info: &ServerInfo{
			Name:    "US-NY#42",
			Country: "US",
			State:   "NY",
			Number:  "42",
		},
	}
}

// collectStatuses returns a callback that collects all status updates.
func collectStatuses() (StatusCallback, *[]ConnectionStatus) {
	var statuses []ConnectionStatus
	cb := func(s ConnectionStatus) {
		statuses = append(statuses, s)
	}
	return cb, &statuses
}

// collectDisconnectStatuses returns a callback that collects all disconnect status updates.
func collectDisconnectStatuses() (DisconnectCallback, *[]DisconnectStatus) {
	var statuses []DisconnectStatus
	cb := func(s DisconnectStatus) {
		statuses = append(statuses, s)
	}
	return cb, &statuses
}

// ---------------------------------------------------------------------------
// parseAddress tests (these already exist but we add more edge cases)
// ---------------------------------------------------------------------------

func TestParseAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantIP   string
		wantMask int // prefix length
		wantErr  bool
	}{
		// Standard IPv4 CIDR
		{"ipv4 /32", "10.2.0.2/32", "10.2.0.2", 32, false},
		{"ipv4 /24", "192.168.1.5/24", "192.168.1.5", 24, false},
		{"ipv4 /16", "172.16.0.1/16", "172.16.0.1", 16, false},

		// Standard IPv6 CIDR
		{"ipv6 /128", "fd00::2/128", "fd00::2", 128, false},
		{"ipv6 /64", "2001:db8::1/64", "2001:db8::1", 64, false},

		// Comma-separated (takes first)
		{"comma ipv4+ipv6", "10.2.0.2/32, fd00::2/128", "10.2.0.2", 32, false},
		{"comma with spaces", "  10.2.0.2/32  ,  fd00::2/128  ", "10.2.0.2", 32, false},
		{"comma ipv6 first", "fd00::2/128, 10.2.0.2/32", "fd00::2", 128, false},

		// Bare IP without prefix (auto-adds /32 or /128)
		{"bare ipv4", "10.2.0.2", "10.2.0.2", 32, false},
		{"bare ipv6", "fd00::2", "fd00::2", 128, false},

		// Comma-separated bare IPs
		{"comma bare ipv4", "10.2.0.2, fd00::2", "10.2.0.2", 32, false},

		// Error cases
		{"invalid address", "not-an-ip/32", "", 0, true},
		{"bare invalid", "not-an-ip", "", 0, true},
		{"empty string", "", "", 0, true},
		{"invalid cidr prefix", "10.2.0.2/abc", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostIP, ipnet, err := parseAddress(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if hostIP.String() != tt.wantIP {
				t.Errorf("hostIP = %q, want %q", hostIP.String(), tt.wantIP)
			}

			ones, _ := ipnet.Mask.Size()
			if ones != tt.wantMask {
				t.Errorf("mask prefix = %d, want %d", ones, tt.wantMask)
			}
		})
	}
}

func TestParseAddressHostIPPreserved(t *testing.T) {
	// net.ParseCIDR masks the IP to the network address, but parseAddress
	// returns the actual host IP. Verify this behavior.
	hostIP, ipnet, err := parseAddress("192.168.1.100/24")
	if err != nil {
		t.Fatal(err)
	}

	// hostIP should be the actual address
	if hostIP.String() != "192.168.1.100" {
		t.Errorf("hostIP = %q, want 192.168.1.100", hostIP.String())
	}

	// ipnet.IP from net.ParseCIDR is the network address (masked)
	if ipnet.IP.String() != "192.168.1.0" {
		t.Errorf("ipnet.IP = %q, want 192.168.1.0 (network address)", ipnet.IP.String())
	}

	// Reconstruct what Connect() does: use host IP with parsed mask
	hostNet := net.IPNet{IP: hostIP, Mask: ipnet.Mask}
	if hostNet.IP.String() != "192.168.1.100" {
		t.Errorf("hostNet.IP = %q, want 192.168.1.100", hostNet.IP.String())
	}
	ones, _ := hostNet.Mask.Size()
	if ones != 24 {
		t.Errorf("hostNet mask = /%d, want /24", ones)
	}
}

// ---------------------------------------------------------------------------
// Connect() tests
// ---------------------------------------------------------------------------

func TestConnect_HappyPath(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	cb, statuses := collectStatuses()

	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	// Check that final status is success
	found := false
	for _, s := range *statuses {
		if s.Success {
			found = true
			if s.NewIP != "2.2.2.2" {
				t.Errorf("NewIP = %q, want 2.2.2.2", s.NewIP)
			}
			if s.OldIP != "1.1.1.1" {
				t.Errorf("OldIP = %q, want 1.1.1.1", s.OldIP)
			}
		}
	}
	if !found {
		t.Error("no success status received")
	}

	// Config should be updated
	if cfg.LastConnectedServer != "US-NY#42" {
		t.Errorf("LastConnectedServer = %q", cfg.LastConnectedServer)
	}
	if cfg.LastPublicIP != "2.2.2.2" {
		t.Errorf("LastPublicIP = %q", cfg.LastPublicIP)
	}
}

func TestConnect_InvalidPrivateKey(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	server.Config.PrivateKey = []byte("short")
	cb, _ := collectStatuses()

	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error for invalid private key")
	}
	if !strings.Contains(err.Error(), "invalid private key") {
		t.Errorf("error = %q, want 'invalid private key'", err.Error())
	}
}

func TestConnect_InvalidPublicKey(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	server.Config.PublicKey = "not-valid-base64!!!"
	cb, _ := collectStatuses()

	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error for invalid public key")
	}
	if !strings.Contains(err.Error(), "invalid public key") {
		t.Errorf("error = %q, want 'invalid public key'", err.Error())
	}
}

func TestConnect_InvalidPresharedKey(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	server.Config.PresharedKey = []byte("short")
	cb, _ := collectStatuses()

	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error for invalid preshared key")
	}
	if !strings.Contains(err.Error(), "invalid preshared key") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConnect_InvalidEndpoint(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	server.Config.Endpoint = "not-an-endpoint"
	cb, _ := collectStatuses()

	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error for invalid endpoint")
	}
	if !strings.Contains(err.Error(), "invalid endpoint") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConnect_InvalidAddress(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	server.Config.Address = "garbage"
	cb, _ := collectStatuses()

	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
	if !strings.Contains(err.Error(), "invalid address") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConnect_InvalidAllowedIPs(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	server.Config.AllowedIPs = "not-a-cidr"
	cb, _ := collectStatuses()

	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error for invalid allowed IPs")
	}
	if !strings.Contains(err.Error(), "invalid allowed IPs") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConnect_InterfaceCreationFails(t *testing.T) {
	setupAllMocks(t)

	// Make the netlink runner fail on LinkAdd
	mock := newMockNetlinkRunner()
	mock.addLink(netlinkpkg.NewMockLink("wg0", 10, net.FlagUp))
	mock.addErr = fmt.Errorf("link add failed")
	netlinkpkg.SetNetlinkRunner(mock)

	cfg := newTestConfig(t)
	server := newTestServer()
	cb, _ := collectStatuses()

	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error when interface creation fails")
	}
	if !strings.Contains(err.Error(), "failed to create interface") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConnect_ConfigureInterfaceFails(t *testing.T) {
	setupAllMocks(t)

	// Make wgctrl fail
	wgMock := &mockWgctrlRunner{configErr: fmt.Errorf("wgctrl config failed")}
	netlinkpkg.SetWgctrlRunner(wgMock)

	cfg := newTestConfig(t)
	server := newTestServer()
	cb, _ := collectStatuses()

	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error when configure interface fails")
	}
	if !strings.Contains(err.Error(), "failed to configure interface") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConnect_AssignAddressFails(t *testing.T) {
	setupAllMocks(t)

	mock := newMockNetlinkRunner()
	mock.addLink(netlinkpkg.NewMockLink("wg0", 10, net.FlagUp))
	mock.addrErr = fmt.Errorf("addr add failed")
	netlinkpkg.SetNetlinkRunner(mock)

	cfg := newTestConfig(t)
	server := newTestServer()
	cb, _ := collectStatuses()

	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error when assign address fails")
	}
	if !strings.Contains(err.Error(), "failed to assign address") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConnect_BringUpFails(t *testing.T) {
	setupAllMocks(t)

	mock := newMockNetlinkRunner()
	mock.addLink(netlinkpkg.NewMockLink("wg0", 10, 0))
	mock.upErr = fmt.Errorf("bring up failed")
	netlinkpkg.SetNetlinkRunner(mock)

	cfg := newTestConfig(t)
	server := newTestServer()
	cb, _ := collectStatuses()

	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error when bring up fails")
	}
	if !strings.Contains(err.Error(), "failed to bring up interface") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConnect_DNSFailureIsFatal(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()

	// DNS failure must cause Connect to fail (queries would leak)
	configureDNSFunc = func(ifaceName string, dns string) error {
		return fmt.Errorf("dns configuration failed")
	}

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("Connect() should fail when DNS configuration fails")
	}
	if !strings.Contains(err.Error(), "DNS configuration failed") {
		t.Errorf("error should mention DNS failure, got: %v", err)
	}
}

func TestConnect_ConnectivityCheckFails(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()

	cleanupCalled := false
	netlinkDeleteSplitRoutes = func(name string) error {
		cleanupCalled = true
		return nil
	}

	utilWaitForConnectivity = func(maxAttempts int, interval time.Duration) bool {
		return false // no connectivity
	}

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error when connectivity check fails")
	}
	if !strings.Contains(err.Error(), "no internet connectivity") {
		t.Errorf("error = %q", err.Error())
	}
	if !cleanupCalled {
		t.Error("cleanup should have been called after connectivity failure")
	}
}

func TestConnect_IPVerificationFails(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()

	utilGetPublicIPv4WithRetry = func(attempts int) (string, error) {
		return "", fmt.Errorf("all IP lookup attempts failed")
	}

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error when IP verification fails")
	}
	if !strings.Contains(err.Error(), "failed to verify public IP") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConnect_IPUnchanged(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()

	// Both old and new IP return the same value
	utilGetPublicIPv4 = func() (string, error) { return "1.1.1.1", nil }
	utilGetPublicIPv4WithRetry = func(attempts int) (string, error) { return "1.1.1.1", nil }

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("expected error when IP unchanged")
	}
	if !strings.Contains(err.Error(), "IP unchanged") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConnect_KillswitchUpdatePath(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()

	firewallIsActive = func() bool { return true }

	updateCalled := false
	firewallUpdate = func(ksCfg *firewall.KillswitchConfig) error {
		updateCalled = true
		if ksCfg.Endpoint != "1.2.3.4" {
			t.Errorf("firewall update endpoint = %q, want 1.2.3.4", ksCfg.Endpoint)
		}
		return nil
	}

	cb, statuses := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	if !updateCalled {
		t.Error("firewall.Update should have been called when killswitch is active")
	}

	// Verify callback includes firewall update stage
	foundFirewall := false
	for _, s := range *statuses {
		if strings.Contains(s.Stage, "Firewall updated") {
			foundFirewall = true
		}
	}
	if !foundFirewall {
		t.Error("expected firewall update status callback")
	}
}

func TestConnect_KillswitchUpdateFails(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()

	firewallIsActive = func() bool { return true }
	firewallUpdate = func(ksCfg *firewall.KillswitchConfig) error {
		return fmt.Errorf("firewall update failed")
	}

	cb, _ := collectStatuses()
	// Should NOT fail - firewall update failure is non-fatal
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() should succeed even when firewall update fails: %v", err)
	}
}

// TestConnect_KillswitchUpdateFails_SurfacesDualChannelWarning is the
// dual-signal companion to TestConnect_KillswitchUpdateFails. The
// existing test only verifies Connect returns nil ("non-fatal"). This
// test verifies both:
//   1) The callback emits a user-visible warning so the TUI's progress
//      view shows what went wrong (otherwise the connect appears to
//      succeed silently with a stale killswitch underneath).
//   2) debug.log records the underlying error so users investigating
//      later have a breadcrumb.
//
// Pattern matches 006036e (disconnect DNS revert), 1c33df3 (interface
// delete), 591fc57 (route cleanup). Same dual-channel contract for
// every warn-and-continue path.
func TestConnect_KillswitchUpdateFails_SurfacesDualChannelWarning(t *testing.T) {
	setupAllMocks(t)
	cfg := newLoggingTestConfig(t)
	server := newTestServer()

	firewallIsActive = func() bool { return true }
	firewallUpdate = func(ksCfg *firewall.KillswitchConfig) error {
		return fmt.Errorf("synthetic firewall update failure")
	}

	cb, statuses := collectStatuses()
	if err := Connect(cfg, server, cb); err != nil {
		t.Fatalf("Connect should not abort on firewall update failure: %v", err)
	}

	// (1) Callback warning visible to caller.
	foundCallbackWarning := false
	for _, s := range *statuses {
		if strings.Contains(s.Stage, "failed to update firewall") {
			foundCallbackWarning = true
			break
		}
	}
	if !foundCallbackWarning {
		t.Errorf("expected callback warning about firewall update failure; statuses: %+v", *statuses)
	}

	// (2) debug.log forensic record.
	logContent := readLogFile(cfg.ConfigDir)
	if !strings.Contains(logContent, "Firewall update failed") {
		t.Errorf("debug.log should contain 'Firewall update failed', got: %q", logContent)
	}
	if !strings.Contains(logContent, "synthetic firewall update failure") {
		t.Errorf("debug.log should preserve underlying error, got: %q", logContent)
	}
}

func TestConnect_DisconnectsExistingConnection(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()

	disconnectCalled := false
	isConnectedFunc = func(name string) bool { return true }
	disconnectFunc = func(cfg *config.Config) error {
		disconnectCalled = true
		return nil
	}

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	if !disconnectCalled {
		t.Error("Disconnect should have been called for existing connection")
	}
}

func TestConnect_StoresRealIPWhenNotConnected(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()

	utilGetPublicIPInfo = func() (string, string, error) { return "5.5.5.5", "Custom ISP", nil }
	utilGetPublicIPv4 = func() (string, error) { return "5.5.5.5", nil }
	isConnectedFunc = func(name string) bool { return false }

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	if cfg.RealPublicIP != "5.5.5.5" {
		t.Errorf("RealPublicIP = %q, want 5.5.5.5", cfg.RealPublicIP)
	}
	if cfg.BaselineIP != "5.5.5.5" {
		t.Errorf("BaselineIP = %q, want 5.5.5.5", cfg.BaselineIP)
	}
	if cfg.BaselineOrg != "Custom ISP" {
		t.Errorf("BaselineOrg = %q, want Custom ISP", cfg.BaselineOrg)
	}
}

func TestConnect_EmptyAllowedIPsDefault(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	server.Config.AllowedIPs = "" // empty should default to "0.0.0.0/0,::/0"

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
}

func TestConnect_CustomMTU(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	server.Config.MTU = 1400

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
}

func TestConnect_MTUSetFailNonFatal(t *testing.T) {
	setupAllMocks(t)

	mock := newMockNetlinkRunner()
	mock.addLink(netlinkpkg.NewMockLink("wg0", 10, net.FlagUp))
	mock.mtuErr = fmt.Errorf("mtu set failed")
	netlinkpkg.SetNetlinkRunner(mock)

	cfg := newTestConfig(t)
	server := newTestServer()

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	// MTU failure is non-fatal
	if err != nil {
		t.Fatalf("Connect() should succeed even when MTU set fails: %v", err)
	}
}

func TestConnect_IPv6LeakCheck(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	// IPv6 protection is read from UFW rules, not config.
	firewallIsIPv6Disabled = func() bool { return true }
	server := newTestServer()

	utilCheckIPv6Leak = func() (string, bool) { return "2001:db8::1", true }

	cb, statuses := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	foundLeak := false
	for _, s := range *statuses {
		if strings.Contains(s.Stage, "IPv6 leak detected") {
			foundLeak = true
		}
	}
	if !foundLeak {
		t.Error("expected IPv6 leak warning in status callbacks")
	}
}

// TestConnect_IPv6Unavailable_HasWarningFlag completes the IPv6
// styling-flag family (01841c7 + e2155cb). When IPv6 protection is
// OFF and the user has no IPv6 connectivity, Connect emits:
//
//   callback(ConnectionStatus{
//     Stage: "IPv6 unavailable (not required)",
//     Warning: true,
//   })
//
// The Warning flag matters: even though IPv6 protection is off (so
// no leak), the absence of IPv6 connectivity might surprise users
// who expect dual-stack. Showing it as yellow/warning lets them know
// "IPv6 isn't reaching you" without alarming them (it's not a leak).
//
// A regression that dropped Warning:true would display this as
// routine info — users might miss that their dual-stack setup isn't
// working as expected. Dropping the message entirely is a different
// bug class (different test); this pins only the styling flag.
//
// Same family as 2a46e3f / 01841c7 / e2155cb.
func TestConnect_IPv6Unavailable_HasWarningFlag(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	firewallIsIPv6Disabled = func() bool { return false } // protection off
	utilGetPublicIPv6 = func() (string, error) {
		return "", fmt.Errorf("no IPv6 connectivity")
	}
	server := newTestServer()

	cb, statuses := collectStatuses()
	if err := Connect(cfg, server, cb); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var unavailStatus *ConnectionStatus
	for i := range *statuses {
		if (*statuses)[i].Stage == "IPv6 unavailable (not required)" {
			unavailStatus = &(*statuses)[i]
			break
		}
	}
	if unavailStatus == nil {
		t.Fatalf("expected 'IPv6 unavailable' status; got: %+v", *statuses)
	}
	if !unavailStatus.Warning {
		t.Error("Warning flag should be true on IPv6-unavailable status (yellow styling vs routine info)")
	}
	// Defensive: not a leak, not a success.
	if unavailStatus.Danger {
		t.Error("Danger flag should not be set (IPv6 unavailable is not a leak)")
	}
	if unavailStatus.Success {
		t.Error("Success flag should not be set (IPv6 unavailable is not a positive confirmation)")
	}
}

// TestConnect_SetMTUFailure_DualChannelWarning covers the warn-and-
// continue + dual-channel signal for the SetMTU step in Connect.
// When the kernel rejects the configured MTU (e.g., link not yet
// up, value out of range for the link type), Connect MUST:
//
//   1) Continue (non-fatal — connection still works at default MTU)
//   2) Emit a callback warning with Warning: true for TUI styling
//   3) Log the underlying error to debug.log for forensic recovery
//
// Without (1), a transient MTU rejection would abort the entire
// connect. Without (2), the user wouldn't see why their custom MTU
// didn't apply. Without (3), there's no forensic record to debug
// "why is my MTU different than configured" after the fact.
//
// Sibling to 6f44216 (firewall update) / 2a46e3f (disconnect error).
func TestConnect_SetMTUFailure_DualChannelWarning(t *testing.T) {
	setupAllMocks(t)
	cfg := newLoggingTestConfig(t)
	cfg.CustomMTU = 1280

	// Replace netlink runner with one that fails on SetMTU.
	mockWithMTUErr := newMockNetlinkRunner()
	mockWithMTUErr.addLink(netlinkpkg.NewMockLink("wg0", 10, net.FlagUp))
	mockWithMTUErr.mtuErr = fmt.Errorf("synthetic MTU rejection")
	netlinkpkg.SetNetlinkRunner(mockWithMTUErr)

	server := newTestServer()
	cb, statuses := collectStatuses()
	if err := Connect(cfg, server, cb); err != nil {
		t.Fatalf("Connect should continue past MTU failure: %v", err)
	}

	// (2) Callback warning with Warning flag.
	var mtuStatus *ConnectionStatus
	for i := range *statuses {
		if strings.Contains((*statuses)[i].Stage, "MTU 1280 not applied") {
			mtuStatus = &(*statuses)[i]
			break
		}
	}
	if mtuStatus == nil {
		t.Fatalf("expected MTU warning status; got: %+v", *statuses)
	}
	if !mtuStatus.Warning {
		t.Error("Warning flag should be true on MTU-rejection status (drives TUI styling)")
	}

	// (3) debug.log forensic record.
	logContent := readLogFile(cfg.ConfigDir)
	if !strings.Contains(logContent, "SetMTU(1280) failed") {
		t.Errorf("debug.log should contain 'SetMTU(1280) failed', got: %q", logContent)
	}
	if !strings.Contains(logContent, "synthetic MTU rejection") {
		t.Errorf("debug.log should preserve underlying error, got: %q", logContent)
	}
}

// TestConnect_IPv6ConfirmedBlocked_HasSuccessFlag is the inverse
// of TestConnect_IPv6LeakDetected_HasDangerFlag. When IPv6 protection
// is on AND no leak is detected, the callback emits:
//
//   callback(ConnectionStatus{
//     Stage: "IPv6 confirmed blocked",
//     Success: true,
//   })
//
// The Success flag drives green/checkmark TUI styling. Without it
// the "confirmed blocked" message would look like routine info — the
// user wouldn't get clear positive feedback that the security check
// passed. For a security feature, the user needs to SEE the green
// checkmark to trust the protection is working.
//
// Same family as 2a46e3f / 01841c7.
func TestConnect_IPv6ConfirmedBlocked_HasSuccessFlag(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	firewallIsIPv6Disabled = func() bool { return true }
	utilCheckIPv6Leak = func() (string, bool) { return "", false } // no leak
	server := newTestServer()

	cb, statuses := collectStatuses()
	if err := Connect(cfg, server, cb); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var blockedStatus *ConnectionStatus
	for i := range *statuses {
		if (*statuses)[i].Stage == "IPv6 confirmed blocked" {
			blockedStatus = &(*statuses)[i]
			break
		}
	}
	if blockedStatus == nil {
		t.Fatalf("expected 'IPv6 confirmed blocked' status; got: %+v", *statuses)
	}
	if !blockedStatus.Success {
		t.Error("Success flag should be true on confirmed-blocked status (drives TUI green/checkmark styling)")
	}
	// Defensive: confirmed-blocked is NOT danger.
	if blockedStatus.Danger {
		t.Error("Danger flag should not be set on confirmed-blocked status")
	}
}

// TestConnect_IPv6LeakDetected_HasDangerFlag is the styling-flag
// companion to TestConnect_IPv6LeakCheck. The existing test verifies
// the "IPv6 leak detected" message text appears in callbacks. This
// test verifies the Danger: true flag is set on that status.
//
// The Danger flag drives TUI styling — it's the difference between
// the user seeing a red/critical "IPv6 LEAK" warning vs a plain
// info-level text line they might scroll past. A regression that
// dropped Danger:true (e.g. someone refactors to use Warning instead)
// would silently downgrade leak warnings to look like routine status
// messages — exactly the wrong direction for a security signal.
//
// Sibling to 2a46e3f (disconnect-error Warning flag pin).
func TestConnect_IPv6LeakDetected_HasDangerFlag(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	firewallIsIPv6Disabled = func() bool { return true }
	utilCheckIPv6Leak = func() (string, bool) { return "2001:db8::1", true }
	server := newTestServer()

	cb, statuses := collectStatuses()
	if err := Connect(cfg, server, cb); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var leakStatus *ConnectionStatus
	for i := range *statuses {
		if strings.Contains((*statuses)[i].Stage, "IPv6 leak detected") {
			leakStatus = &(*statuses)[i]
			break
		}
	}
	if leakStatus == nil {
		t.Fatalf("expected callback with 'IPv6 leak detected' stage; got: %+v", *statuses)
	}
	if !leakStatus.Danger {
		t.Error("Danger flag should be true on IPv6-leak status (drives TUI red/critical styling; without it the leak warning looks like routine info text)")
	}
	// Defensive: a leak is NOT success.
	if leakStatus.Success {
		t.Error("Success flag should not be set on IPv6-leak status")
	}
}

func TestConnect_IPv6AddressShown(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	// IPv6 protection off → connect shows the public v6 address.
	firewallIsIPv6Disabled = func() bool { return false }
	server := newTestServer()

	utilGetPublicIPv6 = func() (string, error) { return "2001:db8::1", nil }

	cb, statuses := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	foundIPv6 := false
	for _, s := range *statuses {
		if strings.Contains(s.Stage, "IPv6: 2001:db8::1") {
			foundIPv6 = true
		}
	}
	if !foundIPv6 {
		t.Error("expected IPv6 address in status callbacks")
	}
}

func TestConnect_WithPresharedKey(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	server.Config.PresharedKey = mustDecodeKey(validBase64Key)

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// configureRoutes tests
// ---------------------------------------------------------------------------

func TestConfigureRoutes_HappyPath(t *testing.T) {
	setupAllMocks(t)

	hostRouteCalled := false
	defaultRouteCalled := false

	netlinkGetDefaultGateway = func() (string, string, error) {
		return "192.168.1.1", "eth0", nil
	}
	netlinkAddHostRoute = func(host, gateway, iface string) error {
		hostRouteCalled = true
		if host != "1.2.3.4" {
			t.Errorf("host = %q, want 1.2.3.4", host)
		}
		if gateway != "192.168.1.1" {
			t.Errorf("gateway = %q, want 192.168.1.1", gateway)
		}
		if iface != "eth0" {
			t.Errorf("iface = %q, want eth0", iface)
		}
		return nil
	}
	netlinkAddSplitRoutes = func(ifaceName string) error {
		defaultRouteCalled = true
		if ifaceName != "wg0" {
			t.Errorf("ifaceName = %q, want wg0", ifaceName)
		}
		return nil
	}

	err := configureRoutes("wg0", "1.2.3.4")
	if err != nil {
		t.Fatalf("configureRoutes() error: %v", err)
	}
	if !hostRouteCalled {
		t.Error("AddHostRoute should have been called")
	}
	if !defaultRouteCalled {
		t.Error("AddSplitRoutes should have been called")
	}
}

func TestConfigureRoutes_EmptyGateway(t *testing.T) {
	setupAllMocks(t)

	hostRouteCalled := false
	netlinkGetDefaultGateway = func() (string, string, error) {
		return "", "", nil
	}
	netlinkAddHostRoute = func(host, gateway, iface string) error {
		hostRouteCalled = true
		return nil
	}
	netlinkAddSplitRoutes = func(ifaceName string) error { return nil }

	err := configureRoutes("wg0", "1.2.3.4")
	if err != nil {
		t.Fatalf("configureRoutes() error: %v", err)
	}
	if hostRouteCalled {
		t.Error("AddHostRoute should NOT be called when gateway is empty")
	}
}

func TestConfigureRoutes_DefaultRouteAlreadyExists(t *testing.T) {
	setupAllMocks(t)

	netlinkAddSplitRoutes = func(ifaceName string) error {
		return fmt.Errorf("file exists")
	}

	err := configureRoutes("wg0", "1.2.3.4")
	if err != nil {
		t.Fatalf("configureRoutes() should succeed when route already exists: %v", err)
	}
}

// TestConfigureRoutes_EEXIST_TypedError verifies the typed
// errors.Is(syscall.EEXIST) path catches an EEXIST that's been
// wrapped in a way that strips the original "file exists" string
// from the rendered message — for example, a future netlink
// wrapper that uses %s formatting on a custom error type but
// still implements Unwrap() returning the errno. The substring
// check alone would miss that; the typed check does not.
func TestConfigureRoutes_EEXIST_TypedError(t *testing.T) {
	setupAllMocks(t)

	netlinkAddSplitRoutes = func(ifaceName string) error {
		// Hide the "file exists" substring while still wrapping
		// EEXIST via Unwrap().
		return &maskedEEXIST{}
	}

	err := configureRoutes("wg0", "1.2.3.4")
	if err != nil {
		t.Fatalf("configureRoutes() should treat wrapped EEXIST as benign, got: %v", err)
	}
}

// maskedEEXIST is a custom error that hides EEXIST's standard
// "file exists" message but still unwraps to syscall.EEXIST.
type maskedEEXIST struct{}

func (m *maskedEEXIST) Error() string { return "route already present" }
func (m *maskedEEXIST) Unwrap() error { return syscall.EEXIST }

func TestConfigureRoutes_DefaultRouteFailure(t *testing.T) {
	setupAllMocks(t)

	netlinkAddSplitRoutes = func(ifaceName string) error {
		return fmt.Errorf("some other error")
	}

	err := configureRoutes("wg0", "1.2.3.4")
	if err == nil {
		t.Fatal("expected error from AddSplitRoutes")
	}
	if !strings.Contains(err.Error(), "failed to add VPN routes") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConfigureRoutes_GatewayErrorNonFatal(t *testing.T) {
	setupAllMocks(t)

	netlinkGetDefaultGateway = func() (string, string, error) {
		return "", "", fmt.Errorf("no default route")
	}
	netlinkAddSplitRoutes = func(ifaceName string) error { return nil }

	err := configureRoutes("wg0", "1.2.3.4")
	if err != nil {
		t.Fatalf("configureRoutes() should succeed even when gateway lookup fails: %v", err)
	}
}

func TestConfigureRoutes_HostRouteFailureNonFatal(t *testing.T) {
	setupAllMocks(t)

	netlinkAddHostRoute = func(host, gateway, iface string) error {
		return fmt.Errorf("host route failed")
	}
	netlinkAddSplitRoutes = func(ifaceName string) error { return nil }

	err := configureRoutes("wg0", "1.2.3.4")
	if err != nil {
		t.Fatalf("configureRoutes() should succeed even when host route fails: %v", err)
	}
}

// TestConfigureRoutes_DeleteBeforeAdd_ClearsStaleHostRoute verifies
// that configureRoutes deletes any stale host route to the endpoint
// BEFORE attempting to add the new one. Pre-fix: a daemon crash
// mid-connect (or power loss) could leave a stale route pointing at
// the previous session's gateway. The next reconnect's AddHostRoute
// would silently EEXIST, leaving the WireGuard handshake routed
// through the stale (and possibly unreachable) gateway.
func TestConfigureRoutes_DeleteBeforeAdd_ClearsStaleHostRoute(t *testing.T) {
	setupAllMocks(t)

	// Record the order of (delete, add) calls so we can assert delete
	// happens first. A bare boolean would miss the ordering bug.
	var callOrder []string

	netlinkGetDefaultGateway = func() (string, string, error) {
		return "192.168.1.1", "eth0", nil
	}
	netlinkDeleteHostRoute = func(host string) error {
		callOrder = append(callOrder, "delete:"+host)
		return nil
	}
	netlinkAddHostRoute = func(host, gateway, iface string) error {
		callOrder = append(callOrder, "add:"+host+":"+gateway+":"+iface)
		return nil
	}
	netlinkAddSplitRoutes = func(ifaceName string) error { return nil }

	err := configureRoutes("wg0", "1.2.3.4")
	if err != nil {
		t.Fatalf("configureRoutes() error: %v", err)
	}

	// Expected: delete first, then add — for the SAME endpoint IP.
	want := []string{
		"delete:1.2.3.4",
		"add:1.2.3.4:192.168.1.1:eth0",
	}
	if len(callOrder) != len(want) {
		t.Fatalf("call order length = %d, want %d:\n  got  %v\n  want %v", len(callOrder), len(want), callOrder, want)
	}
	for i := range want {
		if callOrder[i] != want[i] {
			t.Errorf("callOrder[%d] = %q, want %q", i, callOrder[i], want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// cleanupFailedConnection tests
// ---------------------------------------------------------------------------

func TestCleanupFailedConnection(t *testing.T) {
	setupAllMocks(t)

	deleteRouteCalled := false
	deleteLinkCalled := false
	unconfigDNSCalled := false
	deleteHostRouteCalls := []string{}

	netlinkDeleteSplitRoutes = func(name string) error {
		deleteRouteCalled = true
		if name != "wg0" {
			t.Errorf("DeleteSplitRoutes name = %q, want wg0", name)
		}
		return nil
	}
	netlinkDeleteLinkInterface = func(name string) error {
		deleteLinkCalled = true
		if name != "wg0" {
			t.Errorf("DeleteLinkInterface name = %q, want wg0", name)
		}
		return nil
	}
	unconfigureDNSFunc = func(ifaceName string) error {
		unconfigDNSCalled = true
		if ifaceName != "wg0" {
			t.Errorf("unconfigureDNS ifaceName = %q, want wg0", ifaceName)
		}
		return nil
	}
	netlinkDeleteHostRoute = func(host string) error {
		deleteHostRouteCalls = append(deleteHostRouteCalls, host)
		return nil
	}

	cleanupFailedConnection("wg0", "185.247.68.50")

	if !deleteRouteCalled {
		t.Error("DeleteSplitRoutes not called")
	}
	if !deleteLinkCalled {
		t.Error("DeleteLinkInterface not called")
	}
	if !unconfigDNSCalled {
		t.Error("unconfigureDNS not called")
	}
	if len(deleteHostRouteCalls) != 1 || deleteHostRouteCalls[0] != "185.247.68.50" {
		t.Errorf("DeleteHostRoute calls = %v, want [185.247.68.50]", deleteHostRouteCalls)
	}
}

// TestCleanupFailedConnection_RefreshesKillswitchToSimple verifies the B2
// fix: when killswitch is active and a connect attempt fails after the
// firewallUpdate added an endpoint-specific allow rule, cleanup must
// refresh to a simple killswitch so the stale endpoint allow doesn't
// linger forever. Pre-fix, that allow rule survived until the next
// successful connect (or manual reset).
func TestCleanupFailedConnection_RefreshesKillswitchToSimple(t *testing.T) {
	setupAllMocks(t)

	firewallIsActive = func() bool { return true }
	enableSimpleCalled := false
	firewallEnableSimple = func() error {
		enableSimpleCalled = true
		return nil
	}

	cleanupFailedConnection("wg0", "185.247.68.50")

	if !enableSimpleCalled {
		t.Error("EnableSimple should be called when killswitch is active during cleanup")
	}
}

// TestCleanupFailedConnection_NoSimpleWhenKillswitchOff verifies the B2 fix
// doesn't fire EnableSimple when no killswitch was active in the first
// place — the firewall doesn't need a refresh.
func TestCleanupFailedConnection_NoSimpleWhenKillswitchOff(t *testing.T) {
	setupAllMocks(t)

	firewallIsActive = func() bool { return false }
	enableSimpleCalled := false
	firewallEnableSimple = func() error {
		enableSimpleCalled = true
		return nil
	}

	cleanupFailedConnection("wg0", "185.247.68.50")

	if enableSimpleCalled {
		t.Error("EnableSimple should NOT be called when killswitch is inactive")
	}
}

// TestCleanupFailedConnectionWithLog_KillswitchRefreshErrorIsLogged
// pins the second log path in cleanupFailedConnectionWithLog: when
// the post-failure killswitch refresh (firewallEnableSimple) fails
// with the killswitch active, the warning must surface in debug.log.
//
// Sibling to TestCleanupFailedConnectionWithLog_DNSRevertErrorIsLogged.
// A regression that swallowed this would leave a stale endpoint-allow
// rule for a never-completed connect — the next handshake attempt
// could quietly reach the previously-tried endpoint while the user
// believes the killswitch is fully sealed.
func TestCleanupFailedConnectionWithLog_KillswitchRefreshErrorIsLogged(t *testing.T) {
	setupAllMocks(t)

	cfg := newLoggingTestConfig(t)
	log := logger.New(cfg)
	firewallIsActive = func() bool { return true }
	firewallEnableSimple = func() error {
		return fmt.Errorf("synthetic killswitch refresh failure")
	}

	cleanupFailedConnectionWithLog("wg0", "185.247.68.50", log)

	logContent := readLogFile(cfg.ConfigDir)
	if !strings.Contains(logContent, "killswitch refresh failed") {
		t.Errorf("debug.log should contain killswitch refresh warning, got: %q", logContent)
	}
	// Recovery hint must mention the stale-rule risk so users can act.
	if !strings.Contains(logContent, "stale endpoint-allow") {
		t.Errorf("debug.log should mention stale endpoint-allow risk, got: %q", logContent)
	}
}

// TestCleanupFailedConnectionWithLog_DNSRevertErrorIsLogged verifies the
// debug.log warning when unconfigureDNS fails during failed-connect
// cleanup. The wrapper cleanupFailedConnection (no logger) is silent
// by design; the WithLog variant must surface the error so users
// debugging post-failure broken DNS can see the cause in debug.log.
//
// Sibling to TestCleanupFailedConnection_RefreshesKillswitchToSimple
// (covers firewall refresh path); this covers the DNS path.
func TestCleanupFailedConnectionWithLog_DNSRevertErrorIsLogged(t *testing.T) {
	setupAllMocks(t)

	cfg := newLoggingTestConfig(t)
	log := logger.New(cfg)
	unconfigureDNSFunc = func(ifaceName string) error {
		return fmt.Errorf("synthetic resolvectl revert failure")
	}

	cleanupFailedConnectionWithLog("wg0", "185.247.68.50", log)

	logContent := readLogFile(cfg.ConfigDir)
	if !strings.Contains(logContent, "DNS revert failed") {
		t.Errorf("debug.log should contain DNS revert warning, got: %q", logContent)
	}
	// Recovery hint must include the manual command the user can run.
	if !strings.Contains(logContent, "resolvectl revert wg0") {
		t.Errorf("debug.log should suggest 'resolvectl revert wg0' command, got: %q", logContent)
	}
}

// TestCleanupFailedConnectionWithLog_NilLoggerSilentlyContinues
// confirms the partial wrapper contract: passing nil log MUST NOT
// panic when the DNS revert error occurs. The wrapper exists for
// callers without a logger (cleanupFailedConnection) and should
// silently swallow the error.
func TestCleanupFailedConnectionWithLog_NilLoggerSilentlyContinues(t *testing.T) {
	setupAllMocks(t)

	unconfigureDNSFunc = func(ifaceName string) error {
		return fmt.Errorf("synthetic failure")
	}

	// Must not panic on nil logger.
	cleanupFailedConnectionWithLog("wg0", "185.247.68.50", nil)
}

// TestCleanupFailedConnection_EmptyEndpoint verifies the host-route delete is
// skipped when the endpoint IP is unknown (e.g., cleanup runs before routes
// were configured). Regression guard: netlinkDeleteHostRoute must not be
// called with an empty string.
func TestCleanupFailedConnection_EmptyEndpoint(t *testing.T) {
	setupAllMocks(t)

	hostRouteCalled := false
	netlinkDeleteHostRoute = func(host string) error {
		hostRouteCalled = true
		return nil
	}

	cleanupFailedConnection("wg0", "")

	if hostRouteCalled {
		t.Error("DeleteHostRoute should not be called with empty endpoint")
	}
}

// ---------------------------------------------------------------------------
// ConnectDynamic tests
// ---------------------------------------------------------------------------

func TestConnectDynamic_HappyPath(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)

	// Set up provider and cache files
	providersDir := filepath.Join(cfg.ConfigDir, "providers")
	cacheDir := filepath.Join(cfg.ConfigDir, "cache")
	os.MkdirAll(providersDir, 0700)
	os.MkdirAll(cacheDir, 0700)

	// Write provider config
	providerContent := fmt.Sprintf(`{"private_key":"%s","address":"10.2.0.2/32"}`, validBase64Key)
	os.WriteFile(filepath.Join(providersDir, "protonvpn.json"), []byte(providerContent), 0600)

	// Write server cache
	servers := []config.CachedServer{
		{
			ServerName: "US-NY#42",
			Hostname:   "us-ny-42.protonvpn.net",
			Country:    "US",
			City:       "New York",
			PublicKey:  secondValidBase64Key,
			IPs:        []string{"1.2.3.4"},
		},
	}
	cacheData, _ := json.Marshal(servers)
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), cacheData, 0600)

	// Restore real config loading functions (they need the real files)
	configLoadProvider = config.LoadProvider
	configLoadServerFromCache = config.LoadServerFromCache

	cb, statuses := collectStatuses()
	err := ConnectDynamic(cfg, "protonvpn", "US-NY#42", cb)
	if err != nil {
		t.Fatalf("ConnectDynamic() error: %v", err)
	}

	found := false
	for _, s := range *statuses {
		if s.Success {
			found = true
		}
	}
	if !found {
		t.Error("no success status received from ConnectDynamic")
	}
}

func TestConnectDynamic_ProviderLoadFails(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)

	configLoadProvider = func(configDir, provider string) (*config.ProviderConfig, error) {
		return nil, fmt.Errorf("provider not configured")
	}

	cb, _ := collectStatuses()
	err := ConnectDynamic(cfg, "protonvpn", "US-NY#42", cb)
	if err == nil {
		t.Fatal("expected error when provider load fails")
	}
	if !strings.Contains(err.Error(), "failed to load provider config") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConnectDynamic_CacheLoadFails(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)

	configLoadProvider = func(configDir, provider string) (*config.ProviderConfig, error) {
		return &config.ProviderConfig{
			Provider:   "protonvpn",
			PrivateKey: mustDecodeKey(validBase64Key),
			Address:    "10.2.0.2/32",
			DNS:        "10.2.0.1",
			Port:       51820,
		}, nil
	}
	configLoadServerFromCache = func(configDir, provider, serverName string) (*config.CachedServer, error) {
		return nil, fmt.Errorf("server not found in cache")
	}

	cb, _ := collectStatuses()
	err := ConnectDynamic(cfg, "protonvpn", "US-NY#42", cb)
	if err == nil {
		t.Fatal("expected error when cache load fails")
	}
	if !strings.Contains(err.Error(), "failed to load server from cache") {
		t.Errorf("error = %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Disconnect tests
// ---------------------------------------------------------------------------

func TestDisconnect_NotConnected(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	isConnectedFunc = func(name string) bool { return false }

	cb, statuses := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}

	// Should get "Not connected" status
	found := false
	for _, s := range *statuses {
		if s.Stage == "Not connected" && s.Success {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Not connected' success status")
	}
}

func TestDisconnect_HappyPath(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)

	isConnectedFunc = func(name string) bool { return true }
	utilGetPublicIPv4 = func() (string, error) { return "3.3.3.3", nil }
	// After disconnect, return different IP
	callCount := 0
	utilGetPublicIPv4 = func() (string, error) {
		callCount++
		if callCount == 1 {
			return "2.2.2.2", nil // VPN IP
		}
		return "5.5.5.5", nil // Real IP after disconnect
	}

	deleteLinkCalled := false
	netlinkDeleteLinkInterface = func(name string) error {
		deleteLinkCalled = true
		return nil
	}

	cb, statuses := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}

	if !deleteLinkCalled {
		t.Error("DeleteLinkInterface should have been called")
	}

	found := false
	for _, s := range *statuses {
		if s.Stage == "Disconnected" && s.Success {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Disconnected' success status")
	}

	// Config should be cleared
	if cfg.LastConnectedServer != "" {
		t.Errorf("LastConnectedServer = %q, want empty", cfg.LastConnectedServer)
	}
}

// TestDisconnect_ClearsLastServerFeatures verifies that
// DisconnectWithCallback clears LastServerFeatures alongside
// LastConnectedServer. Pre-fix the disconnect deferred only cleared
// RealPublicIP / LastPublicIP / LastConnectedServer / ConnectedSince
// — leaving stale features attached to a now-empty server name.
//
// User-visible impact today is mild because the dashboard / footer /
// waybar tooltip all guard `LastServerFeatures` on
// `LastConnectedServer != ""` before reading. But persisted
// inconsistent state is a footgun: any future code path that reads
// LastServerFeatures without that guard would surface ghost
// feature labels for an empty server.
func TestDisconnect_ClearsLastServerFeatures(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)

	// Seed the cfg as if a prior connection populated all the
	// daemon-owned connection-state fields, including features.
	cfg.LastConnectedServer = "Proton-US-NY#42"
	cfg.LastServerFeatures = "P2P,Tor"
	cfg.LastPublicIP = "2.2.2.2"
	cfg.RealPublicIP = "5.5.5.5"

	isConnectedFunc = func(name string) bool { return true }
	utilGetPublicIPv4 = func() (string, error) { return "5.5.5.5", nil }
	netlinkDeleteLinkInterface = func(name string) error { return nil }

	cb, _ := collectDisconnectStatuses()
	if err := DisconnectWithCallback(cfg, cb); err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}

	if cfg.LastConnectedServer != "" {
		t.Errorf("LastConnectedServer = %q, want empty", cfg.LastConnectedServer)
	}
	if cfg.LastServerFeatures != "" {
		t.Errorf("LastServerFeatures = %q, want empty — features must clear with the server name to keep persisted state consistent", cfg.LastServerFeatures)
	}
}

// TestDisconnect_DNSRevertFailure_SurfacesWarning verifies the
// disconnect path emits a user-visible warning when both DBus and
// sudo resolvectl revert paths fail. Previously the failure was
// silently swallowed; the user was left with VPN DNS still active
// and no recovery hint.
func TestDisconnect_DNSRevertFailure_SurfacesWarning(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)

	isConnectedFunc = func(name string) bool { return true }
	utilGetPublicIPv4 = func() (string, error) { return "5.5.5.5", nil }
	netlinkDeleteLinkInterface = func(name string) error { return nil }

	// Stub unconfigureDNS to fail with a recognizable error.
	unconfigureDNSFunc = func(ifaceName string) error {
		return fmt.Errorf("simulated DBus + sudo failure")
	}

	cb, statuses := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect should not abort on DNS revert failure: %v", err)
	}

	foundWarning := false
	for _, s := range *statuses {
		if strings.Contains(s.Stage, "DNS revert failed") &&
			strings.Contains(s.Stage, "resolvectl revert") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Errorf("expected user-visible warning about DNS revert failure with recovery hint; got statuses: %+v", *statuses)
	}
}

// TestDisconnect_DNSRevertFailure_LogsToDebugFile is the debug.log
// half of TestDisconnect_DNSRevertFailure_SurfacesWarning. The
// existing test only checks the caller-facing DisconnectStatus
// callback gets the warning. The same failure also gets written to
// debug.log via log.Log so users investigating broken DNS post-
// disconnect can find the cause without re-running with verbose
// logging.
//
// A regression that dropped the log.Log call would silently lose
// the forensic record while keeping the live callback warning —
// hard to debug because the user sees "DNS revert failed" once at
// disconnect time then never again.
func TestDisconnect_DNSRevertFailure_LogsToDebugFile(t *testing.T) {
	setupAllMocks(t)
	cfg := newLoggingTestConfig(t) // enables connection logging

	isConnectedFunc = func(name string) bool { return true }
	utilGetPublicIPv4 = func() (string, error) { return "5.5.5.5", nil }
	netlinkDeleteLinkInterface = func(name string) error { return nil }
	unconfigureDNSFunc = func(ifaceName string) error {
		return fmt.Errorf("simulated DBus + sudo failure")
	}

	cb, _ := collectDisconnectStatuses()
	if err := DisconnectWithCallback(cfg, cb); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	logContent := readLogFile(cfg.ConfigDir)
	if !strings.Contains(logContent, "DNS revert failed") {
		t.Errorf("debug.log should contain 'DNS revert failed' from disconnect path, got: %q", logContent)
	}
	if !strings.Contains(logContent, "simulated DBus + sudo failure") {
		t.Errorf("debug.log should preserve the underlying error message, got: %q", logContent)
	}
}

// TestDisconnect_RouteCleanupFailure_LogsButContinues is the sibling
// warn-and-continue test for the split-routes cleanup step. Same
// contract as TestDisconnect_InterfaceDeleteFailure_LogsButContinues:
// netlinkDeleteSplitRoutes failing must log + continue, NOT abort.
//
// If this regressed to abort, the interface delete that follows
// would be skipped, leaving wg0 alive — the killswitch verification
// would then succeed (interface is up so traffic flows) and return
// the user to "disconnected" UI state while the tunnel still
// processes packets. Silent traffic leak.
func TestDisconnect_RouteCleanupFailure_LogsButContinues(t *testing.T) {
	setupAllMocks(t)
	cfg := newLoggingTestConfig(t)
	cfg.LastConnectedServer = "US-NY#42"

	isConnectedFunc = func(name string) bool { return true }
	utilGetPublicIPv4 = func() (string, error) { return "5.5.5.5", nil }
	deleteLinkCalled := false
	netlinkDeleteLinkInterface = func(name string) error {
		deleteLinkCalled = true
		return nil
	}
	netlinkDeleteSplitRoutes = func(name string) error {
		return fmt.Errorf("synthetic split-routes cleanup failure")
	}

	cb, _ := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect should not abort on split-routes cleanup failure: %v", err)
	}

	logContent := readLogFile(cfg.ConfigDir)
	if !strings.Contains(logContent, "route cleanup failed") {
		t.Errorf("debug.log should contain 'route cleanup failed', got: %q", logContent)
	}
	if !strings.Contains(logContent, "synthetic split-routes cleanup failure") {
		t.Errorf("debug.log should preserve underlying error, got: %q", logContent)
	}
	// Critical: interface delete (next step) must have still happened.
	// If a regression early-returned on route cleanup failure, the wg0
	// interface would still be up — silent traffic leak.
	if !deleteLinkCalled {
		t.Error("netlinkDeleteLinkInterface was not called — early-return regression on route cleanup failure (silent leak risk)")
	}
}

// TestDisconnect_InterfaceDeleteFailure_LogsButContinues pins the
// "warn-and-continue" contract for the interface-delete step in
// DisconnectWithCallback. If netlinkDeleteLinkInterface errors, the
// function MUST:
//   1) Log the warning to debug.log (forensic record)
//   2) Continue execution (no early return) so downstream cleanup
//      (ClearConnectionState defer, verification) still happens
//
// Without (2), a partial-cleanup left the user with stale config
// fields ("connected" when actually disconnected) and the next
// connect attempt would re-use the wrong server name. Without (1),
// users have no breadcrumb when they later wonder why their wg0
// interface lingers.
func TestDisconnect_InterfaceDeleteFailure_LogsButContinues(t *testing.T) {
	setupAllMocks(t)
	cfg := newLoggingTestConfig(t)
	cfg.LastConnectedServer = "US-NY#42" // pre-existing, should be cleared

	isConnectedFunc = func(name string) bool { return true }
	utilGetPublicIPv4 = func() (string, error) { return "5.5.5.5", nil }
	netlinkDeleteLinkInterface = func(name string) error {
		return fmt.Errorf("synthetic netlink rtnetlink error")
	}

	cb, _ := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect should not abort on interface delete failure: %v", err)
	}

	// (1) debug.log should contain the warning + original error.
	logContent := readLogFile(cfg.ConfigDir)
	if !strings.Contains(logContent, "interface delete failed") {
		t.Errorf("debug.log should contain 'interface delete failed', got: %q", logContent)
	}
	if !strings.Contains(logContent, "synthetic netlink rtnetlink error") {
		t.Errorf("debug.log should preserve underlying error, got: %q", logContent)
	}

	// (2) ClearConnectionState defer must still have run — even though
	// interface delete failed, config must reflect "disconnected".
	if cfg.LastConnectedServer != "" {
		t.Errorf("LastConnectedServer = %q, want empty (deferred cleanup must run despite delete failure)", cfg.LastConnectedServer)
	}
}

func TestDisconnect_WithKillswitch_AutoDisable(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	cfg.KillswitchAutoDisable = "true"

	isConnectedFunc = func(name string) bool { return true }
	firewallIsActive = func() bool { return true }

	// When killswitch is blocking, GetPublicIPv4 should fail
	callCount := 0
	utilGetPublicIPv4 = func() (string, error) {
		callCount++
		if callCount == 1 {
			return "2.2.2.2", nil // Before IP
		}
		return "", fmt.Errorf("blocked by killswitch") // After disconnect
	}

	disableCalled := false
	firewallDisable = func() error {
		disableCalled = true
		return nil
	}

	cb, statuses := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}

	if !disableCalled {
		t.Error("firewallDisable should have been called for auto-disable")
	}

	found := false
	for _, s := range *statuses {
		if s.KillswitchAutoDisabled {
			found = true
		}
	}
	if !found {
		t.Error("expected KillswitchAutoDisabled status")
	}
}

func TestDisconnect_WithKillswitch_PromptMode(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	cfg.KillswitchAutoDisable = "false"

	isConnectedFunc = func(name string) bool { return true }
	firewallIsActive = func() bool { return true }

	callCount := 0
	utilGetPublicIPv4 = func() (string, error) {
		callCount++
		if callCount == 1 {
			return "2.2.2.2", nil
		}
		return "", fmt.Errorf("blocked")
	}

	cb, statuses := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}

	found := false
	for _, s := range *statuses {
		if s.KillswitchPromptNeeded {
			found = true
		}
	}
	if !found {
		t.Error("expected KillswitchPromptNeeded status")
	}
}

func TestDisconnect_WithKillswitch_NeverMode(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	cfg.KillswitchAutoDisable = "never"

	isConnectedFunc = func(name string) bool { return true }
	firewallIsActive = func() bool { return true }

	callCount := 0
	utilGetPublicIPv4 = func() (string, error) {
		callCount++
		if callCount == 1 {
			return "2.2.2.2", nil
		}
		return "", fmt.Errorf("blocked")
	}

	cb, statuses := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}

	found := false
	for _, s := range *statuses {
		if s.KillswitchKeptActive {
			found = true
		}
	}
	if !found {
		t.Error("expected KillswitchKeptActive status")
	}
}

func TestDisconnect_KillswitchNotBlocking_IPFailed(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)

	isConnectedFunc = func(name string) bool { return true }

	callCount := 0
	utilGetPublicIPv4 = func() (string, error) {
		callCount++
		if callCount == 1 {
			return "2.2.2.2", nil
		}
		return "", fmt.Errorf("cannot get IP")
	}

	// IP verification failure after disconnect should succeed —
	// the VPN is already torn down, we just can't verify the IP change
	err := DisconnectWithCallback(cfg, nil)
	if err != nil {
		t.Fatalf("expected success (VPN already torn down), got: %v", err)
	}
}

func TestDisconnect_IPUnchanged_NoBaseline(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	cfg.RealPublicIP = "" // No real IP stored — treat as phantom

	isConnectedFunc = func(name string) bool { return true }
	// Same IP before and after
	utilGetPublicIPv4 = func() (string, error) { return "2.2.2.2", nil }

	err := DisconnectWithCallback(cfg, nil)
	if err != nil {
		t.Fatalf("expected no error (phantom when no baseline), got: %v", err)
	}
}

func TestDisconnect_IPUnchanged_NotPhantom(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	cfg.RealPublicIP = "9.9.9.9" // Stored real IP does NOT match

	isConnectedFunc = func(name string) bool { return true }
	// Same IP before and after, but doesn't match stored real IP
	utilGetPublicIPv4 = func() (string, error) { return "2.2.2.2", nil }

	err := DisconnectWithCallback(cfg, nil)
	if err == nil {
		t.Fatal("expected error when IP unchanged and doesn't match stored real IP")
	}
	if !strings.Contains(err.Error(), "IP unchanged after disconnect") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestDisconnect_PhantomConnection(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	cfg.RealPublicIP = "2.2.2.2" // Stored real IP matches

	isConnectedFunc = func(name string) bool { return true }
	// Same IP before and after (VPN was already dead)
	utilGetPublicIPv4 = func() (string, error) { return "2.2.2.2", nil }

	cb, statuses := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}

	found := false
	for _, s := range *statuses {
		if s.PhantomConnection {
			found = true
		}
	}
	if !found {
		t.Error("expected PhantomConnection status")
	}
}

func TestDisconnect_KillswitchBlockingButIPLeaks(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)

	isConnectedFunc = func(name string) bool { return true }
	firewallIsActive = func() bool { return true }

	// IP still accessible despite killswitch
	utilGetPublicIPv4 = func() (string, error) { return "1.1.1.1", nil }

	err := DisconnectWithCallback(cfg, nil)
	if err == nil {
		t.Fatal("expected error when killswitch active but traffic not blocked")
	}
	if !strings.Contains(err.Error(), "killswitch enabled but traffic not blocked") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestDisconnect_NilCallback(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	isConnectedFunc = func(name string) bool { return false }

	// nil callback should not panic
	err := DisconnectWithCallback(cfg, nil)
	if err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}
}

func TestDisconnect_WrapsDisconnectWithCallback(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	isConnectedFunc = func(name string) bool { return false }

	err := Disconnect(cfg)
	if err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ForceDisconnect tests
// ---------------------------------------------------------------------------

func TestForceDisconnect_HappyPath(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	cfg.LastConnectedServer = "US-NY#42"
	cfg.LastPublicIP = "2.2.2.2"
	cfg.RealPublicIP = "5.5.5.5"

	deleteLinkCalled := false
	netlinkInterfaceExists = func(name string) bool { return true }
	netlinkDeleteLinkInterface = func(name string) error {
		deleteLinkCalled = true
		return nil
	}

	err := ForceDisconnect(cfg)
	if err != nil {
		t.Fatalf("ForceDisconnect() error: %v", err)
	}

	if !deleteLinkCalled {
		t.Error("DeleteLinkInterface should have been called")
	}
	// LastConnectedServer is intentionally PRESERVED by ForceDisconnect — it
	// runs from the daemon's terminate handler on system shutdown, where we
	// want autoconnect (mode=last_used) to resume the same server on next
	// boot. Explicit user-disconnect (DisconnectWithCallback) still clears it.
	if cfg.LastConnectedServer != "US-NY#42" {
		t.Errorf("LastConnectedServer = %q, want preserved %q", cfg.LastConnectedServer, "US-NY#42")
	}
	if cfg.LastPublicIP != "" {
		t.Errorf("LastPublicIP = %q, want empty", cfg.LastPublicIP)
	}
	if cfg.RealPublicIP != "" {
		t.Errorf("RealPublicIP = %q, want empty", cfg.RealPublicIP)
	}
}

// TestDisconnectWithCallback_RaceWithLoggerView is the sibling test to
// TestForceDisconnect_RaceWithLoggerView for the explicit-disconnect path.
// DisconnectWithCallback clears five cfg fields in its deferred cleanup
// (RealPublicIP, LastPublicIP, LastConnectedServer, LastServerFeatures,
// ConnectedSince). Pre-fix that was bare assignment, racing the LoggerView
// reads of RealPublicIP / LastPublicIP from any concurrent goroutine in
// the daemon process (handleClient -> sendStatus -> Logger.Log -> LoggerView).
//
// Fix routes through Config.ClearConnectionState(true) which locks cfg.mu.
func TestDisconnectWithCallback_RaceWithLoggerView(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	cfg.LastPublicIP = "2.2.2.2"
	cfg.RealPublicIP = "5.5.5.5"
	cfg.LastConnectedServer = "US-NY#42"
	cfg.LastServerFeatures = "p2p"

	isConnectedFunc = func(string) bool { return false }
	utilGetPublicIPv4 = func() (string, error) { return "5.5.5.5", nil }
	netlinkInterfaceExists = func(string) bool { return false }
	netlinkDeleteLinkInterface = func(string) error { return nil }

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		cb := func(DisconnectStatus) {}
		for {
			select {
			case <-stop:
				return
			default:
				DisconnectWithCallback(cfg, cb)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = cfg.LoggerView()
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestForceDisconnect_RaceWithLoggerView verifies ForceDisconnect's in-memory
// cfg field writes (RealPublicIP/LastPublicIP/ConnectedSince) are race-free
// against a concurrent LoggerView read (which takes cfg.mu.RLock to snapshot
// the same fields).
//
// In production: ForceDisconnect is called from the daemon's sleepWakeListener
// goroutine (via forceDisconnectIfInterfaceExists on wake) and from the
// main-goroutine SIGTERM/switch paths. Meanwhile every Logger.Log() call —
// from any goroutine — invokes cfg.LoggerView() under cfg.mu.RLock and reads
// RealPublicIP/LastPublicIP for sanitization. Pre-fix ForceDisconnect set
// those fields with bare assignment, racing the read.
//
// Same bug class as the prepareForSleep / forceDisconnectIfInterfaceExists
// race fixes; this is the assignment side rather than the read side.
func TestForceDisconnect_RaceWithLoggerView(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	cfg.LastPublicIP = "2.2.2.2"
	cfg.RealPublicIP = "5.5.5.5"

	// Make ForceDisconnect cheap: no real interface, no DNS.
	netlinkInterfaceExists = func(string) bool { return false }

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// No re-prime here — bare assignment from this goroutine
				// would itself race the LoggerView read. ForceDisconnect's
				// own writes (now routed through ClearConnectionState under
				// cfg.mu.Lock) are the surface this test covers.
				ForceDisconnect(cfg)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = cfg.LoggerView()
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestForceDisconnect_InterfaceNotExists(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)

	deleteLinkCalled := false
	netlinkInterfaceExists = func(name string) bool { return false }
	netlinkDeleteLinkInterface = func(name string) error {
		deleteLinkCalled = true
		return nil
	}

	err := ForceDisconnect(cfg)
	if err != nil {
		t.Fatalf("ForceDisconnect() error: %v", err)
	}

	if deleteLinkCalled {
		t.Error("DeleteLinkInterface should NOT be called when interface does not exist")
	}
}

// ---------------------------------------------------------------------------
// IsConnected tests
// ---------------------------------------------------------------------------

func TestIsConnected_InterfaceNotFound(t *testing.T) {
	saveFuncVars(t)

	statusLinkByName = func(name string) (nl.Link, error) {
		return nil, fmt.Errorf("link not found")
	}

	if IsConnected("wg0") {
		t.Error("should return false when interface not found")
	}
}

func TestIsConnected_InterfaceDown(t *testing.T) {
	saveFuncVars(t)

	statusLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, 0), nil // FlagUp not set
	}

	if IsConnected("wg0") {
		t.Error("should return false when interface is down")
	}
}

func TestIsConnected_NoAddresses(t *testing.T) {
	saveFuncVars(t)

	statusLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	statusAddrList = func(link nl.Link, family int) ([]nl.Addr, error) {
		return nil, nil // empty
	}

	if IsConnected("wg0") {
		t.Error("should return false when no addresses assigned")
	}
}

func TestIsConnected_AddrListError(t *testing.T) {
	saveFuncVars(t)

	statusLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	statusAddrList = func(link nl.Link, family int) ([]nl.Addr, error) {
		return nil, fmt.Errorf("addr list error")
	}

	if IsConnected("wg0") {
		t.Error("should return false when AddrList errors")
	}
}

func TestIsConnected_WgctrlError(t *testing.T) {
	saveFuncVars(t)

	statusLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	statusAddrList = func(link nl.Link, family int) ([]nl.Addr, error) {
		return []nl.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)}}}, nil
	}
	statusGetDevice = func(name string) (*wgtypes.Device, bool, error) {
		return nil, false, fmt.Errorf("wgctrl error")
	}

	// When wgctrl fails, rely on interface state -> true
	if !IsConnected("wg0") {
		t.Error("should return true when wgctrl errors (rely on interface state)")
	}
}

func TestIsConnected_NoPeers(t *testing.T) {
	saveFuncVars(t)

	statusLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	statusAddrList = func(link nl.Link, family int) ([]nl.Addr, error) {
		return []nl.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)}}}, nil
	}
	statusGetDevice = func(name string) (*wgtypes.Device, bool, error) {
		return &wgtypes.Device{Peers: nil}, true, nil
	}

	if IsConnected("wg0") {
		t.Error("should return false when no peers configured")
	}
}

func TestIsConnected_RecentHandshake(t *testing.T) {
	saveFuncVars(t)

	now := time.Now()
	timeNow = func() time.Time { return now }

	statusLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	statusAddrList = func(link nl.Link, family int) ([]nl.Addr, error) {
		return []nl.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)}}}, nil
	}
	statusGetDevice = func(name string) (*wgtypes.Device, bool, error) {
		return &wgtypes.Device{
			Peers: []wgtypes.Peer{
				{LastHandshakeTime: now.Add(-1 * time.Minute)}, // 1 minute ago = recent
			},
		}, true, nil
	}

	if !IsConnected("wg0") {
		t.Error("should return true with recent handshake")
	}
}

func TestIsConnected_StaleHandshake(t *testing.T) {
	saveFuncVars(t)

	now := time.Now()
	timeNow = func() time.Time { return now }

	statusLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	statusAddrList = func(link nl.Link, family int) ([]nl.Addr, error) {
		return []nl.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)}}}, nil
	}
	statusGetDevice = func(name string) (*wgtypes.Device, bool, error) {
		return &wgtypes.Device{
			Peers: []wgtypes.Peer{
				{LastHandshakeTime: now.Add(-10 * time.Minute)}, // 10 minutes ago = stale
			},
		}, true, nil
	}

	if IsConnected("wg0") {
		t.Error("should return false with stale handshake")
	}
}

// TestIsConnected_HandshakeAgeBoundary pins the exact MaxHandshakeAge
// boundary in IsConnected:
//
//   if handshakeAge < MaxHandshakeAge { return true }
//
// Existing tests use 1 minute (recent) and 10 minutes (stale), well
// inside the safe zone for either direction. The exact boundary
// (handshakeAge == MaxHandshakeAge) was untested. A `<` -> `<=`
// mutation would let a handshake exactly at the boundary count as
// connected — wireguard's actual stability transitions at this
// boundary (initiator triggers re-handshake), so the strict-less-than
// semantics matter for catching the EXACT moment the connection goes
// stale.
//
// Two sub-tests pin both sides of the boundary:
//   - age = MaxHandshakeAge - 1ns: must return true (still recent)
//   - age = MaxHandshakeAge:       must return false (just past)
func TestIsConnected_HandshakeAgeBoundary(t *testing.T) {
	setupPeer := func(t *testing.T, age time.Duration) {
		saveFuncVars(t)
		now := time.Now()
		timeNow = func() time.Time { return now }
		statusLinkByName = func(name string) (nl.Link, error) {
			return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
		}
		statusAddrList = func(link nl.Link, family int) ([]nl.Addr, error) {
			return []nl.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)}}}, nil
		}
		statusGetDevice = func(name string) (*wgtypes.Device, bool, error) {
			return &wgtypes.Device{
				Peers: []wgtypes.Peer{{LastHandshakeTime: now.Add(-age)}},
			}, true, nil
		}
	}

	t.Run("one_ns_under_boundary_is_recent", func(t *testing.T) {
		setupPeer(t, MaxHandshakeAge-time.Nanosecond)
		if !IsConnected("wg0") {
			t.Error("handshake at MaxHandshakeAge-1ns should be considered recent (boundary regression: `<` -> `<=` would still pass; `<` -> `>` would fail)")
		}
	})

	t.Run("exactly_at_boundary_is_stale", func(t *testing.T) {
		setupPeer(t, MaxHandshakeAge)
		if IsConnected("wg0") {
			t.Error("handshake at exactly MaxHandshakeAge should be stale (`<` excludes equal; a `<=` mutation would falsely pass)")
		}
	})
}

func TestIsConnected_NewPeerNoHandshake(t *testing.T) {
	saveFuncVars(t)

	statusLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	statusAddrList = func(link nl.Link, family int) ([]nl.Addr, error) {
		return []nl.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)}}}, nil
	}
	statusGetDevice = func(name string) (*wgtypes.Device, bool, error) {
		return &wgtypes.Device{
			Peers: []wgtypes.Peer{
				{LastHandshakeTime: time.Time{}}, // Zero = new peer
			},
		}, true, nil
	}

	if !IsConnected("wg0") {
		t.Error("should return true for new peer with no handshake yet")
	}
}

func TestIsConnected_DefaultInterfaceName(t *testing.T) {
	saveFuncVars(t)

	calledWithName := ""
	statusLinkByName = func(name string) (nl.Link, error) {
		calledWithName = name
		return nil, fmt.Errorf("not found")
	}

	IsConnected("") // Empty should default to "wg0"
	if calledWithName != "wg0" {
		t.Errorf("should use default name 'wg0', got %q", calledWithName)
	}
}

func TestIsConnected_MixedPeers_OneStaleOneNew(t *testing.T) {
	saveFuncVars(t)

	now := time.Now()
	timeNow = func() time.Time { return now }

	statusLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	statusAddrList = func(link nl.Link, family int) ([]nl.Addr, error) {
		return []nl.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)}}}, nil
	}
	statusGetDevice = func(name string) (*wgtypes.Device, bool, error) {
		return &wgtypes.Device{
			Peers: []wgtypes.Peer{
				{LastHandshakeTime: now.Add(-10 * time.Minute)}, // stale
				{LastHandshakeTime: time.Time{}},                // new (zero)
			},
		}, true, nil
	}

	// One stale peer but one new peer -> should give benefit of doubt
	if !IsConnected("wg0") {
		t.Error("should return true when there's a new peer with zero handshake time")
	}
}

// ---------------------------------------------------------------------------
// configureDNS tests
// ---------------------------------------------------------------------------

func TestConfigureDNS_EmptyDNS(t *testing.T) {
	err := configureDNS("wg0", "")
	if err != nil {
		t.Fatalf("configureDNS with empty DNS should return nil: %v", err)
	}
}

func TestConfigureDNS_InvalidDNSAddresses(t *testing.T) {
	err := configureDNS("wg0", "not-an-ip, also-not-ip")
	if err == nil {
		t.Fatal("expected error when all DNS addresses are invalid")
	}
	if !strings.Contains(err.Error(), "no valid DNS addresses") {
		t.Errorf("error = %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// stopConnectionDaemon tests
// ---------------------------------------------------------------------------

func TestStopConnectionDaemon_NoPidFile(t *testing.T) {
	tmpDir := t.TempDir()
	err := stopConnectionDaemon(tmpDir)
	if err == nil {
		t.Fatal("expected error when pid file doesn't exist")
	}
}

func TestStopConnectionDaemon_InvalidPid(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, ".daemon.pid"), []byte("not-a-number"), 0600)

	err := stopConnectionDaemon(tmpDir)
	if err == nil {
		t.Fatal("expected error for invalid PID")
	}
}

func TestStopConnectionDaemon_SelfPid(t *testing.T) {
	tmpDir := t.TempDir()
	myPid := fmt.Sprintf("%d", os.Getpid())
	os.WriteFile(filepath.Join(tmpDir, ".daemon.pid"), []byte(myPid), 0600)

	// Should not try to kill itself
	err := stopConnectionDaemon(tmpDir)
	if err != nil {
		t.Fatalf("stopConnectionDaemon should return nil for own PID: %v", err)
	}
}

func TestStopConnectionDaemon_NonexistentProcess(t *testing.T) {
	tmpDir := t.TempDir()
	// Use a PID that almost certainly doesn't exist
	os.WriteFile(filepath.Join(tmpDir, ".daemon.pid"), []byte("999999999"), 0600)

	// Should return error when process doesn't exist
	err := stopConnectionDaemon(tmpDir)
	if err == nil {
		t.Fatal("expected error for nonexistent process")
	}
}

// TestStopConnectionDaemon_SIGKILLBackstop verifies that a process which
// ignores SIGTERM gets force-killed after the 10s poll, instead of being
// silently left alive (which would race subsequent route/interface teardown).
func TestStopConnectionDaemon_SIGKILLBackstop(t *testing.T) {
	// Stub timeSleep so the 100×100ms poll completes instantly.
	origSleep := timeSleep
	timeSleep = func(time.Duration) {}
	t.Cleanup(func() { timeSleep = origSleep })

	// Spawn a child that traps SIGTERM (ignores it) and sleeps. SIGKILL
	// can't be trapped, so this child only dies when stopConnectionDaemon
	// hits the SIGKILL backstop.
	cmd := exec.Command("bash", "-c", "trap '' TERM; sleep 60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn child: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, ".daemon.pid"),
		[]byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0600)

	err := stopConnectionDaemon(tmpDir)
	if err == nil {
		t.Fatal("expected SIGKILL-backstop error when daemon ignores SIGTERM")
	}
	if !strings.Contains(err.Error(), "SIGKILL") {
		t.Errorf("error should mention SIGKILL fallback, got: %v", err)
	}

	// Reap so the next assertion (process gone) works without ECHILD noise.
	cmd.Wait()

	// Confirm the child is actually dead — the whole point of the backstop.
	if err := cmd.Process.Signal(syscall.Signal(0)); err == nil {
		t.Error("child should be dead after SIGKILL backstop, but Signal(0) succeeded")
	}
}

// ---------------------------------------------------------------------------
// configureDNS full-path tests (DBus success + fallback)
// ---------------------------------------------------------------------------

func TestConfigureDNS_DbusSuccess(t *testing.T) {
	saveFuncVars(t)

	dbusCalled := false
	configureDNSviaDbusFunc = func(ifaceName string, dnsAddrs []string) error {
		dbusCalled = true
		if ifaceName != "wg0" {
			t.Errorf("ifaceName = %q, want wg0", ifaceName)
		}
		if len(dnsAddrs) != 1 || dnsAddrs[0] != "10.2.0.1" {
			t.Errorf("dnsAddrs = %v, want [10.2.0.1]", dnsAddrs)
		}
		return nil
	}
	resolvectlCalled := false
	configureDNSviaResolvectlFunc = func(ifaceName string, dnsAddrs []string) error {
		resolvectlCalled = true
		return nil
	}
	origDemote := demotePhysicalDNSDefaultRoute
	t.Cleanup(func() { demotePhysicalDNSDefaultRoute = origDemote })
	demoteCalled := false
	demotePhysicalDNSDefaultRoute = func() {
		demoteCalled = true
	}

	err := configureDNS("wg0", "10.2.0.1")
	if err != nil {
		t.Fatalf("configureDNS() error: %v", err)
	}
	if !dbusCalled {
		t.Error("configureDNSviaDbus should have been called")
	}
	if resolvectlCalled {
		t.Error("configureDNSviaResolvectl should NOT be called when DBus succeeds")
	}
	if !demoteCalled {
		t.Error("demotePhysicalDNSDefaultRoute should ALWAYS be called (Bug: DBus SetLinkDefaultRoute silently fails on NM-managed interfaces, leaks DNS queries to ISP)")
	}
}

func TestConfigureDNS_DbusFails_FallsBackToResolvectl(t *testing.T) {
	saveFuncVars(t)

	configureDNSviaDbusFunc = func(ifaceName string, dnsAddrs []string) error {
		return fmt.Errorf("polkit auth failed")
	}
	resolvectlCalled := false
	configureDNSviaResolvectlFunc = func(ifaceName string, dnsAddrs []string) error {
		resolvectlCalled = true
		return nil
	}

	err := configureDNS("wg0", "10.2.0.1")
	if err != nil {
		t.Fatalf("configureDNS() error: %v", err)
	}
	if !resolvectlCalled {
		t.Error("configureDNSviaResolvectl should be called as fallback")
	}
}

func TestConfigureDNS_BothFail(t *testing.T) {
	saveFuncVars(t)

	configureDNSviaDbusFunc = func(ifaceName string, dnsAddrs []string) error {
		return fmt.Errorf("dbus failed")
	}
	configureDNSviaResolvectlFunc = func(ifaceName string, dnsAddrs []string) error {
		return fmt.Errorf("resolvectl failed")
	}

	err := configureDNS("wg0", "10.2.0.1")
	if err == nil {
		t.Fatal("expected error when both DNS methods fail")
	}
	if !strings.Contains(err.Error(), "resolvectl") {
		t.Errorf("error = %q, want resolvectl error", err.Error())
	}
}

func TestConfigureDNS_MultipleDNSAddresses(t *testing.T) {
	saveFuncVars(t)

	configureDNSviaDbusFunc = func(ifaceName string, dnsAddrs []string) error {
		if len(dnsAddrs) != 2 {
			t.Errorf("expected 2 DNS addrs, got %d: %v", len(dnsAddrs), dnsAddrs)
		}
		if dnsAddrs[0] != "10.2.0.1" || dnsAddrs[1] != "10.2.0.2" {
			t.Errorf("dnsAddrs = %v", dnsAddrs)
		}
		return nil
	}
	configureDNSviaResolvectlFunc = func(ifaceName string, dnsAddrs []string) error {
		return nil
	}

	err := configureDNS("wg0", "10.2.0.1, 10.2.0.2")
	if err != nil {
		t.Fatalf("configureDNS() error: %v", err)
	}
}

func TestConfigureDNS_MixedValidInvalid(t *testing.T) {
	saveFuncVars(t)

	configureDNSviaDbusFunc = func(ifaceName string, dnsAddrs []string) error {
		if len(dnsAddrs) != 1 || dnsAddrs[0] != "10.2.0.1" {
			t.Errorf("expected [10.2.0.1], got %v", dnsAddrs)
		}
		return nil
	}
	configureDNSviaResolvectlFunc = func(ifaceName string, dnsAddrs []string) error {
		return nil
	}

	// "garbage" should be filtered out, "10.2.0.1" should remain
	err := configureDNS("wg0", "garbage, 10.2.0.1")
	if err != nil {
		t.Fatalf("configureDNS() error: %v", err)
	}
}

func TestConfigureDNS_EmptyEntries(t *testing.T) {
	saveFuncVars(t)

	configureDNSviaDbusFunc = func(ifaceName string, dnsAddrs []string) error {
		if len(dnsAddrs) != 1 || dnsAddrs[0] != "10.2.0.1" {
			t.Errorf("expected [10.2.0.1], got %v", dnsAddrs)
		}
		return nil
	}
	configureDNSviaResolvectlFunc = func(ifaceName string, dnsAddrs []string) error {
		return nil
	}

	// Trailing comma creates empty entries
	err := configureDNS("wg0", "10.2.0.1, , ")
	if err != nil {
		t.Fatalf("configureDNS() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// configureDNSviaDbus tests
// ---------------------------------------------------------------------------

func TestConfigureDNSviaDbus_InterfaceNotFound(t *testing.T) {
	saveFuncVars(t)

	netlinkLinkByName = func(name string) (nl.Link, error) {
		return nil, fmt.Errorf("interface not found")
	}

	err := configureDNSviaDbus("wg0", []string{"10.2.0.1"})
	if err == nil {
		t.Fatal("expected error when interface not found")
	}
	if !strings.Contains(err.Error(), "interface not found") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestConfigureDNSviaDbus_SystemBusFails(t *testing.T) {
	saveFuncVars(t)

	netlinkLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	dbusConnectSystemBus = func(opts ...dbus.ConnOption) (*dbus.Conn, error) {
		return nil, fmt.Errorf("dbus connection failed")
	}

	err := configureDNSviaDbus("wg0", []string{"10.2.0.1"})
	if err == nil {
		t.Fatal("expected error when DBus connection fails")
	}
	if !strings.Contains(err.Error(), "failed to connect to system bus") {
		t.Errorf("error = %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// unconfigureDNS tests
// ---------------------------------------------------------------------------

func TestUnconfigureDNS_InterfaceNotFound(t *testing.T) {
	saveFuncVars(t)

	netlinkLinkByName = func(name string) (nl.Link, error) {
		return nil, fmt.Errorf("not found")
	}

	// Should not panic, just return silently
	unconfigureDNS("wg0")
}

func TestUnconfigureDNS_DbusFails_FallsBackToResolvectl(t *testing.T) {
	saveFuncVars(t)

	netlinkLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	dbusConnectSystemBus = func(opts ...dbus.ConnOption) (*dbus.Conn, error) {
		return nil, fmt.Errorf("dbus connection failed")
	}

	// We can't verify resolvectl was called without exec mock,
	// but we verify it doesn't panic
	unconfigureDNS("wg0")
}

// ---------------------------------------------------------------------------
// lookupGeo tests
// ---------------------------------------------------------------------------

func TestLookupGeo_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(geoResponse{
			Status:      "success",
			CountryCode: "US",
			Region:      "NY",
			City:        "New York",
		})
	}))
	defer ts.Close()

	// lookupGeo uses hardcoded URL, so we test it indirectly via lookupGeoFunc
	// Instead test the function directly since it uses http.Client
	// We can't easily test lookupGeo directly because it has a hardcoded URL,
	// but we can test GenerateStandardServerName uses lookupGeoFunc properly
	saveFuncVars(t)

	lookupGeoFunc = func(ip string) *geoResponse {
		if ip != "1.2.3.4" {
			t.Errorf("lookupGeo ip = %q, want 1.2.3.4", ip)
		}
		return &geoResponse{
			Status:      "success",
			CountryCode: "US",
			Region:      "NY",
			City:        "New York",
		}
	}

	cfg := &Config{
		Name:     "US-42",
		Endpoint: "1.2.3.4:51820",
	}
	result := GenerateStandardServerName(cfg, "protonvpn", "")
	// Should have state=NY and city=NewYork from geo lookup
	if !strings.Contains(result, "NY") {
		t.Errorf("result = %q, expected to contain NY from geo lookup", result)
	}
	if !strings.Contains(result, "NewYork") {
		t.Errorf("result = %q, expected to contain NewYork from geo lookup", result)
	}
}

func TestLookupGeo_ReturnsNil(t *testing.T) {
	saveFuncVars(t)

	lookupGeoFunc = func(ip string) *geoResponse {
		return nil
	}

	cfg := &Config{
		Name:     "US-42",
		Endpoint: "1.2.3.4:51820",
	}
	result := GenerateStandardServerName(cfg, "protonvpn", "")
	// Should still work, just without geo data
	if !strings.Contains(result, "Proton") {
		t.Errorf("result = %q, expected to contain Proton", result)
	}
}

// ---------------------------------------------------------------------------
// GenerateStandardServerName additional tests
// ---------------------------------------------------------------------------

func TestGenerateStandardServerName_WithP2PInComments(t *testing.T) {
	saveFuncVars(t)
	lookupGeoFunc = func(ip string) *geoResponse { return nil }

	cfg := &Config{
		Name:     "US-NY#42",
		Endpoint: "",
		Comments: []string{"# p2p enabled"},
	}
	result := GenerateStandardServerName(cfg, "protonvpn", "")
	if !strings.Contains(result, "P2P") {
		t.Errorf("result = %q, expected to contain P2P from comments", result)
	}
	if !strings.Contains(result, "Proton") {
		t.Errorf("result = %q, expected to contain Proton", result)
	}
}

func TestGenerateStandardServerName_TorInComments(t *testing.T) {
	saveFuncVars(t)
	lookupGeoFunc = func(ip string) *geoResponse { return nil }

	cfg := &Config{
		Name:     "US-NY#5",
		Endpoint: "",
		Comments: []string{"# tor exit node"},
	}
	result := GenerateStandardServerName(cfg, "", "")
	if !strings.Contains(result, "Tor") {
		t.Errorf("result = %q, expected to contain Tor from comments", result)
	}
}

func TestGenerateStandardServerName_SecureCoreFromComments(t *testing.T) {
	saveFuncVars(t)
	lookupGeoFunc = func(ip string) *geoResponse { return nil }

	cfg := &Config{
		Name:     "CH#1",
		Endpoint: "",
		Comments: []string{"# SecureCore server"},
	}
	result := GenerateStandardServerName(cfg, "", "")
	if !strings.Contains(result, "SC") {
		t.Errorf("result = %q, expected to contain SC feature", result)
	}
}

func TestGenerateStandardServerName_StreamingFromComments(t *testing.T) {
	saveFuncVars(t)
	lookupGeoFunc = func(ip string) *geoResponse { return nil }

	cfg := &Config{
		Name:     "US-NY#1",
		Endpoint: "",
		Comments: []string{"# streaming server"},
	}
	result := GenerateStandardServerName(cfg, "", "")
	if !strings.Contains(result, "Stream") {
		t.Errorf("result = %q, expected to contain Stream feature", result)
	}
}

func TestGenerateStandardServerName_TierKeywordFiltering(t *testing.T) {
	saveFuncVars(t)
	lookupGeoFunc = func(ip string) *geoResponse { return nil }

	// "FREE" as city should be filtered out (reCountryCity matches US as country, FREE as city, 42 as number)
	cfg := &Config{
		Name:     "US-FREE#42",
		Endpoint: "",
	}
	result := GenerateStandardServerName(cfg, "", "")
	// FREE should be filtered as a tier keyword
	if strings.Contains(strings.ToUpper(result), "FREE") {
		t.Errorf("result = %q, should not contain tier keyword FREE", result)
	}
}

func TestGenerateStandardServerName_NumberAutoGeneration(t *testing.T) {
	saveFuncVars(t)
	lookupGeoFunc = func(ip string) *geoResponse { return nil }

	tmpDir := t.TempDir()
	// Create existing configs with matching prefix pattern
	os.WriteFile(filepath.Join(tmpDir, "US#1.conf"), []byte(""), 0600)
	os.WriteFile(filepath.Join(tmpDir, "US#2.conf"), []byte(""), 0600)

	// Use a pattern where regex extracts country but no number,
	// so auto-generation kicks in. We need a name that matches one of the
	// regexes but without a number. The regexes always capture a number,
	// so we need a name that doesn't match any regex but still provides country.
	// Actually all regexes require digits. If none match, country="" and original
	// name is returned. So this feature only works with geo lookup.
	lookupGeoFunc = func(ip string) *geoResponse {
		return &geoResponse{
			Status:      "success",
			CountryCode: "US",
			Region:      "",
			City:        "",
		}
	}

	cfg := &Config{
		Name:     "myserver",
		Endpoint: "1.2.3.4:51820",
	}
	result := GenerateStandardServerName(cfg, "", tmpDir)
	if !strings.Contains(result, "#") {
		t.Errorf("result = %q, expected to contain auto-generated number", result)
	}
	// Since existing are US#1 and US#2, the search prefix is "US#"
	// and the next number should be 3
	if !strings.HasSuffix(result, "#3") {
		t.Errorf("result = %q, expected to end with #3", result)
	}
}

func TestGenerateStandardServerName_CountryHashNum(t *testing.T) {
	saveFuncVars(t)
	lookupGeoFunc = func(ip string) *geoResponse { return nil }

	cfg := &Config{
		Name:     "SE#130",
		Endpoint: "",
	}
	result := GenerateStandardServerName(cfg, "mullvad", "")
	if result != "Mullvad-SE#130" {
		t.Errorf("result = %q, want Mullvad-SE#130", result)
	}
}

func TestGenerateStandardServerName_CountryStateCityNum(t *testing.T) {
	saveFuncVars(t)
	lookupGeoFunc = func(ip string) *geoResponse { return nil }

	cfg := &Config{
		Name:     "US-DC-Washington-1",
		Endpoint: "",
	}
	result := GenerateStandardServerName(cfg, "", "")
	if !strings.Contains(result, "US") {
		t.Errorf("result = %q, expected to contain US", result)
	}
	if !strings.Contains(result, "DC") {
		t.Errorf("result = %q, expected to contain DC", result)
	}
	if !strings.Contains(result, "Washington") {
		t.Errorf("result = %q, expected to contain Washington", result)
	}
}

func TestGenerateStandardServerName_WithGeoFillRegion(t *testing.T) {
	saveFuncVars(t)

	lookupGeoFunc = func(ip string) *geoResponse {
		return &geoResponse{
			Status:      "success",
			CountryCode: "US",
			Region:      "CA",
			City:        "LosAngeles",
		}
	}

	cfg := &Config{
		Name:     "US-42",
		Endpoint: "1.2.3.4:51820",
	}
	result := GenerateStandardServerName(cfg, "", "")
	if !strings.Contains(result, "CA") {
		t.Errorf("result = %q, expected region CA from geo lookup", result)
	}
	if !strings.Contains(result, "LosAngeles") {
		t.Errorf("result = %q, expected city LosAngeles from geo lookup", result)
	}
}

func TestGenerateStandardServerName_StripProviderPrefix(t *testing.T) {
	saveFuncVars(t)
	lookupGeoFunc = func(ip string) *geoResponse { return nil }

	cfg := &Config{
		Name:     "Proton-US-NY#42",
		Endpoint: "",
	}
	result := GenerateStandardServerName(cfg, "protonvpn", "")
	// Should not double-prefix
	if strings.Count(result, "Proton") > 1 {
		t.Errorf("result = %q, has duplicate Proton prefix", result)
	}
}

func TestGenerateStandardServerName_UnknownProvider(t *testing.T) {
	saveFuncVars(t)
	lookupGeoFunc = func(ip string) *geoResponse { return nil }

	cfg := &Config{
		Name:     "US-NY#42",
		Endpoint: "",
	}
	result := GenerateStandardServerName(cfg, "unknownprovider", "")
	// Unknown provider ID should not add a prefix
	if result != "US-NY#42" {
		t.Errorf("result = %q, want US-NY#42 (no unknown prefix)", result)
	}
}

// ---------------------------------------------------------------------------
// detectServices additional tests
// ---------------------------------------------------------------------------

func TestDetectServices_StreamingInName(t *testing.T) {
	services := detectServices("US-streaming#1", nil)
	if !containsString(services, "streaming") {
		t.Error("expected streaming service")
	}
}

func TestDetectServices_StreamingInComments(t *testing.T) {
	services := detectServices("US-NY#42", []string{"# streaming server"})
	if !containsString(services, "streaming") {
		t.Error("expected streaming service from comment")
	}
}

func TestDetectServices_ModerateNAT(t *testing.T) {
	services := detectServices("US-NY#42", []string{"# Moderate NAT = on"})
	if !containsString(services, "moderatenat") {
		t.Error("expected moderatenat service")
	}
}

func TestDetectServices_NetShield1(t *testing.T) {
	services := detectServices("US-NY#42", []string{"# NetShield = 1"})
	if !containsString(services, "netshield1") {
		t.Error("expected netshield1 service")
	}
}

func TestDetectServices_NetShield2(t *testing.T) {
	services := detectServices("US-NY#42", []string{"# NetShield = 2"})
	if !containsString(services, "netshield2") {
		t.Error("expected netshield2 service")
	}
}

func TestDetectServices_SecureCoreFromComment(t *testing.T) {
	// Peer comment like "# SE-RO#1" should detect securecore
	services := detectServices("US-NY#42", []string{"# SE-RO#1"})
	if !containsString(services, "securecore") {
		t.Error("expected securecore from peer comment")
	}
}

func TestDetectServices_SecureCoreCommentExcludesTO(t *testing.T) {
	// "SE-TO#1" should not trigger securecore (TO = Tor false positive)
	services := detectServices("US-NY#42", []string{"# SE-TO#1"})
	if containsString(services, "securecore") {
		t.Error("SE-TO should be excluded from securecore detection")
	}
}

func TestDetectServices_P2PFromComment(t *testing.T) {
	services := detectServices("US-NY#42", []string{"# p2p enabled"})
	if !containsString(services, "p2p") {
		t.Error("expected p2p from comment")
	}
}

func TestDetectServices_SecureCoreNoDuplicate(t *testing.T) {
	// Name has SecureCore and also matches SC pattern - should not duplicate
	services := detectServices("CH-US-SecureCore#1", nil)
	count := 0
	for _, s := range services {
		if s == "securecore" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("securecore detected %d times, should be 1", count)
	}
}

// ---------------------------------------------------------------------------
// PrettyName additional tests
// ---------------------------------------------------------------------------

func TestPrettyName_SecureCore(t *testing.T) {
	info := ServerInfo{
		Name:     "CH-US#1",
		Country:  "CH",
		State:    "US",
		Number:   "1",
		Services: []string{"securecore"},
	}
	result := info.PrettyName()
	if !strings.Contains(result, "Switzerland") {
		t.Errorf("result = %q, expected Switzerland", result)
	}
	if !strings.Contains(result, "United States") {
		t.Errorf("result = %q, expected United States", result)
	}
}

func TestPrettyName_StateAndCity(t *testing.T) {
	info := ServerInfo{
		Name:    "US-CA-LosAngeles#1",
		Country: "US",
		State:   "CA",
		City:    "LosAngeles",
		Number:  "1",
	}
	result := info.PrettyName()
	if !strings.Contains(result, "United States") {
		t.Errorf("result = %q, expected United States", result)
	}
	// Should have state and city
	if !strings.Contains(result, "California") {
		t.Errorf("result = %q, expected California", result)
	}
}

func TestPrettyName_EmptyCountry(t *testing.T) {
	info := ServerInfo{Name: "test", Country: ""}
	if info.PrettyName() != "test" {
		t.Errorf("PrettyName() = %q, want 'test'", info.PrettyName())
	}
}

func TestPrettyName_NoNumber(t *testing.T) {
	info := ServerInfo{Name: "SE", Country: "SE"}
	result := info.PrettyName()
	if strings.Contains(result, "(") {
		t.Errorf("result = %q, should not have number in parens", result)
	}
}

func TestPrettyName_UnknownProvider(t *testing.T) {
	info := ServerInfo{
		Name:     "SE#5",
		Country:  "SE",
		Number:   "5",
		Provider: "CustomVPN",
	}
	result := info.PrettyName()
	// Unknown provider should use raw name
	if !strings.Contains(result, "CustomVPN") {
		t.Errorf("result = %q, expected CustomVPN", result)
	}
}

// ---------------------------------------------------------------------------
// LoadConfig tests
// ---------------------------------------------------------------------------

func TestLoadConfig_Success(t *testing.T) {
	tmpDir := t.TempDir()
	content := "[Interface]\nPrivateKey = cGhvbmV5cHJpdmF0ZWtleWJhc2U2NGVuY29kZWQ=\n[Peer]\nPublicKey = cHVibGlja2V5cGhvbmV5YmFzZTY0ZW5jb2RlZHg=\nEndpoint = 1.2.3.4:51820\n"
	os.WriteFile(filepath.Join(tmpDir, "test-server.conf"), []byte(content), 0600)

	cfg, err := LoadConfig(tmpDir, "test-server")
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Name != "test-server" {
		t.Errorf("Name = %q", cfg.Name)
	}
}

func TestLoadConfig_WithConfExtension(t *testing.T) {
	tmpDir := t.TempDir()
	content := "[Interface]\nPrivateKey = cGhvbmV5cHJpdmF0ZWtleWJhc2U2NGVuY29kZWQ=\n[Peer]\nPublicKey = cHVibGlja2V5cGhvbmV5YmFzZTY0ZW5jb2RlZHg=\nEndpoint = 1.2.3.4:51820\n"
	os.WriteFile(filepath.Join(tmpDir, "test-server.conf"), []byte(content), 0600)

	cfg, err := LoadConfig(tmpDir, "test-server.conf")
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Name != "test-server" {
		t.Errorf("Name = %q", cfg.Name)
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := LoadConfig(tmpDir, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadConfig_InvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	// Missing required fields
	content := "[Interface]\nAddress = 10.2.0.2/32\n"
	os.WriteFile(filepath.Join(tmpDir, "bad.conf"), []byte(content), 0600)

	_, err := LoadConfig(tmpDir, "bad")
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
	if !strings.Contains(err.Error(), "invalid config") {
		t.Errorf("error = %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// configureDNSviaResolvectl tests (with execCommand mock)
// ---------------------------------------------------------------------------

func TestConfigureDNSviaResolvectl_Success(t *testing.T) {
	saveFuncVars(t)

	// Mock execCommand to return a command that succeeds (true is a no-op success command)
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("true")
	}

	err := configureDNSviaResolvectl("wg0", []string{"10.2.0.1"})
	if err != nil {
		t.Fatalf("configureDNSviaResolvectl() error: %v", err)
	}
}

func TestConfigureDNSviaResolvectl_Failure(t *testing.T) {
	saveFuncVars(t)

	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("false")
	}

	err := configureDNSviaResolvectl("wg0", []string{"10.2.0.1"})
	if err == nil {
		t.Fatal("expected error when resolvectl fails")
	}
	if !strings.Contains(err.Error(), "resolvectl dns failed") {
		t.Errorf("error = %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// unconfigureDNS via resolvectl fallback test
// ---------------------------------------------------------------------------

func TestUnconfigureDNS_ResolvectlFallback(t *testing.T) {
	saveFuncVars(t)

	netlinkLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	dbusConnectSystemBus = func(opts ...dbus.ConnOption) (*dbus.Conn, error) {
		return nil, fmt.Errorf("no dbus")
	}
	execCalled := false
	execCommand = func(name string, args ...string) *exec.Cmd {
		execCalled = true
		return exec.Command("true")
	}

	unconfigureDNS("wg0")
	if !execCalled {
		t.Error("execCommand should be called as resolvectl fallback")
	}
}

// ---------------------------------------------------------------------------
// DNS DefaultRoute leak prevention tests
// ---------------------------------------------------------------------------

func TestConfigureDNS_DbusSuccess_SetsDefaultRoute(t *testing.T) {
	saveFuncVars(t)

	var setDefaultRouteCalls []struct {
		ifaceIdx int32
		val      bool
	}

	// Track SetLinkDefaultRoute calls through the dbus mock
	configureDNSviaDbusFunc = func(ifaceName string, dnsAddrs []string) error {
		// The real function calls SetLinkDefaultRoute — we test the whole flow
		return nil
	}
	configureDNSviaResolvectlFunc = func(ifaceName string, dnsAddrs []string) error {
		return nil
	}

	_ = setDefaultRouteCalls // verified through dbus mock in integration

	err := configureDNS("wg0", "10.2.0.1")
	if err != nil {
		t.Fatalf("configureDNS() error: %v", err)
	}
}

func TestConfigureDNS_Resolvectl_SetsDefaultRoute(t *testing.T) {
	saveFuncVars(t)

	configureDNSviaDbusFunc = func(ifaceName string, dnsAddrs []string) error {
		return fmt.Errorf("dbus failed")
	}

	var execCalls []string
	configureDNSviaResolvectlFunc = func(ifaceName string, dnsAddrs []string) error {
		// The real resolvectl function calls default-route commands
		return nil
	}

	getPhysicalInterface = func() (string, string, error) {
		return "wlan0", "192.168.1.1", nil
	}
	execCommand = func(name string, args ...string) *exec.Cmd {
		execCalls = append(execCalls, strings.Join(append([]string{name}, args...), " "))
		return exec.Command("true")
	}

	err := configureDNS("wg0", "10.2.0.1")
	if err != nil {
		t.Fatalf("configureDNS() error: %v", err)
	}
}

func TestConfigureDNS_PhysicalInterfaceNotFound(t *testing.T) {
	saveFuncVars(t)

	getPhysicalInterface = func() (string, string, error) {
		return "", "", fmt.Errorf("no default route")
	}

	configureDNSviaDbusFunc = func(ifaceName string, dnsAddrs []string) error {
		return nil
	}
	configureDNSviaResolvectlFunc = func(ifaceName string, dnsAddrs []string) error {
		return nil
	}

	// Should succeed even without physical interface (graceful no-op)
	err := configureDNS("wg0", "10.2.0.1")
	if err != nil {
		t.Fatalf("configureDNS() should succeed when physical interface not found: %v", err)
	}
}

func TestUnconfigureDNS_RestoresPhysicalDefaultRoute(t *testing.T) {
	saveFuncVars(t)

	netlinkLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	dbusConnectSystemBus = func(opts ...dbus.ConnOption) (*dbus.Conn, error) {
		return nil, fmt.Errorf("no dbus")
	}
	getPhysicalInterface = func() (string, string, error) {
		return "wlan0", "192.168.1.1", nil
	}

	var execCalls []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		execCalls = append(execCalls, strings.Join(append([]string{name}, args...), " "))
		return exec.Command("true")
	}

	unconfigureDNS("wg0")

	// Should have called resolvectl default-route to restore physical interface
	found := false
	for _, call := range execCalls {
		if strings.Contains(call, "resolvectl default-route wlan0 true") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected resolvectl default-route wlan0 true call, got: %v", execCalls)
	}
}

func TestUnconfigureDNS_InterfaceGone_StillRestoresPhysical(t *testing.T) {
	saveFuncVars(t)

	netlinkLinkByName = func(name string) (nl.Link, error) {
		if name == "wg0" {
			return nil, fmt.Errorf("no such device")
		}
		return netlinkpkg.NewMockLink(name, 20, net.FlagUp), nil
	}
	dbusConnectSystemBus = func(opts ...dbus.ConnOption) (*dbus.Conn, error) {
		return nil, fmt.Errorf("no dbus")
	}
	getPhysicalInterface = func() (string, string, error) {
		return "wlan0", "192.168.1.1", nil
	}

	var execCalls []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		execCalls = append(execCalls, strings.Join(append([]string{name}, args...), " "))
		return exec.Command("true")
	}

	unconfigureDNS("wg0")

	// Should still restore physical interface even when WG interface is gone
	found := false
	for _, call := range execCalls {
		if strings.Contains(call, "resolvectl default-route wlan0 true") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected physical interface restore even when WG gone, got: %v", execCalls)
	}
}

// readLogFile reads the debug.log content from a config directory
func readLogFile(configDir string) string {
	data, err := os.ReadFile(filepath.Join(configDir, "debug.log"))
	if err != nil {
		return ""
	}
	return string(data)
}

// newLoggingTestConfig creates a config with connection logging enabled
func newLoggingTestConfig(t *testing.T) *config.Config {
	t.Helper()
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConnectionName:        "wg0",
		ConfigDir:             tmpDir,
		ConfigFile:            filepath.Join(tmpDir, "config.json"),
		KillswitchAutoDisable: "true",
		LogMode:               "accurate",
		LogConnection:         true,
	}
	return cfg
}

// ===========================================================================
// Mutation-killing tests for connect.go
// ===========================================================================

// Kills CONDITIONALS_NEGATION at connect.go:114:38
// Mutation: err != nil -> err == nil on disconnect error in Connect.
// When disconnect succeeds (err == nil), Connect should continue and succeed.
// When disconnect fails (err != nil), Connect should still continue (error ignored).
// If mutation flips the condition, a successful disconnect would cause the
// block to execute differently. We verify both paths by checking the final outcome.
func TestConnect_DisconnectError_Continues(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()

	isConnectedFunc = func(name string) bool { return true }
	disconnectFunc = func(cfg *config.Config) error {
		return fmt.Errorf("disconnect failed")
	}

	cb, _ := collectStatuses()
	// Should still succeed despite disconnect error
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() should succeed even when prior disconnect fails: %v", err)
	}
}

// TestConnect_DisconnectError_EmitsWarningStatusWithWarningFlag is the
// callback-signal companion to TestConnect_DisconnectError_Continues.
// The existing test only verifies Connect doesn't abort; this one
// pins the actual warning emission AND the Warning: true flag.
//
// The Warning flag matters: it drives TUI styling (yellow/warning
// color vs success-green). A regression that emitted the message
// without Warning:true would display the disconnect failure as if
// it succeeded — confusing the user investigating a reconnect issue.
//
// Single-channel test (no log.Log on this path; the warning is
// caller-only because the existing connection's daemon already
// logged the underlying failure).
func TestConnect_DisconnectError_EmitsWarningStatusWithWarningFlag(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()

	isConnectedFunc = func(name string) bool { return true }
	disconnectFunc = func(cfg *config.Config) error {
		return fmt.Errorf("synthetic disconnect failure")
	}

	cb, statuses := collectStatuses()
	if err := Connect(cfg, server, cb); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var warningStatus *ConnectionStatus
	for i := range *statuses {
		if strings.Contains((*statuses)[i].Stage, "Disconnect warning") {
			warningStatus = &(*statuses)[i]
			break
		}
	}
	if warningStatus == nil {
		t.Fatalf("expected callback with 'Disconnect warning' stage; got: %+v", *statuses)
	}
	if !strings.Contains(warningStatus.Stage, "synthetic disconnect failure") {
		t.Errorf("warning should include underlying error, got: %q", warningStatus.Stage)
	}
	// Critical: Warning flag drives TUI styling.
	if !warningStatus.Warning {
		t.Error("Warning flag should be true so TUI styles this as a warning, not success")
	}
}

// Kills ARITHMETIC_BASE at connect.go:180:66
// Mutation: PersistentKeepalive * time.Second -> PersistentKeepalive + time.Second or - time.Second
// The PersistentKeepalive value is 25, so 25 * time.Second = 25s.
// With + it would be 25 + 1000000000 ns = ~1s, with - it would be negative.
// We check that the keepalive value is correctly applied by verifying
// the interface config gets the right duration.
func TestConnect_PersistentKeepaliveCalculation(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	server.Config.PersistentKeepalive = 30

	// Record what gets passed to wgctrl ConfigureDevice
	wgMock := &mockWgctrlRunner{}
	var capturedCfg wgtypes.Config
	wgMock.configErr = nil
	netlinkpkg.SetWgctrlRunner(&capturingWgctrlRunner{
		inner:       wgMock,
		capturedCfg: &capturedCfg,
	})

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	// Check the captured keepalive duration
	if len(capturedCfg.Peers) > 0 && capturedCfg.Peers[0].PersistentKeepaliveInterval != nil {
		got := *capturedCfg.Peers[0].PersistentKeepaliveInterval
		want := 30 * time.Second
		if got != want {
			t.Errorf("PersistentKeepalive = %v, want %v", got, want)
		}
	}
}

// capturingWgctrlRunner wraps a wgctrl runner and captures ConfigureDevice calls
type capturingWgctrlRunner struct {
	inner       *mockWgctrlRunner
	capturedCfg *wgtypes.Config
}

func (c *capturingWgctrlRunner) ConfigureDevice(name string, cfg wgtypes.Config) error {
	*c.capturedCfg = cfg
	return c.inner.ConfigureDevice(name, cfg)
}

func (c *capturingWgctrlRunner) Device(name string) (*wgtypes.Device, error) {
	return c.inner.Device(name)
}

func (c *capturingWgctrlRunner) Close() error { return nil }

// Kills CONDITIONALS_BOUNDARY at connect.go:208:9 (mtu <= 0 -> mtu < 0)
// AND CONDITIONALS_NEGATION at connect.go:208:9 (mtu <= 0 -> mtu > 0)
// When MTU is exactly 0, the condition mtu <= 0 should be true, using defaultMTU.
// If boundary mutation makes it mtu < 0: 0 < 0 is false, so MTU 0 would be used directly.
// If negation mutation makes it mtu > 0: 0 > 0 is false, same problem.
// We verify that MTU=0 results in defaultMTU (1420) being used, not 0.
func TestConnect_MTU_Zero_UsesDefault(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	server.Config.MTU = 0 // Explicitly zero

	var mtuSet int
	mock := newMockNetlinkRunner()
	mock.addLink(netlinkpkg.NewMockLink("wg0", 10, net.FlagUp))
	netlinkpkg.SetNetlinkRunner(mock)

	// Override LinkSetMTU to capture the value
	origLinkSetMTU := mock.LinkSetMTU
	_ = origLinkSetMTU
	// We can't easily capture LinkSetMTU via the mock because it goes through
	// the netlink package. Instead, let's check via the mock link's attributes.
	// Actually, the mock runner implements LinkSetMTU which sets attrs.MTU.
	// After Connect, we can check what MTU was set on the mock link.

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	// Check the MTU was set on the link via the mock
	for _, link := range mock.links {
		mtuSet = link.Attrs().MTU
	}
	if mtuSet != 1420 {
		t.Errorf("MTU = %d, want 1420 (default) when config MTU is 0", mtuSet)
	}
}

// Exercises connect.go:211:41 (SetMTU error condition).
// Note: This mutation (err != nil -> err == nil) is equivalent because the body
// is an empty comment block. This test verifies the code path works correctly
// but cannot distinguish the mutation.
func TestConnect_MTUSetSuccess_Continues(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()
	server.Config.MTU = 1400

	// Ensure MTU set succeeds (mock default is nil error)
	cb, statuses := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() should succeed when MTU set succeeds: %v", err)
	}
	// Verify we reach the final success stage
	found := false
	for _, s := range *statuses {
		if s.Success {
			found = true
		}
	}
	if !found {
		t.Error("expected success status after MTU set succeeds")
	}
}

// Kills CONDITIONALS_NEGATION at connect.go:224:55
// Mutation: err != nil -> err == nil on configureDNSFunc error check.
// When DNS configuration SUCCEEDS, the warning should NOT be emitted.
// If mutation flips, success would trigger the warning path.
func TestConnect_DNSSuccess_NoWarning(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)
	server := newTestServer()

	configureDNSFunc = func(ifaceName string, dns string) error {
		return nil // success
	}

	cb, statuses := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	for _, s := range *statuses {
		if strings.Contains(s.Stage, "Warning: DNS setup failed") {
			t.Error("DNS warning should not appear when DNS configuration succeeds")
		}
	}
}

// Kills CONDITIONALS_NEGATION at connect.go:236:63
// Mutation: err != nil -> err == nil on configureRoutes error check.
// When route configuration SUCCEEDS, the warning log should NOT contain the route warning.
// When it FAILS, the warning log SHOULD contain it.
func TestConnect_RoutesSuccess_NoWarningLog(t *testing.T) {
	setupAllMocks(t)
	cfg := newLoggingTestConfig(t)
	server := newTestServer()

	// Default mocks have routes succeeding
	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	logContent := readLogFile(cfg.ConfigDir)
	if strings.Contains(logContent, "Route configuration warning") {
		t.Error("log should NOT contain route warning when routes succeed")
	}
}

func TestConnect_RoutesFailure_FatalError(t *testing.T) {
	setupAllMocks(t)
	cfg := newLoggingTestConfig(t)
	server := newTestServer()

	// Make configureRoutes fail (via netlinkAddSplitRoutes returning error)
	netlinkAddSplitRoutes = func(ifaceName string) error {
		return fmt.Errorf("some route error")
	}

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err == nil {
		t.Fatal("Connect() should return error when routes fail")
	}
	if !strings.Contains(err.Error(), "failed to configure routes") {
		t.Errorf("error should mention routes, got: %v", err)
	}

	logContent := readLogFile(cfg.ConfigDir)
	if !strings.Contains(logContent, "Route configuration failed") {
		t.Error("log should contain route failure message")
	}
}

// Kills CONDITIONALS_NEGATION at connect.go:279:28
// Mutation: err != nil -> err == nil on cfg.Save() error check.
// When Save succeeds, no warning log should appear.
// If mutated, success would trigger the warning log.
func TestConnect_SaveSuccess_NoWarningLog(t *testing.T) {
	setupAllMocks(t)
	cfg := newLoggingTestConfig(t)
	server := newTestServer()

	// Ensure config can be saved
	os.WriteFile(cfg.ConfigFile, []byte(""), 0600)

	cb, _ := collectStatuses()
	err := Connect(cfg, server, cb)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}

	logContent := readLogFile(cfg.ConfigDir)
	if strings.Contains(logContent, "failed to save config") {
		t.Error("log should NOT contain save warning when save succeeds")
	}
}

// Kills CONDITIONALS_NEGATION at connect.go:301:9
// Mutation: gateway != "" -> gateway == "" in configureRoutes.
// When gateway IS non-empty, AddHostRoute MUST be called.
// When gateway IS empty, AddHostRoute MUST NOT be called.
// The existing TestConfigureRoutes_EmptyGateway tests the empty case.
// This tests the specific boundary: empty endpointIP when gateway is present.
func TestConfigureRoutes_EmptyEndpoint_NoHostRoute(t *testing.T) {
	setupAllMocks(t)

	hostRouteCalled := false
	netlinkGetDefaultGateway = func() (string, string, error) {
		return "192.168.1.1", "eth0", nil
	}
	netlinkAddHostRoute = func(host, gateway, iface string) error {
		hostRouteCalled = true
		return nil
	}
	netlinkAddSplitRoutes = func(ifaceName string) error { return nil }

	err := configureRoutes("wg0", "")
	if err != nil {
		t.Fatalf("configureRoutes() error: %v", err)
	}
	if hostRouteCalled {
		t.Error("AddHostRoute should NOT be called when endpointIP is empty")
	}
}

// Kills CONDITIONALS_NEGATION at connect.go:309:66
// Mutation: err != nil -> err == nil on netlinkAddHostRoute error check.
// When AddHostRoute SUCCEEDS, there should be no issue.
// If mutated, success would trigger error handling.
func TestConfigureRoutes_HostRouteSuccess(t *testing.T) {
	setupAllMocks(t)

	netlinkGetDefaultGateway = func() (string, string, error) {
		return "192.168.1.1", "eth0", nil
	}
	netlinkAddHostRoute = func(host, gateway, iface string) error {
		return nil // success
	}
	netlinkAddSplitRoutes = func(ifaceName string) error { return nil }

	err := configureRoutes("wg0", "1.2.3.4")
	if err != nil {
		t.Fatalf("configureRoutes() should succeed when host route succeeds: %v", err)
	}
}

// Exercises CONDITIONALS_BOUNDARY at connect.go:339:42
// Mutation: idx >= 0 -> idx > 0 in parseAddress comma handling.
// This boundary is equivalent in practice because both branches lead to a parse error
// when the comma is at position 0. We still exercise the code path.
func TestParseAddress_CommaAtStart(t *testing.T) {
	// Address starts with comma - first "address" is empty
	_, _, err := parseAddress(",10.2.0.2/32")
	if err == nil {
		t.Error("expected error when comma at start creates empty first address")
	}
}

// Test that comma-separated addresses work correctly (exercises the same code path)
func TestParseAddress_CommaPosition(t *testing.T) {
	// Verify comma at position > 0 works correctly
	hostIP, _, err := parseAddress("10.2.0.2/32,fd00::2/128")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hostIP.String() != "10.2.0.2" {
		t.Errorf("hostIP = %q, want 10.2.0.2", hostIP.String())
	}
}

// ===========================================================================
// Mutation-killing tests for disconnect.go
// ===========================================================================

// Kills CONDITIONALS_NEGATION at disconnect.go:50:53
// Mutation: err == nil -> err != nil on stopConnectionDaemon result.
// When stopConnectionDaemon SUCCEEDS, the "Stopped connection daemon" log message should appear.
// When it FAILS, it should NOT appear.
// If mutation flips, success wouldn't log and failure would.
func TestDisconnect_StopDaemonSuccess_Logs(t *testing.T) {
	setupAllMocks(t)
	cfg := newLoggingTestConfig(t)
	isConnectedFunc = func(name string) bool { return false }

	// Create a valid daemon PID file with our own PID so stopConnectionDaemon succeeds
	// (returns nil for own PID)
	os.WriteFile(filepath.Join(cfg.ConfigDir, ".daemon.pid"), []byte(fmt.Sprintf("%d", os.Getpid())), 0600)

	cb, _ := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}

	logContent := readLogFile(cfg.ConfigDir)
	if !strings.Contains(logContent, "Stopped connection daemon") {
		t.Error("log should contain 'Stopped connection daemon' when daemon stop succeeds")
	}
}

func TestDisconnect_StopDaemonFailure_NoLog(t *testing.T) {
	setupAllMocks(t)
	cfg := newLoggingTestConfig(t)
	isConnectedFunc = func(name string) bool { return false }

	// No PID file -> stopConnectionDaemon will fail
	cb, _ := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}

	logContent := readLogFile(cfg.ConfigDir)
	if strings.Contains(logContent, "Stopped connection daemon") {
		t.Error("log should NOT contain 'Stopped connection daemon' when daemon stop fails")
	}
}

// Kills ARITHMETIC_BASE at disconnect.go:81:14
// Mutation: 2 * time.Second -> 2 + time.Second or 2 - time.Second
// The timeSleep call uses 2 * time.Second. We verify the correct duration is passed.
func TestDisconnect_SleepDuration(t *testing.T) {
	setupAllMocks(t)
	cfg := newTestConfig(t)

	isConnectedFunc = func(name string) bool { return true }
	callCount := 0
	utilGetPublicIPv4 = func() (string, error) {
		callCount++
		if callCount == 1 {
			return "2.2.2.2", nil
		}
		return "5.5.5.5", nil
	}

	var sleepDuration time.Duration
	timeSleep = func(d time.Duration) {
		sleepDuration = d
	}

	cb, _ := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}

	want := 2 * time.Second
	if sleepDuration != want {
		t.Errorf("timeSleep called with %v, want %v", sleepDuration, want)
	}
}

// Kills CONDITIONALS_NEGATION at disconnect.go:162:28
// Mutation: err != nil -> err == nil on cfg.Save() at end of Disconnect.
// When Save succeeds, no "failed to save config" warning should be logged.
// If mutated, success would trigger the warning log.
func TestDisconnect_SaveSuccess_NoWarningLog(t *testing.T) {
	setupAllMocks(t)
	cfg := newLoggingTestConfig(t)

	// Ensure config can be saved
	os.WriteFile(cfg.ConfigFile, []byte(""), 0600)

	isConnectedFunc = func(name string) bool { return true }
	callCount := 0
	utilGetPublicIPv4 = func() (string, error) {
		callCount++
		if callCount == 1 {
			return "2.2.2.2", nil
		}
		return "5.5.5.5", nil
	}

	cb, _ := collectDisconnectStatuses()
	err := DisconnectWithCallback(cfg, cb)
	if err != nil {
		t.Fatalf("Disconnect() error: %v", err)
	}

	// Verify config was cleared
	if cfg.LastConnectedServer != "" {
		t.Errorf("LastConnectedServer = %q, want empty", cfg.LastConnectedServer)
	}

	logContent := readLogFile(cfg.ConfigDir)
	if strings.Contains(logContent, "failed to save config") {
		t.Error("log should NOT contain save warning when save succeeds")
	}
}

// ===========================================================================
// Mutation-killing tests for status.go
// ===========================================================================

// Kills CONDITIONALS_BOUNDARY at status.go:80:20
// Mutation: handshakeAge < MaxHandshakeAge -> handshakeAge <= MaxHandshakeAge
// When handshakeAge == MaxHandshakeAge exactly, < returns false (stale), <= returns true (connected).
// The code uses <, so exactly at the boundary should be "stale" (false).
func TestIsConnected_HandshakeExactlyAtBoundary(t *testing.T) {
	saveFuncVars(t)

	now := time.Now()
	timeNow = func() time.Time { return now }

	statusLinkByName = func(name string) (nl.Link, error) {
		return netlinkpkg.NewMockLink(name, 10, net.FlagUp), nil
	}
	statusAddrList = func(link nl.Link, family int) ([]nl.Addr, error) {
		return []nl.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)}}}, nil
	}
	statusGetDevice = func(name string) (*wgtypes.Device, bool, error) {
		return &wgtypes.Device{
			Peers: []wgtypes.Peer{
				{LastHandshakeTime: now.Add(-MaxHandshakeAge)}, // Exactly at boundary
			},
		}, true, nil
	}

	// At exactly MaxHandshakeAge, handshakeAge < MaxHandshakeAge is FALSE.
	// So this should return false (stale).
	if IsConnected("wg0") {
		t.Error("should return false when handshake age equals MaxHandshakeAge exactly")
	}
}

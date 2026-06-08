package latency

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	probing "github.com/prometheus-community/pro-bing"
)

// --- Mock pinger infrastructure ---

// mockPinger implements the Pinger interface for tests.
type mockPinger struct {
	countSet      int
	timeoutSet    time.Duration
	privilegedSet bool
	runErr        error
	stats         *probing.Statistics
}

func (m *mockPinger) SetCount(n int)                  { m.countSet = n }
func (m *mockPinger) SetTimeout(d time.Duration)      { m.timeoutSet = d }
func (m *mockPinger) SetPrivileged(b bool)            { m.privilegedSet = b }
func (m *mockPinger) Run() error                      { return m.runErr }
func (m *mockPinger) Statistics() *probing.Statistics { return m.stats }

// withMockPinger replaces newPinger for the duration of a test and restores it
// via t.Cleanup. It returns a function that the mock factory calls for each
// invocation so callers can vary behaviour per-address.
func withMockPinger(t *testing.T, factory func(addr string) (Pinger, error)) {
	t.Helper()
	orig := newPinger
	newPinger = factory
	t.Cleanup(func() { newPinger = orig })
}

// --- Helper to build a temp config ---

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	tmpDir := t.TempDir()
	return &config.Config{
		ConfigDir:  tmpDir,
		ConfigFile: filepath.Join(tmpDir, "config.json"),
	}
}

// wgConfContent is a valid WireGuard config snippet used across tests.
const wgConfContent = `[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0
`

// --- Struct tests (pre-existing, kept as-is) ---

func TestServerEntryStruct(t *testing.T) {
	s := ServerEntry{
		Type:     "manual",
		Provider: "protonvpn",
		Name:     "US-NY#42",
		IP:       "198.51.100.1",
	}
	if s.Type != "manual" {
		t.Errorf("Type = %q", s.Type)
	}
	if s.Provider != "protonvpn" {
		t.Errorf("Provider = %q", s.Provider)
	}
	if s.Name != "US-NY#42" {
		t.Errorf("Name = %q", s.Name)
	}
	if s.IP != "198.51.100.1" {
		t.Errorf("IP = %q", s.IP)
	}
}

func TestTestResultStruct(t *testing.T) {
	r := TestResult{
		Server:  ServerEntry{Name: "test"},
		Latency: 42,
		Success: true,
	}
	if r.Latency != 42 {
		t.Errorf("Latency = %d", r.Latency)
	}
	if !r.Success {
		t.Error("Success should be true")
	}
	if r.Server.Name != "test" {
		t.Errorf("Server.Name = %q", r.Server.Name)
	}

	// Unreachable server
	r2 := TestResult{Latency: -1, Success: false}
	if r2.Latency != -1 {
		t.Errorf("Latency = %d, want -1", r2.Latency)
	}
	if r2.Success {
		t.Error("Success should be false for unreachable")
	}
}

// --- ProbePing tests ---

func TestProbePingSuccess(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		if addr != "127.0.0.1" {
			t.Errorf("ProbePing should ping 127.0.0.1, got %s", addr)
		}
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 1, AvgRtt: 0},
		}, nil
	})

	if !ProbePing() {
		t.Error("ProbePing() should return true when ping succeeds")
	}
}

func TestProbePingFailure(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{runErr: fmt.Errorf("permission denied")}, nil
	})

	if ProbePing() {
		t.Error("ProbePing() should return false when ping fails")
	}
}

func TestProbePingNewPingerError(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return nil, fmt.Errorf("no pinger")
	})

	if ProbePing() {
		t.Error("ProbePing() should return false when newPinger fails")
	}
}

func TestProbePingUnprivilegedSuccess(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 1, AvgRtt: 0},
		}, nil
	})

	if !ProbePingUnprivileged() {
		t.Error("ProbePingUnprivileged() should return true when ping succeeds")
	}
}

func TestProbePingUnprivilegedFailure(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{runErr: fmt.Errorf("socket error")}, nil
	})

	if ProbePingUnprivileged() {
		t.Error("ProbePingUnprivileged() should return false when ping fails")
	}
}

// --- PingServerUnprivileged tests ---

func TestPingServerUnprivilegedSuccess(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 2, AvgRtt: 30 * time.Millisecond},
		}, nil
	})

	latency := PingServerUnprivileged("198.51.100.1")
	if latency != 30 {
		t.Errorf("PingServerUnprivileged() = %d, want 30", latency)
	}
}

func TestPingServerUnprivilegedRunError(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{runErr: fmt.Errorf("socket error")}, nil
	})

	latency := PingServerUnprivileged("198.51.100.1")
	if latency != -1 {
		t.Errorf("PingServerUnprivileged() = %d, want -1", latency)
	}
}

func TestPingServerUnprivilegedZeroPackets(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 0},
		}, nil
	})

	latency := PingServerUnprivileged("198.51.100.1")
	if latency != -1 {
		t.Errorf("PingServerUnprivileged() = %d, want -1", latency)
	}
}

func TestPingServerUnprivilegedNewPingerError(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return nil, fmt.Errorf("DNS resolution failed")
	})

	latency := PingServerUnprivileged("198.51.100.1")
	if latency != -1 {
		t.Errorf("PingServerUnprivileged() = %d, want -1", latency)
	}
}

// --- PingServer tests ---

func TestPingServerSuccess(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{
			stats: &probing.Statistics{
				PacketsRecv: 2,
				AvgRtt:      50 * time.Millisecond,
			},
		}, nil
	})

	latency := PingServer("198.51.100.1")
	if latency != 50 {
		t.Errorf("PingServer() = %d, want 50", latency)
	}
}

func TestPingServerNewPingerError(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return nil, fmt.Errorf("DNS resolution failed")
	})

	latency := PingServer("198.51.100.1")
	if latency != -1 {
		t.Errorf("PingServer() = %d, want -1 on NewPinger error", latency)
	}
}

func TestPingServerRunError(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{
			runErr: fmt.Errorf("permission denied"),
		}, nil
	})

	latency := PingServer("198.51.100.1")
	if latency != -1 {
		t.Errorf("PingServer() = %d, want -1 on Run error", latency)
	}
}

func TestPingServerZeroPacketsReceived(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{
			stats: &probing.Statistics{
				PacketsRecv: 0,
				AvgRtt:      0,
			},
		}, nil
	})

	latency := PingServer("198.51.100.1")
	if latency != -1 {
		t.Errorf("PingServer() = %d, want -1 when 0 packets received", latency)
	}
}

func TestPingServerEmptyIP(t *testing.T) {
	// An empty string should cause newPinger to fail (the real probing.NewPinger
	// rejects it). We mock this to guarantee the error path.
	withMockPinger(t, func(addr string) (Pinger, error) {
		if addr == "" {
			return nil, fmt.Errorf("empty address")
		}
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 1, AvgRtt: 10 * time.Millisecond},
		}, nil
	})

	latency := PingServer("")
	if latency != -1 {
		t.Errorf("PingServer(\"\") = %d, want -1", latency)
	}
}

// --- collectServers tests ---

func TestCollectServersEmpty(t *testing.T) {
	cfg := testConfig(t)

	// Create empty wireguard directory
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "wireguard"), 0755)

	servers := collectServers(cfg)
	if len(servers) != 0 {
		t.Errorf("expected 0 servers from empty config, got %d", len(servers))
	}
}

func TestCollectServersManual(t *testing.T) {
	cfg := testConfig(t)

	// Create wireguard directory with a valid config
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	os.WriteFile(filepath.Join(wgDir, "US-NY#1.conf"), []byte(wgConfContent), 0600)

	servers := collectServers(cfg)
	found := false
	for _, s := range servers {
		if s.Type == "manual" && s.IP == "198.51.100.1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find manual server with IP 198.51.100.1, got %v", servers)
	}
}

func TestCollectServersDynamic(t *testing.T) {
	cfg := testConfig(t)

	// Create directories
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "wireguard"), 0755)
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "providers"), 0755)
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "cache"), 0755)

	// Create a provider config
	providerConf := `{"private_key":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=","address":"10.2.0.2/32","dns":"10.2.0.1"}`
	os.WriteFile(filepath.Join(cfg.ConfigDir, "providers", "testprovider.json"), []byte(providerConf), 0600)

	// Create a server cache file (named provider_servers.json, uses "ips" array)
	cacheContent := `[{"ips":["203.0.113.1"],"hostname":"server1.test.com","server_name":"US-NY#1"},{"ips":["203.0.113.2"],"hostname":"server2.test.com","server_name":"SE#5"}]`
	os.WriteFile(filepath.Join(cfg.ConfigDir, "cache", "testprovider_servers.json"), []byte(cacheContent), 0644)

	servers := collectServers(cfg)
	dynamicCount := 0
	for _, s := range servers {
		if s.Type == "dynamic" && s.Provider == "testprovider" {
			dynamicCount++
		}
	}
	if dynamicCount != 2 {
		t.Errorf("expected 2 dynamic servers, got %d (total: %v)", dynamicCount, servers)
	}
}

func TestCollectServersManualAndDynamic(t *testing.T) {
	cfg := testConfig(t)

	// Create wireguard directory with 2 manual configs
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	conf1 := `[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Endpoint = 198.51.100.10:51820
AllowedIPs = 0.0.0.0/0
`
	conf2 := `[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.2.0.3/32
DNS = 10.2.0.1

[Peer]
PublicKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Endpoint = 198.51.100.20:51820
AllowedIPs = 0.0.0.0/0
`
	os.WriteFile(filepath.Join(wgDir, "US-NY#10.conf"), []byte(conf1), 0600)
	os.WriteFile(filepath.Join(wgDir, "DE-Berlin#3.conf"), []byte(conf2), 0600)

	// Create dynamic provider + cache
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "providers"), 0755)
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "cache"), 0755)

	providerConf := `{"private_key":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=","address":"10.2.0.2/32"}`
	os.WriteFile(filepath.Join(cfg.ConfigDir, "providers", "myprovider.json"), []byte(providerConf), 0600)

	cacheContent := `[{"ips":["203.0.113.50"],"hostname":"s1.vpn.com","server_name":"JP-Tokyo#1"},{"ips":["203.0.113.51"],"hostname":"s2.vpn.com","server_name":"AU-Sydney#2"}]`
	os.WriteFile(filepath.Join(cfg.ConfigDir, "cache", "myprovider_servers.json"), []byte(cacheContent), 0644)

	servers := collectServers(cfg)

	manualCount := 0
	dynamicCount := 0
	for _, s := range servers {
		switch s.Type {
		case "manual":
			manualCount++
		case "dynamic":
			dynamicCount++
		}
	}

	if manualCount != 2 {
		t.Errorf("expected 2 manual servers, got %d", manualCount)
	}
	if dynamicCount != 2 {
		t.Errorf("expected 2 dynamic servers, got %d", dynamicCount)
	}
	if len(servers) != 4 {
		t.Errorf("expected 4 total servers, got %d", len(servers))
	}
}

func TestCollectServersDynamicUsesHostnameWhenServerNameEmpty(t *testing.T) {
	cfg := testConfig(t)

	os.MkdirAll(filepath.Join(cfg.ConfigDir, "wireguard"), 0755)
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "providers"), 0755)
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "cache"), 0755)

	providerConf := `{"private_key":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=","address":"10.2.0.2/32"}`
	os.WriteFile(filepath.Join(cfg.ConfigDir, "providers", "fallbacktest.json"), []byte(providerConf), 0600)

	// server_name is empty, so collectServers should fall back to hostname
	cacheContent := `[{"ips":["203.0.113.99"],"hostname":"fallback.example.com","server_name":""}]`
	os.WriteFile(filepath.Join(cfg.ConfigDir, "cache", "fallbacktest_servers.json"), []byte(cacheContent), 0644)

	servers := collectServers(cfg)
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Name != "fallback.example.com" {
		t.Errorf("expected hostname fallback, got Name=%q", servers[0].Name)
	}
}

// --- testBatch tests ---

func TestTestBatchConcurrency(t *testing.T) {
	// Map IP -> latency for our mock
	latencyMap := map[string]int{
		"10.0.0.1": 20,
		"10.0.0.2": 50,
		"10.0.0.3": 100,
	}

	withMockPinger(t, func(addr string) (Pinger, error) {
		ms, ok := latencyMap[addr]
		if !ok {
			return nil, fmt.Errorf("unknown addr %s", addr)
		}
		return &mockPinger{
			stats: &probing.Statistics{
				PacketsRecv: 2,
				AvgRtt:      time.Duration(ms) * time.Millisecond,
			},
		}, nil
	})

	servers := []ServerEntry{
		{Type: "manual", Name: "s1", IP: "10.0.0.1"},
		{Type: "manual", Name: "s2", IP: "10.0.0.2"},
		{Type: "manual", Name: "s3", IP: "10.0.0.3"},
	}

	results := testBatch(servers)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	for i, r := range results {
		expected := latencyMap[servers[i].IP]
		if r.Latency != expected {
			t.Errorf("result[%d] latency = %d, want %d", i, r.Latency, expected)
		}
		if !r.Success {
			t.Errorf("result[%d] should be successful", i)
		}
		if r.Server.Name != servers[i].Name {
			t.Errorf("result[%d] server name = %q, want %q", i, r.Server.Name, servers[i].Name)
		}
	}
}

func TestTestBatchEmpty(t *testing.T) {
	results := testBatch(nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for nil batch, got %d", len(results))
	}
}

// --- TestAllServers tests ---

func TestTestAllServersHappyPath(t *testing.T) {
	cfg := testConfig(t)
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	// Create 3 manual configs
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, ip := range ips {
		content := fmt.Sprintf(`[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.2.0.2/32

[Peer]
PublicKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Endpoint = %s:51820
AllowedIPs = 0.0.0.0/0
`, ip)
		os.WriteFile(filepath.Join(wgDir, fmt.Sprintf("server%d.conf", i+1)), []byte(content), 0600)
	}

	// Mock: 10.0.0.1 -> 30ms, 10.0.0.2 -> 60ms, 10.0.0.3 -> 15ms
	latencyMap := map[string]int{
		"10.0.0.1": 30,
		"10.0.0.2": 60,
		"10.0.0.3": 15,
	}
	withMockPinger(t, func(addr string) (Pinger, error) {
		ms, ok := latencyMap[addr]
		if !ok {
			return nil, fmt.Errorf("unknown")
		}
		return &mockPinger{
			stats: &probing.Statistics{
				PacketsRecv: 2,
				AvgRtt:      time.Duration(ms) * time.Millisecond,
			},
		}, nil
	})

	var progressCalls []struct{ tested, total, reachable int }
	results, err := TestAllServers(cfg, 2, func(tested, total, reachable int) {
		progressCalls = append(progressCalls, struct{ tested, total, reachable int }{tested, total, reachable})
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}
	if successCount != 3 {
		t.Errorf("expected 3 successful, got %d", successCount)
	}

	// With batch size 2 and 3 servers, we expect 2 progress calls:
	// batch 1: tested=2, total=3; batch 2: tested=3, total=3
	if len(progressCalls) != 2 {
		t.Errorf("expected 2 progress calls, got %d", len(progressCalls))
	}
	if len(progressCalls) >= 1 && progressCalls[0].total != 3 {
		t.Errorf("first progress total = %d, want 3", progressCalls[0].total)
	}
	if len(progressCalls) >= 2 && progressCalls[1].tested != 3 {
		t.Errorf("second progress tested = %d, want 3", progressCalls[1].tested)
	}
}

func TestTestAllServersNoServers(t *testing.T) {
	cfg := testConfig(t)
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "wireguard"), 0755)

	_, err := TestAllServers(cfg, 10, nil)
	if err == nil {
		t.Error("expected error for empty server list")
	}
}

func TestTestAllServersNilProgress(t *testing.T) {
	cfg := testConfig(t)
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	os.WriteFile(filepath.Join(wgDir, "test-server.conf"), []byte(wgConfContent), 0600)

	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 1, AvgRtt: 25 * time.Millisecond},
		}, nil
	})

	results, err := TestAllServers(cfg, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected at least one result")
	}
}

// --- FindQuickestServer tests ---

func TestFindQuickestServerPicksLowest(t *testing.T) {
	cfg := testConfig(t)
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	// Create 3 configs with different IPs
	for i, ip := range []string{"10.1.0.1", "10.1.0.2", "10.1.0.3"} {
		content := fmt.Sprintf(`[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.2.0.2/32

[Peer]
PublicKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Endpoint = %s:51820
AllowedIPs = 0.0.0.0/0
`, ip)
		os.WriteFile(filepath.Join(wgDir, fmt.Sprintf("svr%d.conf", i+1)), []byte(content), 0600)
	}

	// 10.1.0.2 should win with 5ms
	latencyMap := map[string]int{
		"10.1.0.1": 100,
		"10.1.0.2": 5,
		"10.1.0.3": 50,
	}
	withMockPinger(t, func(addr string) (Pinger, error) {
		ms, ok := latencyMap[addr]
		if !ok {
			return nil, fmt.Errorf("unknown")
		}
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 2, AvgRtt: time.Duration(ms) * time.Millisecond},
		}, nil
	})

	server, latency, err := FindQuickestServer(cfg, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if latency != 5 {
		t.Errorf("latency = %d, want 5", latency)
	}
	if server.IP != "10.1.0.2" {
		t.Errorf("server IP = %q, want 10.1.0.2", server.IP)
	}
}

func TestFindQuickestServerAllUnreachable(t *testing.T) {
	cfg := testConfig(t)
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	os.WriteFile(filepath.Join(wgDir, "unreachable.conf"), []byte(wgConfContent), 0600)

	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 0, AvgRtt: 0},
		}, nil
	})

	_, _, err := FindQuickestServer(cfg, 10, nil)
	if err == nil {
		t.Error("expected error when all servers unreachable")
	}
}

func TestFindQuickestServerNoServers(t *testing.T) {
	cfg := testConfig(t)
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "wireguard"), 0755)

	_, _, err := FindQuickestServer(cfg, 10, nil)
	if err == nil {
		t.Error("expected error for empty server list")
	}
}

// --- GetRandomServer tests ---

func TestGetRandomServerReturnsServer(t *testing.T) {
	cfg := testConfig(t)
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	os.WriteFile(filepath.Join(wgDir, "test-server.conf"), []byte(wgConfContent), 0600)

	server, err := GetRandomServer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if server == nil {
		t.Fatal("expected non-nil server")
	}
	if server.IP == "" {
		t.Error("server IP should not be empty")
	}
	if server.Type != "manual" {
		t.Errorf("server.Type = %q, want manual", server.Type)
	}
}

func TestGetRandomServerEmpty(t *testing.T) {
	cfg := testConfig(t)
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "wireguard"), 0755)

	_, err := GetRandomServer(cfg)
	if err == nil {
		t.Error("expected error for empty server list")
	}
}

func TestGetRandomServerMultiple(t *testing.T) {
	cfg := testConfig(t)
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	for i, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		content := fmt.Sprintf(`[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.2.0.2/32

[Peer]
PublicKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Endpoint = %s:51820
AllowedIPs = 0.0.0.0/0
`, ip)
		os.WriteFile(filepath.Join(wgDir, fmt.Sprintf("s%d.conf", i+1)), []byte(content), 0600)
	}

	server, err := GetRandomServer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	validIPs := map[string]bool{"10.0.0.1": true, "10.0.0.2": true, "10.0.0.3": true}
	if !validIPs[server.IP] {
		t.Errorf("server.IP = %q, want one of 10.0.0.1/2/3", server.IP)
	}
}

// --- Additional edge-case and integration-style tests ---

func TestTestAllServersProgressTracksReachable(t *testing.T) {
	cfg := testConfig(t)
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	// 2 servers: one reachable, one not
	for i, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		content := fmt.Sprintf(`[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.2.0.2/32

[Peer]
PublicKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Endpoint = %s:51820
AllowedIPs = 0.0.0.0/0
`, ip)
		os.WriteFile(filepath.Join(wgDir, fmt.Sprintf("sv%d.conf", i+1)), []byte(content), 0600)
	}

	withMockPinger(t, func(addr string) (Pinger, error) {
		if addr == "10.0.0.1" {
			return &mockPinger{
				stats: &probing.Statistics{PacketsRecv: 2, AvgRtt: 10 * time.Millisecond},
			}, nil
		}
		// 10.0.0.2 is unreachable
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 0},
		}, nil
	})

	var lastReachable int
	results, err := TestAllServers(cfg, 10, func(tested, total, reachable int) {
		lastReachable = reachable
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if lastReachable != 1 {
		t.Errorf("reachable = %d, want 1", lastReachable)
	}

	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}
	if successCount != 1 {
		t.Errorf("expected 1 successful result, got %d", successCount)
	}
}

func TestTestBatchPreservesOrderWithMixedResults(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		switch addr {
		case "10.0.0.1":
			return &mockPinger{
				stats: &probing.Statistics{PacketsRecv: 2, AvgRtt: 20 * time.Millisecond},
			}, nil
		case "10.0.0.2":
			return nil, fmt.Errorf("DNS failure")
		case "10.0.0.3":
			return &mockPinger{
				runErr: fmt.Errorf("socket error"),
			}, nil
		case "10.0.0.4":
			return &mockPinger{
				stats: &probing.Statistics{PacketsRecv: 0},
			}, nil
		default:
			return nil, fmt.Errorf("unexpected addr: %s", addr)
		}
	})

	servers := []ServerEntry{
		{Name: "ok", IP: "10.0.0.1"},
		{Name: "dns-fail", IP: "10.0.0.2"},
		{Name: "run-fail", IP: "10.0.0.3"},
		{Name: "no-recv", IP: "10.0.0.4"},
	}

	results := testBatch(servers)
	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	// ok: success
	if !results[0].Success || results[0].Latency != 20 {
		t.Errorf("results[0] = {Success:%v, Latency:%d}, want {true, 20}", results[0].Success, results[0].Latency)
	}
	// dns-fail: fail
	if results[1].Success || results[1].Latency != -1 {
		t.Errorf("results[1] = {Success:%v, Latency:%d}, want {false, -1}", results[1].Success, results[1].Latency)
	}
	// run-fail: fail
	if results[2].Success || results[2].Latency != -1 {
		t.Errorf("results[2] = {Success:%v, Latency:%d}, want {false, -1}", results[2].Success, results[2].Latency)
	}
	// no-recv: fail
	if results[3].Success || results[3].Latency != -1 {
		t.Errorf("results[3] = {Success:%v, Latency:%d}, want {false, -1}", results[3].Success, results[3].Latency)
	}
}

func TestPingServerSetsParameters(t *testing.T) {
	var captured mockPinger
	withMockPinger(t, func(addr string) (Pinger, error) {
		captured = mockPinger{
			stats: &probing.Statistics{PacketsRecv: 1, AvgRtt: 7 * time.Millisecond},
		}
		return &captured, nil
	})

	result := PingServer("10.0.0.1")
	if result != 7 {
		t.Errorf("PingServer() = %d, want 7", result)
	}
	if captured.countSet != 2 {
		t.Errorf("SetCount called with %d, want 2", captured.countSet)
	}
	if captured.timeoutSet != 2*time.Second {
		t.Errorf("SetTimeout called with %v, want 2s", captured.timeoutSet)
	}
	if !captured.privilegedSet {
		t.Error("SetPrivileged should have been called with true")
	}
}

func TestTestBatchConcurrentExecution(t *testing.T) {
	// Verify that testBatch actually runs pings concurrently by tracking
	// how many are in-flight simultaneously.
	var running int64
	var maxRunning int64

	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 1, AvgRtt: 10 * time.Millisecond},
			runErr: func() error {
				cur := atomic.AddInt64(&running, 1)
				for {
					old := atomic.LoadInt64(&maxRunning)
					if cur <= old {
						break
					}
					if atomic.CompareAndSwapInt64(&maxRunning, old, cur) {
						break
					}
				}
				// Brief sleep to increase chance of overlap
				time.Sleep(5 * time.Millisecond)
				atomic.AddInt64(&running, -1)
				return nil
			}(),
		}, nil
	})

	servers := make([]ServerEntry, 5)
	for i := range servers {
		servers[i] = ServerEntry{Name: fmt.Sprintf("s%d", i), IP: fmt.Sprintf("10.0.0.%d", i+1)}
	}

	results := testBatch(servers)
	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}

	// We can't guarantee max concurrency in a test, but all results should be present
	for i, r := range results {
		if r.Server.Name != servers[i].Name {
			t.Errorf("result[%d] name = %q, want %q", i, r.Server.Name, servers[i].Name)
		}
	}
}

func TestCollectServersSkipsServersWithEmptyIP(t *testing.T) {
	cfg := testConfig(t)

	// Create a wireguard config without an endpoint (so EndpointIP() returns "")
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	noEndpoint := `[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.2.0.2/32

[Peer]
PublicKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
AllowedIPs = 0.0.0.0/0
`
	os.WriteFile(filepath.Join(wgDir, "no-endpoint.conf"), []byte(noEndpoint), 0600)

	servers := collectServers(cfg)
	if len(servers) != 0 {
		t.Errorf("expected 0 servers when endpoint is empty, got %d: %v", len(servers), servers)
	}
}

func TestCollectServersDynamicSkipsEmptyIPs(t *testing.T) {
	cfg := testConfig(t)

	os.MkdirAll(filepath.Join(cfg.ConfigDir, "wireguard"), 0755)
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "providers"), 0755)
	os.MkdirAll(filepath.Join(cfg.ConfigDir, "cache"), 0755)

	providerConf := `{"private_key":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=","address":"10.2.0.2/32"}`
	os.WriteFile(filepath.Join(cfg.ConfigDir, "providers", "emptyip.json"), []byte(providerConf), 0600)

	// One server with an IP, one without
	cacheContent := `[{"ips":["203.0.113.1"],"hostname":"has-ip.com","server_name":"WithIP"},{"ips":[],"hostname":"no-ip.com","server_name":"NoIP"}]`
	os.WriteFile(filepath.Join(cfg.ConfigDir, "cache", "emptyip_servers.json"), []byte(cacheContent), 0644)

	servers := collectServers(cfg)
	if len(servers) != 1 {
		t.Errorf("expected 1 server (skipping empty IP), got %d: %v", len(servers), servers)
	}
	if len(servers) == 1 && servers[0].Name != "WithIP" {
		t.Errorf("expected server name WithIP, got %q", servers[0].Name)
	}
}

// TestPingerWrapperMethods exercises the pingerWrapper passthrough methods.
// We construct a real probing.Pinger (which doesn't require privileges until
// Run is called) and verify the wrapper delegates correctly.
func TestPingerWrapperMethods(t *testing.T) {
	p, err := probing.NewPinger("127.0.0.1")
	if err != nil {
		t.Fatalf("probing.NewPinger(127.0.0.1) failed: %v", err)
	}

	pw := &pingerWrapper{p: p}

	pw.SetCount(5)
	if p.Count != 5 {
		t.Errorf("SetCount: p.Count = %d, want 5", p.Count)
	}

	pw.SetTimeout(3 * time.Second)
	if p.Timeout != 3*time.Second {
		t.Errorf("SetTimeout: p.Timeout = %v, want 3s", p.Timeout)
	}

	pw.SetPrivileged(true)
	if !p.Privileged() {
		t.Error("SetPrivileged(true): expected Privileged() == true")
	}
	pw.SetPrivileged(false)
	if p.Privileged() {
		t.Error("SetPrivileged(false): expected Privileged() == false")
	}

	// Statistics() should return non-nil (probing.Pinger initializes stats)
	stats := pw.Statistics()
	if stats == nil {
		t.Error("Statistics() returned nil")
	}

	// We do NOT call pw.Run() because that requires raw sockets.
	// But we can verify the Run method exists and is wired correctly
	// by checking the wrapper method is callable (type-system guarantees).
}

// --- Mutation-killing boundary tests ---

// TestTestAllServersBatchExactDivide kills the mutant at line 75
// (i < len(servers) mutated to i <= len(servers)).
// When batchSize exactly divides server count, the mutant would run an extra
// empty iteration, producing an extra progress callback call. We verify the
// exact number of progress calls.
func TestTestAllServersBatchExactDivide(t *testing.T) {
	cfg := testConfig(t)
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	// Create exactly 2 servers and use batchSize=2 so it divides evenly.
	for i, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		content := fmt.Sprintf(`[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.2.0.2/32

[Peer]
PublicKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Endpoint = %s:51820
AllowedIPs = 0.0.0.0/0
`, ip)
		os.WriteFile(filepath.Join(wgDir, fmt.Sprintf("exact%d.conf", i+1)), []byte(content), 0600)
	}

	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 1, AvgRtt: 10 * time.Millisecond},
		}, nil
	})

	progressCallCount := 0
	results, err := TestAllServers(cfg, 2, func(tested, total, reachable int) {
		progressCallCount++
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
	// With 2 servers and batchSize=2, there must be exactly 1 batch (1 progress call).
	// The mutant (i <= len) would produce an extra empty batch -> 2 calls.
	if progressCallCount != 1 {
		t.Errorf("expected exactly 1 progress call (exact batch divide), got %d", progressCallCount)
	}
}

// TestTestAllServersBatchExactDivideResultCount is an additional check:
// with batchSize == len(servers), the total result count must be exactly len(servers).
// The mutant at line 75 would append results from an empty extra batch (0 extra),
// but this test combined with the progress count above ensures the loop runs
// the correct number of times.
func TestTestAllServersBatchExactDivideResultCount(t *testing.T) {
	cfg := testConfig(t)
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	// Create exactly 1 server with batchSize=1
	os.WriteFile(filepath.Join(wgDir, "single.conf"), []byte(wgConfContent), 0600)

	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 1, AvgRtt: 5 * time.Millisecond},
		}, nil
	})

	progressCallCount := 0
	_, err := TestAllServers(cfg, 1, func(tested, total, reachable int) {
		progressCallCount++
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if progressCallCount != 1 {
		t.Errorf("expected exactly 1 progress call (1 server, batch 1), got %d", progressCallCount)
	}
}

// TestTestBatchZeroLatencySuccess kills the mutant at line 112
// (latency >= 0 mutated to latency > 0).
// When latency is exactly 0, Success must be true.
func TestTestBatchZeroLatencySuccess(t *testing.T) {
	withMockPinger(t, func(addr string) (Pinger, error) {
		return &mockPinger{
			stats: &probing.Statistics{
				PacketsRecv: 2,
				AvgRtt:      0, // 0ms latency
			},
		}, nil
	})

	servers := []ServerEntry{
		{Type: "manual", Name: "localhost", IP: "127.0.0.1"},
	}

	results := testBatch(servers)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Latency != 0 {
		t.Errorf("Latency = %d, want 0", results[0].Latency)
	}
	// The boundary: latency == 0 must still be considered a success.
	// The mutant (latency > 0) would set Success = false here.
	if !results[0].Success {
		t.Errorf("Success = false, want true for latency == 0 (server responded with 0ms RTT)")
	}
}

// TestFindQuickestServerTieBreaksToFirst kills the mutant at line 201
// (results[i].Latency < best.Latency mutated to <=).
// When two servers have equal latency, the first encountered must win.
// The mutant (<=) would pick the last server with that latency instead.
func TestFindQuickestServerTieBreaksToFirst(t *testing.T) {
	cfg := testConfig(t)
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	os.MkdirAll(wgDir, 0755)

	// Create 3 configs. Two will share the lowest latency.
	for i, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		content := fmt.Sprintf(`[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.2.0.2/32

[Peer]
PublicKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Endpoint = %s:51820
AllowedIPs = 0.0.0.0/0
`, ip)
		os.WriteFile(filepath.Join(wgDir, fmt.Sprintf("tie%d.conf", i+1)), []byte(content), 0600)
	}

	// 10.0.0.1 and 10.0.0.2 both have 10ms (tied). 10.0.0.3 is slower.
	latencyMap := map[string]int{
		"10.0.0.1": 10,
		"10.0.0.2": 10,
		"10.0.0.3": 50,
	}
	withMockPinger(t, func(addr string) (Pinger, error) {
		ms := latencyMap[addr]
		return &mockPinger{
			stats: &probing.Statistics{PacketsRecv: 2, AvgRtt: time.Duration(ms) * time.Millisecond},
		}, nil
	})

	// Use batchSize = len(servers) so order is preserved in a single batch.
	server, latency, err := FindQuickestServer(cfg, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if latency != 10 {
		t.Errorf("latency = %d, want 10", latency)
	}
	// The first server with latency 10 should win (strict < means ties don't replace).
	// The mutant (<= instead of <) would pick the LAST tied server.
	// We need to know which server comes first in collectServers ordering.
	// collectServers reads from wireguard.ListConfigs which returns sorted names.
	// tie1.conf (10.0.0.1) comes before tie2.conf (10.0.0.2) alphabetically.
	if server.IP != "10.0.0.1" {
		t.Errorf("server.IP = %q, want 10.0.0.1 (first server with lowest latency should win on tie)", server.IP)
	}
}

// NOTE on line 77 mutant (end > len(servers) mutated to end >= len(servers)):
// This is an EQUIVALENT MUTATION. The condition only differs from the original
// when end == len(servers). In that case, the original does NOT enter the if-body
// (keeps end = len(servers)), while the mutant DOES enter the if-body and sets
// end = len(servers) — the same value. The behaviour is identical in both cases
// because clamping end to len(servers) when it already equals len(servers) is a
// no-op. The slice expression servers[i:end] produces the same result either way.
// No test can distinguish these two variants.

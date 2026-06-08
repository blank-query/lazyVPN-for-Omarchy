package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// saveAndRestore captures the current value of a package-level variable and
// returns a function that restores it. Usage:
//
//	t.Cleanup(saveAndRestore(&someVar, newValue))
func saveAndRestoreURL(ptr *string, val string) func() {
	old := *ptr
	*ptr = val
	return func() { *ptr = old }
}

// mockAllIPURLs points all three IP lookup services at the given URL so
// fallback services don't hit real endpoints during tests.
func mockAllIPURLs(t *testing.T, url string) {
	t.Helper()
	t.Cleanup(saveAndRestoreURL(&ipInfoURL, url))
	t.Cleanup(saveAndRestoreURL(&ifconfigURL, url))
	t.Cleanup(saveAndRestoreURL(&ipAPIURL, url))
}

// mockNetInterfaces replaces netInterfaces and returns a cleanup func.
func mockNetInterfaces(fn func() ([]net.Interface, error)) func() {
	old := netInterfaces
	netInterfaces = fn
	return func() { netInterfaces = old }
}

// mockWebrtcDialFunc replaces webrtcDialFunc and returns a cleanup func.
func mockWebrtcDialFunc(fn func(*net.Dialer, string, string) (net.Conn, error)) func() {
	old := webrtcDialFunc
	webrtcDialFunc = fn
	return func() { webrtcDialFunc = old }
}

// mockIPv6DialFunc replaces ipv6DialFunc and returns a cleanup func.
func mockIPv6DialFunc(fn func(context.Context, string, string, time.Duration) (net.Conn, error)) func() {
	old := ipv6DialFunc
	ipv6DialFunc = fn
	return func() { ipv6DialFunc = old }
}

// mockResolvectlOutput replaces resolvectlOutput and returns a cleanup func.
func mockResolvectlOutput(fn func(context.Context) ([]byte, error)) func() {
	old := resolvectlOutput
	resolvectlOutput = fn
	return func() { resolvectlOutput = old }
}

// mockResolvectlStatusOutput replaces resolvectlStatusOutput and returns a cleanup func.
func mockResolvectlStatusOutput(fn func(context.Context) ([]byte, error)) func() {
	old := resolvectlStatusOutput
	resolvectlStatusOutput = fn
	return func() { resolvectlStatusOutput = old }
}

// mockReadResolvConf replaces readResolvConf and returns a cleanup func.
func mockReadResolvConf(fn func() ([]byte, error)) func() {
	old := readResolvConf
	readResolvConf = fn
	return func() { readResolvConf = old }
}

// mockLookupTXT replaces lookupTXTFunc and returns a cleanup func.
func mockLookupTXT(fn func(string) ([]string, error)) func() {
	old := lookupTXTFunc
	lookupTXTFunc = fn
	return func() { lookupTXTFunc = old }
}

// mockLookupAddr replaces lookupAddrFunc and returns a cleanup func.
func mockLookupAddr(fn func(string) ([]string, error)) func() {
	old := lookupAddrFunc
	lookupAddrFunc = fn
	return func() { lookupAddrFunc = old }
}

// mockDNSLookupHost replaces dnsLookupHost and returns a cleanup func.
func mockDNSLookupHost(fn func(context.Context, string) ([]string, error)) func() {
	old := dnsLookupHost
	dnsLookupHost = fn
	return func() { dnsLookupHost = old }
}

// ---------------------------------------------------------------------------
// Pure function tests (no mocking needed)
// ---------------------------------------------------------------------------

func TestIsVirtualInterface(t *testing.T) {
	tests := []struct {
		name   string
		iface  string
		expect bool
	}{
		{"docker0", "docker0", true},
		{"docker bridge", "docker_gwbridge", true},
		{"veth pair", "veth1234abc", true},
		{"br- bridge", "br-abc123", true},
		{"virbr", "virbr0", true},
		{"lxc", "lxc-bridge", true},
		{"lxd", "lxd0", true},
		{"cni", "cni0", true},
		{"flannel", "flannel.1", true},
		{"calico", "cali1234", true},
		{"podman", "podman0", true},
		{"eth0 physical", "eth0", false},
		{"wlan0", "wlan0", false},
		{"enp0s3", "enp0s3", false},
		{"wg0 vpn", "wg0", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isVirtualInterface(tt.iface)
			if got != tt.expect {
				t.Errorf("isVirtualInterface(%q) = %v, want %v", tt.iface, got, tt.expect)
			}
		})
	}
}

func TestBaselineComparison(t *testing.T) {
	tests := []struct {
		name        string
		baselineIP  string
		baselineOrg string
		currentIP   string
		currentOrg  string
		wantSafe    bool
	}{
		{"no baseline", "", "", "1.2.3.4", "Some ISP", true},
		{"same IP = leak", "1.2.3.4", "Comcast", "1.2.3.4", "Comcast", false},
		{"different IP = safe", "1.2.3.4", "Comcast", "10.0.0.1", "VPN Corp", true},
		{"same org different IP = leak", "1.2.3.4", "Comcast", "5.6.7.8", "Comcast", false},
		{"different org same IP = leak", "1.2.3.4", "Comcast", "1.2.3.4", "VPN Corp", false},
		{"different both = safe", "1.2.3.4", "Comcast", "10.0.0.1", "Mullvad", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the logic directly (mirrors checkPublicIP logic)
			var isSafe bool
			if tt.baselineIP != "" {
				isSafe = tt.currentIP != tt.baselineIP && !strings.EqualFold(tt.currentOrg, tt.baselineOrg)
			} else {
				isSafe = true
			}
			if isSafe != tt.wantSafe {
				t.Errorf("baseline(%q,%q) vs current(%q,%q): safe=%v, want %v",
					tt.baselineIP, tt.baselineOrg, tt.currentIP, tt.currentOrg, isSafe, tt.wantSafe)
			}
		})
	}
}

func TestBaselineDNSComparison(t *testing.T) {
	tests := []struct {
		name        string
		baselineDNS []string
		resolverIP  string
		wantSafe    bool
	}{
		{"no baseline", nil, "8.8.8.8", true},
		{"empty baseline", []string{}, "8.8.8.8", true},
		{"matches baseline = leak", []string{"8.8.8.8", "1.1.1.1"}, "8.8.8.8", false},
		{"no match = safe", []string{"8.8.8.8", "1.1.1.1"}, "10.2.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lt := &LeakTest{BaselineDNS: tt.baselineDNS}
			isISP := lt.isBaselineDNS(tt.resolverIP)
			isSafe := !isISP
			if len(tt.baselineDNS) == 0 {
				isSafe = true
			}
			if isSafe != tt.wantSafe {
				t.Errorf("baselineDNS=%v, resolver=%q: safe=%v, want %v",
					tt.baselineDNS, tt.resolverIP, isSafe, tt.wantSafe)
			}
		})
	}
}

func TestNewLeakTest(t *testing.T) {
	lt := NewLeakTest(DefaultDNSProviders, "", "", nil)
	if lt.ID == "" {
		t.Error("ID should not be empty")
	}
	if lt.Error != nil {
		t.Error("Error should be nil")
	}
	if lt.Stage != "" {
		t.Error("Stage should be empty")
	}

	// IDs should be numeric strings (from math/rand.Int63)
	for _, c := range lt.ID {
		if c < '0' || c > '9' {
			t.Errorf("ID contains non-digit character %q in %q", string(c), lt.ID)
			break
		}
	}
}

func TestNewLeakTestUniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		lt := NewLeakTest(DefaultDNSProviders, "", "", nil)
		if ids[lt.ID] {
			t.Errorf("duplicate ID generated: %s", lt.ID)
		}
		ids[lt.ID] = true
	}
}

func TestHasLeaks(t *testing.T) {
	t.Run("no leaks", func(t *testing.T) {
		lt := &LeakTest{
			IPResult:     &LeakTestResult{IsSafe: true},
			WebRTCResult: &WebRTCLeakResult{IsSafe: true},
			IPv6Result:   &IPv6LeakResult{IsSafe: true},
			DNSResults:   []LeakTestResult{{IsSafe: true}},
		}
		if lt.HasLeaks() {
			t.Error("should not have leaks")
		}
	})

	t.Run("IP leak", func(t *testing.T) {
		lt := &LeakTest{
			IPResult: &LeakTestResult{IsSafe: false},
		}
		if !lt.HasLeaks() {
			t.Error("should detect IP leak")
		}
	})

	t.Run("DNS leak", func(t *testing.T) {
		lt := &LeakTest{
			DNSResults: []LeakTestResult{{IsSafe: false}},
		}
		if !lt.HasLeaks() {
			t.Error("should detect DNS leak")
		}
	})

	t.Run("DNS leak mixed results", func(t *testing.T) {
		lt := &LeakTest{
			DNSResults: []LeakTestResult{
				{IsSafe: true, Provider: "Mullvad DNS"},
				{IsSafe: false, Provider: "Google DNS"},
			},
		}
		if !lt.HasLeaks() {
			t.Error("should detect DNS leak when any result is unsafe")
		}
	})

	t.Run("WebRTC leak", func(t *testing.T) {
		lt := &LeakTest{
			WebRTCResult: &WebRTCLeakResult{IsSafe: false},
		}
		if !lt.HasLeaks() {
			t.Error("should detect WebRTC leak")
		}
	})

	t.Run("IPv6 leak", func(t *testing.T) {
		lt := &LeakTest{
			IPv6Result: &IPv6LeakResult{IsSafe: false},
		}
		if !lt.HasLeaks() {
			t.Error("should detect IPv6 leak")
		}
	})

	t.Run("nil results no leak", func(t *testing.T) {
		lt := &LeakTest{}
		if lt.HasLeaks() {
			t.Error("nil results should not report leaks")
		}
	})

	t.Run("multiple leaks", func(t *testing.T) {
		lt := &LeakTest{
			IPResult:     &LeakTestResult{IsSafe: false},
			DNSResults:   []LeakTestResult{{IsSafe: false}},
			WebRTCResult: &WebRTCLeakResult{IsSafe: false},
			IPv6Result:   &IPv6LeakResult{IsSafe: false},
		}
		if !lt.HasLeaks() {
			t.Error("should detect multiple leaks")
		}
	})
}

func TestSummary(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		lt := &LeakTest{Error: fmt.Errorf("test error")}
		if lt.Summary() != "Error: test error" {
			t.Errorf("got %q", lt.Summary())
		}
	})

	t.Run("no leaks", func(t *testing.T) {
		lt := &LeakTest{}
		if lt.Summary() != "No leaks detected" {
			t.Errorf("got %q", lt.Summary())
		}
	})

	t.Run("has leaks", func(t *testing.T) {
		lt := &LeakTest{
			IPResult: &LeakTestResult{IsSafe: false},
		}
		if lt.Summary() != "WARNING: Leaks detected!" {
			t.Errorf("got %q", lt.Summary())
		}
	})

	t.Run("error takes priority over leaks", func(t *testing.T) {
		lt := &LeakTest{
			Error:    fmt.Errorf("connection failed"),
			IPResult: &LeakTestResult{IsSafe: false},
		}
		got := lt.Summary()
		if !strings.HasPrefix(got, "Error:") {
			t.Errorf("error should take priority, got %q", got)
		}
	})
}

func TestKillswitchTestResult(t *testing.T) {
	result := &KillswitchTestResult{
		Attempts:  10,
		Successes: 0,
		IsSafe:    true,
		Message:   "test",
	}
	if !result.IsSafe {
		t.Error("should be safe")
	}
	if result.Successes != 0 {
		t.Errorf("Successes = %d, want 0", result.Successes)
	}
}

func TestMTUTestResult(t *testing.T) {
	result := &MTUTestResult{
		CurrentMTU: 1420,
		OptimalMTU: 1420,
		NeedsFix:   false,
	}
	if result.NeedsFix {
		t.Error("should not need fix")
	}

	result2 := &MTUTestResult{
		CurrentMTU: 1500,
		OptimalMTU: 1420,
		NeedsFix:   true,
	}
	if !result2.NeedsFix {
		t.Error("should need fix")
	}
}

// ---------------------------------------------------------------------------
// checkPublicIP tests (HTTP mock via httptest)
// ---------------------------------------------------------------------------

func TestCheckPublicIP_DiffersFromBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"ip":      "185.159.157.42",
			"org":     "Mullvad VPN AB",
			"country": "SE",
		})
	}))
	defer srv.Close()

	t.Cleanup(saveAndRestoreURL(&ipInfoURL, srv.URL))

	lt := &LeakTest{
		ID:          "test123",
		BaselineIP:  "203.0.113.5",
		BaselineOrg: "Comcast Cable Communications",
	}
	lt.checkPublicIP()

	if lt.Error != nil {
		t.Fatalf("unexpected error: %v", lt.Error)
	}
	if lt.IPResult == nil {
		t.Fatal("IPResult should not be nil")
	}
	if lt.IPResult.IP != "185.159.157.42" {
		t.Errorf("IP = %q, want %q", lt.IPResult.IP, "185.159.157.42")
	}
	if lt.IPResult.Provider != "Mullvad VPN AB" {
		t.Errorf("Provider = %q, want %q", lt.IPResult.Provider, "Mullvad VPN AB")
	}
	if lt.IPResult.Country != "SE" {
		t.Errorf("Country = %q, want %q", lt.IPResult.Country, "SE")
	}
	if !lt.IPResult.IsSafe {
		t.Error("IsSafe should be true when IP differs from baseline")
	}
}

func TestCheckPublicIP_MatchesBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"ip":      "203.0.113.5",
			"org":     "Comcast Cable Communications",
			"country": "US",
		})
	}))
	defer srv.Close()

	t.Cleanup(saveAndRestoreURL(&ipInfoURL, srv.URL))

	lt := &LeakTest{
		ID:          "test123",
		BaselineIP:  "203.0.113.5",
		BaselineOrg: "Comcast Cable Communications",
	}
	lt.checkPublicIP()

	if lt.Error != nil {
		t.Fatalf("unexpected error: %v", lt.Error)
	}
	if lt.IPResult == nil {
		t.Fatal("IPResult should not be nil")
	}
	if lt.IPResult.IsSafe {
		t.Error("IsSafe should be false when IP matches baseline (leak)")
	}
}

func TestCheckPublicIP_NoBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"ip":      "203.0.113.5",
			"org":     "Comcast Cable Communications",
			"country": "US",
		})
	}))
	defer srv.Close()

	t.Cleanup(saveAndRestoreURL(&ipInfoURL, srv.URL))

	lt := &LeakTest{ID: "test123"} // no baseline set
	lt.checkPublicIP()

	if lt.Error != nil {
		t.Fatalf("unexpected error: %v", lt.Error)
	}
	if lt.IPResult == nil {
		t.Fatal("IPResult should not be nil")
	}
	if !lt.IPResult.IsSafe {
		t.Error("IsSafe should be true when no baseline is set (graceful degradation)")
	}
}

func TestCheckPublicIP_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	// Close the server immediately to force a connection error
	srv.Close()

	mockAllIPURLs(t, srv.URL)

	lt := &LeakTest{ID: "test123"}
	lt.checkPublicIP()

	if lt.Error == nil {
		t.Fatal("expected an error for closed server")
	}
	if !strings.Contains(lt.Error.Error(), "all IP lookup services failed") {
		t.Errorf("error should mention all services failed: %v", lt.Error)
	}
}

func TestCheckPublicIP_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not json"))
	}))
	defer srv.Close()

	mockAllIPURLs(t, srv.URL)

	lt := &LeakTest{ID: "test123"}
	lt.checkPublicIP()

	if lt.Error == nil {
		t.Fatal("expected an error for invalid JSON")
	}
	if !strings.Contains(lt.Error.Error(), "all IP lookup services failed") {
		t.Errorf("error should mention all services failed: %v", lt.Error)
	}
}

func TestCheckPublicIP_EmptyJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{}"))
	}))
	defer srv.Close()

	mockAllIPURLs(t, srv.URL)

	lt := &LeakTest{ID: "test123"}
	lt.checkPublicIP()

	// All parsers reject empty IP, so all services fail
	if lt.Error == nil {
		t.Fatal("expected an error for empty JSON (no IP in response)")
	}
}

func TestCheckPublicIP_HTTPStatus500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	mockAllIPURLs(t, srv.URL)

	lt := &LeakTest{ID: "test123"}
	lt.checkPublicIP()

	// All services return non-JSON bodies, so all parsers fail
	if lt.Error == nil {
		t.Fatal("expected an error for 500 response with non-JSON body")
	}
}

// TestCheckPublicIP_CancelsLosersOnFirstSuccess proves the parent-context
// fix: when one service responds quickly, the in-flight requests to the
// other services must observe their context being canceled rather than
// running to their own 10s timeout. Pre-fix, two 10s requests would leak
// past the function's return.
func TestCheckPublicIP_CancelsLosersOnFirstSuccess(t *testing.T) {
	var slowSawCancel atomic.Int32
	var slowCount atomic.Int32

	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"ip":      "203.0.113.99",
			"org":     "VPN Provider",
			"country": "US",
		})
	}))
	defer fast.Close()

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slowCount.Add(1)
		select {
		case <-r.Context().Done():
			slowSawCancel.Add(1)
		case <-time.After(2 * time.Second):
			// Loser request ran to its own timeout — cancel did not propagate.
		}
	}))
	defer slow.Close()

	t.Cleanup(saveAndRestoreURL(&ipInfoURL, fast.URL))
	t.Cleanup(saveAndRestoreURL(&ifconfigURL, slow.URL))
	t.Cleanup(saveAndRestoreURL(&ipAPIURL, slow.URL))

	lt := &LeakTest{ID: "test123"}

	start := time.Now()
	lt.checkPublicIP()
	elapsed := time.Since(start)

	if elapsed > 1500*time.Millisecond {
		t.Errorf("checkPublicIP took %v, expected < 1.5s (slow services should be canceled, not awaited)", elapsed)
	}

	// Wait briefly for the in-flight slow handlers to observe the cancel.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && slowSawCancel.Load() < slowCount.Load() {
		time.Sleep(10 * time.Millisecond)
	}

	got := slowSawCancel.Load()
	want := slowCount.Load()
	if want == 0 {
		t.Skip("slow handlers never started — race-dependent setup, can't validate cancel propagation")
	}
	if got != want {
		t.Errorf("slow handlers saw cancel %d/%d times; expected all of them — fetch goroutines are leaking past the function return", got, want)
	}
}

// ---------------------------------------------------------------------------
// testDNS tests
// ---------------------------------------------------------------------------

func TestTestDNS_ReflectionNotInBaseline(t *testing.T) {
	// lookupTXT returns a DNS resolver IP not in baseline
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return []string{"10.2.0.1"}, nil
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return []string{"dns1.protonvpn.ch."}, nil
	}))
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))

	lt := &LeakTest{
		ID:          "test123",
		BaselineDNS: []string{"8.8.8.8"}, // ISP DNS (not 10.2.0.1)
	}
	lt.testDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected at least one DNS result")
	}

	var found bool
	for _, r := range lt.DNSResults {
		if r.IP == "10.2.0.1" {
			found = true
			if !r.IsSafe {
				t.Error("should be safe — resolver not in baseline")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected result with IP 10.2.0.1, got %+v", lt.DNSResults)
	}
}

func TestTestDNS_ReflectionReturnsDNSLeak(t *testing.T) {
	// lookupTXT returns an ISP resolver IP (Google DNS)
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return []string{"8.8.8.8"}, nil
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return []string{"dns.google."}, nil
	}))
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))

	lt := &LeakTest{ID: "test456", BaselineDNS: []string{"8.8.8.8"}}
	lt.testDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results")
	}

	// Find the reflection result — 8.8.8.8 matches baseline, so it's a leak
	for _, r := range lt.DNSResults {
		if r.IP == "8.8.8.8" {
			if r.IsSafe {
				t.Error("Google DNS matching baseline should not be safe (DNS leak)")
			}
			return
		}
	}
	t.Error("expected result with IP 8.8.8.8")
}

func TestTestDNS_ReflectionReturnsMultipleResults(t *testing.T) {
	// Each reflection domain returns a different IP
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		if domain == "whoami.v4.powerdns.org" {
			return []string{"10.2.0.1"}, nil
		}
		return []string{"10.64.0.1"}, nil
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		if addr == "10.2.0.1" {
			return []string{"dns1.protonvpn.ch."}, nil
		}
		return []string{"dns.mullvad.net."}, nil
	}))
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))

	lt := &LeakTest{ID: "test789", Providers: DefaultDNSProviders}
	lt.testDNS()

	// Should have 2 reflection results (one per domain) plus any local results
	reflectionCount := 0
	for _, r := range lt.DNSResults {
		if r.IP == "10.2.0.1" || r.IP == "10.64.0.1" {
			reflectionCount++
		}
	}
	if reflectionCount != 2 {
		t.Fatalf("expected 2 reflection results, got %d (total results: %+v)", reflectionCount, lt.DNSResults)
	}
}

func TestTestDNS_ReflectionFails_FallsBackToLocal(t *testing.T) {
	// All lookupTXT calls fail — should fall back to checkLocalDNS
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return nil, fmt.Errorf("lookup failed")
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return nil, fmt.Errorf("should not be called")
	}))
	// Mock resolvectl status + dns to fail, resolv.conf to have VPN DNS
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("resolvectl not found")
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("resolvectl not found")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return []byte("nameserver 10.2.0.1\n"), nil
	}))

	lt := &LeakTest{ID: "test000"}
	lt.testDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected fallback DNS results")
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("should detect ProtonVPN DNS as safe via fallback")
	}
}

func TestTestDNS_ReflectionError_FallsBackToLocal(t *testing.T) {
	// lookupTXT returns error for all domains
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return nil, fmt.Errorf("DNS resolution failed")
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return nil, fmt.Errorf("should not be called")
	}))
	// Mock checkLocalDNS path
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("resolvectl not found")
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("resolvectl not found")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return []byte("nameserver 10.64.0.1\n"), nil
	}))

	lt := &LeakTest{ID: "testfail"}
	lt.testDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected fallback DNS results after reflection failure")
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("Mullvad DNS should be safe")
	}
}

func TestTestDNS_ReflectionReturnsNonIP_FallsBackToLocal(t *testing.T) {
	// lookupTXT returns text that is not a valid IP
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return []string{"not an ip address"}, nil
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return nil, fmt.Errorf("should not be called")
	}))
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("no resolvectl")
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("no resolvectl")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("no resolv.conf")
	}))

	lt := &LeakTest{ID: "testbadjson"}
	lt.testDNS()

	// Should have the "could not determine" fallback from checkLocalDNS
	if len(lt.DNSResults) == 0 {
		t.Fatal("expected fallback DNS results")
	}
	if lt.DNSResults[0].IsSafe {
		t.Error("should be unsafe when DNS cannot be determined")
	}
}

// ---------------------------------------------------------------------------
// checkLocalDNS tests
// ---------------------------------------------------------------------------

func TestCheckLocalDNS_ResolvectlWithVPNDNS(t *testing.T) {
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return []byte("Link 3 (wg0): 10.2.0.1\nLink 2 (eth0): 8.8.8.8\n"), nil
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("should not be called")
	}))

	// Baseline shows ISP DNS was 8.8.8.8; VPN DNS 10.2.0.1 is NOT ISP → safe
	lt := &LeakTest{ID: "testlocal", BaselineDNS: []string{"8.8.8.8"}}
	lt.checkLocalDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results from resolvectl")
	}
	// First result is 10.2.0.1, which is not in baseline → safe
	if !lt.DNSResults[0].IsSafe {
		t.Error("VPN DNS (not matching baseline) should be safe")
	}
	if lt.DNSResults[0].IP != "10.2.0.1" {
		t.Errorf("expected first DNS to be 10.2.0.1, got %q", lt.DNSResults[0].IP)
	}
}

func TestCheckLocalDNS_ResolvectlFails_ResolvConfWithVPNDNS(t *testing.T) {
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("resolvectl not found")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return []byte("nameserver 10.64.0.1\nnameserver 8.8.8.8\n"), nil
	}))

	lt := &LeakTest{ID: "testrc"}
	lt.checkLocalDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results from resolv.conf")
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("Mullvad DNS should be safe")
	}
}

func TestCheckLocalDNS_StubResolver_DNSBlocked(t *testing.T) {
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("no resolvectl")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return []byte("nameserver 127.0.0.53\n"), nil
	}))
	t.Cleanup(mockDNSLookupHost(func(_ context.Context, _ string) ([]string, error) {
		return nil, fmt.Errorf("lookup failed: no such host")
	}))

	lt := &LeakTest{ID: "teststub"}
	lt.checkLocalDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results for blocked DNS")
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("blocked DNS should be safe (killswitch working)")
	}
	if !strings.Contains(lt.DNSResults[0].Provider, "DNS blocked") {
		t.Errorf("should mention DNS blocked, got %q", lt.DNSResults[0].Provider)
	}
}

func TestCheckLocalDNS_StubResolver_DNSResolves_NoVPN(t *testing.T) {
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("no resolvectl")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		// Has stub resolver but no VPN DNS
		return []byte("nameserver 127.0.0.53\n"), nil
	}))
	t.Cleanup(mockDNSLookupHost(func(_ context.Context, _ string) ([]string, error) {
		// DNS resolution succeeds - means DNS is leaking through
		return []string{"1.1.1.1"}, nil
	}))

	lt := &LeakTest{ID: "teststub2"}
	lt.checkLocalDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results")
	}
	// When stub resolver resolves successfully and no VPN DNS found, it falls through
	// to the "Could not determine" result
	if lt.DNSResults[0].IsSafe {
		t.Error("should be unsafe when DNS is not VPN")
	}
}

func TestCheckLocalDNS_AllFail(t *testing.T) {
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("no resolvectl")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("file not found")
	}))

	lt := &LeakTest{ID: "testall"}
	lt.checkLocalDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected fallback DNS result")
	}
	if lt.DNSResults[0].IsSafe {
		t.Error("should be unsafe when cannot determine DNS")
	}
	if lt.DNSResults[0].IP != "Check manually" {
		t.Errorf("IP = %q, want %q", lt.DNSResults[0].IP, "Check manually")
	}
}

func TestCheckLocalDNS_ResolvectlNoVPN_ResolvConfNoVPN(t *testing.T) {
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		// resolvectl works but has ISP DNS (same as baseline)
		return []byte("Link 2 (eth0): 8.8.8.8\n"), nil
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return []byte("nameserver 8.8.8.8\n"), nil
	}))

	// With baseline set, 8.8.8.8 matches ISP → leak
	lt := &LeakTest{ID: "testnovpn", BaselineDNS: []string{"8.8.8.8"}}
	lt.checkLocalDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results")
	}
	if lt.DNSResults[0].IsSafe {
		t.Error("ISP DNS matching baseline should be unsafe (leak)")
	}
}

// ---------------------------------------------------------------------------
// testWebRTC tests
// ---------------------------------------------------------------------------

func TestTestWebRTC_OnlyLoopback(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{
				Index: 1,
				Name:  "lo",
				Flags: net.FlagLoopback | net.FlagUp,
			},
		}, nil
	}))

	lt := &LeakTest{ID: "testwebrtc", KillswitchActive: true}
	lt.testWebRTC()

	if lt.WebRTCResult == nil {
		t.Fatal("WebRTCResult should not be nil")
	}
	if !lt.WebRTCResult.IsSafe {
		t.Error("should be safe with only loopback")
	}
	if lt.WebRTCResult.Message != "Physical interface access blocked" {
		t.Errorf("unexpected message: %q", lt.WebRTCResult.Message)
	}
}

// TestTestWebRTC_KillswitchOffSkipsProbe verifies that when the killswitch
// is not active, the WebRTC/interface-bind probe is skipped (not reported as
// a leak). Without a firewall to bypass, physical-NIC binding is expected for
// every userspace VPN and flagging it red was pure noise.
func TestTestWebRTC_KillswitchOffSkipsProbe(t *testing.T) {
	// If netInterfaces were called we'd see other results; make sure it isn't.
	called := false
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		called = true
		return nil, nil
	}))

	lt := &LeakTest{ID: "testwebrtc-ks-off", KillswitchActive: false}
	lt.testWebRTC()

	if lt.WebRTCResult == nil {
		t.Fatal("WebRTCResult should not be nil")
	}
	if !lt.WebRTCResult.IsSafe {
		t.Error("should be Safe when killswitch is off (probe premise is moot)")
	}
	if !strings.Contains(lt.WebRTCResult.Message, "killswitch off") {
		t.Errorf("message should mention killswitch off, got %q", lt.WebRTCResult.Message)
	}
	if called {
		t.Error("netInterfaces should not be called when killswitch is off")
	}
}

func TestTestWebRTC_InterfaceError(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return nil, fmt.Errorf("permission denied")
	}))

	lt := &LeakTest{ID: "testwebrtcerr", KillswitchActive: true}
	lt.testWebRTC()

	if lt.WebRTCResult == nil {
		t.Fatal("WebRTCResult should not be nil")
	}
	if !lt.WebRTCResult.IsSafe {
		t.Error("should default to safe on error")
	}
	if lt.WebRTCResult.Message != "Could not enumerate interfaces" {
		t.Errorf("unexpected message: %q", lt.WebRTCResult.Message)
	}
}

func TestTestWebRTC_VPNInterfaceSkipped(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
			{Index: 2, Name: "wg0", Flags: net.FlagUp},
		}, nil
	}))

	lt := &LeakTest{ID: "testskipvpn", KillswitchActive: true}
	lt.testWebRTC()

	if lt.WebRTCResult == nil {
		t.Fatal("WebRTCResult should not be nil")
	}
	if !lt.WebRTCResult.IsSafe {
		t.Error("should be safe when only VPN interfaces exist")
	}
	if len(lt.WebRTCResult.LocalIPs) != 0 {
		t.Errorf("should not have local IPs from VPN interface, got %v", lt.WebRTCResult.LocalIPs)
	}
}

func TestTestWebRTC_CustomVPNInterfaceSkipped(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
			{Index: 2, Name: "my-vpn-tun", Flags: net.FlagUp},
		}, nil
	}))

	lt := &LeakTest{ID: "testcustomvpn", VPNInterface: "my-vpn-tun", KillswitchActive: true}
	lt.testWebRTC()

	if lt.WebRTCResult == nil {
		t.Fatal("WebRTCResult should not be nil")
	}
	if !lt.WebRTCResult.IsSafe {
		t.Error("should be safe when custom VPN interface is skipped")
	}
}

func TestTestWebRTC_VirtualInterfaceSkipped(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
			{Index: 2, Name: "docker0", Flags: net.FlagUp},
			{Index: 3, Name: "br-abc123", Flags: net.FlagUp},
		}, nil
	}))

	lt := &LeakTest{ID: "testvirt", KillswitchActive: true}
	lt.testWebRTC()

	if lt.WebRTCResult == nil {
		t.Fatal("WebRTCResult should not be nil")
	}
	if !lt.WebRTCResult.IsSafe {
		t.Error("should be safe with only virtual interfaces")
	}
}

func TestTestWebRTC_PhysicalInterfaceDialBlocked(t *testing.T) {
	// We need a real interface that exists on the system to get Addrs() to work.
	// Instead, mock both netInterfaces and the dial to avoid needing real interfaces.
	// The issue is that iface.Addrs() is a method on net.Interface that we can't mock.
	// We'll use the real loopback interface but modify it.

	// Get real interfaces and find one with an IPv4 address
	realIfaces, err := net.Interfaces()
	if err != nil {
		t.Skip("cannot get real interfaces")
	}

	// Find the first non-loopback, non-virtual, non-wg interface with a routable IPv4
	var targetIface *net.Interface
	var targetIP net.IP
	for i := range realIfaces {
		iface := &realIfaces[i]
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "wg") {
			continue
		}
		if isVirtualInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP
				if ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
					targetIface = iface
					targetIP = ip
					break
				}
			}
		}
		if targetIface != nil {
			break
		}
	}

	if targetIface == nil {
		t.Skip("no suitable physical interface with IPv4 found")
	}

	// Mock the dial to fail (simulating killswitch blocking)
	t.Cleanup(mockWebrtcDialFunc(func(d *net.Dialer, network, address string) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused (mocked killswitch)")
	}))

	lt := &LeakTest{ID: "testphysblocked", KillswitchActive: true}
	lt.testWebRTC()

	if lt.WebRTCResult == nil {
		t.Fatal("WebRTCResult should not be nil")
	}
	if !lt.WebRTCResult.IsSafe {
		t.Error("should be safe when dial is blocked")
	}
	// Should have detected the physical IP
	found := false
	for _, ip := range lt.WebRTCResult.LocalIPs {
		if ip == targetIP.String() {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to find %s in LocalIPs %v", targetIP, lt.WebRTCResult.LocalIPs)
	}
}

func TestTestWebRTC_PhysicalInterfaceDialSucceeds_Leak(t *testing.T) {
	// Find a real interface with IPv4
	realIfaces, err := net.Interfaces()
	if err != nil {
		t.Skip("cannot get real interfaces")
	}

	var hasPhysicalIPv4 bool
	for _, iface := range realIfaces {
		if iface.Flags&net.FlagLoopback != 0 || strings.HasPrefix(iface.Name, "wg") || isVirtualInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP
				if ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
					hasPhysicalIPv4 = true
					break
				}
			}
		}
		if hasPhysicalIPv4 {
			break
		}
	}

	if !hasPhysicalIPv4 {
		t.Skip("no suitable physical interface with IPv4 found")
	}

	// Mock the dial to succeed (simulating a leak)
	// We create a pair of connected net.Conn via net.Pipe
	t.Cleanup(mockWebrtcDialFunc(func(d *net.Dialer, network, address string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go c2.Close() // close the other end immediately
		return c1, nil
	}))

	lt := &LeakTest{ID: "testphysleak", KillswitchActive: true}
	lt.testWebRTC()

	if lt.WebRTCResult == nil {
		t.Fatal("WebRTCResult should not be nil")
	}
	if lt.WebRTCResult.IsSafe {
		t.Error("should NOT be safe when physical interface can connect (leak)")
	}
	if !lt.WebRTCResult.CanBindPhysical {
		t.Error("CanBindPhysical should be true")
	}
	if !strings.Contains(lt.WebRTCResult.Message, "LEAK") {
		t.Errorf("message should contain LEAK, got %q", lt.WebRTCResult.Message)
	}
}

// ---------------------------------------------------------------------------
// testIPv6 tests
// ---------------------------------------------------------------------------

func TestTestIPv6_NoGlobalIPv6(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
		}, nil
	}))

	lt := &LeakTest{ID: "testipv6none"}
	lt.testIPv6()

	if lt.IPv6Result == nil {
		t.Fatal("IPv6Result should not be nil")
	}
	if !lt.IPv6Result.IsSafe {
		t.Error("should be safe with no global IPv6")
	}
	if !lt.IPv6Result.IPv6Blocked {
		t.Error("IPv6Blocked should be true")
	}
	if lt.IPv6Result.IPv6Available {
		t.Error("IPv6Available should be false (no global IPv6 addresses present)")
	}
	if lt.IPv6Result.Message != "No global IPv6 addresses (safe)" {
		t.Errorf("unexpected message: %q", lt.IPv6Result.Message)
	}
}

func TestTestIPv6_InterfaceError(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return nil, fmt.Errorf("permission denied")
	}))

	lt := &LeakTest{ID: "testipv6err"}
	lt.testIPv6()

	if lt.IPv6Result == nil {
		t.Fatal("IPv6Result should not be nil")
	}
	if !lt.IPv6Result.IsSafe {
		t.Error("should default to safe on error")
	}
	if lt.IPv6Result.Message != "Could not check interfaces" {
		t.Errorf("unexpected message: %q", lt.IPv6Result.Message)
	}
}

// fakeIPv6Interface creates a mock interface list with a global IPv6 address.
// We use real net.Interface + a real loopback so Addrs() can return data.
// But since we mock netInterfaces, we need real interfaces that have addrs.
func TestTestIPv6_HasGlobalIPv6_DialBlocked(t *testing.T) {
	// Check if the real system has global IPv6
	realIfaces, err := net.Interfaces()
	if err != nil {
		t.Skip("cannot list interfaces")
	}

	hasIPv6 := false
	for _, iface := range realIfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP
				if ip.To4() == nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
					hasIPv6 = true
					break
				}
			}
		}
		if hasIPv6 {
			break
		}
	}

	if !hasIPv6 {
		t.Skip("no global IPv6 address on this system")
	}

	// Mock the IPv6 dial to fail (blocked)
	t.Cleanup(mockIPv6DialFunc(func(_ context.Context, _, _ string, _ time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("network unreachable (mocked)")
	}))

	lt := &LeakTest{ID: "testipv6blocked"}
	lt.testIPv6()

	if lt.IPv6Result == nil {
		t.Fatal("IPv6Result should not be nil")
	}
	if !lt.IPv6Result.IsSafe {
		t.Error("should be safe when IPv6 dial is blocked")
	}
	if !lt.IPv6Result.IPv6Blocked {
		t.Error("IPv6Blocked should be true")
	}
	if lt.IPv6Result.Message != "IPv6 properly blocked" {
		t.Errorf("unexpected message: %q", lt.IPv6Result.Message)
	}
}

func TestTestIPv6_HasGlobalIPv6_DialSucceeds_Leak(t *testing.T) {
	// Check if the real system has global IPv6
	realIfaces, err := net.Interfaces()
	if err != nil {
		t.Skip("cannot list interfaces")
	}

	hasIPv6 := false
	for _, iface := range realIfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP
				if ip.To4() == nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
					hasIPv6 = true
					break
				}
			}
		}
		if hasIPv6 {
			break
		}
	}

	if !hasIPv6 {
		t.Skip("no global IPv6 address on this system")
	}

	// Mock the IPv6 dial to succeed (leak)
	t.Cleanup(mockIPv6DialFunc(func(_ context.Context, _, _ string, _ time.Duration) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go c2.Close()
		return c1, nil
	}))

	lt := &LeakTest{ID: "testipv6leak"}
	lt.testIPv6()

	if lt.IPv6Result == nil {
		t.Fatal("IPv6Result should not be nil")
	}
	if lt.IPv6Result.IsSafe {
		t.Error("should NOT be safe when IPv6 connection succeeds (leak)")
	}
	if lt.IPv6Result.IPv6Blocked {
		t.Error("IPv6Blocked should be false when connection succeeds")
	}
	if lt.IPv6Result.Message != "LEAK: IPv6 traffic not blocked" {
		t.Errorf("unexpected message: %q", lt.IPv6Result.Message)
	}
}

func TestTestIPv6_OnlyLinkLocal(t *testing.T) {
	// Use the real interface listing but check that link-local only is safe.
	// We mock netInterfaces to return only interfaces with link-local IPv6.
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		// Return a real non-loopback interface, but we need its Addrs() to
		// only show link-local. Since we can't fake Addrs() on net.Interface,
		// just return the loopback which has no global IPv6.
		return []net.Interface{
			{Index: 1, Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
		}, nil
	}))

	lt := &LeakTest{ID: "testipv6ll"}
	lt.testIPv6()

	if lt.IPv6Result == nil {
		t.Fatal("IPv6Result should not be nil")
	}
	if !lt.IPv6Result.IsSafe {
		t.Error("should be safe with only link-local IPv6")
	}
}

// ---------------------------------------------------------------------------
// Full Run() orchestration test
// ---------------------------------------------------------------------------

func TestRun_FullSuccess_NoLeaks(t *testing.T) {
	// Mock IP info server (VPN provider)
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"ip":      "185.159.157.42",
			"org":     "Mullvad VPN AB",
			"country": "SE",
		})
	}))
	defer ipSrv.Close()

	t.Cleanup(saveAndRestoreURL(&ipInfoURL, ipSrv.URL))

	// Mock DNS reflection (VPN DNS)
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		if domain == "whoami-ecs.v4.powerdns.org" {
			return []string{"ip: 10.64.0.1, netmask: no ECS"}, nil
		}
		return []string{"10.64.0.1"}, nil
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return []string{"dns.mullvad.net."}, nil
	}))
	// Local DNS check runs in parallel -- return VPN DNS so the merged
	// result stays safe (IP matches reflection, so it gets deduped).
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return []byte("Link 3 (wg0)\n    Protocols: +DefaultRoute\nDNS Servers: 10.64.0.1\n"), nil
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return []byte("Link 3 (wg0): 10.64.0.1\n"), nil
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))

	// Mock interfaces to return only loopback (no WebRTC or IPv6 leaks)
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
		}, nil
	}))

	lt := NewLeakTest(DefaultDNSProviders, "", "", nil)
	lt.Run()

	if lt.Error != nil {
		t.Fatalf("unexpected error: %v", lt.Error)
	}
	if lt.Stage != "Complete" {
		t.Errorf("Stage = %q, want %q", lt.Stage, "Complete")
	}
	if lt.HasLeaks() {
		t.Error("should not have leaks")
	}
	if lt.Summary() != "No leaks detected" {
		t.Errorf("Summary = %q", lt.Summary())
	}

	// Verify each component was populated
	if lt.IPResult == nil {
		t.Error("IPResult should be set")
	}
	if len(lt.DNSResults) == 0 {
		t.Error("DNSResults should be set")
	}
	if lt.WebRTCResult == nil {
		t.Error("WebRTCResult should be set")
	}
	if lt.IPv6Result == nil {
		t.Error("IPv6Result should be set")
	}
}

func TestRun_IPCheckFailsContinuesExecution(t *testing.T) {
	// Close server to cause connection error
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ipSrv.Close()

	mockAllIPURLs(t, ipSrv.URL)

	lt := NewLeakTest(DefaultDNSProviders, "", "", nil)
	lt.Run()

	// Error should be cleared (recorded in IPResult instead)
	if lt.Error != nil {
		t.Fatalf("Error should be nil, got %v", lt.Error)
	}
	// IPResult should record the failure
	if lt.IPResult == nil {
		t.Fatal("IPResult should be set even when IP check fails")
	}
	if lt.IPResult.IsSafe {
		t.Error("IPResult should not be safe when IP check fails")
	}
	if lt.IPResult.IP != "Unavailable" {
		t.Errorf("IPResult.IP = %q, want Unavailable", lt.IPResult.IP)
	}
	// Verify subsequent stages WERE executed
	if lt.Stage != "Complete" {
		t.Errorf("Stage should be Complete, got %q", lt.Stage)
	}
	// DNS, WebRTC, IPv6 should all have results
	if lt.WebRTCResult == nil {
		t.Error("WebRTC should have been tested after IP failure")
	}
	if lt.IPv6Result == nil {
		t.Error("IPv6 should have been tested after IP failure")
	}
}

func TestRun_WithLeaks(t *testing.T) {
	// Mock IP info as non-VPN (leak)
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"ip":      "203.0.113.5",
			"org":     "Comcast Cable",
			"country": "US",
		})
	}))
	defer ipSrv.Close()

	t.Cleanup(saveAndRestoreURL(&ipInfoURL, ipSrv.URL))

	// Mock DNS reflection as non-VPN (leak)
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return []string{"8.8.8.8"}, nil
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return []string{"dns.google."}, nil
	}))
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
		}, nil
	}))

	// Baseline matches the mock ISP IP/org/DNS — so the test correctly detects leaks
	lt := NewLeakTest(DefaultDNSProviders, "203.0.113.5", "Comcast Cable", []string{"8.8.8.8"})
	lt.Run()

	if lt.Error != nil {
		t.Fatalf("unexpected error: %v", lt.Error)
	}
	if lt.Stage != "Complete" {
		t.Errorf("Stage = %q, want %q", lt.Stage, "Complete")
	}
	if !lt.HasLeaks() {
		t.Error("should detect leaks")
	}
	if lt.Summary() != "WARNING: Leaks detected!" {
		t.Errorf("Summary = %q", lt.Summary())
	}
}

func TestRun_StageProgression(t *testing.T) {
	// Track stages as Run progresses
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"ip":      "185.0.0.1",
			"org":     "Proton AG",
			"country": "CH",
		})
	}))
	defer ipSrv.Close()

	t.Cleanup(saveAndRestoreURL(&ipInfoURL, ipSrv.URL))

	// Mock DNS reflection (VPN DNS)
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return []string{"10.2.0.1"}, nil
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return []string{"dns1.protonvpn.ch."}, nil
	}))
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
		}, nil
	}))

	lt := NewLeakTest(DefaultDNSProviders, "", "", nil)
	lt.Run()

	// After full run, stage should be "Complete"
	if lt.Stage != "Complete" {
		t.Errorf("final Stage = %q, want %q", lt.Stage, "Complete")
	}
}

// ---------------------------------------------------------------------------
// DNS Provider tests
// ---------------------------------------------------------------------------

func TestNewLeakTestStoresProviders(t *testing.T) {
	providers := []string{"google"}
	lt := NewLeakTest(providers, "", "", nil)
	if len(lt.Providers) != 1 || lt.Providers[0] != "google" {
		t.Errorf("Providers = %v, want [google]", lt.Providers)
	}
}

func TestDNSWithCustomProviders(t *testing.T) {
	// Mock IP endpoint
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"ip": "185.0.0.1", "org": "Proton AG", "country": "CH",
		})
	}))
	defer ipSrv.Close()
	t.Cleanup(saveAndRestoreURL(&ipInfoURL, ipSrv.URL))

	// Track which domains are queried
	var mu sync.Mutex
	queriedDomains := make(map[string]bool)
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		mu.Lock()
		queriedDomains[domain] = true
		mu.Unlock()
		return []string{"10.2.0.1"}, nil
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return nil, fmt.Errorf("no reverse DNS")
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{{Index: 1, Name: "lo", Flags: net.FlagLoopback | net.FlagUp}}, nil
	}))

	// Only select google provider
	lt := NewLeakTest([]string{"google"}, "", "", nil)
	lt.Run()

	if lt.Error != nil {
		t.Fatalf("unexpected error: %v", lt.Error)
	}

	mu.Lock()
	defer mu.Unlock()

	if !queriedDomains["o-o.myaddr.l.google.com"] {
		t.Error("expected google domain to be queried")
	}
	if queriedDomains["whoami.v4.powerdns.org"] {
		t.Error("powerdns should NOT be queried when only google is selected")
	}
}

func TestDNSWithNoProvidersFallback(t *testing.T) {
	// Mock IP endpoint
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"ip": "185.0.0.1", "org": "Proton AG", "country": "CH",
		})
	}))
	defer ipSrv.Close()
	t.Cleanup(saveAndRestoreURL(&ipInfoURL, ipSrv.URL))

	var mu sync.Mutex
	queriedDomains := make(map[string]bool)
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		mu.Lock()
		queriedDomains[domain] = true
		mu.Unlock()
		return []string{"10.2.0.1"}, nil
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return nil, fmt.Errorf("no reverse DNS")
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{{Index: 1, Name: "lo", Flags: net.FlagLoopback | net.FlagUp}}, nil
	}))

	// Empty provider list — should fall back to first registry entry (powerdns)
	lt := NewLeakTest([]string{}, "", "", nil)
	lt.Run()

	if lt.Error != nil {
		t.Fatalf("unexpected error: %v", lt.Error)
	}

	mu.Lock()
	defer mu.Unlock()

	if !queriedDomains["whoami.v4.powerdns.org"] {
		t.Error("expected fallback to powerdns domain")
	}
}

func TestDNSWithInvalidProviderFallback(t *testing.T) {
	// Invalid provider ID should fall back to first registry entry
	lt := NewLeakTest([]string{"nonexistent"}, "", "", nil)
	// Just verify it doesn't panic and has the right Providers field
	if len(lt.Providers) != 1 || lt.Providers[0] != "nonexistent" {
		t.Errorf("Providers = %v", lt.Providers)
	}
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestCheckPublicIP_ProtonVPN(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"ip":      "185.159.157.42",
			"org":     "AS209103 Proton AG",
			"country": "CH",
		})
	}))
	defer srv.Close()

	t.Cleanup(saveAndRestoreURL(&ipInfoURL, srv.URL))

	lt := &LeakTest{ID: "testproton"}
	lt.checkPublicIP()

	if lt.Error != nil {
		t.Fatalf("unexpected error: %v", lt.Error)
	}
	if !lt.IPResult.IsVPN {
		t.Error("AS209103 Proton AG should be detected as VPN")
	}
}

func TestCheckLocalDNS_MultipleDNSInResolvConf(t *testing.T) {
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not found")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		// Multiple nameservers in resolv.conf
		return []byte("nameserver 10.0.0.241\nnameserver 10.0.0.242\n"), nil
	}))

	lt := &LeakTest{ID: "testmulti"}
	lt.checkLocalDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results")
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("DNS not in baseline should be safe")
	}
}

func TestCheckLocalDNS_NordVPN(t *testing.T) {
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return []byte("Link 3 (nordtun): 103.86.96.100\n"), nil
	}))

	// VPN DNS (103.86.96.100) not in baseline → safe
	lt := &LeakTest{ID: "testnord", BaselineDNS: []string{"8.8.8.8"}}
	lt.checkLocalDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results")
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("VPN DNS (not matching ISP baseline) should be safe")
	}
	if lt.DNSResults[0].IP != "103.86.96.100" {
		t.Errorf("expected IP 103.86.96.100, got %q", lt.DNSResults[0].IP)
	}
}

func TestCheckLocalDNS_SurfsharkDNS(t *testing.T) {
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not found")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return []byte("nameserver 162.252.172.57\n"), nil
	}))

	lt := &LeakTest{ID: "testsurf"}
	lt.checkLocalDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results")
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("Surfshark DNS should be safe")
	}
}

func TestCheckLocalDNS_WindscribeDNS(t *testing.T) {
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not found")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return []byte("nameserver 10.255.255.1\n"), nil
	}))

	lt := &LeakTest{ID: "testwind"}
	lt.checkLocalDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results")
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("Windscribe DNS should be safe")
	}
}

func TestCheckLocalDNS_IVPNDNS(t *testing.T) {
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not found")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return []byte("nameserver 172.16.0.1\n"), nil
	}))

	lt := &LeakTest{ID: "testivpn"}
	lt.checkLocalDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results")
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("IVPN DNS should be safe")
	}
}

// ---------------------------------------------------------------------------
// testUDPMTU edge case
// ---------------------------------------------------------------------------

func TestTestUDPMTU_SmallPayload(t *testing.T) {
	// testUDPMTU with a very small payload should succeed (UDP always sends small)
	// We can test this since it just sends a UDP packet - no actual response needed
	result := testUDPMTUReal("127.0.0.1:0", 10)
	// May succeed or fail depending on whether anything listens, but should not panic
	_ = result
}

func TestTestUDPMTU_DialError(t *testing.T) {
	// Use a completely invalid address to trigger the net.DialTimeout error path
	result := testUDPMTUReal("invalid-not-a-host:not-a-port", 100)
	if result {
		t.Error("expected false for invalid address")
	}
}

func TestTestUDPMTU_WriteTooLarge(t *testing.T) {
	// Send a payload that exceeds the maximum UDP datagram size (65535 bytes
	// minus headers). This should trigger the conn.Write error path with
	// "message too long" on Linux.
	result := testUDPMTUReal("127.0.0.1:53", 100000)
	if result {
		t.Error("expected false for oversized payload")
	}
}

// ---------------------------------------------------------------------------
// Additional mock helpers for killswitch/MTU/interface tests
// ---------------------------------------------------------------------------

func mockDialTimeoutFunc(fn func(string, string, time.Duration) (net.Conn, error)) func() {
	old := dialTimeoutFunc
	dialTimeoutFunc = fn
	return func() { dialTimeoutFunc = old }
}

func mockDropInterfaceFunc(fn func(string) (bool, error)) func() {
	old := dropInterfaceFunc
	dropInterfaceFunc = fn
	return func() { dropInterfaceFunc = old }
}

func mockBringUpInterfaceFunc(fn func(string) error) func() {
	old := bringUpInterfaceFunc
	bringUpInterfaceFunc = fn
	return func() { bringUpInterfaceFunc = old }
}

func mockInterfaceByNameFunc(fn func(string) (*net.Interface, error)) func() {
	old := interfaceByNameFunc
	interfaceByNameFunc = fn
	return func() { interfaceByNameFunc = old }
}

func mockExecCommandFunc(fn func(context.Context, string, ...string) ([]byte, error)) func() {
	old := execCommandFunc
	execCommandFunc = fn
	return func() { execCommandFunc = old }
}

func mockTestUDPMTUFunc(fn func(string, int) bool) func() {
	old := testUDPMTUFunc
	testUDPMTUFunc = fn
	return func() { testUDPMTUFunc = old }
}

func mockKillswitchSleep(fn func(time.Duration)) func() {
	old := killswitchSleepFunc
	killswitchSleepFunc = fn
	return func() { killswitchSleepFunc = old }
}

// ---------------------------------------------------------------------------
// TestKillswitch tests (mocked - no real interface manipulation)
// ---------------------------------------------------------------------------

func TestTestKillswitch_CannotReachInternet(t *testing.T) {
	// All dial attempts fail - killswitch is already blocking
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}))

	result := TestKillswitch("wg0")

	if !result.IsSafe {
		t.Error("should be safe when internet is unreachable")
	}
	if !strings.Contains(result.Message, "Cannot reach internet") {
		t.Errorf("unexpected message: %q", result.Message)
	}
}

func TestTestKillswitch_DropInterfaceError(t *testing.T) {
	var callCount atomic.Int64
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		n := callCount.Add(1)
		if n <= 1 {
			// Pre-test: can reach internet
			c1, c2 := net.Pipe()
			go c2.Close()
			return c1, nil
		}
		return nil, fmt.Errorf("connection refused")
	}))
	t.Cleanup(mockDropInterfaceFunc(func(name string) (bool, error) {
		return false, fmt.Errorf("interface not found: wg0")
	}))

	result := TestKillswitch("wg0")

	if result.IsSafe {
		t.Error("should not be safe when drop fails")
	}
	if !strings.Contains(result.Message, "Could not drop interface") {
		t.Errorf("unexpected message: %q", result.Message)
	}
}

func TestTestKillswitch_NoLeaks(t *testing.T) {
	var callCount atomic.Int64
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		n := callCount.Add(1)
		if n <= 1 {
			// Pre-test: can reach internet
			c1, c2 := net.Pipe()
			go c2.Close()
			return c1, nil
		}
		// Phase 3: all leak tests fail (killswitch working)
		return nil, fmt.Errorf("connection refused")
	}))
	t.Cleanup(mockDropInterfaceFunc(func(name string) (bool, error) {
		return true, nil
	}))
	t.Cleanup(mockBringUpInterfaceFunc(func(name string) error {
		return nil
	}))
	t.Cleanup(mockKillswitchSleep(func(d time.Duration) {}))

	result := TestKillswitch("wg0")

	if !result.IsSafe {
		t.Errorf("should be safe, got message: %q", result.Message)
	}
	if result.Successes != 0 {
		t.Errorf("Successes = %d, want 0", result.Successes)
	}
	if !result.InterfaceDropped {
		t.Error("InterfaceDropped should be true")
	}
	if !strings.Contains(result.Message, "Killswitch verified") {
		t.Errorf("unexpected message: %q", result.Message)
	}
}

func TestTestKillswitch_WithLeaks(t *testing.T) {
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		// Always succeed - both pre-test and leak test
		c1, c2 := net.Pipe()
		go c2.Close()
		return c1, nil
	}))
	t.Cleanup(mockDropInterfaceFunc(func(name string) (bool, error) {
		return true, nil
	}))
	t.Cleanup(mockBringUpInterfaceFunc(func(name string) error {
		return nil
	}))
	t.Cleanup(mockKillswitchSleep(func(d time.Duration) {}))

	result := TestKillswitch("wg0")

	if result.IsSafe {
		t.Error("should NOT be safe when leaks detected")
	}
	if result.Successes == 0 {
		t.Error("should have detected leaks")
	}
	if !strings.Contains(result.Message, "FAIL") {
		t.Errorf("unexpected message: %q", result.Message)
	}
}

func TestTestKillswitch_InterfaceNotDropped(t *testing.T) {
	var callCount atomic.Int64
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		n := callCount.Add(1)
		if n <= 1 {
			c1, c2 := net.Pipe()
			go c2.Close()
			return c1, nil
		}
		return nil, fmt.Errorf("refused")
	}))
	// Interface already down
	t.Cleanup(mockDropInterfaceFunc(func(name string) (bool, error) {
		return false, nil // Already down
	}))
	t.Cleanup(mockKillswitchSleep(func(d time.Duration) {}))

	result := TestKillswitch("wg0")

	if result.InterfaceDropped {
		t.Error("InterfaceDropped should be false (dial fails before drop is meaningful)")
	}
	// Should still evaluate: no leaks since dial fails
	if !result.IsSafe {
		t.Errorf("should be safe, got: %q", result.Message)
	}
}

func TestTestKillswitch_RestoreInterfaceFails(t *testing.T) {
	var callCount atomic.Int64
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		n := callCount.Add(1)
		if n <= 1 {
			c1, c2 := net.Pipe()
			go c2.Close()
			return c1, nil
		}
		return nil, fmt.Errorf("refused")
	}))
	t.Cleanup(mockDropInterfaceFunc(func(name string) (bool, error) {
		return true, nil
	}))
	t.Cleanup(mockBringUpInterfaceFunc(func(name string) error {
		return fmt.Errorf("permission denied")
	}))
	t.Cleanup(mockKillswitchSleep(func(d time.Duration) {}))

	result := TestKillswitch("wg0")

	if result.IsSafe {
		t.Error("should NOT be safe when restore fails")
	}
	if !strings.Contains(result.Message, "WARNING: Failed to restore") {
		t.Errorf("unexpected message: %q", result.Message)
	}
}

// ---------------------------------------------------------------------------
// dropInterfaceReal tests
// ---------------------------------------------------------------------------

func TestDropInterfaceReal_InterfaceNotFound(t *testing.T) {
	t.Cleanup(mockInterfaceByNameFunc(func(name string) (*net.Interface, error) {
		return nil, fmt.Errorf("no such device: %s", name)
	}))

	dropped, err := dropInterfaceReal("nonexistent0")

	if err == nil {
		t.Fatal("expected error for missing interface")
	}
	if dropped {
		t.Error("should not report dropped for missing interface")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not found: %v", err)
	}
}

func TestDropInterfaceReal_InterfaceAlreadyDown(t *testing.T) {
	t.Cleanup(mockInterfaceByNameFunc(func(name string) (*net.Interface, error) {
		return &net.Interface{
			Index: 5,
			Name:  "wg0",
			Flags: 0, // Not FlagUp
		}, nil
	}))

	dropped, err := dropInterfaceReal("wg0")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dropped {
		t.Error("should not drop an already-down interface")
	}
}

func TestDropInterfaceReal_Success(t *testing.T) {
	t.Cleanup(mockInterfaceByNameFunc(func(name string) (*net.Interface, error) {
		return &net.Interface{
			Index: 5,
			Name:  "wg0",
			Flags: net.FlagUp,
		}, nil
	}))
	t.Cleanup(mockExecCommandFunc(func(_ context.Context, name string, args ...string) ([]byte, error) {
		return []byte(""), nil
	}))

	dropped, err := dropInterfaceReal("wg0")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dropped {
		t.Error("should report interface dropped")
	}
}

func TestDropInterfaceReal_ExecFails(t *testing.T) {
	t.Cleanup(mockInterfaceByNameFunc(func(name string) (*net.Interface, error) {
		return &net.Interface{
			Index: 5,
			Name:  "wg0",
			Flags: net.FlagUp,
		}, nil
	}))
	t.Cleanup(mockExecCommandFunc(func(_ context.Context, name string, args ...string) ([]byte, error) {
		return []byte("operation not permitted"), fmt.Errorf("exit status 1")
	}))

	dropped, err := dropInterfaceReal("wg0")

	if err == nil {
		t.Fatal("expected error from exec failure")
	}
	if dropped {
		t.Error("should not report dropped on exec failure")
	}
	if !strings.Contains(err.Error(), "failed to bring down") {
		t.Errorf("error should mention failure: %v", err)
	}
}

// ---------------------------------------------------------------------------
// bringUpInterfaceReal tests
// ---------------------------------------------------------------------------

func TestBringUpInterfaceReal_Success(t *testing.T) {
	t.Cleanup(mockExecCommandFunc(func(_ context.Context, name string, args ...string) ([]byte, error) {
		return []byte(""), nil
	}))

	err := bringUpInterfaceReal("wg0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBringUpInterfaceReal_Failure(t *testing.T) {
	t.Cleanup(mockExecCommandFunc(func(_ context.Context, name string, args ...string) ([]byte, error) {
		return []byte("permission denied"), fmt.Errorf("exit status 1")
	}))

	err := bringUpInterfaceReal("wg0")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to bring up") {
		t.Errorf("error should mention failure: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestMTU tests (mocked)
// ---------------------------------------------------------------------------

func TestTestMTU_OptimalMTU(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 5, Name: "wg0", MTU: 1420, Flags: net.FlagUp},
		}, nil
	}))
	// Mock: all MTUs succeed at 1500 (first test)
	t.Cleanup(mockTestUDPMTUFunc(func(host string, payloadSize int) bool {
		return true // First MTU (1500) succeeds
	}))

	result := TestMTU("wg0")

	if result.CurrentMTU != 1420 {
		t.Errorf("CurrentMTU = %d, want 1420", result.CurrentMTU)
	}
	// Optimal = 1500 - 80 = 1420
	if result.OptimalMTU != 1420 {
		t.Errorf("OptimalMTU = %d, want 1420", result.OptimalMTU)
	}
	if result.NeedsFix {
		t.Error("should not need fix when current equals optimal")
	}
	if !strings.Contains(result.Message, "MTU optimal") {
		t.Errorf("unexpected message: %q", result.Message)
	}
}

func TestTestMTU_NeedsFix(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 5, Name: "wg0", MTU: 1500, Flags: net.FlagUp},
		}, nil
	}))
	// Mock: first MTU (1500) succeeds
	t.Cleanup(mockTestUDPMTUFunc(func(host string, payloadSize int) bool {
		return true
	}))

	result := TestMTU("wg0")

	if result.CurrentMTU != 1500 {
		t.Errorf("CurrentMTU = %d, want 1500", result.CurrentMTU)
	}
	if result.OptimalMTU != 1420 {
		t.Errorf("OptimalMTU = %d, want 1420", result.OptimalMTU)
	}
	if !result.NeedsFix {
		t.Error("should need fix when current != optimal")
	}
	if !strings.Contains(result.Message, "MTU mismatch") {
		t.Errorf("unexpected message: %q", result.Message)
	}
}

func TestTestMTU_NoMTUWorks(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 5, Name: "wg0", MTU: 1420, Flags: net.FlagUp},
		}, nil
	}))
	// All MTU tests fail
	t.Cleanup(mockTestUDPMTUFunc(func(host string, payloadSize int) bool {
		return false
	}))

	result := TestMTU("wg0")

	if result.OptimalMTU != 1280 {
		t.Errorf("OptimalMTU = %d, want 1280 (conservative)", result.OptimalMTU)
	}
	if !result.NeedsFix {
		t.Error("should need fix when current (1420) != optimal (1280)")
	}
	if !strings.Contains(result.Message, "Could not determine") {
		t.Errorf("unexpected message: %q", result.Message)
	}
}

func TestTestMTU_LowerMTUSucceeds(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 5, Name: "wg0", MTU: 1420, Flags: net.FlagUp},
		}, nil
	}))
	// Only MTU 1280 succeeds (the last one tested)
	t.Cleanup(mockTestUDPMTUFunc(func(host string, payloadSize int) bool {
		// payloadSize = mtu - 28
		// For 1280: payloadSize = 1252
		return payloadSize == 1252
	}))

	result := TestMTU("wg0")

	if len(result.SuccessMTUs) != 1 {
		t.Fatalf("expected 1 success MTU, got %d", len(result.SuccessMTUs))
	}
	if result.SuccessMTUs[0] != 1280 {
		t.Errorf("SuccessMTUs[0] = %d, want 1280", result.SuccessMTUs[0])
	}
	// OptimalMTU = 1280 - 80 = 1200, but clamped to 1280 minimum
	if result.OptimalMTU != 1280 {
		t.Errorf("OptimalMTU = %d, want 1280 (clamped)", result.OptimalMTU)
	}
}

func TestTestMTU_InterfaceNotFound(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{}, nil // No matching interface
	}))
	t.Cleanup(mockTestUDPMTUFunc(func(host string, payloadSize int) bool {
		return true
	}))

	result := TestMTU("nonexistent0")

	// Should use default MTU 1420 when interface not found
	if result.CurrentMTU != 1420 {
		t.Errorf("CurrentMTU = %d, want 1420 (default)", result.CurrentMTU)
	}
}

func TestTestMTU_InterfaceError(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return nil, fmt.Errorf("permission denied")
	}))
	t.Cleanup(mockTestUDPMTUFunc(func(host string, payloadSize int) bool {
		return true
	}))

	result := TestMTU("wg0")

	// Should use default MTU 1420 when interfaces error
	if result.CurrentMTU != 1420 {
		t.Errorf("CurrentMTU = %d, want 1420 (default on error)", result.CurrentMTU)
	}
}

func TestTestMTU_TestedMTUs(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{}, nil
	}))
	// Only 1420 succeeds
	t.Cleanup(mockTestUDPMTUFunc(func(host string, payloadSize int) bool {
		return payloadSize == (1420 - 28)
	}))

	result := TestMTU("wg0")

	// Should have tested 1500, 1472, 1450, 1420 (stops at first success)
	if len(result.TestedMTUs) != 4 {
		t.Errorf("TestedMTUs count = %d, want 4", len(result.TestedMTUs))
	}
	expected := []int{1500, 1472, 1450, 1420}
	for i, mtu := range expected {
		if i >= len(result.TestedMTUs) {
			break
		}
		if result.TestedMTUs[i] != mtu {
			t.Errorf("TestedMTUs[%d] = %d, want %d", i, result.TestedMTUs[i], mtu)
		}
	}
}

// ===========================================================================
// Mutation-killing tests
//
// These tests are designed to catch specific gremlins (mutation testing) that
// survived the original test suite. Each test targets one or more mutant
// lines and explains which mutation it kills.
// ===========================================================================

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:185:37
// Mutation: `20 * time.Second` -> `20 / time.Second` in checkPublicIP client timeout
// Kill: With a ~0ns timeout, the HTTP client.Do will fail with a deadline exceeded.
//
//	We use a server that delays slightly to ensure the mutation is caught.
//
// ---------------------------------------------------------------------------
func TestCheckPublicIP_ClientTimeoutIsReasonable(t *testing.T) {
	// Server that sleeps 50ms before responding — this is fine with a 10s
	// timeout but would fail with a 0ns (mutant) timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		json.NewEncoder(w).Encode(map[string]string{
			"ip":      "1.2.3.4",
			"org":     "Proton AG",
			"country": "CH",
		})
	}))
	defer srv.Close()

	mockAllIPURLs(t, srv.URL)

	lt := &LeakTest{ID: "test-timeout-185"}
	lt.checkPublicIP()

	if lt.Error != nil {
		t.Fatalf("checkPublicIP should succeed with 10s timeout but got error: %v", lt.Error)
	}
	if lt.IPResult == nil {
		t.Fatal("IPResult should not be nil")
	}
	if lt.IPResult.IP != "1.2.3.4" {
		t.Errorf("IP = %q, want %q", lt.IPResult.IP, "1.2.3.4")
	}
}

// ---------------------------------------------------------------------------
// Verify DNS reflection works with a small delay (replaces old HTTP client
// timeout test). The mock lookupTXT sleeps briefly to verify the reflection
// path tolerates non-instant responses.
// ---------------------------------------------------------------------------
func TestTestDNS_ReflectionWorksWithDelay(t *testing.T) {
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		time.Sleep(50 * time.Millisecond)
		return []string{"10.2.0.1"}, nil
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return []string{"dns1.protonvpn.ch."}, nil
	}))
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))

	lt := &LeakTest{ID: "test-delay"}
	lt.testDNS()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results from reflection")
	}

	// Find the reflection result
	var found bool
	for _, r := range lt.DNSResults {
		if r.IP == "10.2.0.1" {
			found = true
			if !r.IsVPN {
				t.Error("should detect ProtonVPN DNS as VPN")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected reflection result with IP 10.2.0.1, got %+v", lt.DNSResults)
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:317:60
// Mutation: `5 * time.Second` -> `5 / time.Second` in checkLocalDNS context timeout
// Kill: resolvectlOutput receives the context. With a 0ns timeout, the context
//
//	is already cancelled. We verify resolvectl path works by checking the
//	context is not expired when our mock is called.
//
// ---------------------------------------------------------------------------
func TestCheckLocalDNS_ContextTimeoutIsReasonable(t *testing.T) {
	var ctxWasValid bool
	t.Cleanup(mockResolvectlOutput(func(ctx context.Context) ([]byte, error) {
		// Small sleep to ensure a 0ns context would have expired
		time.Sleep(5 * time.Millisecond)
		if ctx.Err() == nil {
			ctxWasValid = true
		}
		return []byte("Link 3 (wg0): 10.2.0.1\n"), nil
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("should not be called")
	}))

	lt := &LeakTest{ID: "test-timeout-317"}
	lt.checkLocalDNS()

	if !ctxWasValid {
		t.Error("context should still be valid when resolvectl is called (5s timeout, not 0ns)")
	}
	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results")
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("ProtonVPN DNS should be safe")
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:346:70
// Mutation: `3 * time.Second` -> `3 / time.Second` in checkLocalDNS testCtx timeout
// Kill: dnsLookupHost receives the context. With 0ns timeout it would be
//
//	cancelled immediately, making the lookup fail and reporting DNS blocked
//	even when DNS is actually working (false positive). We verify the
//	context is live when the lookup runs AND that the result is
//	"Could not determine" (because DNS resolves successfully).
//
// ---------------------------------------------------------------------------
func TestCheckLocalDNS_DNSLookupContextIsReasonable(t *testing.T) {
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("no resolvectl")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return []byte("nameserver 127.0.0.53\n"), nil
	}))

	var ctxWasValid bool
	t.Cleanup(mockDNSLookupHost(func(ctx context.Context, host string) ([]string, error) {
		time.Sleep(5 * time.Millisecond)
		if ctx.Err() == nil {
			ctxWasValid = true
		}
		// DNS resolves successfully — means NOT blocked
		return []string{"1.1.1.1"}, nil
	}))

	lt := &LeakTest{ID: "test-timeout-346"}
	lt.checkLocalDNS()

	if !ctxWasValid {
		t.Error("context should be valid during DNS lookup (3s timeout, not 0ns)")
	}
	// Since DNS resolved successfully (not blocked), and no VPN DNS found,
	// the result should be "Could not determine" / unsafe.
	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results")
	}
	if lt.DNSResults[0].IsSafe {
		t.Error("should be unsafe — DNS resolved (not blocked), no VPN DNS found")
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:438:19
// Mutation: `2 * time.Second` -> `2 / time.Second` in WebRTC dialer Timeout
// Kill: The dialer timeout is passed to the mock via the *net.Dialer struct.
//
//	Verify the timeout value is reasonable (2s, not 0ns).
//
// ---------------------------------------------------------------------------
func TestTestWebRTC_DialerTimeoutIsReasonable(t *testing.T) {
	realIfaces, err := net.Interfaces()
	if err != nil {
		t.Skip("cannot get interfaces")
	}
	var hasPhysIPv4 bool
	for _, iface := range realIfaces {
		if iface.Flags&net.FlagLoopback != 0 || strings.HasPrefix(iface.Name, "wg") || isVirtualInterface(iface.Name) {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP
				if ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
					hasPhysIPv4 = true
				}
			}
		}
	}
	if !hasPhysIPv4 {
		t.Skip("no physical IPv4 interface")
	}

	var capturedTimeout atomic.Int64
	t.Cleanup(mockWebrtcDialFunc(func(d *net.Dialer, network, address string) (net.Conn, error) {
		capturedTimeout.Store(int64(d.Timeout))
		return nil, fmt.Errorf("blocked")
	}))

	lt := &LeakTest{ID: "test-timeout-438", KillswitchActive: true}
	lt.testWebRTC()

	got := time.Duration(capturedTimeout.Load())
	if got != 5*time.Second {
		t.Errorf("dialer Timeout = %v, want %v", got, 5*time.Second)
	}
}

// ---------------------------------------------------------------------------
// Mutant: CONDITIONALS_NEGATION at leaktest.go:481:17
// Mutation: `ip.To4() == nil` -> `ip.To4() != nil` (flips IPv6 detection)
// Kill: With the mutation, IPv4 addresses would be flagged as IPv6 and vice
//
//	versa. We mock an interface with ONLY a global IPv6 address and
//	verify IPv6Available is true. With the mutation, To4()!=nil would
//	be false for IPv6, so IPv6Available would stay false.
//
// ---------------------------------------------------------------------------
func TestTestIPv6_ConditionNegation_IPv6Detection(t *testing.T) {
	// We need a real interface that has a global IPv6 address but no IPv4.
	// Since we can't mock iface.Addrs(), we check the real system.
	realIfaces, err := net.Interfaces()
	if err != nil {
		t.Skip("cannot list interfaces")
	}

	// Find an interface with global IPv6
	var hasGlobalIPv6Only bool
	for _, iface := range realIfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP
				if ip.To4() == nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
					hasGlobalIPv6Only = true
				}
			}
		}
	}

	if !hasGlobalIPv6Only {
		t.Skip("no global IPv6 address on system to test condition negation")
	}

	// Mock dial to fail (simulating blocked)
	t.Cleanup(mockIPv6DialFunc(func(_ context.Context, _, _ string, _ time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("blocked")
	}))

	lt := &LeakTest{ID: "test-condneg-481"}
	lt.testIPv6()

	if lt.IPv6Result == nil {
		t.Fatal("IPv6Result should not be nil")
	}
	// With the correct condition `ip.To4() == nil`, IPv6 is detected -> IPv6Available = true
	// With the mutation `ip.To4() != nil`, IPv4 is treated as IPv6 -> wrong behavior
	if !lt.IPv6Result.IPv6Available {
		t.Error("IPv6Available should be true — system has global IPv6")
	}
	if !lt.IPv6Result.IPv6Blocked {
		t.Error("IPv6Blocked should be true (dial was mocked to fail)")
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:497:60
// Mutation: `5 * time.Second` -> `5 / time.Second` in testIPv6 context timeout
// Kill: With 0ns context timeout, ipv6DialFunc receives an already-cancelled
//
//	context. Verify that the context is valid during the call.
//
// ---------------------------------------------------------------------------
func TestTestIPv6_ContextTimeoutIsReasonable(t *testing.T) {
	// Need a system with global IPv6 for the code to reach the dial
	realIfaces, err := net.Interfaces()
	if err != nil {
		t.Skip("cannot list interfaces")
	}
	hasIPv6 := false
	for _, iface := range realIfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP
				if ip.To4() == nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
					hasIPv6 = true
				}
			}
		}
	}
	if !hasIPv6 {
		t.Skip("no global IPv6 on system")
	}

	var ctxWasValid bool
	t.Cleanup(mockIPv6DialFunc(func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		time.Sleep(5 * time.Millisecond)
		if ctx.Err() == nil {
			ctxWasValid = true
		}
		return nil, fmt.Errorf("blocked")
	}))

	lt := &LeakTest{ID: "test-timeout-497"}
	lt.testIPv6()

	if !ctxWasValid {
		t.Error("context should be valid during IPv6 dial (5s timeout, not 0ns)")
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:501:71
// Mutation: `5 * time.Second` -> `5 / time.Second` in ipv6DialFunc timeout arg
// Kill: Verify the timeout parameter passed to ipv6DialFunc is 5s.
// ---------------------------------------------------------------------------
func TestTestIPv6_DialTimeoutParamIsReasonable(t *testing.T) {
	realIfaces, err := net.Interfaces()
	if err != nil {
		t.Skip("cannot list interfaces")
	}
	hasIPv6 := false
	for _, iface := range realIfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP
				if ip.To4() == nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
					hasIPv6 = true
				}
			}
		}
	}
	if !hasIPv6 {
		t.Skip("no global IPv6 on system")
	}

	var capturedTimeout time.Duration
	t.Cleanup(mockIPv6DialFunc(func(_ context.Context, _, _ string, timeout time.Duration) (net.Conn, error) {
		capturedTimeout = timeout
		return nil, fmt.Errorf("blocked")
	}))

	lt := &LeakTest{ID: "test-timeout-501"}
	lt.testIPv6()

	if capturedTimeout != 5*time.Second {
		t.Errorf("ipv6DialFunc timeout = %v, want %v", capturedTimeout, 5*time.Second)
	}
}

// ---------------------------------------------------------------------------
// Mutant: CONDITIONALS_BOUNDARY at leaktest.go:586:16
// Mutation: `i < 3` -> `i <= 3` in pre-test loop (4 iterations instead of 3)
// Kill: Count exactly how many times dialTimeoutFunc is called during the
//
//	pre-test phase. If all fail, it should be exactly 3 with the correct
//	code, and 4 with the mutation.
//
// ---------------------------------------------------------------------------
func TestTestKillswitch_PreTestLoopIterations(t *testing.T) {
	var preTestCalls atomic.Int64
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		preTestCalls.Add(1)
		return nil, fmt.Errorf("connection refused")
	}))

	_ = TestKillswitch("wg0")

	// Pre-test loop does exactly 3 attempts when all fail
	if got := preTestCalls.Load(); got != 3 {
		t.Errorf("pre-test dial attempts = %d, want 3", got)
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:587:54
// Mutation: `1 * time.Second` -> `1 / time.Second` in pre-test dial timeout
// Kill: Capture the timeout value passed to dialTimeoutFunc.
// ---------------------------------------------------------------------------
func TestTestKillswitch_PreTestDialTimeout(t *testing.T) {
	var capturedTimeout time.Duration
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		capturedTimeout = timeout
		return nil, fmt.Errorf("refused")
	}))

	_ = TestKillswitch("wg0")

	if capturedTimeout != 1*time.Second {
		t.Errorf("pre-test dial timeout = %v, want %v", capturedTimeout, 1*time.Second)
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:621:48
// Mutation: `500 * time.Millisecond` -> `500 / time.Millisecond` in phase 3 dial
// Kill: Capture the timeout from phase 3 dial calls.
// ---------------------------------------------------------------------------
func TestTestKillswitch_Phase3DialTimeout(t *testing.T) {
	var preTestDone atomic.Bool
	var phase3Timeouts []time.Duration
	var mu sync.Mutex

	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if !preTestDone.Load() {
			// First call is pre-test — let it succeed, then mark done
			preTestDone.Store(true)
			c1, c2 := net.Pipe()
			go c2.Close()
			return c1, nil
		}
		// Phase 3 calls
		mu.Lock()
		phase3Timeouts = append(phase3Timeouts, timeout)
		mu.Unlock()
		return nil, fmt.Errorf("refused")
	}))
	t.Cleanup(mockDropInterfaceFunc(func(name string) (bool, error) {
		return true, nil
	}))
	t.Cleanup(mockBringUpInterfaceFunc(func(name string) error {
		return nil
	}))
	t.Cleanup(mockKillswitchSleep(func(d time.Duration) {}))

	_ = TestKillswitch("wg0")

	mu.Lock()
	defer mu.Unlock()

	if len(phase3Timeouts) == 0 {
		t.Fatal("expected at least one phase 3 dial call")
	}
	for i, timeout := range phase3Timeouts {
		if timeout != 500*time.Millisecond {
			t.Errorf("phase 3 dial timeout[%d] = %v, want %v", i, timeout, 500*time.Millisecond)
		}
	}
}

// ---------------------------------------------------------------------------
// Mutant: INCREMENT_DECREMENT at leaktest.go:639:24
// Mutation: `result.PostDropLeaks++` -> `result.PostDropLeaks--`
// Kill: When all leaks succeed, PostDropLeaks should be positive (== Attempts).
//
//	With the mutation it would be negative.
//
// ---------------------------------------------------------------------------
func TestTestKillswitch_PostDropLeaksCount(t *testing.T) {
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		// All calls succeed — maximum leakage
		c1, c2 := net.Pipe()
		go c2.Close()
		return c1, nil
	}))
	t.Cleanup(mockDropInterfaceFunc(func(name string) (bool, error) {
		return true, nil
	}))
	t.Cleanup(mockBringUpInterfaceFunc(func(name string) error {
		return nil
	}))
	t.Cleanup(mockKillswitchSleep(func(d time.Duration) {}))

	result := TestKillswitch("wg0")

	// With correct code: PostDropLeaks == 10 (all 10 attempts leaked)
	// With mutation (--): PostDropLeaks == -10
	if result.PostDropLeaks != 10 {
		t.Errorf("PostDropLeaks = %d, want 10", result.PostDropLeaks)
	}
	if result.Successes != 10 {
		t.Errorf("Successes = %d, want 10", result.Successes)
	}
}

// ---------------------------------------------------------------------------
// Mutant: CONDITIONALS_BOUNDARY at leaktest.go:647:31
// Mutation: `attempts < 3` -> `attempts <= 3` (4 restore attempts instead of 3)
// Kill: Count the number of times bringUpInterfaceFunc is called when all
//
//	attempts fail. Should be exactly 3.
//
// ---------------------------------------------------------------------------
func TestTestKillswitch_RestoreRetryCount(t *testing.T) {
	var preTestDone atomic.Bool
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if !preTestDone.Load() {
			preTestDone.Store(true)
			c1, c2 := net.Pipe()
			go c2.Close()
			return c1, nil
		}
		return nil, fmt.Errorf("refused")
	}))
	t.Cleanup(mockDropInterfaceFunc(func(name string) (bool, error) {
		return true, nil
	}))

	var restoreAttempts atomic.Int64
	t.Cleanup(mockBringUpInterfaceFunc(func(name string) error {
		restoreAttempts.Add(1)
		return fmt.Errorf("permission denied")
	}))
	t.Cleanup(mockKillswitchSleep(func(d time.Duration) {}))

	_ = TestKillswitch("wg0")

	if got := restoreAttempts.Load(); got != 3 {
		t.Errorf("restore attempts = %d, want 3", got)
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:653:29
// Mutation: `200 * time.Millisecond` -> `200 / time.Millisecond` in restore sleep
// Kill: Capture the sleep duration during the restore retry loop.
// ---------------------------------------------------------------------------
func TestTestKillswitch_RestoreSleepDuration(t *testing.T) {
	var preTestDone atomic.Bool
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if !preTestDone.Load() {
			preTestDone.Store(true)
			c1, c2 := net.Pipe()
			go c2.Close()
			return c1, nil
		}
		return nil, fmt.Errorf("refused")
	}))
	t.Cleanup(mockDropInterfaceFunc(func(name string) (bool, error) {
		return true, nil
	}))

	var restoreCallCount atomic.Int64
	t.Cleanup(mockBringUpInterfaceFunc(func(name string) error {
		n := restoreCallCount.Add(1)
		if n <= 2 {
			return fmt.Errorf("temporary failure")
		}
		return nil // Third attempt succeeds
	}))

	var sleepDurations []time.Duration
	var mu sync.Mutex
	t.Cleanup(mockKillswitchSleep(func(d time.Duration) {
		mu.Lock()
		sleepDurations = append(sleepDurations, d)
		mu.Unlock()
	}))

	_ = TestKillswitch("wg0")

	mu.Lock()
	defer mu.Unlock()

	// Should have 2 x 200ms sleeps (after failures 1 and 2) + 1 x 500ms (post-restore)
	// The 200ms sleeps happen before the 500ms sleep.
	found200 := false
	for _, d := range sleepDurations {
		if d == 200*time.Millisecond {
			found200 = true
		}
	}
	if !found200 {
		t.Errorf("expected 200ms sleep during restore retries, got durations: %v", sleepDurations)
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:663:27
// Mutation: `500 * time.Millisecond` -> `500 / time.Millisecond` in post-restore sleep
// Kill: Capture the post-restore sleep duration.
// ---------------------------------------------------------------------------
func TestTestKillswitch_PostRestoreSleepDuration(t *testing.T) {
	var preTestDone atomic.Bool
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if !preTestDone.Load() {
			preTestDone.Store(true)
			c1, c2 := net.Pipe()
			go c2.Close()
			return c1, nil
		}
		return nil, fmt.Errorf("refused")
	}))
	t.Cleanup(mockDropInterfaceFunc(func(name string) (bool, error) {
		return true, nil
	}))
	t.Cleanup(mockBringUpInterfaceFunc(func(name string) error {
		return nil // Succeed on first try
	}))

	var sleepDurations []time.Duration
	var mu sync.Mutex
	t.Cleanup(mockKillswitchSleep(func(d time.Duration) {
		mu.Lock()
		sleepDurations = append(sleepDurations, d)
		mu.Unlock()
	}))

	_ = TestKillswitch("wg0")

	mu.Lock()
	defer mu.Unlock()

	// With immediate restore success: only the 500ms post-restore sleep
	found500 := false
	for _, d := range sleepDurations {
		if d == 500*time.Millisecond {
			found500 = true
		}
	}
	if !found500 {
		t.Errorf("expected 500ms post-restore sleep, got durations: %v", sleepDurations)
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:692:60
// Mutation: `5 * time.Second` -> `5 / time.Second` in dropInterfaceReal context timeout
// Kill: Verify context is valid when execCommandFunc is called.
// ---------------------------------------------------------------------------
func TestDropInterfaceReal_ContextTimeoutIsReasonable(t *testing.T) {
	t.Cleanup(mockInterfaceByNameFunc(func(name string) (*net.Interface, error) {
		return &net.Interface{Index: 5, Name: "wg0", Flags: net.FlagUp}, nil
	}))

	var ctxWasValid bool
	t.Cleanup(mockExecCommandFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		time.Sleep(5 * time.Millisecond)
		if ctx.Err() == nil {
			ctxWasValid = true
		}
		return []byte(""), nil
	}))

	dropped, err := dropInterfaceReal("wg0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dropped {
		t.Error("should report dropped")
	}
	if !ctxWasValid {
		t.Error("context should be valid during exec (5s timeout, not 0ns)")
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:705:60
// Mutation: `5 * time.Second` -> `5 / time.Second` in bringUpInterfaceReal context timeout
// Kill: Verify context is valid when execCommandFunc is called.
// ---------------------------------------------------------------------------
func TestBringUpInterfaceReal_ContextTimeoutIsReasonable(t *testing.T) {
	var ctxWasValid bool
	t.Cleanup(mockExecCommandFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		time.Sleep(5 * time.Millisecond)
		if ctx.Err() == nil {
			ctxWasValid = true
		}
		return []byte(""), nil
	}))

	err := bringUpInterfaceReal("wg0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ctxWasValid {
		t.Error("context should be valid during exec (5s timeout, not 0ns)")
	}
}

// ---------------------------------------------------------------------------
// Mutant: CONDITIONALS_BOUNDARY at leaktest.go:767:18
// Mutation: `payloadSize <= 0` -> `payloadSize < 0`
// Kill: With a zero payloadSize (mtu=28), the correct code skips it
//
//	(payloadSize=0 matches <= 0). With the mutation (< 0), payloadSize=0
//	would NOT be skipped and testUDPMTUFunc would be called with size 0.
//	We test with an MTU list containing 28, which produces payloadSize=0.
//
// NOTE: The default testMTUs are [1500..1280], none produce payloadSize <= 0.
//
//	This mutation is on a guard for hypothetical small MTUs. Since the
//	actual testMTUs list never triggers payloadSize <= 0, this mutation
//	is effectively equivalent (dead code for the current input range).
//	We document this as an equivalent mutation.
//
//	However, let's verify the boundary behavior indirectly by ensuring
//	the payload size calculation (mtu - 28) is correct for the smallest
//	tested MTU (1280 -> payload 1252).
//
// ---------------------------------------------------------------------------
func TestTestMTU_PayloadSizeCalculation(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{}, nil
	}))

	var capturedPayloads []int
	var mu sync.Mutex
	t.Cleanup(mockTestUDPMTUFunc(func(host string, payloadSize int) bool {
		mu.Lock()
		capturedPayloads = append(capturedPayloads, payloadSize)
		mu.Unlock()
		return false // All fail — test all MTUs
	}))

	TestMTU("wg0")

	mu.Lock()
	defer mu.Unlock()

	// testMTUs: 1500, 1472, 1450, 1420, 1400, 1380, 1350, 1300, 1280
	// payload = mtu - 28
	expected := []int{1472, 1444, 1422, 1392, 1372, 1352, 1322, 1272, 1252}
	if len(capturedPayloads) != len(expected) {
		t.Fatalf("payload count = %d, want %d", len(capturedPayloads), len(expected))
	}
	for i, want := range expected {
		if capturedPayloads[i] != want {
			t.Errorf("payload[%d] = %d, want %d", i, capturedPayloads[i], want)
		}
	}
}

// ---------------------------------------------------------------------------
// Mutant: CONDITIONALS_BOUNDARY at leaktest.go:776:25
// Mutation: `result.OptimalMTU < 1280` -> `result.OptimalMTU <= 1280`
// Kill: We need OptimalMTU to be exactly 1280 after `mtu - overhead`.
//       mtu - 80 = 1280 means mtu = 1360. If the first succeeding MTU is 1360,
//       OptimalMTU = 1360 - 80 = 1280. With correct code `< 1280`, 1280 is NOT
//       less than 1280, so it stays 1280. With mutation `<= 1280`, 1280 IS
//       <= 1280, so it would be clamped to 1280 (same result — equivalent!).
//
//       Actually wait — 1360 is not in the testMTUs list. Let's find an MTU
//       that produces exactly 1280: mtu - 80 = 1280 -> mtu = 1360.
//       testMTUs = [1500, 1472, 1450, 1420, 1400, 1380, 1350, 1300, 1280].
//       None produce exactly 1280.
//       1300 - 80 = 1220 (< 1280, clamped to 1280)
//       1350 - 80 = 1270 (< 1280, clamped to 1280)
//       1380 - 80 = 1300 (> 1280, no clamp)
//
//       For the mutation to matter, OptimalMTU needs to be exactly 1280.
//       1360 is the magic value, but it's not in the list.
//       This is an equivalent mutation for the current testMTUs list.
//
//       However, 1280 - 80 = 1200, which IS < 1280, so gets clamped to 1280.
//       So when mtu=1280 succeeds: OptimalMTU = 1280-80 = 1200, then clamped
//       to 1280. Both `< 1280` and `<= 1280` would clamp it.
//       This IS an equivalent mutation given the current testMTUs.
//
//       DOCUMENTED: Equivalent mutation — no MTU in the test list produces
//       OptimalMTU of exactly 1280 before the clamp check. All values are
//       either well above or well below 1280.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:806:45
// Mutation: `2 * time.Second` -> `2 / time.Second` in testUDPMTUReal DialTimeout
// Kill: With a 0ns timeout, net.DialTimeout for UDP may still succeed (UDP dial
//
//	doesn't do a handshake). But let's verify the function works correctly
//	with a real target.
//
// ---------------------------------------------------------------------------
func TestTestUDPMTUReal_SuccessfulSend(t *testing.T) {
	// Start a UDP listener so we have a valid target
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start UDP listener: %v", err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().String()
	result := testUDPMTUReal(addr, 100)
	if !result {
		t.Error("expected true for small UDP payload to local listener")
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:815:23
// Mutation: `i % 256` -> `i / 256` in payload fill loop
// Kill: With `i % 256`, a 512-byte payload repeats [0,1,...,255,0,1,...,255].
//       With `i / 256`, a 512-byte payload is [0,0,...,0,1,1,...,1] (first 256
//       are 0, next 256 are 1). The function sends to a UDP endpoint; we can't
//       inspect the payload in flight without raw sockets.
//
//       However, this mutation doesn't affect the return value of the function
//       (the payload content doesn't matter for whether the send succeeds).
//       The payload fill is purely cosmetic/diagnostic data.
//       DOCUMENTED: Equivalent mutation — payload content doesn't affect
//       the boolean return value. The only observable effects are "send
//       succeeded" or "send failed", and both patterns produce the same
//       byte count.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:819:36
// Mutation: `2 * time.Second` -> `2 / time.Second` in SetDeadline
// Kill: With 0ns deadline, time.Now().Add(0) is already in the past, so the
//
//	subsequent Write would fail with i/o timeout. We verify the function
//	succeeds with a valid write.
//
// ---------------------------------------------------------------------------
func TestTestUDPMTUReal_DeadlineAllowsWrite(t *testing.T) {
	// Start a local UDP listener
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start UDP listener: %v", err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().String()
	// Send a reasonably-sized payload
	result := testUDPMTUReal(addr, 500)
	if !result {
		t.Error("expected true — deadline should be 2s, not 0ns")
	}
}

// ---------------------------------------------------------------------------
// Mutant: ARITHMETIC_BASE at leaktest.go:775 (mtu - overhead)
// Already tested by TestTestMTU_OptimalMTU and TestTestMTU_NeedsFix which
// assert OptimalMTU = 1420 (1500 - 80). If `mtu + overhead` were used,
// OptimalMTU would be 1580.
//
// Additional test: verify the exact arithmetic for a mid-range success.
// ---------------------------------------------------------------------------
func TestTestMTU_OptimalMTUArithmetic(t *testing.T) {
	t.Cleanup(mockNetInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 5, Name: "wg0", MTU: 1340, Flags: net.FlagUp},
		}, nil
	}))
	// Only 1420 succeeds (payload = 1420 - 28 = 1392)
	t.Cleanup(mockTestUDPMTUFunc(func(host string, payloadSize int) bool {
		return payloadSize == 1392
	}))

	result := TestMTU("wg0")

	// 1420 - 80 = 1340
	if result.OptimalMTU != 1340 {
		t.Errorf("OptimalMTU = %d, want 1340 (1420 - 80 overhead)", result.OptimalMTU)
	}
	if result.CurrentMTU != 1340 {
		t.Errorf("CurrentMTU = %d, want 1340", result.CurrentMTU)
	}
	if result.NeedsFix {
		t.Error("should not need fix when CurrentMTU == OptimalMTU")
	}
}

// ---------------------------------------------------------------------------
// Verify TestKillswitch Attempts is exactly 10
// (Catches leaktest.go:581 if mutated)
// ---------------------------------------------------------------------------
func TestTestKillswitch_AttemptsFieldIsExactly10(t *testing.T) {
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("refused")
	}))

	result := TestKillswitch("wg0")
	if result.Attempts != 10 {
		t.Errorf("Attempts = %d, want 10", result.Attempts)
	}
}

// ---------------------------------------------------------------------------
// Verify the message format for killswitch test includes exact counts
// (Helps catch PostDropLeaks increment mutation)
// ---------------------------------------------------------------------------
func TestTestKillswitch_LeakMessageIncludesExactCounts(t *testing.T) {
	// Create scenario where exactly 10 out of 10 leak
	t.Cleanup(mockDialTimeoutFunc(func(network, addr string, timeout time.Duration) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go c2.Close()
		return c1, nil
	}))
	t.Cleanup(mockDropInterfaceFunc(func(name string) (bool, error) {
		return true, nil
	}))
	t.Cleanup(mockBringUpInterfaceFunc(func(name string) error {
		return nil
	}))
	t.Cleanup(mockKillswitchSleep(func(d time.Duration) {}))

	result := TestKillswitch("wg0")

	expected := "FAIL: 10/10 packets leaked while interface was down!"
	if result.Message != expected {
		t.Errorf("Message = %q, want %q", result.Message, expected)
	}
}

// ---------------------------------------------------------------------------
// parseResolvectlStatus tests (pure function, no mocking)
// ---------------------------------------------------------------------------

func TestParseResolvectlStatus_VPNAndPhysical(t *testing.T) {
	output := `Link 2 (wlan0)
    Current Scopes: DNS
         Protocols: +DefaultRoute +LLMNR -mDNS -DNSOverTLS
Current DNS Server: 192.168.50.23
       DNS Servers: 192.168.50.23

Link 4 (wg0)
    Current Scopes: DNS
         Protocols: +DefaultRoute +LLMNR -mDNS -DNSOverTLS
Current DNS Server: 10.2.0.1
       DNS Servers: 10.2.0.1
`
	links := parseResolvectlStatus(output)

	if len(links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(links))
	}

	// First link: wlan0
	if links[0].name != "wlan0" {
		t.Errorf("link[0].name = %q, want %q", links[0].name, "wlan0")
	}
	if !links[0].isDefaultRoute {
		t.Error("link[0] should have +DefaultRoute")
	}
	if len(links[0].dnsServers) != 1 || links[0].dnsServers[0] != "192.168.50.23" {
		t.Errorf("link[0].dnsServers = %v, want [192.168.50.23]", links[0].dnsServers)
	}

	// Second link: wg0
	if links[1].name != "wg0" {
		t.Errorf("link[1].name = %q, want %q", links[1].name, "wg0")
	}
	if !links[1].isDefaultRoute {
		t.Error("link[1] should have +DefaultRoute")
	}
	if len(links[1].dnsServers) != 1 || links[1].dnsServers[0] != "10.2.0.1" {
		t.Errorf("link[1].dnsServers = %v, want [10.2.0.1]", links[1].dnsServers)
	}
}

func TestParseResolvectlStatus_SingleInterface(t *testing.T) {
	output := `Link 3 (eth0)
    Current Scopes: DNS
         Protocols: +DefaultRoute
       DNS Servers: 8.8.8.8 8.8.4.4
`
	links := parseResolvectlStatus(output)

	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	if links[0].name != "eth0" {
		t.Errorf("name = %q, want %q", links[0].name, "eth0")
	}
	if len(links[0].dnsServers) != 2 {
		t.Fatalf("expected 2 DNS servers, got %d", len(links[0].dnsServers))
	}
	if links[0].dnsServers[0] != "8.8.8.8" || links[0].dnsServers[1] != "8.8.4.4" {
		t.Errorf("dnsServers = %v", links[0].dnsServers)
	}
}

func TestParseResolvectlStatus_NoDefaultRoute(t *testing.T) {
	output := `Link 2 (wlan0)
    Current Scopes: DNS
         Protocols: -DefaultRoute +LLMNR
       DNS Servers: 192.168.1.1
`
	links := parseResolvectlStatus(output)

	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	if links[0].isDefaultRoute {
		t.Error("should NOT have +DefaultRoute")
	}
}

func TestParseResolvectlStatus_Empty(t *testing.T) {
	links := parseResolvectlStatus("")
	if len(links) != 0 {
		t.Errorf("expected 0 links, got %d", len(links))
	}
}

func TestParseResolvectlStatus_NoDuplicateFromCurrentDNSServer(t *testing.T) {
	output := `Link 2 (wlan0)
    Current Scopes: DNS
         Protocols: +DefaultRoute
Current DNS Server: 10.2.0.1
       DNS Servers: 10.2.0.1
`
	links := parseResolvectlStatus(output)

	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	// Current DNS Server should not duplicate the DNS Servers entry
	if len(links[0].dnsServers) != 1 {
		t.Errorf("expected 1 DNS server (no dupe), got %v", links[0].dnsServers)
	}
}

// ---------------------------------------------------------------------------
// checkLocalDNSEnhanced tests
// ---------------------------------------------------------------------------

func TestCheckLocalDNSEnhanced_SplitDNSLeak(t *testing.T) {
	// wlan0 has ISP DNS with +DefaultRoute, wg0 has VPN DNS with +DefaultRoute
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return []byte(`Link 2 (wlan0)
    Current Scopes: DNS
         Protocols: +DefaultRoute +LLMNR
       DNS Servers: 8.8.8.8

Link 4 (wg0)
    Current Scopes: DNS
         Protocols: +DefaultRoute +LLMNR
       DNS Servers: 10.2.0.1
`), nil
	}))
	// ECS check returns no ECS
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return []string{"ip: 10.2.0.1, netmask: no ECS"}, nil
	}))

	// ISP baseline was 8.8.8.8 → seeing it on wlan0 is a leak
	lt := &LeakTest{ID: "test-split-dns", BaselineDNS: []string{"8.8.8.8"}}
	lt.checkLocalDNSEnhanced()

	// Should have results for both interfaces + ECS
	if len(lt.DNSResults) < 2 {
		t.Fatalf("expected at least 2 results, got %d: %+v", len(lt.DNSResults), lt.DNSResults)
	}

	// Find the leak (ISP DNS on wlan0 matches baseline)
	var foundLeak, foundSafe bool
	for _, r := range lt.DNSResults {
		if r.IP == "8.8.8.8" && !r.IsSafe {
			foundLeak = true
		}
		if r.IP == "10.2.0.1" && r.IsSafe {
			foundSafe = true
		}
	}
	if !foundLeak {
		t.Error("expected leak result for 8.8.8.8 on wlan0 (matches ISP baseline)")
	}
	if !foundSafe {
		t.Error("expected safe result for 10.2.0.1 on wg0 (not in baseline)")
	}
}

func TestCheckLocalDNSEnhanced_AllVPNDNS(t *testing.T) {
	// Only wg0 has DNS with +DefaultRoute
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return []byte(`Link 4 (wg0)
    Current Scopes: DNS
         Protocols: +DefaultRoute
       DNS Servers: 10.2.0.1
`), nil
	}))
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return []string{"ip: 10.2.0.1, netmask: no ECS"}, nil
	}))

	lt := &LeakTest{ID: "test-all-vpn"}
	lt.checkLocalDNSEnhanced()

	// All should be safe
	for _, r := range lt.DNSResults {
		if !r.IsSafe {
			t.Errorf("expected all safe, got unsafe: %+v", r)
		}
	}
}

func TestCheckLocalDNSEnhanced_FallsBackToBasic(t *testing.T) {
	// resolvectlStatusOutput fails
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("resolvectl not found")
	}))
	// Basic check path: resolvectl dns has VPN DNS
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return []byte("Link 3 (wg0): 10.2.0.1\n"), nil
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	// ECS check fails silently
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return nil, fmt.Errorf("lookup failed")
	}))

	lt := &LeakTest{ID: "test-fallback"}
	lt.checkLocalDNSEnhanced()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results from fallback")
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("VPN DNS should be safe via fallback")
	}
}

func TestCheckLocalDNSEnhanced_EmptyLinks(t *testing.T) {
	// resolvectlStatusOutput returns empty (no links parsed)
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return []byte("Global\n  LLMNR setting: yes\n"), nil
	}))
	// Falls back to basic
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return []byte("nameserver 10.64.0.1\n"), nil
	}))
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return nil, fmt.Errorf("lookup failed")
	}))

	lt := &LeakTest{ID: "test-empty-links"}
	lt.checkLocalDNSEnhanced()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results from fallback")
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("Mullvad DNS should be safe")
	}
}

func TestCheckLocalDNSEnhanced_NoDefaultRouteLinks(t *testing.T) {
	// All links have -DefaultRoute and no DNS
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return []byte(`Link 2 (wlan0)
    Current Scopes: DNS
         Protocols: -DefaultRoute
       DNS Servers: 192.168.1.1
`), nil
	}))
	// Falls back to basic since no DefaultRoute links produced results
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return nil, fmt.Errorf("lookup failed")
	}))

	lt := &LeakTest{ID: "test-no-default"}
	lt.checkLocalDNSEnhanced()

	if len(lt.DNSResults) == 0 {
		t.Fatal("expected DNS results from fallback")
	}
	// Falls back to "Could not determine"
	if lt.DNSResults[0].IsSafe {
		t.Error("should be unsafe when cannot determine DNS")
	}
}

// ---------------------------------------------------------------------------
// checkECS tests
// ---------------------------------------------------------------------------

func TestCheckECS_NoECS(t *testing.T) {
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		if domain == "whoami-ecs.v4.powerdns.org" {
			return []string{"ip: 10.2.0.1, netmask: no ECS"}, nil
		}
		return nil, fmt.Errorf("unexpected domain: %s", domain)
	}))

	lt := &LeakTest{ID: "test-ecs-safe"}
	lt.checkECS()

	if len(lt.DNSResults) != 1 {
		t.Fatalf("expected 1 result, got %d", len(lt.DNSResults))
	}
	if !lt.DNSResults[0].IsSafe {
		t.Error("no ECS should be safe")
	}
	if lt.DNSResults[0].Provider != "No ECS (safe)" {
		t.Errorf("Provider = %q, want %q", lt.DNSResults[0].Provider, "No ECS (safe)")
	}
	if lt.DNSResults[0].IP != "10.2.0.1" {
		t.Errorf("IP = %q, want %q", lt.DNSResults[0].IP, "10.2.0.1")
	}
}

func TestCheckECS_ECSLeak(t *testing.T) {
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		if domain == "whoami-ecs.v4.powerdns.org" {
			return []string{"ip: 73.251.160.112, netmask: 24"}, nil
		}
		return nil, fmt.Errorf("unexpected domain: %s", domain)
	}))

	lt := &LeakTest{ID: "test-ecs-leak"}
	lt.checkECS()

	if len(lt.DNSResults) != 1 {
		t.Fatalf("expected 1 result, got %d", len(lt.DNSResults))
	}
	if lt.DNSResults[0].IsSafe {
		t.Error("ECS leak should NOT be safe")
	}
	if lt.DNSResults[0].Provider != "ECS leak detected" {
		t.Errorf("Provider = %q, want %q", lt.DNSResults[0].Provider, "ECS leak detected")
	}
	if lt.DNSResults[0].IP != "73.251.160.112" {
		t.Errorf("IP = %q, want %q", lt.DNSResults[0].IP, "73.251.160.112")
	}
}

func TestCheckECS_LookupFails(t *testing.T) {
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return nil, fmt.Errorf("lookup failed")
	}))

	lt := &LeakTest{ID: "test-ecs-fail"}
	lt.checkECS()

	if len(lt.DNSResults) != 0 {
		t.Errorf("expected 0 results on failure, got %d", len(lt.DNSResults))
	}
}

func TestCheckECS_NoNetmaskInResponse(t *testing.T) {
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		return []string{"some other response"}, nil
	}))

	lt := &LeakTest{ID: "test-ecs-nonetmask"}
	lt.checkECS()

	if len(lt.DNSResults) != 0 {
		t.Errorf("expected 0 results when no netmask in response, got %d", len(lt.DNSResults))
	}
}

// ---------------------------------------------------------------------------
// extractIPFromECS tests (pure function)
// ---------------------------------------------------------------------------

func TestExtractIPFromECS(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"standard no ECS", "ip: 10.2.0.1, netmask: no ECS", "10.2.0.1"},
		{"standard with netmask", "ip: 73.251.160.112, netmask: 24", "73.251.160.112"},
		{"extra whitespace", "ip:  73.251.160.112 , netmask: 24", "73.251.160.112"},
		{"no ip prefix", "some other text", ""},
		{"empty string", "", ""},
		{"ip only no comma", "ip: 1.2.3.4", "1.2.3.4"},
		{"invalid IP", "ip: not-an-ip, netmask: 24", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIPFromECS(tt.input)
			if got != tt.expect {
				t.Errorf("extractIPFromECS(%q) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}

// vpnDNSProvider was removed — leak detection now uses ISP baseline comparison
// instead of hardcoded VPN provider DNS maps.

// ---------------------------------------------------------------------------
// testDNS integration: "local" provider skips domain resolution
// ---------------------------------------------------------------------------

func TestTestDNS_LocalProviderSkipsDomainResolution(t *testing.T) {
	var mu sync.Mutex
	queriedDomains := make(map[string]bool)
	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		mu.Lock()
		queriedDomains[domain] = true
		mu.Unlock()
		if domain == "whoami-ecs.v4.powerdns.org" {
			return []string{"ip: 10.2.0.1, netmask: no ECS"}, nil
		}
		return []string{"10.2.0.1"}, nil
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return nil, fmt.Errorf("no reverse DNS")
	}))
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return []byte("Link 4 (wg0)\n    Protocols: +DefaultRoute\n       DNS Servers: 10.2.0.1\n"), nil
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))

	// Only "local" and "powerdns" selected
	lt := &LeakTest{ID: "test-local-skip", Providers: []string{"powerdns", "local"}}
	lt.testDNS()

	mu.Lock()
	defer mu.Unlock()

	// powerdns domain should be queried
	if !queriedDomains["whoami.v4.powerdns.org"] {
		t.Error("expected powerdns domain to be queried")
	}
	// ECS domain should be queried (from checkLocalDNSEnhanced)
	if !queriedDomains["whoami-ecs.v4.powerdns.org"] {
		t.Error("expected ECS domain to be queried when local is enabled")
	}
}

// TestParseIPInfo_RejectsInvalidIP verifies the parser refuses garbage
// IP fields. Pre-fix, "definitely-not-an-ip" would propagate into
// LeakTest.IPResult.IP and corrupt leak-detection comparisons against
// cfg.BaselineIP (which uses string equality).
func TestParseIPInfo_RejectsInvalidIP(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty IP", `{"ip":"","org":"x"}`},
		{"obviously not an IP", `{"ip":"definitely-not-an-ip","org":"x"}`},
		{"hostname instead of IP", `{"ip":"example.com","org":"x"}`},
		{"injected URL", `{"ip":"http://evil/","org":"x"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseIPInfo([]byte(c.body))
			if err == nil {
				t.Errorf("parseIPInfo(%q) returned nil err; expected validation failure", c.body)
			}
		})
	}
}

// TestParseIfconfig_RejectsInvalidIP — same as above for ifconfig.co
// response shape (uses ip_addr field).
func TestParseIfconfig_RejectsInvalidIP(t *testing.T) {
	cases := []string{
		`{"ip_addr":""}`,
		`{"ip_addr":"not.an.ip.at.all"}`,
		`{"ip_addr":"<script>alert(1)</script>"}`,
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			_, err := parseIfconfig([]byte(body))
			if err == nil {
				t.Errorf("parseIfconfig(%q) returned nil err", body)
			}
		})
	}
}

// TestParseIPAPI_OrgFallback pins the ISP-or-Org fallback contract:
//
//   org := v.ISP
//   if org == "" {
//       org = v.Org
//   }
//
// ip-api.com sometimes populates only one of these fields. The
// dashboard ISP indicator depends on this fallback to display
// SOMETHING when one field is empty. A regression that flipped the
// condition (`!= ""`) would always pick Org first — masking the ISP
// when both are present, and showing empty when only ISP is present.
func TestParseIPAPI_OrgFallback(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "ISP set, Org set → ISP wins",
			body: `{"query":"1.2.3.4","isp":"Comcast","org":"Comcast Cable"}`,
			want: "Comcast",
		},
		{
			name: "ISP empty, Org set → Org used as fallback",
			body: `{"query":"1.2.3.4","isp":"","org":"Comcast Cable"}`,
			want: "Comcast Cable",
		},
		{
			name: "ISP set, Org empty → ISP used (no fallback needed)",
			body: `{"query":"1.2.3.4","isp":"Verizon","org":""}`,
			want: "Verizon",
		},
		{
			name: "both empty → empty result (rare but valid)",
			body: `{"query":"1.2.3.4","isp":"","org":""}`,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIPAPI([]byte(tt.body))
			if err != nil {
				t.Fatalf("parseIPAPI: %v", err)
			}
			if got.org != tt.want {
				t.Errorf("org = %q, want %q", got.org, tt.want)
			}
		})
	}
}

// TestParseIPAPI_RejectsInvalidIP — same as above for ip-api.com
// response shape (uses query field).
func TestParseIPAPI_RejectsInvalidIP(t *testing.T) {
	cases := []string{
		`{"query":""}`,
		`{"query":"garbage","isp":"x"}`,
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			_, err := parseIPAPI([]byte(body))
			if err == nil {
				t.Errorf("parseIPAPI(%q) returned nil err", body)
			}
		})
	}
}

// TestParseIPInfo_AcceptsValidIPs sanity check.
func TestParseIPInfo_AcceptsValidIPs(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"v4", `{"ip":"203.0.113.5","org":"AS1 x"}`, "203.0.113.5"},
		{"v6", `{"ip":"2001:db8::1","org":"AS1 x"}`, "2001:db8::1"},
		{"v6 loopback", `{"ip":"::1"}`, "::1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := parseIPInfo([]byte(c.body))
			if err != nil {
				t.Fatalf("parseIPInfo: %v", err)
			}
			if r.ip != c.want {
				t.Errorf("ip = %q, want %q", r.ip, c.want)
			}
		})
	}
}

// TestTestDNS_HangingLookupBoundedByDeadline verifies the testDNS
// collector loop doesn't wait forever when net.LookupTXT hangs (no
// context-based timeout). Pre-fix the loop blocked on <-results
// indefinitely; the Go resolver's internal per-query retry behavior
// would eventually time out (~5s × N retries) but a leak test
// running with all-dead DNS would freeze the UI.
//
// Previously skipped under -race because the test deliberately
// leaves the stub goroutine parked inside lookupTXTFunc forever,
// and mockLookupTXT's cleanup write to lookupTXTFunc raced the
// parked goroutine's read. testDNS now snapshots lookupTXTFunc
// into a local before spawning the per-domain goroutines, so the
// goroutines read a closure capture instead of the package var —
// race-free under -race.
func TestTestDNS_HangingLookupBoundedByDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("network-timing test")
	}

	t.Cleanup(mockLookupTXT(func(domain string) ([]string, error) {
		select {} // hang forever; goroutine is leaked deliberately
	}))
	t.Cleanup(mockLookupAddr(func(addr string) ([]string, error) {
		return []string{"dns.example."}, nil
	}))
	t.Cleanup(mockResolvectlStatusOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockResolvectlOutput(func(_ context.Context) ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))
	t.Cleanup(mockReadResolvConf(func() ([]byte, error) {
		return nil, fmt.Errorf("not available")
	}))

	lt := &LeakTest{
		ID:          "test-hang",
		BaselineDNS: []string{"8.8.8.8"},
		Providers:   []string{"cloudflare"},
	}

	done := make(chan struct{})
	start := time.Now()
	go func() {
		lt.testDNS()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatalf("testDNS did not return within 15s; deadline-clamp not enforced")
	}
	elapsed := time.Since(start)
	// The clamp is 8s; allow a generous wall-clock buffer for CI.
	if elapsed > 12*time.Second {
		t.Errorf("testDNS took %v with hanging lookups; expected ~8s", elapsed)
	}
}

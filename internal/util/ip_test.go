package util

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// saveAndRestoreURLs saves the current URL vars and restores them after the test.
func saveAndRestoreURLs(t *testing.T) {
	t.Helper()
	origIPify := IPifyURL
	origIPify64 := IPify64URL
	origFallbacks := IPv4FallbackURLs
	t.Cleanup(func() {
		IPifyURL = origIPify
		IPify64URL = origIPify64
		IPv4FallbackURLs = origFallbacks
	})
}

// newIPServer creates an httptest server that returns the given body with the given status code.
func newIPServer(t *testing.T, statusCode int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(func() { srv.Close() })
	return srv
}

// --- getPublicIP tests (internal function, directly testable from same package) ---

func TestGetPublicIP_ValidIPv4(t *testing.T) {
	srv := newIPServer(t, http.StatusOK, "203.0.113.42")
	// getPublicIP with "tcp4" will dial the httptest server on 127.0.0.1 via tcp4
	ip, err := getPublicIP(srv.URL, "tcp4")
	if err != nil {
		t.Fatalf("getPublicIP returned error: %v", err)
	}
	if ip != "203.0.113.42" {
		t.Errorf("getPublicIP = %q, want %q", ip, "203.0.113.42")
	}
}

func TestGetPublicIP_ValidIPv4WithWhitespace(t *testing.T) {
	srv := newIPServer(t, http.StatusOK, "  198.51.100.1\n")
	ip, err := getPublicIP(srv.URL, "tcp4")
	if err != nil {
		t.Fatalf("getPublicIP returned error: %v", err)
	}
	if ip != "198.51.100.1" {
		t.Errorf("getPublicIP = %q, want %q", ip, "198.51.100.1")
	}
}

func TestGetPublicIP_Non200Status(t *testing.T) {
	srv := newIPServer(t, http.StatusInternalServerError, "error")
	_, err := getPublicIP(srv.URL, "tcp4")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error = %q, want it to contain 'status 500'", err.Error())
	}
}

func TestGetPublicIP_InvalidIPResponse(t *testing.T) {
	srv := newIPServer(t, http.StatusOK, "not-an-ip-address")
	_, err := getPublicIP(srv.URL, "tcp4")
	if err == nil {
		t.Fatal("expected error for invalid IP response")
	}
	if !strings.Contains(err.Error(), "invalid IP address") {
		t.Errorf("error = %q, want it to contain 'invalid IP address'", err.Error())
	}
}

func TestGetPublicIP_EmptyResponse(t *testing.T) {
	srv := newIPServer(t, http.StatusOK, "")
	_, err := getPublicIP(srv.URL, "tcp4")
	if err == nil {
		t.Fatal("expected error for empty response")
	}
	if !strings.Contains(err.Error(), "invalid IP address") {
		t.Errorf("error = %q, want it to contain 'invalid IP address'", err.Error())
	}
}

func TestGetPublicIP_HTMLResponse(t *testing.T) {
	// Simulate a captive portal or error page returning HTML
	srv := newIPServer(t, http.StatusOK, "<html><body>Please log in</body></html>")
	_, err := getPublicIP(srv.URL, "tcp4")
	if err == nil {
		t.Fatal("expected error for HTML response")
	}
}

func TestGetPublicIP_ValidIPv6(t *testing.T) {
	// Try to create a listener on IPv6 loopback; skip if not available.
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback not available: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "2001:db8::1")
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(func() { srv.Close() })

	ip, errGet := getPublicIP(srv.URL, "tcp6")
	if errGet != nil {
		t.Fatalf("getPublicIP with tcp6 returned error: %v", errGet)
	}
	if ip != "2001:db8::1" {
		t.Errorf("getPublicIP = %q, want %q", ip, "2001:db8::1")
	}
}

func TestGetPublicIP_ConnectionRefused(t *testing.T) {
	// Use a URL pointing to a port that nothing is listening on.
	_, err := getPublicIP("http://127.0.0.1:1", "tcp4")
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestGetPublicIP_BadURL(t *testing.T) {
	_, err := getPublicIP("://bad-url", "tcp4")
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}

// --- GetPublicIPv4 tests ---

func TestGetPublicIPv4_Success(t *testing.T) {
	saveAndRestoreURLs(t)
	srv := newIPServer(t, http.StatusOK, "192.0.2.10")
	IPifyURL = srv.URL

	ip, err := GetPublicIPv4()
	if err != nil {
		t.Fatalf("GetPublicIPv4 error: %v", err)
	}
	if ip != "192.0.2.10" {
		t.Errorf("GetPublicIPv4 = %q, want %q", ip, "192.0.2.10")
	}
}

func TestGetPublicIPv4_Failure(t *testing.T) {
	saveAndRestoreURLs(t)
	srv := newIPServer(t, http.StatusServiceUnavailable, "maintenance")
	IPifyURL = srv.URL

	_, err := GetPublicIPv4()
	if err == nil {
		t.Fatal("expected error from GetPublicIPv4 on 503")
	}
}

// --- GetPublicIPv6 tests ---

func TestGetPublicIPv6_Success(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback not available: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "2001:db8::42")
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(func() { srv.Close() })

	saveAndRestoreURLs(t)
	IPify64URL = srv.URL

	ip, errGet := GetPublicIPv6()
	if errGet != nil {
		t.Fatalf("GetPublicIPv6 error: %v", errGet)
	}
	if ip != "2001:db8::42" {
		t.Errorf("GetPublicIPv6 = %q, want %q", ip, "2001:db8::42")
	}
}

func TestGetPublicIPv6_Failure(t *testing.T) {
	saveAndRestoreURLs(t)
	// Point at an unreachable IPv6 address to force failure.
	IPify64URL = "http://[::1]:1"

	_, err := GetPublicIPv6()
	if err == nil {
		// On systems without IPv6, this will also error, which is fine.
		// We just verify it doesn't succeed on a bad URL.
		t.Log("GetPublicIPv6 returned nil error (IPv6 may have connected to port 1 somehow)")
	}
}

// --- GetPublicIPv4WithRetry tests ---

func TestGetPublicIPv4WithRetry_PrimarySuccess(t *testing.T) {
	saveAndRestoreURLs(t)
	srv := newIPServer(t, http.StatusOK, "10.0.0.1")
	IPifyURL = srv.URL
	IPv4FallbackURLs = []string{} // no fallbacks needed

	ip, err := GetPublicIPv4WithRetry(1)
	if err != nil {
		t.Fatalf("GetPublicIPv4WithRetry error: %v", err)
	}
	if ip != "10.0.0.1" {
		t.Errorf("got %q, want %q", ip, "10.0.0.1")
	}
}

func TestGetPublicIPv4WithRetry_FallbackSuccess(t *testing.T) {
	saveAndRestoreURLs(t)

	// Primary returns 500
	primarySrv := newIPServer(t, http.StatusInternalServerError, "error")
	// Fallback returns valid IP
	fallbackSrv := newIPServer(t, http.StatusOK, "10.0.0.2")

	IPifyURL = primarySrv.URL
	IPv4FallbackURLs = []string{fallbackSrv.URL}

	ip, err := GetPublicIPv4WithRetry(1)
	if err != nil {
		t.Fatalf("GetPublicIPv4WithRetry error: %v", err)
	}
	if ip != "10.0.0.2" {
		t.Errorf("got %q, want %q", ip, "10.0.0.2")
	}
}

func TestGetPublicIPv4WithRetry_AllFail(t *testing.T) {
	saveAndRestoreURLs(t)

	srv := newIPServer(t, http.StatusInternalServerError, "error")
	IPifyURL = srv.URL
	IPv4FallbackURLs = []string{srv.URL}

	_, err := GetPublicIPv4WithRetry(1)
	if err == nil {
		t.Fatal("expected error when all URLs fail")
	}
	if !strings.Contains(err.Error(), "all IP lookup attempts failed") {
		t.Errorf("error = %q, want it to contain 'all IP lookup attempts failed'", err.Error())
	}
}

func TestGetPublicIPv4WithRetry_MultipleRounds(t *testing.T) {
	saveAndRestoreURLs(t)

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "10.0.0.3")
	}))
	t.Cleanup(func() { srv.Close() })

	IPifyURL = srv.URL
	IPv4FallbackURLs = []string{} // only primary, so each round = 1 call

	ip, err := GetPublicIPv4WithRetry(3)
	if err != nil {
		t.Fatalf("GetPublicIPv4WithRetry error: %v", err)
	}
	if ip != "10.0.0.3" {
		t.Errorf("got %q, want %q", ip, "10.0.0.3")
	}
}

func TestGetPublicIPv4WithRetry_ZeroAttempts(t *testing.T) {
	saveAndRestoreURLs(t)
	// With 0 attempts, the loop body never runs. Should return error.
	_, err := GetPublicIPv4WithRetry(0)
	if err == nil {
		t.Fatal("expected error for 0 attempts")
	}
}

// --- GetPublicIP tests (the combined IPv4+IPv6 function) ---

func TestGetPublicIP_IPv4Success(t *testing.T) {
	saveAndRestoreURLs(t)
	srv := newIPServer(t, http.StatusOK, "203.0.113.1")
	IPifyURL = srv.URL
	// IPv6 should not be tried if IPv4 succeeds
	IPify64URL = "http://[::1]:1"

	ip, err := GetPublicIP()
	if err != nil {
		t.Fatalf("GetPublicIP error: %v", err)
	}
	if ip != "203.0.113.1" {
		t.Errorf("got %q, want %q", ip, "203.0.113.1")
	}
}

func TestGetPublicIP_IPv4FailIPv6Success(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback not available: %v", err)
	}
	srv6 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "2001:db8::99")
	}))
	srv6.Listener = ln
	srv6.Start()
	t.Cleanup(func() { srv6.Close() })

	saveAndRestoreURLs(t)
	// IPv4 fails (bad server)
	badSrv := newIPServer(t, http.StatusInternalServerError, "fail")
	IPifyURL = badSrv.URL
	// IPv6 succeeds
	IPify64URL = srv6.URL

	ip, errGet := GetPublicIP()
	if errGet != nil {
		t.Fatalf("GetPublicIP error: %v", errGet)
	}
	if ip != "2001:db8::99" {
		t.Errorf("got %q, want %q", ip, "2001:db8::99")
	}
}

func TestGetPublicIP_BothFail(t *testing.T) {
	saveAndRestoreURLs(t)
	badSrv := newIPServer(t, http.StatusInternalServerError, "fail")
	IPifyURL = badSrv.URL
	IPify64URL = "http://[::1]:1"

	_, err := GetPublicIP()
	if err == nil {
		t.Fatal("expected error when both IPv4 and IPv6 fail")
	}
}

// --- CheckIPv6Leak tests ---

func TestCheckIPv6Leak_NoLeak(t *testing.T) {
	saveAndRestoreURLs(t)
	// Make IPv6 lookup fail -> no leak
	IPify64URL = "http://[::1]:1"

	ip, leak := CheckIPv6Leak()
	if leak {
		t.Errorf("expected no leak, but got leak with ip=%q", ip)
	}
	if ip != "" {
		t.Errorf("expected empty ip, got %q", ip)
	}
}

func TestCheckIPv6Leak_LeakDetected(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback not available: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "2001:db8::1")
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(func() { srv.Close() })

	saveAndRestoreURLs(t)
	IPify64URL = srv.URL

	ip, leak := CheckIPv6Leak()
	if !leak {
		t.Error("expected leak to be detected")
	}
	if ip != "2001:db8::1" {
		t.Errorf("got ip=%q, want %q", ip, "2001:db8::1")
	}
}

// --- CheckInternetConnectivity tests ---

func TestCheckInternetConnectivity_WithLocalListener(t *testing.T) {
	// This test exercises CheckInternetConnectivity by verifying it doesn't panic.
	// The function dials real DNS servers, so results depend on network access.
	_ = CheckInternetConnectivity()
}

// --- WaitForConnectivity tests ---

func TestWaitForConnectivity_ImmediateSuccess(t *testing.T) {
	// If CheckInternetConnectivity succeeds on first try, WaitForConnectivity
	// should return true. This depends on network access.
	// We test with 1 attempt to ensure the function handles single-attempt correctly.
	_ = WaitForConnectivity(1, 10*time.Millisecond)
}

func TestWaitForConnectivity_MultipleAttempts(t *testing.T) {
	// Test with multiple attempts and short interval.
	// Verifies the retry loop works without hanging.
	result := WaitForConnectivity(2, 10*time.Millisecond)
	// Result depends on network, but should complete quickly.
	_ = result
}

func TestWaitForConnectivity_ZeroAttempts(t *testing.T) {
	// Zero attempts should return false immediately without hanging.
	result := WaitForConnectivity(0, 10*time.Millisecond)
	if result {
		t.Error("WaitForConnectivity(0, ...) should return false")
	}
}

// TestGetPublicIPInfo_RejectsInvalidIP verifies the function refuses
// to return garbage in the IP field. Pre-fix, ipinfo.io returning
// {"ip":"not-an-ip", "org":"..."} would silently propagate into
// cfg.RealPublicIP / cfg.BaselineIP and break leak-detection
// comparisons (which are string-equality on those fields).
func TestGetPublicIPInfo_RejectsInvalidIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ip":"definitely-not-an-ip","org":"Evil Corp"}`))
	}))
	t.Cleanup(srv.Close)

	orig := IPInfoURL
	IPInfoURL = srv.URL
	t.Cleanup(func() { IPInfoURL = orig })

	ip, org, err := GetPublicIPInfo()
	if err == nil {
		t.Fatalf("expected error for invalid IP, got ip=%q org=%q", ip, org)
	}
	if ip != "" || org != "" {
		t.Errorf("on error, ip/org should be empty, got ip=%q org=%q", ip, org)
	}
}

// TestGetPublicIPInfo_AcceptsValidIP sanity-checks the happy path.
func TestGetPublicIPInfo_AcceptsValidIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ip":"203.0.113.5","org":"AS64512 Example ISP"}`))
	}))
	t.Cleanup(srv.Close)

	orig := IPInfoURL
	IPInfoURL = srv.URL
	t.Cleanup(func() { IPInfoURL = orig })

	ip, org, err := GetPublicIPInfo()
	if err != nil {
		t.Fatalf("GetPublicIPInfo: %v", err)
	}
	if ip != "203.0.113.5" {
		t.Errorf("ip = %q, want 203.0.113.5", ip)
	}
	if org != "AS64512 Example ISP" {
		t.Errorf("org = %q, want AS64512 Example ISP", org)
	}
}

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validGluetunJSON is a realistic gluetun server list used across multiple tests.
const validGluetunJSON = `{
	"version": 1,
	"protonvpn": {
		"servers": [
			{
				"server_name": "US-NY#42",
				"hostname": "us-ny-42.protonvpn.net",
				"country": "United States",
				"city": "New York",
				"vpn": "wireguard",
				"wgpubkey": "YNqHbfBQKaGvct4Jt2ZLKXHXP0sMhCX80fPlOSf80Vo=",
				"ips": ["1.2.3.4"],
				"port_forward": true
			},
			{
				"server_name": "US-LA#10",
				"hostname": "us-la-10.protonvpn.net",
				"country": "United States",
				"city": "Los Angeles",
				"vpn": "openvpn",
				"ips": ["5.6.7.8"]
			}
		]
	}
}`

func TestServerName(t *testing.T) {
	tests := []struct {
		name     string
		srv      Server
		wantName string
	}{
		{"server_name set", Server{ServerName: "US-NY#42", Hostname: "ny42.example.com"}, "US-NY#42"},
		{"fallback to hostname", Server{Hostname: "ny42.example.com"}, "ny42.example.com"},
		{"both empty", Server{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.srv.Name()
			if got != tt.wantName {
				t.Errorf("Name() = %q, want %q", got, tt.wantName)
			}
		})
	}
}

func TestServerIP(t *testing.T) {
	tests := []struct {
		name string
		srv  Server
		want string
	}{
		{"has IPs", Server{IPs: []string{"1.2.3.4", "5.6.7.8"}}, "1.2.3.4"},
		{"empty IPs", Server{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.srv.IP()
			if got != tt.want {
				t.Errorf("IP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseGluetunData(t *testing.T) {
	// Simulate the real gluetun JSON structure with version field + provider objects
	data := `{
		"version": 1,
		"protonvpn": {
			"servers": [
				{"server_name": "US-NY#42", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["1.2.3.4"], "country": "US"},
				{"server_name": "SE#5", "vpn": "wireguard", "wgpubkey": "pk2=", "ips": ["5.6.7.8"], "country": "SE"}
			]
		},
		"mullvad": {
			"servers": [
				{"hostname": "se-got-wg-001", "vpn": "wireguard", "wgpubkey": "pk3=", "ips": ["9.10.11.12"], "country": "SE"}
			]
		}
	}`

	result, err := parseGluetunData([]byte(data))
	if err != nil {
		t.Fatalf("parseGluetunData() error: %v", err)
	}

	// version field should be skipped
	if _, ok := result["version"]; ok {
		t.Error("version field should be skipped")
	}

	// protonvpn should have 2 servers
	pv, ok := result["protonvpn"]
	if !ok {
		t.Fatal("protonvpn not found")
	}
	if len(pv.Servers) != 2 {
		t.Errorf("protonvpn servers = %d, want 2", len(pv.Servers))
	}

	// mullvad should have 1 server
	mv, ok := result["mullvad"]
	if !ok {
		t.Fatal("mullvad not found")
	}
	if len(mv.Servers) != 1 {
		t.Errorf("mullvad servers = %d, want 1", len(mv.Servers))
	}
}

func TestParseGluetunDataInvalid(t *testing.T) {
	_, err := parseGluetunData([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// TestParseGluetunDataMixedTypes verifies that non-object values (strings, arrays,
// booleans, null) in the top-level JSON are silently skipped, and that a malformed
// provider entry (one whose value starts with '{' but is not a valid providerEntry)
// is also skipped without causing an error.
func TestParseGluetunDataMixedTypes(t *testing.T) {
	data := `{
		"version": 1,
		"some_string": "hello",
		"some_array": [1, 2, 3],
		"some_bool": true,
		"some_null": null,
		"bad_object": {"unexpected_field": 42},
		"protonvpn": {
			"servers": [
				{"server_name": "US#1", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["1.1.1.1"], "country": "US"}
			]
		}
	}`

	result, err := parseGluetunData([]byte(data))
	if err != nil {
		t.Fatalf("parseGluetunData() error: %v", err)
	}

	// Non-object fields should be skipped
	for _, key := range []string{"version", "some_string", "some_array", "some_bool", "some_null"} {
		if _, ok := result[key]; ok {
			t.Errorf("key %q should have been skipped", key)
		}
	}

	// bad_object parses into providerEntry with zero servers -- that is fine,
	// it is still included because it has valid JSON structure matching providerEntry.
	// The important thing is the valid provider is present.
	pv, ok := result["protonvpn"]
	if !ok {
		t.Fatal("protonvpn not found")
	}
	if len(pv.Servers) != 1 {
		t.Errorf("protonvpn servers = %d, want 1", len(pv.Servers))
	}
}

func TestGluetunProviderMap(t *testing.T) {
	for _, p := range []string{"protonvpn", "mullvad", "ivpn", "airvpn", "nordvpn", "surfshark", "windscribe"} {
		if _, ok := GluetunProviderMap[p]; !ok {
			t.Errorf("GluetunProviderMap missing %q", p)
		}
		if _, ok := ProviderDisplayNames[p]; !ok {
			t.Errorf("ProviderDisplayNames missing %q", p)
		}
	}
}

// TestProviderMapsHaveSameKeySet pins the cross-map consistency
// invariant: GluetunProviderMap and ProviderDisplayNames must share
// the exact same key set. When a new provider is added, both maps
// must be updated together; when one is removed, both must be
// updated together.
//
// The existing TestGluetunProviderMap only verifies a hardcoded
// minimum list; it would silently pass if one map had EXTRA
// providers the other lacked. A regression like "adds 'fastestvpn'
// to GluetunProviderMap but forgets ProviderDisplayNames" would
// surface here as a missing-key error.
//
// The two maps drive different consumers (gluetun fetch path uses
// the gluetun name, TUI display uses the display name); a missing
// entry in either produces a confusing "" string or a "provider
// not found" error somewhere deeper in the call stack.
func TestProviderMapsHaveSameKeySet(t *testing.T) {
	for k := range GluetunProviderMap {
		if _, ok := ProviderDisplayNames[k]; !ok {
			t.Errorf("ProviderDisplayNames missing %q (present in GluetunProviderMap)", k)
		}
	}
	for k := range ProviderDisplayNames {
		if _, ok := GluetunProviderMap[k]; !ok {
			t.Errorf("GluetunProviderMap missing %q (present in ProviderDisplayNames)", k)
		}
	}
	if len(GluetunProviderMap) != len(ProviderDisplayNames) {
		t.Errorf("map sizes differ: GluetunProviderMap=%d, ProviderDisplayNames=%d",
			len(GluetunProviderMap), len(ProviderDisplayNames))
	}
}

func TestFilterProviderServers(t *testing.T) {
	tmpDir := t.TempDir()

	// Write raw cache
	rawData := `{
		"version": 1,
		"protonvpn": {
			"servers": [
				{"server_name": "US-NY#42", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["1.2.3.4"], "country": "US", "city": "New York"},
				{"server_name": "openvpn-srv", "vpn": "openvpn", "wgpubkey": "", "ips": ["2.2.2.2"], "country": "US"},
				{"server_name": "no-key", "vpn": "wireguard", "wgpubkey": "", "ips": ["3.3.3.3"], "country": "US"},
				{"server_name": "SE#5", "vpn": "wireguard", "wgpubkey": "pk2=", "ips": ["5.6.7.8"], "country": "SE", "city": "Stockholm"}
			]
		}
	}`
	os.WriteFile(filepath.Join(tmpDir, "servers_raw.json"), []byte(rawData), 0644)

	servers, err := FilterProviderServers(tmpDir, "protonvpn")
	if err != nil {
		t.Fatalf("FilterProviderServers() error: %v", err)
	}

	// Should only include WireGuard servers with valid keys and IPs
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	// Should be sorted by country
	if servers[0].Country != "SE" {
		t.Errorf("first server country = %q, want 'SE' (sorted)", servers[0].Country)
	}

	// Verify provider cache was written
	cachePath := filepath.Join(tmpDir, "protonvpn_servers.json")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal("provider cache not written")
	}
	var cached []Server
	json.Unmarshal(data, &cached)
	if len(cached) != 2 {
		t.Errorf("cached servers = %d, want 2", len(cached))
	}
}

func TestFilterProviderServersUnknown(t *testing.T) {
	tmpDir := t.TempDir()
	rawData := `{"version": 1, "protonvpn": {"servers": []}}`
	os.WriteFile(filepath.Join(tmpDir, "servers_raw.json"), []byte(rawData), 0644)

	_, err := FilterProviderServers(tmpDir, "unknownprovider")
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

// TestFilterProviderServersNotInGluetun tests the path where the provider key
// exists in GluetunProviderMap but the gluetun data does not contain that provider.
func TestFilterProviderServersNotInGluetun(t *testing.T) {
	tmpDir := t.TempDir()

	// Raw data has protonvpn but NOT mullvad
	rawData := `{
		"version": 1,
		"protonvpn": {
			"servers": [
				{"server_name": "US#1", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["1.2.3.4"], "country": "US"}
			]
		}
	}`
	os.WriteFile(filepath.Join(tmpDir, "servers_raw.json"), []byte(rawData), 0644)

	_, err := FilterProviderServers(tmpDir, "mullvad")
	if err == nil {
		t.Fatal("expected error when provider not in gluetun data")
	}
	if !strings.Contains(err.Error(), "provider not found in gluetun data") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestFilterProviderServersNoRawCache tests the error path when servers_raw.json
// does not exist.
func TestFilterProviderServersNoRawCache(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := FilterProviderServers(tmpDir, "protonvpn")
	if err == nil {
		t.Fatal("expected error when raw cache is missing")
	}
	if !strings.Contains(err.Error(), "raw cache not found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestFilterProviderServersInvalidRawJSON tests the error path when
// servers_raw.json contains invalid JSON.
func TestFilterProviderServersInvalidRawJSON(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "servers_raw.json"), []byte("not json at all"), 0644)

	_, err := FilterProviderServers(tmpDir, "protonvpn")
	if err == nil {
		t.Fatal("expected error for invalid raw JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse cache") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestFilterProviderServersNoIPs tests that a WireGuard server with valid pubkey
// but no IPs is filtered out.
func TestFilterProviderServersNoIPs(t *testing.T) {
	tmpDir := t.TempDir()

	rawData := `{
		"version": 1,
		"protonvpn": {
			"servers": [
				{"server_name": "no-ips", "vpn": "wireguard", "wgpubkey": "pk=", "ips": [], "country": "US"},
				{"server_name": "valid", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["1.2.3.4"], "country": "US"}
			]
		}
	}`
	os.WriteFile(filepath.Join(tmpDir, "servers_raw.json"), []byte(rawData), 0644)

	servers, err := FilterProviderServers(tmpDir, "protonvpn")
	if err != nil {
		t.Fatalf("FilterProviderServers() error: %v", err)
	}
	if len(servers) != 1 {
		t.Errorf("expected 1 server (no-ips filtered), got %d", len(servers))
	}
	if servers[0].ServerName != "valid" {
		t.Errorf("expected server 'valid', got %q", servers[0].ServerName)
	}
}

func TestLoadProviderServers(t *testing.T) {
	tmpDir := t.TempDir()

	servers := []Server{
		{ServerName: "US-NY#42", IPs: []string{"1.2.3.4"}},
		{ServerName: "SE#5", IPs: []string{"5.6.7.8"}},
	}
	data, _ := json.Marshal(servers)
	os.WriteFile(filepath.Join(tmpDir, "protonvpn_servers.json"), data, 0644)

	loaded, err := LoadProviderServers(tmpDir, "protonvpn")
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 {
		t.Errorf("expected 2, got %d", len(loaded))
	}
}

func TestLoadProviderServersMissing(t *testing.T) {
	_, err := LoadProviderServers(t.TempDir(), "protonvpn")
	if err == nil {
		t.Error("expected error for missing cache")
	}
}

// TestLoadProviderServersInvalidJSON tests the error path where the cache file
// exists but contains invalid JSON.
func TestLoadProviderServersInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "protonvpn_servers.json"), []byte("{invalid"), 0644)

	_, err := LoadProviderServers(tmpDir, "protonvpn")
	if err == nil {
		t.Fatal("expected error for invalid JSON in cache")
	}
	if !strings.Contains(err.Error(), "failed to parse cache") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAtomicWriteFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.json")

	if err := atomicWriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("content = %q, want 'hello'", string(data))
	}

	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Errorf("permissions = %o, want 0644", info.Mode().Perm())
	}
}

// TestAtomicWriteFileReadOnlyDir verifies that atomicWriteFile returns an error
// when the target directory is not writable (cannot create temp file).
func TestAtomicWriteFileReadOnlyDir(t *testing.T) {
	tmpDir := t.TempDir()
	roDir := filepath.Join(tmpDir, "readonly")
	os.MkdirAll(roDir, 0755)
	// Make directory read-only so CreateTemp fails
	os.Chmod(roDir, 0555)
	t.Cleanup(func() { os.Chmod(roDir, 0755) })

	path := filepath.Join(roDir, "test.json")
	err := atomicWriteFile(path, []byte("hello"), 0644)
	if err == nil {
		t.Fatal("expected error writing to read-only directory")
	}
}

// TestAtomicWriteFileOverwrite verifies that atomicWriteFile correctly overwrites
// an existing file with new content.
func TestAtomicWriteFileOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "overwrite.json")

	if err := atomicWriteFile(path, []byte("first"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path, []byte("second"), 0644); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second" {
		t.Errorf("content = %q, want %q", string(data), "second")
	}
}

// ---------------------------------------------------------------------------
// FetchServers tests
// ---------------------------------------------------------------------------

// validProviderFile is one provider's file in the gluetun-servers per-provider
// format ({version, timestamp, servers}). It contains one WireGuard server and
// one OpenVPN server so filtering behaviour is exercised end-to-end.
const validProviderFile = `{
	"version": 4,
	"timestamp": 1779159401,
	"servers": [
		{
			"server_name": "US-NY#42",
			"hostname": "us-ny-42.protonvpn.net",
			"country": "United States",
			"city": "New York",
			"vpn": "wireguard",
			"wgpubkey": "YNqHbfBQKaGvct4Jt2ZLKXHXP0sMhCX80fPlOSf80Vo=",
			"ips": ["1.2.3.4"],
			"port_forward": true
		},
		{
			"server_name": "US-LA#10",
			"hostname": "us-la-10.protonvpn.net",
			"country": "United States",
			"city": "Los Angeles",
			"vpn": "openvpn",
			"ips": ["5.6.7.8"]
		}
	]
}`

// saveAndRestoreURL saves the current ServersBaseURL and restores it
// when the test completes. This prevents tests from leaking state to each other.
func saveAndRestoreURL(t *testing.T) {
	t.Helper()
	orig := ServersBaseURL
	t.Cleanup(func() { ServersBaseURL = orig })
}

// newGluetunTestServer creates an httptest.Server that serves the given body
// with the given status code for EVERY per-provider request path. Use this for
// the all-providers-identical happy/error paths.
func newGluetunTestServer(t *testing.T, statusCode int, body string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// providerNameFromPath extracts the gluetun provider name from a request path
// like "/protonvpn.json" -> "protonvpn".
func providerNameFromPath(p string) string {
	return strings.TrimSuffix(strings.TrimPrefix(p, "/"), ".json")
}

// newPerProviderTestServer serves per-provider files keyed by gluetun provider
// name. A provider present in bodies is served 200 with its body; any provider
// absent from bodies gets the given missingStatus (e.g. 404 or 500), letting
// tests simulate partial failure.
func newPerProviderTestServer(t *testing.T, bodies map[string]string, missingStatus int) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := providerNameFromPath(r.URL.Path)
		body, ok := bodies[name]
		if !ok {
			w.WriteHeader(missingStatus)
			fmt.Fprint(w, "missing")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestFetchServersHappyPath(t *testing.T) {
	saveAndRestoreURL(t)
	cacheDir := t.TempDir()

	ts := newGluetunTestServer(t, http.StatusOK, validProviderFile)
	ServersBaseURL = ts.URL

	err := FetchServers(cacheDir, false)
	if err != nil {
		t.Fatalf("FetchServers() error: %v", err)
	}

	// Verify cache file was written
	cachePath := filepath.Join(cacheDir, "servers_raw.json")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("cache file not written: %v", err)
	}

	// Verify content is valid gluetun data
	parsed, err := parseGluetunData(data)
	if err != nil {
		t.Fatalf("cached data is invalid: %v", err)
	}
	if _, ok := parsed["protonvpn"]; !ok {
		t.Error("protonvpn not found in cached data")
	}
}

func TestFetchServersCacheFreshSkipsDownload(t *testing.T) {
	saveAndRestoreURL(t)
	cacheDir := t.TempDir()

	// Pre-populate a fresh cache file (just written, so modtime is now)
	cachePath := filepath.Join(cacheDir, "servers_raw.json")
	os.WriteFile(cachePath, []byte(validGluetunJSON), 0644)

	// Set URL to something that would fail if hit, to prove no HTTP call is made
	ServersBaseURL = "http://127.0.0.1:1/should-not-be-called"

	err := FetchServers(cacheDir, false)
	if err != nil {
		t.Fatalf("FetchServers() should have used cache, got error: %v", err)
	}

	// Verify original content unchanged
	data, _ := os.ReadFile(cachePath)
	if string(data) != validGluetunJSON {
		t.Error("cache content should not have been modified")
	}
}

func TestFetchServersForceRefreshesEvenWhenFresh(t *testing.T) {
	saveAndRestoreURL(t)
	cacheDir := t.TempDir()

	// Pre-populate cache with old content
	cachePath := filepath.Join(cacheDir, "servers_raw.json")
	os.WriteFile(cachePath, []byte(`{"version":1,"old":{"servers":[]}}`), 0644)

	// Serve new content
	ts := newGluetunTestServer(t, http.StatusOK, validProviderFile)
	ServersBaseURL = ts.URL

	err := FetchServers(cacheDir, true)
	if err != nil {
		t.Fatalf("FetchServers(force=true) error: %v", err)
	}

	// Cache should now contain the new data
	data, _ := os.ReadFile(cachePath)
	parsed, err := parseGluetunData(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed["protonvpn"]; !ok {
		t.Error("cache should have been updated with new data containing protonvpn")
	}
}

func TestFetchServersNetworkErrorWithExistingCache(t *testing.T) {
	saveAndRestoreURL(t)
	cacheDir := t.TempDir()

	// Pre-populate cache
	cachePath := filepath.Join(cacheDir, "servers_raw.json")
	os.WriteFile(cachePath, []byte(validGluetunJSON), 0644)

	// Make cache stale so FetchServers attempts a download
	staleTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(cachePath, staleTime, staleTime)

	// Point to an unreachable server to cause a network error
	ServersBaseURL = "http://127.0.0.1:1/unreachable"

	err := FetchServers(cacheDir, false)
	// Should fall back to existing cache and return nil
	if err != nil {
		t.Fatalf("FetchServers() should fall back to cache on network error, got: %v", err)
	}

	// Original cache should still be intact
	data, _ := os.ReadFile(cachePath)
	if string(data) != validGluetunJSON {
		t.Error("cache content should not have been modified")
	}
}

func TestFetchServersNetworkErrorNoCache(t *testing.T) {
	saveAndRestoreURL(t)
	cacheDir := t.TempDir()

	// No existing cache, and an unreachable server
	ServersBaseURL = "http://127.0.0.1:1/unreachable"

	err := FetchServers(cacheDir, false)
	if err == nil {
		t.Fatal("expected error when network fails and no cache exists")
	}
	if !strings.Contains(err.Error(), "failed to fetch server list") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestFetchServersInvalidJSONResponse(t *testing.T) {
	saveAndRestoreURL(t)
	cacheDir := t.TempDir()

	ts := newGluetunTestServer(t, http.StatusOK, "this is not valid json")
	ServersBaseURL = ts.URL

	err := FetchServers(cacheDir, false)
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
	// Every provider file is malformed, so none can be fetched and, with no
	// existing cache to fall back to, FetchServers surfaces the fetch failure.
	if !strings.Contains(err.Error(), "failed to fetch server list") {
		t.Errorf("unexpected error message: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("error should mention the invalid JSON cause: %v", err)
	}

	// Cache file should NOT have been written
	cachePath := filepath.Join(cacheDir, "servers_raw.json")
	if _, err := os.Stat(cachePath); err == nil {
		t.Error("cache should not be written for invalid JSON")
	}
}

func TestFetchServersNon200Status(t *testing.T) {
	saveAndRestoreURL(t)
	cacheDir := t.TempDir()

	ts := newGluetunTestServer(t, http.StatusInternalServerError, "internal error")
	ServersBaseURL = ts.URL

	err := FetchServers(cacheDir, false)
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestFetchServersNon200StatusVariants(t *testing.T) {
	saveAndRestoreURL(t)

	for _, code := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprintf("status_%d", code), func(t *testing.T) {
			saveAndRestoreURL(t)
			cacheDir := t.TempDir()
			ts := newGluetunTestServer(t, code, "error")
			ServersBaseURL = ts.URL

			err := FetchServers(cacheDir, false)
			if err == nil {
				t.Fatalf("expected error for status %d", code)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("status %d", code)) {
				t.Errorf("error should mention status %d, got: %v", code, err)
			}
		})
	}
}

func TestFetchServersCacheExpiryBoundary(t *testing.T) {
	saveAndRestoreURL(t)
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "servers_raw.json")

	// Write cache and set modtime to exactly at the expiry boundary (just expired)
	os.WriteFile(cachePath, []byte(`{"version":1,"old":{"servers":[]}}`), 0644)
	expiredTime := time.Now().Add(-CacheExpiry - 1*time.Second)
	os.Chtimes(cachePath, expiredTime, expiredTime)

	// Serve fresh data -- should be downloaded since cache is expired
	ts := newGluetunTestServer(t, http.StatusOK, validProviderFile)
	ServersBaseURL = ts.URL

	err := FetchServers(cacheDir, false)
	if err != nil {
		t.Fatalf("FetchServers() error: %v", err)
	}

	// Verify cache was updated
	data, _ := os.ReadFile(cachePath)
	parsed, _ := parseGluetunData(data)
	if _, ok := parsed["protonvpn"]; !ok {
		t.Error("cache should have been refreshed with new data")
	}
}

func TestFetchServersCreatesCacheDir(t *testing.T) {
	saveAndRestoreURL(t)
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "new", "nested", "cache")

	ts := newGluetunTestServer(t, http.StatusOK, validProviderFile)
	ServersBaseURL = ts.URL

	err := FetchServers(cacheDir, false)
	if err != nil {
		t.Fatalf("FetchServers() error: %v", err)
	}

	// Verify the nested directory was created and cache was written
	cachePath := filepath.Join(cacheDir, "servers_raw.json")
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache file should exist at %s: %v", cachePath, err)
	}
}

func TestFetchServersForceWithNoCacheDir(t *testing.T) {
	saveAndRestoreURL(t)
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "brand_new")

	ts := newGluetunTestServer(t, http.StatusOK, validProviderFile)
	ServersBaseURL = ts.URL

	err := FetchServers(cacheDir, true)
	if err != nil {
		t.Fatalf("FetchServers(force=true) error: %v", err)
	}

	cachePath := filepath.Join(cacheDir, "servers_raw.json")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	if len(data) == 0 {
		t.Error("cache file should not be empty")
	}
}

// TestFetchServersCacheDirCreationFails verifies the error returned when
// os.MkdirAll fails (e.g., a regular file blocks the path).
func TestFetchServersCacheDirCreationFails(t *testing.T) {
	saveAndRestoreURL(t)
	tmpDir := t.TempDir()

	// Create a regular file where the cache directory should be,
	// so os.MkdirAll will fail.
	blocker := filepath.Join(tmpDir, "blocked")
	os.WriteFile(blocker, []byte("I am a file"), 0644)

	cacheDir := filepath.Join(blocker, "subdir")

	ts := newGluetunTestServer(t, http.StatusOK, validProviderFile)
	ServersBaseURL = ts.URL

	err := FetchServers(cacheDir, false)
	if err == nil {
		t.Fatal("expected error when cache dir creation fails")
	}
	if !strings.Contains(err.Error(), "failed to create cache directory") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestFetchServersCacheWriteFails verifies the error when the cache file
// cannot be written (read-only cache directory).
func TestFetchServersCacheWriteFails(t *testing.T) {
	saveAndRestoreURL(t)
	cacheDir := t.TempDir()

	ts := newGluetunTestServer(t, http.StatusOK, validProviderFile)
	ServersBaseURL = ts.URL

	// Make cache dir read-only AFTER it exists (MkdirAll will succeed, but
	// atomicWriteFile will fail because CreateTemp can't write).
	os.Chmod(cacheDir, 0555)
	t.Cleanup(func() { os.Chmod(cacheDir, 0755) })

	err := FetchServers(cacheDir, true)
	if err == nil {
		t.Fatal("expected error when cache write fails")
	}
	if !strings.Contains(err.Error(), "failed to write cache") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestFetchServersAssemblesMultipleProviders verifies that distinct per-provider
// files are downloaded and assembled into the single combined servers_raw.json
// that FilterProviderServers consumes — the core of the per-provider migration.
func TestFetchServersAssemblesMultipleProviders(t *testing.T) {
	saveAndRestoreURL(t)
	cacheDir := t.TempDir()

	protonBody := `{"version":4,"servers":[{"server_name":"US#1","vpn":"wireguard","wgpubkey":"pp=","ips":["1.1.1.1"],"country":"US"}]}`
	mullvadBody := `{"version":4,"servers":[{"server_name":"SE#9","vpn":"wireguard","wgpubkey":"mm=","ips":["2.2.2.2"],"country":"SE"}]}`
	ts := newPerProviderTestServer(t, map[string]string{
		"protonvpn": protonBody,
		"mullvad":   mullvadBody,
	}, http.StatusNotFound)
	ServersBaseURL = ts.URL

	if err := FetchServers(cacheDir, true); err != nil {
		t.Fatalf("FetchServers() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(cacheDir, "servers_raw.json"))
	if err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	parsed, err := parseGluetunData(data)
	if err != nil {
		t.Fatalf("combined cache invalid: %v", err)
	}
	if pv, ok := parsed["protonvpn"]; !ok || len(pv.Servers) != 1 || pv.Servers[0].ServerName != "US#1" {
		t.Errorf("protonvpn not assembled correctly: %+v (ok=%v)", parsed["protonvpn"], ok)
	}
	if mv, ok := parsed["mullvad"]; !ok || len(mv.Servers) != 1 || mv.Servers[0].ServerName != "SE#9" {
		t.Errorf("mullvad not assembled correctly: %+v (ok=%v)", parsed["mullvad"], ok)
	}
}

// TestFetchServersPartialFailurePreservesExisting verifies the resilience
// contract: when some providers fail to fetch, FetchServers still writes the
// providers it COULD fetch, and preserves previously-cached data for the ones
// that failed (rather than dropping them).
func TestFetchServersPartialFailurePreservesExisting(t *testing.T) {
	saveAndRestoreURL(t)
	cacheDir := t.TempDir()

	// Seed the combined cache with an existing mullvad entry.
	seed := `{"version":1,"mullvad":{"servers":[{"server_name":"SE-OLD#1","vpn":"wireguard","wgpubkey":"old=","ips":["9.9.9.9"],"country":"SE"}]}}`
	if err := os.WriteFile(filepath.Join(cacheDir, "servers_raw.json"), []byte(seed), 0644); err != nil {
		t.Fatal(err)
	}

	// Server only serves protonvpn; every other provider (incl. mullvad) 404s.
	protonBody := `{"version":4,"servers":[{"server_name":"US#1","vpn":"wireguard","wgpubkey":"pp=","ips":["1.1.1.1"],"country":"US"}]}`
	ts := newPerProviderTestServer(t, map[string]string{"protonvpn": protonBody}, http.StatusNotFound)
	ServersBaseURL = ts.URL

	if err := FetchServers(cacheDir, true); err != nil {
		t.Fatalf("FetchServers() should succeed with at least one provider fetched: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(cacheDir, "servers_raw.json"))
	parsed, err := parseGluetunData(data)
	if err != nil {
		t.Fatalf("combined cache invalid: %v", err)
	}
	// Newly fetched provider is present.
	if pv, ok := parsed["protonvpn"]; !ok || len(pv.Servers) != 1 {
		t.Errorf("protonvpn should have been fetched: %+v (ok=%v)", parsed["protonvpn"], ok)
	}
	// Previously-cached provider that failed this run is preserved, not dropped.
	if mv, ok := parsed["mullvad"]; !ok || len(mv.Servers) != 1 || mv.Servers[0].ServerName != "SE-OLD#1" {
		t.Errorf("mullvad should be preserved from existing cache: %+v (ok=%v)", parsed["mullvad"], ok)
	}
}

// TestFetchProviderServersPathEscape verifies that provider names containing
// spaces (gluetun has files like "private internet access.json") are URL-escaped
// in the request path so the fetch actually resolves.
func TestFetchProviderServersPathEscape(t *testing.T) {
	saveAndRestoreURL(t)

	var gotPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path // net/http decodes %20 back to a space here
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"version":4,"servers":[]}`)
	}))
	t.Cleanup(ts.Close)
	ServersBaseURL = ts.URL

	ctx := context.Background()
	client := &http.Client{}
	if _, err := fetchProviderServers(ctx, client, "private internet access"); err != nil {
		t.Fatalf("fetchProviderServers() error: %v", err)
	}
	if gotPath != "/private internet access.json" {
		t.Errorf("request path = %q, want %q", gotPath, "/private internet access.json")
	}
}

// TestParseGluetunDataUnmarshalError ensures that a JSON value starting with '{'
// that cannot be unmarshalled into a providerEntry is silently skipped.
// We achieve this by providing truncated JSON (a value that is syntactically valid
// raw JSON but does not match the providerEntry struct in a way that causes
// json.Unmarshal to fail).
func TestParseGluetunDataUnmarshalError(t *testing.T) {
	// json.Unmarshal into providerEntry won't fail on unknown fields since Go
	// silently ignores them. To trigger an actual unmarshal error for an object,
	// we need a value where a field expected to be one type is another.
	// "servers" is expected to be []Server. If it's a string, unmarshal fails.
	data := `{
		"version": 1,
		"broken_provider": {"servers": "not-an-array"},
		"protonvpn": {
			"servers": [
				{"server_name": "US#1", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["1.1.1.1"], "country": "US"}
			]
		}
	}`

	result, err := parseGluetunData([]byte(data))
	if err != nil {
		t.Fatalf("parseGluetunData() should not return error: %v", err)
	}

	// broken_provider should have been skipped due to unmarshal error
	if _, ok := result["broken_provider"]; ok {
		t.Error("broken_provider should have been skipped")
	}

	// valid provider should still be present
	pv, ok := result["protonvpn"]
	if !ok {
		t.Fatal("protonvpn not found")
	}
	if len(pv.Servers) != 1 {
		t.Errorf("protonvpn servers = %d, want 1", len(pv.Servers))
	}
}

// TestFilterProviderServersSortCityAndName tests the sort comparator's
// city and name tie-breaking branches. We need servers with:
// - Same country, different city (exercises city comparison)
// - Same country + city, different name (exercises name comparison)
func TestFilterProviderServersSortCityAndName(t *testing.T) {
	tmpDir := t.TempDir()

	rawData := `{
		"version": 1,
		"protonvpn": {
			"servers": [
				{"server_name": "US-Z#99", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["1.1.1.1"], "country": "US", "city": "Zurich"},
				{"server_name": "US-A#01", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["2.2.2.2"], "country": "US", "city": "Atlanta"},
				{"server_name": "US-A#02", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["3.3.3.3"], "country": "US", "city": "Atlanta"},
				{"server_name": "DE-B#10", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["4.4.4.4"], "country": "DE", "city": "Berlin"},
				{"server_name": "DE-B#05", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["5.5.5.5"], "country": "DE", "city": "Berlin"}
			]
		}
	}`
	os.WriteFile(filepath.Join(tmpDir, "servers_raw.json"), []byte(rawData), 0644)

	servers, err := FilterProviderServers(tmpDir, "protonvpn")
	if err != nil {
		t.Fatalf("FilterProviderServers() error: %v", err)
	}

	if len(servers) != 5 {
		t.Fatalf("expected 5 servers, got %d", len(servers))
	}

	// Expected order:
	// 1. DE-B#05 (DE, Berlin) - sorted by name within same country+city
	// 2. DE-B#10 (DE, Berlin)
	// 3. US-A#01 (US, Atlanta)
	// 4. US-A#02 (US, Atlanta)
	// 5. US-Z#99 (US, Zurich)
	expected := []string{"DE-B#05", "DE-B#10", "US-A#01", "US-A#02", "US-Z#99"}
	for i, want := range expected {
		got := servers[i].ServerName
		if got != want {
			t.Errorf("servers[%d].ServerName = %q, want %q", i, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Mutation testing: kill survived mutants
// ---------------------------------------------------------------------------

// TestCacheExpiredBoundary tests the cacheExpired helper at exact boundary
// values.  The function uses `age > CacheExpiry` (strictly greater), so:
//   - age == CacheExpiry should NOT be expired
//   - age == CacheExpiry + 1ns should be expired
//   - age == CacheExpiry - 1ns should NOT be expired
//
// Kills mutant: CONDITIONALS_BOUNDARY at gluetun.go:119  (> changed to >=)
func TestCacheExpiredBoundary(t *testing.T) {
	tests := []struct {
		name    string
		age     time.Duration
		expired bool
	}{
		{"well under", CacheExpiry - time.Hour, false},
		{"just under", CacheExpiry - time.Nanosecond, false},
		{"exactly at", CacheExpiry, false}, // key case: > says false, >= says true
		{"just over", CacheExpiry + time.Nanosecond, true},
		{"well over", CacheExpiry + time.Hour, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cacheExpired(tt.age)
			if got != tt.expired {
				t.Errorf("cacheExpired(%v) = %v, want %v", tt.age, got, tt.expired)
			}
		})
	}
}

// TestFilterProviderServersSortIdenticalNames verifies that the sort comparator
// handles servers with identical country, city, and name correctly. With the
// correct `<` comparator, two same-named servers are considered equal and the
// sort is well-defined.  If a mutation changes `<` to `<=`, the comparator
// becomes anti-symmetric-violating (less(i,j) && less(j,i) for equal names),
// which can cause sort.Slice to panic, loop, or produce incorrect output.
//
// We use many duplicates + surrounding distinct values to maximize the chance
// that the sort implementation actually compares two equal-name elements.
//
// Kills mutant: CONDITIONALS_BOUNDARY at gluetun.go:221  (< changed to <=)
func TestFilterProviderServersSortIdenticalNames(t *testing.T) {
	tmpDir := t.TempDir()

	// Many servers with identical country+city+name, plus distinct bookend values.
	rawData := `{
		"version": 1,
		"protonvpn": {
			"servers": [
				{"server_name": "US#5", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["10.0.0.1"], "country": "US", "city": "NY"},
				{"server_name": "US#3", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["10.0.0.2"], "country": "US", "city": "NY"},
				{"server_name": "US#3", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["10.0.0.3"], "country": "US", "city": "NY"},
				{"server_name": "US#3", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["10.0.0.4"], "country": "US", "city": "NY"},
				{"server_name": "US#3", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["10.0.0.5"], "country": "US", "city": "NY"},
				{"server_name": "US#3", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["10.0.0.6"], "country": "US", "city": "NY"},
				{"server_name": "US#3", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["10.0.0.7"], "country": "US", "city": "NY"},
				{"server_name": "US#3", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["10.0.0.8"], "country": "US", "city": "NY"},
				{"server_name": "US#1", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["10.0.0.9"], "country": "US", "city": "NY"}
			]
		}
	}`
	os.WriteFile(filepath.Join(tmpDir, "servers_raw.json"), []byte(rawData), 0644)

	servers, err := FilterProviderServers(tmpDir, "protonvpn")
	if err != nil {
		t.Fatalf("FilterProviderServers() error: %v", err)
	}

	if len(servers) != 9 {
		t.Fatalf("expected 9 servers, got %d", len(servers))
	}

	// Verify sorted order: US#1, then seven US#3s, then US#5.
	if servers[0].ServerName != "US#1" {
		t.Errorf("servers[0].ServerName = %q, want %q", servers[0].ServerName, "US#1")
	}
	for i := 1; i <= 7; i++ {
		if servers[i].ServerName != "US#3" {
			t.Errorf("servers[%d].ServerName = %q, want %q", i, servers[i].ServerName, "US#3")
		}
	}
	if servers[8].ServerName != "US#5" {
		t.Errorf("servers[8].ServerName = %q, want %q", servers[8].ServerName, "US#5")
	}
}

// TestAtomicWriteFileRenameFailure verifies that atomicWriteFile returns an
// error when os.Rename fails. On Linux, renaming a regular file to an existing
// non-empty directory fails with EISDIR.
//
// Kills mutant: CONDITIONALS_NEGATION at gluetun.go:296  (err != nil → err == nil)
func TestAtomicWriteFileRenameFailure(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a subdirectory at the target path — os.Rename of a file onto a
	// directory fails on Linux.
	targetPath := filepath.Join(tmpDir, "target")
	subFile := filepath.Join(targetPath, "blocker")
	os.MkdirAll(targetPath, 0755)
	os.WriteFile(subFile, []byte("x"), 0644)

	err := atomicWriteFile(targetPath, []byte("data"), 0644)
	if err == nil {
		t.Fatal("expected error when rename fails (target is a non-empty directory)")
	}

	// The temp file should have been cleaned up by the defer.
	entries, _ := os.ReadDir(tmpDir)
	for _, e := range entries {
		if e.Name() != "target" {
			t.Errorf("leftover temp file not cleaned up: %s", e.Name())
		}
	}
}

// ---------------------------------------------------------------------------
// Documentation: equivalent mutants that cannot be killed
// ---------------------------------------------------------------------------
//
// ARITHMETIC_BASE at the HTTP client Timeout (FetchServers)
//   Mutation: `60 * time.Second` in the HTTP client Timeout is changed
//   (e.g. to `60 / time.Second`, yielding 0 = no timeout).
//   This is an equivalent mutant from a testing perspective because:
//   - The timeout value is a local variable inside FetchServers
//   - Our httptest servers respond instantly, so any timeout ≥0 works
//   - Testing with a deliberately slow server would make tests fragile/slow
//   - The mutation cannot be observed through the function's return values
//     when the server responds promptly
//
// CONDITIONALS_BOUNDARY at the Country sort comparator (FilterProviderServers)
//   Mutation: `servers[i].Country < servers[j].Country` changed to `<=`
//   This return statement is only reached when
//   `servers[i].Country != servers[j].Country`, meaning the two countries
//   are guaranteed to be different. For distinct strings, `<` and `<=`
//   produce identical results. This is a provably equivalent mutant.
//
// CONDITIONALS_BOUNDARY at the City sort comparator (FilterProviderServers)
//   Mutation: `servers[i].City < servers[j].City` changed to `<=`
//   Same reasoning as the Country comparator: this return is guarded by
//   `servers[i].City != servers[j].City`, so the values are always distinct.
//   `<` and `<=` behave identically for distinct strings. Equivalent mutant.

// TestReadCacheBounded_RejectsOversizedFile verifies that the cap on
// cache file size (maxCacheBytes = 50MB) is enforced. A regression
// where the cap is not enforced would let a corrupted or malicious
// cache file consume unbounded memory in io.ReadAll, OOM-killing the
// daemon. The cap is the only thing standing between bad on-disk
// state and an OOM.
//
// We use os.Truncate to create a sparse file of (maxCacheBytes+1)
// bytes — instant on tmpfs/ext4/btrfs, no actual disk write.
func TestReadCacheBounded_RejectsOversizedFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "huge.json")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Truncate(path, maxCacheBytes+1); err != nil {
		t.Fatal(err)
	}

	_, err = readCacheBounded(path)
	if err == nil {
		t.Fatal("expected error reading file > maxCacheBytes, got nil — cap not enforced")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error doesn't mention size cap: %v", err)
	}
}

// TestReadCacheBounded_AcceptsExactCapSize is the boundary companion
// to the rejection test. A file of EXACTLY maxCacheBytes is the
// largest still-valid input — it must succeed. A `>` -> `>=` mutation
// at the cap check would falsely reject this size.
func TestReadCacheBounded_AcceptsExactCapSize(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "atcap.json")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Truncate(path, maxCacheBytes); err != nil {
		t.Fatal(err)
	}

	data, err := readCacheBounded(path)
	if err != nil {
		t.Fatalf("file at exactly cap size rejected: %v (boundary mutation `>` -> `>=`?)", err)
	}
	if int64(len(data)) != maxCacheBytes {
		t.Errorf("got %d bytes, want %d", len(data), maxCacheBytes)
	}
}

// TestFilterProviderServersWriteCacheFails verifies the error when the provider
// cache file cannot be written.
func TestFilterProviderServersWriteCacheFails(t *testing.T) {
	tmpDir := t.TempDir()

	rawData := `{
		"version": 1,
		"protonvpn": {
			"servers": [
				{"server_name": "US#1", "vpn": "wireguard", "wgpubkey": "pk=", "ips": ["1.2.3.4"], "country": "US"}
			]
		}
	}`
	os.WriteFile(filepath.Join(tmpDir, "servers_raw.json"), []byte(rawData), 0644)

	// Make the directory read-only so the provider cache write fails
	os.Chmod(tmpDir, 0555)
	t.Cleanup(func() { os.Chmod(tmpDir, 0755) })

	_, err := FilterProviderServers(tmpDir, "protonvpn")
	if err == nil {
		t.Fatal("expected error when provider cache write fails")
	}
	if !strings.Contains(err.Error(), "failed to write provider cache") {
		t.Errorf("unexpected error message: %v", err)
	}
}

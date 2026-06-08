package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ServersBaseURL is the base directory URL for our per-provider WireGuard server
// lists. Each provider is a separate file: <base>/<gluetunName>.json.
//
// We fetch from THIS repository's `server-data` branch, NOT from gluetun directly.
// The server-data branch is a data-only orphan branch that the update-servers
// GitHub Action refreshes weekly: it pulls the latest lists from gluetun-servers
// (github.com/qdm12/gluetun-servers), WireGuard-filters them, and commits them here.
//
// Why the indirection: it insulates released binaries from upstream churn. gluetun
// has already moved this data once — the app repo was renamed (qdm12/gluetun →
// passteque/gluetun) and the old combined internal/storage/servers.json was deleted,
// replaced by the separate, brand-new, monthly-cron gluetun-servers repo. By mirroring
// into our own branch and pointing the binary here, a future upstream move breaks only
// our weekly Action (which we fix once, on our schedule) instead of breaking every
// user's binary at once. If the Action stalls, users keep working off the last
// snapshot committed to server-data.
//
// It is a var (not const) so tests can override it with httptest server URLs.
var ServersBaseURL = "https://raw.githubusercontent.com/blank-query/lazyVPN-for-Omarchy/server-data"

const (
	// CacheExpiry is how long a fetched server-list cache stays fresh before
	// FetchServers re-downloads. Set to a week to match our server-data branch,
	// which the update-servers GitHub Action refreshes weekly — a shorter TTL
	// would just re-pull identical data and hammer raw.githubusercontent.com.
	CacheExpiry = 7 * 24 * time.Hour
)

// GluetunProviderMap maps our provider names to gluetun's names
var GluetunProviderMap = map[string]string{
	"protonvpn":  "protonvpn",
	"mullvad":    "mullvad",
	"ivpn":       "ivpn",
	"airvpn":     "airvpn",
	"nordvpn":    "nordvpn",
	"surfshark":  "surfshark",
	"windscribe": "windscribe",
	"fastestvpn": "fastestvpn",
}

// ProviderDisplayNames for UI display
var ProviderDisplayNames = map[string]string{
	"protonvpn":  "ProtonVPN",
	"mullvad":    "Mullvad",
	"ivpn":       "IVPN",
	"airvpn":     "AirVPN",
	"nordvpn":    "NordVPN",
	"surfshark":  "Surfshark",
	"windscribe": "Windscribe",
	"fastestvpn": "FastestVPN",
}

// Server represents a VPN server from gluetun
type Server struct {
	ServerName  string   `json:"server_name"`
	Hostname    string   `json:"hostname"`
	Country     string   `json:"country"`
	City        string   `json:"city"`
	VPN         string   `json:"vpn"`
	WGPubKey    string   `json:"wgpubkey"`
	IPs         []string `json:"ips"`
	PortForward bool     `json:"port_forward"`
	Tor         bool     `json:"tor"`
	SecureCore  bool     `json:"secure_core"`
	Stream      bool     `json:"stream"`
	Free        bool     `json:"free"`
}

// Name returns the best available name for the server
func (s *Server) Name() string {
	if s.ServerName != "" {
		return s.ServerName
	}
	return s.Hostname
}

// IP returns the first IP address
func (s *Server) IP() string {
	if len(s.IPs) > 0 {
		return s.IPs[0]
	}
	return ""
}

// providerEntry represents a provider's data in the combined gluetun cache
// (servers_raw.json) that this package assembles and the rest of the pipeline
// (parseGluetunData, FilterProviderServers) consumes.
type providerEntry struct {
	Servers []Server `json:"servers"`
}

// providerServersFile is the shape of one per-provider file in the
// qdm12/gluetun-servers data repo: {version, timestamp, servers:[...]}.
// We only need the servers list; version/timestamp are ignored.
type providerServersFile struct {
	Servers []Server `json:"servers"`
}

// parseGluetunData parses the raw gluetun JSON, handling the version field
func parseGluetunData(data []byte) (map[string]providerEntry, error) {
	// First parse as raw messages to handle mixed types (version is int, providers are objects)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	result := make(map[string]providerEntry)
	for key, value := range raw {
		// Skip non-object fields like "version": 1
		if len(value) == 0 || value[0] != '{' {
			continue
		}

		var entry providerEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			// Skip entries that don't match provider structure
			continue
		}
		result[key] = entry
	}

	return result, nil
}

// cacheExpired reports whether a cache file with the given age should be
// refreshed. The cache is considered expired only when its age is strictly
// greater than CacheExpiry.
func cacheExpired(age time.Duration) bool {
	return age > CacheExpiry
}

// FetchServers downloads each mapped provider's per-provider file from the
// gluetun-servers data repo and assembles them into the combined cache
// (servers_raw.json) that FilterProviderServers / parseGluetunData consume.
//
// Resilience: it starts from whatever is already in the combined cache and
// overlays each provider it successfully (re-)fetches. A transient failure on
// one provider therefore preserves that provider's previously-cached data
// rather than dropping it. Only when NOT A SINGLE provider could be fetched do
// we fall back wholesale to the existing cache (returning nil) or, if there is
// no existing cache, return the first fetch error.
func FetchServers(cacheDir string, force bool) error {
	rawCachePath := filepath.Join(cacheDir, "servers_raw.json")

	// Check if we need to refresh
	needRefresh := force
	if !force {
		info, err := os.Stat(rawCachePath)
		if err != nil {
			needRefresh = true
		} else {
			age := time.Since(info.ModTime())
			needRefresh = cacheExpired(age)
		}
	}

	if !needRefresh {
		return nil // Cache is fresh
	}

	// Ensure cache directory exists. Mode 0700 matches parent
	// `~/.config/lazyvpn/` — server lists aren't secrets but the
	// containing tree is 0700 and consistent perms down the tree are
	// the right hygiene.
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// One client/transport reused across the per-provider requests. The
	// explicit ctx bounds each request by the deadline — client.Get() doesn't
	// propagate cancel back to the underlying transport even when
	// client.Timeout fires (HTTP/2 connections in particular sit on a half-
	// finished read until their own ReadDeadline), so we thread the deadline
	// through NewRequestWithContext below.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	transport := &http.Transport{}
	client := &http.Client{Timeout: 60 * time.Second, Transport: transport}
	defer transport.CloseIdleConnections()

	// Seed from the existing cache so a single-provider failure doesn't drop
	// previously-good data. Unparseable/missing cache yields an empty map.
	merged := loadCachedProviders(rawCachePath)

	fetchedAny := false
	var firstErr error
	for _, gluetunName := range GluetunProviderMap {
		servers, err := fetchProviderServers(ctx, client, gluetunName)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", gluetunName, err)
			}
			continue
		}
		merged[gluetunName] = providerEntry{Servers: servers}
		fetchedAny = true
	}

	if !fetchedAny {
		// Nothing fetched. Prefer existing cache over surfacing an error.
		if _, statErr := os.Stat(rawCachePath); statErr == nil {
			return nil
		}
		return fmt.Errorf("failed to fetch server list: %w", firstErr)
	}

	data, err := marshalCombined(merged)
	if err != nil {
		return fmt.Errorf("failed to encode server list: %w", err)
	}

	// Write to cache atomically (temp file + rename)
	if err := atomicWriteFile(rawCachePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache: %w", err)
	}

	return nil
}

// fetchProviderServers downloads and decodes a single provider's per-provider
// file from <ServersBaseURL>/<gluetunName>.json. The provider name is
// path-escaped because some gluetun provider names contain spaces (e.g.
// "private internet access").
func fetchProviderServers(ctx context.Context, client *http.Client, gluetunName string) ([]Server, error) {
	reqURL := ServersBaseURL + "/" + url.PathEscape(gluetunName) + ".json"
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	// Limit response size to 50MB to prevent OOM from malicious/misconfigured servers
	const maxSize = 50 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var pf providerServersFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return pf.Servers, nil
}

// loadCachedProviders reads the combined cache at path and returns its
// provider→servers map, or an empty map if the file is missing or unparseable.
func loadCachedProviders(path string) map[string]providerEntry {
	data, err := readCacheBounded(path)
	if err != nil {
		return map[string]providerEntry{}
	}
	parsed, err := parseGluetunData(data)
	if err != nil {
		return map[string]providerEntry{}
	}
	return parsed
}

// marshalCombined encodes the provider→servers map into the combined
// servers_raw.json format (a "version" scalar plus one object per provider)
// that parseGluetunData reads back.
func marshalCombined(merged map[string]providerEntry) ([]byte, error) {
	out := make(map[string]interface{}, len(merged)+1)
	out["version"] = 1
	for k, v := range merged {
		out[k] = v
	}
	return json.MarshalIndent(out, "", "  ")
}

// FilterProviderServers filters and caches servers for a specific provider
func FilterProviderServers(cacheDir, provider string) ([]Server, error) {
	rawCachePath := filepath.Join(cacheDir, "servers_raw.json")
	providerCachePath := filepath.Join(cacheDir, provider+"_servers.json")

	// Read raw cache, bounded the same way as LoadProviderServers.
	// The raw cache is written by the upstream fetch (already 50MB
	// capped) but lives on user-writable disk afterward — re-applying
	// the cap on read defends against hand-edits and corruption.
	data, err := readCacheBounded(rawCachePath)
	if err != nil {
		return nil, fmt.Errorf("raw cache not found: %w", err)
	}

	allData, err := parseGluetunData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cache: %w", err)
	}

	// Get gluetun provider name
	gluetunName, ok := GluetunProviderMap[provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}

	// Get provider data
	providerData, ok := allData[gluetunName]
	if !ok {
		return nil, fmt.Errorf("provider not found in gluetun data: %s", gluetunName)
	}

	// Filter WireGuard servers with valid data
	var servers []Server
	for _, srv := range providerData.Servers {
		if srv.VPN != "wireguard" {
			continue
		}
		if srv.WGPubKey == "" {
			continue
		}
		if len(srv.IPs) == 0 {
			continue
		}
		servers = append(servers, srv)
	}

	// Sort by country, city, server name
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Country != servers[j].Country {
			return servers[i].Country < servers[j].Country
		}
		if servers[i].City != servers[j].City {
			return servers[i].City < servers[j].City
		}
		return servers[i].Name() < servers[j].Name()
	})

	// Save filtered cache
	filteredData, err := json.MarshalIndent(servers, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal servers: %w", err)
	}

	if err := atomicWriteFile(providerCachePath, filteredData, 0644); err != nil {
		return nil, fmt.Errorf("failed to write provider cache: %w", err)
	}

	return servers, nil
}

// maxCacheBytes caps how much of the gluetun cache files are read
// into memory. Matches the upstream fetch limit; realistic filtered
// caches are <10MB. A corrupted or hand-edited cache file (the
// caches live at ~/.config/lazyvpn/cache/, user-writable) larger
// than that would OOM os.ReadFile.
const maxCacheBytes = 50 * 1024 * 1024

// readCacheBounded opens path and reads up to maxCacheBytes through
// a LimitReader, returning a clear "exceeds cap" error on overflow
// so callers can distinguish from JSON parse failures.
func readCacheBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCacheBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read cache: %w", err)
	}
	if int64(len(data)) > maxCacheBytes {
		return nil, fmt.Errorf("cache file %s exceeds %d byte cap — possibly corrupted", filepath.Base(path), maxCacheBytes)
	}
	return data, nil
}

// LoadProviderServers loads cached servers for a provider
func LoadProviderServers(cacheDir, provider string) ([]Server, error) {
	cachePath := filepath.Join(cacheDir, provider+"_servers.json")

	data, err := readCacheBounded(cachePath)
	if err != nil {
		return nil, fmt.Errorf("cache not found for provider %s: %w", provider, err)
	}

	var servers []Server
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, fmt.Errorf("failed to parse cache: %w", err)
	}

	return servers, nil
}

// atomicWriteFile writes data to a file atomically using temp file + rename.
// This prevents corrupted files from interrupted writes.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".tmp.*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	// Check Close error before rename — on delayed-commit filesystems
	// Sync can succeed while Close surfaces the actual write error.
	// Ignoring it lets os.Rename install a truncated cache that the
	// next FilterProviderServers fails to parse, which then falsely
	// reports "raw cache not found" to the user.
	if err := tmpFile.Close(); err != nil {
		return err
	}

	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}

	success = true
	return nil
}

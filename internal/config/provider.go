package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/security"
)

// maxProviderCacheBytes caps how much of a per-provider server-cache
// JSON file the loaders will read into memory. The cache files live
// in ~/.config/lazyvpn/cache/ (user-writable). A corrupted or
// hand-edited file larger than the realistic ~10MB filtered-provider
// payload would OOM a bare os.ReadFile. 50MB matches the upstream
// gluetun fetch cap.
const maxProviderCacheBytes = 50 * 1024 * 1024

// maxConfigBytes caps how much of a small structured config file
// (config.json, providers/*.json) is read into memory. Realistic
// files are <10KB; 1MB is generous and short enough to make a
// hand-edited or corrupted file fail fast rather than OOM the
// process.
const maxConfigBytes = 1 * 1024 * 1024

// readFileBounded opens path and reads up to limit+1 bytes through a
// LimitReader. Reading more is treated as corruption and surfaces a
// dedicated "exceeds N byte cap" error so callers can distinguish
// from JSON parse failures. Shared by every loader that touches a
// user-writable JSON file.
func readFileBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d byte cap — possibly corrupted", filepath.Base(path), limit)
	}
	return data, nil
}

// readCacheBounded is the per-provider-cache-file variant of
// readFileBounded with the 50MB cap baked in. Kept as a thin
// alias so existing callers don't have to repeat the limit literal.
func readCacheBounded(cachePath string) ([]byte, error) {
	return readFileBounded(cachePath, maxProviderCacheBytes)
}

// validNamePattern is used to validate server names and provider names
// to prevent path traversal attacks
var validNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._#-]+$`)

// ValidateName checks if a name is safe for use in file paths
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("name cannot contain '..'")
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("name cannot contain path separators")
	}
	if !validNamePattern.MatchString(name) {
		return fmt.Errorf("name contains invalid characters")
	}
	return nil
}

// Provider default settings
var ProviderDNS = map[string]string{
	"protonvpn":  "10.2.0.1",
	"mullvad":    "10.64.0.1",
	"ivpn":       "172.16.0.1",
	"airvpn":     "10.128.0.1",
	"nordvpn":    "103.86.96.100",
	"surfshark":  "162.252.172.57",
	"windscribe": "10.255.255.1",
	"fastestvpn": "10.8.0.1",
}

var ProviderPort = map[string]int{
	"protonvpn":  51820,
	"mullvad":    51820,
	"ivpn":       2049,
	"airvpn":     1637,
	"nordvpn":    51820,
	"surfshark":  51820,
	"windscribe": 443,
	"fastestvpn": 51820,
}

// ProviderConfig holds credentials for a VPN provider
type ProviderConfig struct {
	Provider   string
	PrivateKey []byte // Raw key bytes (base64-decoded); use ZeroKey() to clear
	Address    string
	DNS        string
	Port       int
}

// ZeroKey zeroes the PrivateKey field via security.ZeroBytes (which
// uses runtime.KeepAlive to prevent the compiler from eliding the
// stores as dead when the slice is not read after zeroing).
func (pc *ProviderConfig) ZeroKey() {
	security.ZeroBytes(pc.PrivateKey)
}

// providerJSON is the JSON-serializable representation of provider credentials.
// PrivateKey is []byte; json.Marshal encodes it as base64, Unmarshal decodes back.
type providerJSON struct {
	PrivateKey []byte `json:"private_key"`
	Address    string `json:"address"`
}

// LoadProvider loads provider credentials from the providers directory
func LoadProvider(configDir, provider string) (*ProviderConfig, error) {
	if err := ValidateName(provider); err != nil {
		return nil, fmt.Errorf("invalid provider name: %w", err)
	}
	path := filepath.Join(configDir, "providers", provider+".json")

	data, err := readFileBounded(path, maxConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("provider not configured: %s", provider)
	}

	var pj providerJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil, fmt.Errorf("invalid provider config for %s: %w", provider, err)
	}

	cfg := &ProviderConfig{
		Provider:   provider,
		PrivateKey: pj.PrivateKey,
		Address:    pj.Address,
		DNS:        ProviderDNS[provider],
		Port:       ProviderPort[provider],
	}

	// Set defaults if not in map
	if cfg.DNS == "" {
		cfg.DNS = "10.2.0.1"
	}
	if cfg.Port == 0 {
		cfg.Port = 51820
	}

	if len(cfg.PrivateKey) == 0 {
		return nil, fmt.Errorf("no private key found for provider: %s", provider)
	}

	// Default address if not set
	if cfg.Address == "" {
		cfg.Address = "10.2.0.2/32"
	}

	return cfg, nil
}

// SaveProvider saves provider credentials as JSON using atomic write.
// privateKey is raw key bytes; JSON encoding handles base64 automatically.
func SaveProvider(configDir, provider string, privateKey []byte, address string) error {
	// Validate provider name to prevent path traversal
	if err := ValidateName(provider); err != nil {
		return fmt.Errorf("invalid provider name: %w", err)
	}

	providersDir := filepath.Join(configDir, "providers")
	if err := os.MkdirAll(providersDir, 0700); err != nil {
		return err
	}

	path := filepath.Join(providersDir, provider+".json")
	data, err := json.MarshalIndent(providerJSON{
		PrivateKey: privateKey,
		Address:    address,
	}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	// Write to temp file first for atomic save (protects credentials)
	tmpFile, err := os.CreateTemp(providersDir, ".provider.tmp.*")
	if err != nil {
		return err
	}

	tmpPath := tmpFile.Name()
	// CreateTemp already creates the file with mode 0600, but on
	// filesystems with default ACL inheritance (NFSv4, some xfs setups)
	// the inherited ACL can widen access regardless. Explicit Chmod
	// resets to 0600. Surfacing the error matters: silent failure here
	// is the difference between "credential file is 0600" and
	// "credential file is group-readable and we don't know."
	if err := os.Chmod(tmpPath, 0600); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to enforce 0600 on provider credential temp file: %w", err)
	}

	// Clean up temp file on failure
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
	// Check Close error before rename — particularly important for the
	// credentials file: Sync can succeed while Close surfaces a delayed
	// write error on network filesystems, and the rename would otherwise
	// install a partial credential file. Defer cleanup via `success` still
	// fires when we return here.
	if err := tmpFile.Close(); err != nil {
		return err
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}

	success = true
	return nil
}

// ListProviders returns a list of configured providers
func ListProviders(configDir string) ([]string, error) {
	providersDir := filepath.Join(configDir, "providers")
	entries, err := os.ReadDir(providersDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var providers []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		providers = append(providers, name)
	}

	return providers, nil
}

// DeleteProvider removes a provider's config file and cache file.
// When the last provider is removed, the shared raw gluetun cache
// (cache/servers_raw.json) is also deleted — with no providers to filter
// for, keeping it around is pure orphan state.
// Returns an error if the provider name is invalid or if removal fails
// for a reason other than the file not existing.
func DeleteProvider(configDir, provider string) error {
	if err := ValidateName(provider); err != nil {
		return fmt.Errorf("invalid provider name: %w", err)
	}

	confPath := filepath.Join(configDir, "providers", provider+".json")
	cachePath := filepath.Join(configDir, "cache", provider+"_servers.json")

	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove provider config: %w", err)
	}
	if err := os.Remove(cachePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove provider cache: %w", err)
	}

	// If no providers remain, the shared raw cache has nothing left to
	// filter for — remove it so uninstall/remove leaves a clean state.
	remaining, err := ListProviders(configDir)
	if err == nil && len(remaining) == 0 {
		rawPath := filepath.Join(configDir, "cache", "servers_raw.json")
		if err := os.Remove(rawPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove raw gluetun cache: %w", err)
		}
	}

	return nil
}

// CachedServer represents a server from the gluetun cache
type CachedServer struct {
	ServerName  string   `json:"server_name"`
	Hostname    string   `json:"hostname"`
	Country     string   `json:"country"`
	City        string   `json:"city"`
	PublicKey   string   `json:"wgpubkey"`
	IPs         []string `json:"ips"`
	IP          string   `json:"-"` // Computed from IPs
	PortForward bool     `json:"port_forward"`
	Tor         bool     `json:"tor"`
	SecureCore  bool     `json:"secure_core"`
	Stream      bool     `json:"stream"`
	Free        bool     `json:"free"`
}

// LoadServerFromCache loads a specific server from the provider's cache
func LoadServerFromCache(configDir, provider, serverName string) (*CachedServer, error) {
	if err := ValidateName(provider); err != nil {
		return nil, fmt.Errorf("invalid provider name: %w", err)
	}
	if err := ValidateName(serverName); err != nil {
		return nil, fmt.Errorf("invalid server name: %w", err)
	}
	cachePath := filepath.Join(configDir, "cache", provider+"_servers.json")

	data, err := readCacheBounded(cachePath)
	if err != nil {
		return nil, fmt.Errorf("cache not found for provider %s: %w", provider, err)
	}

	var servers []CachedServer
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, fmt.Errorf("failed to parse cache: %w", err)
	}

	for _, srv := range servers {
		name := srv.ServerName
		if name == "" {
			name = srv.Hostname
		}
		if name == serverName {
			if len(srv.IPs) > 0 {
				srv.IP = srv.IPs[0]
			}
			return &srv, nil
		}
	}

	return nil, fmt.Errorf("server not found in cache: %s", serverName)
}

// LoadServerCache loads all servers from a provider's cache
func LoadServerCache(configDir, provider string) ([]CachedServer, error) {
	if err := ValidateName(provider); err != nil {
		return nil, fmt.Errorf("invalid provider name: %w", err)
	}
	cachePath := filepath.Join(configDir, "cache", provider+"_servers.json")

	data, err := readCacheBounded(cachePath)
	if err != nil {
		return nil, fmt.Errorf("cache not found for provider %s: %w", provider, err)
	}

	var servers []CachedServer
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, fmt.Errorf("failed to parse cache: %w", err)
	}

	// Populate IP field
	for i := range servers {
		if len(servers[i].IPs) > 0 {
			servers[i].IP = servers[i].IPs[0]
		}
	}

	return servers, nil
}

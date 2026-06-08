package config

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalizeKillswitchAutoDisable(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"true", "true"},
		{"1", "true"},
		{"yes", "true"},
		{"auto", "true"},
		{"false", "false"},
		{"0", "false"},
		{"no", "false"},
		{"prompt", "false"},
		{"never", "never"},
		{"keep", "never"},
		{"garbage", "true"},
		{"", "true"},
		{"  true  ", "true"},
		{"TRUE", "true"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeKillswitchAutoDisable(tt.input)
			if got != tt.want {
				t.Errorf("normalizeKillswitchAutoDisable(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"protonvpn", false},
		{"US-NY#123", false},
		{"server.name", false},
		{"my_server-1", false},
		{"", true},
		{"..", true},
		{"../etc/passwd", true},
		{"foo/bar", true},
		{"foo\\bar", true},
		{"foo bar", true},
		{"hello@world", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateName(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ConnectionName != "wg0" {
		t.Errorf("default ConnectionName = %q, want 'wg0'", cfg.ConnectionName)
	}
	if cfg.KillswitchAutoDisable != "true" {
		t.Errorf("default KillswitchAutoDisable = %q, want 'true'", cfg.KillswitchAutoDisable)
	}
	if !cfg.AutoRecover {
		t.Error("default AutoRecover should be true")
	}
	if cfg.AutoFailover {
		t.Error("default AutoFailover should be false")
	}
	if cfg.Autostart {
		t.Error("default Autostart should be false")
	}
	if cfg.AutostartMode != "last_used" {
		t.Errorf("default AutostartMode = %q, want 'last_used'", cfg.AutostartMode)
	}
	if cfg.LogMode != "safe" {
		t.Errorf("default LogMode = %q, want 'safe'", cfg.LogMode)
	}
	if cfg.ConfigDir == "" {
		t.Error("ConfigDir should not be empty")
	}
	if cfg.ConfigFile == "" {
		t.Error("ConfigFile should not be empty")
	}
	if !strings.HasSuffix(cfg.ConfigFile, "config.json") {
		t.Errorf("ConfigFile should end with config.json, got %q", cfg.ConfigFile)
	}
}

// writeTestConfig is a helper that writes a JSON config file for tests.
func writeTestConfig(t *testing.T, configDir string, obj interface{}) {
	t.Helper()
	os.MkdirAll(configDir, 0700)
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal test config: %v", err)
	}
	os.WriteFile(filepath.Join(configDir, "config.json"), data, 0600)
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ConnectionName:        "wg-test",
		LastConnectedServer:   "US-NY#42",
		LastPublicIP:          "1.2.3.4",
		RealPublicIP:          "5.6.7.8",
		ConnectedSince:        time.Unix(1700000000, 0),
		KillswitchAutoDisable: "never",
		AutoRecover:           true,
		AutoFailover:          true,
		Autostart:             true,
		AutostartMode:         "quickest",
		AutostartServer:       "SE#5",
		Favorites:             []string{"US-NY#42", "SE#5", "DE#1"},
		LogConnection:         true,
		LogAutorecover:        false,
		LogFirewall:           true,
		LogProvider:           false,
		LogAutostart:          true,
		LogMode:               "accurate",
		InstallSourceDir:      "/tmp/lazyvpn-src",
		ConfigDir:             configDir,
		ConfigFile:            filepath.Join(configDir, "config.json"),
	}

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Verify file is valid JSON
	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatalf("config file not readable: %v", err)
	}
	if !json.Valid(data) {
		t.Error("saved config is not valid JSON")
	}

	// Verify some JSON content
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("cannot parse saved JSON: %v", err)
	}
	if raw["connection_name"] != "wg-test" {
		t.Errorf("JSON connection_name = %v, want 'wg-test'", raw["connection_name"])
	}
	if _, ok := raw["killswitch"]; ok {
		t.Error("JSON should NOT contain 'killswitch' — the field was removed (firewall state is the source of truth)")
	}

	// Load from disk via Load() (uses HOME-based path)
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if loaded.ConnectionName != "wg-test" {
		t.Errorf("loaded ConnectionName = %q, want 'wg-test'", loaded.ConnectionName)
	}
	if loaded.LastConnectedServer != "US-NY#42" {
		t.Errorf("loaded LastConnectedServer = %q", loaded.LastConnectedServer)
	}
	if loaded.ConnectedSince.Unix() != 1700000000 {
		t.Errorf("loaded ConnectedSince = %v, want Unix 1700000000", loaded.ConnectedSince)
	}
	if loaded.KillswitchAutoDisable != "never" {
		t.Errorf("loaded KillswitchAutoDisable = %q, want 'never'", loaded.KillswitchAutoDisable)
	}
	if !loaded.AutoFailover {
		t.Error("loaded AutoFailover should be true")
	}
	if loaded.AutostartMode != "quickest" {
		t.Errorf("loaded AutostartMode = %q", loaded.AutostartMode)
	}
	if len(loaded.Favorites) != 3 {
		t.Errorf("loaded Favorites length = %d, want 3", len(loaded.Favorites))
	}
	if !loaded.LogConnection {
		t.Error("loaded LogConnection should be true")
	}
	if loaded.LogMode != "accurate" {
		t.Errorf("loaded LogMode = %q", loaded.LogMode)
	}
}

func TestLoadMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() should not error on missing file: %v", err)
	}
	if cfg.ConnectionName != "wg0" {
		t.Errorf("default ConnectionName = %q, want 'wg0'", cfg.ConnectionName)
	}
}

// TestLoadFailsOnUnresolvableHome verifies that when both HOME and the
// SUDO_USER fallback fail to resolve a home directory, Load returns an
// error rather than silently producing a relative ConfigDir that would
// cause Save to write into CWD/.config/lazyvpn.
func TestLoadFailsOnUnresolvableHome(t *testing.T) {
	// Clear HOME and SUDO_USER. With both unset and not running as
	// root, os.UserHomeDir() returns ENOENT and the SUDO_USER branch
	// in DefaultConfig doesn't fire (Geteuid() != 0). configDir then
	// becomes relative.
	t.Setenv("HOME", "")
	t.Setenv("SUDO_USER", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when home directory is unresolvable, got nil")
	}
	if !strings.Contains(err.Error(), "home directory") {
		t.Errorf("error should mention 'home directory', got: %v", err)
	}
}

// TestLoadNormalizesEmptyAutostartMode verifies that a config.json
// with an explicitly empty autostart_mode field gets normalized to
// "last_used" during validate(). Without the normalize, the boot
// subcommand's switch on cfg.AutostartMode would fall through to
// the default branch (printing "Unknown autostart mode:") and silently
// skip autoconnect even though the user enabled Autostart.
//
// The seed-shadow-with-defaults path in Load handles the MISSING
// field case (Unmarshal preserves the default seed). This test
// covers the manually-cleared case where the JSON explicitly has
// "autostart_mode": "".
func TestLoadNormalizesEmptyAutostartMode(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Explicit empty string overwrites the default seed.
	os.WriteFile(filepath.Join(configDir, "config.json"),
		[]byte(`{"autostart_mode":""}`), 0600)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if cfg.AutostartMode != "last_used" {
		t.Errorf("AutostartMode = %q, want %q (validate should normalize empty)",
			cfg.AutostartMode, "last_used")
	}
}

// TestLoadRejectsHugeConfigFile verifies the bounded-read cap on
// config.json. A corrupted or hand-edited file larger than the
// realistic ~10KB payload would OOM a bare os.ReadFile; the helper
// caps reads at 1MB.
//
// We write a 2MB file (well over the cap), call Load, and assert
// a clear "exceeds N byte cap" error rather than a JSON parse
// failure or a successful read of an oversized buffer.
func TestLoadRejectsHugeConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	// 2MB of valid-looking JSON whitespace inside a wrapper. The
	// content doesn't matter — we just need the file size to exceed
	// the 1MB cap.
	bigPayload := append([]byte(`{"connection_name":"wg0","_padding":"`),
		make([]byte, 2*1024*1024)...)
	bigPayload = append(bigPayload, []byte(`"}`)...)
	for i := 0; i < 2*1024*1024; i++ {
		bigPayload[len(`{"connection_name":"wg0","_padding":"`)+i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), bigPayload, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := Load()
	if err == nil {
		t.Fatal("Load should reject oversized config.json")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected 'exceeds' in error, got: %v", err)
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(configDir, 0700)

	os.WriteFile(filepath.Join(configDir, "config.json"), []byte("{invalid json"), 0600)

	_, err := Load()
	if err == nil {
		t.Error("Load() should return error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "invalid config JSON") {
		t.Errorf("error should mention invalid JSON, got: %v", err)
	}
}

func TestSaveProducesValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.ConfigDir = configDir
	cfg.ConfigFile = filepath.Join(configDir, "config.json")

	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Error("Save() should produce valid JSON")
	}

	// Verify it round-trips through unmarshal
	var j configJSON
	if err := json.Unmarshal(data, &j); err != nil {
		t.Errorf("cannot unmarshal saved JSON: %v", err)
	}
	if j.ConnectionName != "wg0" {
		t.Errorf("saved ConnectionName = %q, want 'wg0'", j.ConnectionName)
	}
}

func TestSaveProvider(t *testing.T) {
	tmpDir := t.TempDir()

	err := SaveProvider(tmpDir, "protonvpn", []byte("testkey123="), "10.2.0.2/32")
	if err != nil {
		t.Fatalf("SaveProvider() error: %v", err)
	}

	providerFile := filepath.Join(tmpDir, "providers", "protonvpn.json")
	data, err := os.ReadFile(providerFile)
	if err != nil {
		t.Fatalf("provider file not created: %v", err)
	}

	if !json.Valid(data) {
		t.Error("provider file should be valid JSON")
	}

	var pj providerJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		t.Fatalf("cannot parse provider JSON: %v", err)
	}
	if string(pj.PrivateKey) != "testkey123=" {
		t.Errorf("PrivateKey = %q, want 'testkey123='", string(pj.PrivateKey))
	}
	if pj.Address != "10.2.0.2/32" {
		t.Errorf("Address = %q, want '10.2.0.2/32'", pj.Address)
	}

	info, _ := os.Stat(providerFile)
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestLoadProvider(t *testing.T) {
	tmpDir := t.TempDir()
	SaveProvider(tmpDir, "mullvad", []byte("myprivatekey=="), "10.64.0.2/32")

	cfg, err := LoadProvider(tmpDir, "mullvad")
	if err != nil {
		t.Fatalf("LoadProvider() error: %v", err)
	}
	if string(cfg.PrivateKey) != "myprivatekey==" {
		t.Errorf("PrivateKey = %q", string(cfg.PrivateKey))
	}
	if cfg.Address != "10.64.0.2/32" {
		t.Errorf("Address = %q", cfg.Address)
	}
	if cfg.DNS != "10.64.0.1" {
		t.Errorf("DNS = %q, want '10.64.0.1'", cfg.DNS)
	}
	if cfg.Port != 51820 {
		t.Errorf("Port = %d, want 51820", cfg.Port)
	}
}

func TestLoadProviderMissing(t *testing.T) {
	_, err := LoadProvider(t.TempDir(), "nonexistent")
	if err == nil {
		t.Error("expected error for missing provider")
	}
}

func TestLoadProviderPathTraversal(t *testing.T) {
	_, err := LoadProvider(t.TempDir(), "../etc/passwd")
	if err == nil {
		t.Error("expected error for path traversal")
	}
}

func TestSaveProviderPathTraversal(t *testing.T) {
	err := SaveProvider(t.TempDir(), "../evil", []byte("key="), "addr")
	if err == nil {
		t.Error("expected error for path traversal")
	}
}

func TestListProviders(t *testing.T) {
	tmpDir := t.TempDir()

	providers, err := ListProviders(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 0 {
		t.Errorf("expected 0 providers, got %d", len(providers))
	}

	SaveProvider(tmpDir, "protonvpn", []byte("key1="), "10.2.0.2/32")
	SaveProvider(tmpDir, "mullvad", []byte("key2="), "10.64.0.2/32")

	providers, err = ListProviders(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(providers))
	}
}

func TestLoadServerFromCache(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	cacheData := `[
		{"server_name":"US-NY#42","ips":["1.2.3.4"],"wgpubkey":"pk="},
		{"server_name":"SE#5","ips":["5.6.7.8","9.10.11.12"],"wgpubkey":"pk2="}
	]`
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte(cacheData), 0644)

	srv, err := LoadServerFromCache(tmpDir, "protonvpn", "US-NY#42")
	if err != nil {
		t.Fatalf("LoadServerFromCache() error: %v", err)
	}
	if srv.IP != "1.2.3.4" {
		t.Errorf("IP = %q, want '1.2.3.4'", srv.IP)
	}

	_, err = LoadServerFromCache(tmpDir, "protonvpn", "NONEXISTENT")
	if err == nil {
		t.Error("expected error for non-existent server")
	}
}

func TestLoadServerCache(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	cacheData := `[{"server_name":"A","ips":["1.1.1.1"]},{"server_name":"B","ips":["2.2.2.2"]}]`
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte(cacheData), 0644)

	servers, err := LoadServerCache(tmpDir, "protonvpn")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
	if servers[0].IP != "1.1.1.1" {
		t.Errorf("servers[0].IP = %q", servers[0].IP)
	}
}

func TestProviderDNSAndPortMaps(t *testing.T) {
	for _, p := range []string{"protonvpn", "mullvad", "ivpn", "airvpn", "nordvpn", "surfshark", "windscribe", "fastestvpn"} {
		if _, ok := ProviderDNS[p]; !ok {
			t.Errorf("ProviderDNS missing %q", p)
		}
		if _, ok := ProviderPort[p]; !ok {
			t.Errorf("ProviderPort missing %q", p)
		}
	}
}

// TestProviderDNSAndPort_SameKeySet pins the cross-map invariant:
// ProviderDNS and ProviderPort must share an identical key set. Every
// provider key MUST appear in both maps — they're consumed together
// in provider-setup flows (LoadProvider uses both to fill in defaults
// when the on-disk config lacks them).
//
// The pre-existing TestProviderDNSAndPortMaps only verifies a hardcoded
// minimum list — it would silently pass if a provider was added to
// ProviderDNS but forgotten in ProviderPort (or vice versa). A divergence
// would surface as a "0 port" or "" DNS at provider-setup time, far
// from the actual missing-entry root cause.
//
// Sibling to TestProviderMapsHaveSameKeySet in internal/provider for
// GluetunProviderMap + ProviderDisplayNames.
func TestProviderDNSAndPort_SameKeySet(t *testing.T) {
	for k := range ProviderDNS {
		if _, ok := ProviderPort[k]; !ok {
			t.Errorf("ProviderPort missing %q (present in ProviderDNS)", k)
		}
	}
	for k := range ProviderPort {
		if _, ok := ProviderDNS[k]; !ok {
			t.Errorf("ProviderDNS missing %q (present in ProviderPort)", k)
		}
	}
	if len(ProviderDNS) != len(ProviderPort) {
		t.Errorf("map sizes differ: ProviderDNS=%d, ProviderPort=%d",
			len(ProviderDNS), len(ProviderPort))
	}
}

func TestDeleteProvider(t *testing.T) {
	tmpDir := t.TempDir()

	// Set up provider and cache
	SaveProvider(tmpDir, "protonvpn", []byte("key="), "10.2.0.2/32")
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte("[]"), 0644)

	// Verify files exist before deletion
	if _, err := os.Stat(filepath.Join(tmpDir, "providers", "protonvpn.json")); err != nil {
		t.Fatal("provider config should exist before delete")
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "protonvpn_servers.json")); err != nil {
		t.Fatal("cache file should exist before delete")
	}

	// Delete provider
	if err := DeleteProvider(tmpDir, "protonvpn"); err != nil {
		t.Fatalf("DeleteProvider() error: %v", err)
	}

	// Verify both files removed
	if _, err := os.Stat(filepath.Join(tmpDir, "providers", "protonvpn.json")); !os.IsNotExist(err) {
		t.Error("provider config should be deleted")
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "protonvpn_servers.json")); !os.IsNotExist(err) {
		t.Error("cache file should be deleted")
	}
}

func TestDeleteProviderPathTraversal(t *testing.T) {
	err := DeleteProvider(t.TempDir(), "../evil")
	if err == nil {
		t.Error("expected error for path traversal")
	}
}

func TestDeleteProviderNonexistent(t *testing.T) {
	// Deleting a non-existent provider should succeed (idempotent)
	if err := DeleteProvider(t.TempDir(), "nonexistent"); err != nil {
		t.Errorf("DeleteProvider(nonexistent) error: %v", err)
	}
}

// TestDeleteProviderLastRemovesRawCache verifies that when the last provider
// is deleted, the shared gluetun raw cache (servers_raw.json) is also removed.
// With no providers left, it has nothing to filter for and is pure orphan state.
func TestDeleteProviderLastRemovesRawCache(t *testing.T) {
	tmpDir := t.TempDir()
	SaveProvider(tmpDir, "protonvpn", []byte("key="), "10.2.0.2/32")
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)
	rawPath := filepath.Join(cacheDir, "servers_raw.json")
	os.WriteFile(rawPath, []byte("{}"), 0644)

	if err := DeleteProvider(tmpDir, "protonvpn"); err != nil {
		t.Fatalf("DeleteProvider() error: %v", err)
	}
	if _, err := os.Stat(rawPath); !os.IsNotExist(err) {
		t.Error("servers_raw.json should be deleted when last provider is removed")
	}
}

// TestDeleteProviderKeepsRawCacheWithRemaining verifies the raw cache stays
// intact when other providers still exist — they may need to filter from it.
func TestDeleteProviderKeepsRawCacheWithRemaining(t *testing.T) {
	tmpDir := t.TempDir()
	SaveProvider(tmpDir, "protonvpn", []byte("key="), "10.2.0.2/32")
	SaveProvider(tmpDir, "mullvad", []byte("key="), "10.64.0.2/32")
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)
	rawPath := filepath.Join(cacheDir, "servers_raw.json")
	os.WriteFile(rawPath, []byte("{}"), 0644)

	if err := DeleteProvider(tmpDir, "protonvpn"); err != nil {
		t.Fatalf("DeleteProvider() error: %v", err)
	}
	if _, err := os.Stat(rawPath); err != nil {
		t.Errorf("servers_raw.json should be kept while mullvad remains: %v", err)
	}
}

func TestReload(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Create initial config
	cfg := &Config{
		ConnectionName:        "wg0",
		AutoRecover:           true,
		AutoFailover:          false,
		LogMode:               "safe",
		KillswitchAutoDisable: "true",
		ConfigDir:             configDir,
		ConfigFile:            filepath.Join(configDir, "config.json"),
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	// Modify config file on disk (simulate external change)
	cfg2 := &Config{
		ConnectionName:        "wg-test",
		AutoRecover:           false,
		AutoFailover:          true,
		LogMode:               "accurate",
		Favorites:             []string{"US-NY#42", "SE#5"},
		KillswitchAutoDisable: "true",
		ConfigDir:             configDir,
		ConfigFile:            filepath.Join(configDir, "config.json"),
	}
	if err := cfg2.Save(); err != nil {
		t.Fatal(err)
	}

	// Reload and verify fields updated
	if err := cfg.Reload(); err != nil {
		t.Fatalf("Reload() error: %v", err)
	}

	if cfg.ConnectionName != "wg-test" {
		t.Errorf("after reload ConnectionName = %q, want 'wg-test'", cfg.ConnectionName)
	}
	if cfg.AutoRecover {
		t.Error("after reload AutoRecover should be false")
	}
	if !cfg.AutoFailover {
		t.Error("after reload AutoFailover should be true")
	}
	if cfg.LogMode != "accurate" {
		t.Errorf("after reload LogMode = %q", cfg.LogMode)
	}
	if len(cfg.Favorites) != 2 {
		t.Errorf("after reload Favorites len = %d, want 2", len(cfg.Favorites))
	}
}

func TestReloadMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	cfg := &Config{
		ConnectionName: "custom",
		ConfigDir:      filepath.Join(tmpDir, ".config", "lazyvpn"),
		ConfigFile:     filepath.Join(tmpDir, ".config", "lazyvpn", "config.json"),
	}

	// Reload from non-existent file should reset to defaults
	if err := cfg.Reload(); err != nil {
		t.Fatal(err)
	}

	if cfg.ConnectionName != "wg0" {
		t.Errorf("after reload (missing file) ConnectionName = %q, want 'wg0'", cfg.ConnectionName)
	}
}

func TestLoadProviderDefaults(t *testing.T) {
	tmpDir := t.TempDir()

	// Provider without known DNS/Port mapping
	providersDir := filepath.Join(tmpDir, "providers")
	os.MkdirAll(providersDir, 0700)
	data, _ := json.Marshal(providerJSON{PrivateKey: []byte("testkey="), Address: "10.5.0.2/32"})
	os.WriteFile(filepath.Join(providersDir, "unknownvpn.json"), data, 0600)

	cfg, err := LoadProvider(tmpDir, "unknownvpn")
	if err != nil {
		t.Fatal(err)
	}

	// Should get fallback defaults
	if cfg.DNS != "10.2.0.1" {
		t.Errorf("fallback DNS = %q, want '10.2.0.1'", cfg.DNS)
	}
	if cfg.Port != 51820 {
		t.Errorf("fallback Port = %d, want 51820", cfg.Port)
	}
}

func TestLoadProviderMissingPrivateKey(t *testing.T) {
	tmpDir := t.TempDir()
	providersDir := filepath.Join(tmpDir, "providers")
	os.MkdirAll(providersDir, 0700)
	data, _ := json.Marshal(providerJSON{Address: "10.2.0.2/32"})
	os.WriteFile(filepath.Join(providersDir, "badprov.json"), data, 0600)

	_, err := LoadProvider(tmpDir, "badprov")
	if err == nil {
		t.Error("expected error for missing private key")
	}
}

func TestLoadProviderDefaultAddress(t *testing.T) {
	tmpDir := t.TempDir()
	providersDir := filepath.Join(tmpDir, "providers")
	os.MkdirAll(providersDir, 0700)
	data, _ := json.Marshal(providerJSON{PrivateKey: []byte("testkey=")})
	os.WriteFile(filepath.Join(providersDir, "protonvpn.json"), data, 0600)

	cfg, err := LoadProvider(tmpDir, "protonvpn")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Address != "10.2.0.2/32" {
		t.Errorf("default Address = %q, want '10.2.0.2/32'", cfg.Address)
	}
}

func TestLoadServerFromCacheByHostname(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	// Server with hostname but no server_name
	cacheData := `[{"hostname":"se-sto-wg-001","ips":["5.6.7.8"],"wgpubkey":"pk="}]`
	os.WriteFile(filepath.Join(cacheDir, "mullvad_servers.json"), []byte(cacheData), 0644)

	srv, err := LoadServerFromCache(tmpDir, "mullvad", "se-sto-wg-001")
	if err != nil {
		t.Fatalf("LoadServerFromCache() error: %v", err)
	}
	if srv.IP != "5.6.7.8" {
		t.Errorf("IP = %q", srv.IP)
	}
}

func TestLoadServerCachePathTraversal(t *testing.T) {
	_, err := LoadServerCache(t.TempDir(), "../evil")
	if err == nil {
		t.Error("expected error for path traversal")
	}
}

func TestLoadServerFromCachePathTraversal(t *testing.T) {
	_, err := LoadServerFromCache(t.TempDir(), "../evil", "server")
	if err == nil {
		t.Error("expected error for path traversal (provider)")
	}
	_, err = LoadServerFromCache(t.TempDir(), "protonvpn", "../evil")
	if err == nil {
		t.Error("expected error for path traversal (server name)")
	}
}

// ---------------------------------------------------------------------------
// Additional tests for coverage improvement
// ---------------------------------------------------------------------------

func TestLookupUserHome(t *testing.T) {
	// lookupUserHome reads /etc/passwd for a given username.
	// We can test it with the current user who definitely has an entry.
	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	home := lookupUserHome(currentUser.Username)
	if home == "" {
		t.Errorf("lookupUserHome(%q) returned empty, expected a home directory", currentUser.Username)
	}
	if home != currentUser.HomeDir {
		t.Errorf("lookupUserHome(%q) = %q, want %q", currentUser.Username, home, currentUser.HomeDir)
	}
}

func TestLookupUserHomeNonexistent(t *testing.T) {
	// A user that definitely doesn't exist should return ""
	home := lookupUserHome("this_user_does_not_exist_xyzzy_99999")
	if home != "" {
		t.Errorf("lookupUserHome for nonexistent user returned %q, want empty", home)
	}
}

func TestDefaultConfigDaemonTuningDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.HealthCheckInterval != 5 {
		t.Errorf("default HealthCheckInterval = %d, want 5", cfg.HealthCheckInterval)
	}
	if cfg.MaxHealthFails != 3 {
		t.Errorf("default MaxHealthFails = %d, want 3", cfg.MaxHealthFails)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("default MaxRetries = %d, want 3", cfg.MaxRetries)
	}
}

func TestLoadConnectedSinceEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		value    int64
		wantZero bool
	}{
		{"zero", 0, true},
		{"negative", -100, true},
		{"valid", 1700000000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeTestConfig(t, configDir, map[string]interface{}{
				"connected_since": tt.value,
			})
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantZero && !cfg.ConnectedSince.IsZero() {
				t.Errorf("ConnectedSince should be zero for input %d, got %v", tt.value, cfg.ConnectedSince)
			}
			if !tt.wantZero && cfg.ConnectedSince.IsZero() {
				t.Errorf("ConnectedSince should not be zero for input %d", tt.value)
			}
		})
	}
}

func TestLoadHealthCheckNegativeAndOverflow(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Negative and zero values should be rejected by validate(), keeping defaults
	writeTestConfig(t, configDir, map[string]interface{}{
		"health_check_interval": -1,
		"max_health_fails":      0,
		"max_retries":           -999,
	})

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// Defaults should be preserved since validate() resets invalid values
	if cfg.HealthCheckInterval != 5 {
		t.Errorf("HealthCheckInterval = %d, want default 5 for negative input", cfg.HealthCheckInterval)
	}
	if cfg.MaxHealthFails != 3 {
		t.Errorf("MaxHealthFails = %d, want default 3 for zero input", cfg.MaxHealthFails)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want default 3 for negative input", cfg.MaxRetries)
	}
}

func TestLoadHealthCheckValidValues(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	writeTestConfig(t, configDir, map[string]interface{}{
		"health_check_interval": 10,
		"max_health_fails":      5,
		"max_retries":           7,
	})

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HealthCheckInterval != 10 {
		t.Errorf("HealthCheckInterval = %d, want 10", cfg.HealthCheckInterval)
	}
	if cfg.MaxHealthFails != 5 {
		t.Errorf("MaxHealthFails = %d, want 5", cfg.MaxHealthFails)
	}
	if cfg.MaxRetries != 7 {
		t.Errorf("MaxRetries = %d, want 7", cfg.MaxRetries)
	}
}

func TestLoadEmptyFavorites(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Favorites with empty array should result in empty favorites
	writeTestConfig(t, configDir, map[string]interface{}{
		"favorites": []string{},
	})

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Favorites) != 0 {
		t.Errorf("Favorites should be empty, got %v", cfg.Favorites)
	}
}

func TestLoadSingleFavorite(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	writeTestConfig(t, configDir, map[string]interface{}{
		"favorites": []string{"US-NY#42"},
	})

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Favorites) != 1 || cfg.Favorites[0] != "US-NY#42" {
		t.Errorf("Favorites = %v, want [US-NY#42]", cfg.Favorites)
	}
}

func TestLoadAllLogFields(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	writeTestConfig(t, configDir, map[string]interface{}{
		"log_connection":     true,
		"log_autorecover":    true,
		"log_firewall":       true,
		"log_provider":       true,
		"log_autostart":      true,
		"log_mode":           "accurate",
		"install_source_dir": "/opt/lazyvpn",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.LogConnection {
		t.Error("LogConnection should be true")
	}
	if !cfg.LogAutorecover {
		t.Error("LogAutorecover should be true")
	}
	if !cfg.LogFirewall {
		t.Error("LogFirewall should be true")
	}
	if !cfg.LogProvider {
		t.Error("LogProvider should be true")
	}
	if !cfg.LogAutostart {
		t.Error("LogAutostart should be true")
	}
	if cfg.LogMode != "accurate" {
		t.Errorf("LogMode = %q", cfg.LogMode)
	}
	if cfg.InstallSourceDir != "/opt/lazyvpn" {
		t.Errorf("InstallSourceDir = %q", cfg.InstallSourceDir)
	}
}

func TestSaveSilentWhenConfigDirMissing(t *testing.T) {
	// Save now returns nil silently when ConfigDir doesn't exist (lazyvpn not
	// installed). This prevents `lazyvpn` invocations after uninstall from
	// re-creating ~/.config/lazyvpn/, which would then trip the install
	// detector's "leftover config" path.
	tmpDir := t.TempDir()
	cfg := &Config{
		ConnectionName: "wg0",
		ConfigDir:      filepath.Join(tmpDir, "nonexistent"),
		ConfigFile:     filepath.Join(tmpDir, "nonexistent", "config.json"),
	}

	if err := cfg.Save(); err != nil {
		t.Errorf("Save() should be silent when ConfigDir missing, got: %v", err)
	}
	if _, err := os.Stat(cfg.ConfigDir); !os.IsNotExist(err) {
		t.Error("Save() should not have created ConfigDir")
	}
}

func TestSaveCannotCreateTempFile(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(configDir, 0700)

	cfg := &Config{
		ConnectionName: "wg0",
		ConfigDir:      configDir,
		ConfigFile:     filepath.Join(configDir, "config.json"),
	}

	// First save should succeed to create the directory
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	// Now make the config dir read-only so temp file creation fails
	os.Chmod(configDir, 0500)
	defer os.Chmod(configDir, 0700) // restore for cleanup

	err := cfg.Save()
	if err == nil {
		t.Error("Save() should fail when directory is read-only")
	}
}

func TestSaveAndLoadRoundTripAllFields(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ConnectionName:        "wg-full",
		LastConnectedServer:   "dynamic:protonvpn:US-NY#42",
		LastPublicIP:          "203.0.113.1",
		LastServerFeatures:    "p2p,tor",
		RealPublicIP:          "198.51.100.1",
		ConnectedSince:        time.Unix(1700000000, 0),
		KillswitchAutoDisable: "never",
		AutoRecover:           false,
		AutoFailover:          true,
		Autostart:             true,
		AutostartMode:         "specific",
		AutostartServer:       "DE#1",
		Favorites:             []string{"US-NY#42", "SE#5"},
		HealthCheckInterval:   10,
		LightTickInterval:     5,
		HeavyTickInterval:     20,
		ReconnectThreshold:    50,
		MaxHealthFails:        5,
		MaxRetries:            7,
		CustomMTU:             1400,
		LogConnection:         true,
		LogAutorecover:        true,
		LogFirewall:           true,
		LogProvider:           true,
		LogAutostart:          true,
		LogMode:               "accurate",
		Distro:                "omarchy",
		FSType:                "btrfs",
		InstallSourceDir:      "/opt/lazyvpn",
		ConfigDir:             configDir,
		ConfigFile:            filepath.Join(configDir, "config.json"),
	}

	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// Verify every field that persists through Save/Load
	if loaded.ConnectionName != "wg-full" {
		t.Errorf("ConnectionName = %q", loaded.ConnectionName)
	}
	if loaded.LastConnectedServer != "dynamic:protonvpn:US-NY#42" {
		t.Errorf("LastConnectedServer = %q", loaded.LastConnectedServer)
	}
	if loaded.LastPublicIP != "203.0.113.1" {
		t.Errorf("LastPublicIP = %q", loaded.LastPublicIP)
	}
	if loaded.Distro != "omarchy" {
		t.Errorf("Distro = %q, want 'omarchy'", loaded.Distro)
	}
	if loaded.FSType != "btrfs" {
		t.Errorf("FSType = %q, want 'btrfs'", loaded.FSType)
	}
	if loaded.LastServerFeatures != "p2p,tor" {
		t.Errorf("LastServerFeatures = %q", loaded.LastServerFeatures)
	}
	if loaded.RealPublicIP != "198.51.100.1" {
		t.Errorf("RealPublicIP = %q", loaded.RealPublicIP)
	}
	if loaded.ConnectedSince.Unix() != 1700000000 {
		t.Errorf("ConnectedSince = %v", loaded.ConnectedSince)
	}
	if loaded.KillswitchAutoDisable != "never" {
		t.Errorf("KillswitchAutoDisable = %q", loaded.KillswitchAutoDisable)
	}
	if loaded.AutoRecover {
		t.Error("AutoRecover should be false")
	}
	if !loaded.AutoFailover {
		t.Error("AutoFailover should be true")
	}
	if loaded.HealthCheckInterval != 10 {
		t.Errorf("HealthCheckInterval = %d", loaded.HealthCheckInterval)
	}
	if loaded.LightTickInterval != 5 {
		t.Errorf("LightTickInterval = %d", loaded.LightTickInterval)
	}
	if loaded.HeavyTickInterval != 20 {
		t.Errorf("HeavyTickInterval = %d", loaded.HeavyTickInterval)
	}
	if loaded.ReconnectThreshold != 50 {
		t.Errorf("ReconnectThreshold = %d", loaded.ReconnectThreshold)
	}
	if loaded.MaxHealthFails != 5 {
		t.Errorf("MaxHealthFails = %d", loaded.MaxHealthFails)
	}
	if loaded.MaxRetries != 7 {
		t.Errorf("MaxRetries = %d", loaded.MaxRetries)
	}
	if loaded.CustomMTU != 1400 {
		t.Errorf("CustomMTU = %d", loaded.CustomMTU)
	}
	if loaded.AutostartServer != "DE#1" {
		t.Errorf("AutostartServer = %q", loaded.AutostartServer)
	}
	if !loaded.Autostart {
		t.Error("Autostart should be true")
	}
	if !loaded.LogAutorecover {
		t.Error("LogAutorecover should be true")
	}
	if !loaded.LogFirewall {
		t.Error("LogFirewall should be true")
	}
	if !loaded.LogProvider {
		t.Error("LogProvider should be true")
	}
	if !loaded.LogAutostart {
		t.Error("LogAutostart should be true")
	}
	if loaded.InstallSourceDir != "/opt/lazyvpn" {
		t.Errorf("InstallSourceDir = %q", loaded.InstallSourceDir)
	}
	if len(loaded.Favorites) != 2 {
		t.Errorf("Favorites len = %d, want 2", len(loaded.Favorites))
	}
}

func TestMigrateFavoritesFromV1(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(configDir, 0700)

	// Create a config file without favorites
	writeTestConfig(t, configDir, map[string]interface{}{
		"connection_name": "wg0",
	})

	// Create a v1-style favorites file
	favContent := "# Favorites\nUS-NY#42\nSE#5\nDE#1\n"
	os.WriteFile(filepath.Join(configDir, "favorites"), []byte(favContent), 0600)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Favorites) != 3 {
		t.Fatalf("Favorites len = %d, want 3", len(cfg.Favorites))
	}
	if cfg.Favorites[0] != "US-NY#42" {
		t.Errorf("Favorites[0] = %q", cfg.Favorites[0])
	}
	if cfg.Favorites[1] != "SE#5" {
		t.Errorf("Favorites[1] = %q", cfg.Favorites[1])
	}
	if cfg.Favorites[2] != "DE#1" {
		t.Errorf("Favorites[2] = %q", cfg.Favorites[2])
	}
}

func TestMigrateFavoritesEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(configDir, 0700)

	// Config with no favorites and no v1 favorites file
	writeTestConfig(t, configDir, map[string]interface{}{
		"connection_name": "wg0",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Favorites) != 0 {
		t.Errorf("Favorites should be empty when no v1 file exists, got %v", cfg.Favorites)
	}
}

func TestMigrateFavoritesEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(configDir, 0700)

	// Config with no favorites
	writeTestConfig(t, configDir, map[string]interface{}{
		"connection_name": "wg0",
	})

	// Create an empty v1 favorites file
	os.WriteFile(filepath.Join(configDir, "favorites"), []byte("# just a comment\n\n"), 0600)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// Empty favorites file (only comments/blank lines) should not populate Favorites
	if len(cfg.Favorites) != 0 {
		t.Errorf("Favorites should be empty for v1 file with only comments, got %v", cfg.Favorites)
	}
}

func TestLoadServerFromCacheEmptyIPs(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	// Server with empty IPs array
	cacheData := `[{"server_name":"US-NY#42","ips":[],"wgpubkey":"pk="}]`
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte(cacheData), 0644)

	srv, err := LoadServerFromCache(tmpDir, "protonvpn", "US-NY#42")
	if err != nil {
		t.Fatalf("LoadServerFromCache() error: %v", err)
	}
	if srv.IP != "" {
		t.Errorf("IP should be empty for server with no IPs, got %q", srv.IP)
	}
}

func TestLoadServerFromCacheNullIPs(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	// Server with null IPs
	cacheData := `[{"server_name":"US-NY#42","ips":null,"wgpubkey":"pk="}]`
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte(cacheData), 0644)

	srv, err := LoadServerFromCache(tmpDir, "protonvpn", "US-NY#42")
	if err != nil {
		t.Fatalf("LoadServerFromCache() error: %v", err)
	}
	if srv.IP != "" {
		t.Errorf("IP should be empty for null IPs, got %q", srv.IP)
	}
}

func TestLoadServerFromCacheMalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte("{not json}"), 0644)

	_, err := LoadServerFromCache(tmpDir, "protonvpn", "US-NY#42")
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse cache") {
		t.Errorf("error should mention parse failure, got: %v", err)
	}
}

func TestLoadServerFromCacheMissingFile(t *testing.T) {
	_, err := LoadServerFromCache(t.TempDir(), "protonvpn", "US-NY#42")
	if err == nil {
		t.Error("expected error for missing cache file")
	}
	if !strings.Contains(err.Error(), "cache not found") {
		t.Errorf("error should mention cache not found, got: %v", err)
	}
}

func TestLoadServerCacheMalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte("not json at all"), 0644)

	_, err := LoadServerCache(tmpDir, "protonvpn")
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse cache") {
		t.Errorf("error should mention parse failure, got: %v", err)
	}
}

func TestLoadServerCacheMissingFile(t *testing.T) {
	_, err := LoadServerCache(t.TempDir(), "protonvpn")
	if err == nil {
		t.Error("expected error for missing cache file")
	}
}

func TestLoadServerCacheEmptyIPs(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	// Mix of servers: one with IPs, one without
	cacheData := `[
		{"server_name":"A","ips":["1.1.1.1"]},
		{"server_name":"B","ips":[]},
		{"server_name":"C","ips":null}
	]`
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte(cacheData), 0644)

	servers, err := LoadServerCache(tmpDir, "protonvpn")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(servers))
	}
	if servers[0].IP != "1.1.1.1" {
		t.Errorf("servers[0].IP = %q, want '1.1.1.1'", servers[0].IP)
	}
	if servers[1].IP != "" {
		t.Errorf("servers[1].IP should be empty, got %q", servers[1].IP)
	}
	if servers[2].IP != "" {
		t.Errorf("servers[2].IP should be empty, got %q", servers[2].IP)
	}
}

func TestLoadServerCacheWithAllFields(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	cacheData := `[{
		"server_name": "US-NY#42",
		"hostname": "us-ny-42.protonvpn.net",
		"country": "United States",
		"city": "New York",
		"wgpubkey": "publickey123=",
		"ips": ["1.2.3.4", "5.6.7.8"],
		"port_forward": true,
		"tor": false,
		"secure_core": true,
		"stream": true,
		"free": false
	}]`
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte(cacheData), 0644)

	servers, err := LoadServerCache(tmpDir, "protonvpn")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	srv := servers[0]
	if srv.ServerName != "US-NY#42" {
		t.Errorf("ServerName = %q", srv.ServerName)
	}
	if srv.Hostname != "us-ny-42.protonvpn.net" {
		t.Errorf("Hostname = %q", srv.Hostname)
	}
	if srv.Country != "United States" {
		t.Errorf("Country = %q", srv.Country)
	}
	if srv.City != "New York" {
		t.Errorf("City = %q", srv.City)
	}
	if srv.PublicKey != "publickey123=" {
		t.Errorf("PublicKey = %q", srv.PublicKey)
	}
	if srv.IP != "1.2.3.4" {
		t.Errorf("IP = %q, want first IP '1.2.3.4'", srv.IP)
	}
	if !srv.PortForward {
		t.Error("PortForward should be true")
	}
	if srv.Tor {
		t.Error("Tor should be false")
	}
	if !srv.SecureCore {
		t.Error("SecureCore should be true")
	}
	if !srv.Stream {
		t.Error("Stream should be true")
	}
	if srv.Free {
		t.Error("Free should be false")
	}
}

func TestListProvidersSkipsNonJSONFiles(t *testing.T) {
	tmpDir := t.TempDir()
	providersDir := filepath.Join(tmpDir, "providers")
	os.MkdirAll(providersDir, 0700)

	// Create a .json file, a non-.json file, and a subdirectory
	SaveProvider(tmpDir, "protonvpn", []byte("k="), "10.2.0.2/32")
	os.WriteFile(filepath.Join(providersDir, "notes.txt"), []byte("some notes"), 0600)
	os.WriteFile(filepath.Join(providersDir, ".hidden"), []byte("hidden"), 0600)
	os.MkdirAll(filepath.Join(providersDir, "subdir.json"), 0700) // directory ending in .json

	providers, err := ListProviders(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 1 {
		t.Errorf("expected 1 provider, got %d: %v", len(providers), providers)
	}
	if len(providers) > 0 && providers[0] != "protonvpn" {
		t.Errorf("provider = %q, want 'protonvpn'", providers[0])
	}
}

func TestSaveProviderReadOnlyDir(t *testing.T) {
	tmpDir := t.TempDir()
	readonlyDir := filepath.Join(tmpDir, "readonly")
	os.MkdirAll(readonlyDir, 0500)

	err := SaveProvider(filepath.Join(readonlyDir, "nope"), "protonvpn", []byte("key="), "10.2.0.2/32")
	if err == nil {
		t.Error("SaveProvider should fail when directory is read-only")
	}
}

func TestLoadProviderAllKnownProviders(t *testing.T) {
	// Ensure each known provider gets the right DNS and port
	knownProviders := []struct {
		name string
		dns  string
		port int
	}{
		{"protonvpn", "10.2.0.1", 51820},
		{"mullvad", "10.64.0.1", 51820},
		{"ivpn", "172.16.0.1", 2049},
		{"airvpn", "10.128.0.1", 1637},
		{"nordvpn", "103.86.96.100", 51820},
		{"surfshark", "162.252.172.57", 51820},
		{"windscribe", "10.255.255.1", 443},
		{"fastestvpn", "10.8.0.1", 51820},
	}

	for _, p := range knownProviders {
		t.Run(p.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			SaveProvider(tmpDir, p.name, []byte("testkey="), "10.0.0.2/32")

			cfg, err := LoadProvider(tmpDir, p.name)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.DNS != p.dns {
				t.Errorf("DNS = %q, want %q", cfg.DNS, p.dns)
			}
			if cfg.Port != p.port {
				t.Errorf("Port = %d, want %d", cfg.Port, p.port)
			}
			if cfg.Provider != p.name {
				t.Errorf("Provider = %q, want %q", cfg.Provider, p.name)
			}
		})
	}
}

func TestReloadPreservesConfigDirAndFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ConnectionName:        "wg0",
		KillswitchAutoDisable: "true",
		ConfigDir:             configDir,
		ConfigFile:            filepath.Join(configDir, "config.json"),
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	// After reload, ConfigDir and ConfigFile should be set
	if err := cfg.Reload(); err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigDir == "" {
		t.Error("ConfigDir should not be empty after reload")
	}
	if cfg.ConfigFile == "" {
		t.Error("ConfigFile should not be empty after reload")
	}
}

func TestSaveEmptyFavorites(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ConnectionName: "wg0",
		Favorites:      nil,
		ConfigDir:      configDir,
		ConfigFile:     filepath.Join(configDir, "config.json"),
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}

	// Favorites should be null or absent in JSON when nil
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)
	if fav, ok := raw["favorites"]; ok && fav != nil {
		t.Errorf("favorites should be null for nil slice, got %v", fav)
	}
}

func TestSaveZeroDaemonTuning(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ConnectionName:      "wg0",
		HealthCheckInterval: 0,
		MaxHealthFails:      0,
		MaxRetries:          0,
		ConfigDir:           configDir,
		ConfigFile:          filepath.Join(configDir, "config.json"),
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]interface{}
	json.Unmarshal(data, &raw)
	// Zero values should be present in JSON (they serialize as 0)
	if v, ok := raw["health_check_interval"]; !ok || v != float64(0) {
		t.Errorf("health_check_interval = %v, want 0", v)
	}
	if v, ok := raw["max_health_fails"]; !ok || v != float64(0) {
		t.Errorf("max_health_fails = %v, want 0", v)
	}
	if v, ok := raw["max_retries"]; !ok || v != float64(0) {
		t.Errorf("max_retries = %v, want 0", v)
	}
}

func TestLoadServerFromCacheMultipleIPsUsesFirst(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	cacheData := `[{"server_name":"US-NY#42","ips":["10.0.0.1","10.0.0.2","10.0.0.3"]}]`
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte(cacheData), 0644)

	srv, err := LoadServerFromCache(tmpDir, "protonvpn", "US-NY#42")
	if err != nil {
		t.Fatal(err)
	}
	if srv.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want first IP '10.0.0.1'", srv.IP)
	}
}

func TestLoadServerFromCacheServerNamePriority(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	// Server has both server_name and hostname; match should be on server_name
	cacheData := `[{"server_name":"US-NY#42","hostname":"us-ny-42.proton.net","ips":["1.2.3.4"]}]`
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte(cacheData), 0644)

	// Searching by server_name should work
	srv, err := LoadServerFromCache(tmpDir, "protonvpn", "US-NY#42")
	if err != nil {
		t.Fatal(err)
	}
	if srv.IP != "1.2.3.4" {
		t.Errorf("IP = %q", srv.IP)
	}

	// Searching by hostname should NOT match (server_name is non-empty, so hostname is not used)
	_, err = LoadServerFromCache(tmpDir, "protonvpn", "us-ny-42.proton.net")
	if err == nil {
		t.Error("searching by hostname when server_name exists should fail")
	}
}

func TestLoadServerCacheEmptyArray(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte("[]"), 0644)

	servers, err := LoadServerCache(tmpDir, "protonvpn")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestSaveProviderOverwritesExisting(t *testing.T) {
	tmpDir := t.TempDir()

	// Save initial
	if err := SaveProvider(tmpDir, "protonvpn", []byte("oldkey="), "10.2.0.2/32"); err != nil {
		t.Fatal(err)
	}

	// Overwrite
	if err := SaveProvider(tmpDir, "protonvpn", []byte("newkey="), "10.2.0.3/32"); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadProvider(tmpDir, "protonvpn")
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg.PrivateKey) != "newkey=" {
		t.Errorf("PrivateKey = %q, want 'newkey='", string(cfg.PrivateKey))
	}
	if cfg.Address != "10.2.0.3/32" {
		t.Errorf("Address = %q, want '10.2.0.3/32'", cfg.Address)
	}
}

func TestDeleteProviderOnlyConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// Create provider without cache
	SaveProvider(tmpDir, "protonvpn", []byte("key="), "10.2.0.2/32")

	// Delete should succeed even without cache file
	if err := DeleteProvider(tmpDir, "protonvpn"); err != nil {
		t.Fatalf("DeleteProvider() error: %v", err)
	}

	// Verify config is deleted
	if _, err := os.Stat(filepath.Join(tmpDir, "providers", "protonvpn.json")); !os.IsNotExist(err) {
		t.Error("provider config should be deleted")
	}
}

func TestDeleteProviderOnlyCache(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte("[]"), 0644)

	// Delete should succeed even without provider config
	if err := DeleteProvider(tmpDir, "protonvpn"); err != nil {
		t.Fatalf("DeleteProvider() error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(cacheDir, "protonvpn_servers.json")); !os.IsNotExist(err) {
		t.Error("cache file should be deleted")
	}
}

func TestLoadFileOpenErrorNotNotExist(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(configDir, 0700)

	// Create a directory where the config file should be (so ReadFile fails with a non-NotExist error)
	os.MkdirAll(filepath.Join(configDir, "config.json"), 0700)

	_, err := Load()
	if err == nil {
		t.Error("Load() should return error when config path is a directory")
	}
}

func TestSaveConnectedSinceZeroTime(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ConnectionName: "wg0",
		ConnectedSince: time.Time{}, // zero time
		ConfigDir:      configDir,
		ConfigFile:     filepath.Join(configDir, "config.json"),
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)
	if raw["connected_since"] != float64(0) {
		t.Errorf("zero ConnectedSince should save as 0, got %v", raw["connected_since"])
	}
}

func TestValidateNameSpecialCases(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"a", false},                 // single char
		{"A.B.C", false},             // dots
		{"test-server_1.2#3", false}, // mixed valid chars
		{"a..b", true},               // contains ".."
		{" ", true},                  // space
		{"\t", true},                 // tab
		{"\n", true},                 // newline
		{"a b", true},                // space in middle
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateName(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestReloadErrorPath(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(configDir, 0700)

	// Make config path a directory so Load() returns an error
	os.MkdirAll(filepath.Join(configDir, "config.json"), 0700)

	cfg := &Config{
		ConnectionName: "wg0",
		ConfigDir:      configDir,
		ConfigFile:     filepath.Join(configDir, "config.json"),
	}

	err := cfg.Reload()
	if err == nil {
		t.Error("Reload() should return error when Load() fails")
	}
	// Original values should be preserved since Reload failed before acquiring lock
	if cfg.ConnectionName != "wg0" {
		t.Errorf("ConnectionName should be unchanged after failed reload, got %q", cfg.ConnectionName)
	}
}

func TestListProvidersReadDirError(t *testing.T) {
	tmpDir := t.TempDir()
	providersDir := filepath.Join(tmpDir, "providers")

	// Create the providers directory, then make it unreadable
	os.MkdirAll(providersDir, 0700)
	SaveProvider(tmpDir, "protonvpn", []byte("k="), "10.2.0.2/32")
	os.Chmod(providersDir, 0000)
	defer os.Chmod(providersDir, 0700) // restore for cleanup

	_, err := ListProviders(tmpDir)
	if err == nil {
		t.Error("expected error when providers directory is unreadable")
	}
}

func TestDeleteProviderRemoveError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create provider config
	SaveProvider(tmpDir, "protonvpn", []byte("key="), "10.2.0.2/32")

	// Make the providers directory unwritable so Remove fails with permission error
	providersDir := filepath.Join(tmpDir, "providers")
	os.Chmod(providersDir, 0500)
	defer os.Chmod(providersDir, 0700) // restore for cleanup

	err := DeleteProvider(tmpDir, "protonvpn")
	if err == nil {
		t.Error("expected error when providers directory is not writable")
	}
	if !strings.Contains(err.Error(), "failed to remove provider config") {
		t.Errorf("error should mention provider config removal, got: %v", err)
	}
}

func TestDeleteProviderCacheRemoveError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create cache but no provider config
	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte("[]"), 0644)

	// Make the cache directory unwritable so Remove of cache file fails
	os.Chmod(cacheDir, 0500)
	defer os.Chmod(cacheDir, 0700) // restore for cleanup

	err := DeleteProvider(tmpDir, "protonvpn")
	if err == nil {
		t.Error("expected error when cache directory is not writable")
	}
	if !strings.Contains(err.Error(), "failed to remove provider cache") {
		t.Errorf("error should mention cache removal, got: %v", err)
	}
}

func TestLoadWithAllFieldsInFile(t *testing.T) {
	// Comprehensive test that exercises full JSON loading
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	writeTestConfig(t, configDir, map[string]interface{}{
		"connection_name":         "wg-full",
		"last_connected_server":   "dynamic:protonvpn:US-NY#42",
		"last_public_ip":          "203.0.113.1",
		"last_server_features":    "p2p,tor",
		"real_public_ip":          "198.51.100.1",
		"connected_since":         1700000000,
		"killswitch":              true,
		"killswitch_auto_disable": "never",
		"auto_recover":            false,
		"auto_failover":           true,
		"autostart":               true,
		"autostart_mode":          "specific",
		"autostart_server":        "DE#1",
		"favorites":               []string{"US-NY#42", "SE#5", "DE#1"},
		"health_check_interval":   10,
		"max_health_fails":        5,
		"max_retries":             7,
		"log_connection":          true,
		"log_autorecover":         true,
		"log_firewall":            true,
		"log_provider":            true,
		"log_autostart":           true,
		"log_mode":                "accurate",
		"install_source_dir":      "/opt/lazyvpn",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ConnectionName != "wg-full" {
		t.Errorf("ConnectionName = %q", cfg.ConnectionName)
	}
	if cfg.LastConnectedServer != "dynamic:protonvpn:US-NY#42" {
		t.Errorf("LastConnectedServer = %q", cfg.LastConnectedServer)
	}
	if cfg.LastPublicIP != "203.0.113.1" {
		t.Errorf("LastPublicIP = %q", cfg.LastPublicIP)
	}
	if cfg.LastServerFeatures != "p2p,tor" {
		t.Errorf("LastServerFeatures = %q", cfg.LastServerFeatures)
	}
	if cfg.RealPublicIP != "198.51.100.1" {
		t.Errorf("RealPublicIP = %q", cfg.RealPublicIP)
	}
	if cfg.ConnectedSince.Unix() != 1700000000 {
		t.Errorf("ConnectedSince = %v", cfg.ConnectedSince)
	}
	if cfg.KillswitchAutoDisable != "never" {
		t.Errorf("KillswitchAutoDisable = %q", cfg.KillswitchAutoDisable)
	}
	if cfg.AutoRecover {
		t.Error("AutoRecover should be false")
	}
	if !cfg.AutoFailover {
		t.Error("AutoFailover should be true")
	}
	if !cfg.Autostart {
		t.Error("Autostart should be true")
	}
	if cfg.AutostartMode != "specific" {
		t.Errorf("AutostartMode = %q", cfg.AutostartMode)
	}
	if cfg.AutostartServer != "DE#1" {
		t.Errorf("AutostartServer = %q", cfg.AutostartServer)
	}
	if len(cfg.Favorites) != 3 {
		t.Errorf("Favorites len = %d", len(cfg.Favorites))
	}
	if cfg.HealthCheckInterval != 10 {
		t.Errorf("HealthCheckInterval = %d", cfg.HealthCheckInterval)
	}
	if cfg.MaxHealthFails != 5 {
		t.Errorf("MaxHealthFails = %d", cfg.MaxHealthFails)
	}
	if cfg.MaxRetries != 7 {
		t.Errorf("MaxRetries = %d", cfg.MaxRetries)
	}
	if !cfg.LogConnection {
		t.Error("LogConnection should be true")
	}
	if !cfg.LogAutorecover {
		t.Error("LogAutorecover should be true")
	}
	if !cfg.LogFirewall {
		t.Error("LogFirewall should be true")
	}
	if !cfg.LogProvider {
		t.Error("LogProvider should be true")
	}
	if !cfg.LogAutostart {
		t.Error("LogAutostart should be true")
	}
	if cfg.LogMode != "accurate" {
		t.Errorf("LogMode = %q", cfg.LogMode)
	}
	if cfg.InstallSourceDir != "/opt/lazyvpn" {
		t.Errorf("InstallSourceDir = %q", cfg.InstallSourceDir)
	}
}

func TestSaveRenameFailure(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(configDir, 0700)

	// Create a directory at the ConfigFile path -- rename will fail because
	// you cannot atomically rename a file over a non-empty directory
	configFilePath := filepath.Join(configDir, "config.json")
	os.MkdirAll(filepath.Join(configFilePath, "blocker"), 0700)

	cfg := &Config{
		ConnectionName: "wg0",
		ConfigDir:      configDir,
		ConfigFile:     configFilePath,
	}

	err := cfg.Save()
	if err == nil {
		t.Error("Save() should fail when ConfigFile path is a non-empty directory")
	}
}

func TestSaveProviderTempFileCleanedOnFailure(t *testing.T) {
	tmpDir := t.TempDir()
	providersDir := filepath.Join(tmpDir, "providers")
	os.MkdirAll(providersDir, 0700)

	// Make providers dir have a blocking directory at the target path
	targetPath := filepath.Join(providersDir, "protonvpn.json")
	os.MkdirAll(filepath.Join(targetPath, "blocker"), 0700)

	_ = SaveProvider(tmpDir, "protonvpn", []byte("key="), "10.2.0.2/32")

	// Verify no temp files were left behind
	entries, _ := os.ReadDir(providersDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".provider.tmp.") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestSaveProviderRenameFailure(t *testing.T) {
	tmpDir := t.TempDir()
	providersDir := filepath.Join(tmpDir, "providers")
	os.MkdirAll(providersDir, 0700)

	// Create a non-empty directory at the target path so rename fails
	targetPath := filepath.Join(providersDir, "protonvpn.json")
	os.MkdirAll(filepath.Join(targetPath, "blocker"), 0700)

	err := SaveProvider(tmpDir, "protonvpn", []byte("key="), "10.2.0.2/32")
	if err == nil {
		t.Error("SaveProvider should fail when target is a non-empty directory")
	}
}

// TestValidateBoundaries pins the boundary conditions in validate() so a
// future change from < to <= (or > to >=) would fail a test. Surfaced via
// gremlins mutation testing — production code is correct, tests just
// didn't lock the boundaries.
func TestValidateBoundaries(t *testing.T) {
	t.Run("MTU 1280 accepted (lower bound)", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", CustomMTU: 1280}
		c.validate()
		if c.CustomMTU != 1280 {
			t.Errorf("MTU 1280 should be accepted, got %d", c.CustomMTU)
		}
	})
	t.Run("MTU 1279 rejected", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", CustomMTU: 1279}
		c.validate()
		if c.CustomMTU != 1420 {
			t.Errorf("MTU 1279 should reset to 1420, got %d", c.CustomMTU)
		}
	})
	t.Run("MTU 9000 accepted (upper bound)", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", CustomMTU: 9000}
		c.validate()
		if c.CustomMTU != 9000 {
			t.Errorf("MTU 9000 should be accepted, got %d", c.CustomMTU)
		}
	})
	t.Run("MTU 9001 rejected", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", CustomMTU: 9001}
		c.validate()
		if c.CustomMTU != 1420 {
			t.Errorf("MTU 9001 should reset to 1420, got %d", c.CustomMTU)
		}
	})
	t.Run("ReconnectThreshold 0 reset to default", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", ReconnectThreshold: 0}
		c.validate()
		if c.ReconnectThreshold != 40 {
			t.Errorf("ReconnectThreshold 0 should reset to 40, got %d", c.ReconnectThreshold)
		}
	})
	t.Run("ReconnectThreshold 1 accepted", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", ReconnectThreshold: 1}
		c.validate()
		if c.ReconnectThreshold != 1 {
			t.Errorf("ReconnectThreshold 1 should be accepted, got %d", c.ReconnectThreshold)
		}
	})
	t.Run("DNSProbeHost empty gets default", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", DNSProbeHost: ""}
		c.validate()
		if c.DNSProbeHost != "cloudflare.com" {
			t.Errorf("empty DNSProbeHost should default to cloudflare.com, got %q", c.DNSProbeHost)
		}
	})
	t.Run("DNSProbeHost custom preserved", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", DNSProbeHost: "google.com"}
		c.validate()
		if c.DNSProbeHost != "google.com" {
			t.Errorf("custom DNSProbeHost should be preserved, got %q", c.DNSProbeHost)
		}
	})
	t.Run("Interface name 'a' accepted (lower bound)", func(t *testing.T) {
		// Single character 'a' tests the c >= 'a' boundary in isValidInterfaceName.
		if !isValidInterfaceName("a") {
			t.Error("single char 'a' should be valid")
		}
	})
	t.Run("Interface name with backtick rejected", func(t *testing.T) {
		// '`' is one ASCII before 'a' — tests that the c >= 'a' check
		// rejects the char immediately below the lower boundary.
		if isValidInterfaceName("a`b") {
			t.Error("interface name with backtick should be rejected")
		}
	})
	t.Run("Interface name 15 chars accepted (IFNAMSIZ upper bound)", func(t *testing.T) {
		// Exactly 15 chars — at the IFNAMSIZ-1 boundary. The check is
		// `len(s) > 15`, so 15 must pass. A `>` -> `>=` mutation would
		// reject this case. The kernel allocates IFNAMSIZ=16 bytes
		// including the trailing NUL, so 15 is the longest legal name.
		name := "abcdefghijklmno" // 15 chars
		if !isValidInterfaceName(name) {
			t.Errorf("15-char name %q should be accepted (kernel limit is 15 + NUL)", name)
		}
	})
	t.Run("Interface name 16 chars rejected (one over IFNAMSIZ)", func(t *testing.T) {
		// One past the boundary — must be rejected. A `>` -> `> 16`
		// mutation would accept this case, only to fail later when
		// netlink rejects it with an opaque error from the kernel.
		name := "abcdefghijklmnop" // 16 chars
		if isValidInterfaceName(name) {
			t.Errorf("16-char name %q should be rejected (one over IFNAMSIZ)", name)
		}
	})
	t.Run("Interface name empty rejected (lower bound)", func(t *testing.T) {
		// len(s) == 0 path. Already covered indirectly by the
		// validate() ConnectionName check, but pinning here keeps
		// the unit test for isValidInterfaceName complete.
		if isValidInterfaceName("") {
			t.Error("empty name should be rejected")
		}
	})

	// LightTickInterval / HeavyTickInterval boundary tests — sibling to
	// the HealthCheckInterval boundary tests above. validate() resets
	// these to their defaults (3 / 15) when ≤ 0 so the daemon's tick
	// loop has positive intervals; without normalization, time.NewTicker
	// would panic on a zero or negative interval.
	t.Run("LightTickInterval 0 resets to 3", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", LightTickInterval: 0}
		c.validate()
		if c.LightTickInterval != 3 {
			t.Errorf("LightTickInterval 0 should reset to 3, got %d", c.LightTickInterval)
		}
	})
	t.Run("LightTickInterval 1 accepted (lower bound)", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", LightTickInterval: 1}
		c.validate()
		if c.LightTickInterval != 1 {
			t.Errorf("LightTickInterval 1 should be accepted, got %d", c.LightTickInterval)
		}
	})
	t.Run("HeavyTickInterval 0 resets to 15", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", HeavyTickInterval: 0}
		c.validate()
		if c.HeavyTickInterval != 15 {
			t.Errorf("HeavyTickInterval 0 should reset to 15, got %d", c.HeavyTickInterval)
		}
	})
	t.Run("HeavyTickInterval 1 accepted (lower bound)", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", HeavyTickInterval: 1}
		c.validate()
		if c.HeavyTickInterval != 1 {
			t.Errorf("HeavyTickInterval 1 should be accepted, got %d", c.HeavyTickInterval)
		}
	})

	// PingTargets default — empty list gets repopulated. Without this,
	// timedPingEndpoint would have nothing to dial and every health
	// tick's ping check would no-op.
	t.Run("PingTargets nil gets defaults", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", PingTargets: nil}
		c.validate()
		if len(c.PingTargets) != 2 {
			t.Errorf("PingTargets nil should populate 2 defaults, got %d: %v", len(c.PingTargets), c.PingTargets)
		}
	})
	t.Run("PingTargets custom preserved", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", PingTargets: []string{"9.9.9.9:53"}}
		c.validate()
		if len(c.PingTargets) != 1 || c.PingTargets[0] != "9.9.9.9:53" {
			t.Errorf("custom PingTargets should be preserved, got %v", c.PingTargets)
		}
	})

	// BandwidthDisplay normalization — UI render switches on this value;
	// any unrecognized string would silently fall through to the default
	// branch (no display) without normalization. validate() coerces
	// invalid values to "sparkline".
	t.Run("BandwidthDisplay garbage normalizes to sparkline", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", BandwidthDisplay: "graph"}
		c.validate()
		if c.BandwidthDisplay != "sparkline" {
			t.Errorf("garbage BandwidthDisplay should normalize to 'sparkline', got %q", c.BandwidthDisplay)
		}
	})
	t.Run("BandwidthDisplay empty normalizes to sparkline", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", BandwidthDisplay: ""}
		c.validate()
		if c.BandwidthDisplay != "sparkline" {
			t.Errorf("empty BandwidthDisplay should normalize to 'sparkline', got %q", c.BandwidthDisplay)
		}
	})
	t.Run("BandwidthDisplay 'bar' preserved", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", BandwidthDisplay: "bar"}
		c.validate()
		if c.BandwidthDisplay != "bar" {
			t.Errorf("'bar' BandwidthDisplay should be preserved, got %q", c.BandwidthDisplay)
		}
	})
	t.Run("BandwidthDisplay 'sparkline' preserved", func(t *testing.T) {
		c := &Config{ConnectionName: "wg0", BandwidthDisplay: "sparkline"}
		c.validate()
		if c.BandwidthDisplay != "sparkline" {
			t.Errorf("'sparkline' BandwidthDisplay should be preserved, got %q", c.BandwidthDisplay)
		}
	})
}

func TestCustomMTURoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ConnectionName: "wg0",
		CustomMTU:      1400,
		ConfigDir:      configDir,
		ConfigFile:     filepath.Join(configDir, "config.json"),
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CustomMTU != 1400 {
		t.Errorf("CustomMTU = %d, want 1400", loaded.CustomMTU)
	}
}

func TestCustomMTUDefaultValue(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ConnectionName: "wg0",
		CustomMTU:      1420, // default
		ConfigDir:      configDir,
		ConfigFile:     filepath.Join(configDir, "config.json"),
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CustomMTU != 1420 {
		t.Errorf("CustomMTU = %d, want 1420", loaded.CustomMTU)
	}
}

func TestLoadCustomMTUInvalidIgnored(t *testing.T) {
	tests := []struct {
		name string
		mtu  int
	}{
		{"negative", -100},
		{"zero", 0},
		{"too_low", 1000},
		{"too_high", 10000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			t.Setenv("HOME", tmpDir)

			configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
			if err := os.MkdirAll(configDir, 0700); err != nil {
				t.Fatal(err)
			}
			writeTestConfig(t, configDir, map[string]interface{}{
				"custom_mtu": tt.mtu,
			})

			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			// Invalid values should be reset to default 1420 by validate()
			if cfg.CustomMTU != 1420 {
				t.Errorf("CustomMTU = %d, want 1420 (invalid value should use default)", cfg.CustomMTU)
			}
		})
	}
}

func TestDNSProvidersRoundTrip(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	cfg := DefaultConfig()
	if err := os.MkdirAll(cfg.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg.DNSProviders = []string{"powerdns", "google"}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify JSON content
	content, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var raw map[string]interface{}
	json.Unmarshal(content, &raw)
	providers, ok := raw["dns_providers"].([]interface{})
	if !ok || len(providers) != 2 {
		t.Errorf("dns_providers not saved correctly in JSON, got %v", raw["dns_providers"])
	}

	// Load fresh
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.DNSProviders) != 2 {
		t.Fatalf("DNSProviders len = %d, want 2", len(loaded.DNSProviders))
	}
	if loaded.DNSProviders[0] != "powerdns" || loaded.DNSProviders[1] != "google" {
		t.Errorf("DNSProviders = %v, want [powerdns google]", loaded.DNSProviders)
	}

	// Test Reload
	cfg2 := DefaultConfig()
	cfg2.DNSProviders = nil
	if err := cfg2.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if len(cfg2.DNSProviders) != 2 {
		t.Errorf("after Reload, DNSProviders len = %d, want 2", len(cfg2.DNSProviders))
	}
}

func TestDNSProvidersDefaultNil(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.DNSProviders != nil {
		t.Errorf("default DNSProviders should be nil, got %v", cfg.DNSProviders)
	}
}

func TestDNSProvidersNullInJSON(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestConfig(t, configDir, map[string]interface{}{
		"dns_providers": nil,
	})

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNSProviders != nil {
		t.Errorf("null dns_providers should remain nil, got %v", cfg.DNSProviders)
	}
}

func TestIsOmarchy(t *testing.T) {
	cfg := &Config{Distro: "omarchy"}
	if !cfg.IsOmarchy() {
		t.Error("IsOmarchy() should be true for distro 'omarchy'")
	}

	cfg.Distro = "arch"
	if cfg.IsOmarchy() {
		t.Error("IsOmarchy() should be false for distro 'arch'")
	}

	cfg.Distro = ""
	if cfg.IsOmarchy() {
		t.Error("IsOmarchy() should be false for empty distro")
	}
}

func TestIsCOWFilesystem(t *testing.T) {
	cfg := &Config{FSType: "btrfs"}
	if !cfg.IsCOWFilesystem() {
		t.Error("IsCOWFilesystem() should be true for 'btrfs'")
	}

	cfg.FSType = "ext4"
	if cfg.IsCOWFilesystem() {
		t.Error("IsCOWFilesystem() should be false for 'ext4'")
	}

	cfg.FSType = "xfs"
	if cfg.IsCOWFilesystem() {
		t.Error("IsCOWFilesystem() should be false for 'xfs'")
	}

	// Safe default: unknown / empty FSTypes (overlayfs, tmpfs, encrypted
	// volumes, network mounts, missing config) are treated as CoW so the
	// caller picks PlainDelete (rm) instead of SecureDelete (shred). On
	// any CoW or unknown layer, shred writes new extents while the
	// original blocks remain — picking the safe default avoids the false
	// sense of security.
	cfg.FSType = "unknown"
	if !cfg.IsCOWFilesystem() {
		t.Error("IsCOWFilesystem() should be true for 'unknown' (safe default)")
	}

	cfg.FSType = ""
	if !cfg.IsCOWFilesystem() {
		t.Error("IsCOWFilesystem() should be true for empty fstype (safe default)")
	}
}

func TestLoadDistroAndFSType(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestConfig(t, configDir, map[string]interface{}{
		"distro":  "omarchy",
		"fs_type": "btrfs",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Distro != "omarchy" {
		t.Errorf("Distro = %q, want 'omarchy'", cfg.Distro)
	}
	if cfg.FSType != "btrfs" {
		t.Errorf("FSType = %q, want 'btrfs'", cfg.FSType)
	}
}

func TestSaveDistroAndFSType(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ConnectionName: "wg0",
		Distro:         "arch",
		FSType:         "ext4",
		ConfigDir:      configDir,
		ConfigFile:     filepath.Join(configDir, "config.json"),
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)
	if raw["distro"] != "arch" {
		t.Errorf("distro = %v, want 'arch'", raw["distro"])
	}
	if raw["fs_type"] != "ext4" {
		t.Errorf("fs_type = %v, want 'ext4'", raw["fs_type"])
	}
}

func TestReloadDistroAndFSType(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Save with distro/fstype
	cfg := &Config{
		ConnectionName:        "wg0",
		Distro:                "debian",
		FSType:                "xfs",
		KillswitchAutoDisable: "true",
		ConfigDir:             configDir,
		ConfigFile:            filepath.Join(configDir, "config.json"),
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	// Create a new config and reload
	cfg2 := &Config{
		ConfigDir:  configDir,
		ConfigFile: filepath.Join(configDir, "config.json"),
	}
	if err := cfg2.Reload(); err != nil {
		t.Fatal(err)
	}
	if cfg2.Distro != "debian" {
		t.Errorf("after reload Distro = %q, want 'debian'", cfg2.Distro)
	}
	if cfg2.FSType != "xfs" {
		t.Errorf("after reload FSType = %q, want 'xfs'", cfg2.FSType)
	}
}

func TestLoadPartialJSON(t *testing.T) {
	// JSON with only some fields should preserve defaults for the rest
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestConfig(t, configDir, map[string]interface{}{
		"connection_name": "wg-test",
		"killswitch":      true,
	})

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnectionName != "wg-test" {
		t.Errorf("ConnectionName = %q, want 'wg-test'", cfg.ConnectionName)
	}
	// Defaults should be preserved for unset fields
	if !cfg.AutoRecover {
		t.Error("AutoRecover default (true) should be preserved")
	}
	if cfg.AutostartMode != "last_used" {
		t.Errorf("AutostartMode default should be 'last_used', got %q", cfg.AutostartMode)
	}
	if cfg.CustomMTU != 1420 {
		t.Errorf("CustomMTU default should be 1420, got %d", cfg.CustomMTU)
	}
}

func TestValidateConnectionName(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Invalid connection name should be reset to default by validate()
	writeTestConfig(t, configDir, map[string]interface{}{
		"connection_name": "this-name-is-way-too-long-for-ifnamsiz",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnectionName != "wg0" {
		t.Errorf("invalid connection_name should be reset to 'wg0', got %q", cfg.ConnectionName)
	}
}

func TestLoadProviderInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	providersDir := filepath.Join(tmpDir, "providers")
	os.MkdirAll(providersDir, 0700)
	os.WriteFile(filepath.Join(providersDir, "badprov.json"), []byte("{bad json"), 0600)

	_, err := LoadProvider(tmpDir, "badprov")
	if err == nil {
		t.Error("expected error for invalid provider JSON")
	}
	if !strings.Contains(err.Error(), "invalid provider config") {
		t.Errorf("error should mention invalid provider config, got: %v", err)
	}
}

func TestBandwidthFieldsRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ConnectionName:   "wg0",
		BandwidthDisplay: "sparkline",
		BandwidthUnit:    "bytes",
		BandwidthTotal:   true,
		ConfigDir:        configDir,
		ConfigFile:       filepath.Join(configDir, "config.json"),
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.BandwidthDisplay != "sparkline" {
		t.Errorf("BandwidthDisplay = %q, want 'sparkline'", loaded.BandwidthDisplay)
	}
	if loaded.BandwidthUnit != "bytes" {
		t.Errorf("BandwidthUnit = %q, want 'bytes'", loaded.BandwidthUnit)
	}
	if !loaded.BandwidthTotal {
		t.Error("BandwidthTotal should be true")
	}
}

func TestBaselineFieldsRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ConnectionName: "wg0",
		BaselineIP:     "1.2.3.4",
		BaselineOrg:    "Comcast",
		BaselineDNS:    []string{"8.8.8.8", "8.8.4.4"},
		ConfigDir:      configDir,
		ConfigFile:     filepath.Join(configDir, "config.json"),
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.BaselineIP != "1.2.3.4" {
		t.Errorf("BaselineIP = %q", loaded.BaselineIP)
	}
	if loaded.BaselineOrg != "Comcast" {
		t.Errorf("BaselineOrg = %q", loaded.BaselineOrg)
	}
	if len(loaded.BaselineDNS) != 2 || loaded.BaselineDNS[0] != "8.8.8.8" {
		t.Errorf("BaselineDNS = %v", loaded.BaselineDNS)
	}
}

// TestSaveConnectionState_PreservesUserPrefs is the regression test for the
// reboot-persistence bug: a daemon-side cfg.Save() with stale in-memory user
// prefs would clobber a TUI-side edit (e.g. KillswitchAutoDisable=never set
// while the daemon's in-memory copy still had "true"). SaveConnectionState
// reads disk first and only writes the connection-state fields, leaving
// user prefs untouched.
func TestSaveConnectionState_PreservesUserPrefs(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(configDir, "config.json")

	// Step 1: daemon writes initial config (KAD=true is the "old" daemon view).
	daemonView := &Config{
		ConnectionName:        "wg0",
		LastConnectedServer:   "US-NY#42",
		ConnectedSince:        time.Unix(1700000000, 0),
		KillswitchAutoDisable: "true",
		AutoRecover:           true,
		Autostart:             true,
		AutostartMode:         "last_used",
		CustomMTU:             1420,
		ConfigDir:             configDir,
		ConfigFile:            cfgFile,
	}
	if err := daemonView.Save(); err != nil {
		t.Fatalf("initial Save: %v", err)
	}

	// Step 2: TUI process edits user-pref fields (simulated by writing a
	// fresh load + edit + save). After this, disk has KAD=never, MTU=1280.
	tuiView, err := Load()
	if err != nil {
		t.Fatalf("TUI Load: %v", err)
	}
	tuiView.KillswitchAutoDisable = "never"
	tuiView.CustomMTU = 1280
	tuiView.AutoRecover = false
	tuiView.AutostartMode = "quickest"
	if err := tuiView.Save(); err != nil {
		t.Fatalf("TUI Save: %v", err)
	}

	// Step 3: daemon (still holding the OLD in-memory view with KAD=true,
	// MTU=1420, AutoRecover=true, AutostartMode=last_used) updates connection
	// state and calls SaveConnectionState. The bug: cfg.Save() would write the
	// daemon's stale view, undoing the TUI's edits. SaveConnectionState should
	// only write the connection-state fields and preserve disk's user prefs.
	daemonView.LastConnectedServer = "DE#1"
	daemonView.LastPublicIP = "9.9.9.9"
	daemonView.ConnectedSince = time.Unix(1700001000, 0)
	if err := daemonView.SaveConnectionState(); err != nil {
		t.Fatalf("SaveConnectionState: %v", err)
	}

	// Step 4: re-read from disk and verify TUI edits survived AND daemon
	// connection-state was written.
	final, err := Load()
	if err != nil {
		t.Fatalf("final Load: %v", err)
	}

	// Connection-state: daemon's writes
	if final.LastConnectedServer != "DE#1" {
		t.Errorf("LastConnectedServer = %q, want %q (daemon's write)", final.LastConnectedServer, "DE#1")
	}
	if final.LastPublicIP != "9.9.9.9" {
		t.Errorf("LastPublicIP = %q, want %q", final.LastPublicIP, "9.9.9.9")
	}

	// User prefs: TUI's writes preserved
	if final.KillswitchAutoDisable != "never" {
		t.Errorf("KillswitchAutoDisable = %q, want %q (TUI edit clobbered)", final.KillswitchAutoDisable, "never")
	}
	if final.CustomMTU != 1280 {
		t.Errorf("CustomMTU = %d, want 1280 (TUI edit clobbered)", final.CustomMTU)
	}
	if final.AutoRecover {
		t.Error("AutoRecover should be false (TUI edit clobbered)")
	}
	if final.AutostartMode != "quickest" {
		t.Errorf("AutostartMode = %q, want %q (TUI edit clobbered)", final.AutostartMode, "quickest")
	}
}

// TestReloadUserPrefs_RefreshesKADOnly verifies ReloadUserPrefs picks up the
// disk's killswitch policy without touching the daemon-owned connection-state
// (or Log* fields, which would race with the logger goroutine).
func TestReloadUserPrefs_RefreshesKADOnly(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(configDir, "config.json")

	// Disk: TUI-edited values
	disk := &Config{
		ConnectionName:        "wg0",
		KillswitchAutoDisable: "never",
		AutoRecover:           false,
		AutoFailover:          true,
		LogConnection:         true,
		ConfigDir:             configDir,
		ConfigFile:            cfgFile,
	}
	if err := disk.Save(); err != nil {
		t.Fatal(err)
	}

	// Daemon view: stale prefs + live connection-state
	daemon := &Config{
		ConnectionName:        "wg0",
		LastConnectedServer:   "DE#1",
		ConnectedSince:        time.Unix(1700001000, 0),
		KillswitchAutoDisable: "true",
		AutoRecover:           true,
		AutoFailover:          false,
		LogConnection:         false, // daemon reads this; must NOT be touched
		ConfigDir:             configDir,
		ConfigFile:            cfgFile,
	}

	if err := daemon.ReloadUserPrefs(); err != nil {
		t.Fatalf("ReloadUserPrefs: %v", err)
	}

	// Refreshed: daemon-relevant user prefs
	if daemon.KillswitchAutoDisable != "never" {
		t.Errorf("KillswitchAutoDisable = %q, want %q", daemon.KillswitchAutoDisable, "never")
	}
	if daemon.AutoRecover {
		t.Error("AutoRecover should be refreshed to false")
	}
	if !daemon.AutoFailover {
		t.Error("AutoFailover should be refreshed to true")
	}

	// Untouched: connection-state (daemon-owned)
	if daemon.LastConnectedServer != "DE#1" {
		t.Errorf("LastConnectedServer = %q, should not be touched by ReloadUserPrefs", daemon.LastConnectedServer)
	}

	// Untouched: Log* (logger reads without mutex; refreshing would race)
	if daemon.LogConnection {
		t.Error("LogConnection should NOT be refreshed (logger race protection)")
	}
}

// TestRecordBaselineCapture_FirstConnectOnlyPreservesBaseline pins
// the critical leak-detection contract: BaselineIP/Org/DNS are
// captured ONLY on first connect; subsequent calls preserve them.
//
//   func RecordBaselineCapture(realIP, org string, dns []string) {
//     c.RealPublicIP = realIP        // always update
//     if c.BaselineIP == "" {        // only on first connect
//       c.BaselineIP = realIP
//       c.BaselineOrg = baselineOrg
//       c.BaselineDNS = baselineDNS
//     }
//   }
//
// The baseline is the "ISP fingerprint" captured BEFORE the first
// VPN connect. Leak detection compares the current public IP to this
// baseline — match = leak (VPN not routing); mismatch = healthy.
//
// A regression that dropped the `if c.BaselineIP == ""` guard would
// overwrite the baseline on every connect with the current (post-VPN)
// IP. Leak detection would then ALWAYS compare against a VPN IP,
// never detecting a leak — silent security failure.
//
// The race-safety contract is covered by TestRecordBaselineCapture_
// RaceWithLoggerView. This pins the first-connect-only semantics.
func TestRecordBaselineCapture_FirstConnectOnlyPreservesBaseline(t *testing.T) {
	c := &Config{}

	// First connect: ISP fingerprint captured.
	c.RecordBaselineCapture("73.251.160.112", "Comcast", []string{"75.75.75.75"})
	if c.BaselineIP != "73.251.160.112" {
		t.Errorf("after first connect: BaselineIP = %q, want '73.251.160.112'", c.BaselineIP)
	}
	if c.BaselineOrg != "Comcast" {
		t.Errorf("after first connect: BaselineOrg = %q, want 'Comcast'", c.BaselineOrg)
	}
	if len(c.BaselineDNS) != 1 || c.BaselineDNS[0] != "75.75.75.75" {
		t.Errorf("after first connect: BaselineDNS = %v, want [75.75.75.75]", c.BaselineDNS)
	}
	if c.RealPublicIP != "73.251.160.112" {
		t.Errorf("RealPublicIP = %q, want set", c.RealPublicIP)
	}

	// Second call (e.g. reconnect): RealPublicIP updates, but
	// Baseline* MUST stay frozen at the first-connect values.
	c.RecordBaselineCapture("185.247.68.99", "Mullvad", []string{"10.64.0.1"})
	if c.BaselineIP != "73.251.160.112" {
		t.Errorf("after second call: BaselineIP = %q, want PRESERVED '73.251.160.112' (regression: leak detection would compare against VPN IP)", c.BaselineIP)
	}
	if c.BaselineOrg != "Comcast" {
		t.Errorf("after second call: BaselineOrg = %q, want PRESERVED 'Comcast'", c.BaselineOrg)
	}
	if len(c.BaselineDNS) != 1 || c.BaselineDNS[0] != "75.75.75.75" {
		t.Errorf("after second call: BaselineDNS = %v, want PRESERVED [75.75.75.75]", c.BaselineDNS)
	}
	// RealPublicIP IS expected to update on each call.
	if c.RealPublicIP != "185.247.68.99" {
		t.Errorf("after second call: RealPublicIP = %q, want updated '185.247.68.99'", c.RealPublicIP)
	}
}

// TestClearConnectionState_ClearLastServerFlag pins the conditional-
// clear semantics of ClearConnectionState's clearLastServer parameter.
// Documented in CLAUDE.md's "Daemon teardown — two paths, two semantics":
//
//   ClearConnectionState(true):   clears LastConnectedServer (explicit
//                                 user disconnect — autoconnect should
//                                 NOT resume the same server on boot)
//   ClearConnectionState(false):  preserves LastConnectedServer (system
//                                 shutdown — autoconnect mode=last_used
//                                 SHOULD resume on next boot)
//
// "If you ever change one path's clearing behavior, change the other
// deliberately too — the asymmetry is intentional."
//
// A regression that inverted the flag's meaning would cause:
//   - false → all cleared: shutdown loses the autoconnect anchor
//   - true → only partial: explicit disconnect leaves stale state
//     that autoconnect would re-use unexpectedly
//
// Two sub-tests pin both arms in-memory (the trailing SaveConnectionState
// may fail without an on-disk config, but the in-memory writes happen
// first and survive the save error — that's the contract).
func TestClearConnectionState_ClearLastServerFlag(t *testing.T) {
	prime := func() *Config {
		return &Config{
			RealPublicIP:        "9.9.9.9",
			LastPublicIP:        "8.8.8.8",
			ConnectedSince:      time.Now(),
			LastConnectedServer: "US-NY#42",
			LastServerFeatures:  "p2p",
		}
	}

	t.Run("clearLastServer=false_preserves_anchor", func(t *testing.T) {
		c := prime()
		_ = c.ClearConnectionState(false) // best-effort save error ignored
		if c.RealPublicIP != "" {
			t.Errorf("RealPublicIP = %q, want empty", c.RealPublicIP)
		}
		if c.LastPublicIP != "" {
			t.Errorf("LastPublicIP = %q, want empty", c.LastPublicIP)
		}
		if !c.ConnectedSince.IsZero() {
			t.Errorf("ConnectedSince = %v, want zero", c.ConnectedSince)
		}
		// Critical: LastConnectedServer + LastServerFeatures MUST be preserved.
		// This is the system-shutdown path; autoconnect needs these for resume.
		if c.LastConnectedServer != "US-NY#42" {
			t.Errorf("LastConnectedServer = %q, want preserved 'US-NY#42' (shutdown path)", c.LastConnectedServer)
		}
		if c.LastServerFeatures != "p2p" {
			t.Errorf("LastServerFeatures = %q, want preserved 'p2p' (shutdown path)", c.LastServerFeatures)
		}
	})

	t.Run("clearLastServer=true_clears_anchor_too", func(t *testing.T) {
		c := prime()
		_ = c.ClearConnectionState(true)
		// All five fields cleared.
		if c.RealPublicIP != "" || c.LastPublicIP != "" || !c.ConnectedSince.IsZero() {
			t.Errorf("base state not cleared: rp=%q lp=%q since=%v", c.RealPublicIP, c.LastPublicIP, c.ConnectedSince)
		}
		if c.LastConnectedServer != "" {
			t.Errorf("LastConnectedServer = %q, want empty (explicit disconnect)", c.LastConnectedServer)
		}
		if c.LastServerFeatures != "" {
			t.Errorf("LastServerFeatures = %q, want empty (explicit disconnect)", c.LastServerFeatures)
		}
	})
}

// TestGetConnectionName_ReturnsCurrentField is a direct unit test
// for the locked accessor. The function is exercised indirectly via
// the daemon's sleepWakeListener / forceDisconnectIfInterfaceExists
// race tests, but had no direct test asserting the basic contract:
// returns the current value of cfg.ConnectionName.
//
// A regression that returned a different field (e.g. cfg.LastConnectedServer
// — both are strings, both relate to "connection identity") would slip
// past the race tests since they only check race-safety, not the
// specific value returned. Direct field-binding test catches this.
func TestGetConnectionName_ReturnsCurrentField(t *testing.T) {
	cfg := &Config{ConnectionName: "wg-test-42"}
	if got := cfg.GetConnectionName(); got != "wg-test-42" {
		t.Errorf("GetConnectionName() = %q, want %q", got, "wg-test-42")
	}

	// Verify it reflects updates (sanity: not cached at construction).
	cfg.mu.Lock()
	cfg.ConnectionName = "wg-renamed"
	cfg.mu.Unlock()
	if got := cfg.GetConnectionName(); got != "wg-renamed" {
		t.Errorf("after rename: GetConnectionName() = %q, want %q", got, "wg-renamed")
	}
}

// TestUserPrefsView_ReturnsSnapshot is the sibling to
// TestLoggerView_ReturnsSnapshot. UserPrefsView() returns AutoRecover
// and AutoFailover atomically snapshotted under cfg.mu.RLock —
// sendStatus calls it from handleClient goroutines while
// ReloadUserPrefs may concurrently write the same fields.
//
// The contract has two halves:
//   1) Returned values reflect the source fields at snapshot time.
//   2) Mutating the source AFTER the snapshot must NOT leak through.
//
// Without (2), a TUI status reply could see partial writes from a
// concurrent ReloadUserPrefs — e.g. AutoRecover=true and AutoFailover
// from a different point in time.
func TestUserPrefsView_ReturnsSnapshot(t *testing.T) {
	cfg := &Config{
		AutoRecover:  true,
		AutoFailover: false,
	}

	v := cfg.UserPrefsView()
	if v.AutoRecover != true {
		t.Errorf("AutoRecover = %v, want true", v.AutoRecover)
	}
	if v.AutoFailover != false {
		t.Errorf("AutoFailover = %v, want false", v.AutoFailover)
	}

	// Snapshot semantics: source mutation after UserPrefsView must
	// NOT leak through to the previously-returned struct.
	cfg.AutoRecover = false
	cfg.AutoFailover = true

	if v.AutoRecover != true {
		t.Error("UserPrefsView should be a snapshot — source AutoRecover mutation leaked")
	}
	if v.AutoFailover != false {
		t.Error("UserPrefsView should be a snapshot — source AutoFailover mutation leaked")
	}
}

// TestLoggerView_ReturnsSnapshot verifies LoggerView() returns the exact
// fields the logger reads, atomically snapshotted. Mutating the source
// Config after the snapshot must NOT affect the returned LoggerView.
func TestLoggerView_ReturnsSnapshot(t *testing.T) {
	cfg := &Config{
		LogConnection:  true,
		LogAutorecover: false,
		LogFirewall:    true,
		LogProvider:    false,
		LogAutostart:   true,
		LogMode:        "accurate",
		RealPublicIP:   "1.2.3.4",
		LastPublicIP:   "5.6.7.8",
	}

	v := cfg.LoggerView()

	if v.LogConnection != true || v.LogAutorecover != false ||
		v.LogFirewall != true || v.LogProvider != false || v.LogAutostart != true {
		t.Errorf("LoggerView log toggles wrong: %+v", v)
	}
	if v.LogMode != "accurate" {
		t.Errorf("LogMode = %q, want %q", v.LogMode, "accurate")
	}
	if v.RealPublicIP != "1.2.3.4" || v.LastPublicIP != "5.6.7.8" {
		t.Errorf("IP fields = %q / %q", v.RealPublicIP, v.LastPublicIP)
	}

	// Snapshot semantics: mutating source AFTER LoggerView must not
	// affect the returned struct.
	cfg.LogConnection = false
	cfg.LogMode = "safe"
	cfg.RealPublicIP = "9.9.9.9"

	if v.LogConnection != true {
		t.Error("LoggerView should be a snapshot — source mutation leaked through")
	}
	if v.LogMode != "accurate" {
		t.Error("LoggerView LogMode should be a snapshot")
	}
	if v.RealPublicIP != "1.2.3.4" {
		t.Error("LoggerView RealPublicIP should be a snapshot")
	}
}

// TestProviderConfig_ZeroKey verifies that ZeroKey actually zeroes the
// PrivateKey bytes — important security property: provider keys must not
// linger in memory longer than necessary. The runtime.KeepAlive in
// security.ZeroBytes prevents the compiler from eliding the writes.
func TestProviderConfig_ZeroKey(t *testing.T) {
	pc := &ProviderConfig{
		PrivateKey: []byte{0x42, 0xab, 0xcd, 0xef, 0x01, 0x02, 0x03, 0x04},
	}
	original := make([]byte, len(pc.PrivateKey))
	copy(original, pc.PrivateKey)

	pc.ZeroKey()

	for i, b := range pc.PrivateKey {
		if b != 0 {
			t.Errorf("PrivateKey[%d] = 0x%02x after ZeroKey, want 0x00 (was 0x%02x)", i, b, original[i])
		}
	}

	// Should be safe to call on nil/empty key.
	empty := &ProviderConfig{PrivateKey: nil}
	empty.ZeroKey() // must not panic
	zero := &ProviderConfig{PrivateKey: []byte{}}
	zero.ZeroKey() // must not panic
}

// TestSaveConnectionState_FallsBackOnDiskReadFailure verifies the load-fail
// fallback in SaveConnectionState. When disk Load fails (e.g. removed
// ConfigDir), it falls through to a full saveLocked instead of dropping
// the daemon's writes silently.
func TestSaveConnectionState_FallsBackOnDiskReadFailure(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	configDir := filepath.Join(tmpDir, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		LastConnectedServer: "DE#1",
		ConnectedSince:      time.Unix(1700000000, 0),
		ConfigDir:           configDir,
		ConfigFile:          filepath.Join(configDir, "config.json"),
	}

	// Wipe the configDir so Load() inside SaveConnectionState fails. The
	// fallback path skips disk-load and calls saveLocked directly, which
	// itself returns nil silently when ConfigDir is absent (uninstall race).
	if err := os.RemoveAll(configDir); err != nil {
		t.Fatal(err)
	}

	// Should not return an error — disk-gone is the expected uninstall race
	// and saveLocked handles it as a silent no-op (existing contract).
	if err := cfg.SaveConnectionState(); err != nil {
		t.Errorf("SaveConnectionState with missing ConfigDir: %v (want nil silent)", err)
	}
}

// TestRecordBaselineCapture_RaceWithLoggerView and the sibling
// TestRecordConnectSuccess_RaceWithLoggerView lock the regression on the
// race that wireguard.Connect used to have — bare assignment to
// RealPublicIP / LastPublicIP racing concurrent LoggerView reads from
// other goroutines (handleClient -> sendStatus / Logger.Log path in
// the daemon). The setter methods take c.mu.Lock around the writes;
// if a future refactor drops the lock these tests fire under -race.
func TestRecordBaselineCapture_RaceWithLoggerView(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &Config{
		ConnectionName: "wg0",
		ConfigDir:      tmpDir,
		ConfigFile:     filepath.Join(tmpDir, "config.json"),
	}

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
				cfg.RecordBaselineCapture("1.1.1.1", "Example ISP", []string{"8.8.8.8"})
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

// TestSetLastServerFeatures_RaceWithSaveConnectionState locks the
// regression on the LastServerFeatures bare-write race. doConnect (main
// goroutine) used to bare-write d.cfg.LastServerFeatures; the
// sleepWakeListener goroutine path (ForceDisconnect ->
// ClearConnectionState -> SaveConnectionState) reads that field under
// c.mu.Lock to construct the disk snapshot. Bare write raced the
// Lock-protected read.
func TestSetLastServerFeatures_RaceWithSaveConnectionState(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &Config{
		ConnectionName: "wg0",
		ConfigDir:      tmpDir,
		ConfigFile:     filepath.Join(tmpDir, "config.json"),
	}

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
				_ = cfg.SetLastServerFeatures("p2p,tor")
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
				_ = cfg.SaveConnectionState()
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestRecordConnectSuccess_RaceWithLoggerView(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &Config{
		ConnectionName: "wg0",
		ConfigDir:      tmpDir,
		ConfigFile:     filepath.Join(tmpDir, "config.json"),
	}

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
				_ = cfg.RecordConnectSuccess("US-NY#42", "2.2.2.2", time.Now())
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

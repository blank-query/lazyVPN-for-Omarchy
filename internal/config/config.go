package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	// Protects concurrent Save / Reload / SaveConnectionState writes and
	// the LoggerView snapshot reads. RWMutex (not Mutex) so the logger's
	// per-Log RLock doesn't serialize against itself in a hot logging path.
	mu sync.RWMutex

	// Connection settings
	ConnectionName      string
	LastConnectedServer string
	LastPublicIP        string
	LastServerFeatures  string // Comma-separated feature list (e.g. "p2p,tor")
	RealPublicIP        string
	BaselineIP          string    // ISP public IP captured before VPN connect
	BaselineOrg         string    // ISP org name from ipinfo.io before connect
	BaselineDNS         []string  // DNS resolver IPs before connect
	ConnectedSince      time.Time // When the current connection was established

	// Feature toggles.
	// Note: killswitch state is NOT persisted here — it's derived at runtime
	// from firewall.IsActive() (the UFW rules are the source of truth).
	// KillswitchAutoDisable is the only killswitch-related preference that
	// persists: it controls what happens to the firewall on user disconnect.
	KillswitchAutoDisable string // "true", "false", "never"
	AutoRecover           bool
	AutoFailover          bool
	// Note: IPv6 protection and LAN mode state are NOT persisted here.
	// They're derived at runtime from UFW rules (the source of truth):
	//   firewall.IsIPv6Disabled(), firewall.IsLANBlockActive(), firewall.IsLANStealthActive().
	// UFW rules persist across reboot (via ufw.service), so there's nothing
	// config needs to remember as a "preference" separate from the rules.

	// Autostart
	Autostart       bool
	AutostartMode   string // "last_used", "quickest", "random", "specific"
	AutostartServer string // Server name for "specific" mode

	// Favorites
	Favorites []string

	// Daemon tuning
	HealthCheckInterval int // seconds, legacy (used as LightTickInterval fallback)
	LightTickInterval   int // seconds, default 3 — light health probes
	HeavyTickInterval   int // seconds, default 15 — heavy health probes (ping + DNS)
	ReconnectThreshold  int // health score below this triggers recovery, default 40
	MaxHealthFails      int // default 3 (consecutive bad ticks)
	MaxRetries          int // default 3

	// Health check targets
	PingTargets  []string // TCP dial targets for health probes (default ["8.8.8.8:53", "1.1.1.1:53"])
	DNSProbeHost string   // Hostname to resolve for DNS health probe (default "cloudflare.com")

	// Advanced / Connection settings
	CustomMTU        int      // WireGuard MTU (default 1420)
	DNSProviders     []string // IDs of enabled DNS reflection providers (nil = use defaults)
	BandwidthDisplay string   // "sparkline" or "bar" (default "sparkline")
	BandwidthUnit    string   // "bits" or "bytes" (default "bits")
	BandwidthTotal   bool     // show cumulative session transfer (default false)

	// UI state
	TutorialSeen bool // first-run tutorial prompt has been shown

	// Debug logging
	LogConnection  bool
	LogAutorecover bool
	LogFirewall    bool
	LogProvider    bool
	LogAutostart   bool
	LogMode        string // "safe" or "accurate"

	// System (detected at install time)
	Distro string // "omarchy", "arch", "debian", "ubuntu", etc.
	FSType string // "btrfs", "ext4", "xfs", etc.

	// SudoersInstalled records whether the user opted into the passwordless
	// sudoers file at install time. Source of truth for "should we refresh
	// /etc/sudoers.d/lazyvpn after rename / reinstall?" — os.Stat on that
	// path returns EACCES from non-root because the parent dir is 0750, so
	// stat-based existence checks silently mis-classify.
	SudoersInstalled bool

	// Update
	AutoCheckUpdates bool
	LastUpdateCheck  int64 // Unix timestamp of last update check

	// Paths
	ConfigDir        string
	ConfigFile       string
	InstallSourceDir string // Git clone directory where LazyVPN was installed from
}

// configJSON is the JSON-serializable shadow of Config.
// ConfigDir/ConfigFile are excluded (runtime-only paths).
// ConnectedSince is stored as a unix timestamp for clean JSON.
type configJSON struct {
	ConnectionName      string   `json:"connection_name"`
	LastConnectedServer string   `json:"last_connected_server"`
	LastPublicIP        string   `json:"last_public_ip"`
	LastServerFeatures  string   `json:"last_server_features"`
	RealPublicIP        string   `json:"real_public_ip"`
	BaselineIP          string   `json:"baseline_ip"`
	BaselineOrg         string   `json:"baseline_org"`
	BaselineDNS         []string `json:"baseline_dns"`
	ConnectedSince      int64    `json:"connected_since"`

	KillswitchAutoDisable string `json:"killswitch_auto_disable"`
	AutoRecover           bool   `json:"auto_recover"`
	AutoFailover          bool   `json:"auto_failover"`

	Autostart       bool   `json:"autostart"`
	AutostartMode   string `json:"autostart_mode"`
	AutostartServer string `json:"autostart_server"`

	Favorites []string `json:"favorites"`

	HealthCheckInterval int `json:"health_check_interval"`
	LightTickInterval   int `json:"light_tick_interval"`
	HeavyTickInterval   int `json:"heavy_tick_interval"`
	ReconnectThreshold  int `json:"reconnect_threshold"`
	MaxHealthFails      int `json:"max_health_fails"`
	MaxRetries          int `json:"max_retries"`

	PingTargets  []string `json:"ping_targets"`
	DNSProbeHost string   `json:"dns_probe_host"`

	CustomMTU        int      `json:"custom_mtu"`
	DNSProviders     []string `json:"dns_providers"`
	BandwidthDisplay string   `json:"bandwidth_display"`
	BandwidthUnit    string   `json:"bandwidth_unit"`
	BandwidthTotal   bool     `json:"bandwidth_total"`

	TutorialSeen bool `json:"tutorial_seen"`

	LogConnection  bool   `json:"log_connection"`
	LogAutorecover bool   `json:"log_autorecover"`
	LogFirewall    bool   `json:"log_firewall"`
	LogProvider    bool   `json:"log_provider"`
	LogAutostart   bool   `json:"log_autostart"`
	LogMode        string `json:"log_mode"`

	Distro           string `json:"distro"`
	FSType           string `json:"fs_type"`
	SudoersInstalled bool   `json:"sudoers_installed"`

	AutoCheckUpdates bool  `json:"auto_check_updates"`
	LastUpdateCheck  int64 `json:"last_update_check"`

	InstallSourceDir string `json:"install_source_dir"`
}

func (c *Config) toJSON() configJSON {
	var ts int64
	if !c.ConnectedSince.IsZero() {
		ts = c.ConnectedSince.Unix()
	}
	return configJSON{
		ConnectionName:        c.ConnectionName,
		LastConnectedServer:   c.LastConnectedServer,
		LastPublicIP:          c.LastPublicIP,
		LastServerFeatures:    c.LastServerFeatures,
		RealPublicIP:          c.RealPublicIP,
		BaselineIP:            c.BaselineIP,
		BaselineOrg:           c.BaselineOrg,
		BaselineDNS:           c.BaselineDNS,
		ConnectedSince:        ts,
		KillswitchAutoDisable: c.KillswitchAutoDisable,
		AutoRecover:           c.AutoRecover,
		AutoFailover:          c.AutoFailover,
		Autostart:             c.Autostart,
		AutostartMode:         c.AutostartMode,
		AutostartServer:       c.AutostartServer,
		Favorites:             c.Favorites,
		HealthCheckInterval:   c.HealthCheckInterval,
		LightTickInterval:     c.LightTickInterval,
		HeavyTickInterval:     c.HeavyTickInterval,
		ReconnectThreshold:    c.ReconnectThreshold,
		MaxHealthFails:        c.MaxHealthFails,
		MaxRetries:            c.MaxRetries,
		PingTargets:           c.PingTargets,
		DNSProbeHost:          c.DNSProbeHost,
		CustomMTU:             c.CustomMTU,
		DNSProviders:          c.DNSProviders,
		BandwidthDisplay:      c.BandwidthDisplay,
		BandwidthUnit:         c.BandwidthUnit,
		BandwidthTotal:        c.BandwidthTotal,
		TutorialSeen:          c.TutorialSeen,
		LogConnection:         c.LogConnection,
		LogAutorecover:        c.LogAutorecover,
		LogFirewall:           c.LogFirewall,
		LogProvider:           c.LogProvider,
		LogAutostart:          c.LogAutostart,
		LogMode:               c.LogMode,
		Distro:                c.Distro,
		FSType:                c.FSType,
		SudoersInstalled:      c.SudoersInstalled,
		AutoCheckUpdates:      c.AutoCheckUpdates,
		LastUpdateCheck:       c.LastUpdateCheck,
		InstallSourceDir:      c.InstallSourceDir,
	}
}

func (c *Config) fromJSON(j configJSON) {
	c.ConnectionName = j.ConnectionName
	c.LastConnectedServer = j.LastConnectedServer
	c.LastPublicIP = j.LastPublicIP
	c.LastServerFeatures = j.LastServerFeatures
	c.RealPublicIP = j.RealPublicIP
	c.BaselineIP = j.BaselineIP
	c.BaselineOrg = j.BaselineOrg
	c.BaselineDNS = j.BaselineDNS
	if j.ConnectedSince > 0 {
		c.ConnectedSince = time.Unix(j.ConnectedSince, 0)
	} else {
		c.ConnectedSince = time.Time{}
	}
	c.KillswitchAutoDisable = j.KillswitchAutoDisable
	c.AutoRecover = j.AutoRecover
	c.AutoFailover = j.AutoFailover
	c.Autostart = j.Autostart
	c.AutostartMode = j.AutostartMode
	c.AutostartServer = j.AutostartServer
	c.Favorites = j.Favorites
	c.HealthCheckInterval = j.HealthCheckInterval
	c.LightTickInterval = j.LightTickInterval
	c.HeavyTickInterval = j.HeavyTickInterval
	c.ReconnectThreshold = j.ReconnectThreshold
	c.MaxHealthFails = j.MaxHealthFails
	c.MaxRetries = j.MaxRetries
	c.PingTargets = j.PingTargets
	c.DNSProbeHost = j.DNSProbeHost
	c.CustomMTU = j.CustomMTU
	c.DNSProviders = j.DNSProviders
	c.BandwidthDisplay = j.BandwidthDisplay
	c.BandwidthUnit = j.BandwidthUnit
	c.BandwidthTotal = j.BandwidthTotal
	c.TutorialSeen = j.TutorialSeen
	c.LogConnection = j.LogConnection
	c.LogAutorecover = j.LogAutorecover
	c.LogFirewall = j.LogFirewall
	c.LogProvider = j.LogProvider
	c.LogAutostart = j.LogAutostart
	c.LogMode = j.LogMode
	c.Distro = j.Distro
	c.FSType = j.FSType
	c.SudoersInstalled = j.SudoersInstalled
	c.AutoCheckUpdates = j.AutoCheckUpdates
	c.LastUpdateCheck = j.LastUpdateCheck
	c.InstallSourceDir = j.InstallSourceDir
}

// validate applies post-load validation and normalizes values.
func (c *Config) validate() {
	if !isValidInterfaceName(c.ConnectionName) {
		c.ConnectionName = "wg0"
	}
	c.KillswitchAutoDisable = normalizeKillswitchAutoDisable(c.KillswitchAutoDisable)
	if c.CustomMTU < 1280 || c.CustomMTU > 9000 {
		c.CustomMTU = 1420
	}
	if c.HealthCheckInterval <= 0 {
		c.HealthCheckInterval = 5
	}
	if c.LightTickInterval <= 0 {
		c.LightTickInterval = 3
	}
	if c.HeavyTickInterval <= 0 {
		c.HeavyTickInterval = 15
	}
	if c.ReconnectThreshold <= 0 {
		c.ReconnectThreshold = 40
	}
	if c.MaxHealthFails <= 0 {
		c.MaxHealthFails = 3
	}
	if c.MaxRetries <= 0 {
		c.MaxRetries = 3
	}
	if len(c.PingTargets) == 0 {
		c.PingTargets = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	if c.DNSProbeHost == "" {
		c.DNSProbeHost = "cloudflare.com"
	}
	if c.BandwidthDisplay != "sparkline" && c.BandwidthDisplay != "bar" {
		c.BandwidthDisplay = "sparkline"
	}
	// Normalize empty AutostartMode to "last_used". The boot
	// subcommand's switch matches "last_used" explicitly, not "",
	// so an empty value (e.g. user manually cleared the field in
	// config.json) would fall through to the default branch and
	// silently skip autoconnect even though the user enabled
	// Autostart. settings.go's cycling logic already treats
	// `"last_used", ""` as the same state; normalize here so every
	// other consumer agrees.
	if c.AutostartMode == "" {
		c.AutostartMode = "last_used"
	}
}

func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()

	// When running under sudo, os.UserHomeDir() returns /root.
	// Resolve the real user's home directory via SUDO_USER.
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && os.Geteuid() == 0 {
		// Look up the real user's home directory from /etc/passwd
		if home := lookupUserHome(sudoUser); home != "" {
			homeDir = home
		}
	}

	configDir := filepath.Join(homeDir, ".config", "lazyvpn")

	return &Config{
		ConnectionName:        "wg0",
		KillswitchAutoDisable: "true",
		AutoRecover:           true,
		AutoFailover:          false,
		Autostart:             false,
		AutostartMode:         "last_used",
		HealthCheckInterval:   5,
		LightTickInterval:     3,
		HeavyTickInterval:     15,
		ReconnectThreshold:    40,
		MaxHealthFails:        3,
		MaxRetries:            3,
		LogMode:               "safe",
		PingTargets:           []string{"8.8.8.8:53", "1.1.1.1:53"},
		DNSProbeHost:          "cloudflare.com",
		CustomMTU:             1420,
		BandwidthDisplay:      "sparkline",
		BandwidthUnit:         "bits",
		BandwidthTotal:        false,
		ConfigDir:             configDir,
		ConfigFile:            filepath.Join(configDir, "config.json"),
	}
}

func Load() (*Config, error) {
	cfg := DefaultConfig()

	// Sanity check: if os.UserHomeDir() failed AND SUDO_USER fallback
	// also failed, configDir ends up as a relative path (".config/
	// lazyvpn"). Subsequent Save calls would then write under whatever
	// CWD the binary is invoked from — config silently appears in odd
	// places, and the next Load wouldn't find it. Surface this so the
	// caller can prompt the user to set HOME rather than writing into
	// the wrong tree.
	if !filepath.IsAbs(cfg.ConfigDir) {
		return cfg, fmt.Errorf("could not determine home directory (HOME unset and /etc/passwd lookup failed); set HOME and retry")
	}

	// Bounded read: a corrupted or hand-edited config.json larger
	// than ~10KB-realistic would OOM a bare os.ReadFile. Shared
	// helper applies maxConfigBytes (1MB).
	data, err := readFileBounded(cfg.ConfigFile, maxConfigBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // Return defaults if no config exists
		}
		return cfg, err
	}

	// Empty file is treated the same as missing — use defaults
	if len(data) == 0 {
		return cfg, nil
	}

	// Seed shadow struct with defaults so absent JSON keys preserve defaults
	j := cfg.toJSON()
	if err := json.Unmarshal(data, &j); err != nil {
		return cfg, fmt.Errorf("invalid config JSON: %w", err)
	}
	cfg.fromJSON(j)
	cfg.validate()

	// Migrate favorites from v1 format if needed
	// v1 stored favorites in a separate file ~/.config/lazyvpn/favorites
	if len(cfg.Favorites) == 0 {
		cfg.migrateFavorites()
	}

	return cfg, nil
}

// migrateFavorites reads favorites from the v1 format (separate file)
func (c *Config) migrateFavorites() {
	favFile := filepath.Join(c.ConfigDir, "favorites")
	file, err := os.Open(favFile)
	if err != nil {
		return // No favorites file, nothing to migrate
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var favorites []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			favorites = append(favorites, line)
		}
	}

	if len(favorites) > 0 {
		c.Favorites = favorites
		// Save to persist the migration (best-effort; retries on next load)
		if err := c.Save(); err != nil {
			return
		}
		// Remove legacy file so cleared favorites don't re-populate
		os.Remove(favFile)
	}
}

// lookupUserHome reads /etc/passwd to find a user's home directory.
// This avoids importing os/user which uses cgo.
func lookupUserHome(username string) string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 6 && fields[0] == username {
			return fields[5]
		}
	}
	return ""
}

// isValidInterfaceName checks that s matches ^[a-zA-Z0-9._-]+$ and fits
// within the Linux IFNAMSIZ limit (15 chars).
func isValidInterfaceName(s string) bool {
	if len(s) == 0 || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// normalizeKillswitchAutoDisable converts various input formats to canonical values
// Accepts: true/false/yes/no/1/0/never/prompt -> returns "true"/"false"/"never"
func normalizeKillswitchAutoDisable(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "true", "1", "yes", "auto":
		return "true"
	case "false", "0", "no", "prompt":
		return "false"
	case "never", "keep":
		return "never"
	default:
		return "true" // Default to auto-disable for safety
	}
}

// Save writes the config back to disk as JSON using atomic write (temp file + rename).
// Thread-safe: uses mutex to prevent concurrent writes.
//
// Will NOT create the config directory on demand. If the dir is missing,
// LazyVPN isn't installed and Save returns silently — running `lazyvpn`
// (e.g. to peek at the TUI) shouldn't leave state behind that a subsequent
// `lazyvpn install` will mis-detect as "leftover config". The install flow
// creates ConfigDir explicitly via MkdirAll before any Save.
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveLocked()
}

// saveLocked writes c.toJSON() atomically. Caller must hold c.mu.
func (c *Config) saveLocked() error {
	if _, err := os.Stat(c.ConfigDir); os.IsNotExist(err) {
		return nil
	}

	data, err := json.MarshalIndent(c.toJSON(), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	// Write to temp file first for atomic save
	tmpFile, err := os.CreateTemp(c.ConfigDir, ".config.tmp.*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	// Explicit Chmod resets default ACLs that NFSv4 / some xfs setups
	// can inherit on a freshly-created tempfile. Surface the error —
	// silent failure here is the difference between "config file is
	// 0600" and "config file leaks the daemon socket path / install
	// dir to other local users and we don't know."
	if err := os.Chmod(tmpPath, 0600); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to enforce 0600 on config temp file: %w", err)
	}

	// Clean up temp file on any error
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

	// Sync to ensure data is on disk before rename
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	// Check Close error before rename: on network filesystems (NFS / SMB
	// delayed-commit), Sync can succeed while Close still surfaces a
	// write error. Pre-fix the ignored Close would let os.Rename install
	// a possibly-partial file; the next Load would then either fail to
	// parse or read corrupt state. Defer cleanup via the success flag
	// still applies.
	if err := tmpFile.Close(); err != nil {
		return err
	}

	// Atomic rename
	if err := os.Rename(tmpPath, c.ConfigFile); err != nil {
		return err
	}

	success = true
	return nil
}

// SaveConnectionState writes only the daemon-owned connection-state fields
// to disk. User-preference fields on disk are preserved verbatim — protects
// against stale daemon in-memory cfg overwriting TUI-side changes that
// happened after the daemon loaded its copy.
//
// The pattern: daemon updates connection state in-memory → SaveConnectionState
// re-reads disk, patches only the connection-state fields, writes back atomically.
// User prefs (KillswitchAutoDisable, Autostart*, log toggles, MTU, DNS providers,
// etc.) come from disk so any TUI edits in the meantime are preserved — IF the
// TUI's write happens entirely outside the daemon's Load→saveLocked window. The
// window is short (a few µs), but the protection is best-effort, not atomic:
// there is no cross-process file lock between the read at Load() and the write
// at saveLocked(). A TUI Save() that lands inside that window will still get
// clobbered. This is the original bug at a much smaller probability — sufficient
// for the typical "daemon writes connection state at connect/disconnect, TUI
// writes user prefs occasionally" pattern, but not a hard guarantee.
//
// Connection-state fields owned by the daemon:
//   LastConnectedServer, LastPublicIP, LastServerFeatures, RealPublicIP,
//   BaselineIP, BaselineOrg, BaselineDNS, ConnectedSince
//
// On disk-read failure, falls back to full Save (best-effort; can still clobber).
func (c *Config) SaveConnectionState() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	disk, err := Load()
	if err != nil {
		// Disk unreadable — fall back to whole-config save.
		return c.saveLocked()
	}

	// Carry the runtime paths over (Load resolves these from $HOME).
	disk.ConfigDir = c.ConfigDir
	disk.ConfigFile = c.ConfigFile

	// Patch only the daemon-owned connection-state fields.
	disk.LastConnectedServer = c.LastConnectedServer
	disk.LastPublicIP = c.LastPublicIP
	disk.LastServerFeatures = c.LastServerFeatures
	disk.RealPublicIP = c.RealPublicIP
	disk.BaselineIP = c.BaselineIP
	disk.BaselineOrg = c.BaselineOrg
	disk.BaselineDNS = c.BaselineDNS
	disk.ConnectedSince = c.ConnectedSince

	return disk.saveLocked()
}

// RecordBaselineCapture writes the ISP public-IP fields under c.mu.Lock,
// then returns without saving. wireguard.Connect calls this early in
// the connect flow (BEFORE handshake) to make the captured baseline
// available for log sanitization during the connect itself —
// SaveConnectionState happens at the end via RecordConnectSuccess.
//
// Race surface: every Logger.Log invocation in the daemon reads
// cfg.RealPublicIP via LoggerView (under c.mu.RLock) for sanitization.
// Bare assignment from wireguard.Connect raced those reads, especially
// when a client goroutine was logging from handleClient concurrently
// with the daemon's main-goroutine connect attempt.
//
// First-connect semantics preserved: when BaselineIP is empty, the
// baseline trio (BaselineIP / Org / DNS) gets captured atomically.
// Reconnects (BaselineIP already set) only refresh RealPublicIP.
func (c *Config) RecordBaselineCapture(realIP, baselineOrg string, baselineDNS []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.RealPublicIP = realIP
	if c.BaselineIP == "" {
		c.BaselineIP = realIP
		c.BaselineOrg = baselineOrg
		c.BaselineDNS = baselineDNS
	}
}

// SetLastServerFeatures writes LastServerFeatures under c.mu.Lock and
// routes through SaveConnectionState. The daemon's post-connect handler
// looks up provider-specific feature flags (p2p/tor/securecore/etc.)
// AFTER wireguard.Connect returns, so this is a separate write site
// from RecordConnectSuccess (which fires inside Connect).
//
// Pre-fix bare assignment from doConnect (main goroutine) raced
// SaveConnectionState's c.mu.Lock read of LastServerFeatures from the
// sleepWakeListener goroutine path (ForceDisconnect ->
// ClearConnectionState -> SaveConnectionState). The race window is
// small but real: wake-during-connect is the realistic trigger.
func (c *Config) SetLastServerFeatures(features string) error {
	c.mu.Lock()
	c.LastServerFeatures = features
	c.mu.Unlock()
	return c.SaveConnectionState()
}

// RecordConnectSuccess writes the post-connect state fields under
// c.mu.Lock and routes through SaveConnectionState. Same race surface
// as RecordBaselineCapture: cfg.LastPublicIP is read by LoggerView
// from any goroutine (client) that calls Logger.Log.
func (c *Config) RecordConnectSuccess(lastServer, lastIP string, connectedSince time.Time) error {
	c.mu.Lock()
	c.LastConnectedServer = lastServer
	c.LastPublicIP = lastIP
	c.ConnectedSince = connectedSince
	c.mu.Unlock()
	return c.SaveConnectionState()
}

// ClearConnectionState zeros the in-memory connection-state fields that
// disconnect paths need to wipe, then atomically saves them to disk via
// SaveConnectionState.
//
// The two steps must be locked together — wireguard.ForceDisconnect and
// wireguard.DisconnectWithCallback are called from goroutines (sleepWakeListener,
// main, occasionally client) while another goroutine may be reading
// cfg.RealPublicIP / cfg.LastPublicIP via LoggerView (under cfg.mu.RLock). Bare
// assignment from the wireguard package would race those reads. This method
// writes the fields under c.mu.Lock and then routes through SaveConnectionState
// (which takes its own lock briefly) — the small lock-acquire-twice cost is
// worth keeping the public API minimal.
//
// clearLastServer controls whether LastConnectedServer + LastServerFeatures
// are also cleared:
//
//   - false (ForceDisconnect): preserve LastConnectedServer. The field is the
//     autoconnect (mode=last_used) anchor; preserving it across system shutdown
//     and the daemon's switch path is the whole point of ForceDisconnect.
//   - true (DisconnectWithCallback): clear LastConnectedServer too. Explicit
//     user-disconnect ("lazyvpn daemon stop") means "fully disconnected, don't
//     try to resume on next launch."
//
// The two go together — LastServerFeatures describes the same connection as
// LastConnectedServer, so leaving features behind while the name is cleared
// would be inconsistent state (ghost feature labels in any future code path
// that reads LastServerFeatures without first guarding on
// LastConnectedServer != "").
func (c *Config) ClearConnectionState(clearLastServer bool) error {
	c.mu.Lock()
	c.RealPublicIP = ""
	c.LastPublicIP = ""
	c.ConnectedSince = time.Time{}
	if clearLastServer {
		c.LastConnectedServer = ""
		c.LastServerFeatures = ""
	}
	c.mu.Unlock()
	return c.SaveConnectionState()
}

// IsOmarchy returns true if the detected distro is Omarchy Linux.
func (c *Config) IsOmarchy() bool {
	return c.Distro == "omarchy"
}

// IsCOWFilesystem returns true if the detected filesystem is copy-on-write
// (e.g. btrfs), OR if detection returned "unknown" (overlayfs, tmpfs,
// encrypted volumes, network mounts — anything that fell off the recognized
// list). Treating "unknown" as CoW is the safe default: PlainDelete (rm)
// is correct everywhere, while SecureDelete (shred) is theater on CoW and
// can mislead the user into thinking sensitive data was overwritten when
// the original blocks remain in the underlying subvolume / overlay layer.
func (c *Config) IsCOWFilesystem() bool {
	return c.FSType == "btrfs" || c.FSType == "unknown" || c.FSType == ""
}

// Reload reloads the config from disk.
// Thread-safe: loads file first, then acquires lock to swap values.
func (c *Config) Reload() error {
	// Load from disk WITHOUT holding the lock (file I/O can block)
	newCfg, err := Load()
	if err != nil {
		return err
	}

	// Now acquire lock and copy fields via shadow struct.
	// Note: ConfigDir / ConfigFile are intentionally NOT touched here. Both
	// are derived from $HOME at Load() time and don't legitimately change
	// during a process lifetime; rewriting them on every Reload was a no-op
	// in practice but caused a real race against any reader (e.g. the
	// logger's filepath.Join(l.cfg.ConfigDir, ...) in Logger.write) that
	// touches the path without holding c.mu.
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fromJSON(newCfg.toJSON())
	return nil
}

// ReloadUserPrefs refreshes the user-pref fields the daemon consults at
// runtime — KillswitchAutoDisable, AutoRecover, AutoFailover. Other user-pref
// fields are intentionally left alone because the daemon doesn't consult them
// mid-session: health-check timings, MTU, DNS providers, bandwidth display,
// autostart mode, etc. are read at startup or by the boot subcommand from a
// fresh Load. Log* fields are read by the logger via LoggerView() which has
// its own RLock-based snapshot path, so they don't need to be refreshed here
// either — TUI-side log-toggle edits are visible to the logger immediately.
//
// Use before checking KillswitchAutoDisable (e.g. at terminate or disconnect
// time) so the daemon honors a TUI edit made after it started.
func (c *Config) ReloadUserPrefs() error {
	disk, err := Load()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.KillswitchAutoDisable = disk.KillswitchAutoDisable
	c.AutoRecover = disk.AutoRecover
	c.AutoFailover = disk.AutoFailover
	return nil
}

// LoggerView is a thread-safe point-in-time snapshot of the Config fields
// the logger reads on every Log() call. Returned by LoggerView() under an
// RLock so the read doesn't race with concurrent Save / Reload writes.
//
// Background: the logger used to read l.cfg.LogConnection (and friends)
// directly without any synchronization. That worked in practice because
// nothing wrote to those fields after startup, but the moment anything
// called Reload / SaveConnectionState / ReloadUserPrefs that wrote to a
// Log* field, the race detector flagged it (real WAR/RAR race even if
// outcomes are usually benign for bool fields). This snapshot collapses
// every per-field RLock into one and gives the logger a consistent view.
type LoggerView struct {
	LogConnection  bool
	LogAutorecover bool
	LogFirewall    bool
	LogProvider    bool
	LogAutostart   bool
	LogMode        string
	RealPublicIP   string
	LastPublicIP   string
}

// LoggerView returns a thread-safe snapshot of the fields the logger reads.
// Designed to be called once per Log() invocation.
func (c *Config) LoggerView() LoggerView {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return LoggerView{
		LogConnection:  c.LogConnection,
		LogAutorecover: c.LogAutorecover,
		LogFirewall:    c.LogFirewall,
		LogProvider:    c.LogProvider,
		LogAutostart:   c.LogAutostart,
		LogMode:        c.LogMode,
		RealPublicIP:   c.RealPublicIP,
		LastPublicIP:   c.LastPublicIP,
	}
}

// UserPrefsView is a thread-safe point-in-time snapshot of the
// user-preference fields callers cross goroutines to read while
// ReloadUserPrefs / Reload may be concurrently writing them. Same
// shape as LoggerView — see that type for the broader rationale.
type UserPrefsView struct {
	AutoRecover  bool
	AutoFailover bool
}

// UserPrefsView returns a thread-safe snapshot of the user-preference
// fields the daemon's sendStatus reads from a different goroutine
// than the ReloadUserPrefs / Reload writers.
func (c *Config) UserPrefsView() UserPrefsView {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return UserPrefsView{
		AutoRecover:  c.AutoRecover,
		AutoFailover: c.AutoFailover,
	}
}

// GetConnectionName returns the configured WireGuard interface name
// under cfg.mu.RLock. The daemon's sleepWakeListener goroutine reads
// this field at wake while the main goroutine may be running
// cfg.Reload (which rewrites every field including ConnectionName)
// — direct read would race the write. Other readers in the daemon's
// main goroutine are safe (same goroutine that calls Reload), so we
// don't migrate them.
func (c *Config) GetConnectionName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ConnectionName
}

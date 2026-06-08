package wireguard

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/security"
)

// Config represents a WireGuard configuration
type Config struct {
	Name string // Server name (filename without .conf)
	Path string // Full path to config file

	// Interface section
	PrivateKey []byte // Raw key bytes (base64-decoded); use ZeroKeys() to clear
	Address    string
	DNS        string
	MTU        int // MTU value (0 means use default 1420)

	// Peer section
	PublicKey           string
	PresharedKey        []byte // Optional; raw key bytes (base64-decoded)
	Endpoint            string
	AllowedIPs          string
	PersistentKeepalive int

	// Comments from the config file (used for feature detection)
	Comments []string

	// ParseError is set if the config file failed to parse or validate
	ParseError string
}

// zeroKeysOnError wipes parsed key material from a Config that is about
// to be discarded on an error path. Exposed as a var so tests can verify
// that the wipe actually fires — without observability the defense is
// unverifiable except by inspection.
var zeroKeysOnError = (*Config).ZeroKeys

// ParseConfig reads and parses a WireGuard config file
func ParseConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &Config{
		Path:                path,
		Name:                strings.TrimSuffix(filepath.Base(path), ".conf"),
		PersistentKeepalive: 25, // Default
	}

	// Defense-in-depth: every "return nil, err" below leaves cfg
	// unreachable to the caller. If [Interface] PrivateKey decoded
	// successfully and then [Peer] PresharedKey decode fails (or
	// scanner.Err fires after either was set), the parsed key bytes
	// would otherwise linger on heap until GC. Defer wipes them on
	// any non-success exit.
	parseSucceeded := false
	defer func() {
		if !parseSucceeded {
			zeroKeysOnError(cfg)
		}
	}()

	scanner := bufio.NewScanner(file)
	// Raise buffer cap to 1MB. The default 64KB cap is tight for a
	// legitimate WireGuard config: an AllowedIPs line listing many
	// CIDRs (corporate subnets, cloud provider IP ranges) can run
	// long. Pre-fix the parse returned a cryptic bufio "token too
	// long" error instead of a useful diagnostic. 1MB is well above
	// any plausible single config line.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	section := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines; capture comments for feature detection
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			cfg.Comments = append(cfg.Comments, line)
			continue
		}

		// Check for section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		// Parse key=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		// Remove inline comments: require whitespace before # to match wg-quick behavior
		if idx := strings.Index(value, " #"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				decoded, err := base64.StdEncoding.DecodeString(value)
				if err != nil {
					return nil, fmt.Errorf("invalid PrivateKey: %w", err)
				}
				cfg.PrivateKey = decoded
			case "address":
				cfg.Address = value
			case "dns":
				cfg.DNS = value
			case "mtu":
				fmt.Sscanf(value, "%d", &cfg.MTU)
			}
		case "peer":
			switch key {
			case "publickey":
				cfg.PublicKey = value
			case "presharedkey":
				decoded, err := base64.StdEncoding.DecodeString(value)
				if err != nil {
					return nil, fmt.Errorf("invalid PresharedKey: %w", err)
				}
				cfg.PresharedKey = decoded
			case "endpoint":
				cfg.Endpoint = value
			case "allowedips":
				cfg.AllowedIPs = value
			case "persistentkeepalive":
				// Parse keepalive, use default if malformed
				fmt.Sscanf(value, "%d", &cfg.PersistentKeepalive)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	parseSucceeded = true
	return cfg, nil
}

// Validate checks if the config has all required fields
func (c *Config) Validate() error {
	if len(c.PrivateKey) == 0 {
		return fmt.Errorf("missing PrivateKey")
	}
	if c.PublicKey == "" {
		return fmt.Errorf("missing PublicKey")
	}
	if c.Endpoint == "" {
		return fmt.Errorf("missing Endpoint")
	}
	return nil
}

// ValidatePrivateKey validates decoded WireGuard private key bytes.
// Returns nil if valid, error describing the issue if invalid.
// Base64 format validation is implicit — invalid base64 fails at decode time
// in ParseConfig, leaving PrivateKey nil.
func ValidatePrivateKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("invalid length: expected 32 bytes, got %d", len(key))
	}

	// Must not be all zeros (zeroed-out or sanitized key)
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("key is all zeros")
	}

	return nil
}

// ZeroKeys zeroes the PrivateKey and PresharedKey fields.
func (c *Config) ZeroKeys() {
	security.ZeroBytes(c.PrivateKey)
	security.ZeroBytes(c.PresharedKey)
}

// EndpointIP returns just the IP/hostname from the endpoint (without port)
func (c *Config) EndpointIP() string {
	if c.Endpoint == "" {
		return ""
	}
	// Handle both IPv4 (host:port) and IPv6 ([host]:port)
	if strings.HasPrefix(c.Endpoint, "[") {
		// IPv6
		if idx := strings.Index(c.Endpoint, "]:"); idx > 0 {
			return c.Endpoint[1:idx]
		}
		return strings.Trim(c.Endpoint, "[]")
	}
	// IPv4 or hostname
	if idx := strings.LastIndex(c.Endpoint, ":"); idx > 0 {
		return c.Endpoint[:idx]
	}
	return c.Endpoint
}

// LoadConfig loads a specific config by name from the given directory
func LoadConfig(dir string, name string) (*Config, error) {
	// Try with .conf extension first
	path := filepath.Join(dir, name)
	if !strings.HasSuffix(path, ".conf") {
		path = path + ".conf"
	}

	// Prevent path traversal: resolve symlinks then ensure path stays within dir
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("invalid directory: %w", err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return nil, fmt.Errorf("invalid config path: %w", err)
	}
	realDir, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		return nil, fmt.Errorf("invalid directory path: %w", err)
	}
	if !strings.HasPrefix(realPath, realDir+string(filepath.Separator)) {
		return nil, fmt.Errorf("invalid config name: path traversal detected")
	}

	cfg, err := ParseConfig(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config %s: %w", name, err)
	}

	if err := cfg.Validate(); err != nil {
		// ParseConfig succeeded so cfg holds parsed PrivateKey bytes;
		// returning nil here would orphan them on heap. Wipe before
		// dropping the reference.
		zeroKeysOnError(cfg)
		return nil, fmt.Errorf("invalid config %s: %w", name, err)
	}

	return cfg, nil
}

// ListConfigs returns all WireGuard configs in the given directory.
// Configs that fail to parse or validate are included with ParseError set.
//
// PrivateKey and PresharedKey bytes are zeroed before return — every
// production caller (latency probes, daemon failover scan, server
// browser, autoconnect picker, addserver dedup, settings count,
// removeserver list) consumes only metadata (Name, Endpoint, DNS,
// Comments). Callers that need decoded key material must call
// LoadConfig with the specific config name.
//
// Slices keep their original length so callers can still distinguish
// "key was decoded" (len > 0, all zeros) from "key was missing"
// (len == 0).
func ListConfigs(dir string) ([]*Config, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var configs []*Config
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		cfg, err := ParseConfig(path)
		if err != nil {
			configs = append(configs, &Config{
				Name:       strings.TrimSuffix(entry.Name(), ".conf"),
				Path:       path,
				ParseError: err.Error(),
			})
			continue
		}

		if valErr := cfg.Validate(); valErr != nil {
			cfg.ParseError = valErr.Error()
		}
		// Zero key bytes before exposing the cfg to callers — see
		// function comment for the rationale. Slice length is preserved
		// so PrivateKey/PresharedKey == nil still means "absent".
		cfg.ZeroKeys()
		configs = append(configs, cfg)
	}

	return configs, nil
}

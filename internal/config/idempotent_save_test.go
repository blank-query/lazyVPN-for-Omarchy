package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestSaveIsIdempotent: save → load → save → load → compare bytes. If the
// JSON marshal isn't deterministic (map iteration order, etc.) the second
// save will differ even though no fields changed, and a downstream
// "did the config actually change?" check would falsely fire.
func TestSaveIsIdempotent(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	configDir := filepath.Join(tmp, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.ConfigDir = configDir
	cfg.ConfigFile = filepath.Join(configDir, "config.json")
	cfg.ConnectionName = "wg0"
	cfg.LastConnectedServer = "Proton-US-NY#42"
	cfg.BaselineDNS = []string{"1.1.1.1", "8.8.8.8"}
	cfg.PingTargets = []string{"cloudflare.com", "1.1.1.1"}
	cfg.DNSProviders = []string{"powerdns", "akamai", "local"}
	cfg.CustomMTU = 1380

	if err := cfg.Save(); err != nil {
		t.Fatalf("save 1: %v", err)
	}
	first, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}

	// Load the just-saved file into a fresh Config and save again.
	loaded, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	loaded.ConfigFile = cfg.ConfigFile
	if err := loaded.Save(); err != nil {
		t.Fatalf("save 2: %v", err)
	}
	second, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first, second) {
		t.Errorf("save → load → save not byte-equal\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

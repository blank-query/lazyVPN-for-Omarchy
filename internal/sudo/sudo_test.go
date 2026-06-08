package sudo

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestIsAuthError_PasswordRequired(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"password required", "sudo: a password is required", true},
		{"terminal required", "sudo: a terminal is required to read the password", true},
		{"password prefix", "a password is required to run this command", true},
		{"terminal prefix", "a terminal is required", true},
		{"unrelated error", "iptables: No chain/target/match by that name.", false},
		{"empty output", "", false},
		{"exit status", "exit status 1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAuthError([]byte(tt.output))
			if got != tt.want {
				t.Errorf("IsAuthError(%q) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

func TestErrAuthRequired_ErrorString(t *testing.T) {
	if ErrAuthRequired.Error() != "sudo authentication required" {
		t.Errorf("ErrAuthRequired = %q", ErrAuthRequired.Error())
	}
}

func TestZeroBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"nil", nil},
		{"single", []byte{0xFF}},
		{"mixed", []byte{1, 2, 3, 0, 255, 128}},
		{"ascii", []byte("password123")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := append([]byte(nil), tt.input...)
			ZeroBytes(b)
			for i, v := range b {
				if v != 0 {
					t.Errorf("byte %d = %d, want 0", i, v)
				}
			}
		})
	}
}

func TestAuthenticate_Injectable(t *testing.T) {
	origAuth := Authenticate
	t.Cleanup(func() { Authenticate = origAuth })

	Authenticate = func(password []byte) error {
		if string(password) == "correct" {
			return nil
		}
		return fmt.Errorf("incorrect password")
	}

	if err := Authenticate([]byte("correct")); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
	if err := Authenticate([]byte("wrong")); err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestProbeCache_Injectable(t *testing.T) {
	origProbe := ProbeCache
	t.Cleanup(func() { ProbeCache = origProbe })

	ProbeCache = func() bool { return true }
	if !ProbeCache() {
		t.Error("expected true")
	}

	ProbeCache = func() bool { return false }
	if ProbeCache() {
		t.Error("expected false")
	}
}

func TestProbeCapabilities_Injectable(t *testing.T) {
	origProbe := ProbeCapabilities
	t.Cleanup(func() { ProbeCapabilities = origProbe })

	ProbeCapabilities = func(path string) bool {
		return path == "/usr/bin/lazyvpn"
	}
	if !ProbeCapabilities("/usr/bin/lazyvpn") {
		t.Error("expected true for matching path")
	}
	if ProbeCapabilities("/other/path") {
		t.Error("expected false for non-matching path")
	}
}

func TestSetCapabilities_Injectable(t *testing.T) {
	origSet := SetCapabilities
	t.Cleanup(func() { SetCapabilities = origSet })

	SetCapabilities = func(path string) error {
		if path == "/usr/bin/lazyvpn" {
			return nil
		}
		return ErrAuthRequired
	}
	if err := SetCapabilities("/usr/bin/lazyvpn"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
	if err := SetCapabilities("/other"); err != ErrAuthRequired {
		t.Errorf("expected ErrAuthRequired, got %v", err)
	}
}

// TestSetCLocale_AppendsLCAllC verifies LC_ALL=C is appended without
// dropping any pre-set environment. Test fakes (helper-process pattern)
// rely on GO_WANT_HELPER_PROCESS being preserved in cmd.Env.
func TestSetCLocale_AppendsLCAllC(t *testing.T) {
	t.Run("nil env starts from os.Environ + LC_ALL=C", func(t *testing.T) {
		cmd := exec.Command("true")
		if cmd.Env != nil {
			t.Fatal("setup: expected nil env on fresh exec.Command")
		}
		SetCLocale(cmd)
		if cmd.Env == nil {
			t.Fatal("Env still nil after SetCLocale")
		}
		found := false
		for _, e := range cmd.Env {
			if e == "LC_ALL=C" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("LC_ALL=C not found in Env; got: %v", cmd.Env)
		}
	})

	t.Run("preserves pre-set env entries", func(t *testing.T) {
		cmd := exec.Command("true")
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "FOO=bar"}
		SetCLocale(cmd)
		// Both originals preserved
		gotHelper, gotFoo, gotLC := false, false, false
		for _, e := range cmd.Env {
			switch e {
			case "GO_WANT_HELPER_PROCESS=1":
				gotHelper = true
			case "FOO=bar":
				gotFoo = true
			case "LC_ALL=C":
				gotLC = true
			}
		}
		if !gotHelper || !gotFoo {
			t.Errorf("pre-set env entries lost; env: %v", cmd.Env)
		}
		if !gotLC {
			t.Errorf("LC_ALL=C not appended; env: %v", cmd.Env)
		}
	})

	t.Run("LC_ALL=C wins if duplicated", func(t *testing.T) {
		// Go's exec.Cmd takes the LAST occurrence of a duplicated key in Env
		// (per os/exec docs: "If Env contains duplicate environment keys,
		// only the last value in the slice for each duplicate key is used.").
		// SetCLocale appends, so even if env already has LC_ALL=fr_FR.UTF-8,
		// the trailing LC_ALL=C wins.
		cmd := exec.Command("true")
		cmd.Env = []string{"LC_ALL=fr_FR.UTF-8"}
		SetCLocale(cmd)
		// Last entry should be LC_ALL=C
		last := cmd.Env[len(cmd.Env)-1]
		if !strings.HasPrefix(last, "LC_ALL=") || !strings.HasSuffix(last, "=C") {
			t.Errorf("expected last env entry to be LC_ALL=C, got %q", last)
		}
	})
}

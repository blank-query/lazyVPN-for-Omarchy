package firewall

import (
	"fmt"
	"sync"
	"testing"
)

func TestSetLogFunc(t *testing.T) {
	// Reset global state
	SetLogFunc(nil)

	// Verify nil log doesn't panic
	log("test %s", "message")

	// Set a log function
	var captured string
	SetLogFunc(func(format string, args ...interface{}) {
		captured = fmt.Sprintf(format, args...)
	})

	log("hello %s %d", "world", 42)
	if captured != "hello world 42" {
		t.Errorf("captured = %q, want %q", captured, "hello world 42")
	}

	// Clear log function
	SetLogFunc(nil)
	captured = ""
	log("should not capture")
	if captured != "" {
		t.Error("log should not call nil function")
	}
}

func TestSetLogFuncConcurrent(t *testing.T) {
	var wg sync.WaitGroup

	// Concurrent reads and writes should not race
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			SetLogFunc(func(format string, args ...interface{}) {})
		}()
		go func() {
			defer wg.Done()
			log("concurrent %d", 1)
		}()
	}

	wg.Wait()
	SetLogFunc(nil) // cleanup
}

func TestKillswitchConfigStruct(t *testing.T) {
	cfg := &KillswitchConfig{
		InterfaceName: "wg0",
		DNS:           "10.2.0.1",
		Endpoint:      "198.51.100.1",
	}

	if cfg.InterfaceName != "wg0" {
		t.Errorf("InterfaceName = %q", cfg.InterfaceName)
	}
	if cfg.DNS != "10.2.0.1" {
		t.Errorf("DNS = %q", cfg.DNS)
	}
	if cfg.Endpoint != "198.51.100.1" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
}

func TestKillswitchConfigDefaults(t *testing.T) {
	cfg := &KillswitchConfig{}
	if cfg.InterfaceName != "" {
		t.Errorf("default InterfaceName should be empty, got %q", cfg.InterfaceName)
	}
}

func TestLogFormatting(t *testing.T) {
	tests := []struct {
		name   string
		format string
		args   []interface{}
		want   string
	}{
		{"no args", "simple message", nil, "simple message"},
		{"string arg", "hello %s", []interface{}{"world"}, "hello world"},
		{"int arg", "count: %d", []interface{}{42}, "count: 42"},
		{"multiple args", "%s=%d (%v)", []interface{}{"x", 5, true}, "x=5 (true)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			SetLogFunc(func(format string, args ...interface{}) {
				got = fmt.Sprintf(format, args...)
			})
			log(tt.format, tt.args...)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
	SetLogFunc(nil) // cleanup
}

func TestTagConstants(t *testing.T) {
	if TagKillswitch != "lazyvpn:ks" {
		t.Errorf("TagKillswitch = %q, want lazyvpn:ks", TagKillswitch)
	}
	if TagLANBlock != "lazyvpn:lb" {
		t.Errorf("TagLANBlock = %q, want lazyvpn:lb", TagLANBlock)
	}
	if TagStealth != "lazyvpn:st" {
		t.Errorf("TagStealth = %q, want lazyvpn:st", TagStealth)
	}
	if TagIPv6 != "lazyvpn:v6" {
		t.Errorf("TagIPv6 = %q, want lazyvpn:v6", TagIPv6)
	}
}

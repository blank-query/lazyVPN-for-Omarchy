package netlink

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestParsePrivateKey(t *testing.T) {
	// Valid 32-byte key decoded from base64
	validKeyBytes, err := base64.StdEncoding.DecodeString("YNqHbfBQKaGvct4Jt2ZLKXHXP0sMhCX80fPlOSf80Vo=")
	if err != nil {
		t.Fatalf("failed to decode test key: %v", err)
	}

	t.Run("valid key", func(t *testing.T) {
		key, err := ParsePrivateKey(validKeyBytes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key == (Key{}) {
			t.Error("key should not be zero")
		}
	})

	t.Run("wrong length short", func(t *testing.T) {
		_, err := ParsePrivateKey([]byte("short"))
		if err == nil {
			t.Error("expected error for wrong key length")
		}
	})

	t.Run("wrong length 16 bytes", func(t *testing.T) {
		_, err := ParsePrivateKey(make([]byte, 16))
		if err == nil {
			t.Error("expected error for wrong key length")
		}
		if !strings.Contains(err.Error(), "invalid key length") {
			t.Errorf("error should mention length: %v", err)
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		_, err := ParsePrivateKey([]byte{})
		if err == nil {
			t.Error("expected error for empty slice")
		}
	})
}

func TestParsePublicKey(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{"valid 32-byte base64", "YNqHbfBQKaGvct4Jt2ZLKXHXP0sMhCX80fPlOSf80Vo=", false, ""},
		{"empty string", "", true, "invalid key length"},
		{"invalid base64", "not!valid!base64", true, "invalid base64 key"},
		{"correct base64 wrong length", "YWJjZA==", true, "invalid key length"}, // "abcd" → 4 bytes
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParsePublicKey(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got key=%v", key)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key == (Key{}) {
				t.Error("key should not be zero on success")
			}
		})
	}
}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantIP  string
		wantErr bool
	}{
		{"valid ipv4", "1.2.3.4:51820", "1.2.3.4", false},
		{"valid ipv6", "[::1]:51820", "::1", false},
		{"no port", "1.2.3.4", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := ParseEndpoint(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantIP != "" && addr.IP.String() != tt.wantIP {
				t.Errorf("IP = %q, want %q", addr.IP.String(), tt.wantIP)
			}
			if addr.Port != 51820 {
				t.Errorf("Port = %d, want 51820", addr.Port)
			}
		})
	}
}

func TestParseAllowedIPs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int // expected count
		wantErr bool
	}{
		{"single cidr", "0.0.0.0/0", 1, false},
		{"two cidrs", "0.0.0.0/0, ::/0", 2, false},
		{"host route", "10.0.0.1/32", 1, false},
		{"empty", "", 0, false},
		{"spaces", "  10.0.0.0/24 , 192.168.0.0/16  ", 2, false},
		{"invalid cidr", "not-a-cidr", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAllowedIPs(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.want {
				t.Errorf("count = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestMaskBits(t *testing.T) {
	tests := []struct {
		name string
		mask net.IPMask
		want int
	}{
		{"/32", net.CIDRMask(32, 32), 32},
		{"/24", net.CIDRMask(24, 32), 24},
		{"/0", net.CIDRMask(0, 32), 0},
		{"/128 ipv6", net.CIDRMask(128, 128), 128},
		{"/64 ipv6", net.CIDRMask(64, 128), 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskBits(tt.mask)
			if got != tt.want {
				t.Errorf("maskBits() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name string
		s    string
		sep  string
		want []string
	}{
		{"normal", "a,b,c", ",", []string{"a", "b", "c"}},
		{"spaces", " a , b , c ", ",", []string{"a", "b", "c"}},
		{"empty parts", "a,,b", ",", []string{"a", "b"}},
		{"single", "a", ",", []string{"a"}},
		{"empty string", "", ",", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitAndTrim(tt.s, tt.sep)
			if len(got) != len(tt.want) {
				t.Errorf("count = %d, want %d: %v", len(got), len(tt.want), got)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIsPermError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		expect bool
	}{
		{"operation not permitted", fmt.Errorf("operation not permitted"), true},
		{"permission denied", fmt.Errorf("permission denied"), true},
		{"generic error", fmt.Errorf("something else"), false},
		{"wrapped perm", fmt.Errorf("wrapped: operation not permitted"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPermError(tt.err)
			if got != tt.expect {
				t.Errorf("isPermError(%q) = %v, want %v", tt.err, got, tt.expect)
			}
		})
	}
}

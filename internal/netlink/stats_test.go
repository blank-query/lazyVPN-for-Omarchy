package netlink

import (
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.00 KB"},
		{1536, "1.50 KB"},
		{1048576, "1.00 MB"},
		{1572864, "1.50 MB"},
		{1073741824, "1.00 GB"},
		{2147483648, "2.00 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatBytes(tt.input)
			if got != tt.want {
				t.Errorf("FormatBytes(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatBytesPerSec(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{0, "0 B/s"},
		{512, "512 B/s"},
		{1024, "1.00 KB/s"},
		{1048576, "1.00 MB/s"},
		{1073741824, "1.00 GB/s"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatBytesPerSec(tt.input)
			if got != tt.want {
				t.Errorf("FormatBytesPerSec(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// FormatBitsPerSec converts B/s to bits/s with SI thresholds (1000-base).
// Distinct from FormatBytesPerSec which uses 1024-base.
func TestFormatBitsPerSec(t *testing.T) {
	tests := []struct {
		input float64 // bytes/sec
		want  string  // displayed as bits/sec
	}{
		{0, "0 bps"},
		{1, "8 bps"},               // 1 B/s × 8 = 8 bps
		{124, "992 bps"},           // just under Kbit threshold
		{125, "1.00 Kbps"},         // exactly Kbit (8 × 125 = 1000)
		{125_000, "1.00 Mbps"},     // 8 × 125_000 = 1_000_000
		{125_000_000, "1.00 Gbps"}, // 8 × 125_000_000 = 1_000_000_000
		{156_250_000, "1.25 Gbps"}, // mid-Gbps
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatBitsPerSec(tt.input)
			if got != tt.want {
				t.Errorf("FormatBitsPerSec(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

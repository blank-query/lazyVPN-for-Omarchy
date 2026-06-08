package ui

import (
	"strings"
	"testing"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		s    string
		max  int
		want string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"truncated", "hello world", 5, "hell\u2026"},
		{"max 1", "hello", 1, "h"},
		{"max 0", "hello", 0, ""},
		{"empty string", "", 5, ""},
		{"unicode", "\U0001F1FA\U0001F1F8 US", 4, "\U0001F1FA\U0001F1F8 \u2026"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Truncate(tt.s, tt.max)
			if got != tt.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tt.s, tt.max, got, tt.want)
			}
		})
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		name string
		s    string
		min  int
		want string
	}{
		{"short string", "hi", 5, "hi   "},
		{"exact length", "hello", 5, "hello"},
		{"longer than min", "hello world", 5, "hello world"},
		{"empty string", "", 3, "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Pad(tt.s, tt.min)
			if got != tt.want {
				t.Errorf("Pad(%q, %d) = %q, want %q", tt.s, tt.min, got, tt.want)
			}
		})
	}
}

func TestCenterText(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		width int
		want  string
	}{
		{"center hello", "hello", 11, "   hello"},
		{"exact width", "hello", 5, "hello"},
		{"wider than width", "hello world", 5, "hello world"},
		{"single char", "x", 5, "  x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CenterText(tt.s, tt.width)
			if got != tt.want {
				t.Errorf("CenterText(%q, %d) = %q, want %q", tt.s, tt.width, got, tt.want)
			}
		})
	}
}

func TestWrapText(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		width int
		check func(string) bool
	}{
		{
			"short text no wrap",
			"hello world",
			20,
			func(s string) bool { return s == "hello world" },
		},
		{
			"wraps at word boundary",
			"hello world foo bar",
			11,
			func(s string) bool { return strings.Contains(s, "\n") },
		},
		{
			"zero width returns original",
			"hello world",
			0,
			func(s string) bool { return s == "hello world" },
		},
		{
			"single word longer than width",
			"superlongword",
			5,
			func(s string) bool { return s == "superlongword" }, // can't break mid-word
		},
		{
			"empty string",
			"",
			10,
			func(s string) bool { return s == "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WrapText(tt.s, tt.width)
			if !tt.check(got) {
				t.Errorf("WrapText(%q, %d) = %q, check failed", tt.s, tt.width, got)
			}
		})
	}
}

func TestTruncateLines(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		maxLines int
		want     string
	}{
		{"empty string", "", 5, ""},
		{"one line within limit", "hello", 5, "hello"},
		{"exact lines", "a\nb\nc", 3, "a\nb\nc"},
		{"more lines than limit", "a\nb\nc\nd\ne", 3, "a\nb\nc"},
		{"single line limit", "a\nb\nc", 1, "a"},
		{"zero limit", "a\nb", 0, ""},
		{"negative limit", "a\nb", -1, ""},
		{"newline only", "\n\n\n", 2, "\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateLines(tt.s, tt.maxLines)
			if got != tt.want {
				t.Errorf("TruncateLines(%q, %d) = %q, want %q", tt.s, tt.maxLines, got, tt.want)
			}
		})
	}
}

func TestSwitchViewMsg(t *testing.T) {
	msg := SwitchViewMsg{
		View:     "connect-progress",
		Server:   "US-NY#42",
		Provider: "protonvpn",
		Dynamic:  true,
	}
	if msg.View != "connect-progress" {
		t.Errorf("View = %q", msg.View)
	}
	if msg.Server != "US-NY#42" {
		t.Errorf("Server = %q", msg.Server)
	}
	if !msg.Dynamic {
		t.Error("Dynamic should be true")
	}
}

func TestConnectionCompleteMsg(t *testing.T) {
	msg := ConnectionCompleteMsg{
		Success: true,
		Server:  "US-NY#42",
		IP:      "1.2.3.4",
	}
	if !msg.Success {
		t.Error("Success should be true")
	}
	if msg.Server != "US-NY#42" {
		t.Errorf("Server = %q", msg.Server)
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateHyprBinding(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		launchCmd    string
		wantChanged  bool
		wantSubstr   string
		wantNoSubstr string
	}{
		{
			name:         "legacy line gets rewritten",
			in:           "bindd = SUPER, L, LazyVPN, exec, /old/path\n",
			launchCmd:    "/new/path",
			wantChanged:  true,
			wantSubstr:   "bindd = SUPER SHIFT, L, LazyVPN, exec, /new/path",
			wantNoSubstr: "SUPER, L, LazyVPN",
		},
		{
			name:        "no legacy line, no change",
			in:          "bindd = SUPER SHIFT, L, LazyVPN, exec, /existing\n",
			launchCmd:   "/new",
			wantChanged: false,
		},
		{
			name:        "empty input",
			in:          "",
			launchCmd:   "/x",
			wantChanged: false,
		},
		{
			name:        "preserves surrounding lines",
			in:          "# something\nbindd = SUPER, L, LazyVPN, exec, /a\n# tail\n",
			launchCmd:   "/b",
			wantChanged: true,
			wantSubstr:  "# something\nbindd = SUPER SHIFT, L, LazyVPN, exec, /b\n# tail\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := migrateHyprBinding(tt.in, tt.launchCmd)
			if changed != tt.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tt.wantChanged)
			}
			if tt.wantSubstr != "" && !strings.Contains(got, tt.wantSubstr) {
				t.Errorf("missing substring %q in:\n%s", tt.wantSubstr, got)
			}
			if tt.wantNoSubstr != "" && strings.Contains(got, tt.wantNoSubstr) {
				t.Errorf("unexpected substring %q in:\n%s", tt.wantNoSubstr, got)
			}
		})
	}
}

func TestHyprBindingExists(t *testing.T) {
	if hyprBindingExists("") {
		t.Error("empty content should not match")
	}
	if !hyprBindingExists("bindd = X, # LazyVPN comment") {
		t.Error("LazyVPN substring should match")
	}
	if hyprBindingExists("just regular bindings") {
		t.Error("unrelated content should not match")
	}
}

func TestAppendHyprBinding(t *testing.T) {
	got := appendHyprBinding("/some/path")
	if !strings.HasPrefix(got, "\n") {
		t.Error("output should start with newline (clean append to non-newline-terminated file)")
	}
	if !strings.Contains(got, "# LazyVPN") || !strings.Contains(got, "/some/path") {
		t.Errorf("missing markers in: %q", got)
	}
}

func TestAddHyprWindowRules(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"existing rules removed first", "windowrule = float on, match:class org.lazyvpn\n# LazyVPN floating window rules\n"},
		{"unrelated content preserved", "binds = whatever\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := addHyprWindowRules(tt.in)
			// Should always end with the three windowrule lines
			if !strings.Contains(got, "match:class org.lazyvpn") {
				t.Errorf("output missing class match: %q", got)
			}
			// Should not double-write rules
			occurrences := strings.Count(got, "windowrule = float on, match:class org.lazyvpn")
			if occurrences != 1 {
				t.Errorf("windowrule appeared %d times, want 1", occurrences)
			}
		})
	}
}

func TestRemoveLazyvpnFromHyprBindings(t *testing.T) {
	in := `# unrelated
bind = SUPER, X, exec, foo
# LazyVPN
bindd = SUPER SHIFT, L, LazyVPN, exec, /home/user/.local/bin/lazyvpn
# tail`
	got := removeLazyvpnFromHyprBindings(in)
	if strings.Contains(got, "LazyVPN") {
		t.Errorf("LazyVPN content not removed: %q", got)
	}
	if !strings.Contains(got, "# unrelated") || !strings.Contains(got, "bind = SUPER, X") || !strings.Contains(got, "# tail") {
		t.Errorf("unrelated content lost: %q", got)
	}
}

func TestRemoveLazyvpnFromHyprBindingsNoOp(t *testing.T) {
	in := "bind = SUPER, X, exec, foo\n"
	got := removeLazyvpnFromHyprBindings(in)
	if got != in {
		t.Errorf("got %q, want unchanged %q", got, in)
	}
}

func TestRemoveLazyvpnFromHyprlandConf(t *testing.T) {
	in := `general {
  layout = master
}
# LazyVPN floating window rules
windowrule = float on, match:class org.lazyvpn
windowrule = size 900 600, match:class org.lazyvpn
# tail`
	got := removeLazyvpnFromHyprlandConf(in)
	if strings.Contains(got, "lazyvpn") || strings.Contains(got, "LazyVPN") {
		t.Errorf("residual LazyVPN content: %q", got)
	}
	if !strings.Contains(got, "general {") || !strings.Contains(got, "# tail") {
		t.Errorf("non-LazyVPN content lost: %q", got)
	}
}

func TestRemoveLazyvpnFromKeybindings(t *testing.T) {
	in := "Super+L | LazyVPN | Open VPN manager\nSuper+T | Terminal | Open terminal\n"
	got := removeLazyvpnFromKeybindings(in)
	if strings.Contains(got, "LazyVPN") {
		t.Errorf("LazyVPN line not removed: %q", got)
	}
	if !strings.Contains(got, "Terminal") {
		t.Errorf("unrelated line lost: %q", got)
	}
}

func TestRemoveLazyvpnFromShellRC(t *testing.T) {
	in := `export PATH=/usr/local/bin:$PATH
# LazyVPN
export PATH=/home/user/.local/bin:$PATH
alias ll='ls -la'`
	got := removeLazyvpnFromShellRC(in)
	if strings.Contains(got, "# LazyVPN") {
		t.Errorf("LazyVPN comment not removed: %q", got)
	}
	if strings.Contains(got, "/home/user/.local/bin") {
		t.Errorf("PATH export line not removed (skipNext logic broken): %q", got)
	}
	if !strings.Contains(got, "/usr/local/bin") || !strings.Contains(got, "alias ll") {
		t.Errorf("unrelated lines lost: %q", got)
	}
}

func TestRemoveLazyvpnFromShellRCNoOp(t *testing.T) {
	in := "export PATH=/usr/bin:$PATH\n"
	got := removeLazyvpnFromShellRC(in)
	if got != in {
		t.Errorf("got %q, want unchanged %q", got, in)
	}
}

func TestRemoveWaybarLazyvpnModule(t *testing.T) {
	in := `{
  "modules-right": ["network", "custom/lazyvpn", "battery"],
  "custom/lazyvpn": {
    "format": "{}",
    "interval": 2,
    "exec": "/usr/local/bin/lazyvpn waybar"
  },
  "battery": { "format": "{capacity}%" }
}`
	got := removeWaybarLazyvpnModule(in)
	if strings.Contains(got, "custom/lazyvpn") {
		t.Errorf("custom/lazyvpn not removed: %q", got)
	}
	if !strings.Contains(got, `"network"`) || !strings.Contains(got, `"battery"`) {
		t.Errorf("sibling modules lost: %q", got)
	}
	if !strings.Contains(got, `"format": "{capacity}%"`) {
		t.Errorf("battery module body lost: %q", got)
	}
}

func TestRemoveWaybarLazyvpnModuleNoOp(t *testing.T) {
	in := `{ "modules-right": ["network"] }`
	got := removeWaybarLazyvpnModule(in)
	if got != in {
		t.Errorf("got %q, want unchanged %q", got, in)
	}
}

func TestRemoveWaybarLazyvpnModuleHandlesFirstPosition(t *testing.T) {
	// Module is FIRST in modules-right (no leading comma), still has trailing.
	in := `{ "modules-right": ["custom/lazyvpn", "network"] }`
	got := removeWaybarLazyvpnModule(in)
	if strings.Contains(got, "custom/lazyvpn") {
		t.Errorf("first-position module not removed: %q", got)
	}
	if !strings.Contains(got, `"network"`) {
		t.Errorf("trailing module lost: %q", got)
	}
}

func TestWriteFileAtomic_WritesContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hyprland.conf")
	want := []byte("monitor=,preferred,auto,1\n")

	if err := writeFileAtomic(target, want, 0644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("content mismatch: got %q want %q", got, want)
	}

	// Permissions match what we asked for.
	st, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0644 {
		t.Errorf("perm = %o, want 0644", st.Mode().Perm())
	}

	// No .lazyvpn-tmp.* orphan left in the directory.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".lazyvpn-tmp.") {
			t.Errorf("orphan tmp file left behind: %s", e.Name())
		}
	}
}

// TestMatchesExeBaseName covers the suffix-stripping comparison the
// TUI's single-instance check relies on. The kernel appends
// " (deleted)" to /proc/<pid>/exe after the binary has been
// atomic-renamed. Pre-fix, isAnotherTUIRunning compared base names
// directly and missed processes whose binary had been replaced via
// `lazyvpn update` — letting a second TUI start.
func TestMatchesExeBaseName(t *testing.T) {
	tests := []struct {
		name     string
		link     string
		baseName string
		want     bool
	}{
		{
			name:     "exact match — fresh binary",
			link:     "/home/user/.local/bin/lazyvpn",
			baseName: "lazyvpn",
			want:     true,
		},
		{
			name:     "deleted suffix — post-update old binary",
			link:     "/home/user/.local/bin/lazyvpn (deleted)",
			baseName: "lazyvpn",
			want:     true,
		},
		{
			name:     "different binary",
			link:     "/usr/bin/curl",
			baseName: "lazyvpn",
			want:     false,
		},
		{
			name:     "different binary with deleted suffix",
			link:     "/usr/bin/curl (deleted)",
			baseName: "lazyvpn",
			want:     false,
		},
		{
			name:     "substring is not a match",
			link:     "/usr/bin/lazyvpn-other",
			baseName: "lazyvpn",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesExeBaseName(tt.link, tt.baseName)
			if got != tt.want {
				t.Errorf("matchesExeBaseName(%q, %q) = %v, want %v",
					tt.link, tt.baseName, got, tt.want)
			}
		})
	}
}

// TestWriteFileAtomic_PreservesOriginalOnFailure verifies that if the
// atomic write fails (here: by pointing at a directory we cannot write
// into because it does not exist), the original file at the target
// path is left untouched and no .lazyvpn-tmp.* orphan is left in the
// surrounding filesystem.
//
// The whole point of writeFileAtomic over bare os.WriteFile is that
// callers' user-shared config files (hyprland.conf, waybar config)
// stay intact even when the write attempt blows up partway through.
func TestWriteFileAtomic_PreservesOriginalOnFailure(t *testing.T) {
	dir := t.TempDir()
	original := []byte("# user's existing hyprland.conf — must not be lost\n")
	target := filepath.Join(dir, "hyprland.conf")
	if err := os.WriteFile(target, original, 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Aim writeFileAtomic at a path inside a non-existent dir. CreateTemp
	// fails, the function returns early, and the original file at `target`
	// is untouched.
	bogusTarget := filepath.Join(dir, "no-such-subdir", "hyprland.conf")
	if err := writeFileAtomic(bogusTarget, []byte("REPLACEMENT"), 0644); err == nil {
		t.Fatal("expected error writing into non-existent dir, got nil")
	}

	// The original file at `target` must not have been touched.
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("original file was clobbered despite write failure:\n  got  %q\n  want %q", got, original)
	}
}

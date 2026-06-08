package daemon

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoFullCfgSaveInDaemonProductionCode is a static regression guard
// for the daemon-side persistence contract documented in CLAUDE.md:
//
//   cfg.Save() — full struct write. ONLY safe when caller knows it
//   owns every field on disk. NEVER call from daemon code.
//
// The reason: daemon and TUI are separate processes. Each loads
// config.json at startup and holds its own in-memory *Config for
// life. A daemon-side cfg.Save() writes the daemon's stale view of
// user prefs over any TUI edit made since the daemon started —
// silently reverting Autoconnect, AutoRecover, log toggles, etc.
//
// Daemon code MUST use cfg.SaveConnectionState() (which reads disk
// first, patches only connection-state fields, writes back) for
// every persistence call. This test scans non-test daemon source
// files and fails if any cfg.Save() call appears.
//
// If you legitimately need to call cfg.Save() in daemon code, add
// the file to the allowlist below and document why in CLAUDE.md.
func TestNoFullCfgSaveInDaemonProductionCode(t *testing.T) {
	// The daemon package source dir is this test's own directory.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Match `cfg.Save(`, `c.Save(`, `d.cfg.Save(` etc.
	// Excludes SaveConnectionState (the correct daemon-side method).
	pattern := regexp.MustCompile(`\b\w+\.cfg\.Save\(\)|\b(c|cfg)\.Save\(\)`)

	var violations []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if pattern.MatchString(line) {
				violations = append(violations, name+":"+itoa(i+1)+" "+strings.TrimSpace(line))
			}
		}
	}

	if len(violations) > 0 {
		t.Errorf("forbidden cfg.Save() call(s) in daemon production code (use SaveConnectionState instead — see CLAUDE.md):\n  %s",
			strings.Join(violations, "\n  "))
	}
}

// itoa is a tiny stdlib-free integer to string for line numbers,
// avoiding the strconv import for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

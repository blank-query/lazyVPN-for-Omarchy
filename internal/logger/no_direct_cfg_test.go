package logger

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoDirectCfgFieldReadsInLogger is a static regression guard for
// the logger's race-safety contract documented in CLAUDE.md:
//
//   Logger reads cfg via cfg.LoggerView() (one RLock per Log() call).
//   Don't add direct reads of l.cfg.LogXxx — they race with
//   Save/Reload.
//
// Pre-fix the logger read l.cfg.LogConnection / l.cfg.LogMode /
// l.cfg.RealPublicIP / l.cfg.LastPublicIP directly while the daemon
// goroutine concurrently called cfg.Reload() / SaveConnectionState()
// which write the same fields under cfg.mu.Lock — a real race the
// detector flagged. The fix routes every read through LoggerView()
// which takes one RLock and returns a snapshot.
//
// This test scans logger.go for any forbidden direct reads of
// LoggerView-mirrored fields. ConfigDir/ConfigFile reads are allowed
// (they're $HOME-derived at Load time and never legitimately written
// after — Reload explicitly skips them).
//
// Currently zero violations. The test exists as a regression guard:
// a future PR that reintroduces a direct l.cfg.LogXxx read will fail
// here with a pointer to LoggerView.
func TestNoDirectCfgFieldReadsInLogger(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	// Forbidden field names — every field LoggerView mirrors. If new
	// fields are added to LoggerView, add them here too.
	fields := []string{
		"LogConnection",
		"LogAutorecover",
		"LogFirewall",
		"LogProvider",
		"LogAutostart",
		"LogMode",
		"RealPublicIP",
		"LastPublicIP",
	}
	pattern := regexp.MustCompile(`\bl\.cfg\.(` + strings.Join(fields, "|") + `)\b`)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

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
			// Skip comments — the contract docs reference these names.
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if m := pattern.FindString(line); m != "" {
				violations = append(violations, name+":"+itoa(i+1)+" "+m+" — use LoggerView() snapshot instead")
			}
		}
	}

	if len(violations) > 0 {
		t.Errorf("forbidden direct cfg field read(s) in logger production code (route via cfg.LoggerView() — see CLAUDE.md):\n  %s",
			strings.Join(violations, "\n  "))
	}
}

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

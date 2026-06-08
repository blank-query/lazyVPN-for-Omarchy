package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
	"github.com/charmbracelet/x/vt"
)

// TestDashboardBandwidthToggles drives the dashboard's right-column
// bandwidth toggles (Bandwidth Style / Bandwidth Unit / Show Session
// Total) via teatest. Tmux scripting had trouble with these
// because adjacent rows get hit by Down/Enter chains under load.
// teatest is deterministic and verifies the cycle behavior.
func TestDashboardBandwidthToggles(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	configDir := filepath.Join(tmp, ".config", "lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.ConfigDir = configDir
	cfg.ConfigFile = filepath.Join(configDir, "config.json")
	cfg.TutorialSeen = true
	cfg.BandwidthDisplay = "sparkline"
	cfg.BandwidthUnit = "Kbps"
	cfg.BandwidthTotal = false
	if err := cfg.Save(); err != nil {
		t.Fatalf("save cfg: %v", err)
	}

	InitTheme()

	emu := vt.NewEmulator(140, 50)
	defer emu.Close()

	tm := teatest.NewTestModel(t, NewLayout(), teatest.WithInitialTermSize(140, 50))
	t.Cleanup(func() {
		// See interactive_test.go for rationale — Quit() is async; without
		// WaitFinished the bubbletea Program goroutine leaks past the test
		// and races package-level color vars in subsequent tests.
		tm.Quit()
		tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
	})

	time.Sleep(500 * time.Millisecond)
	drain(tm, emu)

	// Initial focus is on the sidebar with cursor on Dashboard. Tab moves
	// focus into the dashboard content (cursor lands on left action col).
	// Right switches active column to right (settings).
	send(tm, emu, tea.KeyTab)
	send(tm, emu, tea.KeyRight)
	// Down from Killswitch (top of right col) to Bandwidth Style: KS,
	// KS-on-Disc, IPv6, Local Network, DNS Providers, Bandwidth Style.
	// Five Downs lands on Bandwidth Style.
	for i := 0; i < 5; i++ {
		send(tm, emu, tea.KeyDown)
	}

	// Verify cursor is on Bandwidth Style
	screen := drain(tm, emu)
	if !strings.Contains(screen, "Bandwidth Style") {
		t.Fatalf("Bandwidth Style row not visible:\n%s", screen)
	}

	// Toggle: Sparkline → Bar
	screen = send(tm, emu, tea.KeyEnter)
	if !strings.Contains(screen, "Bar") {
		t.Errorf("after first Enter, expected Bar style; screen:\n%s", screen)
	}
	// Toggle back: Bar → Sparkline
	screen = send(tm, emu, tea.KeyEnter)
	if !strings.Contains(screen, "Sparkline") {
		t.Errorf("after second Enter, expected Sparkline; screen:\n%s", screen)
	}

	// Down to Bandwidth Unit, cycle once
	send(tm, emu, tea.KeyDown)
	pre := drain(tm, emu)
	send(tm, emu, tea.KeyEnter)
	post := drain(tm, emu)
	if pre == post {
		t.Errorf("Bandwidth Unit cycle produced no visible change")
	}

	// Down to Show Session Total
	send(tm, emu, tea.KeyDown)
	send(tm, emu, tea.KeyEnter)
	on := drain(tm, emu)
	if !strings.Contains(on, "Show Session Total") {
		t.Errorf("Show Session Total row should still be visible:\n%s", on)
	}
	send(tm, emu, tea.KeyEnter)
	off := drain(tm, emu)
	_ = off
}

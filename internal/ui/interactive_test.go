package ui

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
	"github.com/charmbracelet/x/vt"
)

func drain(tm *teatest.TestModel, emu *vt.Emulator) string {
	buf := make([]byte, 128*1024)
	for {
		n, _ := tm.Output().Read(buf)
		if n == 0 {
			break
		}
		emu.Write(buf[:n])
	}
	return emu.String()
}

func send(tm *teatest.TestModel, emu *vt.Emulator, k tea.KeyType) string {
	tm.Send(tea.KeyMsg{Type: k})
	time.Sleep(200 * time.Millisecond)
	return drain(tm, emu)
}

func dumpScreen(t *testing.T, label string, screen string) {
	t.Helper()
	t.Logf("=== %s ===", label)
	for _, line := range strings.Split(screen, "\n") {
		trimmed := strings.TrimRight(line, " ")
		if trimmed != "" {
			t.Logf("  %s", trimmed)
		}
	}
}

func TestInteractive(t *testing.T) {
	cfg, _ := config.Load()
	data, _ := os.ReadFile(cfg.ConfigFile)
	t.Cleanup(func() {
		os.WriteFile(cfg.ConfigFile, data, 0600)
	})

	cfg.TutorialSeen = true
	cfg.Save()

	InitTheme()

	emu := vt.NewEmulator(120, 40)
	defer emu.Close()

	tm := teatest.NewTestModel(t, NewLayout(), teatest.WithInitialTermSize(120, 40))
	t.Cleanup(func() {
		// Quit then WAIT — without WaitFinished the teatest's tea.Program
		// goroutine outlives this test and races package-level color vars
		// (theme_test.go's resetColorDefaults vs Layout.View's Color reads)
		// when subsequent tests run. Caught by `go test -race -shuffle=on`.
		tm.Quit()
		tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
	})

	time.Sleep(2 * time.Second)
	drain(tm, emu)

	// Nav to Settings, Enter, right col, down to Show Tutorial
	send(tm, emu, tea.KeyDown)
	send(tm, emu, tea.KeyDown)
	send(tm, emu, tea.KeyDown)
	send(tm, emu, tea.KeyEnter)
	send(tm, emu, tea.KeyRight)
	// Down 10 to Show Tutorial
	for i := 0; i < 10; i++ {
		send(tm, emu, tea.KeyDown)
	}
	screen := send(tm, emu, tea.KeyDown)
	dumpScreen(t, "CURSOR on Show Tutorial", screen)

	// Enter tutorial
	screen = send(tm, emu, tea.KeyEnter)
	dumpScreen(t, "TUTORIAL PAGE 1", screen)

	screen = send(tm, emu, tea.KeyEnter)
	dumpScreen(t, "TUTORIAL PAGE 2", screen)

	screen = send(tm, emu, tea.KeyEnter)
	dumpScreen(t, "TUTORIAL PAGE 3", screen)

	screen = send(tm, emu, tea.KeyEnter)
	dumpScreen(t, "TUTORIAL PAGE 4", screen)

	screen = send(tm, emu, tea.KeyEnter)
	dumpScreen(t, "TUTORIAL PAGE 5", screen)
}

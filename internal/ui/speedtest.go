package ui

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type SpeedTestState int

const (
	SpeedTestIdle SpeedTestState = iota
	SpeedTestRunning
	SpeedTestComplete
	SpeedTestError
)

const (
	speedTestBytes   = 1_000_000 // 1MB per run
	speedTestMaxRuns = 10
	speedTestMinGood = 3 // Minimum successful runs to report average
)

type Speedtest struct {
	cfg        *config.Config
	state      SpeedTestState
	speedMbps  float64
	avgMbps    float64
	error      string
	serverName string
	width      int
	height     int

	// Multi-run tracking
	currentRun int
	runResults []float64 // Mbps for each completed run
	failures   int

	// Progress tracking for current run
	downloaded      int64 // bytes downloaded so far
	liveMbps        float64
	progressDone    *atomic.Bool  // signals download completion
	downloadCounter *atomic.Int64 // shared between runSpeedTest and tickProgress
	startNano       *atomic.Int64 // shared between runSpeedTest and tickProgress

	// runCancel cancels the in-flight HTTP run so the user's Esc actually
	// stops the test instead of letting the 15s ctx run to completion in
	// the background after the model has been replaced.
	runCancel context.CancelFunc
}

func NewSpeedtest(cfg *config.Config) Speedtest {
	serverName := ""
	if isWGConnected(cfg.ConnectionName) {
		serverName = cfg.LastConnectedServer
		if strings.HasPrefix(serverName, "dynamic:") {
			parts := strings.SplitN(serverName, ":", 3)
			if len(parts) == 3 {
				serverName = parts[2]
			}
		}
	}

	return Speedtest{
		cfg:        cfg,
		state:      SpeedTestIdle,
		serverName: serverName,
	}
}

func (m Speedtest) Init() tea.Cmd {
	return nil
}

type speedTestRunCompleteMsg struct {
	runIndex  int
	speedMbps float64
	err       error
}

type speedTestProgressMsg struct {
	downloaded int64
	liveMbps   float64
}

func (m Speedtest) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			// Cancel any in-flight run so we don't burn another ~15s of
			// HTTP after the user already navigated away.
			if m.runCancel != nil {
				m.runCancel()
				m.runCancel = nil
			}
			if m.progressDone != nil {
				m.progressDone.Store(true)
			}
			return m, func() tea.Msg { return BackMsg{} }
		case "enter", " ":
			if m.state == SpeedTestIdle || m.state == SpeedTestComplete || m.state == SpeedTestError {
				m.state = SpeedTestRunning
				m.speedMbps = 0
				m.avgMbps = 0
				m.downloaded = 0
				m.liveMbps = 0
				m.currentRun = 0
				m.runResults = nil
				m.failures = 0
				done := &atomic.Bool{}
				m.progressDone = done
				m.downloadCounter = &atomic.Int64{}
				m.startNano = &atomic.Int64{}
				// Cancel any prior context (left over from a previous full
				// test cycle) before assigning a new one. Without this the
				// old context leaks until program exit per Go's context
				// docs: "Failing to call the CancelFunc leaks the context's
				// parent until the parent is canceled or the timer fires."
				if m.runCancel != nil {
					m.runCancel()
				}
				ctx, cancel := context.WithCancel(context.Background())
				m.runCancel = cancel
				return m, tea.Batch(m.runSingleTest(ctx, 0, m.downloadCounter, m.startNano), m.tickProgress(done, m.downloadCounter, m.startNano))
			}
		}

	case speedTestProgressMsg:
		m.downloaded = msg.downloaded
		m.liveMbps = msg.liveMbps
		if m.state == SpeedTestRunning && m.progressDone != nil && !m.progressDone.Load() {
			return m, m.tickProgress(m.progressDone, m.downloadCounter, m.startNano)
		}

	case speedTestRunCompleteMsg:
		if m.progressDone != nil {
			m.progressDone.Store(true)
		}

		if msg.err != nil {
			m.failures++
		} else {
			m.runResults = append(m.runResults, msg.speedMbps)
			m.speedMbps = msg.speedMbps
		}

		m.currentRun = msg.runIndex + 1

		// Check if we should continue
		if m.currentRun < speedTestMaxRuns {
			// Start next run
			m.downloaded = 0
			m.liveMbps = 0
			done := &atomic.Bool{}
			m.progressDone = done
			m.downloadCounter = &atomic.Int64{}
			m.startNano = &atomic.Int64{}
			// Cancel the previous run's context so it doesn't leak. The
			// run goroutine has already returned (we're processing its
			// completion msg), so cancellation is just bookkeeping —
			// but per Go context docs the cancel must still fire to
			// release the parent linkage.
			if m.runCancel != nil {
				m.runCancel()
			}
			ctx, cancel := context.WithCancel(context.Background())
			m.runCancel = cancel
			return m, tea.Batch(m.runSingleTest(ctx, m.currentRun, m.downloadCounter, m.startNano), m.tickProgress(done, m.downloadCounter, m.startNano))
		}

		// All runs complete
		if len(m.runResults) >= speedTestMinGood {
			var sum float64
			for _, r := range m.runResults {
				sum += r
			}
			m.avgMbps = sum / float64(len(m.runResults))
			m.state = SpeedTestComplete
		} else {
			m.state = SpeedTestError
			m.error = fmt.Sprintf("Too many failures (%d/%d runs failed)", m.failures, speedTestMaxRuns)
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

// progressReader wraps a reader to track bytes read
type progressReader struct {
	downloaded *atomic.Int64
	reader     interface{ Read([]byte) (int, error) }
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.downloaded.Add(int64(n))
	}
	return n, err
}

// runSingleTest issues one ~1MB download against speed.cloudflare.com,
// streaming bytes into dlCounter so tickProgress can render a live bar.
// The shared `done` atomic.Bool isn't passed in — Update flips it on the
// returned speedTestRunCompleteMsg (or on Esc/cancel), which is the
// authoritative completion signal. The caller's `tickProgress(done, …)`
// uses the same flag to stop ticking.
func (m Speedtest) runSingleTest(parent context.Context, runIndex int, dlCounter *atomic.Int64, startNano *atomic.Int64) tea.Cmd {
	return func() tea.Msg {
		testURL := "https://speed.cloudflare.com/__down?bytes=1000000"

		ctx, cancel := context.WithTimeout(parent, 15*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			return speedTestRunCompleteMsg{runIndex: runIndex, err: err}
		}

		// Private transport so the speedtest's 10 sequential 1MB downloads
		// don't leave 10 idle HTTP/2 connections sitting in the default
		// pool (each waits the default 90s idle timeout before GC).
		transport := &http.Transport{DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Timeout: 15 * time.Second, Transport: transport}

		dlCounter.Store(0)
		startNano.Store(time.Now().UnixNano())

		resp, err := client.Do(req)
		if err != nil {
			return speedTestRunCompleteMsg{runIndex: runIndex, err: err}
		}
		defer resp.Body.Close()

		const maxBytes = 2 * 1024 * 1024 // 2MB safety limit
		pr := &progressReader{
			downloaded: dlCounter,
			reader:     resp.Body,
		}

		buf := make([]byte, 32*1024)
		var total int64
		for {
			n, err := pr.Read(buf)
			total += int64(n)
			if total >= maxBytes {
				break
			}
			if err != nil {
				break
			}
		}

		elapsed := float64(time.Now().UnixNano()-startNano.Load()) / float64(time.Second)
		if elapsed < 0.001 {
			elapsed = 0.001
		}

		bytesPerSec := float64(total) / elapsed
		mbps := (bytesPerSec * 8) / 1_000_000

		return speedTestRunCompleteMsg{runIndex: runIndex, speedMbps: mbps}
	}
}

func (m Speedtest) tickProgress(done *atomic.Bool, dlCounter *atomic.Int64, startNano *atomic.Int64) tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(t time.Time) tea.Msg {
		if done.Load() {
			return nil
		}
		downloaded := dlCounter.Load()
		elapsed := float64(time.Now().UnixNano()-startNano.Load()) / float64(time.Second)
		var liveMbps float64
		if elapsed > 0.1 {
			liveMbps = (float64(downloaded) * 8) / (elapsed * 1_000_000)
		}
		return speedTestProgressMsg{
			downloaded: downloaded,
			liveMbps:   liveMbps,
		}
	})
}

func (m Speedtest) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("Speed Test") + "\n\n")

	if m.serverName != "" {
		b.WriteString(fmt.Sprintf("  Server: %s\n\n", m.serverName))
	}

	switch m.state {
	case SpeedTestIdle:
		b.WriteString("  Press Enter to start speed test\n\n")
		b.WriteString(MutedStyle.Render("  Runs 10 x 1MB downloads and averages the results") + "\n")

	case SpeedTestRunning:
		b.WriteString(fmt.Sprintf("  Run %d/%d", m.currentRun+1, speedTestMaxRuns))
		if m.failures > 0 {
			b.WriteString(fmt.Sprintf(" (%d failed)", m.failures))
		}
		b.WriteString("\n\n")

		// Progress bar showing completed runs (fills as each test finishes).
		// Uses background-painted cells (see dashboard.go buildBar comment for
		// rationale — block-element glyphs render as thin baselines at small
		// font sizes).
		pct := float64(m.currentRun) / float64(speedTestMaxRuns) * 100
		barWidth := 30
		filled := int(pct / 100 * float64(barWidth))
		fillStyle := lipgloss.NewStyle().Background(ColorAccent)
		emptyStyle := lipgloss.NewStyle().Background(ColorMuted)
		bar := fillStyle.Render(strings.Repeat(" ", filled)) + emptyStyle.Render(strings.Repeat(" ", barWidth-filled))
		b.WriteString(fmt.Sprintf("  [%s] %d/%d runs", bar, m.currentRun, speedTestMaxRuns))

		// Live speed for current run
		if m.liveMbps > 0 {
			b.WriteString(fmt.Sprintf("  (%.1f Mbps)", m.liveMbps))
		}
		b.WriteString("\n\n")

		// Show completed runs
		if len(m.runResults) > 0 {
			b.WriteString(MutedStyle.Render("  Completed runs:") + "\n")
			for i, r := range m.runResults {
				b.WriteString(MutedStyle.Render(fmt.Sprintf("    #%d: %.1f Mbps", i+1, r)) + "\n")
			}
		}

	case SpeedTestComplete:
		b.WriteString(SuccessStyle.Render(fmt.Sprintf("  Average Speed: %.2f Mbps", m.avgMbps)) + "\n\n")

		// Show individual runs
		b.WriteString(MutedStyle.Render(fmt.Sprintf("  Results (%d/%d successful):", len(m.runResults), speedTestMaxRuns)) + "\n")
		for i, r := range m.runResults {
			b.WriteString(MutedStyle.Render(fmt.Sprintf("    #%d: %.1f Mbps", i+1, r)) + "\n")
		}

		b.WriteString("\n  Press Enter to test again\n")

	case SpeedTestError:
		b.WriteString(ErrorStyle.Render("  Error: "+m.error) + "\n\n")
		if len(m.runResults) > 0 {
			var sum float64
			for _, r := range m.runResults {
				sum += r
			}
			partial := sum / float64(len(m.runResults))
			b.WriteString(MutedStyle.Render(fmt.Sprintf("  Partial average (%d runs): %.1f Mbps", len(m.runResults), partial)) + "\n")
		}
		b.WriteString("\n  Press Enter to try again\n")
	}

	b.WriteString("\n" + MutedStyle.Render("  esc: back"))

	return b.String()
}

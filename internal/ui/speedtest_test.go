package ui

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

func TestSpeedtestStateConstants(t *testing.T) {
	if SpeedTestIdle != 0 {
		t.Errorf("SpeedTestIdle = %d", SpeedTestIdle)
	}
	if SpeedTestRunning != 1 {
		t.Errorf("SpeedTestRunning = %d", SpeedTestRunning)
	}
	if SpeedTestComplete != 2 {
		t.Errorf("SpeedTestComplete = %d", SpeedTestComplete)
	}
	if SpeedTestError != 3 {
		t.Errorf("SpeedTestError = %d", SpeedTestError)
	}
}

func TestSpeedtestInit(t *testing.T) {
	st := Speedtest{cfg: &config.Config{}}
	if st.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestSpeedtestEsc(t *testing.T) {
	st := Speedtest{cfg: &config.Config{}}
	_, cmd := st.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestSpeedtestEnterStartsTest(t *testing.T) {
	st := Speedtest{cfg: &config.Config{}, state: SpeedTestIdle}
	model, cmd := st.Update(tea.KeyMsg{Type: tea.KeyEnter})
	st = model.(Speedtest)
	if st.state != SpeedTestRunning {
		t.Errorf("state = %d, want SpeedTestRunning", st.state)
	}
	if cmd == nil {
		t.Error("enter should return cmd")
	}
	if st.progressDone == nil {
		t.Error("progressDone should be initialized")
	}
	if st.downloadCounter == nil {
		t.Error("downloadCounter should be initialized")
	}
	if st.startNano == nil {
		t.Error("startNano should be initialized")
	}
}

func TestSpeedtestEnterFromComplete(t *testing.T) {
	st := Speedtest{cfg: &config.Config{}, state: SpeedTestComplete}
	model, cmd := st.Update(tea.KeyMsg{Type: tea.KeyEnter})
	st = model.(Speedtest)
	if st.state != SpeedTestRunning {
		t.Errorf("state = %d, want SpeedTestRunning", st.state)
	}
	if cmd == nil {
		t.Error("should restart test")
	}
}

// TestSpeedtestEnterCancelsPriorRunCancel verifies that pressing
// enter to start a new test cancels the previous run's context
// before assigning a new one. Pre-fix, m.runCancel was overwritten
// without calling the prior cancel, leaking one context per
// test-run cycle until program exit.
//
// Per Go context docs: "Failing to call the CancelFunc leaks the
// context's parent until the parent is canceled or the timer
// fires." Background contexts never fire a timer, so the leak
// would persist for the lifetime of the lazyvpn process.
func TestSpeedtestEnterCancelsPriorRunCancel(t *testing.T) {
	var cancelCount atomic.Int32
	priorCancel := func() {
		cancelCount.Add(1)
	}

	st := Speedtest{
		cfg:       &config.Config{},
		state:     SpeedTestComplete,
		runCancel: priorCancel,
	}
	model, _ := st.Update(tea.KeyMsg{Type: tea.KeyEnter})
	st = model.(Speedtest)

	if cancelCount.Load() != 1 {
		t.Errorf("prior runCancel call count = %d, want 1 (the cancel was overwritten without firing)", cancelCount.Load())
	}
	if st.runCancel == nil {
		t.Error("new runCancel should be set after starting fresh test")
	}
}

func TestSpeedtestEnterFromError(t *testing.T) {
	st := Speedtest{cfg: &config.Config{}, state: SpeedTestError}
	model, cmd := st.Update(tea.KeyMsg{Type: tea.KeyEnter})
	st = model.(Speedtest)
	if st.state != SpeedTestRunning {
		t.Errorf("state = %d, want SpeedTestRunning", st.state)
	}
	if cmd == nil {
		t.Error("should restart test")
	}
}

func TestSpeedtestEnterWhileRunningIgnored(t *testing.T) {
	st := Speedtest{cfg: &config.Config{}, state: SpeedTestRunning}
	model, cmd := st.Update(tea.KeyMsg{Type: tea.KeyEnter})
	st = model.(Speedtest)
	if st.state != SpeedTestRunning {
		t.Error("should stay running")
	}
	if cmd != nil {
		t.Error("should not return cmd while running")
	}
}

func TestSpeedtestSpaceStartsTest(t *testing.T) {
	st := Speedtest{cfg: &config.Config{}, state: SpeedTestIdle}
	model, cmd := st.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	st = model.(Speedtest)
	if st.state != SpeedTestRunning {
		t.Errorf("state = %d, want SpeedTestRunning", st.state)
	}
	if cmd == nil {
		t.Error("space should start test")
	}
}

func TestSpeedtestProgressMsg(t *testing.T) {
	done := &atomic.Bool{}
	st := Speedtest{
		cfg:             &config.Config{},
		state:           SpeedTestRunning,
		progressDone:    done,
		downloadCounter: &atomic.Int64{},
		startNano:       &atomic.Int64{},
	}

	model, cmd := st.Update(speedTestProgressMsg{downloaded: 500000, liveMbps: 42.5})
	st = model.(Speedtest)
	if st.downloaded != 500000 {
		t.Errorf("downloaded = %d, want 500000", st.downloaded)
	}
	if st.liveMbps != 42.5 {
		t.Errorf("liveMbps = %f, want 42.5", st.liveMbps)
	}
	if cmd == nil {
		t.Error("should return tick cmd while running")
	}
}

func TestSpeedtestProgressMsgDone(t *testing.T) {
	done := &atomic.Bool{}
	done.Store(true)
	st := Speedtest{
		cfg:             &config.Config{},
		state:           SpeedTestRunning,
		progressDone:    done,
		downloadCounter: &atomic.Int64{},
		startNano:       &atomic.Int64{},
	}

	_, cmd := st.Update(speedTestProgressMsg{downloaded: 1000000, liveMbps: 50.0})
	if cmd != nil {
		t.Error("should not tick when done")
	}
}

func TestSpeedtestRunCompleteMsg(t *testing.T) {
	st := Speedtest{
		cfg:          &config.Config{},
		state:        SpeedTestRunning,
		currentRun:   0,
		progressDone: &atomic.Bool{},
	}

	model, cmd := st.Update(speedTestRunCompleteMsg{runIndex: 0, speedMbps: 50.0})
	st = model.(Speedtest)
	if st.currentRun != 1 {
		t.Errorf("currentRun = %d, want 1", st.currentRun)
	}
	if len(st.runResults) != 1 || st.runResults[0] != 50.0 {
		t.Errorf("runResults = %v", st.runResults)
	}
	if st.speedMbps != 50.0 {
		t.Errorf("speedMbps = %f, want 50.0", st.speedMbps)
	}
	// Should start next run
	if cmd == nil {
		t.Error("should return cmd for next run")
	}
}

func TestSpeedtestRunCompleteMsgWithError(t *testing.T) {
	st := Speedtest{
		cfg:          &config.Config{},
		state:        SpeedTestRunning,
		currentRun:   0,
		progressDone: &atomic.Bool{},
	}

	model, _ := st.Update(speedTestRunCompleteMsg{runIndex: 0, err: errForTest("timeout")})
	st = model.(Speedtest)
	if st.failures != 1 {
		t.Errorf("failures = %d, want 1", st.failures)
	}
	if len(st.runResults) != 0 {
		t.Error("should not add to runResults on error")
	}
}

func TestSpeedtestAllRunsCompleteSuccess(t *testing.T) {
	st := Speedtest{
		cfg:          &config.Config{},
		state:        SpeedTestRunning,
		currentRun:   9,
		runResults:   []float64{40, 50, 60, 70, 80, 90, 100, 110, 120},
		progressDone: &atomic.Bool{},
	}

	model, _ := st.Update(speedTestRunCompleteMsg{runIndex: 9, speedMbps: 130.0})
	st = model.(Speedtest)
	if st.state != SpeedTestComplete {
		t.Errorf("state = %d, want SpeedTestComplete", st.state)
	}
	if st.avgMbps == 0 {
		t.Error("avgMbps should be calculated")
	}
}

func TestSpeedtestAllRunsCompleteTooManyFailures(t *testing.T) {
	st := Speedtest{
		cfg:          &config.Config{},
		state:        SpeedTestRunning,
		currentRun:   9,
		runResults:   []float64{40, 50},
		failures:     7,
		progressDone: &atomic.Bool{},
	}

	model, _ := st.Update(speedTestRunCompleteMsg{runIndex: 9, err: errForTest("fail")})
	st = model.(Speedtest)
	if st.state != SpeedTestError {
		t.Errorf("state = %d, want SpeedTestError", st.state)
	}
	if !strings.Contains(st.error, "Too many failures") {
		t.Errorf("error = %q", st.error)
	}
}

func TestSpeedtestWindowSize(t *testing.T) {
	st := Speedtest{cfg: &config.Config{}}
	model, _ := st.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	st = model.(Speedtest)
	if st.width != 100 || st.height != 30 {
		t.Errorf("size = %dx%d, want 100x30", st.width, st.height)
	}
}

func TestSpeedtestViewIdle(t *testing.T) {
	st := Speedtest{cfg: &config.Config{}, state: SpeedTestIdle}
	view := st.View()
	if !strings.Contains(view, "Speed Test") {
		t.Error("should contain title")
	}
	if !strings.Contains(view, "Press Enter") {
		t.Error("should show start prompt")
	}
}

func TestSpeedtestViewIdleWithServer(t *testing.T) {
	st := Speedtest{cfg: &config.Config{}, state: SpeedTestIdle, serverName: "US-NY#42"}
	view := st.View()
	if !strings.Contains(view, "US-NY#42") {
		t.Error("should show server name")
	}
}

func TestSpeedtestViewRunning(t *testing.T) {
	st := Speedtest{
		cfg:        &config.Config{},
		state:      SpeedTestRunning,
		currentRun: 3,
		downloaded: 500000,
		liveMbps:   42.5,
		runResults: []float64{40.0, 45.0, 50.0},
	}
	view := st.View()
	if !strings.Contains(view, "Run 4/10") {
		t.Error("should show current run")
	}
	if !strings.Contains(view, "42.5 Mbps") {
		t.Error("should show live speed")
	}
	if !strings.Contains(view, "Completed runs") {
		t.Error("should show completed runs")
	}
}

func TestSpeedtestViewRunningWithFailures(t *testing.T) {
	st := Speedtest{
		cfg:        &config.Config{},
		state:      SpeedTestRunning,
		currentRun: 3,
		failures:   1,
	}
	view := st.View()
	if !strings.Contains(view, "1 failed") {
		t.Error("should show failure count")
	}
}

func TestSpeedtestViewComplete(t *testing.T) {
	st := Speedtest{
		cfg:        &config.Config{},
		state:      SpeedTestComplete,
		avgMbps:    75.5,
		runResults: []float64{70.0, 75.0, 80.0, 77.0},
	}
	view := st.View()
	if !strings.Contains(view, "75.50 Mbps") {
		t.Error("should show average speed")
	}
	if !strings.Contains(view, "4/10 successful") {
		t.Error("should show success count")
	}
	if !strings.Contains(view, "Press Enter to test again") {
		t.Error("should show retry prompt")
	}
}

func TestSpeedtestViewError(t *testing.T) {
	st := Speedtest{
		cfg:   &config.Config{},
		state: SpeedTestError,
		error: "Too many failures (8/10 runs failed)",
	}
	view := st.View()
	if !strings.Contains(view, "Too many failures") {
		t.Error("should show error message")
	}
	if !strings.Contains(view, "Press Enter to try again") {
		t.Error("should show retry prompt")
	}
}

func TestSpeedtestViewErrorWithPartialResults(t *testing.T) {
	st := Speedtest{
		cfg:        &config.Config{},
		state:      SpeedTestError,
		error:      "Too many failures",
		runResults: []float64{40.0, 50.0},
	}
	view := st.View()
	if !strings.Contains(view, "Partial average") {
		t.Error("should show partial average when some runs succeeded")
	}
}

func TestNewSpeedtestDisconnected(t *testing.T) {
	cfg := &config.Config{
		ConnectionName:      "nonexistent-iface",
		LastConnectedServer: "US-NY#42",
	}
	st := NewSpeedtest(cfg)

	// wireguard.IsConnected returns false for nonexistent interface
	if st.serverName != "" {
		t.Errorf("serverName = %q, want empty (not connected)", st.serverName)
	}
	if st.state != SpeedTestIdle {
		t.Errorf("state = %d, want SpeedTestIdle", st.state)
	}
	if st.cfg != cfg {
		t.Error("cfg should be set")
	}
}

// TestNewSpeedtestConnected tests that NewSpeedtest picks up the server name
// when isWGConnected returns true.
func TestNewSpeedtestConnected(t *testing.T) {
	mockConnected(t)

	cfg := &config.Config{
		ConnectionName:      "wg0",
		LastConnectedServer: "US-NY#42",
	}
	st := NewSpeedtest(cfg)

	if st.serverName != "US-NY#42" {
		t.Errorf("serverName = %q, want US-NY#42", st.serverName)
	}
}

// TestNewSpeedtestConnectedDynamic tests that NewSpeedtest strips the dynamic prefix.
func TestNewSpeedtestConnectedDynamic(t *testing.T) {
	mockConnected(t)

	cfg := &config.Config{
		ConnectionName:      "wg0",
		LastConnectedServer: "dynamic:protonvpn:US-NY#42",
	}
	st := NewSpeedtest(cfg)

	if st.serverName != "US-NY#42" {
		t.Errorf("serverName = %q, want US-NY#42 (stripped dynamic prefix)", st.serverName)
	}
}

// TestNewSpeedtestConnectedNonDynamicPrefix tests a server name that starts
// with "dynamic:" but has only 2 parts (malformed).
func TestNewSpeedtestConnectedMalformedDynamic(t *testing.T) {
	mockConnected(t)

	cfg := &config.Config{
		ConnectionName:      "wg0",
		LastConnectedServer: "dynamic:only-two-parts",
	}
	st := NewSpeedtest(cfg)

	// Malformed dynamic prefix (only 2 parts, needs 3), so serverName stays as-is
	if st.serverName != "dynamic:only-two-parts" {
		t.Errorf("serverName = %q, want dynamic:only-two-parts", st.serverName)
	}
}

func TestSpeedtestViewRunningNoLiveMbps(t *testing.T) {
	st := Speedtest{
		cfg:        &config.Config{},
		state:      SpeedTestRunning,
		currentRun: 0,
		downloaded: 500000,
		liveMbps:   0, // No live speed yet
	}
	view := st.View()
	if !strings.Contains(view, "Run 1/10") {
		t.Error("should show run number")
	}
	// Should not contain Mbps when liveMbps is 0
	if strings.Contains(view, "Mbps)") {
		t.Error("should not show live speed when liveMbps is 0")
	}
}

func TestSpeedtestViewRunningNoRunResults(t *testing.T) {
	st := Speedtest{
		cfg:        &config.Config{},
		state:      SpeedTestRunning,
		currentRun: 0,
		downloaded: 100,
	}
	view := st.View()
	if strings.Contains(view, "Completed runs") {
		t.Error("should not show completed runs when none exist")
	}
}

func TestProgressReaderRead(t *testing.T) {
	data := []byte("hello world")
	pr := &progressReader{
		downloaded: &atomic.Int64{},
		reader:     strings.NewReader(string(data)),
	}

	buf := make([]byte, 5)
	n, err := pr.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
	if pr.downloaded.Load() != 5 {
		t.Errorf("downloaded = %d, want 5", pr.downloaded.Load())
	}

	n, err = pr.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
	if pr.downloaded.Load() != 10 {
		t.Errorf("downloaded = %d, want 10", pr.downloaded.Load())
	}
}

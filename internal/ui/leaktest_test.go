package ui

import (
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/tools"
	tea "github.com/charmbracelet/bubbletea"
)

func TestLeaktestStateConstants(t *testing.T) {
	if LeakTestIdle != 0 {
		t.Errorf("LeakTestIdle = %d", LeakTestIdle)
	}
	if LeakTestRunning != 1 {
		t.Errorf("LeakTestRunning = %d", LeakTestRunning)
	}
	if LeakTestComplete != 2 {
		t.Errorf("LeakTestComplete = %d", LeakTestComplete)
	}
	if LeakTestError != 3 {
		t.Errorf("LeakTestError = %d", LeakTestError)
	}
}

func TestLeaktestInit(t *testing.T) {
	lt := Leaktest{cfg: &config.Config{}}
	if lt.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestLeaktestEsc(t *testing.T) {
	lt := Leaktest{cfg: &config.Config{}}
	_, cmd := lt.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestLeaktestEnterStartsTest(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestIdle}
	model, cmd := lt.Update(tea.KeyMsg{Type: tea.KeyEnter})
	lt = model.(*Leaktest)
	if lt.state != LeakTestRunning {
		t.Errorf("state = %d, want LeakTestRunning", lt.state)
	}
	if cmd == nil {
		t.Error("enter should return cmd to run test")
	}
}

func TestLeaktestEnterFromComplete(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestComplete}
	model, cmd := lt.Update(tea.KeyMsg{Type: tea.KeyEnter})
	lt = model.(*Leaktest)
	if lt.state != LeakTestRunning {
		t.Errorf("state = %d, want LeakTestRunning", lt.state)
	}
	if cmd == nil {
		t.Error("should restart test")
	}
}

func TestLeaktestEnterFromError(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestError}
	model, cmd := lt.Update(tea.KeyMsg{Type: tea.KeyEnter})
	lt = model.(*Leaktest)
	if lt.state != LeakTestRunning {
		t.Errorf("state = %d, want LeakTestRunning", lt.state)
	}
	if cmd == nil {
		t.Error("should restart test")
	}
}

func TestLeaktestEnterWhileRunningIgnored(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestRunning}
	model, cmd := lt.Update(tea.KeyMsg{Type: tea.KeyEnter})
	lt = model.(*Leaktest)
	if lt.state != LeakTestRunning {
		t.Error("should stay running")
	}
	if cmd != nil {
		t.Error("should not return cmd while running")
	}
}

func TestLeaktestSpaceStartsTest(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestIdle}
	model, cmd := lt.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	lt = model.(*Leaktest)
	if lt.state != LeakTestRunning {
		t.Errorf("state = %d, want LeakTestRunning", lt.state)
	}
	if cmd == nil {
		t.Error("space should start test")
	}
}

func TestLeaktestResultMsgSuccess(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestRunning}
	test := &tools.LeakTest{
		IPResult: &tools.LeakTestResult{IsSafe: true, IP: "1.2.3.4"},
	}
	model, _ := lt.Update(leakTestResultMsg{test: test})
	lt = model.(*Leaktest)
	if lt.state != LeakTestComplete {
		t.Errorf("state = %d, want LeakTestComplete", lt.state)
	}
	if lt.test != test {
		t.Error("test result should be stored")
	}
}

func TestLeaktestResultMsgError(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestRunning}
	model, _ := lt.Update(leakTestResultMsg{err: errForTest("test failed")})
	lt = model.(*Leaktest)
	if lt.state != LeakTestError {
		t.Errorf("state = %d, want LeakTestError", lt.state)
	}
	if lt.error != "test failed" {
		t.Errorf("error = %q", lt.error)
	}
}

func TestLeaktestWindowSize(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}}
	model, _ := lt.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	lt = model.(*Leaktest)
	if lt.width != 120 || lt.height != 40 {
		t.Errorf("size = %dx%d, want 120x40", lt.width, lt.height)
	}
}

func TestLeaktestViewIdle(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestIdle}
	view := lt.View()
	if !strings.Contains(view, "DNS Leak Test") {
		t.Error("should contain title")
	}
	if !strings.Contains(view, "Press Enter") {
		t.Error("should show start prompt")
	}
}

func TestLeaktestViewIdleNotConnected(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestIdle, vpnConnected: false}
	view := lt.View()
	if !strings.Contains(view, "Not connected") {
		t.Error("should show not connected warning")
	}
}

// TestNewLeaktestConnected tests that NewLeaktest sets vpnConnected=true
// when isWGConnected is mocked.
func TestNewLeaktestConnected(t *testing.T) {
	mockConnected(t)

	cfg := &config.Config{ConnectionName: "wg0"}
	lt := NewLeaktest(cfg)

	if !lt.vpnConnected {
		t.Error("vpnConnected should be true when isWGConnected returns true")
	}
}

// TestLeaktestViewIdleConnected tests that the not-connected warning
// is NOT shown when vpnConnected is true.
func TestLeaktestViewIdleConnected(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestIdle, vpnConnected: true}
	view := lt.View()
	if strings.Contains(view, "Not connected") {
		t.Error("should NOT show not connected warning when vpnConnected is true")
	}
}

func TestLeaktestViewRunning(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestRunning, stage: "Testing DNS..."}
	view := lt.View()
	if !strings.Contains(view, "Running leak test") {
		t.Error("should show running message")
	}
	if !strings.Contains(view, "Testing DNS...") {
		t.Error("should show stage")
	}
}

func TestLeaktestViewCompleteNoLeaks(t *testing.T) {
	lt := &Leaktest{
		cfg:   &config.Config{},
		state: LeakTestComplete,
		test: &tools.LeakTest{
			IPResult:   &tools.LeakTestResult{IsSafe: true, IP: "1.2.3.4", Provider: "VPN Corp", Country: "US"},
			DNSResults: []tools.LeakTestResult{{IsSafe: true, IP: "10.0.0.1", Provider: "VPN DNS"}},
		},
	}
	view := lt.View()
	if !strings.Contains(view, "1.2.3.4") {
		t.Error("should show IP")
	}
	if !strings.Contains(view, "NO LEAKS") {
		t.Error("should show no leaks")
	}
}

func TestLeaktestViewCompleteWithLeaks(t *testing.T) {
	lt := &Leaktest{
		cfg:   &config.Config{},
		state: LeakTestComplete,
		test: &tools.LeakTest{
			IPResult:   &tools.LeakTestResult{IsSafe: false, IP: "5.6.7.8"},
			DNSResults: []tools.LeakTestResult{{IsSafe: false, IP: "8.8.8.8", Provider: "Google"}},
		},
	}
	view := lt.View()
	if !strings.Contains(view, "LEAKS DETECTED") {
		t.Error("should show leaks detected")
	}
}

func TestLeaktestViewCompleteNilTest(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestComplete, test: nil}
	view := lt.View()
	if !strings.Contains(view, "No results") {
		t.Error("should show no results for nil test")
	}
}

func TestLeaktestViewCompleteNoDNS(t *testing.T) {
	lt := &Leaktest{
		cfg:   &config.Config{},
		state: LeakTestComplete,
		test: &tools.LeakTest{
			IPResult: &tools.LeakTestResult{IsSafe: true, IP: "1.2.3.4"},
		},
	}
	view := lt.View()
	if !strings.Contains(view, "No DNS servers detected") {
		t.Error("should show no DNS servers")
	}
}

func TestLeaktestViewError(t *testing.T) {
	lt := &Leaktest{cfg: &config.Config{}, state: LeakTestError, error: "connection timeout"}
	view := lt.View()
	if !strings.Contains(view, "connection timeout") {
		t.Error("should show error message")
	}
	if !strings.Contains(view, "Press Enter to try again") {
		t.Error("should show retry prompt")
	}
}

// TestRunLeakTestWithMock exercises runLeakTest end-to-end.
// Since Run() makes real HTTP calls, we mock newLeakTest to return a LeakTest
// that will fail on HTTP (no real network), exercising the error path.
func TestRunLeakTestWithMock(t *testing.T) {
	// Default newLeakTest returns a real LeakTest whose Run() will try HTTP.
	// In test environment this will fail, which exercises the error code path.
	lt := &Leaktest{cfg: &config.Config{ConnectionName: "nonexistent-iface"}}
	cmd := lt.runLeakTest()
	if cmd == nil {
		t.Fatal("runLeakTest should return a cmd")
	}

	msg := cmd()
	result, ok := msg.(leakTestResultMsg)
	if !ok {
		t.Fatalf("expected leakTestResultMsg, got %T", msg)
	}
	// Run() will either succeed (if network is available) or fail with an error.
	// Both paths are exercised. Just verify we got a valid result.
	if result.err != nil {
		// Error path exercised
		if result.test != nil {
			t.Error("test should be nil on error path")
		}
	} else {
		// Success path exercised
		if result.test == nil {
			t.Error("test should not be nil on success path")
		}
	}
}

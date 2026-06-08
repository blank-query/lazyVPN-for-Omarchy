package ui

import (
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/tools"
	tea "github.com/charmbracelet/bubbletea"
)

func TestNewAuditView(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuditView(cfg)

	if len(a.results) != 6 {
		t.Errorf("expected 6 results, got %d", len(a.results))
	}
	if a.testing {
		t.Error("should not be testing initially")
	}
	if a.results[0].Name != "IPv4 Routing" {
		t.Errorf("first result name = %q", a.results[0].Name)
	}
	if a.results[5].Name != "MTU Analysis" {
		t.Errorf("last result name = %q", a.results[5].Name)
	}
	for _, r := range a.results {
		if r.Status != "PENDING" {
			t.Errorf("result %q status = %q, want PENDING", r.Name, r.Status)
		}
	}
}

func TestAuditViewInit(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuditView(cfg)
	if a.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestAuditViewEsc(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuditView(cfg)

	_, cmd := a.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestAuditViewWindowSize(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuditView(cfg)

	model, _ := a.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	av := model.(*AuditView)
	if av.width != 120 || av.height != 40 {
		t.Errorf("size = %dx%d, want 120x40", av.width, av.height)
	}
}

func TestAuditViewProgressMsg(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuditView(cfg)

	model, _ := a.Update(AuditProgressMsg{Stage: "Testing DNS..."})
	av := model.(*AuditView)
	if av.stage != "Testing DNS..." {
		t.Errorf("stage = %q", av.stage)
	}
}

func TestAuditViewCompleteNotConnected(t *testing.T) {
	cfg := &config.Config{ConnectionName: "wg0"}
	a := NewAuditView(cfg)
	a.testing = true

	model, _ := a.Update(AuditCompleteMsg{})
	av := model.(*AuditView)
	if av.testing {
		t.Error("should not be testing after complete")
	}
	if av.stage != "Complete" {
		t.Errorf("stage = %q, want Complete", av.stage)
	}
	// All results should be N/A (not connected)
	for _, r := range av.results {
		if r.Status != "N/A" {
			t.Errorf("result %q status = %q, want N/A", r.Name, r.Status)
		}
	}
}

func TestAuditViewCompleteWithResults(t *testing.T) {
	cfg := &config.Config{ConnectionName: "nonexistent-will-fail"}
	a := NewAuditView(cfg)
	a.testing = true

	lt := &tools.LeakTest{
		IPResult:     &tools.LeakTestResult{IsSafe: true, IP: "1.2.3.4"},
		IPv6Result:   &tools.IPv6LeakResult{IsSafe: true, Message: "Blocked"},
		DNSResults:   []tools.LeakTestResult{{IsSafe: true, Provider: "SecureDNS"}},
		WebRTCResult: &tools.WebRTCLeakResult{IsSafe: true, Message: "No leaks"},
	}
	mtu := &tools.MTUTestResult{CurrentMTU: 1420, OptimalMTU: 1420, NeedsFix: false}
	ks := &tools.KillswitchTestResult{IsSafe: true, Message: "All blocked"}

	model, _ := a.Update(AuditCompleteMsg{
		LeakTest:  lt,
		MTUResult: mtu,
		KSResult:  ks,
	})
	av := model.(*AuditView)

	// Since wireguard.IsConnected will return false for "nonexistent-will-fail",
	// updateResults sets all to N/A
	if av.results[0].Status != "N/A" {
		t.Errorf("IPv4 status = %q (not connected = N/A)", av.results[0].Status)
	}
}

func TestAuditViewViewPending(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuditView(cfg)
	a.width = 80
	a.height = 30

	view := a.View()
	if !strings.Contains(view, "SECURITY AUDIT") {
		t.Error("should contain title")
	}
	if !strings.Contains(view, "IPv4 Routing") {
		t.Error("should contain test names")
	}
	if !strings.Contains(view, "PENDING") {
		t.Error("should show PENDING status")
	}
}

func TestAuditViewViewTesting(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuditView(cfg)
	a.testing = true
	a.stage = "Running DNS checks..."

	view := a.View()
	if !strings.Contains(view, "Running DNS checks...") {
		t.Error("should show stage when testing")
	}
}

func TestAuditViewViewAllSafe(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuditView(cfg)
	for i := range a.results {
		a.results[i].Status = "SECURE"
		a.results[i].IsSafe = true
	}

	view := a.View()
	if !strings.Contains(view, "All security checks passed") {
		t.Error("should show all passed message")
	}
}

func TestAuditViewViewIssuesDetected(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuditView(cfg)
	a.results[0].Status = "EXPOSED"
	a.results[0].IsSafe = false
	for i := 1; i < len(a.results); i++ {
		a.results[i].Status = "SECURE"
		a.results[i].IsSafe = true
	}

	view := a.View()
	if !strings.Contains(view, "Security issues detected") {
		t.Error("should show issues detected message")
	}
}

func TestAuditResultStruct(t *testing.T) {
	r := AuditResult{
		Name:    "Test",
		Status:  "SECURE",
		Details: "All good",
		IsSafe:  true,
	}
	if r.Name != "Test" {
		t.Errorf("Name = %q", r.Name)
	}
	if !r.IsSafe {
		t.Error("should be safe")
	}
}

// TestAuditViewUpdateResultsNotConnected verifies updateResults sets all results
// to N/A when the VPN is not connected (wireguard.IsConnected returns false).
func TestAuditViewUpdateResultsNotConnected(t *testing.T) {
	cfg := &config.Config{ConnectionName: "nonexistent-iface"}
	a := NewAuditView(cfg)

	// Populate with test data that would normally produce results
	a.leakTest = &tools.LeakTest{
		IPResult:     &tools.LeakTestResult{IsSafe: true, IP: "10.0.0.1"},
		IPv6Result:   &tools.IPv6LeakResult{IsSafe: true, Message: "Blocked"},
		DNSResults:   []tools.LeakTestResult{{IsSafe: true, Provider: "SecureDNS"}},
		WebRTCResult: &tools.WebRTCLeakResult{IsSafe: true, Message: "No leaks"},
	}
	a.mtuResult = &tools.MTUTestResult{CurrentMTU: 1420, OptimalMTU: 1420, NeedsFix: false}
	a.ksResult = &tools.KillswitchTestResult{IsSafe: true, Message: "All blocked"}

	a.updateResults()

	// Since wireguard.IsConnected returns false, all results should be N/A
	for _, r := range a.results {
		if r.Status != "N/A" {
			t.Errorf("result %q status = %q, want N/A", r.Name, r.Status)
		}
		if r.Details != "Not connected" {
			t.Errorf("result %q details = %q, want 'Not connected'", r.Name, r.Details)
		}
		if r.IsSafe {
			t.Errorf("result %q should not be safe when disconnected", r.Name)
		}
	}
}

// TestAuditViewRunAuditReturnsCmd verifies that runAudit returns a command
// when the audit starts.
func TestAuditViewRunAuditReturnsCmd(t *testing.T) {
	cfg := &config.Config{ConnectionName: "nonexistent-iface"}
	a := NewAuditView(cfg)

	// Press enter/r to start audit
	model, cmd := a.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	av := model.(*AuditView)
	if !av.testing {
		t.Error("should be testing after pressing r")
	}
	if cmd == nil {
		t.Fatal("runAudit should return cmd")
	}

	// Execute the command - it will hit the !connected path and return immediately
	msg := cmd()
	complete, ok := msg.(AuditCompleteMsg)
	if !ok {
		t.Fatalf("expected AuditCompleteMsg, got %T", msg)
	}
	// Not connected, so all results should be nil
	if complete.LeakTest != nil {
		t.Error("LeakTest should be nil when not connected")
	}
	if complete.MTUResult != nil {
		t.Error("MTUResult should be nil when not connected")
	}
	if complete.KSResult != nil {
		t.Error("KSResult should be nil when not connected")
	}
}

// TestAuditViewRunAuditIgnoredWhileTesting verifies that pressing r while
// already testing does not start another audit.
func TestAuditViewRunAuditIgnoredWhileTesting(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuditView(cfg)
	a.testing = true

	_, cmd := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Error("should not start new audit while already testing")
	}
}

// TestAuditViewViewNA verifies View renders N/A status correctly
func TestAuditViewViewNA(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuditView(cfg)
	for i := range a.results {
		a.results[i].Status = "N/A"
		a.results[i].Details = "Not connected"
	}

	view := a.View()
	if !strings.Contains(view, "N/A") {
		t.Error("should show N/A status")
	}
	if !strings.Contains(view, "Checks not run") {
		t.Error("should show 'Checks not run' message when all N/A")
	}
}

// TestAuditViewViewAllNA_NoAllPassed verifies that "All security checks passed"
// does NOT appear when all results are N/A.
func TestAuditViewViewAllNA_NoAllPassed(t *testing.T) {
	cfg := &config.Config{}
	a := NewAuditView(cfg)
	for i := range a.results {
		a.results[i].Status = "N/A"
		a.results[i].Details = "Not connected"
	}

	view := a.View()
	if strings.Contains(view, "All security checks passed") {
		t.Error("should NOT show 'All security checks passed' when all N/A")
	}
}

// mockConnected temporarily sets isWGConnected to always return true,
// and restores it when the test finishes.
func mockConnected(t *testing.T) {
	t.Helper()
	orig := isWGConnected
	isWGConnected = func(string) bool { return true }
	t.Cleanup(func() { isWGConnected = orig })
}

// mockDisconnected temporarily sets isWGConnected to always return false,
// and restores it when the test finishes.
func mockDisconnected(t *testing.T) {
	t.Helper()
	orig := isWGConnected
	isWGConnected = func(string) bool { return false }
	t.Cleanup(func() { isWGConnected = orig })
}

// TestAuditViewUpdateResultsConnectedAllSafe verifies that updateResults
// correctly populates all 6 results when connected and all tests pass.
func TestAuditViewUpdateResultsConnectedAllSafe(t *testing.T) {
	mockConnected(t)

	cfg := &config.Config{ConnectionName: "wg0"}
	a := NewAuditView(cfg)
	a.leakTest = &tools.LeakTest{
		IPResult:     &tools.LeakTestResult{IsSafe: true, IP: "10.0.0.1", Provider: "VPN Corp"},
		IPv6Result:   &tools.IPv6LeakResult{IsSafe: true, Message: "IPv6 blocked"},
		DNSResults:   []tools.LeakTestResult{{IsSafe: true, IP: "10.0.0.53", Provider: "SecureDNS"}},
		WebRTCResult: &tools.WebRTCLeakResult{IsSafe: true, Message: "No WebRTC leaks"},
	}
	a.mtuResult = &tools.MTUTestResult{CurrentMTU: 1420, OptimalMTU: 1420, NeedsFix: false}
	a.ksResult = &tools.KillswitchTestResult{IsSafe: true, Message: "All non-VPN traffic blocked"}

	a.updateResults()

	// IPv4 Routing
	if a.results[0].Status != "SECURE" {
		t.Errorf("IPv4 status = %q, want SECURE", a.results[0].Status)
	}
	if a.results[0].Details != "10.0.0.1" {
		t.Errorf("IPv4 details = %q", a.results[0].Details)
	}
	if !a.results[0].IsSafe {
		t.Error("IPv4 should be safe")
	}

	// IPv6
	if a.results[1].Status != "BLOCKED" {
		t.Errorf("IPv6 status = %q, want BLOCKED", a.results[1].Status)
	}
	if !a.results[1].IsSafe {
		t.Error("IPv6 should be safe")
	}

	// DNS
	if a.results[2].Status != "ENCRYPTED" {
		t.Errorf("DNS status = %q, want ENCRYPTED", a.results[2].Status)
	}
	if !strings.Contains(a.results[2].Details, "SecureDNS") {
		t.Errorf("DNS details = %q, want SecureDNS", a.results[2].Details)
	}
	if !a.results[2].IsSafe {
		t.Error("DNS should be safe")
	}

	// WebRTC
	if a.results[3].Status != "LOCKED" {
		t.Errorf("WebRTC status = %q, want LOCKED", a.results[3].Status)
	}
	if !a.results[3].IsSafe {
		t.Error("WebRTC should be safe")
	}

	// Killswitch
	if a.results[4].Status != "PASSED" {
		t.Errorf("Killswitch status = %q, want PASSED", a.results[4].Status)
	}
	if !a.results[4].IsSafe {
		t.Error("Killswitch should be safe")
	}

	// MTU
	if a.results[5].Status != "OPTIMAL" {
		t.Errorf("MTU status = %q, want OPTIMAL", a.results[5].Status)
	}
	if !strings.Contains(a.results[5].Details, "1420") {
		t.Errorf("MTU details = %q", a.results[5].Details)
	}
	if !a.results[5].IsSafe {
		t.Error("MTU should be safe")
	}
}

// TestAuditViewUpdateResultsConnectedAllUnsafe verifies that updateResults
// correctly populates unsafe results when connected and all tests fail.
func TestAuditViewUpdateResultsConnectedAllUnsafe(t *testing.T) {
	mockConnected(t)

	cfg := &config.Config{ConnectionName: "wg0"}
	a := NewAuditView(cfg)
	a.leakTest = &tools.LeakTest{
		IPResult:     &tools.LeakTestResult{IsSafe: false, IP: "1.2.3.4", Provider: "ISP"},
		IPv6Result:   &tools.IPv6LeakResult{IsSafe: false, Message: "IPv6 exposed"},
		DNSResults:   []tools.LeakTestResult{{IsSafe: false, IP: "8.8.8.8", Provider: "Google"}},
		WebRTCResult: &tools.WebRTCLeakResult{IsSafe: false, Message: "WebRTC leaking"},
	}
	a.mtuResult = &tools.MTUTestResult{CurrentMTU: 1500, OptimalMTU: 1420, NeedsFix: true}
	a.ksResult = &tools.KillswitchTestResult{IsSafe: false, Message: "Traffic leaking"}

	a.updateResults()

	// IPv4 Routing
	if a.results[0].Status != "EXPOSED" {
		t.Errorf("IPv4 status = %q, want EXPOSED", a.results[0].Status)
	}
	if a.results[0].IsSafe {
		t.Error("IPv4 should not be safe")
	}

	// IPv6
	if a.results[1].Status != "LEAKING" {
		t.Errorf("IPv6 status = %q, want LEAKING", a.results[1].Status)
	}
	if a.results[1].IsSafe {
		t.Error("IPv6 should not be safe")
	}

	// DNS
	if a.results[2].Status != "LEAKING" {
		t.Errorf("DNS status = %q, want LEAKING", a.results[2].Status)
	}
	if a.results[2].IsSafe {
		t.Error("DNS should not be safe")
	}

	// WebRTC
	if a.results[3].Status != "EXPOSED" {
		t.Errorf("WebRTC status = %q, want EXPOSED", a.results[3].Status)
	}
	if a.results[3].IsSafe {
		t.Error("WebRTC should not be safe")
	}

	// Killswitch
	if a.results[4].Status != "FAILED" {
		t.Errorf("Killswitch status = %q, want FAILED", a.results[4].Status)
	}
	if a.results[4].IsSafe {
		t.Error("Killswitch should not be safe")
	}

	// MTU
	if a.results[5].Status != "MISMATCH" {
		t.Errorf("MTU status = %q, want MISMATCH", a.results[5].Status)
	}
	if !strings.Contains(a.results[5].Details, "1500") {
		t.Errorf("MTU details = %q, should contain current MTU", a.results[5].Details)
	}
	if !strings.Contains(a.results[5].Details, "1420") {
		t.Errorf("MTU details = %q, should contain optimal MTU", a.results[5].Details)
	}
	if a.results[5].IsSafe {
		t.Error("MTU should not be safe")
	}
}

// TestAuditViewUpdateResultsConnectedPartialResults tests when some test
// results are nil (e.g. only leak test data, no MTU/killswitch).
func TestAuditViewUpdateResultsConnectedPartialResults(t *testing.T) {
	mockConnected(t)

	cfg := &config.Config{ConnectionName: "wg0"}
	a := NewAuditView(cfg)
	a.leakTest = &tools.LeakTest{
		IPResult: &tools.LeakTestResult{IsSafe: true, IP: "10.0.0.1"},
	}
	// No IPv6, DNS, WebRTC, MTU, or KS results

	a.updateResults()

	// IPv4 should be updated
	if a.results[0].Status != "SECURE" {
		t.Errorf("IPv4 status = %q, want SECURE", a.results[0].Status)
	}
	// IPv6 should remain PENDING (nil IPv6Result)
	if a.results[1].Status != "PENDING" {
		t.Errorf("IPv6 status = %q, want PENDING", a.results[1].Status)
	}
	// DNS should remain PENDING (no DNS results)
	if a.results[2].Status != "PENDING" {
		t.Errorf("DNS status = %q, want PENDING", a.results[2].Status)
	}
	// WebRTC should remain PENDING (nil WebRTCResult)
	if a.results[3].Status != "PENDING" {
		t.Errorf("WebRTC status = %q, want PENDING", a.results[3].Status)
	}
	// Killswitch should remain PENDING (nil ksResult)
	if a.results[4].Status != "PENDING" {
		t.Errorf("Killswitch status = %q, want PENDING", a.results[4].Status)
	}
	// MTU should remain PENDING (nil mtuResult)
	if a.results[5].Status != "PENDING" {
		t.Errorf("MTU status = %q, want PENDING", a.results[5].Status)
	}
}

// TestAuditViewUpdateResultsDNSMultipleProviders tests DNS results with
// multiple providers, some safe and some not.
func TestAuditViewUpdateResultsDNSMultipleProviders(t *testing.T) {
	mockConnected(t)

	cfg := &config.Config{ConnectionName: "wg0"}
	a := NewAuditView(cfg)
	a.leakTest = &tools.LeakTest{
		DNSResults: []tools.LeakTestResult{
			{IsSafe: true, IP: "10.0.0.53", Provider: "VPN DNS"},
			{IsSafe: false, IP: "8.8.8.8", Provider: "Google"},
		},
	}

	a.updateResults()

	// One unsafe DNS result means overall is LEAKING
	if a.results[2].Status != "LEAKING" {
		t.Errorf("DNS status = %q, want LEAKING", a.results[2].Status)
	}
	if a.results[2].IsSafe {
		t.Error("DNS should not be safe with mixed results")
	}
	if !strings.Contains(a.results[2].Details, "VPN DNS") {
		t.Errorf("DNS details = %q, should contain VPN DNS", a.results[2].Details)
	}
	if !strings.Contains(a.results[2].Details, "Google") {
		t.Errorf("DNS details = %q, should contain Google", a.results[2].Details)
	}
}

// TestAuditViewRunAuditEnterKey tests that pressing Enter also starts audit.
func TestAuditViewRunAuditEnterKey(t *testing.T) {
	cfg := &config.Config{ConnectionName: "nonexistent-iface"}
	a := NewAuditView(cfg)

	model, cmd := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	av := model.(*AuditView)
	if !av.testing {
		t.Error("should be testing after pressing enter")
	}
	if cmd == nil {
		t.Fatal("enter should return cmd")
	}
}

// TestAuditViewCompleteWithResultsConnected tests the full flow of completing
// an audit when connected.
func TestAuditViewCompleteWithResultsConnected(t *testing.T) {
	mockConnected(t)

	cfg := &config.Config{ConnectionName: "wg0"}
	a := NewAuditView(cfg)
	a.testing = true

	lt := &tools.LeakTest{
		IPResult:     &tools.LeakTestResult{IsSafe: true, IP: "10.0.0.1"},
		IPv6Result:   &tools.IPv6LeakResult{IsSafe: true, Message: "Blocked"},
		DNSResults:   []tools.LeakTestResult{{IsSafe: true, Provider: "SecureDNS"}},
		WebRTCResult: &tools.WebRTCLeakResult{IsSafe: true, Message: "No leaks"},
	}
	mtu := &tools.MTUTestResult{CurrentMTU: 1420, OptimalMTU: 1420, NeedsFix: false}
	ks := &tools.KillswitchTestResult{IsSafe: true, Message: "All blocked"}

	model, _ := a.Update(AuditCompleteMsg{LeakTest: lt, MTUResult: mtu, KSResult: ks})
	av := model.(*AuditView)

	if av.testing {
		t.Error("should not be testing after complete")
	}
	if av.results[0].Status != "SECURE" {
		t.Errorf("IPv4 status = %q, want SECURE", av.results[0].Status)
	}
	if av.results[5].Status != "OPTIMAL" {
		t.Errorf("MTU status = %q, want OPTIMAL", av.results[5].Status)
	}
}

// mockNewLeakTestAudit temporarily replaces newLeakTest for audit tests.
func mockNewLeakTestAudit(t *testing.T, fn func([]string, string, string, []string) *tools.LeakTest) {
	t.Helper()
	orig := newLeakTest
	newLeakTest = fn
	t.Cleanup(func() { newLeakTest = orig })
}

// mockTestMTU temporarily replaces testMTU.
func mockTestMTU(t *testing.T, fn func(string) *tools.MTUTestResult) {
	t.Helper()
	orig := testMTU
	testMTU = fn
	t.Cleanup(func() { testMTU = orig })
}

// mockTestKillswitch temporarily replaces testKillswitch.
func mockTestKillswitch(t *testing.T, fn func(string) *tools.KillswitchTestResult) {
	t.Helper()
	orig := testKillswitch
	testKillswitch = fn
	t.Cleanup(func() { testKillswitch = orig })
}

// mockIsFirewallActive temporarily replaces isFirewallActive.
func mockIsFirewallActive(t *testing.T, active bool) {
	t.Helper()
	orig := isFirewallActive
	isFirewallActive = func() bool { return active }
	t.Cleanup(func() { isFirewallActive = orig })
}

// TestRunAuditConnectedAllSafe exercises the runAudit command when
// connected and all tests pass (firewall active).
func TestRunAuditConnectedAllSafe(t *testing.T) {
	mockConnected(t)
	mockIsFirewallActive(t, true)
	mockNewLeakTestAudit(t, func(providers []string, baselineIP, baselineOrg string, baselineDNS []string) *tools.LeakTest {
		return &tools.LeakTest{
			IPResult:     &tools.LeakTestResult{IsSafe: true, IP: "10.0.0.1"},
			IPv6Result:   &tools.IPv6LeakResult{IsSafe: true, Message: "Blocked"},
			DNSResults:   []tools.LeakTestResult{{IsSafe: true, Provider: "SecureDNS"}},
			WebRTCResult: &tools.WebRTCLeakResult{IsSafe: true, Message: "No leaks"},
		}
	})
	mockTestMTU(t, func(connName string) *tools.MTUTestResult {
		return &tools.MTUTestResult{CurrentMTU: 1420, OptimalMTU: 1420, NeedsFix: false}
	})
	mockTestKillswitch(t, func(connName string) *tools.KillswitchTestResult {
		return &tools.KillswitchTestResult{IsSafe: true, Message: "All blocked"}
	})

	cfg := &config.Config{ConnectionName: "wg0"}
	a := NewAuditView(cfg)

	model, cmd := a.Update(tea.KeyMsg{Type: tea.KeyEnter})
	av := model.(*AuditView)
	if !av.testing {
		t.Error("should be testing")
	}
	if cmd == nil {
		t.Fatal("should return cmd")
	}

	// Execute the audit
	msg := cmd()
	complete, ok := msg.(AuditCompleteMsg)
	if !ok {
		t.Fatalf("expected AuditCompleteMsg, got %T", msg)
	}
	if complete.LeakTest == nil {
		t.Error("LeakTest should not be nil")
	}
	if complete.MTUResult == nil {
		t.Error("MTUResult should not be nil")
	}
	if complete.KSResult == nil {
		t.Error("KSResult should not be nil")
	}
	if !complete.KSResult.IsSafe {
		t.Error("KS result should be safe")
	}
}

// TestRunAuditConnectedFirewallInactive exercises runAudit when firewall
// is not active (killswitch test is skipped).
func TestRunAuditConnectedFirewallInactive(t *testing.T) {
	mockConnected(t)
	mockIsFirewallActive(t, false)
	mockNewLeakTestAudit(t, func(providers []string, baselineIP, baselineOrg string, baselineDNS []string) *tools.LeakTest {
		return &tools.LeakTest{
			IPResult: &tools.LeakTestResult{IsSafe: true, IP: "10.0.0.1"},
		}
	})
	mockTestMTU(t, func(connName string) *tools.MTUTestResult {
		return &tools.MTUTestResult{CurrentMTU: 1420, OptimalMTU: 1420, NeedsFix: false}
	})

	cfg := &config.Config{ConnectionName: "wg0"}
	a := NewAuditView(cfg)
	cmd := a.runAudit()
	msg := cmd()

	complete, ok := msg.(AuditCompleteMsg)
	if !ok {
		t.Fatalf("expected AuditCompleteMsg, got %T", msg)
	}
	if complete.KSResult == nil {
		t.Fatal("KSResult should not be nil (should be skip message)")
	}
	if complete.KSResult.IsSafe {
		t.Error("KS should not be marked safe when not enabled")
	}
	if !strings.Contains(complete.KSResult.Message, "not enabled") {
		t.Errorf("KS message = %q, want contains 'not enabled'", complete.KSResult.Message)
	}
}

// TestAuditViewCompleteWithNilResults verifies handling of AuditCompleteMsg
// with all nil results (disconnected path).
func TestAuditViewCompleteWithNilResults(t *testing.T) {
	cfg := &config.Config{ConnectionName: "nonexistent"}
	a := NewAuditView(cfg)
	a.testing = true

	model, _ := a.Update(AuditCompleteMsg{
		LeakTest:  nil,
		MTUResult: nil,
		KSResult:  nil,
	})
	av := model.(*AuditView)

	if av.testing {
		t.Error("should not be testing after complete")
	}
	// All should be N/A (not connected)
	for _, r := range av.results {
		if r.Status != "N/A" {
			t.Errorf("result %q = %q, want N/A", r.Name, r.Status)
		}
	}
}

package ui

import (
	"fmt"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/tools"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// AuditResult represents a single audit test result
type AuditResult struct {
	Name    string
	Status  string // "SECURE", "BLOCKED", "PASSED", "FAILED", "TESTING", "PENDING"
	Details string
	IsSafe  bool
}

// AuditView displays the Ironclad security audit dashboard
type AuditView struct {
	cfg       *config.Config
	results   []AuditResult
	leakTest  *tools.LeakTest
	mtuResult *tools.MTUTestResult
	ksResult  *tools.KillswitchTestResult
	testing   bool
	stage     string
	width     int
	height    int
	spinner   Spinner
}

// NewAuditView creates a new security audit view
func NewAuditView(cfg *config.Config) *AuditView {
	return &AuditView{
		cfg: cfg,
		results: []AuditResult{
			{Name: "IPv4 Routing", Status: "PENDING", Details: "Not tested"},
			{Name: "IPv6 Leak", Status: "PENDING", Details: "Not tested"},
			{Name: "DNS Encryption", Status: "PENDING", Details: "Not tested"},
			{Name: "WebRTC Isolation", Status: "PENDING", Details: "Not tested"},
			{Name: "Killswitch Test", Status: "PENDING", Details: "Not tested"},
			{Name: "MTU Analysis", Status: "PENDING", Details: "Not tested"},
		},
	}
}

// AuditProgressMsg signals audit progress
type AuditProgressMsg struct {
	Stage string
}

// AuditCompleteMsg signals audit completion with results
type AuditCompleteMsg struct {
	LeakTest  *tools.LeakTest
	MTUResult *tools.MTUTestResult
	KSResult  *tools.KillswitchTestResult
}

func (a *AuditView) Init() tea.Cmd {
	return nil
}

func (a *AuditView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return a, func() tea.Msg { return BackMsg{} }
		case "r", "enter":
			if !a.testing {
				return a, a.runAudit()
			}
		}
	case AuditProgressMsg:
		a.stage = msg.Stage
		a.spinner.Tick()
		return a, nil
	case AuditCompleteMsg:
		a.testing = false
		a.stage = "Complete"
		a.leakTest = msg.LeakTest
		a.mtuResult = msg.MTUResult
		a.ksResult = msg.KSResult
		a.updateResults()
		return a, nil
	case StatusUpdateMsg:
		if a.testing {
			a.spinner.Tick()
		}
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
	}
	return a, nil
}

func (a *AuditView) runAudit() tea.Cmd {
	a.testing = true
	a.stage = "Starting security audit..."

	connName := a.cfg.ConnectionName

	return func() tea.Msg {
		// Check if connected
		if !isWGConnected(connName) {
			return AuditCompleteMsg{}
		}

		// Run leak tests
		providers := a.cfg.DNSProviders
		if len(providers) == 0 {
			providers = tools.DefaultDNSProviders
		}
		lt := newLeakTest(providers, a.cfg.BaselineIP, a.cfg.BaselineOrg, a.cfg.BaselineDNS)
		lt.VPNInterface = connName
		lt.KillswitchActive = isFirewallActive()
		lt.Run()

		// Run MTU test
		mtu := testMTU(connName)

		// Run killswitch test only if killswitch is active
		var ks *tools.KillswitchTestResult
		if isFirewallActive() {
			ks = testKillswitch(connName)
		} else {
			ks = &tools.KillswitchTestResult{
				IsSafe:  false,
				Message: "Killswitch not enabled",
			}
		}

		return AuditCompleteMsg{
			LeakTest:  lt,
			MTUResult: mtu,
			KSResult:  ks,
		}
	}
}

func (a *AuditView) updateResults() {
	connName := a.cfg.ConnectionName
	connected := isWGConnected(connName)

	if !connected {
		for i := range a.results {
			a.results[i].Status = "N/A"
			a.results[i].Details = "Not connected"
			a.results[i].IsSafe = false
		}
		return
	}

	// Update IPv4 Routing result
	if a.leakTest != nil && a.leakTest.IPResult != nil {
		if a.leakTest.IPResult.IsError {
			a.results[0].Status = "ERROR"
			a.results[0].Details = a.leakTest.IPResult.Provider
			a.results[0].IsSafe = false
		} else if a.leakTest.IPResult.IsSafe {
			a.results[0].Status = "SECURE"
			a.results[0].Details = a.leakTest.IPResult.IP
			a.results[0].IsSafe = true
		} else {
			a.results[0].Status = "EXPOSED"
			a.results[0].Details = a.leakTest.IPResult.IP
			a.results[0].IsSafe = false
		}
	}

	// Update IPv6 Leak result
	if a.leakTest != nil && a.leakTest.IPv6Result != nil {
		if a.leakTest.IPv6Result.IsSafe {
			a.results[1].Status = "BLOCKED"
			a.results[1].Details = a.leakTest.IPv6Result.Message
			a.results[1].IsSafe = true
		} else {
			a.results[1].Status = "LEAKING"
			a.results[1].Details = a.leakTest.IPv6Result.Message
			a.results[1].IsSafe = false
		}
	}

	// Update DNS result
	if a.leakTest != nil && len(a.leakTest.DNSResults) > 0 {
		allSafe := true
		allError := true
		var providers []string
		for _, dns := range a.leakTest.DNSResults {
			if !dns.IsSafe {
				allSafe = false
			}
			if !dns.IsError {
				allError = false
			}
			if dns.Provider != "" {
				providers = append(providers, dns.Provider)
			}
		}
		if allError {
			a.results[2].Status = "ERROR"
			a.results[2].Details = "Could not test"
			a.results[2].IsSafe = false
		} else if allSafe {
			a.results[2].Status = "ENCRYPTED"
			a.results[2].Details = strings.Join(providers, ", ")
			a.results[2].IsSafe = true
		} else {
			a.results[2].Status = "LEAKING"
			a.results[2].Details = strings.Join(providers, ", ")
			a.results[2].IsSafe = false
		}
	}

	// Update WebRTC result
	if a.leakTest != nil && a.leakTest.WebRTCResult != nil {
		if a.leakTest.WebRTCResult.IsSafe {
			a.results[3].Status = "LOCKED"
			a.results[3].Details = a.leakTest.WebRTCResult.Message
			a.results[3].IsSafe = true
		} else {
			a.results[3].Status = "EXPOSED"
			a.results[3].Details = a.leakTest.WebRTCResult.Message
			a.results[3].IsSafe = false
		}
	}

	// Update Killswitch result
	if a.ksResult != nil {
		if a.ksResult.IsSafe {
			a.results[4].Status = "PASSED"
			a.results[4].Details = a.ksResult.Message
			a.results[4].IsSafe = true
		} else if a.ksResult.Message == "Killswitch not enabled" {
			a.results[4].Status = "INACTIVE"
			a.results[4].Details = a.ksResult.Message
			a.results[4].IsSafe = false
		} else {
			a.results[4].Status = "FAILED"
			a.results[4].Details = a.ksResult.Message
			a.results[4].IsSafe = false
		}
	}

	// Update MTU result
	if a.mtuResult != nil {
		if !a.mtuResult.NeedsFix {
			a.results[5].Status = "OPTIMAL"
			a.results[5].Details = fmt.Sprintf("MTU: %d", a.mtuResult.CurrentMTU)
			a.results[5].IsSafe = true
		} else {
			a.results[5].Status = "MISMATCH"
			a.results[5].Details = fmt.Sprintf("Current: %d, Optimal: %d", a.mtuResult.CurrentMTU, a.mtuResult.OptimalMTU)
			a.results[5].IsSafe = false
		}
	}
}

func (a *AuditView) View() string {
	var b strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorAccent).
		Border(lipgloss.DoubleBorder()).
		BorderForeground(ColorAccent).
		Padding(0, 2).
		Align(lipgloss.Center)

	b.WriteString(titleStyle.Render("SECURITY AUDIT") + "\n\n")

	// Status indicator
	if a.testing {
		b.WriteString(MutedStyle.Render(fmt.Sprintf("  %s Testing: %s\n\n", a.spinner.View(), a.stage)))
	}

	// Results table — use fixed-width lipgloss columns to avoid ANSI alignment bugs
	nameColW := 20
	statusColW := 12

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorFg)
	nameHdr := lipgloss.NewStyle().Width(nameColW).Render("Test")
	statusHdr := lipgloss.NewStyle().Width(statusColW).Render("Result")
	b.WriteString("  " + headerStyle.Render(nameHdr+statusHdr+"Details") + "\n")
	b.WriteString(MutedStyle.Render("  "+strings.Repeat("─", 60)) + "\n")

	for _, result := range a.results {
		// Color status based on safety
		var statusStyle lipgloss.Style
		switch result.Status {
		case "SECURE", "BLOCKED", "PASSED", "ENCRYPTED", "LOCKED", "OPTIMAL", "FIXED":
			statusStyle = SuccessStyle
		case "EXPOSED", "LEAKING", "FAILED", "MISMATCH", "FIX FAILED":
			statusStyle = ErrorStyle
		case "TESTING", "INACTIVE", "ERROR":
			statusStyle = lipgloss.NewStyle().Foreground(ColorWarning)
		default:
			statusStyle = MutedStyle
		}

		nameCol := lipgloss.NewStyle().Width(nameColW).Render(result.Name)
		statusCol := statusStyle.Width(statusColW).Render(result.Status)
		detailCol := MutedStyle.Render(Truncate(result.Details, 30))

		b.WriteString("  " + nameCol + statusCol + detailCol + "\n")
	}

	// Summary
	b.WriteString("\n")
	if !a.testing {
		allNA := true
		for _, r := range a.results {
			if r.Status != "N/A" {
				allNA = false
				break
			}
		}
		if allNA {
			b.WriteString(MutedStyle.Render("  Checks not run — connect to VPN first") + "\n")
		} else if a.results[0].Status != "PENDING" {
			hasErrors := false
			hasFailures := false
			for _, r := range a.results {
				if r.Status == "ERROR" {
					hasErrors = true
				}
				if !r.IsSafe && r.Status != "PENDING" && r.Status != "N/A" && r.Status != "INACTIVE" && r.Status != "ERROR" {
					hasFailures = true
				}
			}
			if hasFailures {
				b.WriteString(ErrorStyle.Render("  ⚠ Security issues detected") + "\n")
			} else if hasErrors {
				b.WriteString(lipgloss.NewStyle().Foreground(ColorWarning).Render("  ⚠ Some tests could not complete") + "\n")
			} else {
				b.WriteString(SuccessStyle.Render("  ✓ All security checks passed") + "\n")
			}
		}
	}

	// Help
	b.WriteString("\n" + MutedStyle.Render("  enter/r: run audit  esc: back"))

	return b.String()
}

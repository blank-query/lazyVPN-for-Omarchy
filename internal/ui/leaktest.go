package ui

import (
	"fmt"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/tools"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type LeakTestState int

const (
	LeakTestIdle LeakTestState = iota
	LeakTestRunning
	LeakTestComplete
	LeakTestError
)

type Leaktest struct {
	cfg          *config.Config
	state        LeakTestState
	test         *tools.LeakTest
	stage        string
	error        string
	width        int
	height       int
	vpnConnected bool
}

func NewLeaktest(cfg *config.Config) *Leaktest {
	return &Leaktest{
		cfg:          cfg,
		state:        LeakTestIdle,
		vpnConnected: isWGConnected(cfg.ConnectionName),
	}
}

func (m *Leaktest) Init() tea.Cmd {
	return nil
}

type leakTestResultMsg struct {
	test *tools.LeakTest
	err  error
}

func (m *Leaktest) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, func() tea.Msg { return BackMsg{} }
		case "enter", " ":
			if m.state == LeakTestIdle || m.state == LeakTestComplete || m.state == LeakTestError {
				m.state = LeakTestRunning
				m.stage = "Starting leak test..."
				return m, m.runLeakTest()
			}
		}

	case leakTestResultMsg:
		if msg.err != nil {
			m.state = LeakTestError
			m.error = msg.err.Error()
		} else {
			m.state = LeakTestComplete
			m.test = msg.test
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m *Leaktest) runLeakTest() tea.Cmd {
	return func() tea.Msg {
		providers := m.cfg.DNSProviders
		if len(providers) == 0 {
			providers = tools.DefaultDNSProviders
		}
		test := newLeakTest(providers, m.cfg.BaselineIP, m.cfg.BaselineOrg, m.cfg.BaselineDNS)
		test.VPNInterface = m.cfg.ConnectionName
		test.KillswitchActive = isFirewallActive()
		test.Run()

		if test.Error != nil {
			return leakTestResultMsg{err: test.Error}
		}
		return leakTestResultMsg{test: test}
	}
}

func (m *Leaktest) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("DNS Leak Test") + "\n\n")

	switch m.state {
	case LeakTestIdle:
		b.WriteString("  Press Enter to start leak test\n\n")
		b.WriteString(MutedStyle.Render("  Tests for IP and DNS leaks") + "\n")
		b.WriteString(MutedStyle.Render("  Checks if traffic is properly routed through VPN") + "\n")
		if !m.vpnConnected {
			b.WriteString("\n" + WarningStyle.Render("  Note: Not connected to VPN. Results will show your real IP/DNS.") + "\n")
		}
		if m.cfg.BaselineIP == "" {
			b.WriteString("\n" + MutedStyle.Render("  ISP baseline not captured. Connect to VPN to capture it.") + "\n")
		}

	case LeakTestRunning:
		b.WriteString("  Running leak test...\n\n")
		if m.stage != "" {
			b.WriteString(MutedStyle.Render("  "+m.stage) + "\n")
		}

	case LeakTestComplete:
		if m.test == nil {
			b.WriteString(ErrorStyle.Render("  No results") + "\n")
		} else {
			ipColW := 20
			statusColW := 12

			// IP Result
			b.WriteString(SubtitleStyle.Render("─── Public IP ───") + "\n\n")
			if m.test.IPResult != nil {
				ip := m.test.IPResult
				var statusStyle lipgloss.Style
				var statusText string
				if ip.IsError {
					statusStyle = lipgloss.NewStyle().Foreground(ColorWarning)
					statusText = "ERROR"
				} else if ip.IsSafe {
					statusStyle = SuccessStyle
					statusText = "SAFE ✓"
				} else {
					statusStyle = ErrorStyle
					statusText = "LEAK ✗"
				}
				ipCol := lipgloss.NewStyle().Width(ipColW).Render(ip.IP)
				stCol := statusStyle
				statusCol := stCol.Width(statusColW).Render(statusText)
				providerCol := MutedStyle.Render(ip.Provider)
				b.WriteString("  " + ipCol + statusCol + providerCol + "\n")
				if ip.Country != "" {
					b.WriteString(MutedStyle.Render(fmt.Sprintf("  Country: %s", ip.Country)) + "\n")
				}
			}

			// DNS Results
			b.WriteString("\n" + SubtitleStyle.Render("─── DNS Servers ───") + "\n\n")
			if len(m.test.DNSResults) == 0 {
				b.WriteString(MutedStyle.Render("  No DNS servers detected") + "\n")
			} else {
				for _, dns := range m.test.DNSResults {
					var statusStyle lipgloss.Style
					var statusText string
					if dns.IsError {
						statusStyle = lipgloss.NewStyle().Foreground(ColorWarning)
						statusText = "ERROR"
					} else if dns.IsSafe {
						statusStyle = SuccessStyle
						statusText = "SAFE ✓"
					} else {
						statusStyle = ErrorStyle
						statusText = "LEAK ✗"
					}
					ipCol := lipgloss.NewStyle().Width(ipColW).Render(dns.IP)
					stCol := statusStyle
					statusCol := stCol.Width(statusColW).Render(statusText)
					providerCol := MutedStyle.Render(dns.Provider)
					b.WriteString("  " + ipCol + statusCol + providerCol + "\n")
				}
			}

			// WebRTC Result
			if m.test.WebRTCResult != nil {
				b.WriteString("\n" + SubtitleStyle.Render("─── WebRTC / Interface Isolation ───") + "\n\n")
				if m.test.WebRTCResult.IsSafe {
					b.WriteString("  " + SuccessStyle.Render("SAFE ✓") + "  " + MutedStyle.Render(m.test.WebRTCResult.Message) + "\n")
				} else {
					b.WriteString("  " + ErrorStyle.Render("LEAK ✗") + "  " + m.test.WebRTCResult.Message + "\n")
				}
			}

			// IPv6 Result
			if m.test.IPv6Result != nil {
				b.WriteString("\n" + SubtitleStyle.Render("─── IPv6 ───") + "\n\n")
				if m.test.IPv6Result.IsSafe {
					b.WriteString("  " + SuccessStyle.Render("SAFE ✓") + "  " + MutedStyle.Render(m.test.IPv6Result.Message) + "\n")
				} else {
					b.WriteString("  " + ErrorStyle.Render("LEAK ✗") + "  " + m.test.IPv6Result.Message + "\n")
				}
			}

			// Summary
			b.WriteString("\n" + SubtitleStyle.Render("─── Conclusion ───") + "\n\n")
			hasErrors := false
			hasLeaks := m.test.HasLeaks()
			if m.test.IPResult != nil && m.test.IPResult.IsError {
				hasErrors = true
			}
			for _, dns := range m.test.DNSResults {
				if dns.IsError {
					hasErrors = true
				}
			}
			if hasLeaks {
				b.WriteString(ErrorStyle.Render("  ⚠ LEAKS DETECTED") + "\n")
				b.WriteString(MutedStyle.Render("  Your real IP or DNS may be exposed") + "\n")
			} else if hasErrors {
				b.WriteString(lipgloss.NewStyle().Foreground(ColorWarning).Render("  ⚠ Some tests could not complete") + "\n")
				b.WriteString(MutedStyle.Render("  Rerun to retry failed checks") + "\n")
			} else {
				b.WriteString(SuccessStyle.Render("  ✓ NO LEAKS DETECTED") + "\n")
				b.WriteString(MutedStyle.Render("  Traffic is properly routed through VPN") + "\n")
			}
		}

		b.WriteString("\n  Press Enter to test again\n")

	case LeakTestError:
		b.WriteString(ErrorStyle.Render("  Error: "+m.error) + "\n\n")
		b.WriteString("  Press Enter to try again\n")
	}

	b.WriteString("\n" + MutedStyle.Render("  esc: back"))

	return b.String()
}

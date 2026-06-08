package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func formatUptime(d time.Duration) string {
	// Clock skew (NTP step, manual `date` change, DST transition) can
	// make time.Since(ConnectedSince) return a negative duration. Without
	// this clamp the dashboard would show "-1h -34m -56s" because Go's
	// integer modulo preserves the sign of the dividend. Treat negative
	// elapsed time as zero — the connection didn't time-travel, the wall
	// clock did.
	if d < 0 {
		d = 0
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// StatusFooter displays persistent connection status.
// Minimal: status label + server name + killswitch icon.
// Bandwidth display lives exclusively on the Dashboard.
type StatusFooter struct {
	cfg        *config.Config
	connected  bool
	prettyName string
	killswitch bool
	width      int

	OverlayText    string // when set, replaces normal footer content
	OverlayIsError bool   // when true, overlay text is styled as an error
}

// NewStatusFooter creates a new status footer
func NewStatusFooter(cfg *config.Config) *StatusFooter {
	return &StatusFooter{cfg: cfg}
}

func (f *StatusFooter) Init() tea.Cmd {
	// Start periodic status updates. The first refresh is dispatched
	// immediately rather than after the 1s tick so the footer doesn't
	// briefly render with stale-default state on startup. Snapshot cfg
	// fields synchronously so refreshAsync doesn't race the dashboard.
	connName := f.cfg.ConnectionName
	serverRaw := f.cfg.LastConnectedServer
	featuresRaw := f.cfg.LastServerFeatures
	return tea.Batch(f.refreshAsync(connName, serverRaw, featuresRaw), f.scheduleTick())
}

// scheduleTick re-arms the 1s tick that drives StatusUpdateMsg.
func (f *StatusFooter) scheduleTick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return StatusUpdateMsg{}
	})
}

// statusFooterRefreshMsg carries the snapshot read by refreshAsync.
// Decoupling read (background goroutine) from apply (UI goroutine)
// keeps Update from blocking on cfg.Reload + sudo ufw + netlink for
// up to ~50ms every second.
type statusFooterRefreshMsg struct {
	connected   bool
	prettyName  string
	killswitch  bool
}

func (f *StatusFooter) Update(msg tea.Msg) (*StatusFooter, tea.Cmd) {
	switch msg := msg.(type) {
	case StatusUpdateMsg:
		// Snapshot cfg fields HERE on the UI goroutine — racing them
		// against the dashboard's parallel refresh on a different
		// goroutine corrupts shared *config.Config state.
		// The slow I/O (cfg.Reload disk read, isWGConnected netlink,
		// isFirewallActive sudo) goes into the background goroutine;
		// only the field-snapshot crosses the boundary.
		f.cfg.Reload()
		connName := f.cfg.ConnectionName
		serverRaw := f.cfg.LastConnectedServer
		featuresRaw := f.cfg.LastServerFeatures
		return f, tea.Batch(f.refreshAsync(connName, serverRaw, featuresRaw), f.scheduleTick())

	case statusFooterRefreshMsg:
		f.connected = msg.connected
		f.prettyName = msg.prettyName
		f.killswitch = msg.killswitch

	case tea.WindowSizeMsg:
		f.width = msg.Width
	}
	return f, nil
}

// refreshAsync runs the slow netlink + sudo probes in a background
// goroutine using the pre-snapshotted cfg fields the caller passed in.
// Returns the result via statusFooterRefreshMsg. The cfg pointer is
// NOT touched in here — see Update for the rationale.
func (f *StatusFooter) refreshAsync(connName, serverRaw, featuresRaw string) tea.Cmd {
	return func() tea.Msg {
		connected := isWGConnected(connName)
		ksActive := isFirewallActive()
		var prettyName string
		if connected {
			serverName := serverRaw
			if strings.HasPrefix(serverName, "dynamic:") {
				parts := strings.SplitN(serverName, ":", 3)
				if len(parts) == 3 {
					serverName = parts[2]
				}
			}
			info := wireguard.ParseServerName(serverName)
			if len(info.Services) == 0 && featuresRaw != "" {
				parts := strings.Split(featuresRaw, ",")
				for _, p := range parts {
					p = strings.TrimSpace(p)
					if p != "" {
						info.Services = append(info.Services, p)
					}
				}
			}
			prettyName = info.PrettyName()
		}
		return statusFooterRefreshMsg{
			connected:  connected,
			prettyName: prettyName,
			killswitch: ksActive,
		}
	}
}

// refresh is the legacy synchronous refresh path, kept for tests that
// directly call it. Production callers should use refreshAsync via
// Update.
func (f *StatusFooter) refresh() {
	f.cfg.Reload()

	connName := f.cfg.ConnectionName
	f.connected = isWGConnected(connName)

	if f.connected {
		serverRaw := f.cfg.LastConnectedServer
		serverName := serverRaw
		if strings.HasPrefix(serverName, "dynamic:") {
			parts := strings.SplitN(serverName, ":", 3)
			if len(parts) == 3 {
				serverName = parts[2]
			}
		}

		info := wireguard.ParseServerName(serverName)
		if len(info.Services) == 0 && f.cfg.LastServerFeatures != "" {
			parts := strings.Split(f.cfg.LastServerFeatures, ",")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					info.Services = append(info.Services, p)
				}
			}
		}
		f.prettyName = info.PrettyName()
		f.killswitch = isFirewallActive()
	} else {
		f.prettyName = ""
		f.killswitch = isFirewallActive()
	}
}

func (f *StatusFooter) View() string {
	if f.OverlayText != "" {
		return f.viewWithOverlay()
	}
	return f.viewNormal()
}

func (f *StatusFooter) viewWithOverlay() string {
	barStyle := lipgloss.NewStyle().
		Background(ColorBg).
		Padding(0, 1).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(ColorBarBorder)
	if f.width > 0 {
		barStyle = barStyle.Width(f.width - 2)
	}

	descStyle := lipgloss.NewStyle().
		Foreground(ColorFg).
		Background(ColorBg)
	if f.OverlayIsError {
		descStyle = lipgloss.NewStyle().
			Foreground(ColorDanger).
			Background(ColorBg).
			Bold(true)
	}

	if f.connected {
		statusStyle := lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Background(ColorBg).
			Bold(true)
		status := statusStyle.Render(" CONNECTED ")

		var extras []string
		if f.prettyName != "" {
			extras = append(extras, f.prettyName)
		}
		if f.killswitch {
			ksStyle := lipgloss.NewStyle().
				Foreground(ColorSuccess).
				Background(ColorBg)
			extras = append(extras, ksStyle.Render("🔒"))
		}

		left := status
		if len(extras) > 0 {
			left += "  " + strings.Join(extras, "  ")
		}

		leftLen := lipgloss.Width(left)
		descLen := lipgloss.Width(f.OverlayText)
		availWidth := f.width - 6

		if leftLen+descLen+4 <= availWidth {
			gap := availWidth - leftLen - descLen
			if gap < 2 {
				gap = 2
			}
			content := left + strings.Repeat(" ", gap) + descStyle.Render(f.OverlayText)
			return barStyle.Render(content)
		}

		maxLeft := availWidth - descLen - 4
		if maxLeft < 12 {
			return barStyle.Render(descStyle.Render(f.OverlayText))
		}
		gap := availWidth - leftLen - descLen
		if gap < 2 {
			gap = 2
		}
		content := left + strings.Repeat(" ", gap) + descStyle.Render(f.OverlayText)
		return barStyle.Render(content)
	}

	// Disconnected — show description with status
	var left []string
	if f.killswitch {
		ksStyle := lipgloss.NewStyle().
			Foreground(ColorWarning).
			Background(ColorBg).
			Bold(true)
		left = append(left, ksStyle.Render(" KILLSWITCH "))
	} else {
		statusStyle := lipgloss.NewStyle().
			Foreground(ColorDanger).
			Background(ColorBg).
			Bold(true)
		left = append(left, statusStyle.Render(" DISCONNECTED "))
	}

	leftContent := strings.Join(left, "  ")
	leftLen := lipgloss.Width(leftContent)
	descLen := lipgloss.Width(f.OverlayText)
	availWidth := f.width - 6

	gap := availWidth - leftLen - descLen
	if gap < 2 {
		gap = 2
	}
	content := leftContent + strings.Repeat(" ", gap) + descStyle.Render(f.OverlayText)
	return barStyle.Render(content)
}

func (f *StatusFooter) viewNormal() string {
	var left []string
	var right []string

	// Status indicator (left side)
	if f.connected {
		statusStyle := lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)
		left = append(left, statusStyle.Render(" CONNECTED "))
	} else if f.killswitch {
		statusStyle := lipgloss.NewStyle().
			Foreground(ColorWarning).
			Bold(true)
		left = append(left, statusStyle.Render(" KILLSWITCH "))
	} else {
		statusStyle := lipgloss.NewStyle().
			Foreground(ColorDanger).
			Bold(true)
		left = append(left, statusStyle.Render(" DISCONNECTED "))
	}

	if f.connected {
		// Server name (left side)
		if f.prettyName != "" {
			left = append(left, f.prettyName)
		}

		// KS icon (right side)
		if f.killswitch {
			ksStyle := lipgloss.NewStyle().Foreground(ColorSuccess)
			right = append(right, ksStyle.Render("🔒 KS"))
		}
	} else {
		if f.killswitch {
			ksStyle := lipgloss.NewStyle().Foreground(ColorWarning)
			right = append(right, ksStyle.Render("🔒 KS Active"))
		}
	}

	leftContent := strings.Join(left, "  ")
	rightContent := strings.Join(right, "  ")

	barStyle := lipgloss.NewStyle().
		Background(ColorBg).
		Padding(0, 1).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(ColorBarBorder)

	if f.width > 0 {
		leftLen := lipgloss.Width(leftContent)
		rightLen := lipgloss.Width(rightContent)
		gap := f.width - leftLen - rightLen - 6
		if gap < 2 {
			gap = 2
		}
		content := leftContent + strings.Repeat(" ", gap) + rightContent
		barStyle = barStyle.Width(f.width - 2)
		return barStyle.Render(content)
	}

	content := leftContent
	if rightContent != "" {
		content += "  " + rightContent
	}
	return barStyle.Render(content)
}

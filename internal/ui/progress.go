package ui

import (
	"fmt"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/daemon"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
	tea "github.com/charmbracelet/bubbletea"
)

const progressUpdateBuffer = 20

// ProgressType indicates what operation is being performed
type ProgressType int

const (
	ProgressConnect ProgressType = iota
	ProgressDisconnect
)

// ProgressLine represents a single line of progress output
type ProgressLine struct {
	Text    string
	Success bool
	Warning bool
	Error   bool
	Muted   bool
}

// Progress shows connection/disconnection progress
type Progress struct {
	progressType ProgressType
	serverName   string
	provider     string
	dynamic      bool
	lines        []ProgressLine
	done         bool
	success      bool
	err          error
	width        int
	height       int
	cfg          *config.Config
	oldIP        string
	newIP        string
	auth         *AuthPrompt
	spinner      Spinner
}

// ProgressUpdateMsg is sent when there's a progress update
type ProgressUpdateMsg struct {
	Line ProgressLine
}

// ProgressDoneMsg is sent when the operation completes
type ProgressDoneMsg struct {
	Success bool
	Error   error
	OldIP   string
	NewIP   string
}

// authCheckPassedMsg signals that sudo credentials are available.
type authCheckPassedMsg struct{}

// authCheckFailedMsg signals that sudo credentials are NOT available.
type authCheckFailedMsg struct{}

// NewConnectProgress creates a progress view for connecting
func NewConnectProgress(cfg *config.Config, serverName string, provider string, dynamic bool) Progress {
	return Progress{
		progressType: ProgressConnect,
		serverName:   serverName,
		provider:     provider,
		dynamic:      dynamic,
		cfg:          cfg,
		lines:        make([]ProgressLine, 0),
		auth:         &AuthPrompt{},
	}
}

// NewDisconnectProgress creates a progress view for disconnecting
func NewDisconnectProgress(cfg *config.Config) Progress {
	return Progress{
		progressType: ProgressDisconnect,
		cfg:          cfg,
		lines:        make([]ProgressLine, 0),
		auth:         &AuthPrompt{},
	}
}

func (m Progress) Init() tea.Cmd {
	return func() tea.Msg {
		// If binary already has file capabilities, no auth needed —
		// the daemon subprocess will inherit them via the executable.
		if execPath, err := osExecutable(); err == nil && sudo.ProbeCapabilities(execPath) {
			return authCheckPassedMsg{}
		}
		// If sudo credentials are cached or NOPASSWD is configured, proceed.
		if sudo.ProbeCache() {
			return authCheckPassedMsg{}
		}
		return authCheckFailedMsg{}
	}
}

func (m Progress) startConnect() tea.Cmd {
	return func() tea.Msg {
		// Channel for progress updates
		updates := make(chan ProgressLine, progressUpdateBuffer)

		// Shared variables to capture IPs from EventConnected
		var capturedOldIP, capturedNewIP string

		go func() {
			defer close(updates)

			// Get path to current executable for spawning daemon
			execPath, err := osExecutable()
			if err != nil {
				select {
				case updates <- ProgressLine{Text: fmt.Sprintf("Error: %s", err.Error()), Error: true}:
				default:
				}
				return
			}

			callback := func(event daemon.Event) {
				line := ProgressLine{Text: event.Message}
				switch event.Type {
				case daemon.EventConnected, daemon.EventReconnected:
					line.Success = true
					if event.OldIP != "" {
						capturedOldIP = event.OldIP
					}
					if event.PublicIP != "" {
						capturedNewIP = event.PublicIP
					}
				case daemon.EventError, daemon.EventFailed:
					line.Error = true
					if event.Error != "" {
						line.Text = fmt.Sprintf("Error: %s", event.Error)
					}
				case daemon.EventHealthFail:
					line.Muted = true
				default:
					// Apply hint-based styling for progress lines
					switch event.Hint {
					case "success":
						line.Success = true
					case "error":
						line.Error = true
					case "warning":
						line.Warning = true
					}
				}
				select {
				case updates <- line:
				default:
				}
			}

			// If a daemon is already running, send a switch command instead of spawning
			var client *daemon.Client
			var connectErr error
			if isDaemonRunning(m.cfg.ConfigDir) {
				client = daemon.NewClient(m.cfg.ConfigDir)
				if connErr := client.Connect(); connErr == nil {
					// Send switch command
					switchErr := client.RequestSwitch(m.serverName, m.provider, m.dynamic)
					if switchErr != nil {
						client.Close()
						client = nil
						connectErr = fmt.Errorf("failed to send switch command: %w", switchErr)
					} else {
						// Monitor events until connected or failed
						for {
							event, readErr := client.ReadEvent()
							if readErr != nil {
								connectErr = fmt.Errorf("lost connection to daemon: %w", readErr)
								break
							}
							callback(*event)
							switch event.Type {
							case daemon.EventConnected:
								goto done
							case daemon.EventFailed, daemon.EventError:
								if event.Error != "" {
									connectErr = fmt.Errorf("%s", event.Error)
								} else {
									connectErr = fmt.Errorf("switch failed")
								}
								goto done
							case daemon.EventDisconnected:
								connectErr = fmt.Errorf("daemon disconnected unexpectedly")
								goto done
							}
						}
					done:
					}
				} else {
					client = nil
				}
			}

			// No running daemon — spawn one
			if client == nil && connectErr == nil {
				client, connectErr = spawnAndWaitForConnect(
					m.cfg.ConfigDir,
					execPath,
					m.serverName,
					m.provider,
					m.dynamic,
					callback,
				)
			}

			if client != nil {
				client.Close()
			}

			if connectErr != nil {
				select {
				case updates <- ProgressLine{Text: fmt.Sprintf("Error: %s", connectErr.Error()), Error: true}:
				default:
				}
			}
		}()

		// Collect first update
		if line, ok := <-updates; ok {
			return progressStreamMsg{line: line, updates: updates, oldIP: &capturedOldIP, newIP: &capturedNewIP}
		}
		return ProgressDoneMsg{Success: false, Error: fmt.Errorf("no progress updates")}
	}
}

func (m Progress) startDisconnect() tea.Cmd {
	return func() tea.Msg {
		updates := make(chan ProgressLine, progressUpdateBuffer)

		// Capture the current VPN IP before disconnecting
		var capturedOldIP, capturedNewIP string
		m.cfg.Reload()
		capturedOldIP = m.cfg.LastPublicIP

		go func() {
			defer close(updates)

			callback := func(event daemon.Event) {
				line := ProgressLine{Text: event.Message}
				switch event.Type {
				case daemon.EventDisconnected:
					line.Success = true
				case daemon.EventError:
					line.Error = true
					if event.Error != "" {
						line.Text = fmt.Sprintf("Error: %s", event.Error)
					}
				}
				select {
				case updates <- line:
				default:
				}
			}

			// Send disconnect command to daemon and wait
			err := waitForDisconnect(m.cfg.ConfigDir, callback)
			if err != nil {
				// Daemon may be gone — fall back to direct disconnect
				select {
				case updates <- ProgressLine{Text: "Daemon not available, cleaning up directly..."}:
				default:
				}
				if forceErr := forceDisconnect(m.cfg); forceErr != nil {
					select {
					case updates <- ProgressLine{Text: fmt.Sprintf("Error: %s", forceErr.Error()), Error: true}:
					default:
					}
				} else {
					select {
					case updates <- ProgressLine{Text: "Disconnected", Success: true}:
					default:
					}
				}
			}

			// After disconnect, fetch real public IP
			if newIP, ipErr := getPublicIP(); ipErr == nil {
				capturedNewIP = newIP
			}
		}()

		if line, ok := <-updates; ok {
			return progressStreamMsg{line: line, updates: updates, oldIP: &capturedOldIP, newIP: &capturedNewIP}
		}
		return ProgressDoneMsg{Success: true}
	}
}

// progressStreamMsg carries progress updates from the channel
type progressStreamMsg struct {
	line    ProgressLine
	updates chan ProgressLine
	oldIP   *string
	newIP   *string
}

func (m Progress) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Route key events to auth prompt when active
		if m.auth.Active() {
			handled, cmd := m.auth.HandleKey(msg)
			if handled {
				if !m.auth.Active() {
					// User cancelled auth — go back
					return m, func() tea.Msg { return BackMsg{} }
				}
				return m, cmd
			}
		}
		if m.done {
			switch msg.String() {
			case "enter", "esc", " ":
				return m, func() tea.Msg { return BackMsg{} }
			}
		} else if msg.String() == "esc" {
			// Let user leave — the operation continues in the background.
			// Sends to the updates channel are non-blocking so no goroutine leak.
			return m, func() tea.Msg { return BackMsg{} }
		}

	case authCheckPassedMsg:
		// Sudo credentials cached or NOPASSWD — proceed directly
		if m.progressType == ProgressConnect {
			return m, m.startConnect()
		}
		return m, m.startDisconnect()

	case authCheckFailedMsg:
		// Need auth prompt before starting operation
		startOp := func() {
			// no-op: actual start happens via authResultMsg handler
		}
		goBack := func() {
			// no-op: cancel handled via HandleKey
		}
		m.auth.Show(startOp, goBack)
		return m, nil

	case authResultMsg:
		if m.auth.Active() {
			if retryFn := m.auth.HandleAuthResult(msg); retryFn != nil {
				// Auth succeeded — set file caps on binary so the daemon
				// subprocess can use netlink without sudo (avoids tty_tickets
				// issue where daemon's new session can't use cached creds).
				if execPath, err := osExecutable(); err == nil {
					if err := sudo.SetCapabilities(execPath); err != nil {
						m.lines = append(m.lines, ProgressLine{
							Text:  "Could not set binary capabilities — daemon may require authentication",
							Error: true,
						})
					} else {
						m.lines = append(m.lines, ProgressLine{
							Text:    "Binary capabilities set",
							Success: true,
						})
					}
				}
				// Start the operation
				if m.progressType == ProgressConnect {
					return m, m.startConnect()
				}
				return m, m.startDisconnect()
			}
			return m, nil
		}

	case progressStreamMsg:
		m.lines = append(m.lines, msg.line)

		// Capture IP pointers for use in closure
		oldIPPtr := msg.oldIP
		newIPPtr := msg.newIP

		// Check for more updates
		return m, func() tea.Msg {
			if line, ok := <-msg.updates; ok {
				return progressStreamMsg{line: line, updates: msg.updates, oldIP: oldIPPtr, newIP: newIPPtr}
			}
			// Channel closed, we're done
			success := true
			for _, l := range m.lines {
				if l.Error {
					success = false
					break
				}
			}
			var oldIP, newIP string
			if oldIPPtr != nil {
				oldIP = *oldIPPtr
			}
			if newIPPtr != nil {
				newIP = *newIPPtr
			}
			return ProgressDoneMsg{Success: success, OldIP: oldIP, NewIP: newIP}
		}

	case StatusUpdateMsg:
		if !m.done {
			m.spinner.Tick()
		}

	case ProgressDoneMsg:
		m.done = true
		m.success = msg.Success
		m.err = msg.Error
		m.oldIP = msg.OldIP
		m.newIP = msg.NewIP

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.auth.SetWidth(msg.Width)
	}

	return m, nil
}

func (m Progress) View() string {
	var b strings.Builder

	// Title based on operation type
	var title string
	if m.progressType == ProgressConnect {
		if !m.done {
			title = m.spinner.View() + " " + TitleStyle.Render("Connecting")
		} else {
			title = TitleStyle.Render("Connecting")
		}
	} else {
		if !m.done {
			title = m.spinner.View() + " " + TitleStyle.Render("Disconnecting")
		} else {
			title = TitleStyle.Render("Disconnecting")
		}
	}
	b.WriteString(title + "\n\n")

	// Server info for connect
	if m.progressType == ProgressConnect && m.serverName != "" {
		serverDisplay := m.serverName
		if m.provider != "" {
			serverDisplay = fmt.Sprintf("%s (%s)", m.serverName, m.provider)
		}
		b.WriteString(SubtitleStyle.Render("  Server: "+serverDisplay) + "\n\n")
	}

	// Auth prompt overlay
	if m.auth.Active() {
		b.WriteString(m.auth.View())
		return b.String()
	}

	// Progress lines
	for _, line := range m.lines {
		prefix := "  "
		text := line.Text

		if line.Success {
			text = SuccessStyle.Render(text)
		} else if line.Warning {
			text = WarningStyle.Render(text)
		} else if line.Error {
			text = ErrorStyle.Render(text)
		} else if line.Muted {
			text = MutedStyle.Render(text)
		}

		b.WriteString(prefix + text + "\n")
	}

	// Final status
	if m.done {
		b.WriteString("\n")
		if m.success {
			if m.progressType == ProgressConnect {
				b.WriteString(SuccessStyle.Render("  Successfully connected") + "\n")
			} else {
				b.WriteString(SuccessStyle.Render("  Successfully disconnected") + "\n")
			}
			if m.oldIP != "" || m.newIP != "" {
				b.WriteString(MutedStyle.Render(fmt.Sprintf("  Old IP: %s  ->  New IP: %s", m.oldIP, m.newIP)) + "\n")
			}
		} else {
			if m.err != nil {
				b.WriteString(ErrorStyle.Render(fmt.Sprintf("  Failed: %s", m.err.Error())) + "\n")
			} else {
				b.WriteString(ErrorStyle.Render("  Operation failed") + "\n")
			}
		}
		b.WriteString("\n" + MutedStyle.Render("  Press Enter to continue"))
	}

	return b.String()
}

// Success returns whether the operation succeeded
func (m Progress) Success() bool {
	return m.success
}

// Done returns whether the operation is complete
func (m Progress) Done() bool {
	return m.done
}

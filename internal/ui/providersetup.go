package ui

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/provider"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/security"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
)

// SetupStep represents the current step in provider setup
type SetupStep int

const (
	StepSelectFile SetupStep = iota
	StepConfirmProvider
	StepConfirmOverwrite
	StepSaving
	StepComplete
	StepError
)

type configFile struct {
	path       string
	name       string
	provider   string
	valid      bool
	privateKey []byte // Raw key bytes (base64-decoded)
	address    string
}

// ProviderSetup handles the provider setup wizard
type ProviderSetup struct {
	step              SetupStep
	files             []configFile
	cursor            int
	selectedFile      *configFile
	detectedProv      string
	confirmedProv     string
	cfg               *config.Config
	width             int
	height            int
	message           string
	errorMsg          string
	fetchServers      bool
	alreadyConfigured bool
	focused           bool
}

// zeroAllKeys zeroes private key material in all parsed config files.
func (m *ProviderSetup) zeroAllKeys() {
	for i := range m.files {
		security.ZeroBytes(m.files[i].privateKey)
	}
}

// SetFocused sets the focus state for cursor visibility.
func (m *ProviderSetup) SetFocused(focused bool) {
	m.focused = focused
}

// NewProviderSetup creates a new provider setup wizard
func NewProviderSetup(cfg *config.Config) *ProviderSetup {
	ps := &ProviderSetup{
		cfg:  cfg,
		step: StepSelectFile,
	}
	ps.scanDownloads()
	return ps
}

func (m *ProviderSetup) scanDownloads() {
	homeDir, _ := os.UserHomeDir()
	downloadsDir := filepath.Join(homeDir, "Downloads")

	entries, err := os.ReadDir(downloadsDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}

		path := filepath.Join(downloadsDir, entry.Name())
		cf := configFile{
			path: path,
			name: entry.Name(),
		}

		// Parse and validate
		wgCfg, err := wireguard.ParseConfig(path)
		if err == nil && wgCfg.Validate() == nil {
			// Also validate the private key format
			if wireguard.ValidatePrivateKey(wgCfg.PrivateKey) == nil {
				cf.valid = true
				cf.privateKey = wgCfg.PrivateKey
				cf.address = wgCfg.Address

				// Detect provider
				cf.provider = detectProvider(path, wgCfg)
			}
		}

		// Defense-in-depth: zero parsed key material from wgCfg before
		// the local goes out of scope.
		//   - PrivateKey: only zero if we DIDN'T store it in cf.privateKey
		//     (invalid-path case). On the valid path cf.privateKey shares
		//     wgCfg.PrivateKey's backing array — zeroing here would zero
		//     the cf.privateKey we just saved, which zeroAllKeys is
		//     supposed to defer.
		//   - PresharedKey: never stored in cf, so always safe to zero.
		//     Pre-fix the parsed PSK lingered on heap until GC.
		if wgCfg != nil {
			if !cf.valid {
				security.ZeroBytes(wgCfg.PrivateKey)
			}
			security.ZeroBytes(wgCfg.PresharedKey)
		}

		m.files = append(m.files, cf)
	}
}

// detectProvider delegates to provider.DetectProvider — the single source of
// truth shared with the confcheck diagnostic so detection can't drift.
func detectProvider(path string, cfg *wireguard.Config) string {
	return provider.DetectProvider(cfg, path)
}

func (m *ProviderSetup) Init() tea.Cmd {
	return nil
}

func (m *ProviderSetup) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.step {
		case StepSelectFile:
			return m.handleFileSelect(msg)
		case StepConfirmProvider:
			return m.handleProviderConfirm(msg)
		case StepConfirmOverwrite:
			return m.handleOverwriteConfirm(msg)
		case StepComplete:
			return m.handleComplete(msg)
		case StepError:
			if msg.String() == "enter" || msg.String() == "esc" {
				m.zeroAllKeys()
				return m, func() tea.Msg { return BackMsg{} }
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case providerSetupSuccessMsg:
		m.step = StepComplete
		// Auto-fetch server list immediately
		return m, m.doFetchServers()

	case providerSetupErrorMsg:
		m.step = StepError
		m.errorMsg = msg.err.Error()
		// Zero key material on save failure too — the success path
		// zeros via line 400's security.ZeroBytes after SaveProvider
		// succeeds. Pre-fix, a save failure left the key bytes
		// lingering in m.selectedFile.privateKey until the model was
		// destroyed (when zeroAllKeys would finally fire on
		// handleComplete's success branch). zeroAllKeys is idempotent
		// so calling it here is safe — already-zeroed slices stay
		// zeroed.
		m.zeroAllKeys()
		return m, nil

	case providerFetchDoneMsg:
		m.fetchServers = true
		m.message = "Server list fetched!"
		return m, nil
	}

	return m, nil
}

func (m *ProviderSetup) handleFileSelect(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.zeroAllKeys()
		return m, func() tea.Msg { return BackMsg{} }
	case "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down":
		if m.cursor < len(m.files)-1 {
			m.cursor++
		}
	case "enter":
		if len(m.files) > 0 && m.cursor < len(m.files) {
			cf := m.files[m.cursor]
			if !cf.valid {
				m.message = "Invalid config - missing required fields or invalid private key"
				return m, nil
			}
			m.selectedFile = &cf
			m.detectedProv = cf.provider

			// If provider was auto-detected, check if already configured
			if m.detectedProv != "" {
				m.confirmedProv = m.detectedProv

				// Check if provider is already configured
				providerFile := filepath.Join(m.cfg.ConfigDir, "providers", m.confirmedProv+".json")
				if _, err := os.Stat(providerFile); err == nil {
					m.alreadyConfigured = true
					m.step = StepConfirmOverwrite
					return m, nil
				}

				// Not already configured - save directly
				m.step = StepSaving
				return m, m.saveCredentials()
			}

			// No provider detected - need user to select
			m.step = StepConfirmProvider
		}
	}
	return m, nil
}

func (m *ProviderSetup) handleProviderConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	providers := []string{"protonvpn", "mullvad", "ivpn", "airvpn", "nordvpn", "surfshark", "windscribe", "fastestvpn"}

	switch msg.String() {
	case "esc":
		m.step = StepSelectFile
		return m, nil
	case "up":
		// Cycle through providers
		for i, p := range providers {
			if p == m.confirmedProv {
				if i > 0 {
					m.confirmedProv = providers[i-1]
				} else {
					m.confirmedProv = providers[len(providers)-1]
				}
				break
			}
		}
		if m.confirmedProv == "" {
			m.confirmedProv = providers[0]
		}
	case "down":
		for i, p := range providers {
			if p == m.confirmedProv {
				if i < len(providers)-1 {
					m.confirmedProv = providers[i+1]
				} else {
					m.confirmedProv = providers[0]
				}
				break
			}
		}
		if m.confirmedProv == "" {
			m.confirmedProv = providers[0]
		}
	case "enter":
		if m.confirmedProv == "" {
			m.message = "Please select a provider"
			return m, nil
		}

		// Check if provider is already configured
		providerFile := filepath.Join(m.cfg.ConfigDir, "providers", m.confirmedProv+".json")
		if _, err := os.Stat(providerFile); err == nil {
			m.alreadyConfigured = true
			m.step = StepConfirmOverwrite
			return m, nil
		}

		// Save credentials
		m.step = StepSaving
		return m, m.saveCredentials()
	}
	return m, nil
}

func (m *ProviderSetup) handleOverwriteConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		// User confirmed overwrite - proceed to save
		m.step = StepSaving
		return m, m.saveCredentials()
	case "n", "N", "esc":
		// User cancelled - go back to file selection
		m.step = StepSelectFile
		m.alreadyConfigured = false
		return m, nil
	}
	return m, nil
}

func (m *ProviderSetup) saveCredentials() tea.Cmd {
	return func() tea.Msg {
		err := config.SaveProvider(
			m.cfg.ConfigDir,
			m.confirmedProv,
			m.selectedFile.privateKey,
			m.selectedFile.address,
		)
		if err != nil {
			return providerSetupErrorMsg{err: err}
		}
		// Zero key material only after successful save
		security.ZeroBytes(m.selectedFile.privateKey)
		return providerSetupSuccessMsg{}
	}
}

type providerSetupSuccessMsg struct{}
type providerSetupErrorMsg struct{ err error }

func (m *ProviderSetup) handleComplete(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Don't accept input until server fetch is done
	if !m.fetchServers {
		return m, nil
	}

	switch msg.String() {
	case "y", "Y":
		// Source file contains the private key; delete with the tool
		// appropriate for the filesystem (shred on ext4/xfs, rm on CoW).
		if m.selectedFile != nil {
			security.DeleteForFS(m.cfg.IsCOWFilesystem())([]string{m.selectedFile.path}, security.NoSudo)
		}
		m.zeroAllKeys()
		return m, func() tea.Msg { return BackMsg{} }
	case "n", "N", "enter", "esc":
		// Don't shred, just leave
		m.zeroAllKeys()
		return m, func() tea.Msg { return BackMsg{} }
	}
	return m, nil
}

func (m *ProviderSetup) doFetchServers() tea.Cmd {
	return func() tea.Msg {
		cacheDir := filepath.Join(m.cfg.ConfigDir, "cache")
		if err := fetchServers(cacheDir, true); err != nil {
			return providerSetupErrorMsg{err: err}
		}
		if _, err := filterProviderServers(cacheDir, m.confirmedProv); err != nil {
			return providerSetupErrorMsg{err: err}
		}
		return providerFetchDoneMsg{}
	}
}

type providerFetchDoneMsg struct{}

func (m *ProviderSetup) View() string {
	var b strings.Builder

	switch m.step {
	case StepSelectFile:
		b.WriteString(TitleStyle.Render("Provider Setup") + "\n\n")
		b.WriteString("Select a WireGuard config file from Downloads:\n\n")

		if len(m.files) == 0 {
			b.WriteString(MutedStyle.Render("  No .conf files found in ~/Downloads") + "\n\n")
			b.WriteString(MutedStyle.Render("  Please download a WireGuard config from your VPN provider:") + "\n")
			b.WriteString(MutedStyle.Render("    ProtonVPN: https://account.protonvpn.com/downloads") + "\n")
			b.WriteString(MutedStyle.Render("    Mullvad: https://mullvad.net/account/wireguard-config") + "\n")
			b.WriteString(MutedStyle.Render("    IVPN: https://www.ivpn.net/account/wireguard-config") + "\n")
		} else {
			for i, f := range m.files {
				cursor := "  "
				if i == m.cursor && m.focused {
					cursor = "> "
				}

				status := SuccessStyle.Render("VALID")
				if !f.valid {
					status = ErrorStyle.Render("INVALID")
				}

				provDisplay := ""
				if f.provider != "" {
					displayName := provider.ProviderDisplayNames[f.provider]
					if displayName == "" {
						displayName = f.provider
					}
					provDisplay = fmt.Sprintf(" [%s]", displayName)
				}

				line := fmt.Sprintf("%s%s %s%s", cursor, f.name, status, provDisplay)
				if i == m.cursor && m.focused {
					line = SelectedStyle.Render(line)
				}
				b.WriteString(line + "\n")
			}
		}

		if m.message != "" {
			b.WriteString("\n" + ErrorStyle.Render("  "+m.message) + "\n")
		}

		b.WriteString("\n" + MutedStyle.Render("  enter: select  esc: back"))

	case StepConfirmProvider:
		b.WriteString(TitleStyle.Render("Confirm Provider") + "\n\n")
		b.WriteString(fmt.Sprintf("  File: %s\n", m.selectedFile.name))
		// Show minimal key info - just first 4 and last 2 chars to confirm it's the right key
		keyDisplay := base64.StdEncoding.EncodeToString(m.selectedFile.privateKey)
		if len(keyDisplay) > 8 {
			keyDisplay = keyDisplay[:4] + "..." + keyDisplay[len(keyDisplay)-2:]
		}
		b.WriteString(fmt.Sprintf("  Private Key: %s (detected)\n", keyDisplay))
		if m.selectedFile.address != "" {
			b.WriteString(fmt.Sprintf("  Address: %s\n", m.selectedFile.address))
		}
		b.WriteString("\n")

		if m.detectedProv != "" {
			displayName := provider.ProviderDisplayNames[m.detectedProv]
			b.WriteString(SuccessStyle.Render(fmt.Sprintf("  Detected: %s", displayName)) + "\n\n")
		} else {
			b.WriteString(MutedStyle.Render("  Could not auto-detect provider") + "\n\n")
		}

		b.WriteString("  Select provider (up/down to change):\n\n")

		providers := []string{"protonvpn", "mullvad", "ivpn", "airvpn", "nordvpn", "surfshark", "windscribe", "fastestvpn"}
		for _, p := range providers {
			cursor := "    "
			if p == m.confirmedProv && m.focused {
				cursor = "  > "
			}
			displayName := provider.ProviderDisplayNames[p]
			line := cursor + displayName
			if p == m.confirmedProv && m.focused {
				line = SelectedStyle.Render(line)
			}
			b.WriteString(line + "\n")
		}

		b.WriteString("\n" + MutedStyle.Render("  enter: confirm  esc: back"))

	case StepConfirmOverwrite:
		displayName := provider.ProviderDisplayNames[m.confirmedProv]
		b.WriteString(TitleStyle.Render("Provider Already Configured") + "\n\n")
		b.WriteString(fmt.Sprintf("  File: %s\n", m.selectedFile.name))
		// Show minimal key info
		keyDisplay2 := base64.StdEncoding.EncodeToString(m.selectedFile.privateKey)
		if len(keyDisplay2) > 8 {
			keyDisplay2 = keyDisplay2[:4] + "..." + keyDisplay2[len(keyDisplay2)-2:]
		}
		b.WriteString(fmt.Sprintf("  Private Key: %s (detected)\n", keyDisplay2))
		if m.selectedFile.address != "" {
			b.WriteString(fmt.Sprintf("  Address: %s\n", m.selectedFile.address))
		}
		b.WriteString("\n")
		b.WriteString(SuccessStyle.Render(fmt.Sprintf("  Provider: %s", displayName)) + "\n\n")
		b.WriteString(ErrorStyle.Render(fmt.Sprintf("  WARNING: %s is already configured.", displayName)) + "\n\n")
		b.WriteString("  Overwrite existing configuration?\n\n")
		b.WriteString(MutedStyle.Render("  y: overwrite  n/esc: cancel"))

	case StepSaving:
		b.WriteString(TitleStyle.Render("Saving...") + "\n\n")
		b.WriteString("  Saving provider credentials...\n")

	case StepComplete:
		displayName := provider.ProviderDisplayNames[m.confirmedProv]
		b.WriteString(TitleStyle.Render("Setup Complete") + "\n\n")
		b.WriteString(SuccessStyle.Render(fmt.Sprintf("  %s configured successfully!", displayName)) + "\n\n")

		if !m.fetchServers {
			b.WriteString("  Fetching server list...\n")
		} else {
			b.WriteString(SuccessStyle.Render("  Server list fetched!") + "\n\n")

			if m.selectedFile != nil {
				b.WriteString("  Source config contains your private key:\n")
				b.WriteString(fmt.Sprintf("    %s\n\n", m.selectedFile.name))
				b.WriteString("  Delete it? (y = delete, enter = keep)\n")
			}

			b.WriteString("\n" + MutedStyle.Render("  y: delete source  enter: done"))
		}

	case StepError:
		b.WriteString(TitleStyle.Render("Error") + "\n\n")
		b.WriteString(ErrorStyle.Render("  "+m.errorMsg) + "\n")
		b.WriteString("\n" + MutedStyle.Render("  enter: back"))
	}

	return b.String()
}

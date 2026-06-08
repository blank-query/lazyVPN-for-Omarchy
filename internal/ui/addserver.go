package ui

import (
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

type importFile struct {
	path            string
	name            string
	provider        string
	valid           bool
	duplicate       bool
	duplicateReason string // e.g. "same endpoint as US-NY#5", "filename exists"
	selected        bool
}

// AddServer handles importing manual WireGuard configs
type AddServer struct {
	files         []importFile
	cursor        int
	cfg           *config.Config
	width         int
	height        int
	message       string
	importing     bool
	importDone    bool
	imported      int
	skipped       int
	deleteFiles   bool
	importedPaths []string
	focused       bool
}

// SetFocused sets the focus state for cursor visibility.
func (m *AddServer) SetFocused(focused bool) {
	m.focused = focused
}

// NewAddServer creates a new add server view
func NewAddServer(cfg *config.Config) *AddServer {
	as := &AddServer{cfg: cfg}
	as.scanDownloads()
	return as
}

func (m *AddServer) scanDownloads() {
	homeDir, _ := os.UserHomeDir()
	downloadsDir := filepath.Join(homeDir, "Downloads")
	wgDir := filepath.Join(m.cfg.ConfigDir, "wireguard")

	// Build a map of existing endpoint IPs → config name for semantic duplicate detection
	existingEndpoints := make(map[string]string)
	existingConfigs, _ := wireguard.ListConfigs(wgDir)
	for _, cfg := range existingConfigs {
		if ip := cfg.EndpointIP(); ip != "" {
			existingEndpoints[ip] = cfg.Name
		}
	}

	entries, err := os.ReadDir(downloadsDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}

		path := filepath.Join(downloadsDir, entry.Name())
		f := importFile{
			path: path,
			name: entry.Name(),
		}

		// Parse and validate
		wgCfg, err := wireguard.ParseConfig(path)
		if err == nil && wgCfg.Validate() == nil {
			f.valid = true

			// Detect provider
			f.provider = detectProvider(path, wgCfg)

			// Check for duplicates - both filename and endpoint IP match
			destName := strings.TrimSuffix(entry.Name(), ".conf")
			if _, err := os.Stat(filepath.Join(wgDir, destName+".conf")); err == nil {
				f.duplicate = true
				f.duplicateReason = "filename exists"
			}
			// Semantic duplicate: same endpoint IP already exists under a different name
			if !f.duplicate {
				if ip := wgCfg.EndpointIP(); ip != "" {
					if existingName, ok := existingEndpoints[ip]; ok {
						f.duplicate = true
						f.duplicateReason = fmt.Sprintf("same endpoint as %s", existingName)
					}
				}
			}
		}

		// Defense-in-depth: wgCfg never escapes scanDownloads — importFile
		// only carries path/name/provider/duplicate metadata, never the
		// parsed key bytes. Without explicit zeroing, the decoded
		// PrivateKey + PresharedKey linger on heap until GC for every
		// .conf in ~/Downloads. Same pattern as providersetup.scanDownloads.
		if wgCfg != nil {
			security.ZeroBytes(wgCfg.PrivateKey)
			security.ZeroBytes(wgCfg.PresharedKey)
		}

		m.files = append(m.files, f)
	}
}

func (m *AddServer) Init() tea.Cmd {
	return nil
}

func (m *AddServer) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.importDone {
			switch msg.String() {
			case "y", "Y":
				// Imported files contain private keys; delete with the tool
				// appropriate for the filesystem (shred on ext4/xfs, rm on CoW).
				security.DeleteForFS(m.cfg.IsCOWFilesystem())(m.importedPaths, security.NoSudo)
				m.deleteFiles = true
				m.message = "Source files deleted"
				return m, nil
			case "n", "N", "enter", "esc":
				return m, func() tea.Msg { return BackMsg{} }
			}
			return m, nil
		}

		switch msg.String() {
		case "esc":
			return m, func() tea.Msg { return BackMsg{} }
		case "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down":
			if m.cursor < len(m.files)-1 {
				m.cursor++
			}
		case " ":
			// Toggle selection (only for valid, non-duplicate files)
			if len(m.files) > 0 && m.cursor < len(m.files) {
				f := &m.files[m.cursor]
				if f.valid && !f.duplicate {
					f.selected = !f.selected
				}
			}
		case "a":
			// Select all valid, non-duplicate
			for i := range m.files {
				if m.files[i].valid && !m.files[i].duplicate {
					m.files[i].selected = true
				}
			}
		case "enter":
			if m.importing {
				break
			}
			// If nothing is selected, select the currently highlighted file
			hasSelection := false
			for _, f := range m.files {
				if f.selected {
					hasSelection = true
					break
				}
			}
			if !hasSelection && len(m.files) > 0 && m.cursor < len(m.files) {
				f := &m.files[m.cursor]
				if f.valid && !f.duplicate {
					f.selected = true
				}
			}
			m.importing = true
			return m, m.doImport()
		}

	case importDoneMsg:
		m.importing = false
		m.importDone = true
		m.imported = msg.imported
		m.skipped = msg.skipped
		m.importedPaths = msg.paths

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

type importDoneMsg struct {
	imported int
	skipped  int
	paths    []string
}

func (m *AddServer) doImport() tea.Cmd {
	return func() tea.Msg {
		wgDir := filepath.Join(m.cfg.ConfigDir, "wireguard")
		os.MkdirAll(wgDir, 0700)

		imported := 0
		skipped := 0
		var importedPaths []string

		for _, f := range m.files {
			if !f.selected {
				continue
			}
			if !f.valid || f.duplicate {
				skipped++
				continue
			}

			// Generate standardized server name. ParseConfig decodes
			// PrivateKey + PresharedKey from the source file into wgCfg
			// but GenerateStandardServerName only reads metadata. Zero
			// the key bytes once wgCfg is no longer needed.
			wgCfg, parseErr := wireguard.ParseConfig(f.path)
			destBase := strings.TrimSuffix(f.name, ".conf")
			if parseErr == nil {
				stdName := wireguard.GenerateStandardServerName(wgCfg, f.provider, wgDir)
				if stdName != "" {
					destBase = stdName
				}
			}
			if wgCfg != nil {
				security.ZeroBytes(wgCfg.PrivateKey)
				security.ZeroBytes(wgCfg.PresharedKey)
			}
			destName := destBase + ".conf"
			destPath := filepath.Join(wgDir, destName)

			content, err := os.ReadFile(f.path)
			if err != nil {
				skipped++
				continue
			}

			// Write to temp file first, then rename for atomicity.
			//
			// Use os.CreateTemp (O_EXCL + random suffix) instead of a
			// predictable "<destPath>.tmp" path. Predictable temp paths
			// are a CWE-377 symlink-attack vector: an attacker who can
			// write to ~/.config/lazyvpn/wireguard/ could pre-place a
			// symlink at "<expected name>.tmp" pointing at any file the
			// user can write to. os.WriteFile would follow the symlink
			// and write the WireGuard config CONTENT (including the
			// user's PrivateKey) to the symlink target — leaking secrets.
			// CreateTemp's O_EXCL refuses to follow a pre-existing
			// symlink and the random suffix defeats pre-placement.
			//
			// The wireguard dir is 0700 so the attacker would need
			// write access to a private dir already, but the fix is
			// trivial and matches the pattern in security/journal.go.
			tmpFile, err := os.CreateTemp(wgDir, ".import-"+destBase+".tmp.*")
			if err != nil {
				skipped++
				continue
			}
			tmpPath := tmpFile.Name()
			if _, err := tmpFile.Write(content); err != nil {
				tmpFile.Close()
				os.Remove(tmpPath)
				skipped++
				continue
			}
			if err := tmpFile.Close(); err != nil {
				os.Remove(tmpPath)
				skipped++
				continue
			}
			// CreateTemp on Unix produces 0600 by default; explicit
			// chmod for belt-and-suspenders / non-Unix portability.
			if err := os.Chmod(tmpPath, 0600); err != nil {
				os.Remove(tmpPath)
				skipped++
				continue
			}
			if err := os.Rename(tmpPath, destPath); err != nil {
				os.Remove(tmpPath)
				security.ZeroBytes(content)
				skipped++
				continue
			}

			// Zero the raw file bytes now that they've been written to
			// disk. content holds the entire .conf with the base64-
			// encoded PrivateKey in plain text — defense-in-depth wipes
			// it from heap before the next iteration overwrites the
			// local with another file's contents.
			security.ZeroBytes(content)

			imported++
			importedPaths = append(importedPaths, f.path)
		}

		return importDoneMsg{imported: imported, skipped: skipped, paths: importedPaths}
	}
}

func (m *AddServer) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("Import WireGuard Configs") + "\n\n")

	if m.importDone {
		if m.imported > 0 {
			b.WriteString(SuccessStyle.Render(fmt.Sprintf("  Imported %d config(s)", m.imported)) + "\n")
		} else {
			b.WriteString(MutedStyle.Render("  No configs imported") + "\n")
		}
		if m.skipped > 0 {
			b.WriteString(MutedStyle.Render(fmt.Sprintf("  Skipped %d (invalid/duplicate)", m.skipped)) + "\n")
		}
		b.WriteString("\n")

		if len(m.importedPaths) > 0 && !m.deleteFiles {
			b.WriteString("  Delete source files from Downloads? [y/n]\n")
		} else if m.deleteFiles {
			b.WriteString(MutedStyle.Render("  Source files deleted") + "\n")
		}

		b.WriteString("\n" + MutedStyle.Render("  enter: done"))
		return b.String()
	}

	if len(m.files) == 0 {
		b.WriteString(MutedStyle.Render("  No .conf files found in ~/Downloads") + "\n")
		b.WriteString("\n" + MutedStyle.Render("  esc: back"))
		return b.String()
	}

	b.WriteString("  Space: toggle  a: select all  Enter: import\n\n")

	// Calculate visible area (default to 24 if height not yet set)
	height := m.height
	if height == 0 {
		height = 24
	}
	visibleHeight := height - 10
	if visibleHeight < 5 {
		visibleHeight = 15
	}

	start := 0
	if m.cursor >= visibleHeight {
		start = m.cursor - visibleHeight + 1
	}
	end := start + visibleHeight
	if end > len(m.files) {
		end = len(m.files)
	}

	for i := start; i < end; i++ {
		f := m.files[i]

		cursor := "  "
		if i == m.cursor && m.focused {
			cursor = "> "
		}

		checkbox := "[ ]"
		if f.selected {
			checkbox = "[x]"
		}

		status := ""
		if !f.valid {
			status = ErrorStyle.Render(" INVALID")
		} else if f.duplicate {
			reason := "exists"
			if f.duplicateReason != "" {
				reason = f.duplicateReason
			}
			status = MutedStyle.Render(fmt.Sprintf(" (%s)", reason))
		}

		provDisplay := ""
		if f.provider != "" {
			displayName := provider.ProviderDisplayNames[f.provider]
			if displayName == "" {
				displayName = f.provider
			}
			provDisplay = MutedStyle.Render(fmt.Sprintf(" [%s]", displayName))
		}

		line := fmt.Sprintf("%s%s %s%s%s", cursor, checkbox, f.name, status, provDisplay)
		if i == m.cursor && m.focused {
			line = SelectedStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}

	// Scroll indicator
	if len(m.files) > visibleHeight {
		b.WriteString("\n" + MutedStyle.Render(fmt.Sprintf("  %d/%d files", m.cursor+1, len(m.files))))
	}

	// Count selected
	selected := 0
	for _, f := range m.files {
		if f.selected {
			selected++
		}
	}
	if selected > 0 {
		b.WriteString(MutedStyle.Render(fmt.Sprintf("  (%d selected)", selected)))
	}

	b.WriteString("\n\n" + MutedStyle.Render("  esc: back"))

	return b.String()
}

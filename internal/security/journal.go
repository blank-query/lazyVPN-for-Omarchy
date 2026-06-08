package security

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
)

// readMachineIDFunc reads the machine ID. Replaceable in tests.
var readMachineIDFunc = func() ([]byte, error) {
	return os.ReadFile("/etc/machine-id")
}

// journalBaseDirs lists the base directories to search for journal files.
// Replaceable in tests.
var journalBaseDirs = []string{"/var/log/journal", "/run/log/journal"}

// JournalCleanResult summarises the outcome of a journal scrub.
type JournalCleanResult struct {
	Scanned      int          // total journal files examined
	WithEvidence int          // files containing VPN references
	Clean        int          // files with no VPN references (preserved)
	Delete       DeleteResult // delete attempt outcomes for the flagged files
}

// CleanJournalLogs scans every systemd journal file under the current
// machine's journal directory, identifies files containing VPN-related
// evidence (LazyVPN name, WireGuard, or the VPN interface name), stops
// systemd-journald, deletes the flagged files using deleteFn, and restarts
// journald.
//
// The caller is responsible for having already prompted the user to confirm
// this step. deleteFn is the FS-appropriate delete function (SecureDelete on
// ext4/xfs, PlainDelete on btrfs/ZFS) — typically obtained via DeleteForFS.
// Journal files are root-owned, and no NOPASSWD entry matches the delete
// paths (by design — log destruction should require explicit authentication),
// so the caller typically passes SudoInteractive for the deletion mode.
func CleanJournalLogs(interfaceName string, deleteFn DeleteFunc, mode SudoMode) (JournalCleanResult, error) {
	result := JournalCleanResult{}

	fmt.Println("  - Scanning journal files for VPN activity...")

	machineID, err := readMachineIDFunc()
	if err != nil {
		return result, fmt.Errorf("failed to read machine-id: %w", err)
	}
	machineIDStr := strings.TrimSpace(string(machineID))

	var journalDir string
	for _, base := range journalBaseDirs {
		candidate := filepath.Join(base, machineIDStr)
		if _, err := os.Stat(candidate); err == nil {
			journalDir = candidate
			break
		}
	}
	if journalDir == "" {
		return result, fmt.Errorf("journal directory not found")
	}

	var allJournals []string
	err = filepath.Walk(journalDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".journal") || strings.HasSuffix(path, ".journal~")) {
			allJournals = append(allJournals, path)
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	result.Scanned = len(allJournals)

	if len(allJournals) == 0 {
		fmt.Println("    - No journal files found.")
		return result, nil
	}

	fmt.Printf("    Scanning %d journal files...\n", len(allJournals))

	var vpnJournals []string
	ifaceLower := strings.ToLower(interfaceName)
	for _, journalFile := range allJournals {
		cmd := execCommand("journalctl", "--file="+journalFile, "-o", "short", "--no-pager")
		// Stream through a pipe + bufio.Scanner so we don't load the
		// whole journal into memory + double-allocate via ToLower.
		// Default systemd journal files rotate at 4GB; pre-fix the
		// uninstaller's scan would peak at ~8GB per file (output +
		// lowercase copy). The streaming scanner stops on first
		// keyword match, so the common "VPN evidence found" case
		// short-circuits early.
		if scanJournalForVPN(cmd, ifaceLower) {
			vpnJournals = append(vpnJournals, journalFile)
		}
	}

	result.WithEvidence = len(vpnJournals)
	result.Clean = len(allJournals) - result.WithEvidence

	fmt.Printf("    Found VPN evidence in %d of %d journal files.\n", result.WithEvidence, result.Scanned)

	if result.WithEvidence == 0 {
		return result, nil
	}

	fmt.Println("  - Stopping systemd-journald...")
	stopCmd := execCommand("sudo", "-n", "systemctl", "stop", "systemd-journald")
	sudo.SetCLocale(stopCmd)
	// Bound the systemctl call so a wedged systemd or sudo doesn't
	// freeze the uninstaller indefinitely at this step. 15s is generous
	// for a healthy `systemctl stop` (typically <2s) and short enough to
	// surface as a recoverable error rather than an apparent hang. Reuse
	// the runWithKillTimeout helper from delete.go (same package).
	if out, err := runWithKillTimeout(stopCmd, 15*time.Second); err != nil {
		if sudo.IsAuthError(out) {
			return result, fmt.Errorf("failed to stop journald: %w (sudoers NOPASSWD entry for systemctl stop systemd-journald is missing — run lazyvpn install to refresh sudoers)", sudo.ErrAuthRequired)
		}
		return result, fmt.Errorf("failed to stop journald: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("    - systemd-journald stopped.")

	defer func() {
		// Critical recovery path — if this fails, the user's system has
		// no journald running until they manually restart it. Loud
		// banner ensures the message survives the scrolling uninstaller
		// output.
		//
		// Bound the systemctl start the same way as the stop above. A
		// wedged systemd here is even worse than wedging the stop
		// because the user's journald is now off — so the timeout is
		// what makes the loud banner actually appear within seconds
		// rather than forever-later.
		fmt.Println("  - Restarting systemd-journald...")
		startCmd := execCommand("sudo", "-n", "systemctl", "start", "systemd-journald")
		sudo.SetCLocale(startCmd)
		out, err := runWithKillTimeout(startCmd, 15*time.Second)
		if err != nil {
			fmt.Println()
			fmt.Println("    ╔════════════════════════════════════════════════════════════╗")
			fmt.Println("    ║  ✗ FAILED TO RESTART systemd-journald                      ║")
			fmt.Println("    ║                                                            ║")
			fmt.Println("    ║  Your system is currently NOT logging via journald.        ║")
			fmt.Println("    ║  Run this command immediately to restore logging:          ║")
			fmt.Println("    ║                                                            ║")
			fmt.Println("    ║    sudo systemctl start systemd-journald                   ║")
			fmt.Println("    ╚════════════════════════════════════════════════════════════╝")
			fmt.Printf("    Underlying error: %v: %s\n", err, strings.TrimSpace(string(out)))
			fmt.Println()
		} else {
			fmt.Println("    - systemd-journald restarted.")
		}
	}()

	result.Delete = deleteFn(vpnJournals, mode)
	return result, nil
}

// scanJournalForVPN runs the given journalctl cmd and reads its stdout
// line-by-line, looking for the VPN keywords. Returns true on first
// match, false otherwise (or on any subprocess/pipe error). Bounds
// memory at one bufio.Scanner buffer (~256KB) regardless of journal
// file size. The scanJournalMaxBytes cap prevents a pathological
// single line from exhausting memory; journal lines are typically
// well under 1KB but not strictly bounded.
func scanJournalForVPN(cmd *exec.Cmd, ifaceLower string) bool {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	defer func() {
		// Drain remainder so the pipe doesn't block journalctl.
		// Fast-path: short-circuit if we already matched and Wait
		// the subprocess to release its FDs.
		_, _ = io.Copy(io.Discard, stdout)
		_ = cmd.Wait()
	}()

	const scanJournalMaxBytes = 1 * 1024 * 1024 // 1MB per line
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), scanJournalMaxBytes)
	for scanner.Scan() {
		// Lowercase a per-line copy (~bytes.ToLower of one line, not
		// the whole file) before substring search.
		lower := bytes.ToLower(scanner.Bytes())
		if bytes.Contains(lower, []byte("lazyvpn")) ||
			bytes.Contains(lower, []byte("wireguard")) ||
			(ifaceLower != "" && bytes.Contains(lower, []byte(ifaceLower))) {
			return true
		}
	}
	return false
}

// providerKeywords are the lowercase tokens that identify a VPN provider
// in shell history (e.g. "cat proton-us-01.conf"). Keep in sync with the
// supported-providers list in docs/providers.md.
var providerKeywords = []string{
	"proton", "mullvad", "ivpn", "airvpn",
	"nord", "surfshark", "windscribe", "fastestvpn",
}

// filterHistoryLines filters out VPN-related lines from shell history.
// This is the pure logic extracted for testability.
//
// Defense-in-depth: the interface-name match is gated on a non-empty
// pattern. Without the gate, strings.Contains(lower, "") returns true
// for every line and the entire shell history is wiped. Current callers
// always pass a non-empty connName (config.validate resets to "wg0" if
// missing), but rm -rf-grade behavior should never depend on a caller
// invariant alone. Sibling scanJournalForVPN has the same guard.
func filterHistoryLines(lines []string, interfaceName string) []string {
	interfacePattern := strings.ToLower(interfaceName)
	var cleanedLines []string
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "lazyvpn") ||
			strings.Contains(lower, "wireguard") ||
			(interfacePattern != "" && strings.Contains(lower, interfacePattern)) ||
			containsProviderConf(lower) {
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}
	return cleanedLines
}

// containsProviderConf reports whether line references a .conf file
// belonging to one of the supported providers.
func containsProviderConf(lower string) bool {
	if !strings.Contains(lower, ".conf") {
		return false
	}
	for _, kw := range providerKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// CleanShellHistory rewrites the user's shell history files, removing
// VPN-related command entries. The cleaned copy replaces the original
// atomically via os.Rename.
func CleanShellHistory(interfaceName string) {
	fmt.Println()
	fmt.Println("Cleaning shell history...")
	fmt.Println("Removing VPN-related commands from shell history files...")

	homeDir, _ := os.UserHomeDir()

	historyFiles := []string{
		filepath.Join(homeDir, ".bash_history"),
		filepath.Join(homeDir, ".zsh_history"),
		filepath.Join(homeDir, ".local/share/fish/fish_history"),
	}

	cleanHistoryFiles(historyFiles, interfaceName)
}

// cleanHistoryFiles processes a list of history files, filtering VPN-related
// lines. Extracted from CleanShellHistory for testability. The rewrite uses
// atomic rename — no deleteFn step, see the inline comment for rationale.
func cleanHistoryFiles(historyFiles []string, interfaceName string) (cleaned int, skipped int) {
	for _, histFile := range historyFiles {
		if _, err := os.Stat(histFile); os.IsNotExist(err) {
			continue
		}

		shellName := filepath.Base(histFile)
		if strings.Contains(shellName, "_") {
			parts := strings.Split(shellName, "_")
			if len(parts) > 0 {
				shellName = parts[0]
			}
		}
		shellName = strings.TrimPrefix(shellName, ".")

		// Fish history is YAML, not line-per-command. Each entry is:
		//   - cmd: <command>
		//     when: <timestamp>
		//     paths:
		//       - <path>
		// Filtering line-by-line would remove "- cmd: lazyvpn random"
		// while leaving the orphan "when:"/"paths:" lines attached to
		// the wrong (or nonexistent) entry — corrupting the user's
		// entire fish history. Bash and zsh are line-per-entry, so the
		// generic filter is correct for them. For fish, skip with a
		// pointer so the user can clean it manually.
		//
		// Skip BEFORE the file read — users with years of fish history
		// accumulate multi-MB files; reading just to discard is waste.
		if strings.Contains(shellName, "fish") || strings.HasSuffix(histFile, "fish_history") {
			fmt.Printf("  - %s history: skipped (fish uses YAML; remove VPN entries manually with `history delete --contains 'lazyvpn'` or edit %s)\n", shellName, histFile)
			skipped++
			continue
		}

		content, err := os.ReadFile(histFile)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		cleanedLines := filterHistoryLines(lines, interfaceName)
		removedCount := len(lines) - len(cleanedLines)

		if removedCount > 0 {
			// Write cleaned version to temp file first, then atomic replace.
			// POSIX rename(tmp, hist) unlinks the destination atomically,
			// so we never end up in the state where the user has no history
			// file at all. The previous "deleteFn(hist) then rename" order
			// could lose the user's history on a crash between the two steps.
			//
			// Use os.CreateTemp (O_EXCL + random suffix) instead of a
			// predictable "<histFile>.tmp" path. A predictable path is a
			// symlink-attack vector (CWE-377): an attacker who can drop a
			// symlink at ~/.bash_history.tmp before uninstall runs would
			// otherwise have os.WriteFile follow the symlink and truncate
			// the target. CreateTemp's O_EXCL refuses to follow a
			// pre-existing symlink and the random suffix makes pre-placement
			// impossible.
			//
			// Tradeoff: the original inode's blocks aren't actively zeroed
			// before being released to the freelist. On non-CoW filesystems
			// where the caller would pass SecureDelete, the lazyvpn command
			// strings linger as recoverable data until the freelist reuses
			// the blocks. We accept this — losing the user's bash history
			// to a crash window would be much worse than that residual risk.
			cleanedContent := []byte(strings.Join(cleanedLines, "\n"))
			tmpFile, err := os.CreateTemp(filepath.Dir(histFile), "."+shellName+"_history.tmp.*")
			if err != nil {
				fmt.Printf("  ✗ Failed to create temp file for %s history: %v\n", shellName, err)
				continue
			}
			tmpPath := tmpFile.Name()
			writeOK := true
			if _, err := tmpFile.Write(cleanedContent); err != nil {
				fmt.Printf("  ✗ Failed to write cleaned %s history: %v\n", shellName, err)
				writeOK = false
			}
			if err := tmpFile.Close(); err != nil && writeOK {
				fmt.Printf("  ✗ Failed to close cleaned %s history: %v\n", shellName, err)
				writeOK = false
			}
			if !writeOK {
				os.Remove(tmpPath)
				continue
			}
			// CreateTemp produces 0600 by default; explicit Chmod for
			// belt-and-suspenders in case the umask flow changes upstream.
			if err := os.Chmod(tmpPath, 0600); err != nil {
				os.Remove(tmpPath)
				fmt.Printf("  ✗ Failed to chmod cleaned %s history: %v\n", shellName, err)
				continue
			}
			if err := os.Rename(tmpPath, histFile); err != nil {
				os.Remove(tmpPath)
				fmt.Printf("  ✗ Failed to replace %s history: %v\n", shellName, err)
				continue
			}
			fmt.Printf("  - Cleaned %s history: removed %d line(s)\n", shellName, removedCount)
			cleaned++
		} else {
			fmt.Printf("  - %s history: no VPN commands found\n", shellName)
			skipped++
		}
	}

	if cleaned == 0 && skipped == 0 {
		fmt.Println("  - No shell history files found")
	} else {
		fmt.Println()
		fmt.Printf("  Summary: Cleaned %d history file(s), %d had no VPN commands\n", cleaned, skipped)
	}

	return cleaned, skipped
}

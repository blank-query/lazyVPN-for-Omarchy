package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// hyprctlReload runs `hyprctl reload` bounded with a 2-second
// context timeout. Bare `exec.Command("hyprctl", "reload").Run()`
// would block the install/uninstall flow indefinitely if the
// hyprctl IPC socket is wedged (rare but happens after Hyprland
// crashes or upgrades-mid-session). 2s is generous for a healthy
// hyprctl call (~10ms typical) and short enough to surface as a
// recoverable hiccup rather than an apparent freeze.
func hyprctlReload() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "hyprctl", "reload").Run()
}

// matchesExeBaseName reports whether a /proc/<pid>/exe symlink target
// refers to a binary with the given baseName, accounting for the
// kernel's " (deleted)" suffix that appears after the binary has been
// atomic-renamed.
//
// `lazyvpn update` atomic-renames the binary at ~/.local/bin/lazyvpn.
// A TUI process that was already running the OLD binary then shows
// /proc/<pid>/exe → "/home/.../lazyvpn (deleted)". Without stripping
// the suffix, isAnotherTUIRunning's filepath.Base comparison would
// see "lazyvpn (deleted)" vs "lazyvpn" and conclude they don't
// match — defeating the single-instance check, so a fresh `lazyvpn`
// invocation in another terminal would happily start a second TUI.
//
// Same suffix-stripping pattern as daemon/sameExePath.
func matchesExeBaseName(link, baseName string) bool {
	return strings.TrimSuffix(filepath.Base(link), " (deleted)") == baseName
}

// writeFileAtomic writes data to path via temp file + rename, so a
// crash, OOM kill, or sudden shutdown mid-install/uninstall can never
// leave the destination truncated. The install/uninstall flows rewrite
// user-shared config files (hyprland.conf, waybar config, etc.); a
// truncated hyprland.conf would break the user's window manager on
// next login. Bare os.WriteFile gives no such guarantee.
//
// The temp file is created in the same directory as the target so the
// rename is atomic (cross-filesystem rename falls back to copy + delete,
// which loses the atomicity guarantee). On any failure the temp file
// is cleaned up so we never leave .tmp.* orphans behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".lazyvpn-tmp.*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	success = true
	return nil
}

// migrateHyprBinding rewrites the legacy "bindd = SUPER, L, LazyVPN" line
// to "bindd = SUPER SHIFT, L, LazyVPN, exec, <launchCmd>". Returns the
// new file contents and a bool indicating whether anything was changed.
func migrateHyprBinding(content, launchCmd string) (string, bool) {
	if !strings.Contains(content, "bindd = SUPER, L, LazyVPN") {
		return content, false
	}
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, "bindd = SUPER, L, LazyVPN") {
			line = fmt.Sprintf("bindd = SUPER SHIFT, L, LazyVPN, exec, %s", launchCmd)
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n"), true
}

// hyprBindingExists reports whether the bindings file already contains
// any LazyVPN entry. Used to decide between migrate / append / no-op.
func hyprBindingExists(content string) bool {
	return strings.Contains(content, "LazyVPN")
}

// appendHyprBinding produces the lines to append to a bindings file when
// no LazyVPN entry exists yet. Output starts with a leading newline so
// it appends cleanly to a file that may not end in one.
func appendHyprBinding(launchCmd string) string {
	return fmt.Sprintf("\n# LazyVPN\nbindd = SUPER SHIFT, L, LazyVPN, exec, %s\n", launchCmd)
}

// addHyprWindowRules strips any existing LazyVPN window rule lines from
// hyprland.conf content, then appends a fresh block. Idempotent.
func addHyprWindowRules(content string) string {
	if strings.Contains(content, "org.lazyvpn") || strings.Contains(content, "# LazyVPN floating") {
		lines := strings.Split(content, "\n")
		out := make([]string, 0, len(lines))
		for _, line := range lines {
			if !strings.Contains(line, "org.lazyvpn") && !strings.Contains(line, "# LazyVPN floating") {
				out = append(out, line)
			}
		}
		content = strings.Join(out, "\n")
	}
	content += "\n# LazyVPN floating window rules\n"
	content += "windowrule = float on, match:class org.lazyvpn\n"
	content += "windowrule = size 900 600, match:class org.lazyvpn\n"
	content += "windowrule = center on, match:class org.lazyvpn\n"
	return content
}

// removeLazyvpnFromHyprBindings drops the LazyVPN comment line and any
// matching SUPER/SUPER SHIFT keybindings. Returns new content.
func removeLazyvpnFromHyprBindings(content string) string {
	if !strings.Contains(content, "LazyVPN") {
		return content
	}
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, "# LazyVPN") ||
			strings.Contains(line, "bindd = SUPER SHIFT, L, LazyVPN") ||
			strings.Contains(line, "bindd = SUPER, L, LazyVPN") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// removeLazyvpnFromHyprlandConf strips window-rule lines tagged for LazyVPN.
func removeLazyvpnFromHyprlandConf(content string) string {
	if !strings.Contains(content, "lazyvpn") && !strings.Contains(content, "LazyVPN") {
		return content
	}
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, "org.lazyvpn") || strings.Contains(line, "# LazyVPN") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// removeLazyvpnFromKeybindings strips lines containing "LazyVPN" from the
// omarchy-menu-keybindings helper.
func removeLazyvpnFromKeybindings(content string) string {
	if !strings.Contains(content, "LazyVPN") {
		return content
	}
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.Contains(line, "LazyVPN") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// removeLazyvpnFromShellRC drops the "# LazyVPN" comment and the PATH
// export line that immediately follows it.
func removeLazyvpnFromShellRC(content string) string {
	if !strings.Contains(content, "# LazyVPN") {
		return content
	}
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	skipNext := false
	for _, line := range lines {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.Contains(line, "# LazyVPN") {
			skipNext = true
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// removeWaybarLazyvpnModule strips both the "custom/lazyvpn" entry from
// modules-right and the matching module definition block.
func removeWaybarLazyvpnModule(content string) string {
	if !strings.Contains(content, "custom/lazyvpn") {
		return content
	}
	moduleDefRe := regexp.MustCompile(`(?s),?\s*"custom/lazyvpn"\s*:\s*\{.*?\n\s*\}`)
	content = moduleDefRe.ReplaceAllString(content, "")
	content = strings.Replace(content, `, "custom/lazyvpn"`, "", -1)
	content = strings.Replace(content, `"custom/lazyvpn", `, "", -1)
	return content
}

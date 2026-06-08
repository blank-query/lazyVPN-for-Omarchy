package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
)

const (
	maxRespBytes = 64 * 1024 // 64KB limit on API response
	httpTimeout  = 5 * time.Second
)

// repoAPI is a var (not const) so tests can override with httptest.NewServer.URL.
var repoAPI = "https://api.github.com/repos/blank-query/lazyVPN-for-Omarchy/releases/latest"

// Release holds information about a GitHub release.
type Release struct {
	TagName     string // "v1.2.0"
	Body        string // Release notes (markdown)
	PublishedAt string // ISO 8601 timestamp
	AssetURL    string // Download URL for the linux-amd64 binary
}

// githubRelease is the JSON shape from the GitHub API.
type githubRelease struct {
	TagName     string        `json:"tag_name"`
	Body        string        `json:"body"`
	PublishedAt string        `json:"published_at"`
	Assets      []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// httpClient is injectable for testing (API calls with short timeout).
var httpClient = &http.Client{Timeout: httpTimeout}

// downloadClient streams the release binary. No client.Timeout — a
// large binary on a slow connection can legitimately take many
// minutes — but ResponseHeaderTimeout caps the silent gap before the
// first byte (after dial+TLS), which is the actual hang failure mode
// we hit in practice (server accepts then stalls). The per-download
// overall bound is a context.WithTimeout in Apply itself.
var downloadClient = &http.Client{
	Transport: &http.Transport{
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	},
}

// downloadOverallTimeout caps the entire download attempt (dial through
// last byte) so a slow trickle can't hang lazyvpn update forever. 20
// minutes accommodates ~100KB/s connections downloading a 100MB binary
// (the LimitReader cap) with margin.
const downloadOverallTimeout = 20 * time.Minute

// maxBinaryBytes is the size cap for downloaded release binaries.
// Var (not const) so tests can shrink it to exercise the overflow path
// without allocating 100MB. Production value is 100MB; the actual lazyvpn
// binary is ~30MB, leaving plenty of headroom.
var maxBinaryBytes int64 = 100 * 1024 * 1024

// setCapFn is injectable for testing — runs setcap on the binary after update.
// Bounded with 10s — a wedged sudo (NSS hang) would otherwise stall
// 'lazyvpn update' indefinitely after the binary write succeeded.
// Mirrors sudo.SetCapabilities's bound (this is a duplicate that
// stays in update package to keep its dependency graph minimal).
var setCapFn = func(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// sudo -n: non-interactive. Succeeds silently for sudoers users,
	// fails immediately (no prompt) for non-sudoers users — both are fine.
	cmd := exec.CommandContext(ctx, "sudo", "-n", "setcap", "cap_net_admin,cap_net_raw+ep", path)
	sudo.SetCLocale(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("setcap timed out — sudo may be wedged")
		}
		return fmt.Errorf("setcap: %w: %s", err, out)
	}
	return nil
}

// Check queries the GitHub API for the latest release and returns it
// if it's newer than currentVersion. Returns nil if up to date.
func Check(currentVersion string) (*Release, error) {
	req, err := http.NewRequest("GET", repoAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("check update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("GitHub API rate limit exceeded")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no releases found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var gr githubRelease
	if err := json.Unmarshal(body, &gr); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if !IsNewer(currentVersion, gr.TagName) {
		return nil, nil // up to date
	}

	// Find the lazyvpn binary asset. Match the platform-suffixed name
	// pattern GitHub releases typically use (lazyvpn-linux-amd64), with a
	// single-asset fallback (a release with one binary is unambiguous).
	// Plain "lazyvpn" is also accepted for releases that don't suffix.
	assetURL := ""
	for _, a := range gr.Assets {
		if a.Name == "lazyvpn" ||
			(strings.Contains(a.Name, "linux") && strings.Contains(a.Name, "amd64")) {
			assetURL = a.BrowserDownloadURL
			break
		}
	}
	if assetURL == "" && len(gr.Assets) == 1 {
		assetURL = gr.Assets[0].BrowserDownloadURL
	}

	return &Release{
		TagName:     gr.TagName,
		Body:        gr.Body,
		PublishedAt: gr.PublishedAt,
		AssetURL:    assetURL,
	}, nil
}

// Apply downloads the release binary and replaces the current executable.
// After replacement, it attempts to set file capabilities (silent on failure).
func Apply(release *Release, binaryPath string) error {
	if release.AssetURL == "" {
		return fmt.Errorf("no download URL available for this release")
	}

	ctx, cancel := context.WithTimeout(context.Background(), downloadOverallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", release.AssetURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	resp, err := downloadClient.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	// Write to temp file in the same directory (same filesystem for atomic rename)
	dir := filepath.Dir(binaryPath)
	tmp, err := os.CreateTemp(dir, ".lazyvpn-update-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Clean up on failure
	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath)
		}
	}()

	// Cap the reader at maxBinaryBytes+1 so a binary that hits the cap
	// is detected as overflow rather than silently truncated. A pure
	// LimitReader at exactly maxBinaryBytes returns (cap, nil) on truncation,
	// the ELF magic check still passes (first 4 bytes intact), and the
	// atomic rename installs a corrupt binary that segfaults on next launch.
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxBinaryBytes+1))
	if err != nil {
		tmp.Close()
		return fmt.Errorf("write binary: %w", err)
	}
	// Check Close error before falling through to chmod+rename. On
	// delayed-commit filesystems (NFS / SMB) the io.Copy can return
	// nil while the trailing write is still buffered, with Close
	// surfacing the actual error. Ignoring it lets os.Rename install
	// a truncated binary that passes the ELF magic check (intact
	// first 4 bytes) and segfaults the next time the user runs it.
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close binary: %w", err)
	}

	if n == 0 {
		return fmt.Errorf("downloaded file is empty")
	}
	if n > maxBinaryBytes {
		return fmt.Errorf("downloaded file exceeds %d byte cap — release binary larger than expected", maxBinaryBytes)
	}

	// Verify ELF magic bytes
	f, err := os.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	magic := make([]byte, 4)
	_, err = io.ReadFull(f, magic)
	f.Close()
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if string(magic) != "\x7fELF" {
		return fmt.Errorf("downloaded file is not a valid ELF binary")
	}

	// Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	// Atomic replace
	if err := os.Rename(tmpPath, binaryPath); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}
	success = true

	// Set capabilities — silent on failure (non-sudoers users chose manual sudo)
	_ = setCapFn(binaryPath)

	return nil
}

// IsNewer returns true if latest is a newer semver than current.
// "dev" is always older than any tagged version.
func IsNewer(current, latest string) bool {
	if current == "dev" {
		return latest != "dev"
	}
	if latest == "dev" {
		return false
	}

	curParts := parseSemver(current)
	latParts := parseSemver(latest)

	for i := 0; i < 3; i++ {
		if latParts[i] > curParts[i] {
			return true
		}
		if latParts[i] < curParts[i] {
			return false
		}
	}
	return false // equal
}

// parseSemver extracts [major, minor, patch] from a version string like "v1.2.3".
func parseSemver(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	var result [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		n, _ := strconv.Atoi(parts[i])
		result[i] = n
	}
	return result
}


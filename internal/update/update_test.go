package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsNewer(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{"dev", "v1.0.0", true},
		{"dev", "dev", false},
		{"v1.0.0", "dev", false},
		{"v1.0.0", "v1.0.0", false},
		{"v1.0.0", "v1.0.1", true},
		{"v1.0.0", "v1.1.0", true},
		{"v1.0.0", "v2.0.0", true},
		{"v1.1.0", "v1.0.0", false},
		{"v2.0.0", "v1.9.9", false},
		{"v1.0.1", "v1.0.0", false},
		{"v0.0.1", "v0.0.2", true},
		{"v1.2.3", "v1.2.3", false},
	}
	for _, tt := range tests {
		t.Run(tt.current+"_vs_"+tt.latest, func(t *testing.T) {
			got := IsNewer(tt.current, tt.latest)
			if got != tt.want {
				t.Errorf("IsNewer(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input string
		want  [3]int
	}{
		{"v1.2.3", [3]int{1, 2, 3}},
		{"1.2.3", [3]int{1, 2, 3}},
		{"v0.0.1", [3]int{0, 0, 1}},
		{"v1", [3]int{1, 0, 0}},
		{"v1.2", [3]int{1, 2, 0}},
		{"bad", [3]int{0, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseSemver(tt.input)
			if got != tt.want {
				t.Errorf("parseSemver(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCheckUpToDate(t *testing.T) {
	release := githubRelease{
		TagName:     "v1.0.0",
		Body:        "Initial release",
		PublishedAt: "2026-01-01T00:00:00Z",
		Assets: []githubAsset{
			{Name: "lazyvpn-linux-amd64", BrowserDownloadURL: "https://example.com/lazyvpn"},
		},
	}
	data, _ := json.Marshal(release)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer srv.Close()

	// Override the API URL by patching httpClient to use test server
	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	// We can't easily override the URL constant, so instead we test via the mock server
	// by overriding Check to use our server URL. Test the logic directly:
	oldAPI := repoAPI
	repoAPI = srv.URL
	defer func() { repoAPI = oldAPI }()

	rel, err := Check("v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rel != nil {
		t.Errorf("expected nil (up to date), got %+v", rel)
	}
}

func TestCheckUpdateAvailable(t *testing.T) {
	release := githubRelease{
		TagName:     "v2.0.0",
		Body:        "Big update",
		PublishedAt: "2026-03-01T00:00:00Z",
		Assets: []githubAsset{
			{Name: "lazyvpn-linux-amd64", BrowserDownloadURL: "https://example.com/lazyvpn-v2"},
		},
	}
	data, _ := json.Marshal(release)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	oldAPI := repoAPI
	repoAPI = srv.URL
	defer func() { repoAPI = oldAPI }()

	rel, err := Check("v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rel == nil {
		t.Fatal("expected release, got nil")
	}
	if rel.TagName != "v2.0.0" {
		t.Errorf("TagName = %q, want %q", rel.TagName, "v2.0.0")
	}
	if rel.Body != "Big update" {
		t.Errorf("Body = %q, want %q", rel.Body, "Big update")
	}
	if rel.AssetURL != "https://example.com/lazyvpn-v2" {
		t.Errorf("AssetURL = %q, want %q", rel.AssetURL, "https://example.com/lazyvpn-v2")
	}
}

// TestCheckAssetNameVariants exercises the asset-matching logic for the
// three release-naming conventions we accept: bare "lazyvpn", platform-
// suffixed "lazyvpn-linux-amd64" (the most common GitHub release name),
// and a single-asset fallback (release with one binary, any name).
// Production previously matched only "lazyvpn" exactly, so the typical
// platform-suffixed naming would have left assetURL empty.
func TestCheckAssetNameVariants(t *testing.T) {
	tests := []struct {
		name    string
		assets  []githubAsset
		wantURL string
	}{
		{
			name:    "bare lazyvpn",
			assets:  []githubAsset{{Name: "lazyvpn", BrowserDownloadURL: "https://e/bare"}},
			wantURL: "https://e/bare",
		},
		{
			name:    "platform suffixed",
			assets:  []githubAsset{{Name: "lazyvpn-linux-amd64", BrowserDownloadURL: "https://e/p"}},
			wantURL: "https://e/p",
		},
		{
			name: "platform suffixed with sibling",
			assets: []githubAsset{
				{Name: "checksums.txt", BrowserDownloadURL: "https://e/c"},
				{Name: "lazyvpn-linux-amd64", BrowserDownloadURL: "https://e/p"},
			},
			wantURL: "https://e/p",
		},
		{
			name:    "single asset fallback (unrecognized name)",
			assets:  []githubAsset{{Name: "release-bundle.tar.gz", BrowserDownloadURL: "https://e/single"}},
			wantURL: "https://e/single",
		},
		{
			name:    "no matching asset (multiple unrecognized)",
			assets:  []githubAsset{{Name: "a.txt", BrowserDownloadURL: "https://e/a"}, {Name: "b.txt", BrowserDownloadURL: "https://e/b"}},
			wantURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := json.Marshal(githubRelease{TagName: "v9.9.9", Assets: tt.assets})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write(data)
			}))
			defer srv.Close()

			oldClient := httpClient
			httpClient = srv.Client()
			defer func() { httpClient = oldClient }()
			oldAPI := repoAPI
			repoAPI = srv.URL
			defer func() { repoAPI = oldAPI }()

			rel, err := Check("v1.0.0")
			if err != nil {
				t.Fatalf("Check error: %v", err)
			}
			if rel == nil {
				t.Fatal("expected release, got nil")
			}
			if rel.AssetURL != tt.wantURL {
				t.Errorf("AssetURL = %q, want %q", rel.AssetURL, tt.wantURL)
			}
		})
	}
}

// TestCheckGenericNonOKStatus pins the catch-all branch:
//
//   if resp.StatusCode != http.StatusOK {
//     return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
//   }
//
// Specific branches handle 403 (rate limit) and 404 (no releases).
// Every other non-200 (500/502/503/etc.) falls through this catch-all
// — common during GitHub Actions deploy incidents and brief Edge
// outages.
//
// Without this test, a regression that dropped the catch-all would
// proceed to ReadAll on an error-page HTML body, then json.Unmarshal
// would fail with "invalid character '<' looking for beginning of
// value" — confusing the user with a JSON parse error when the
// actual problem is GitHub being down.
//
// Two sub-tests cover representative status codes (500 + 502).
func TestCheckGenericNonOKStatus(t *testing.T) {
	for _, status := range []int{500, 502} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				w.Write([]byte("<html>oops</html>"))
			}))
			defer srv.Close()

			oldClient := httpClient
			httpClient = srv.Client()
			defer func() { httpClient = oldClient }()
			oldAPI := repoAPI
			repoAPI = srv.URL
			defer func() { repoAPI = oldAPI }()

			_, err := Check("v1.0.0")
			if err == nil {
				t.Fatalf("expected error for status %d, got nil", status)
			}
			if !strings.Contains(err.Error(), "GitHub API returned") {
				t.Errorf("error should mention 'GitHub API returned', got: %v", err)
			}
			// The status code itself must appear so the user can
			// distinguish 500 vs 502 vs 503 etc.
			if !strings.Contains(err.Error(), fmt.Sprintf("%d", status)) {
				t.Errorf("error should include status code %d, got: %v", status, err)
			}
		})
	}
}

func TestCheckRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	oldAPI := repoAPI
	repoAPI = srv.URL
	defer func() { repoAPI = oldAPI }()

	_, err := Check("v1.0.0")
	if err == nil {
		t.Fatal("expected error for 403, got nil")
	}
	if err.Error() != "GitHub API rate limit exceeded" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	oldAPI := repoAPI
	repoAPI = srv.URL
	defer func() { repoAPI = oldAPI }()

	_, err := Check("v1.0.0")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestCheckDevVersionAlwaysUpgradable(t *testing.T) {
	release := githubRelease{
		TagName: "v0.0.1",
		Body:    "First release",
		Assets: []githubAsset{
			{Name: "lazyvpn-linux-amd64", BrowserDownloadURL: "https://example.com/bin"},
		},
	}
	data, _ := json.Marshal(release)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	oldAPI := repoAPI
	repoAPI = srv.URL
	defer func() { repoAPI = oldAPI }()

	rel, err := Check("dev")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rel == nil {
		t.Fatal("expected release for dev version, got nil")
	}
}

func TestApply(t *testing.T) {
	// Create a fake "current binary"
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "lazyvpn")
	os.WriteFile(binaryPath, []byte("old binary"), 0755)

	// Create a fake ELF binary to serve
	elfBinary := append([]byte("\x7fELF"), make([]byte, 100)...)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(elfBinary)
	}))
	defer srv.Close()

	// Mock setcap to do nothing
	oldSetCap := setCapFn
	setCapCalled := false
	setCapFn = func(path string) error {
		setCapCalled = true
		return nil
	}
	defer func() { setCapFn = oldSetCap }()

	rel := &Release{
		TagName:  "v2.0.0",
		AssetURL: srv.URL + "/lazyvpn-linux-amd64",
	}

	err := Apply(rel, binaryPath)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Verify binary was replaced
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if string(data[:4]) != "\x7fELF" {
		t.Errorf("binary doesn't start with ELF magic: %x", data[:4])
	}

	if !setCapCalled {
		t.Error("setcap was not called")
	}
}

func TestApplyEmptyFile(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "lazyvpn")
	os.WriteFile(binaryPath, []byte("old"), 0755)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Empty response
	}))
	defer srv.Close()

	oldSetCap := setCapFn
	setCapFn = func(path string) error { return nil }
	defer func() { setCapFn = oldSetCap }()

	rel := &Release{
		TagName:  "v2.0.0",
		AssetURL: srv.URL + "/lazyvpn",
	}

	err := Apply(rel, binaryPath)
	if err == nil {
		t.Fatal("expected error for empty download")
	}
}

func TestApplyNotELF(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "lazyvpn")
	os.WriteFile(binaryPath, []byte("old"), 0755)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not an elf binary"))
	}))
	defer srv.Close()

	oldSetCap := setCapFn
	setCapFn = func(path string) error { return nil }
	defer func() { setCapFn = oldSetCap }()

	rel := &Release{
		TagName:  "v2.0.0",
		AssetURL: srv.URL + "/lazyvpn",
	}

	err := Apply(rel, binaryPath)
	if err == nil {
		t.Fatal("expected error for non-ELF download")
	}
}

// TestApplyRejectsOversizedBinary verifies that a release binary larger
// than maxBinaryBytes is detected as overflow and rejected, rather than
// silently truncated to the cap and installed as a corrupt binary.
//
// Pre-fix: io.LimitReader at exactly maxBinaryBytes returned (cap, nil)
// on a server delivering more bytes; the ELF magic check (first 4 bytes)
// still passed, and `lazyvpn update` reported success while the renamed
// binary segfaulted on next launch.
func TestApplyRejectsOversizedBinary(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "lazyvpn")
	os.WriteFile(binaryPath, []byte("old"), 0755)

	// Shrink the cap so we don't have to push 100MB through the test server.
	oldCap := maxBinaryBytes
	maxBinaryBytes = 1024
	defer func() { maxBinaryBytes = oldCap }()

	// Server delivers cap+512 bytes — comfortably over the limit but
	// still tiny in absolute terms. Starts with valid ELF magic so the
	// magic-byte check is not what's stopping us.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		payload := make([]byte, maxBinaryBytes+512)
		copy(payload, []byte("\x7fELF"))
		w.Write(payload)
	}))
	defer srv.Close()

	oldSetCap := setCapFn
	setCapFn = func(path string) error { return nil }
	defer func() { setCapFn = oldSetCap }()

	rel := &Release{
		TagName:  "v2.0.0",
		AssetURL: srv.URL + "/lazyvpn",
	}

	err := Apply(rel, binaryPath)
	if err == nil {
		t.Fatal("expected error for oversized download, got nil — binary would have been silently truncated")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected overflow error, got: %v", err)
	}

	// Verify the original binary on disk was NOT replaced.
	got, _ := os.ReadFile(binaryPath)
	if string(got) != "old" {
		t.Fatalf("binary at %s was replaced despite overflow rejection — got %q", binaryPath, string(got[:min(20, len(got))]))
	}
}

// TestApplyDownloadNon200 pins Apply's HTTP status-check branch:
//
//   if resp.StatusCode != http.StatusOK {
//     return fmt.Errorf("download returned %d", resp.StatusCode)
//   }
//
// Without this branch, Apply would proceed to write an error-page
// HTML body to the temp file, then ELF magic verification would
// reject it with "downloaded file is not a valid ELF binary" —
// confusing error pointing at file format when the actual problem
// is GitHub returning 404/500/etc. on the download URL.
//
// Two sub-tests verify representative status codes plus that the
// status code appears in the error message (so users can debug
// "asset deleted from release" vs "GitHub Edge incident").
func TestApplyDownloadNon200(t *testing.T) {
	for _, status := range []int{404, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				w.Write([]byte("<html>asset not found</html>"))
			}))
			defer srv.Close()

			oldClient := downloadClient
			downloadClient = srv.Client()
			defer func() { downloadClient = oldClient }()

			tmpDir := t.TempDir()
			binPath := filepath.Join(tmpDir, "lazyvpn")
			err := Apply(&Release{AssetURL: srv.URL + "/lazyvpn"}, binPath)
			if err == nil {
				t.Fatalf("expected error for download status %d, got nil", status)
			}
			if !strings.Contains(err.Error(), "download returned") {
				t.Errorf("error should mention 'download returned', got: %v", err)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("%d", status)) {
				t.Errorf("error should include status code %d, got: %v", status, err)
			}
			// Binary must NOT have been written.
			if _, statErr := os.Stat(binPath); !os.IsNotExist(statErr) {
				t.Errorf("binary path should not exist after failed download, stat err = %v", statErr)
			}
		})
	}
}

func TestApplyNoURL(t *testing.T) {
	rel := &Release{
		TagName:  "v2.0.0",
		AssetURL: "",
	}

	err := Apply(rel, "/tmp/lazyvpn-test")
	if err == nil {
		t.Fatal("expected error for empty asset URL")
	}
}

// TestApply_ResponseHeaderTimeout verifies the download client gives
// up if the server accepts the connection but never sends headers,
// rather than hanging indefinitely. Previously downloadClient had no
// timeout at all — a stalled CDN would hang lazyvpn update forever.
func TestApply_ResponseHeaderTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("network-timing test")
	}
	// Override the transport for this test with a tight timeout so we
	// don't have to wait the production 30s. Restore on cleanup.
	origClient := downloadClient
	downloadClient = &http.Client{
		Transport: &http.Transport{
			ResponseHeaderTimeout: 200 * time.Millisecond,
		},
	}
	t.Cleanup(func() { downloadClient = origClient })

	// Server that accepts the connection but never writes a response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection so net/http doesn't auto-flush headers
		// when we return. We hold it open and never write.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server doesn't support hijack")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		// Hold open until the test cleanup closes us via srv.Close().
		// We don't close conn ourselves — the test's deadline is the
		// timeout we're testing.
		<-r.Context().Done()
		conn.Close()
	}))
	t.Cleanup(srv.Close)

	binDir := t.TempDir()
	rel := &Release{TagName: "v9.9.9", AssetURL: srv.URL + "/lazyvpn"}

	start := time.Now()
	err := Apply(rel, filepath.Join(binDir, "lazyvpn"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	// Must complete well under what the production 20-minute overall
	// deadline would have allowed — proves ResponseHeaderTimeout fired.
	if elapsed > 5*time.Second {
		t.Errorf("Apply took %v, expected fast failure under header timeout", elapsed)
	}
	// Error should mention timeout / deadline / EOF.
	es := err.Error()
	if !(strings.Contains(es, "timeout") || strings.Contains(es, "deadline") || strings.Contains(es, "Timeout") || strings.Contains(es, "EOF")) {
		t.Errorf("error %q does not look like a timeout", es)
	}
}

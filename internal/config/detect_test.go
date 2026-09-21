package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDetectDistroOmarchy(t *testing.T) {
	tmpDir := t.TempDir()
	omarchyDir := filepath.Join(tmpDir, "omarchy-marker")
	os.MkdirAll(omarchyDir, 0755)

	origCheck := omarchyDirCheck
	omarchyDirCheck = func() string { return omarchyDir }
	t.Cleanup(func() { omarchyDirCheck = origCheck })

	got := DetectDistro()
	if got != "omarchy" {
		t.Errorf("DetectDistro() = %q, want 'omarchy'", got)
	}
}

func TestDetectDistroFromOSRelease(t *testing.T) {
	tmpDir := t.TempDir()

	// No omarchy dir
	origCheck := omarchyDirCheck
	omarchyDirCheck = func() string { return filepath.Join(tmpDir, "nonexistent") }
	t.Cleanup(func() { omarchyDirCheck = origCheck })

	// Create fake /etc/os-release
	osRelease := filepath.Join(tmpDir, "os-release")
	os.WriteFile(osRelease, []byte(`NAME="Arch Linux"
ID=arch
PRETTY_NAME="Arch Linux"
`), 0644)

	origFile := osReleaseFile
	osReleaseFile = osRelease
	t.Cleanup(func() { osReleaseFile = origFile })

	got := DetectDistro()
	if got != "arch" {
		t.Errorf("DetectDistro() = %q, want 'arch'", got)
	}
}

func TestDetectDistroQuotedID(t *testing.T) {
	tmpDir := t.TempDir()

	origCheck := omarchyDirCheck
	omarchyDirCheck = func() string { return filepath.Join(tmpDir, "nonexistent") }
	t.Cleanup(func() { omarchyDirCheck = origCheck })

	osRelease := filepath.Join(tmpDir, "os-release")
	os.WriteFile(osRelease, []byte(`ID="ubuntu"
`), 0644)

	origFile := osReleaseFile
	osReleaseFile = osRelease
	t.Cleanup(func() { osReleaseFile = origFile })

	got := DetectDistro()
	if got != "ubuntu" {
		t.Errorf("DetectDistro() = %q, want 'ubuntu'", got)
	}
}

func TestDetectDistroFallbackLinux(t *testing.T) {
	tmpDir := t.TempDir()

	origCheck := omarchyDirCheck
	omarchyDirCheck = func() string { return filepath.Join(tmpDir, "nonexistent") }
	t.Cleanup(func() { omarchyDirCheck = origCheck })

	// No os-release file
	origFile := osReleaseFile
	osReleaseFile = filepath.Join(tmpDir, "no-such-file")
	t.Cleanup(func() { osReleaseFile = origFile })

	got := DetectDistro()
	if got != "linux" {
		t.Errorf("DetectDistro() = %q, want 'linux'", got)
	}
}

func TestDetectDistroEmptyID(t *testing.T) {
	tmpDir := t.TempDir()

	origCheck := omarchyDirCheck
	omarchyDirCheck = func() string { return filepath.Join(tmpDir, "nonexistent") }
	t.Cleanup(func() { omarchyDirCheck = origCheck })

	osRelease := filepath.Join(tmpDir, "os-release")
	os.WriteFile(osRelease, []byte("ID=\nNAME=Test\n"), 0644)

	origFile := osReleaseFile
	osReleaseFile = osRelease
	t.Cleanup(func() { osReleaseFile = origFile })

	got := DetectDistro()
	if got != "linux" {
		t.Errorf("DetectDistro() = %q, want 'linux' for empty ID", got)
	}
}

func TestDetectFSTypeBtrfs(t *testing.T) {
	origStatfs := statfsFunc
	statfsFunc = func(path string, stat *syscall.Statfs_t) error {
		stat.Type = btrfsMagic
		return nil
	}
	t.Cleanup(func() { statfsFunc = origStatfs })

	got := DetectFSType("/")
	if got != "btrfs" {
		t.Errorf("DetectFSType() = %q, want 'btrfs'", got)
	}
}

func TestDetectFSTypeExt4(t *testing.T) {
	origStatfs := statfsFunc
	statfsFunc = func(path string, stat *syscall.Statfs_t) error {
		stat.Type = ext4Magic
		return nil
	}
	t.Cleanup(func() { statfsFunc = origStatfs })

	got := DetectFSType("/")
	if got != "ext4" {
		t.Errorf("DetectFSType() = %q, want 'ext4'", got)
	}
}

func TestDetectFSTypeXFS(t *testing.T) {
	origStatfs := statfsFunc
	statfsFunc = func(path string, stat *syscall.Statfs_t) error {
		stat.Type = xfsMagic
		return nil
	}
	t.Cleanup(func() { statfsFunc = origStatfs })

	got := DetectFSType("/")
	if got != "xfs" {
		t.Errorf("DetectFSType() = %q, want 'xfs'", got)
	}
}

func TestDetectFSTypeUnknown(t *testing.T) {
	origStatfs := statfsFunc
	statfsFunc = func(path string, stat *syscall.Statfs_t) error {
		stat.Type = 0x12345678
		return nil
	}
	t.Cleanup(func() { statfsFunc = origStatfs })

	got := DetectFSType("/")
	if got != "unknown" {
		t.Errorf("DetectFSType() = %q, want 'unknown'", got)
	}
}

func TestDetectFSTypeError(t *testing.T) {
	origStatfs := statfsFunc
	statfsFunc = func(path string, stat *syscall.Statfs_t) error {
		return syscall.ENOENT
	}
	t.Cleanup(func() { statfsFunc = origStatfs })

	got := DetectFSType("/nonexistent")
	if got != "unknown" {
		t.Errorf("DetectFSType() = %q, want 'unknown' on error", got)
	}
}

// ---------------------------------------------------------------------------
// DetectDistroFamily
// ---------------------------------------------------------------------------

// setOSRelease writes an os-release file with the given content and points
// detection at it for the duration of the test.
func setOSRelease(t *testing.T, content string) {
	t.Helper()
	osRelease := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(osRelease, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	origFile := osReleaseFile
	osReleaseFile = osRelease
	t.Cleanup(func() { osReleaseFile = origFile })
}

func TestDetectDistroFamily(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		// Direct IDs
		{"arch", "ID=arch\n", "arch"},
		{"debian", "ID=debian\n", "debian"},
		{"ubuntu", `ID=ubuntu` + "\n" + `ID_LIKE=debian` + "\n", "debian"},
		{"fedora", "ID=fedora\n", "fedora"},
		{"opensuse-tumbleweed", `ID="opensuse-tumbleweed"` + "\n" + `ID_LIKE="opensuse suse"` + "\n", "suse"},
		// Derivatives classify by ID_LIKE lineage
		{"cachyos", `ID=cachyos` + "\n" + `ID_LIKE=arch` + "\n", "arch"},
		{"pop", `ID=pop` + "\n" + `ID_LIKE="ubuntu debian"` + "\n", "debian"},
		{"centos", `ID="centos"` + "\n" + `ID_LIKE="rhel fedora"` + "\n", "fedora"},
		// ID wins over ID_LIKE when both map
		{"id-wins", "ID=debian\nID_LIKE=arch\n", "debian"},
		// Unknowns
		{"gentoo", "ID=gentoo\n", "unknown"},
		{"empty", "\n", "unknown"},
		{"quoted-id", `ID="arch"` + "\n", "arch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setOSRelease(t, tc.content)
			if got := DetectDistroFamily(); got != tc.want {
				t.Errorf("DetectDistroFamily() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDetectDistroFamilyMissingFile(t *testing.T) {
	origFile := osReleaseFile
	osReleaseFile = filepath.Join(t.TempDir(), "no-such-file")
	t.Cleanup(func() { osReleaseFile = origFile })
	if got := DetectDistroFamily(); got != "unknown" {
		t.Errorf("DetectDistroFamily() = %q, want \"unknown\" for missing os-release", got)
	}
}

// Family() prefers the stored value; empty falls through to detection.
// The Omarchy hierarchy: family NEVER decides an Omarchy feature —
// IsOmarchy() stays marker/Distro-based and is independent of family.
func TestConfigFamilyStoredAndFallback(t *testing.T) {
	setOSRelease(t, "ID=debian\n")
	c := &Config{DistroFamily: "arch"}
	if got := c.Family(); got != "arch" {
		t.Errorf("Family() = %q, want stored \"arch\"", got)
	}
	c2 := &Config{} // pre-scaffold config: no stored family → detect
	if got := c2.Family(); got != "debian" {
		t.Errorf("Family() = %q, want detected \"debian\"", got)
	}
	// Omarchy identity is orthogonal to family
	c3 := &Config{Distro: "omarchy", DistroFamily: "arch"}
	if !c3.IsOmarchy() {
		t.Error("IsOmarchy() must key off Distro, independent of family")
	}
}

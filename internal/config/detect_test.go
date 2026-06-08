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

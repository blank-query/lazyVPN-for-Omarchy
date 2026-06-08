package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Filesystem magic numbers
const (
	btrfsMagic = 0x9123683E
	ext4Magic  = 0xEF53
	xfsMagic   = 0x58465342
)

// omarchyDirCheck is replaceable in tests.
var omarchyDirCheck = func() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "omarchy")
}

// osReleaseFile is replaceable in tests.
var osReleaseFile = "/etc/os-release"

// statfsFunc is replaceable in tests.
var statfsFunc = func(path string, stat *syscall.Statfs_t) error {
	return syscall.Statfs(path, stat)
}

// DetectDistro detects the Linux distribution.
// Returns "omarchy" if the Omarchy marker directory exists,
// otherwise parses /etc/os-release for the ID= field.
// Falls back to "linux" if detection fails.
func DetectDistro() string {
	// Check for Omarchy marker directory
	omarchyDir := omarchyDirCheck()
	if _, err := os.Stat(omarchyDir); err == nil {
		return "omarchy"
	}

	// Parse /etc/os-release for ID=
	f, err := os.Open(osReleaseFile)
	if err != nil {
		return "linux"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "ID=") {
			value := strings.TrimPrefix(line, "ID=")
			value = strings.Trim(value, "\"'")
			if value != "" {
				return value
			}
		}
	}

	return "linux"
}

// DetectFSType detects the filesystem type at the given path using statfs.
// Returns "btrfs", "ext4", "xfs", or "unknown".
func DetectFSType(path string) string {
	var stat syscall.Statfs_t
	if err := statfsFunc(path, &stat); err != nil {
		return "unknown"
	}
	switch stat.Type {
	case btrfsMagic:
		return "btrfs"
	case ext4Magic:
		return "ext4"
	case xfsMagic:
		return "xfs"
	default:
		return "unknown"
	}
}

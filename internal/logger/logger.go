package logger

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
)

const (
	maxLines    = 1000
	logFileName = "debug.log"
)

// Category represents a log category
type Category string

const (
	Connection  Category = "connection"
	Autorecover Category = "autorecover"
	Firewall    Category = "firewall"
	Provider    Category = "provider"
	Autostart   Category = "autostart"
)

// Logger handles debug logging for LazyVPN
type Logger struct {
	cfg   *config.Config
	mu    sync.Mutex
	lines int
}

var (
	// Patterns to sanitize in safe mode
	ipv4Pattern = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	// IPv6 pattern matches both full and compressed forms:
	// - Full: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
	// - Compressed: 2001:db8::1, ::1, fe80::1%eth0
	ipv6Pattern = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\b|` + // partial groups
		`\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|` + // with :: in middle
		`\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|` + // starting with ::
		`\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|` + // ending with ::
		`\b::1\b`) // loopback
	base64Pattern = regexp.MustCompile(`\b[A-Za-z0-9+/]{43}=\b`) // WireGuard keys are 44 chars with =
	privkeyMarker = regexp.MustCompile(`(?i)(private.?key|privkey)\s*[:=]\s*\S+`)
)

// New creates a new Logger
func New(cfg *config.Config) *Logger {
	return &Logger{cfg: cfg, lines: -1}
}

// Log writes a message if the category is enabled. Snapshots cfg fields
// once via LoggerView so nothing in this call path races with concurrent
// Config.Save / Reload / SaveConnectionState writers.
func (l *Logger) Log(cat Category, format string, args ...interface{}) {
	if l.cfg == nil {
		return
	}

	view := l.cfg.LoggerView()
	if !isEnabledIn(view, cat) {
		return
	}

	msg := fmt.Sprintf(format, args...)
	if view.LogMode != "accurate" {
		msg = sanitizeWith(view, msg)
	}

	l.write(cat, msg)
}

// isEnabled is a thread-safe convenience wrapper for tests and any external
// caller that wants to query a single category. Production callers use
// LoggerView directly to amortize the lock acquisition.
func (l *Logger) isEnabled(cat Category) bool {
	if l.cfg == nil {
		return false
	}
	return isEnabledIn(l.cfg.LoggerView(), cat)
}

// sanitize is a thread-safe convenience wrapper for tests. With a nil cfg
// it still runs the regex passes against an empty view (no real/vpn IPs to
// match), matching the pre-refactor behavior tests rely on.
func (l *Logger) sanitize(msg string) string {
	var v config.LoggerView
	if l.cfg != nil {
		v = l.cfg.LoggerView()
	}
	return sanitizeWith(v, msg)
}

// isEnabledIn checks the snapshot for the given category.
func isEnabledIn(v config.LoggerView, cat Category) bool {
	switch cat {
	case Connection:
		return v.LogConnection
	case Autorecover:
		return v.LogAutorecover
	case Firewall:
		return v.LogFirewall
	case Provider:
		return v.LogProvider
	case Autostart:
		return v.LogAutostart
	}
	return false
}

// sanitizeWith removes sensitive data from log messages with context-sensitive
// placeholders, using the LoggerView snapshot's IP fields (avoids a second
// race-prone read of l.cfg).
func sanitizeWith(v config.LoggerView, msg string) string {
	realIP := v.RealPublicIP
	vpnIP := v.LastPublicIP
	msg = ipv4Pattern.ReplaceAllStringFunc(msg, func(ip string) string {
		if realIP != "" && ip == realIP {
			return "[real public ip]"
		}
		if vpnIP != "" && ip == vpnIP {
			return "[vpn ip]"
		}
		// Check for private/LAN ranges - these are less sensitive
		if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || ip == "127.0.0.1" {
			return "[local ip]"
		}
		// Check 172.16.0.0/12 (only 172.16-31.x.x is private, not all 172.x.x.x)
		if strings.HasPrefix(ip, "172.") {
			parts := strings.SplitN(ip, ".", 3)
			if len(parts) >= 2 {
				if octet, err := strconv.Atoi(parts[1]); err == nil && octet >= 16 && octet <= 31 {
					return "[local ip]"
				}
			}
		}
		return "[server endpoint]"
	})

	// Replace IPv6
	msg = ipv6Pattern.ReplaceAllString(msg, "[ipv6 address]")

	// Replace private key assignments first (more specific)
	msg = privkeyMarker.ReplaceAllString(msg, "[private key]")

	// Replace WireGuard keys (44 char base64)
	msg = base64Pattern.ReplaceAllString(msg, "[wireguard key]")

	return msg
}

// write appends a log line to the file
func (l *Logger) write(cat Category, msg string) {
	logPath := filepath.Join(l.cfg.ConfigDir, logFileName)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] [%s] %s\n", timestamp, cat, msg)

	l.mu.Lock()
	defer l.mu.Unlock()

	// Count existing lines if we haven't yet
	if l.lines < 0 {
		l.countLines(logPath)
	}

	// Rotate if needed. Before doing so, re-sync from disk: another
	// lazyvpn process (daemon vs TUI both writing the same debug.log) may
	// have rotated since we last counted, in which case our cached
	// l.lines is stale and we'd rotate redundantly.
	if l.lines >= maxLines {
		l.countLines(logPath)
		if l.lines >= maxLines {
			l.rotate(logPath)
		}
	}

	// Open file for appending
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	if _, err := f.WriteString(line); err == nil {
		l.lines++
	}
}

// countLines counts existing lines in the log file.
//
// Buffer raised to 1MB so a single oversized log line (e.g. an error
// message containing a long subprocess stderr or sanitized HTTP body)
// doesn't trip bufio.ErrTooLong and silently undercount the rest of
// the file. The default 64KB scanner buffer is the wrong default for
// log-file traversal where pathologically long lines can occur.
func (l *Logger) countLines(path string) {
	f, err := os.Open(path)
	if err != nil {
		l.lines = 0
		return
	}
	defer f.Close()

	l.lines = 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		l.lines++
	}
}

// rotate removes old log entries keeping only the last half.
//
// Buffer raised to 1MB and Err() checked so a single oversized log line
// doesn't trip bufio.ErrTooLong, terminate Scan() early, and cause the
// rotation to silently drop every line that came after the long one.
// Pre-fix the partial slice would be written back as the new file
// content, deleting unrelated subsequent log entries.
func (l *Logger) rotate(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}

	// Read all lines
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		// Read failed mid-stream (oversized line, I/O error). Don't
		// rotate — writing the partial slice back would silently delete
		// the unread tail. Better to leave the log oversized and re-try
		// on the next write; the user can manually truncate if needed.
		f.Close()
		return
	}
	f.Close() // Close before writing to same file (not deferred to release handle earlier)

	// Keep only last half
	keep := maxLines / 2
	if len(lines) > keep {
		lines = lines[len(lines)-keep:]
	}

	// Write to temp file first, then rename for atomicity
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".log.tmp.*")
	if err != nil {
		return
	}
	tmpPath := tmpFile.Name()

	// Clean up on failure
	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath)
		}
	}()

	for _, line := range lines {
		if _, err := tmpFile.WriteString(line + "\n"); err != nil {
			tmpFile.Close()
			return
		}
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return
	}
	// Check Close error before rename — on delayed-commit filesystems
	// Sync can succeed while Close surfaces the actual write error.
	// Ignoring it would let os.Rename install a truncated log, which
	// the next countLines scan would then misreport.
	if err := tmpFile.Close(); err != nil {
		return
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		return
	}

	success = true
	l.lines = len(lines)
}

package sudo

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// connNameRe matches a safe WireGuard interface name: alphanumeric plus
// dot/underscore/dash, 1-15 chars (Linux IFNAMSIZ-1). The same pattern is
// applied at install time in cmd/lazyvpn; we re-apply here as a defence-
// in-depth check because GenerateSudoersContent interpolates connName 18+
// times into a privileged file. A tampered config.json with a newline in
// connection_name could otherwise inject extra sudoers stanzas. visudo
// catches most malformed inputs but a careful injection that's still
// syntactically valid would slip through — fail fast at the source.
var connNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)

// GenerateSudoersContent returns the sudoers file content scoped to the
// given binary path, WireGuard interface name, and detected physical
// interfaces.
//
// cowFilesystem controls which delete tool entries are emitted. On
// copy-on-write filesystems (btrfs, ZFS) shred is theater — it writes new
// extents while the original data remains — so the shred entries are
// omitted. `rm` entries are uniform: primary delete on CoW, fallback on
// non-CoW. Every NOPASSWD line is a privilege grant, so we only emit what
// the runtime actually invokes.
func GenerateSudoersContent(execPath, connName string, physicalIfaces []string, cowFilesystem bool) (string, error) {
	if !connNameRe.MatchString(connName) {
		return "", fmt.Errorf("refusing to generate sudoers: connName %q does not match %s", connName, connNameRe.String())
	}
	// Same defense-in-depth check for every physicalIface. The names
	// are interpolated into sudoers rules via fmt.Sprintf with no
	// escaping; a newline-injected entry like "eth0\n%wheel ALL=(ALL)
	// NOPASSWD: ALL" passes visudo (it's two syntactically valid lines)
	// and grants full root. Currently the names come from
	// DetectPhysicalInterfaces (net.Interfaces, kernel-validated), so
	// unreachable today — but the guard makes the invariant local to
	// the function rather than depending on the caller forever.
	for _, iface := range physicalIfaces {
		if !connNameRe.MatchString(iface) {
			return "", fmt.Errorf("refusing to generate sudoers: iface %q does not match %s", iface, connNameRe.String())
		}
	}
	// Build per-interface host route rules (endpoint routing through physical gateway).
	// If DetectPhysicalInterfaces returned empty, emit nothing — the runtime
	// route-add will fail at use time and surface the underlying problem
	// (net.Interfaces() returning nothing is degenerate enough that a
	// wildcard fallback would mask the real issue).
	var hostRouteRules string
	for _, iface := range physicalIfaces {
		hostRouteRules += fmt.Sprintf("%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip route add * via * dev %s\n", iface)
	}

	// shred entries are only emitted on non-CoW filesystems. On CoW, shred
	// would write to freshly allocated extents while the original data
	// remains on disk, so we don't pretend — and we don't grant privilege
	// that nothing uses. See docs/refactor-delete-api.md (design principles).
	var shredEntries string
	if !cowFilesystem {
		shredEntries = `# shred for root-owned LazyVPN files (ext4/xfs; non-CoW only)
%wheel ALL=(ALL) NOPASSWD: /usr/bin/shred -u /etc/sysctl.d/99-lazyvpn-ipv6.conf
%wheel ALL=(ALL) NOPASSWD: /usr/bin/shred -u /etc/sudoers.d/lazyvpn

`
	}

	return fmt.Sprintf(`# LazyVPN sudoers configuration
# Allow VPN management without password (native netlink approach)
# Interface: %s

# WireGuard interface management (scoped to configured interface name)
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip link add dev %s type wireguard
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip link delete dev %s
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip link set dev %s up
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip link set dev %s down
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip link set dev %s mtu *

# IP address management (scoped to configured interface).
# Note: only 'addr add' is here — addr deletion goes through netlink syscalls,
# never a shell fallback.
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip addr add * dev %s

# IP route commands (split routes + endpoint host route)
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip route add 0.0.0.0/1 dev %s
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip route add 128.0.0.0/1 dev %s
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip route add default dev %s metric *
# Endpoint host route scoped to detected physical interfaces
%s%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip route del 0.0.0.0/1 dev %s
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip route del 128.0.0.0/1 dev %s
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip route del default dev %s

# DNS management via systemd-resolved (scoped to configured interface)
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/resolvectl dns %s *
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/resolvectl domain %s *
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/resolvectl default-route %s *
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/resolvectl revert %s
# Physical interface DNS restore (interface name varies)
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/resolvectl default-route * true
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/resolvectl default-route * false

# File capabilities - set CAP_NET_ADMIN on lazyvpn binary only
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/setcap cap_net_admin\,cap_net_raw+ep %s

# Firewall management - UFW for killswitch, LAN block, stealth, IPv6 protection
# Scoped to specific subcommands (ufw reset stays out — never needed at runtime).
# enable/disable ARE required: the killswitch must be able to activate UFW (a
# deny policy on an inactive firewall enforces nothing) and restore it on exit.
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw --force enable
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw disable
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw status
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw status verbose
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw show added
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw default allow outgoing
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw default allow incoming
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw default deny outgoing
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw default deny incoming
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw allow *
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw deny *
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw reject *
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw delete *
# UFW logging level — enumerate the five accepted values rather than
# allowing 'ufw logging *' which would let any string through.
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw logging off
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw logging low
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw logging medium
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw logging high
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw logging full

# sysctl -p applies the persistent ipv6 conf to the running kernel. Used
# by DisableIPv6 as a fallback when /proc writes EACCES — happens during
# the install flow because file caps on the binary don't activate until
# next exec. Exact-argv match: only the lazyvpn .conf path is allowed.
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/sysctl -p /etc/sysctl.d/99-lazyvpn-ipv6.conf

# No 'systemctl restart/reload systemd-networkd' entry — the rewrite uses
# netlink directly and never manages networkd drop-in files.

# Journal daemon control during log scrubbing. Journal file deletion itself
# has no NOPASSWD entry — log destruction must escalate to interactive sudo
# so the user consciously authenticates for it.
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/systemctl start systemd-journald
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop systemd-journald

# No NOPASSWD entry for 'snapper delete' — the uninstaller's snapshot purge
# modifies base-OS state and must require manual authentication, same as
# journal file deletion. sudo prompts interactively at purge time.

# IPv6 leak protection — persistent kernel disable.
# tee writes the conf at toggle time (filesystem DAC needs root, capabilities
# don't help). Exact-argv match: only this specific destination is allowed.
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/sysctl.d/99-lazyvpn-ipv6.conf

%s# rm for root-owned LazyVPN files (primary on CoW filesystems, fallback on non-CoW)
# Note: no -f flag — runtime calls bare 'rm' so missing files surface via
# stderr ('No such file') and can be classified as NotPresent rather than
# silently masked as success.
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/rm /etc/sysctl.d/99-lazyvpn-ipv6.conf
%%wheel ALL=(ALL) NOPASSWD: /usr/bin/rm /etc/sudoers.d/lazyvpn
`,
		// Comment: interface name
		connName,
		// ip link: add, delete, set up, set down, set mtu
		connName, connName, connName, connName, connName,
		// ip addr: add (no del — netlink syscall handles deletion)
		connName,
		// ip route add: split 0/1, split 128/1, default
		connName, connName, connName,
		// endpoint host route rules (per physical interface)
		hostRouteRules,
		// ip route del: split 0/1, split 128/1, default
		connName, connName, connName,
		// resolvectl: dns, domain, default-route, revert
		connName, connName, connName, connName,
		// setcap
		execPath,
		// CoW-conditional shred entries (empty string on CoW)
		shredEntries,
	), nil
}

// DetectPhysicalInterfaces returns the names of all non-virtual, non-VPN
// network interfaces on the system (e.g. eth0, wlan0, enp3s0).
func DetectPhysicalInterfaces() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var physical []string
	for _, iface := range ifaces {
		name := iface.Name
		// Skip loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// Skip VPN/virtual interfaces
		if isVirtualInterface(name) {
			continue
		}
		physical = append(physical, name)
	}
	return physical
}

// isVirtualInterface returns true for known VPN and virtual interface prefixes.
func isVirtualInterface(name string) bool {
	prefixes := []string{"wg", "tun", "tap", "nordlynx", "proton", "mullvad",
		"veth", "br-", "docker", "virbr", "vbox", "vmnet"}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// InstallSudoers writes the sudoers file for the given binary and interface name.
// Detects physical interfaces for scoped host route rules. cowFilesystem
// controls whether shred entries are emitted (see GenerateSudoersContent).
// Uses visudo to validate syntax before installing. Requires sudo.
// Returns nil on success, error on failure.
var InstallSudoers = func(execPath, connName string, cowFilesystem bool) error {
	physicalIfaces := DetectPhysicalInterfaces()
	content, err := GenerateSudoersContent(execPath, connName, physicalIfaces, cowFilesystem)
	if err != nil {
		return fmt.Errorf("sudoers content generation: %w", err)
	}

	// Write to temp file in a private directory. Go 1.16+ MkdirTemp uses
	// mode 0700 by default — no separate Chmod needed (the prior
	// post-MkdirTemp Chmod implied the author was uncertain, but the doc
	// guarantees 0700 since 1.16).
	tmpDir, err := os.MkdirTemp("", "lazyvpn-sudoers-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpPath := filepath.Join(tmpDir, "lazyvpn")
	if err := os.WriteFile(tmpPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write temp sudoers file: %w", err)
	}

	// Validate syntax with visudo. All three install steps bounded
	// with 10s — even though install runs interactively where a hang
	// is visible to the user, sudo can wedge for non-obvious reasons
	// (NSS hang on group lookup) and leaving a timeout in place keeps
	// behavior consistent across all sudo call sites in this codebase.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	visudoCmd := exec.CommandContext(ctx, "sudo", "-n", "visudo", "-cf", tmpPath)
	SetCLocale(visudoCmd)
	if out, err := visudoCmd.CombinedOutput(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("sudoers visudo timed out — sudo may be wedged")
		}
		if IsAuthError(out) {
			return fmt.Errorf("sudoers syntax validation: %w", ErrAuthRequired)
		}
		return fmt.Errorf("sudoers syntax validation failed: %w", err)
	}

	// Install
	cpCtx, cpCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cpCancel()
	cpCmd := exec.CommandContext(cpCtx, "sudo", "-n", "cp", tmpPath, "/etc/sudoers.d/lazyvpn")
	SetCLocale(cpCmd)
	if out, err := cpCmd.CombinedOutput(); err != nil {
		if cpCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("sudoers cp timed out — sudo may be wedged")
		}
		if IsAuthError(out) {
			return fmt.Errorf("sudoers install: %w", ErrAuthRequired)
		}
		return fmt.Errorf("failed to install sudoers file: %w", err)
	}

	chmodCtx, chmodCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer chmodCancel()
	chmodCmd := exec.CommandContext(chmodCtx, "sudo", "-n", "chmod", "0440", "/etc/sudoers.d/lazyvpn")
	SetCLocale(chmodCmd)
	if out, err := chmodCmd.CombinedOutput(); err != nil {
		if chmodCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("sudoers chmod timed out — sudo may be wedged")
		}
		if IsAuthError(out) {
			return fmt.Errorf("sudoers permissions: %w", ErrAuthRequired)
		}
		return fmt.Errorf("failed to set sudoers permissions: %w", err)
	}

	return nil
}

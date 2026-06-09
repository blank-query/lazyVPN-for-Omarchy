package firewall

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
)

// ufwStateMarker records that lazyvpn was the one to activate UFW, so the
// teardown path can disable it again without clobbering a UFW the user had on.
// A package var so tests can point it at a temp path.
var ufwStateMarker = defaultUFWStateMarker()

func defaultUFWStateMarker() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/tmp/.lazyvpn-ufw-enabled"
	}
	return filepath.Join(home, ".config", "lazyvpn", ".ufw-enabled-by-lazyvpn")
}


// ufwIsEnabled reports whether UFW is currently active.
func ufwIsEnabled() bool {
	out, err := runUFW.Run("status")
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Status: active")
}

// ensureUFWEnabled activates UFW if it isn't already. Without this, setting a
// deny policy on an inactive firewall enforces nothing AND `ufw status verbose`
// reports no Default line, so IsActive() reads false and the UI flips the
// toggle back off. Records a marker so teardown can restore the prior state.
func ensureUFWEnabled() error {
	if ufwIsEnabled() {
		return nil
	}
	if _, err := runUFW.Run("--force", "enable"); err != nil {
		return fmt.Errorf("ufw --force enable: %w", err)
	}
	// Best-effort marker; if it can't be written we simply won't auto-disable.
	if err := os.MkdirAll(filepath.Dir(ufwStateMarker), 0700); err == nil {
		_ = os.WriteFile(ufwStateMarker, []byte("1\n"), 0600)
	}
	return nil
}

// maybeRestoreUFW disables UFW only if lazyvpn enabled it (marker present) AND
// no lazyvpn rules remain (killswitch, LAN block/stealth, IPv6 all off). A
// firewall the user already had on, or one still backing another feature, is
// left untouched.
func maybeRestoreUFW() {
	if _, err := os.Stat(ufwStateMarker); err != nil {
		return // we didn't enable it
	}
	if hasRulesWithTag(TagKillswitch) || hasRulesWithTag(TagLANBlock) ||
		hasRulesWithTag(TagStealth) || hasRulesWithTag(TagLANAllow) ||
		hasRulesWithTag(TagIPv6) {
		return // another feature still needs UFW active
	}
	if _, err := runUFW.Run("disable"); err != nil {
		log("Warning: failed to disable UFW during teardown: %v", err)
		return
	}
	_ = os.Remove(ufwStateMarker)
}

// validateIP checks that addr is a valid IP address (no CIDR notation, no ports).
func validateIP(addr string) bool {
	return net.ParseIP(addr) != nil
}

// logFuncMu protects LogFunc from concurrent read/write
var logFuncMu sync.RWMutex

// LogFunc is a callback for logging firewall events
var LogFunc func(format string, args ...interface{})

// SetLogFunc safely sets the logging callback
func SetLogFunc(f func(format string, args ...interface{})) {
	logFuncMu.Lock()
	LogFunc = f
	logFuncMu.Unlock()
}

// log writes to the log callback if set
func log(format string, args ...interface{}) {
	logFuncMu.RLock()
	fn := LogFunc
	logFuncMu.RUnlock()
	if fn != nil {
		fn(format, args...)
	}
}

// KillswitchConfig holds configuration for killswitch rules.
//
// The killswitch owns leak prevention ONLY — it forces outbound through the
// tunnel and rejects anything else leaving the physical interface. It does
// NOT touch LAN/private-CIDR traffic: the Local Network layer (Allow/Stealth/
// Block, tags la/st/lb) owns those rules independently and always, whether or
// not the killswitch is engaged. The LAN layer's allow-out rules carry lower
// UFW rule numbers than the killswitch's physical-interface reject, so LAN
// traffic survives the killswitch by first-match ordering.
type KillswitchConfig struct {
	InterfaceName string
	DNS           string
	Endpoint      string
}

// ufwMu protects all UFW operations to prevent concurrent modifications
var ufwMu sync.Mutex

// Comment tags for identifying LazyVPN rules
const (
	TagKillswitch = "lazyvpn:ks"
	TagLANBlock   = "lazyvpn:lb"
	TagStealth    = "lazyvpn:st"
	TagLANAllow   = "lazyvpn:la"
	TagIPv6       = "lazyvpn:v6"
)

// privateCIDRsV4 are IPv4 private address ranges
var privateCIDRsV4 = []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "169.254.0.0/16"}

// privateCIDRsV6 are IPv6 private address ranges
var privateCIDRsV6 = []string{"fe80::/10", "fc00::/7"}

// addRule is a helper that runs a ufw command and returns any error.
func addRule(args ...string) error {
	_, err := runUFW.Run(args...)
	return err
}

// Enable activates the killswitch with the given configuration.
func Enable(cfg *KillswitchConfig) error {
	ufwMu.Lock()
	defer ufwMu.Unlock()
	return enableLocked(cfg)
}

// enableLocked implements Enable; caller must hold ufwMu.
func enableLocked(cfg *KillswitchConfig) error {
	log("Enabling killswitch (interface=%s, endpoint=%s)", cfg.InterfaceName, cfg.Endpoint)

	// Save previous default policy for rollback
	prevPolicy := getDefaultOutgoingPolicy()

	// Clean slate — remove any existing killswitch rules
	if err := deleteRulesByTag(TagKillswitch); err != nil {
		log("Warning: failed to clean existing killswitch rules: %v", err)
	}

	// Rollback on failure: restore previous policy and delete added rules.
	// Preserve whatever the policy was — including "deny" — so we don't
	// silently regress security. If we couldn't read the previous policy
	// (prevPolicy == ""), default to "allow" since most systems start there
	// and the safer guess is "user could reach the internet before".
	success := false
	defer func() {
		if !success {
			log("Killswitch enable failed, rolling back")
			deleteRulesByTag(TagKillswitch)
			restorePolicy := prevPolicy
			if restorePolicy == "" {
				restorePolicy = "allow"
			}
			addRule("default", restorePolicy, "outgoing")
			maybeRestoreUFW()
		}
	}()

	// Add all allow rules BEFORE setting default deny, so we don't
	// kill an active VPN connection during the transition.

	// Allow loopback (both directions)
	if err := addRule("allow", "out", "on", "lo", "comment", TagKillswitch); err != nil {
		return err
	}
	if err := addRule("allow", "in", "on", "lo", "comment", TagKillswitch); err != nil {
		return err
	}

	// Allow DNS (supports comma-separated list)
	if cfg.DNS != "" {
		for _, dnsAddr := range strings.Split(cfg.DNS, ",") {
			dnsAddr = strings.TrimSpace(dnsAddr)
			if dnsAddr == "" {
				continue
			}
			if !validateIP(dnsAddr) {
				log("Skipping invalid DNS address: %s", dnsAddr)
				continue
			}
			if err := addRule("allow", "out", "proto", "udp", "to", dnsAddr, "port", "53", "comment", TagKillswitch); err != nil {
				return err
			}
			if err := addRule("allow", "out", "proto", "tcp", "to", dnsAddr, "port", "53", "comment", TagKillswitch); err != nil {
				return err
			}
		}
	}

	// Allow VPN endpoint
	if cfg.Endpoint != "" {
		if !validateIP(cfg.Endpoint) {
			return fmt.Errorf("invalid endpoint IP: %q", cfg.Endpoint)
		}
		if err := addRule("allow", "out", "to", cfg.Endpoint, "comment", TagKillswitch); err != nil {
			return err
		}
	}

	// Physical-interface carve-outs: VPN endpoint, the gateway, and DHCP.
	physIface, gateway, _ := GetPhysicalInterface()
	if physIface != "" && cfg.InterfaceName != "" {
		// Allow endpoint on physical interface
		if cfg.Endpoint != "" {
			if err := addRule("allow", "out", "on", physIface, "to", cfg.Endpoint, "comment", TagKillswitch); err != nil {
				return err
			}
		}
		// Allow the gateway BOTH directions — required for any network access
		// in EVERY LAN mode. The gateway lives inside a private CIDR, so this
		// must precede the LAN deny rules added later (UFW is first-match).
		if gateway != "" {
			if err := addRule("allow", "out", "on", physIface, "to", gateway, "comment", TagKillswitch); err != nil {
				return err
			}
			if err := addRule("allow", "in", "on", physIface, "from", gateway, "comment", TagKillswitch); err != nil {
				return err
			}
		}
		// Allow DHCP both directions (lease renewal)
		if err := addRule("allow", "out", "on", physIface, "proto", "udp", "to", "any", "port", "67:68", "comment", TagKillswitch); err != nil {
			return err
		}
		if err := addRule("allow", "in", "on", physIface, "proto", "udp", "from", "any", "port", "67:68", "comment", TagKillswitch); err != nil {
			return err
		}
	}

	// NOTE: LAN/private-CIDR rules are deliberately NOT emitted here. The Local
	// Network layer (EnableLANAllow/EnableLANStealth/EnableLANBlock, tags
	// la/st/lb) owns them as a standing constant. Those rules are added before
	// the killswitch (at install, or re-applied before the killswitch on a mode
	// change) so their lower UFW rule numbers beat the physical-interface reject
	// below — LAN traffic survives the killswitch by first-match ordering.

	// Allow all traffic on the VPN interface (both directions — this is the tunnel)
	if cfg.InterfaceName != "" {
		if err := addRule("allow", "out", "on", cfg.InterfaceName, "comment", TagKillswitch); err != nil {
			return err
		}
		if err := addRule("allow", "in", "on", cfg.InterfaceName, "comment", TagKillswitch); err != nil {
			return err
		}
	}

	// WebRTC/STUN isolation: reject anything ELSE leaving the physical interface.
	// MUST be last — after the endpoint/gateway/DHCP/LAN allows — or it would
	// swallow that traffic (UFW first-match) and break LAN/gateway access.
	if physIface != "" && cfg.InterfaceName != "" {
		if err := addRule("reject", "out", "on", physIface, "comment", TagKillswitch); err != nil {
			return err
		}
	}

	// Activate UFW (no-op if already active) so the rules actually enforce, then
	// flip the OUTGOING default to deny — force outbound through the tunnel. The
	// killswitch is outbound-only: it never touches the incoming policy. Inbound
	// is owned by the Local Network layer (Stealth/Block deny it; Allow permits
	// LAN in), and unsolicited WAN inbound can't reach a NAT'd host anyway.
	if err := ensureUFWEnabled(); err != nil {
		return err
	}
	if err := addRule("default", "deny", "outgoing"); err != nil {
		return fmt.Errorf("ufw default deny outgoing: %w", err)
	}

	success = true
	log("Killswitch enabled successfully")
	return nil
}

// Disable deactivates the killswitch (allows all traffic).
func Disable() error {
	ufwMu.Lock()

	log("Disabling killswitch")

	if err := deleteRulesByTag(TagKillswitch); err != nil {
		log("Warning: failed to delete killswitch rules: %v", err)
	}

	if err := addRule("default", "allow", "outgoing"); err != nil {
		ufwMu.Unlock()
		return fmt.Errorf("ufw default allow outgoing: %w", err)
	}

	// Outbound-only killswitch — it never touched the incoming policy, so
	// there's nothing to restore here.

	// If lazyvpn was the one that turned UFW on, and nothing else needs it
	// anymore, turn it back off so we leave the system as we found it.
	maybeRestoreUFW()

	ufwMu.Unlock()

	// The killswitch and Stealth both add the identical DHCP-in rule; UFW
	// dedups by match (ignoring the comment), so the killswitch's tag owned the
	// single rule and the deleteRulesByTag above just removed it — orphaning
	// Stealth's need for DHCP-in. Re-assert Stealth (only it adds a colliding
	// DHCP-in) so its full rule set is restored under the st tag. Done after
	// releasing ufwMu because EnableLANStealth takes the lock itself.
	if IsLANStealthActive() {
		if err := EnableLANStealth(); err != nil {
			log("Warning: failed to re-assert Stealth after killswitch disable: %v", err)
		}
	}

	log("Killswitch disabled successfully")
	return nil
}

// IsActive checks if the killswitch is currently active (default outgoing = deny).
func IsActive() bool {
	return getDefaultOutgoingPolicy() == "deny"
}

// Update updates the killswitch rules with new configuration.
func Update(cfg *KillswitchConfig) error {
	ufwMu.Lock()
	defer ufwMu.Unlock()

	if getDefaultOutgoingPolicy() != "deny" {
		return nil // Killswitch not active, nothing to update
	}
	return enableLocked(cfg)
}

// EnableSimple enables a simple blocking killswitch (when no VPN is connected).
func EnableSimple() error {
	ufwMu.Lock()
	defer ufwMu.Unlock()

	log("Enabling simple killswitch")

	// Save the prior default outgoing policy so a partial failure
	// rolls back to it. Pre-fix the rollback hardcoded "allow", which
	// downgrades killswitch-on-with-custom-policy callers if a UFW
	// rule add fails mid-flight. Now we restore exactly what was
	// there before. (Same pattern enableLocked already uses.)
	prevPolicy := getDefaultOutgoingPolicy()

	// Clean existing rules
	if err := deleteRulesByTag(TagKillswitch); err != nil {
		log("Warning: failed to clean existing killswitch rules: %v", err)
	}

	// Set up rollback NOW, before any state change that could later
	// fail. Pre-fix the loopback-addRule failure path returned early
	// without restoring anything — leaving the system with the
	// existing-killswitch-rules deleted (line above) but default
	// policy unchanged. Now the deferred rollback covers every
	// failure path.
	success := false
	defer func() {
		if !success {
			log("Simple killswitch enable failed, rolling back")
			deleteRulesByTag(TagKillswitch)
			restorePolicy := prevPolicy
			if restorePolicy == "" {
				restorePolicy = "allow"
			}
			addRule("default", restorePolicy, "outgoing")
			maybeRestoreUFW()
		}
	}()

	// Allow loopback (both directions) BEFORE setting default deny, so we don't
	// block systemd-resolved (127.0.0.53) during the transition window.
	if err := addRule("allow", "out", "on", "lo", "comment", TagKillswitch); err != nil {
		return err
	}
	if err := addRule("allow", "in", "on", "lo", "comment", TagKillswitch); err != nil {
		return err
	}

	// No VPN is connected, so there's no tunnel to allow — everything except
	// loopback (and whatever the Local Network layer permits) is blocked. LAN
	// access is NOT handled here: the standing Local Network layer (tags
	// la/st/lb) owns it, and its allow-out rules carry lower UFW rule numbers
	// than this default-deny, so LAN survives by first-match. Simple mode adds
	// no physical-interface reject (there's no tunnel to prevent leaks around),
	// so the default-deny is the only thing the LAN allow rules must beat.

	// Activate UFW, then deny OUTGOING by default — with no tunnel connected,
	// nothing goes out except loopback and the Local Network layer's allowances.
	// Outbound-only: inbound stays the user's policy, owned by the LAN layer.
	if err := ensureUFWEnabled(); err != nil {
		return err
	}
	if err := addRule("default", "deny", "outgoing"); err != nil {
		return fmt.Errorf("ufw default deny outgoing: %w", err)
	}

	success = true
	log("Simple killswitch enabled")
	return nil
}

// ---------------------------------------------------------------------------
// IPv6 disable/enable
// ---------------------------------------------------------------------------

// sysctlIPv6ConfPath is the sysctl config path for persistent IPv6 disable.
// Tests can override this to write to a temp directory.
var sysctlIPv6ConfPath = "/etc/sysctl.d/99-lazyvpn-ipv6.conf"

// File-op vars that tests can override.
//
// writeFile targets the /proc IPv6 controls — those work via CAP_NET_ADMIN
// (no sudo) so plain os.WriteFile suffices.
//
// writeSysctlConf and removeSysctlConf target /etc/sysctl.d/, which is
// 0755 root:root. Capabilities don't help with filesystem DAC, so these
// shell out via sudo -n to entries the installer adds to /etc/sudoers.d/lazyvpn:
//   - 'tee /etc/sysctl.d/99-lazyvpn-ipv6.conf' for the write
//   - 'rm  /etc/sysctl.d/99-lazyvpn-ipv6.conf' for the removal (already
//     present for the uninstaller's IPv6 cleanup; we reuse it).
//
// Tests override these vars to bypass sudo and write to a temp path.
var (
	writeFile        = os.WriteFile
	writeSysctlConf  = sudoTeeSysctlConf
	removeSysctlConf = sudoRmSysctlConf
)

// sudoTeeSysctlConf streams the content into `sudo -n tee <conf>`. Captures
// stderr so an auth failure (NOPASSWD entry missing) surfaces as
// sudo.ErrAuthRequired instead of a generic exit-status error.
//
// Bounded with context.WithTimeout — a wedged sudo (NSS hang, pam stuck)
// would otherwise hang the IPv6 protection toggle (UI-initiated) forever.
func sudoTeeSysctlConf(content string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-n", "tee", sysctlIPv6ConfPath)
	sudo.SetCLocale(cmd) // keep auth-required text English for IsAuthError
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("ipv6 sysctl write timed out — sudo may be wedged")
		}
		if sudo.IsAuthError(stderr.Bytes()) {
			return fmt.Errorf("ipv6 sysctl write: %w", sudo.ErrAuthRequired)
		}
		return fmt.Errorf("ipv6 sysctl write: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// sudoRmSysctlConf invokes the `sudo -n rm <conf>` NOPASSWD entry the
// uninstaller already relies on, so removal works at toggle-time too.
// Captures stderr to surface auth failures (vs silent generic-error).
// Bounded — same rationale as sudoTeeSysctlConf.
func sudoRmSysctlConf() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-n", "rm", sysctlIPv6ConfPath)
	sudo.SetCLocale(cmd) // keep auth-required text English for IsAuthError
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("ipv6 sysctl remove timed out — sudo may be wedged")
		}
		if sudo.IsAuthError(stderr.Bytes()) {
			return fmt.Errorf("ipv6 sysctl remove: %w", sudo.ErrAuthRequired)
		}
		return fmt.Errorf("ipv6 sysctl remove: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// ipv6ProcPaths are the /proc paths to write for disabling/enabling IPv6.
// Tests can override this to use temp paths.
var ipv6ProcPaths = []string{
	"/proc/sys/net/ipv6/conf/all/disable_ipv6",
	"/proc/sys/net/ipv6/conf/default/disable_ipv6",
	"/proc/sys/net/ipv6/conf/lo/disable_ipv6",
}

// DisableIPv6 disables IPv6 for the system (leak protection).
// Defense-in-depth: sysctl (all, default, lo) + persistent config + UFW deny rule.
func DisableIPv6() error {
	// Layer 1: Disable IPv6 immediately via /proc (all, default, AND loopback).
	// Requires CAP_NET_ADMIN, which the lazyvpn binary picks up via setcap on
	// next exec. The install process itself runs the install BEFORE the
	// fresh-exec, so caps aren't yet active for it — Layer 1 will EACCES.
	// We try /proc anyway (most callers DO have caps), then fall through to
	// the persistent conf + sysctl-load fallback below.
	procFailed := false
	for _, path := range ipv6ProcPaths {
		if err := writeFile(path, []byte("1"), 0644); err != nil {
			procFailed = true
			break
		}
	}

	// Layer 2: Create persistent sysctl config (survives reboot). Goes
	// through sudo because /etc/sysctl.d is 0755 root:root and CAP_NET_ADMIN
	// doesn't grant filesystem write access there.
	sysctlContent := `# LazyVPN: Disable IPv6 to prevent leaks
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
`
	sysctlConfErr := writeSysctlConf(sysctlContent)
	if sysctlConfErr != nil {
		log("Warning: failed to create persistent IPv6 sysctl config: %v", sysctlConfErr)
	}

	// If Layer 1 failed AND Layer 2 also failed, the kernel state was
	// never touched — IPv6 remains permitted system-wide. Surface this
	// rather than falling through to Layer 3 (UFW deny rules, which
	// alone don't block local processes' IPv6 sockets) and returning
	// nil. Pre-fix the TUI displayed "IPv6 protection ON" while the
	// kernel still leaked.
	if procFailed && sysctlConfErr != nil {
		return fmt.Errorf("ipv6 disable failed: /proc write unavailable AND persistent sysctl config could not be written: %w", sysctlConfErr)
	}

	if sysctlConfErr == nil && procFailed {
		// Layer 1 couldn't write /proc directly (no caps on this process —
		// typically the install flow). Apply the conf we just wrote via
		// `sysctl -p`, which runs as root through the existing NOPASSWD
		// entry. Net effect matches Layer 1: kernel state changes immediately.
		sysctlCtx, sysctlCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer sysctlCancel()
		sysctlCmd := exec.CommandContext(sysctlCtx, "sudo", "-n", "sysctl", "-p", sysctlIPv6ConfPath)
		sudo.SetCLocale(sysctlCmd)
		if out, err := sysctlCmd.CombinedOutput(); err != nil {
			if sysctlCtx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("ipv6 disable: sysctl -p timed out — sudo may be wedged")
			}
			if sudo.IsAuthError(out) {
				return fmt.Errorf("ipv6 disable: %w", sudo.ErrAuthRequired)
			}
			return fmt.Errorf("ipv6 disable: sysctl -p failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}

	// Layer 3: UFW deny rules for all IPv6 traffic (both directions). IPv6
	// protection is an independent UFW layer (like the killswitch and Local
	// Network), so it activates UFW itself — otherwise these deny rules sit on
	// an inactive firewall and never enforce. The kernel-level disable above is
	// the primary block; these UFW rules are defense-in-depth, so an activation
	// failure is a warning, not fatal.
	ufwMu.Lock()
	if err := ensureUFWEnabled(); err != nil {
		log("Warning: failed to activate UFW for IPv6 block rules: %v", err)
	}
	if err := addRule("deny", "out", "to", "::/0", "comment", TagIPv6); err != nil {
		log("Warning: failed to add IPv6 outbound block rule: %v", err)
	}
	if err := addRule("deny", "in", "from", "::/0", "comment", TagIPv6); err != nil {
		log("Warning: failed to add IPv6 inbound block rule: %v", err)
	}
	ufwMu.Unlock()

	return nil
}

// ipv6ReadPath is the file consulted by IsIPv6Disabled. Tests override it
// to point at a temp file so they don't depend on the host's actual v6 state.
var ipv6ReadPath = "/proc/sys/net/ipv6/conf/all/disable_ipv6"

// IsIPv6Disabled reports whether the kernel currently has IPv6 disabled
// system-wide. Source of truth is /proc/sys/net/ipv6/conf/all/disable_ipv6,
// not lazyvpn's UFW rules — same principle as killswitch state coming from
// UFW directly: the dashboard reflects what the system is actually doing,
// not what we last wrote. If something else (manual sysctl, another tool,
// distro init) flipped v6 outside the deny-rule layer, the toggle still
// reads correctly.
func IsIPv6Disabled() bool {
	data, err := os.ReadFile(ipv6ReadPath)
	if err != nil {
		// /proc path missing means IPv6 is compiled out of the kernel
		// (extremely rare on Linux desktops, but in that case "disabled"
		// is honest — no v6 stack exists).
		return true
	}
	return strings.TrimSpace(string(data)) == "1"
}

// EnableIPv6 enables IPv6 for the system.
// Cleans up all defense-in-depth layers.
func EnableIPv6() error {
	// Layer 1: Enable IPv6 immediately via /proc (all, default, AND loopback).
	// Tolerate per-path failures: an early return here used to leave the
	// kernel in a partial state (some paths flipped to 0, others still 1)
	// AND skipped Layers 2 and 3 — so the persistent conf and UFW deny
	// rule both survived. Now we attempt all paths, run the cleanup
	// regardless, and surface the aggregated error at the end.
	var procErrs []string
	for _, path := range ipv6ProcPaths {
		if err := writeFile(path, []byte("0"), 0644); err != nil {
			procErrs = append(procErrs, fmt.Sprintf("%s: %v", path, err))
		}
	}

	// Layer 2: Remove persistent sysctl config (sudo — same DAC reason
	// as the write side; reuses the existing `rm /etc/sysctl.d/...`
	// NOPASSWD entry from the uninstaller).
	if err := removeSysctlConf(); err != nil {
		log("Warning: failed to remove persistent IPv6 sysctl config: %v", err)
	}

	// Layer 3: Remove UFW IPv6 block rule. If IPv6 protection was the only
	// lazyvpn layer keeping UFW active, release it — mirrors the killswitch and
	// Local Network teardown. maybeRestoreUFW only disables UFW when lazyvpn
	// enabled it (marker present) AND no other lazyvpn tags remain.
	ufwMu.Lock()
	if err := deleteRulesByTag(TagIPv6); err != nil {
		log("Warning: failed to remove IPv6 block rules: %v", err)
	}
	maybeRestoreUFW()
	ufwMu.Unlock()

	if len(procErrs) > 0 {
		return fmt.Errorf("failed to enable IPv6 on %d/%d /proc paths: %s",
			len(procErrs), len(ipv6ProcPaths), strings.Join(procErrs, "; "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// LAN Stealth Mode — blocks inbound connections from private IP ranges
// ---------------------------------------------------------------------------

// EnableLANStealth blocks inbound connections from private IP ranges
// on the physical interface.
func EnableLANStealth() error {
	ufwMu.Lock()
	defer ufwMu.Unlock()

	log("Enabling LAN stealth mode")

	physIface, _, _ := GetPhysicalInterface()
	if physIface == "" {
		return fmt.Errorf("no physical interface found")
	}

	// Clean existing stealth rules
	if err := deleteRulesByTag(TagStealth); err != nil {
		log("Warning: failed to clean existing stealth rules: %v", err)
	}

	success := false
	defer func() {
		if !success {
			log("LAN stealth enable failed, rolling back")
			deleteRulesByTag(TagStealth)
			maybeRestoreUFW()
		}
	}()

	// LAN stealth rules only enforce when UFW is active.
	if err := ensureUFWEnabled(); err != nil {
		return err
	}

	// Emit via the shared builder so the granular path and Reconcile produce
	// identical Stealth rules (DHCP-in, allow-out to LAN, broad deny-in).
	if err := emitLANRules(State{LANMode: LANStealth}, physIface); err != nil {
		return err
	}

	success = true
	log("LAN stealth mode enabled (interface=%s)", physIface)
	return nil
}

// DisableLANStealth removes LAN stealth rules.
func DisableLANStealth() error {
	ufwMu.Lock()
	defer ufwMu.Unlock()

	log("Disabling LAN stealth mode")

	if err := deleteRulesByTag(TagStealth); err != nil {
		return err
	}
	maybeRestoreUFW()

	log("LAN stealth mode disabled")
	return nil
}

// IsLANStealthActive checks if LAN stealth rules are in place.
func IsLANStealthActive() bool {
	return hasRulesWithTag(TagStealth)
}

// ---------------------------------------------------------------------------
// LAN Block Mode — blocks outbound traffic to private IP ranges
// ---------------------------------------------------------------------------

// EnableLANBlock blocks outbound traffic to private IP ranges.
// Allows loopback, VPN tunnel, VPN endpoint, gateway, DNS, and DHCP.
// The dns parameter is a comma-separated list of DNS server IPs (e.g. from the VPN config).
func EnableLANBlock(vpnInterface, endpoint, gateway, dns string) error {
	ufwMu.Lock()
	defer ufwMu.Unlock()

	log("Enabling LAN block (vpn=%s, endpoint=%s, gw=%s, dns=%s)", vpnInterface, endpoint, gateway, dns)

	// Clean existing LAN block rules
	if err := deleteRulesByTag(TagLANBlock); err != nil {
		log("Warning: failed to clean existing LAN block rules: %v", err)
	}

	success := false
	defer func() {
		if !success {
			log("LAN block enable failed, rolling back")
			deleteRulesByTag(TagLANBlock)
			maybeRestoreUFW()
		}
	}()

	// LAN block rules only enforce when UFW is active.
	if err := ensureUFWEnabled(); err != nil {
		return err
	}

	// Emit via the shared builder so the granular path and Reconcile produce
	// identical Block rules (loopback/gateway/tunnel/endpoint/DNS/DHCP allows,
	// deny LAN egress, broad deny-in).
	physIface, gw, _ := GetPhysicalInterface()
	if gateway == "" {
		gateway = gw
	}
	s := State{
		LANMode:       LANBlock,
		InterfaceName: vpnInterface,
		Endpoint:      endpoint,
		DNS:           dns,
		Gateway:       gateway,
		Connected:     vpnInterface != "",
	}
	if err := emitLANRules(s, physIface); err != nil {
		return err
	}

	success = true
	log("LAN block enabled")
	return nil
}

// DisableLANBlock removes LAN block rules.
func DisableLANBlock() error {
	ufwMu.Lock()
	defer ufwMu.Unlock()

	log("Disabling LAN block")

	if err := deleteRulesByTag(TagLANBlock); err != nil {
		return err
	}
	maybeRestoreUFW()

	log("LAN block disabled")
	return nil
}

// IsLANBlockActive checks if LAN block rules are in place.
func IsLANBlockActive() bool {
	return hasRulesWithTag(TagLANBlock)
}

// ---------------------------------------------------------------------------
// LAN Allow Mode — full LAN access (inbound + outbound to private ranges)
// ---------------------------------------------------------------------------

// EnableLANAllow grants full local-network access: explicit allow rules for
// inbound from and outbound to private ranges. These are EXPLICIT (not a
// reliance on UFW's default policy) so the displayed "Allow: full LAN access"
// matches inspectable reality — and so inbound LAN works even on systems whose
// base incoming policy is deny (e.g. Omarchy's default). The allow-out rules
// also carry lower rule numbers than the killswitch's physical-interface
// reject, so LAN egress survives when the killswitch is engaged.
func EnableLANAllow() error {
	ufwMu.Lock()
	defer ufwMu.Unlock()

	log("Enabling LAN allow mode")

	physIface, _, _ := GetPhysicalInterface()
	if physIface == "" {
		return fmt.Errorf("no physical interface found")
	}

	// Clean existing allow rules
	if err := deleteRulesByTag(TagLANAllow); err != nil {
		log("Warning: failed to clean existing LAN allow rules: %v", err)
	}

	success := false
	defer func() {
		if !success {
			log("LAN allow enable failed, rolling back")
			deleteRulesByTag(TagLANAllow)
			maybeRestoreUFW()
		}
	}()

	// LAN allow rules only enforce when UFW is active.
	if err := ensureUFWEnabled(); err != nil {
		return err
	}

	// Emit via the shared builder so the granular path and Reconcile produce
	// identical Allow rules (allow in + out to/from private ranges).
	if err := emitLANRules(State{LANMode: LANAllow}, physIface); err != nil {
		return err
	}

	success = true
	log("LAN allow mode enabled (interface=%s)", physIface)
	return nil
}

// DisableLANAllow removes LAN allow rules.
func DisableLANAllow() error {
	ufwMu.Lock()
	defer ufwMu.Unlock()

	log("Disabling LAN allow mode")

	if err := deleteRulesByTag(TagLANAllow); err != nil {
		return err
	}
	maybeRestoreUFW()

	log("LAN allow mode disabled")
	return nil
}

// IsLANAllowActive checks if explicit LAN allow rules are in place.
func IsLANAllowActive() bool {
	return hasRulesWithTag(TagLANAllow)
}

// ---------------------------------------------------------------------------
// Teardown — full cleanup for uninstall
// ---------------------------------------------------------------------------

// Teardown completely removes all LazyVPN firewall rules and resets defaults.
// Used during uninstall to leave no orphaned firewall state.
func Teardown() error {
	ufwMu.Lock()
	defer ufwMu.Unlock()

	log("Tearing down all LazyVPN firewall rules")

	// Restore the OUTGOING default to "allow" — the killswitch flips it to
	// "deny" when active, so we reset what we changed. We never touch the
	// INCOMING default (the killswitch is outbound-only), so a user who set
	// "deny incoming" themselves keeps it.
	addRule("default", "allow", "outgoing")

	// Delete all tagged rules
	for _, tag := range []string{TagKillswitch, TagLANBlock, TagStealth, TagLANAllow, TagIPv6} {
		if err := deleteRulesByTag(tag); err != nil {
			log("Warning: failed to delete rules with tag %s: %v", tag, err)
		}
	}

	// If lazyvpn was the one that activated UFW, turn it back off now that
	// all our rules are gone — leave the system as we found it.
	maybeRestoreUFW()

	log("Teardown complete")
	return nil
}

// ---------------------------------------------------------------------------
// UFW Logging
// ---------------------------------------------------------------------------

// SetLogging sets the UFW logging level (off, low, medium, high, full).
func SetLogging(level string) error {
	ufwMu.Lock()
	defer ufwMu.Unlock()

	_, err := runUFW.Run("logging", level)
	return err
}

// GetLoggingLevel returns the current UFW logging level by parsing
// `ufw status verbose`. Returns "off", "low", "medium", "high", or "full".
// Returns "off" on error.
func GetLoggingLevel() string {
	out, err := runUFW.Run("status", "verbose")
	if err != nil {
		return "off"
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Logging:") {
			rest := strings.TrimPrefix(line, "Logging:")
			rest = strings.TrimSpace(rest)
			// "off" or "on (low)" / "on (medium)" / "on (high)" / "on (full)"
			if rest == "off" {
				return "off"
			}
			if idx := strings.Index(rest, "("); idx >= 0 {
				end := strings.Index(rest, ")")
				if end > idx {
					return rest[idx+1 : end]
				}
			}
			return "low" // "on" without parenthetical defaults to low
		}
	}
	return "off"
}

// ---------------------------------------------------------------------------
// Physical interface detection (unchanged from iptables version)
// ---------------------------------------------------------------------------

// procNetRoutePath is the path to /proc/net/route.
// Tests can override this to inject fake route data.
var procNetRoutePath = "/proc/net/route"

// isVPNInterface returns true if the interface name belongs to a VPN tunnel.
func isVPNInterface(name string) bool {
	return strings.HasPrefix(name, "wg") ||
		strings.HasPrefix(name, "tun") ||
		strings.HasPrefix(name, "tap") ||
		strings.HasPrefix(name, "nordlynx") ||
		strings.HasPrefix(name, "proton") ||
		strings.HasPrefix(name, "mullvad")
}

// GetPhysicalInterface returns the default physical interface (eth0, wlan0, etc.)
// Skips VPN interfaces (wg*, tun*, tap*, etc.) so callers always get the real
// network adapter even when a VPN tunnel has become the primary default route.
func GetPhysicalInterface() (string, string, error) {
	data, err := os.ReadFile(procNetRoutePath)
	if err != nil {
		return "", "", err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] { // Skip header
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "00000000" && !isVPNInterface(fields[0]) {
			iface := fields[0]
			// Parse gateway (little endian hex)
			gwHex := fields[2]
			if len(gwHex) == 8 {
				var gwBytes [4]byte
				n, _ := fmt.Sscanf(gwHex, "%02x%02x%02x%02x", &gwBytes[3], &gwBytes[2], &gwBytes[1], &gwBytes[0])
				if n == 4 {
					gateway := fmt.Sprintf("%d.%d.%d.%d", gwBytes[0], gwBytes[1], gwBytes[2], gwBytes[3])
					return iface, gateway, nil
				}
			}
			return iface, "", nil
		}
	}

	return "", "", fmt.Errorf("no default route found")
}

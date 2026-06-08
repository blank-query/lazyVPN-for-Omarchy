package sudo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateSudoersScoping covers the per-physical-interface host route
// scoping, which applies regardless of filesystem variant.
func TestGenerateSudoersScoping(t *testing.T) {
	// With physical interfaces - should scope to each
	content, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"enp3s0", "wlan0"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(content, "ip route add * via * dev *") {
		t.Error("should NOT contain wildcard dev when physical interfaces provided")
	}
	if !strings.Contains(content, "ip route add * via * dev enp3s0") {
		t.Error("missing scoped rule for enp3s0")
	}
	if !strings.Contains(content, "ip route add * via * dev wlan0") {
		t.Error("missing scoped rule for wlan0")
	}

	// Without physical interfaces — should NOT emit a wildcard fallback
	// (degenerate state; route-add will fail loudly at use time rather
	// than silently granting `ip route add * via * dev *`).
	content2, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(content2, "ip route add * via * dev *") {
		t.Error("should NOT emit wildcard fallback when no physical interfaces detected")
	}
	if strings.Contains(content2, "ip route add * via *") {
		t.Error("should NOT emit any host-route grant when no physical interfaces detected")
	}

	// Verify %wheel is single-percent (sudoers group syntax), not %%wheel
	if strings.Contains(content, "%%wheel") {
		t.Error("sudoers contains %%wheel (double percent) — sudoers requires %wheel (single percent)")
	}
	if !strings.Contains(content, "%wheel") {
		t.Error("sudoers missing %wheel group entries")
	}
}

func TestDetectPhysicalInterfaces(t *testing.T) {
	ifaces := DetectPhysicalInterfaces()
	// Should find at least one interface on any real machine
	if len(ifaces) == 0 {
		t.Skip("no physical interfaces found (CI/container?)")
	}
	for _, name := range ifaces {
		if name == "lo" {
			t.Errorf("should not include loopback, got: %v", ifaces)
		}
		if isVirtualInterface(name) {
			t.Errorf("should not include virtual interface %q", name)
		}
	}
	t.Logf("Detected physical interfaces: %v", ifaces)
}

// TestSetcapCapabilityStringConsistency pins the cross-file invariant
// that the capability list passed to setcap is identical in:
//
//   internal/sudo/sudo.go:     "cap_net_admin,cap_net_raw+ep" (literal)
//   internal/sudo/sudoers.go:  cap_net_admin\,cap_net_raw+ep (escaped)
//
// Sudoers parses the escaped form into the literal at parse time. If
// a future maintainer adds a capability (e.g. CAP_SYS_ADMIN) to one
// source but forgets the other:
//   - Add to runtime only: sudo denies the call ("password required"
//     — the cap_net_admin,cap_net_raw,cap_sys_admin+ep arg doesn't
//     match the NOPASSWD entry exactly)
//   - Add to sudoers only: runtime never uses the granted privilege;
//     dead permission grant
//
// Source-scan test: read both files, verify the unescaped capability
// string appears in both. A regression in either alone fails the test.
//
// Pattern: same family as the static-source guards in
// internal/daemon/no_full_save_test.go and internal/logger/
// no_direct_cfg_test.go.
func TestSetcapCapabilityStringConsistency(t *testing.T) {
	const cap = "cap_net_admin,cap_net_raw+ep" // unescaped form

	sudoSrc, err := os.ReadFile("sudo.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sudoSrc), cap) {
		t.Errorf("sudo.go missing capability string %q — runtime caps would not match sudoers entry", cap)
	}

	sudoersSrc, err := os.ReadFile("sudoers.go")
	if err != nil {
		t.Fatal(err)
	}
	// sudoers source has escaped form `cap_net_admin\,cap_net_raw+ep`.
	// Strip the backslash for the comparison.
	unescaped := strings.ReplaceAll(string(sudoersSrc), `\,`, ",")
	if !strings.Contains(unescaped, cap) {
		t.Errorf("sudoers.go missing capability string %q (unescaped form) — sudoers entry would not match runtime cap", cap)
	}
}

// TestIsVirtualInterface_AllPrefixesCovered pins the exact set of
// prefixes isVirtualInterface treats as virtual:
//
//   wg, tun, tap            — WireGuard / tunneling
//   nordlynx, proton, mullvad — provider-branded VPN interfaces
//   veth, br-, docker       — container / bridge networking
//   virbr, vbox, vmnet      — VM hypervisor networking
//
// The list drives DetectPhysicalInterfaces' skip filter — any interface
// matching one of these prefixes is treated as virtual and EXCLUDED
// from sudoers host-route rules.
//
// A regression dropping a prefix would treat the matching virtual
// interface as physical → generate a sudoers NOPASSWD entry for
// "ip route add * via * dev <iface>" on it. For Docker / VM bridges
// this is privilege creep; for WireGuard interfaces (wg0, wg-...)
// it's circular routing.
//
// A regression adding a prefix that matches a real physical interface
// (e.g. "en" would match enp3s0) would silently exclude that iface
// → no host-route rules generated → connect-time route-add fails
// for that interface.
//
// Two sub-tests: each prefix marks its sample positive; common
// physical names (eth0, wlan0, enp3s0, eno1) must NOT match.
func TestIsVirtualInterface_AllPrefixesCovered(t *testing.T) {
	t.Run("known_virtual_prefixes_match", func(t *testing.T) {
		samples := map[string]string{
			"wg":       "wg0",
			"tun":      "tun0",
			"tap":      "tap0",
			"nordlynx": "nordlynx",
			"proton":   "proton0",
			"mullvad":  "mullvad-fr1",
			"veth":     "vethABC123",
			"br-":      "br-1234567890ab",
			"docker":   "docker0",
			"virbr":    "virbr0",
			"vbox":     "vboxnet0",
			"vmnet":    "vmnet8",
		}
		for prefix, sample := range samples {
			if !isVirtualInterface(sample) {
				t.Errorf("isVirtualInterface(%q) = false, want true (prefix %q dropped from list?)", sample, prefix)
			}
		}
	})

	t.Run("real_physical_names_dont_match", func(t *testing.T) {
		physical := []string{"eth0", "eth1", "wlan0", "wlan1", "enp3s0", "eno1", "ens33", "wlp2s0"}
		for _, name := range physical {
			if isVirtualInterface(name) {
				t.Errorf("isVirtualInterface(%q) = true, want false — a prefix is over-matching real interfaces", name)
			}
		}
	})
}

// --- Filesystem-conditional content tests ---

// entriesDroppedEverywhere are sudoers fragments that must not appear in any
// variant after the delete-API refactor. journal-file shred moved to
// SudoInteractive; dd overwrite and fstrim were removed as CoW theater.
var entriesDroppedEverywhere = []string{
	"/usr/bin/shred -u /var/log/journal",
	"/usr/bin/dd if=/dev/urandom",
	"/usr/bin/fstrim",
}

// shredFileEntries are the CoW-conditional entries: present on non-CoW,
// absent on CoW (where shred writes to new extents and is pure theater).
var shredFileEntries = []string{
	"/usr/bin/shred -u /etc/sysctl.d/99-lazyvpn-ipv6.conf",
	"/usr/bin/shred -u /etc/sudoers.d/lazyvpn",
}

// rmFileEntries are uniform across both variants — primary delete path on
// CoW, fallback on non-CoW. Bare `rm` (no -f) so NotPresent surfaces via
// stderr rather than being silently swallowed.
var rmFileEntries = []string{
	"/usr/bin/rm /etc/sysctl.d/99-lazyvpn-ipv6.conf",
	"/usr/bin/rm /etc/sudoers.d/lazyvpn",
}

func TestGenerateSudoersCoWVariant(t *testing.T) {
	content, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"enp3s0"}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, bad := range entriesDroppedEverywhere {
		if strings.Contains(content, bad) {
			t.Errorf("CoW variant still contains removed entry: %q", bad)
		}
	}
	for _, bad := range shredFileEntries {
		if strings.Contains(content, bad) {
			t.Errorf("CoW variant should NOT contain shred entry: %q", bad)
		}
	}
	for _, want := range rmFileEntries {
		if !strings.Contains(content, want) {
			t.Errorf("CoW variant missing uniform rm entry: %q", want)
		}
	}
	// rm entries should not have -f (runtime calls bare rm for NotPresent
	// detection; an `-f` sudoers entry wouldn't match the actual invocation).
	if strings.Contains(content, "/usr/bin/rm -f ") {
		t.Error("CoW variant contains `rm -f` entries; runtime calls bare `rm`")
	}
}

func TestGenerateSudoersNonCoWVariant(t *testing.T) {
	content, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"enp3s0"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, bad := range entriesDroppedEverywhere {
		if strings.Contains(content, bad) {
			t.Errorf("non-CoW variant still contains removed entry: %q", bad)
		}
	}
	for _, want := range shredFileEntries {
		if !strings.Contains(content, want) {
			t.Errorf("non-CoW variant missing shred entry: %q", want)
		}
	}
	for _, want := range rmFileEntries {
		if !strings.Contains(content, want) {
			t.Errorf("non-CoW variant missing rm entry: %q", want)
		}
	}
	if strings.Contains(content, "/usr/bin/rm -f ") {
		t.Error("non-CoW variant contains `rm -f` entries; runtime calls bare `rm`")
	}
}

// TestGenerateSudoers_ExactPathOpsPresent pins the exact-path NOPASSWD
// entries that don't take wildcards — each operation is scoped to a
// SPECIFIC LazyVPN file/argument:
//
//   sysctl -p /etc/sysctl.d/99-lazyvpn-ipv6.conf  IPv6 protection fallback
//   tee /etc/sysctl.d/99-lazyvpn-ipv6.conf        IPv6 conf write (toggle on)
//   rm /etc/sysctl.d/99-lazyvpn-ipv6.conf         IPv6 conf delete (toggle off)
//   rm /etc/sudoers.d/lazyvpn                     uninstaller cleanup
//   systemctl start systemd-journald              CleanJournalLogs (post-scrub)
//   systemctl stop systemd-journald               CleanJournalLogs (pre-scrub)
//
// These are EXACT-PATH entries (no wildcards): the path must literally
// match what runtime invokes. A regression that broadened them to
// wildcards (e.g. `rm /etc/*`) would expand the attack surface —
// any wheel-group user could delete arbitrary /etc files without
// password. A regression that NARROWED them past the runtime's call
// (e.g. omitting the path) would silently break the operation.
//
// Sibling to the other sudoers-completeness pins; this completes the
// coverage of every NOPASSWD entry in the template.
func TestGenerateSudoers_ExactPathOpsPresent(t *testing.T) {
	content, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"enp3s0"}, false)
	if err != nil {
		t.Fatalf("GenerateSudoersContent: %v", err)
	}
	wantEntries := []string{
		"/usr/bin/sysctl -p /etc/sysctl.d/99-lazyvpn-ipv6.conf",
		"/usr/bin/tee /etc/sysctl.d/99-lazyvpn-ipv6.conf",
		"/usr/bin/rm /etc/sysctl.d/99-lazyvpn-ipv6.conf",
		"/usr/bin/rm /etc/sudoers.d/lazyvpn",
		"/usr/bin/systemctl start systemd-journald",
		"/usr/bin/systemctl stop systemd-journald",
	}
	for _, want := range wantEntries {
		if !strings.Contains(content, want) {
			t.Errorf("sudoers missing %q — corresponding runtime op would fail with 'password required'", want)
		}
	}
	// Defensive: no wildcard expansion of these paths. A regression
	// like "rm /etc/*" would silently broaden delete privileges.
	for _, dangerous := range []string{
		"/usr/bin/rm /etc/*",
		"/usr/bin/rm *",
		"/usr/bin/tee /etc/*",
		"/usr/bin/sysctl -p *",
	} {
		if strings.Contains(content, dangerous) {
			t.Errorf("sudoers contains DANGEROUS wildcard %q — exact-path security boundary regressed", dangerous)
		}
	}
}

// TestGenerateSudoers_SetcapEntry pins the exact-match sudoers entry
// for setcap (binary capability assignment). Runtime calls:
//
//   sudo -n setcap cap_net_admin,cap_net_raw+ep <execPath>
//
// Sudoers entry uses the sudoers comma-escape:
//
//   %wheel ALL=(ALL) NOPASSWD: /usr/bin/setcap cap_net_admin\,cap_net_raw+ep <execPath>
//
// Two failure modes to catch:
//   1) Missing entry entirely: cap-set fails at install/upgrade time,
//      leaving the binary without CAP_NET_ADMIN — netlink ops then
//      fall back to sudo for EVERY call, slow + interactive prompts
//   2) Wrong escape (literal comma instead of \,): sudoers parses
//      the comma as list separator, splits the rule into two invalid
//      entries; visudo MAY reject the file, breaking ALL sudoers
//      entries until manual fix
//
// The test injects a specific execPath and asserts both the escaped
// capability list AND the binary path appear in the generated content.
func TestGenerateSudoers_SetcapEntry(t *testing.T) {
	execPath := "/opt/lazyvpn-test/lazyvpn"
	content, err := GenerateSudoersContent(execPath, "wg0", []string{"enp3s0"}, false)
	if err != nil {
		t.Fatalf("GenerateSudoersContent: %v", err)
	}
	// Sudoers comma-escape: must use "\," not "," (sudoers parses
	// bare commas as list separators).
	wantEscaped := `cap_net_admin\,cap_net_raw+ep`
	if !strings.Contains(content, wantEscaped) {
		t.Errorf("sudoers missing escaped capability list %q — runtime setcap would fail or break visudo parsing", wantEscaped)
	}
	// Binary path interpolation: must match the execPath passed in.
	wantBinary := "/usr/bin/setcap cap_net_admin\\,cap_net_raw+ep " + execPath
	if !strings.Contains(content, wantBinary) {
		t.Errorf("sudoers missing setcap entry for execPath %q — full want: %q", execPath, wantBinary)
	}
	// Defensive: no bare-comma form should appear. If someone
	// "fixed" the escape by removing the backslash, this catches it.
	if strings.Contains(content, "setcap cap_net_admin,cap_net_raw") {
		t.Error("sudoers contains BARE-comma setcap form — must be escaped as cap_net_admin\\,cap_net_raw")
	}
}

// TestGenerateSudoers_AllUfwSubcommandsPresent pins the UFW
// subcommands the firewall package invokes at runtime:
//
//   ufw status                  (lifecycle queries)
//   ufw status verbose          (getDefaultOutgoingPolicy, GetLoggingLevel)
//   ufw show added              (deleteRulesByTag, hasRulesWithTag)
//   ufw default allow outgoing  (Disable — restore default)
//   ufw default deny outgoing   (Enable / EnableSimple — flip to deny)
//   ufw default allow incoming  (Teardown — restore default)
//   ufw allow *                 (per-rule addRule for allow rules)
//   ufw deny *                  (per-rule addRule for deny rules)
//   ufw reject *                (per-rule addRule for reject rules)
//   ufw delete *                (deleteRulesByTag per-rule delete)
//
// A dropped entry breaks the matching firewall flow:
//   - Drop "show added":  rule lookup fails → tag-based cleanup broken
//   - Drop "default deny outgoing": killswitch can't activate
//   - Drop "allow/deny/reject": rule additions fail mid-flight, rollback fires
//   - Drop "delete":      cleanup leaks rules, accumulating over time
//
// Sibling pattern to 819acfb (resolvectl), 0688f32 (UFW logging),
// a3b8a8d (ip link), 5a0bc49 (ip route+addr).
func TestGenerateSudoers_AllUfwSubcommandsPresent(t *testing.T) {
	content, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"enp3s0"}, false)
	if err != nil {
		t.Fatalf("GenerateSudoersContent: %v", err)
	}
	wantEntries := []string{
		"/usr/bin/ufw status",
		"/usr/bin/ufw status verbose",
		"/usr/bin/ufw show added",
		"/usr/bin/ufw default allow outgoing",
		"/usr/bin/ufw default allow incoming",
		"/usr/bin/ufw default deny outgoing",
		"/usr/bin/ufw allow *",
		"/usr/bin/ufw deny *",
		"/usr/bin/ufw reject *",
		"/usr/bin/ufw delete *",
	}
	for _, want := range wantEntries {
		if !strings.Contains(content, want) {
			t.Errorf("sudoers missing %q — corresponding runUFW.Run(...) call would fail with 'password required'", want)
		}
	}
}

// TestGenerateSudoers_AllIpRouteAndAddrOperationsPresent pins the
// remaining ip sudo fallbacks: route add/del split routes, route add
// default, ip addr add. Sibling to a3b8a8d (ip link) — covers the
// rest of the netlink-EPERM fallback surface for ip(8).
//
// Runtime calls (from internal/netlink/routes.go and wireguard.go):
//   ip route add 0.0.0.0/1 dev <iface>      (configureSplitRoutes)
//   ip route add 128.0.0.0/1 dev <iface>    (configureSplitRoutes)
//   ip route add default dev <iface> metric (configureSplitRoutes)
//   ip route del 0.0.0.0/1 dev <iface>      (DeleteSplitRoutes)
//   ip route del 128.0.0.0/1 dev <iface>    (DeleteSplitRoutes)
//   ip route del default dev <iface>        (DeleteSplitRoutes)
//   ip addr add * dev <iface>               (assignAddressSudo)
//
// A dropped split-route entry breaks the VPN routing — traffic stays
// on the physical interface even though the tunnel is up. Silent
// failure since the netlink call succeeded BEFORE EPERM hit.
func TestGenerateSudoers_AllIpRouteAndAddrOperationsPresent(t *testing.T) {
	content, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"enp3s0"}, false)
	if err != nil {
		t.Fatalf("GenerateSudoersContent: %v", err)
	}
	wantEntries := []string{
		// Split routes — the two halves of 0/0
		"/usr/bin/ip route add 0.0.0.0/1 dev wg0",
		"/usr/bin/ip route add 128.0.0.0/1 dev wg0",
		"/usr/bin/ip route del 0.0.0.0/1 dev wg0",
		"/usr/bin/ip route del 128.0.0.0/1 dev wg0",
		// Default route with metric (some daemon configs install default
		// rather than split — keep both supported)
		"/usr/bin/ip route add default dev wg0 metric *",
		"/usr/bin/ip route del default dev wg0",
		// Address assignment
		"/usr/bin/ip addr add * dev wg0",
	}
	for _, want := range wantEntries {
		if !strings.Contains(content, want) {
			t.Errorf("sudoers missing %q — netlink-EPERM fallback for that op would fail with 'password required'", want)
		}
	}
}

// TestGenerateSudoers_AllIpLinkOperationsPresent pins NOPASSWD
// entries for the ip link operations the netlink package falls back
// to when netlink syscalls return EPERM:
//
//   ip link add dev <iface> type wireguard   (createInterfaceSudo)
//   ip link delete dev <iface>               (Delete)
//   ip link set dev <iface> up               (bringUpSudo)
//   ip link set dev <iface> mtu N            (SetMTU fallback)
//
// All five sudoers entries scoped to the configured connName (%s).
// A dropped entry means the netlink-EPERM fallback for that step
// fails — runtime sees "password required" and the connect/disconnect
// step aborts with an opaque error.
//
// Sibling pattern to 819acfb (resolvectl) and 0688f32 (UFW logging).
// Each enumeration is a security boundary — explicit allow-list
// catches the dropped-entry silent-failure pattern.
func TestGenerateSudoers_AllIpLinkOperationsPresent(t *testing.T) {
	content, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"enp3s0"}, false)
	if err != nil {
		t.Fatalf("GenerateSudoersContent: %v", err)
	}
	wantEntries := []string{
		"/usr/bin/ip link add dev wg0 type wireguard",
		"/usr/bin/ip link delete dev wg0",
		"/usr/bin/ip link set dev wg0 up",
		"/usr/bin/ip link set dev wg0 down",
		"/usr/bin/ip link set dev wg0 mtu *",
	}
	for _, want := range wantEntries {
		if !strings.Contains(content, want) {
			t.Errorf("sudoers missing %q — netlink-EPERM fallback would fail with 'password required'", want)
		}
	}
}

// TestGenerateSudoers_AllResolvectlSubcommandsPresent pins NOPASSWD
// entries for the four resolvectl subcommands the runtime invokes:
//
//   resolvectl dns <iface> <addrs...>         (configureDNSviaResolvectl)
//   resolvectl domain <iface> ~.              (configureDNSviaResolvectl)
//   resolvectl default-route <iface> true     (configureDNSviaResolvectl)
//   resolvectl default-route <iface> false    (demotePhysicalDNSDefaultRoute)
//   resolvectl revert <iface>                 (unconfigureDNS)
//
// A regression dropping any one entry would silently break DNS
// configuration for that step:
//   - Drop "dns":          VPN DNS never gets set → user uses ISP DNS
//   - Drop "domain":       Domain routing breaks → split-DNS misroutes
//   - Drop "default-route":Physical interface keeps DNS authority → leak
//   - Drop "revert":       DNS sticks after disconnect → resolves via VPN-gone
//
// The lazyvpn-interface form scopes to %s (the connName), but
// default-route also has a separate wildcard "* true" / "* false"
// form for the PHYSICAL interface restore. Both forms matter.
//
// Sibling pattern to 0688f32 (UFW logging levels).
func TestGenerateSudoers_AllResolvectlSubcommandsPresent(t *testing.T) {
	content, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"enp3s0"}, false)
	if err != nil {
		t.Fatalf("GenerateSudoersContent: %v", err)
	}
	wantEntries := []string{
		// VPN-interface scoped (wg0)
		"/usr/bin/resolvectl dns wg0",
		"/usr/bin/resolvectl domain wg0",
		"/usr/bin/resolvectl default-route wg0",
		"/usr/bin/resolvectl revert wg0",
		// Physical-interface wildcard for the demote/restore pair
		"/usr/bin/resolvectl default-route * true",
		"/usr/bin/resolvectl default-route * false",
	}
	for _, want := range wantEntries {
		if !strings.Contains(content, want) {
			t.Errorf("sudoers missing %q — runtime resolvectl call would fail at sudo layer", want)
		}
	}
}

// TestGenerateSudoers_AllUfwLoggingLevelsPresent pins the five UFW
// logging levels (off, low, medium, high, full) as NOPASSWD entries.
//
// SetLogging in firewall package accepts ANY string and passes it
// straight to `ufw logging <level>`. The sudoers template explicitly
// enumerates the 5 accepted values rather than allowing `ufw logging *`
// — wildcard would let any string through (e.g. "ufw logging delete
// proxy-rules"). The enumeration is the security boundary.
//
// A regression that dropped any of the 5 entries from the sudoers
// template would silently break that one logging level — user
// switches to "high" via TUI, runtime gets "sudo: a password is
// required" (the missing entry), and the firewall logging level
// quietly doesn't change. Easy to miss in manual testing of the
// 4 levels that ARE permitted.
//
// Sibling pattern to other security-list pins (6885299, 9e8cc3e,
// 2ab851b) — explicit enumeration prevents silent failure modes.
func TestGenerateSudoers_AllUfwLoggingLevelsPresent(t *testing.T) {
	content, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"enp3s0"}, false)
	if err != nil {
		t.Fatalf("GenerateSudoersContent: %v", err)
	}
	levels := []string{"off", "low", "medium", "high", "full"}
	for _, level := range levels {
		want := "/usr/bin/ufw logging " + level
		if !strings.Contains(content, want) {
			t.Errorf("sudoers content missing NOPASSWD entry for ufw logging %q — runtime SetLogging(%q) would fail at sudo layer with 'password required'", level, level)
		}
	}
}

// TestGenerateSudoersRejectsBadConnName guards the connName validation:
// any value with newlines, shell metas, or anything outside the
// alphanumeric+._- character set must be rejected before interpolation.
// A tampered config.json with a newline-injected stanza would otherwise
// produce sudoers content that visudo might still accept (the injected
// stanza could be syntactically valid).
func TestGenerateSudoersRejectsBadConnName(t *testing.T) {
	bad := []string{
		"",                                // empty
		"wg0\n%wheel ALL=(ALL) NOPASSWD:", // newline injection
		"wg 0",                            // space
		"wg0;rm",                          // semicolon
		"wg0 ALL=",                        // sudoers-like syntax
		"wg0/foo",                         // slash
		"a234567890123456",                // 16 chars (IFNAMSIZ-1 = 15)
	}
	for _, name := range bad {
		_, err := GenerateSudoersContent("/usr/bin/lazyvpn", name, []string{"enp3s0"}, false)
		if err == nil {
			t.Errorf("expected rejection for connName=%q, got no error", name)
		}
	}
	good := []string{"wg0", "wg-vpn", "wg.test", "wg_0", "Aa1.-_"}
	for _, name := range good {
		_, err := GenerateSudoersContent("/usr/bin/lazyvpn", name, []string{"enp3s0"}, false)
		if err != nil {
			t.Errorf("expected success for connName=%q, got %v", name, err)
		}
	}
}

// Defense-in-depth: same validation must apply to physicalIfaces entries.
// connName is validated against connNameRe to refuse newline / shell-meta
// injection, but physicalIfaces was trusted blindly — every iface is
// interpolated into a sudoers rule via fmt.Sprintf with no escaping.
//
// Currently sourced from DetectPhysicalInterfaces() (net.Interfaces()
// returns kernel-validated names), so unreachable today. But a sudoers
// injection that visudo accepts (a syntactically valid extra rule like
// "%wheel ALL=(ALL) NOPASSWD: ALL") would be a full privilege escalation
// if any future code path ever sources iface names from user input or
// untrusted state. Validate at the source.
func TestGenerateSudoersRejectsBadIfaceName(t *testing.T) {
	badIfaces := []string{
		"",                                       // empty
		"eth0\n%wheel ALL=(ALL) NOPASSWD: ALL",   // newline injection — visudo accepts the resulting file
		"eth 0",                                  // space
		"eth0;rm",                                // semicolon
		"eth0 ALL=",                              // sudoers-like syntax
		"../etc",                                 // path traversal-y chars (slash)
		"eth0/foo",                               // slash
		"a234567890123456",                       // 16 chars (IFNAMSIZ-1 = 15)
	}
	for _, iface := range badIfaces {
		_, err := GenerateSudoersContent("/usr/bin/lazyvpn", "wg0", []string{iface}, false)
		if err == nil {
			t.Errorf("expected rejection for iface=%q, got no error", iface)
		}
	}
	// One bad among many must still be rejected (not silently skipped).
	if _, err := GenerateSudoersContent("/usr/bin/lazyvpn", "wg0", []string{"eth0", "bad\nname", "wlan0"}, false); err == nil {
		t.Error("expected rejection when one of several physicalIfaces is bad")
	}

	good := []string{"eth0", "wlan0", "enp3s0", "eno1", "br-data", "wlx0123456789ab"}
	for _, iface := range good {
		_, err := GenerateSudoersContent("/usr/bin/lazyvpn", "wg0", []string{iface}, false)
		if err != nil {
			t.Errorf("expected success for iface=%q, got %v", iface, err)
		}
	}
}

// TestGenerateSudoersPassesVisudo runs `visudo -cf` against both variants to
// confirm the emitted content is syntactically valid. Skips cleanly if
// visudo isn't installed on the host.
func TestGenerateSudoersPassesVisudo(t *testing.T) {
	visudoPath, err := exec.LookPath("visudo")
	if err != nil {
		t.Skip("visudo not available; skipping syntax validation")
	}

	cases := []struct {
		name string
		cow  bool
	}{
		{"cow", true},
		{"non-cow", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			content, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"enp3s0"}, c.cow)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "lazyvpn")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatalf("write temp sudoers: %v", err)
			}

			out, err := exec.Command(visudoPath, "-cf", path).CombinedOutput()
			if err != nil {
				t.Errorf("visudo -cf failed for %s variant: %v\nOutput:\n%s", c.name, err, out)
			}
		})
	}
}

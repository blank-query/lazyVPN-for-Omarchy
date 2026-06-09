package firewall

import (
	"fmt"
	"strings"
)

// LANMode is the Local Network posture — an independent standing layer.
type LANMode int

const (
	LANAllow LANMode = iota // full LAN access (inbound + outbound)
	LANStealth              // outbound LAN works, inbound blocked
	LANBlock                // all LAN traffic blocked
)

// State is the complete desired lazyvpn firewall posture. Reconcile rebuilds
// the ENTIRE tagged ruleset from this in one deterministic, validated pass.
//
// This is the only function that emits the live ruleset. Every UFW toggle —
// killswitch, Local Network, IPv6 — assembles a full State and calls Reconcile;
// nothing edits rules incrementally. A full teardown-and-rebuild on every change
// is what makes rule ordering, the killswitch/Stealth DHCP-in dedup, and layer
// independence structurally correct instead of something to reconcile by hand.
type State struct {
	Killswitch    bool   // killswitch engaged
	Connected     bool   // a tunnel is up → full killswitch (endpoint allow + physical-interface reject); else "simple" (no tunnel to protect)
	InterfaceName string // VPN interface, e.g. wg0
	Endpoint      string // VPN endpoint IP (handshake / reconnect carve-out)
	DNS           string // comma-separated DNS server IPs
	Gateway       string // physical default gateway; Reconcile detects it when ""
	LANMode       LANMode
	IPv6Blocked   bool // emit the v6 UFW deny rules (the kernel disable_ipv6 sysctl is managed separately)
}

// allLazyvpnTags is every comment tag lazyvpn owns; Reconcile clears them all
// before each rebuild.
var allLazyvpnTags = []string{TagKillswitch, TagLANBlock, TagStealth, TagLANAllow, TagIPv6}

// Reconcile rebuilds the entire lazyvpn firewall ruleset from the desired state.
func Reconcile(s State) error {
	ufwMu.Lock()
	defer ufwMu.Unlock()
	return reconcileLocked(s)
}

// reconcileLocked implements Reconcile; caller holds ufwMu.
//
// Rebuild order is fixed and load-bearing:
//  1. Local Network rules (allow-out FIRST → lowest rule numbers)
//  2. IPv6 deny rules
//  3. Killswitch allows, then the physical-interface reject LAST
//  4. Default policies (deny in+out when the killswitch is on; otherwise allow
//     outgoing and restore the captured incoming policy)
//
// Because the LAN allow-out rules are emitted before the killswitch reject,
// LAN egress always wins by UFW first-match — no post-hoc re-ordering needed.
func reconcileLocked(s State) error {
	physIface, gw, _ := GetPhysicalInterface()
	if s.Gateway == "" {
		s.Gateway = gw
	}

	log("Reconciling firewall (killswitch=%v connected=%v lan=%d ipv6Blocked=%v)",
		s.Killswitch, s.Connected, s.LANMode, s.IPv6Blocked)

	// Clean slate: drop everything lazyvpn owns, then rebuild from scratch.
	for _, tag := range allLazyvpnTags {
		if err := deleteRulesByTag(tag); err != nil {
			log("Warning: reconcile could not clear tag %s: %v", tag, err)
		}
	}

	// lazyvpn always manages at least the Local Network layer, so UFW must be
	// active for the rebuilt rules to enforce. (Teardown is the only path that
	// removes everything and releases UFW.)
	if err := ensureUFWEnabled(); err != nil {
		return fmt.Errorf("reconcile: activate UFW: %w", err)
	}

	// 1. Local Network layer — allow-out rules land first (lowest numbers).
	if err := emitLANRules(s, physIface); err != nil {
		return fmt.Errorf("reconcile: LAN rules: %w", err)
	}

	// 2. IPv6 UFW deny rules.
	if s.IPv6Blocked {
		emitIPv6DenyRules()
	}

	// 3 & 4. Killswitch (allows + reject last) and the outgoing default.
	//
	// The killswitch is OUTBOUND-ONLY: it forces traffic through the tunnel and
	// stops leaks out, and never touches the incoming policy. Inbound is owned
	// entirely by the Local Network layer above (Allow permits LAN in; Stealth
	// and Block deny all unsolicited inbound). For a laptop behind NAT that's
	// the complete inbound story — unsolicited WAN inbound can't reach the host,
	// LAN inbound is the LAN layer's job, and replies come back via conntrack.
	if s.Killswitch {
		emitKillswitchRules(s, physIface)
		if err := addRule("default", "deny", "outgoing"); err != nil {
			return fmt.Errorf("reconcile: deny outgoing: %w", err)
		}
	} else {
		if err := addRule("default", "allow", "outgoing"); err != nil {
			return fmt.Errorf("reconcile: allow outgoing: %w", err)
		}
	}

	return validateState(s)
}

// emitLANRules writes the Local Network layer for the desired mode. Allow-out
// rules are written before deny rules so they precede the later killswitch
// reject. Caller holds ufwMu.
func emitLANRules(s State, physIface string) error {
	switch s.LANMode {
	case LANAllow:
		// Explicit full LAN access: allow out to and in from private ranges.
		for _, cidr := range append(append([]string{}, privateCIDRsV4...), privateCIDRsV6...) {
			if err := addRule("allow", "out", "to", cidr, "comment", TagLANAllow); err != nil {
				return err
			}
		}
		if physIface != "" {
			for _, cidr := range append(append([]string{}, privateCIDRsV4...), privateCIDRsV6...) {
				if err := addRule("allow", "in", "on", physIface, "from", cidr, "comment", TagLANAllow); err != nil {
					return err
				}
			}
		}
	case LANStealth:
		// Coffee-shop mode: reach out to the LAN, but nobody reaches in — from
		// the LAN OR the internet. DHCP-in first (not conntrack-tracked), then
		// allow-out to the LAN, then a single broad deny-in on the physical
		// interface. UFW's before.rules accept established/related and essential
		// ICMPv6 (NDP) ahead of this, so replies and IPv6 still work; only
		// unsolicited inbound is dropped.
		if physIface != "" {
			if err := addRule("allow", "in", "on", physIface, "proto", "udp", "from", "any", "port", "67:68", "comment", TagStealth); err != nil {
				return err
			}
		}
		for _, cidr := range append(append([]string{}, privateCIDRsV4...), privateCIDRsV6...) {
			if err := addRule("allow", "out", "to", cidr, "comment", TagStealth); err != nil {
				return err
			}
		}
		if physIface != "" {
			if err := addRule("deny", "in", "on", physIface, "comment", TagStealth); err != nil {
				return err
			}
		}
	case LANBlock:
		// Total LAN isolation: the only locally-reachable thing is the gateway
		// (so you can still route out to the internet/VPN). Everything else on
		// the LAN is cut, in and out, and ALL unsolicited inbound is dropped
		// (LAN and internet — no SSH in, nothing). Replies/NDP still work via
		// UFW's before.rules.
		if err := addRule("allow", "out", "on", "lo", "comment", TagLANBlock); err != nil {
			return err
		}
		// The gateway — the one local exception (must precede the LAN deny-out).
		if s.Gateway != "" && validateIP(s.Gateway) {
			if err := addRule("allow", "out", "to", s.Gateway+"/32", "comment", TagLANBlock); err != nil {
				return err
			}
		}
		// Tunnel + endpoint + VPN DNS so the VPN itself keeps working (these are
		// on tunnel-only / private IPs that the LAN deny-out below would catch).
		if s.InterfaceName != "" {
			if err := addRule("allow", "out", "on", s.InterfaceName, "comment", TagLANBlock); err != nil {
				return err
			}
		}
		if s.Connected && s.Endpoint != "" && validateIP(s.Endpoint) {
			if err := addRule("allow", "out", "to", s.Endpoint, "comment", TagLANBlock); err != nil {
				return err
			}
		}
		for _, dnsAddr := range splitTrim(s.DNS) {
			if !validateIP(dnsAddr) {
				continue
			}
			if err := addRule("allow", "out", "proto", "udp", "to", dnsAddr, "port", "53", "comment", TagLANBlock); err != nil {
				return err
			}
			if err := addRule("allow", "out", "proto", "tcp", "to", dnsAddr, "port", "53", "comment", TagLANBlock); err != nil {
				return err
			}
		}
		if err := addRule("allow", "out", "proto", "udp", "to", "any", "port", "67:68", "comment", TagLANBlock); err != nil {
			return err
		}
		// Deny LAN egress (the gateway/tunnel/DNS exceptions above already won).
		for _, cidr := range append(append([]string{}, privateCIDRsV4...), privateCIDRsV6...) {
			if err := addRule("deny", "out", "to", cidr, "comment", TagLANBlock); err != nil {
				return err
			}
		}
		// Deny ALL unsolicited inbound on the physical interface.
		if physIface != "" {
			if err := addRule("deny", "in", "on", physIface, "comment", TagLANBlock); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitIPv6DenyRules writes the UFW IPv6 block rules. Caller holds ufwMu.
func emitIPv6DenyRules() {
	if err := addRule("deny", "out", "to", "::/0", "comment", TagIPv6); err != nil {
		log("Warning: failed to add IPv6 outbound block rule: %v", err)
	}
	if err := addRule("deny", "in", "from", "::/0", "comment", TagIPv6); err != nil {
		log("Warning: failed to add IPv6 inbound block rule: %v", err)
	}
}

// emitKillswitchRules writes the killswitch allow rules and, when a tunnel is
// up, the physical-interface reject LAST. Caller holds ufwMu.
//
// The killswitch's purpose: if the tunnel drops, nothing reaches the clear
// network except the gateway link and the minimum needed to re-establish
// (endpoint handshake, DHCP, loopback). Everything else is dropped by the deny
// defaults + reject the caller adds after this.
func emitKillswitchRules(s State, physIface string) {
	// Loopback both directions (local processes, systemd-resolved).
	_ = addRule("allow", "out", "on", "lo", "comment", TagKillswitch)
	_ = addRule("allow", "in", "on", "lo", "comment", TagKillswitch)

	// DNS to the configured servers (VPN DNS lives on a tunnel-only IP, so it
	// fails closed when the tunnel is down — no clearnet DNS leak).
	for _, dnsAddr := range splitTrim(s.DNS) {
		if !validateIP(dnsAddr) {
			continue
		}
		_ = addRule("allow", "out", "proto", "udp", "to", dnsAddr, "port", "53", "comment", TagKillswitch)
		_ = addRule("allow", "out", "proto", "tcp", "to", dnsAddr, "port", "53", "comment", TagKillswitch)
	}

	// VPN endpoint (handshake / reconnect) — only meaningful with a tunnel.
	if s.Connected && s.Endpoint != "" && validateIP(s.Endpoint) {
		_ = addRule("allow", "out", "to", s.Endpoint, "comment", TagKillswitch)
	}

	if physIface != "" {
		// Endpoint reachable on the physical interface (reconnect path).
		if s.Connected && s.Endpoint != "" && validateIP(s.Endpoint) {
			_ = addRule("allow", "out", "on", physIface, "to", s.Endpoint, "comment", TagKillswitch)
		}
		// Gateway both directions — the bare link the killswitch must always keep.
		if s.Gateway != "" && validateIP(s.Gateway) {
			_ = addRule("allow", "out", "on", physIface, "to", s.Gateway, "comment", TagKillswitch)
			_ = addRule("allow", "in", "on", physIface, "from", s.Gateway, "comment", TagKillswitch)
		}
		// DHCP both directions (lease renewal keeps the link alive).
		_ = addRule("allow", "out", "on", physIface, "proto", "udp", "to", "any", "port", "67:68", "comment", TagKillswitch)
		_ = addRule("allow", "in", "on", physIface, "proto", "udp", "from", "any", "port", "67:68", "comment", TagKillswitch)
	}

	// The tunnel itself — all traffic in/out of wg0.
	if s.InterfaceName != "" {
		_ = addRule("allow", "out", "on", s.InterfaceName, "comment", TagKillswitch)
		_ = addRule("allow", "in", "on", s.InterfaceName, "comment", TagKillswitch)
	}

	// Leak guard: reject anything else leaving the physical interface. MUST be
	// last so the allow rules above (and the LAN allow-outs from emitLANRules)
	// win by first-match. Only meaningful with a tunnel up.
	if s.Connected && physIface != "" && s.InterfaceName != "" {
		_ = addRule("reject", "out", "on", physIface, "comment", TagKillswitch)
	}
}

// validateState confirms the rebuilt ruleset matches the desired posture in the
// way that matters most: when the killswitch is on, the outgoing default must
// actually read "deny" (a rule that silently failed to apply would leave a
// leak). The killswitch is outbound-only, so it makes no claim about incoming.
func validateState(s State) error {
	if !s.Killswitch {
		return nil
	}
	if got := getDefaultOutgoingPolicy(); got != "deny" {
		return fmt.Errorf("reconcile validation: killswitch on but default outgoing is %q, not deny", got)
	}
	return nil
}

// splitTrim splits a comma-separated list and trims/filters empties.
func splitTrim(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

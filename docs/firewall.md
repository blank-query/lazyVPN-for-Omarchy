# Firewall: Killswitch + LAN Modes

Two toggles on the dashboard: **Killswitch** (ON/OFF) and **Local Network** (Allow/Stealth/Block). Both are UFW-backed. Same underlying machinery, different rule sets, different tags. This file covers both because the interactions between them are where most user confusion lives.

For IPv6 leak protection (a separate, kernel-stack-level thing), see [ipv6.md](ipv6.md).

---

## Why UFW

lazyVPN doesn't ship its own firewall, doesn't write iptables rules directly, doesn't run an `nftables` table. It composes UFW rules tagged with comments so they're identifiable and removable.

Three reasons:
1. **You can audit it.** `ufw status numbered` shows every rule lazyVPN owns (tagged) alongside everything else. Raw nftables tables are a separate namespace per app, harder to inspect.
2. **It survives reboots cleanly.** UFW reapplies its rule set on boot via `ufw.service`. Killswitch state persists without lazyVPN doing anything at boot time.
3. **It's the system source of truth.** The dashboard reads UFW state directly to decide what to display — not a config file's "is killswitch enabled" bit. If something else flips a UFW rule (your sysadmin, you on a bad day), the dashboard reflects what's actually enforced.

The rule tags lazyVPN uses:

| Tag | Meaning |
|---|---|
| `lazyvpn:ks` | Killswitch rules |
| `lazyvpn:lb` | LAN Block rules |
| `lazyvpn:st` | LAN Stealth rules |
| `lazyvpn:v6` | IPv6 deny rules (see [ipv6.md](ipv6.md)) |

Disabling any toggle deletes only the matching tag's rules. They don't step on each other.

---

## Killswitch

The killswitch's job is one sentence: if the VPN drops, no traffic leaves the machine that didn't already go through it.

### What it adds when you toggle it on

In this order:

1. `ufw default deny outgoing` — flips the default policy. Nothing leaves unless explicitly allowed.
2. `ufw allow out on lo` — loopback, always.
3. `ufw allow out proto udp/tcp to <DNS> port 53` — your VPN's DNS servers (one rule per family).
4. `ufw allow out to <endpoint IP>` — the WireGuard server you're connected to. This is the handshake escape route.
5. **WebRTC isolation** (only if a physical interface is detected):
   - Allow `endpoint IP` on physical interface
   - Allow `gateway` on physical interface
   - Allow `67:68/udp` (DHCP) on physical interface
   - **Reject everything else on physical interface** — this is the part that kills WebRTC and other STUN-style leak vectors
6. **Local network passthrough** (only if "Local Network: Allow" is set, see below):
   - Allow out to each private CIDR (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `169.254.0.0/16`)
   - Same set for v6 ULAs (`fe80::/10`, `fc00::/7`)
7. `ufw allow out on <vpn-iface>` — the only general "outbound traffic OK" rule, and it's locked to wg0.

Every rule above is tagged `lazyvpn:ks`. Disabling the killswitch deletes every rule with that tag, then resets the default policy.

### What it looks like in practice

Killswitch on, you're connected:
- DNS query → goes to VPN's DNS via wg0 ✓
- Web traffic → routed through wg0, allowed by the wg0 rule ✓
- A misbehaving app trying to bind to your physical NIC → REJECTed ✗
- Your laptop's auto-update talking to the LAN → blocked unless "Local Network: Allow" is set

Killswitch on, VPN drops:
- wg0 interface goes away
- Default deny outgoing is still active
- DNS allow rule references the VPN DNS (no longer reachable) → DNS fails
- Endpoint allow → endpoint is unreachable, traffic blackholes
- Net effect: no traffic leaves until you reconnect or disable the killswitch

### IPv6 with killswitch

The killswitch's v6 rules mirror the v4 ones (UFW's default `IPV6=yes` creates parallel rules). So with killswitch ON, if your VPN supports IPv6 (`AllowedIPs` includes `::/0` or some v6 range), v6 flows through wg0. If it doesn't, the kernel has no v6 route to wg0 and v6 traffic gets either blackholed or rejected at the firewall — no leak either way.

You don't need the IPv6 toggle Blocked for the killswitch to handle v6 leaks. The IPv6 toggle is a heavier hammer (kernel-level disable). Killswitch handles "v6 traffic shouldn't escape via the physical NIC" cleanly on its own.

### "KS on Disconnect" setting

Three values: Auto / Prompt / Off. This controls what happens when *you* disconnect (not when the VPN drops):

- **Auto** (default): killswitch turns off when you disconnect cleanly. Most users want this — disconnecting means "I'm done, give me my normal internet."
- **Prompt**: TUI asks each time. Good for paranoid sessions where you sometimes want to leave the killswitch up after disconnecting.
- **Off**: killswitch stays on after disconnect. You'll have no internet until you manually disable it. Useful if you're disconnecting briefly to switch servers.

This setting doesn't affect what happens on a *crash* (VPN drops, daemon dies, etc.) — the killswitch always stays up in those cases. That's the whole point.

### EnableSimple — killswitch with no VPN context

If you toggle killswitch ON before ever connecting (or while disconnected), there's no endpoint, no DNS, no VPN interface to allow. lazyVPN takes a simpler path: just `default deny outgoing` + loopback allow.

Result: total internet blackout except localhost. Not super useful unless you specifically want that, but it's a real configuration. Toggling off restores allow.

---

## LAN Modes

Three values, mutually exclusive: **Allow**, **Stealth**, **Block**. The toggle on the dashboard cycles through them.

Each mode controls how lazyVPN treats traffic to/from RFC1918 ranges (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `169.254.0.0/16`) and the v6 equivalents (`fe80::/10`, `fc00::/7`).

### Allow (default)

lazyVPN doesn't add any LAN-related rules. Your machine talks to your router, your printer, your NAS, your other devices, normally — assuming your VPN config and the killswitch don't get in the way.

If the killswitch is also ON in this mode, the killswitch builder adds *allow out* rules to the private CIDRs (tagged `lazyvpn:ks`, see step 6 above). LAN access stays intact even with killswitch protecting your egress.

UFW rules with tag `lazyvpn:lb` or `lazyvpn:st`: **none**.

### Stealth

Blocks **inbound** connections from private CIDRs. Outbound is unaffected.

Use case: coffee shop, hotel WiFi, anywhere you don't trust the other devices on the network. They can't probe your machine, but you can still reach the internet (through the VPN, normally) and use your own gateway for DHCP/DNS.

UFW rules added (tagged `lazyvpn:st`):
- DENY in from each private CIDR on physical interface
- ALLOW in from DHCP source (`67:68/udp`) — otherwise your lease can't renew
- Same set for IPv6 (deny `fe80::/10` + `fc00::/7` inbound, allow DHCPv6)

Note this is **interface-scoped** (`on enp7s0` or whatever your physical NIC is). Local services on `lo` aren't affected.

### Block

Blocks **both inbound AND outbound** to private CIDRs. Bidirectional severance.

Use case: you want zero LAN interaction. No talking to local devices, no LAN DNS lookups, no `arp` chatter beyond what the kernel has to do. Effectively you exist on the network only as a VPN endpoint.

UFW rules added (tagged `lazyvpn:lb`):
- ALLOW out to your VPN's DNS (so DNS still works — VPN DNS is often on a private IP like `10.2.0.1`, would otherwise be denied)
- ALLOW out on `lo` and on VPN interface
- ALLOW out to endpoint and gateway/32
- ALLOW out `67:68/udp` (DHCP renewal)
- DENY out to each private CIDR
- DENY in from each private CIDR
- v6 mirrors

The DNS-allow rule has to come **before** the deny-CIDR rules — UFW evaluates in order and your VPN DNS server is usually inside one of the private ranges. Without that priority, blocking LAN also breaks DNS resolution.

### Cycle order in the TUI

The dashboard's "Local Network" toggle cycles `Allow → Stealth → Block → Allow → ...`. There's a 3-4 second delay on each transition because UFW rule additions/deletions are not instant.

Mid-cycle you might briefly see a state with both `lazyvpn:st` and `lazyvpn:lb` rules in `ufw status`. That's the rule-removal-then-rule-addition window. By the time the dashboard updates, exactly one mode's rules are present (or none, for Allow).

---

## Killswitch ↔ LAN Mode interactions

Layered, not exclusive. Every combination is valid:

| Killswitch | LAN mode | Effect |
|---|---|---|
| OFF | Allow | LAN works normally, no VPN-related blocking |
| OFF | Stealth | LAN inbound blocked, outbound free, no killswitch |
| OFF | Block | LAN bidirectionally blocked, internet free (no VPN) |
| ON | Allow | Killswitch protects internet, LAN works (killswitch installs allow-out for private CIDRs) |
| ON | Stealth | Killswitch + LAN inbound deny |
| ON | Block | Killswitch + LAN bidirectional block. DNS still works (priority allow). |

The killswitch's `lazyvpn:ks` rules and the LAN mode's `lazyvpn:st` or `lazyvpn:lb` rules coexist independently. Disabling killswitch removes only `:ks` rules. Switching LAN modes only touches `:st`/`:lb` rules.

Changing LAN mode while killswitch is up triggers a killswitch rebuild — the killswitch builder includes/excludes the LAN-allow rules based on the new mode. So toggling Allow → Block → Allow with killswitch ON updates the live ruleset correctly.

---

## Why these three LAN modes and not more

Allow + Block are obvious. Stealth exists as a middle ground because there's a real use case — public WiFi where you DO want to use the local gateway for DHCP/DNS but DON'T want the network's other devices probing you. "Allow" is too loose for that, "Block" is too strict.

A fourth mode of "block inbound and outbound EXCEPT my router" was considered but rejected: identifying "my router" reliably is fiddly, and Block + DHCP-allow + gateway-allow gets you 95% there if you really need it.

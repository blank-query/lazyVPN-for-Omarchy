# Changelog

All notable changes to LazyVPN are documented here.

## 1.0.2

### Local Network and killswitch are now fully independent layers
- **Local Network mode is a standing constant**, in effect whether or not the
  killswitch is engaged. All three modes now lay down **explicit, inspectable**
  UFW rules per private range (no more relying on the base policy):
  - **Allow** — allow inbound + outbound to private ranges (genuine full LAN
    access, even on a deny-incoming base like Omarchy's default)
  - **Stealth** — allow outbound, deny inbound (coffee-shop mode)
  - **Block** — deny inbound + outbound
- **Stealth is now the default**, established as a visible, consented step
  during `install` — it matches a typical desktop firewall (and Omarchy's own
  default): reach out to LAN devices, but nothing on the network can reach in.
- **The killswitch no longer touches LAN traffic at all** — it owns leak
  prevention only (force outbound through the tunnel, reject everything else off
  the physical interface). LAN egress survives the killswitch by UFW first-match
  ordering: the Local Network allow-out rules carry lower rule numbers than the
  killswitch's reject. Changing LAN mode while the killswitch is on re-applies
  the killswitch so its reject stays last.

### State-aware update action
- The Settings **update control is now 2-state**: it reads "Check for Updates
  Now" until a check finds a newer release, then becomes "Install update
  X.X.X" — selecting it installs. The nav-banner confirm dialog now labels its
  button "Install" to match.

## 1.0.1

- Fix the **Check for Updates Now** action: the result (up to date / update available / error) now displays in the footer instead of getting stuck on "Checking…".

## 1.0.0 — Go rewrite (initial release)

LazyVPN is now a single Go binary. There is **no upgrade path** from the
previous bash-script version — they share nothing in common at the
implementation level. To switch:

```bash
# 1. Uninstall the bash version (run from where you have the old script)
./uninstall_lazyVPN.sh

# 2. Install the Go version
git clone https://github.com/blank-query/lazyVPN-for-Omarchy.git
cd lazyVPN-for-Omarchy
./lazyvpn install
```

The bash version is preserved on the `old-stable` branch for reference.

Below is the list of what's different — useful if you're deciding whether
to switch and want to know what changes.

### Single binary
- One statically-linked `~/.local/bin/lazyvpn` instead of `install_lazyVPN.sh`,
  helper scripts, and Walker menu entries scattered across the system.
- Privileged operations use `CAP_NET_ADMIN` + `CAP_NET_RAW` file capabilities
  on the binary plus a tightly-scoped `/etc/sudoers.d/lazyvpn` (NOPASSWD only
  for the exact `ip`/`ufw`/`resolvectl`/`tee`/`rm` invocations the runtime
  makes — no blanket sudo).

### Network management
- WireGuard tunnels are created and torn down via direct **netlink + wgctrl**
  calls, not `wg-quick` or `systemd-networkd` `.netdev`/`.network` drop-ins.
- **UFW** is the firewall layer for killswitch / LAN block / LAN stealth /
  IPv6 protection. Rules are tagged (`lazyvpn:ks`, `lazyvpn:lb`, `lazyvpn:st`,
  `lazyvpn:v6`) for clean enable/disable. Replaces the bash version's
  iptables rule-file management.
- DNS configured via systemd-resolved through `resolvectl`.

### TUI
- Full-screen Bubbletea TUI with Lip Gloss styling, replacing the bash
  version's Walker pop-up menus and `fzf` server browser.
- Live dashboard: connection state, server flag, public IP, endpoint, DNS,
  uptime, transfer counters, bandwidth chart, and a 0–100 health grade
  (Excellent/Good/Fair/Poor/Bad) computed from handshake age, latency,
  packet loss, and DNS health.
- Settings: two-column layout for Providers, Automation, Servers, Debug,
  Advanced. Settings include autoconnect-on-boot, auto-recover, auto-failover,
  auto-check-updates, custom MTU, WireGuard interface name, health-check
  targets.
- First-run tutorial with 9 pages.

### Dynamic server browser (new)
- Fetches per-provider WireGuard server lists — mirrored from
  [gluetun-servers](https://github.com/qdm12/gluetun-servers) into this repo's
  `server-data` branch (refreshed weekly by a GitHub Action) — and lets you
  browse the provider's full network in-TUI: search-as-you-type, feature
  filters (P2P, Tor, Streaming, Secure Core, Free), latency probe, fastest-pick,
  favorites.
- Provider setup is one config file: drop a single `.conf` from your
  provider in `~/Downloads`, point lazyvpn at it, credentials are extracted
  and cached. The bash version required one `.conf` per server.

### Supported providers
- **Verified:** ProtonVPN.
- **Experimental** (wired but unverified): Mullvad, IVPN, AirVPN, NordVPN,
  Surfshark, Windscribe, FastestVPN.
- See [`docs/providers.md`](docs/providers.md) for the full tier matrix and
  the three criteria a provider must meet (in gluetun with WireGuard
  entries, supports WireGuard, user can download a `.conf`).

### Killswitch
- UFW-based with explicit allow rules (loopback, DNS, VPN endpoint, VPN
  interface, optional private CIDRs, WebRTC isolation on the physical
  interface) plus default-deny outgoing. Atomic enable/disable with rollback
  on failure.
- Per-disconnect behavior is configurable: `Auto` (clear killswitch on
  disconnect), `Prompt` (let CLI/TUI ask), `Never` (keep blocking).
- Killswitch state is read from UFW directly — UFW is the source of truth,
  not a persisted config bit. Replaces the bash version's iptables rules-file
  approach.

### Auto-recovery and failover
- Background daemon monitors the tunnel every 5s (configurable). Bad
  handshake / packet loss / DNS failures lower the health score; below a
  threshold for N consecutive ticks triggers auto-reconnect.
- Auto-failover (opt-in): if a server fails repeatedly, switch to the next
  best one.
- The daemon uses an O_EXCL PID file with `/proc/<pid>/exe` identity
  verification — recycled PIDs from unrelated processes can't be killed by
  accident.

### Health checks
- Built-in **leak test**: public IP comparison against captured ISP baseline
  (no false-positive "is this a known VPN?" lookups), DNS reflection probes,
  WebRTC isolation test, IPv6 leak detection.
- Built-in **speed test**: 10 × 1 MB downloads averaged.
- Built-in **security audit**: 6 checks (IPv4 routing, IPv6 leak, DNS
  encryption, WebRTC isolation, killswitch test, MTU analysis).

### Configuration
- All state under `~/.config/lazyvpn/`:
  - `config.json` — settings (snake_case JSON)
  - `wireguard/*.conf` — manually imported WireGuard configs (chmod 600)
  - `providers/*.json` — provider credentials (chmod 600)
  - `cache/*.json` — cached server lists, refreshed weekly
- Atomic writes via temp file + rename. Filesystem-aware delete for
  uninstall: `rm` on copy-on-write filesystems (btrfs/ZFS), `shred -u` on
  traditional filesystems (ext4/xfs).

### CLI
- `lazyvpn` — TUI (default).
- `lazyvpn random` / `quickest` — connect without TUI.
- `lazyvpn killswitch enable|disable|off|status` — emergency CLI control.
- `lazyvpn daemon stop|status` — stop the connection daemon.
- `lazyvpn update` — check GitHub for new release, download + replace in place
  on confirm.
- `lazyvpn install|uninstall` — interactive installer / uninstaller.

### Uninstaller
- 16 numbered steps. Tears down UFW rules, stops the daemon, removes
  Hyprland keybindings + window rules, removes Waybar integration, removes
  from PATH, removes `.desktop` autostart and launcher entries, prompts
  about debug-log deletion, removes credentials + config + cache + manual
  WireGuard configs, prompts about journal scrubbing (sudo) + shell history
  scrub, removes the sudoers file, removes the binary, and on btrfs prompts
  about scanning snapper snapshots.
- Each delete attempt is reported per-file (`shredded` / `removed` / `file
  not found` / `failed`). On failure the uninstaller prompts: retry with
  sudo, fall back to `rm` (flagged as insecure), or skip — no silent recovery.

### What's removed from the bash version
- `wg-quick` invocation — replaced by direct netlink/wgctrl.
- `systemd-networkd` `.netdev`/`.network` files — never written.
- iptables rules-file management — replaced by UFW.
- `bc`, `curl` runtime dependencies — Go stdlib + wgctrl.
- Walker menus, `fzf` server browser, `lazyvpn-file-helper` script — replaced
  by the in-binary TUI.

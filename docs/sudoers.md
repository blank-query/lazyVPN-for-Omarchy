# Sudoers

lazyVPN installs a NOPASSWD sudoers file at `/etc/sudoers.d/lazyvpn` so the runtime can do its job without prompting you every 30 seconds. Everything in that file is exact-argv-matched and scoped to the operations lazyVPN actually performs. Nothing in there is a blanket grant.

## What's in the file

The grants fall into a handful of categories:

**WireGuard interface ops** (scoped to your chosen interface name — usually `wg0`):
- `ip link add/delete/set dev <iface>`
- `ip link set dev <iface> mtu *`
- `ip addr add * dev <iface>`
- `ip route add 0.0.0.0/1 dev <iface>` and `128.0.0.0/1` (the split routes)

**Per-physical-interface host routes** (one entry per detected NIC, e.g. `enp7s0`, `wlan0`):
- `ip route add * via * dev <nic>` — used to route VPN handshake packets via the ISP gateway, bypassing the tunnel itself

**DNS**:
- `resolvectl dns/domain/revert <iface> ...`

**Firewall**:
- `ufw <subcommand> ...` — covers killswitch, LAN block/stealth, IPv6 deny rules, log levels (off/low/medium/high/full — enumerated, not wildcarded)

**IPv6 leak protection**:
- `tee /etc/sysctl.d/99-lazyvpn-ipv6.conf` (write the persistent conf)
- `sysctl -p /etc/sysctl.d/99-lazyvpn-ipv6.conf` (apply it without reboot)
- `rm /etc/sysctl.d/99-lazyvpn-ipv6.conf` (toggle off)

**Journald** (uninstaller-only):
- `systemctl start/stop systemd-journald` — to clean lazyVPN entries from the journal

**Capability management** (install-only):
- `setcap cap_net_admin,cap_net_raw=ep <binary path>`

**File removal**:
- `rm /etc/sudoers.d/lazyvpn` (uninstall)

That's the whole list.

## What's deliberately NOT in there

These are operations lazyVPN's runtime needs sometimes but should always prompt for:

- **`shred -u <journal files>`** and **`rm <journal files>`** — log destruction. The uninstaller asks for your password explicitly when scrubbing journal entries.
- **`snapper delete`** — modifying base-OS snapshot history. Manual sudo only.
- **`systemctl restart/reload systemd-networkd`** — never needed; the rewrite uses netlink directly.
- **`cp` and `chmod`** for the sudoers file itself — install-only, sudo cache is warm from `sudo -v`.
- **General `sysctl -w`** — only the `-p <our specific conf>` form is granted.

The principle: anything that touches base-OS state outside of "the things VPN ops actually do" requires you to retype your password. That's the trade-off for not having to enter it every time you connect.

## Why per-NIC scoping for routes

The host-route grant could have been written as `ip route add * via * dev *` — accept any device. We don't do that. Instead, lazyVPN detects your physical interfaces at install time (`enp3s0`, `wlan0`, etc.) and emits one grant per real NIC.

If at install time you have no physical interfaces detected (running in a stripped container, weird state), lazyVPN emits **no** wildcard fallback. Route-add will fail loudly at use time rather than silently granting `* via * dev *`. You'll know.

## What happens if you decline sudoers at install

The install asks you `Enable passwordless sudo for VPN commands? [Y/n]`. If you say no:

- File is not written.
- `cfg.SudoersInstalled` is set false in your config.
- TUI usage still works — every action that needs sudo will surface an auth prompt (a modal in the TUI, not a hidden shell prompt).
- CLI subcommands (`lazyvpn killswitch enable`, `lazyvpn quickest`, etc.) will exit cleanly with a hint pointing you at `lazyvpn install` to add the entries.

This is supported but slower — every connect/disconnect interrupts you for a password.

## Renaming your interface regenerates the file

If you change the WireGuard interface name in Settings (e.g. `wg0` → `wgtest`), the sudoers entries scoped to the old name become stale. The TUI handles this automatically: rename triggers `sudo.InstallSudoers` again with the new name, the file is regenerated, the old grants are gone.

This needs sudo because `cp` and `chmod` to `/etc/sudoers.d/` aren't NOPASSWD-granted (deliberately). The TUI's auth prompt fires once for that flow.

## Why `/etc/sudoers.d/lazyvpn` and not `/etc/sudoers`

Modifying the main `/etc/sudoers` file is the single most common way to lock yourself out of sudo. Drop-ins in `/etc/sudoers.d/` are loaded by the same parser but isolated — a syntax error in our file doesn't break your other entries. lazyVPN also runs `visudo -cf` against the staged file before installing it, so a malformed grant never reaches `/etc/sudoers.d/`.

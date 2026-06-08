# Architecture

A single Go binary, four moving parts.

## The pieces

**TUI** (`internal/ui`) — the Bubbletea front-end you see when you run `lazyvpn`. Owns the dashboard, settings page, server browsers, dialogs. Stateless — reads config from disk on launch, reads system state on demand. When you toggle something, the TUI calls into the firewall/wireguard packages directly, then re-reads system state to confirm what actually happened.

**Daemon** (`internal/daemon`) — a long-running process spawned by the TUI when you connect. Owns the connection lifecycle: health checks, auto-recover, sleep/wake handling, IPC with the TUI over a Unix socket. Exits when the connection ends. The daemon is what keeps the VPN alive when the TUI window closes.

**Firewall** (`internal/firewall`) — wraps UFW. Killswitch, LAN block/stealth, IPv6 deny rules. Every UFW rule lazyVPN owns is tagged with a comment (`lazyvpn:ks`, `lazyvpn:lb`, `lazyvpn:st`, `lazyvpn:v6`) so cleanup is unambiguous.

**Netlink** (`internal/netlink`) — direct kernel netlink + wgctrl calls for WireGuard interface ops. No `wg-quick`, no shell scripts. Falls back to `sudo -n ip link/addr/route ...` if the netlink syscall fails (e.g., capabilities stripped by something external).

## How a connection happens

```
You click "Connect" in TUI
  └── ui/dashboard.go calls wireguard.Connect()
        ├── netlink: create wg0 interface
        ├── netlink: configure WireGuard (peer, key, endpoint)
        ├── netlink: assign IP, bring up
        ├── netlink: add route to endpoint via gateway (so handshake escapes the tunnel)
        ├── netlink: add 0.0.0.0/1 + 128.0.0.0/1 split routes through wg0
        ├── DNS: configure via D-Bus (resolve1) or sudo resolvectl fallback
        └── spawn daemon
              ├── opens IPC socket at ~/.config/lazyvpn/.daemon.sock
              ├── starts health-check tickers (TCP ping, DNS probe)
              └── pushes status events back to TUI
```

Disconnect runs the same sequence backward. Ctrl+C in the TUI doesn't kill the daemon — the daemon owns its own lifecycle.

## Where state lives

| Lives in | What it is |
|---|---|
| `~/.config/lazyvpn/config.json` | User preferences (interface name, MTU, log toggles, baseline IP). lazyVPN-managed |
| `~/.config/lazyvpn/wireguard/*.conf` | WireGuard configs you imported. Standard WG format |
| `~/.config/lazyvpn/providers/*.json` | Provider credentials (private key + endpoint). One per provider |
| `~/.config/lazyvpn/cache/*.json` | Server lists fetched from gluetun. Refresh regenerates |
| `~/.config/lazyvpn/.daemon.{pid,sock}` | Runtime daemon files. Cleaned on disconnect |
| `~/.config/lazyvpn/debug.log` | Only if you turned on a log toggle |
| UFW rules (in-kernel) | Killswitch / LAN modes / IPv6 deny — lazyVPN tags them, doesn't store them in config |
| `/etc/sudoers.d/lazyvpn` | NOPASSWD grants for VPN ops — see [sudoers.md](sudoers.md) |
| `/etc/sysctl.d/99-lazyvpn-ipv6.conf` | Only when IPv6 protection is enabled |

The split between "in config.json" and "in UFW" is deliberate: anything UFW knows about is read from UFW directly. The dashboard never asks the config "is killswitch on?" — it asks UFW, because UFW is what's actually enforcing it. Same principle for IPv6 (reads `/proc`), LAN modes (reads UFW), and current connection state (reads `wgctrl`).

## Why no `wg-quick` or `systemd-networkd`

`wg-quick` is a 700-line bash script that pretends `iptables`, `nftables`, `ip route`, and `resolvconf` are interchangeable. They're not. Calling into it from a Go binary means shelling out, parsing its output, and catching cases where its assumptions don't match yours.

`systemd-networkd` would manage interfaces via drop-in files. That works, but it makes lazyVPN's interface state coupled to networkd's reload schedule, and it leaves files on the filesystem that the user can't easily inspect.

Direct netlink + wgctrl is one syscall per operation, deterministic, and the failure mode is a Go error — not a parser race against a shell script.

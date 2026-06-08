# IPv6

The dashboard has an `IPv6` toggle with two values: **Allowed** and **Blocked**. Default is Blocked, set during install.

## What "Blocked" actually does

Blocked is a heavier hammer than the label suggests. It's three layers of disabling IPv6, applied together:

1. **Kernel**: writes `1` to `/proc/sys/net/ipv6/conf/{all,default,lo}/disable_ipv6`. The IPv6 stack is off immediately, including loopback. No `::1` for you.
2. **Persistence**: writes `/etc/sysctl.d/99-lazyvpn-ipv6.conf` with the same three settings, so the disable survives a reboot. (Install also runs `sudo sysctl -p` against this file because the install process doesn't yet have the file capabilities to write `/proc` directly.)
3. **Firewall**: adds UFW DENY rules for all v6 traffic in both directions, tagged `lazyvpn:v6`. Belt-and-suspenders against any kernel weirdness or per-interface override.

## What "Allowed" means

The opposite. lazyVPN doesn't touch your IPv6 stack — kernel default applies, no sysctl conf, no UFW v6 deny rules.

## Why default Blocked

The reasoning starts from one number: very few consumer VPNs carry IPv6, and very few non-VPN consumer services *require* IPv6. For the typical user, IPv6 is a leak vector — the kernel happily routes v6 traffic out the physical interface even when v4 is going through the VPN — without offering anything they were going to use.

So we default to off. Power users who actually use IPv6 (Tailscale, mesh networks, local v6 services, IPv6-supporting VPNs) will know what the toggle is, recognize that disabling it breaks their setup, and flip it.

## When to set "Allowed"

If any of these apply, leave IPv6 Allowed:

- Your VPN's WireGuard config has `AllowedIPs` containing `::/0` or other v6 ranges. The provider supports IPv6 and you'll lose that capability if you Block.
- You use Tailscale or another mesh that does v6 routing.
- You bind local services to `::1` and need them reachable.
- You're on an IPv6-only network (rare but real — some mobile carriers, some new ISPs).

## Why not just rely on the killswitch for v6?

You can. The killswitch has v6 REJECT rules on the physical interface (see [firewall.md](firewall.md)). With killswitch ON, v6 traffic can't leak out your physical NIC even if the IPv6 stack is alive.

The IPv6 toggle is a *separate* mechanism that operates at the kernel-stack level, not the firewall level. There are scenarios where it matters:

- Killswitch is OFF and you don't want v6 leaking. The toggle blocks v6 regardless of UFW.
- You want zero v6 traffic, period — not even loopback, not even link-local. The toggle disables the stack entirely.
- You're trying to debug a leak and want to eliminate v6 from the equation entirely while you investigate.

For most people in most situations, killswitch handles v6 leak protection adequately. The IPv6 toggle exists for the cases where killswitch isn't enough or isn't appropriate.

## How the dashboard knows what state IPv6 is in

It reads `/proc/sys/net/ipv6/conf/all/disable_ipv6` directly. Not the config, not "did we add the UFW deny rule" — the kernel's actual current state.

This means: if you (or some other tool) flips the bit outside lazyVPN, the dashboard reflects reality on next refresh. `sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0` from a terminal → the dashboard's "IPv6: Blocked" flips to "Allowed" within a few seconds, and the per-state sync logic puts a notification on the screen telling you state changed externally.

## What happens at uninstall

The persistent sysctl conf, the UFW deny rules, and the kernel-state are all reverted. After uninstall, IPv6 is back to whatever your distro defaults to (almost always: enabled).

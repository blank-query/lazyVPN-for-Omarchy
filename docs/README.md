# lazyVPN Technical Docs

If you're reading these, you want more than the README gives. Each file describes one slice of how lazyVPN works — not every line of code, just enough that you can predict what it'll do before you run it.

| Doc | What's in it |
|---|---|
| [architecture.md](architecture.md) | The pieces (TUI, daemon, firewall, netlink, security) and how they fit |
| [sudoers.md](sudoers.md) | What lazyVPN can do without prompting, what it can't, and why |
| [firewall.md](firewall.md) | Killswitch + LAN modes — UFW rules, v4 + v6, interaction matrix |
| [ipv6.md](ipv6.md) | What "IPv6: Blocked" means, when to leave it Allowed |
| [deletion.md](deletion.md) | How files get removed, why CoW filesystems get a different path |
| [providers.md](providers.md) | Which VPN providers work, support tiers |

Read in order if you're new to the codebase, or jump to whichever is biting you right now.

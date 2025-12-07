# LazyVPN

**LazyVPN** is a powerful, script-based utility for managing WireGuard® VPN connections, built for Omarchy Linux. It replaces manual `systemd-networkd` configuration with a fast, keyboard-driven TUI.

## Table of Contents

- [Quick Start](#quick-start)
- [Requirements](#requirements)
- [Installation](#installation)
- [Screenshots](#screenshots)
- [Features](#features)
  - [Connection Management](#-connection-management)
  - [Security & Privacy](#-security--privacy)
  - [Automation](#-automation)
  - [Performance Testing](#-performance-testing)
  - [System Integration](#-system-integration)
- [Server Naming & Features](#server-naming--features)
- [Usage & Menu Structure](#usage--menu-structure)
- [Technical Details](#technical-details)
- [Uninstallation](#uninstallation)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [License](#license)

---

## Quick Start

```bash
git clone https://github.com/blank-query/lazyVPN-for-Omarchy.git
cd lazyVPN-for-Omarchy
./install_lazyVPN.sh
```

1. Press `SUPER+L` to open LazyVPN menu
2. Select `➕ Add New Server` to import `.conf` files from `~/Downloads`
3. Choose `⚡ Lowest Latency` to auto-connect to fastest server
4. Your connection is verified with IP checks and DNS leak testing

---

## Requirements

-   **Omarchy Linux** (this tool is built specifically for Omarchy and will not work on other distributions)
-	VPN provider that supports wireguard connections

**Dependencies** (auto-installed by installer):
-   `curl` - Speed tests and public IP detection
-   `bc` - Latency/speed calculations
-   `iptables` - Killswitch functionality
-   `bind-tools` - DNS leak testing (`dig`)

---

## Installation

```bash
git clone https://github.com/blank-query/lazyVPN-for-Omarchy.git
cd lazyVPN-for-Omarchy
./install_lazyVPN.sh
```

During installation, you'll be asked whether to enable **passwordless sudo** for VPN operations:
- **Yes (default)**: Specific VPN commands (`networkctl`, `ip route`, `iptables`, systemd-networkd) run without password prompts
- **No**: Password required for VPN operations (more secure for shared systems)

You can change this choice by uninstalling and reinstalling (server configs are preserved).

---

## Screenshots

### Main Menu & Connection
![Main Menu](images/01-main-menu.png)
*Main menu when disconnected*

![Connection Modes](images/02-connection-modes.png)
*Connection modes: lowest latency, random, choose, or last used*

![Server Selection](images/03-server-selection.png)
*Server picker with country flags, feature emojis, and real-time filtering*

![Connecting](images/04-connecting.png)
*Connection verification with IP and DNS leak checks*

### Testing & Configuration

<details>
<summary>Click to see more screenshots</summary>

![Tests Menu](images/05-tests-menu.png)
*Testing suite: latency, speed, DNS leak tests, and performance history*

![Killswitch Settings](images/06-killswitch-settings.png)
*Killswitch with local network access and disconnect behavior*

![Autoconnect Settings](images/07-autoconnect-settings.png)
*Autoconnect on boot with multiple mode options*

![Options Menu](images/08-options-menu.png)
*Server management, auto-recover daemon, IPv6 protection*

![Add Servers](images/09-add-servers.png)
*Smart server import with validation and duplicate prevention*

![Latency Test](images/10-latency-test-results.png)
*Parallel latency testing across all servers*

</details>

---

## Features

### 🔄 Connection Management

-   **Multiple Connection Modes**:
    -   **⚡ Lowest Latency**: Parallel latency tests across all servers, connects to fastest
    -   **🎲 Random Server**: Connect to randomly selected server
    -   **🌍 Choose Server**: Filterable `fzf` list with preview panel
    -   **🔄 Last Used**: Reconnect to most recent server

-   **Connection Verification**:
    -   IP verification before and after connection
    -   Automatic failure detection if traffic not routing through VPN
    -   Intelligent retry logic with prompts to retry or return to previous server
    -   Automatic cleanup of failed connections (no ghost interfaces)
    -   Killswitch-aware verification logic

-   **Seamless Server Switching**: Change servers without disconnecting - firewall rules and routes update automatically before connecting to new server

-   **Smart Display**:
    -   Server auto-renaming to standardized format using provider detection, filename parsing, and IP geolocation
    -   Pretty names with full locations and flags: `🇺🇸 United States - New York (123) • ProtonVPN`
    -   Feature emojis show capabilities at a glance: 🔄 P2P, 🔒 Secure Core, 🧅 Tor, 🚀 Accelerator, etc.
    -   Provider detection: ProtonVPN, Mullvad, IVPN, PIA, NordVPN, Surfshark, and others

-   **Real-time Status**: Menu bar shows verified connection state and current server

### 🛡️ Security & Privacy

-   **Firewall Killswitch**:
    -   iptables-based killswitch blocks all traffic if VPN disconnects
    -   **Dynamic updates**: Automatically allows traffic to new VPN endpoint *before* connecting (seamless server switching)
    -   **Configurable local network access**: Toggle LAN device access (printers, NAS) while killswitch active
    -   **Disconnect behavior**: Three modes:
        -   `🟢 AUTO`: Automatically disable killswitch on disconnect
        -   `🟡 PROMPT`: Ask whether to disable
        -   `🔴 NEVER`: Keep killswitch active (internet blocked until reconnect)

-   **🔁 Auto-Recover Daemon**:
    -   Background daemon monitors VPN connection health (10-second interval)
    -   3-strike failure threshold before triggering reconnection (30 seconds total)
    -   Attempts 3 reconnections to same server
    -   **Auto-failover** (optional): After 3 failed reconnects, switches to next-fastest server (disabled by default, toggle in Options menu)
    -   Logs to `~/.config/lazyvpn/auto-recover.log` with rotation (max 1000 lines)

-   **🔒 IPv6 Leak Protection**: Actively checks for and prevents IPv6 leaks (enabled by default, toggleable)

-   **🧪 DNS Leak Test**: Verifies DNS queries route through VPN's DNS servers, not your ISP's

-   **🗑️ Secure Deletion**:
    -   **During usage**:
        -   Adding servers: Optional secure deletion of original `.conf` files from Downloads
        -   Removing servers: Automatic shredding of configs and performance history
    -   **During uninstall**:
        -   Performance logs, configs, systemd-networkd files: Always shredded (3-pass)
        -   Server configs (private keys): User choice
        -   System journal logs: Optional surgical removal (only VPN-related logs)
        -   Shell history: Automatic cleanup of VPN commands (bash, zsh, fish)

-   **🔐 Security Hardening**:
    -   Input validation prevents path traversal and injection attacks
    -   Symlink detection in all file operations
    -   Secure file helper isolates privileged operations
    -   Atomic configuration updates prevent corruption
    -   Regex metacharacter validation for connection names

-   **📁 Configuration Storage**: Server configs stored in `~/.config/lazyvpn/wireguard/` (encrypted storage planned - see [Roadmap](#roadmap))

### ⚙️ Automation

-   **🔌 Autoconnect on Boot**:
    -   Four modes: `last used`, `lowest latency`, `random`, or `specific server`
    -   Waits up to 30 seconds for network connectivity before connecting
    -   Fallback to random if last-used server unavailable

-   **➕ Server Management**:
    -   **Add servers**: Guided `fzf` interface with:
        -   Automatic validation before and after import
        -   Provider and location detection (IP geolocation fallback)
        -   Standardized renaming and duplicate prevention
        -   Optional secure deletion of original files
    -   **Remove servers**: Secure deletion (shredded, not just deleted) with cleanup of performance history

-   **✏️ Interface Renaming**: Change network interface name (e.g., `wg0` → `lazyvpn`)

-   **Robust Configuration**:
    -   Atomic file writes prevent corruption
    -   Interactive recovery for deleted/corrupted configs
    -   **Automatic migration** from older versions:
        -   Renames deprecated settings
        -   Adds missing configuration keys
        -   Migrates daemon PID and log files

-   **Change Detection**: Automatically detects external `.conf` file additions/removals and notifies you

### 📊 Performance Testing

-   **⏱️ Latency Testing**:
    -   Test single server or all servers in parallel
    -   Optional non-VPN baseline comparison
    -   Results automatically recorded

-   **💨 Speed Testing**:
    -   Download speed test on current server (10MB test file)
    -   **Test all servers**: Sequential connection and speed test for comprehensive ranking
    -   Optional non-VPN baseline test
    -   Prevents usage while killswitch active (would block switching)

-   **📈 Performance History**:
    -   Automatic recording of all test results
    -   Summary view: Average speeds/latencies and test counts for all servers
    -   Detailed view: Last 20 tests for specific server with timestamps
    -   Tracks non-VPN results as `🌐 Direct (Non-VPN)` for comparison
    -   Automatic log rotation (max 100 entries per server)

### ✨ System Integration

-   **Omarchy Menu**: Adds LazyVPN entry to main Omarchy menu (`SUPER+ALT+SPACE`)
-   **Dedicated Keybinding**: `SUPER+L` (registered in Omarchy keybind help at `SUPER+K`)
-   **Desktop Notifications**: Clear notifications for all key events
-   **Passwordless Operation (Optional)**: Specific VPN commands only (not blanket sudo access)

---

## Server Naming & Features

### Automatic Server Renaming

VPN providers give configs inconsistent names like `wg-US-FREE-27.conf`, `SE-31-TOR.conf`, or `server-uk-123.conf`. LazyVPN automatically renames these to a standardized format when importing:

**Format**: `[Provider-]Country[-State][-City][-Features]#Number`

**Examples**:
-   `Proton-US-NY#123` → 🇺🇸 United States - New York (123) • ProtonVPN
-   `Mullvad-SE-Stockholm#5` → 🇸🇪 Sweden - Stockholm (5) • Mullvad
-   `IVPN-NL-Amsterdam-P2P#3` → 🇳🇱 Netherlands - Amsterdam (3) 🔄 • IVPN
-   `PIA-US-CA-LosAngeles#7` → 🇺🇸 United States - California, Los Angeles (7) • PIA
-   `Proton-CH-Tor#2` → 🇨🇭 Switzerland (2) 🧅 • ProtonVPN

**How it works**:
1. Provider detection from DNS, endpoint, or config contents
2. Location parsing from filename
3. Server IP geolocation fallback if filename parsing fails (ip-api.com, rate limited to 45 requests/min)
4. Feature detection (P2P, Tor, Secure Core, etc.) developed using the proton conf file conventions
5. Auto-numbering for servers in same location

### Feature Detection & Emojis

LazyVPN automatically detects server features from WireGuard configs and displays them with emoji indicators:

| Emoji | Feature | Detection Source |
|-------|---------|------------------|
| 🔄 | **P2P / Torrenting** | `# NAT-PMP (Port Forwarding) = on` in config |
| 🔒 | **Secure Core** (multi-hop) | Peer comment pattern: `CH/IS/SE-[EXIT_COUNTRY]#N` |
| 🧅 | **Tor Routing** | Peer comment contains `-TOR` |
| 🤡 | **Free Tier** | Peer comment contains `FREE` |
| 🚀 | **VPN Accelerator** | `# VPN Accelerator = on` in config |
| 🗡️ | **NetShield Level 1** (malware blocking) | `# NetShield = 1` in config |
| ⚔️ | **NetShield Level 2** (ads+malware blocking) | `# NetShield = 2` in config |
| 🎮 | **Moderate NAT** (gaming optimized) | `# Moderate NAT = on` in config |

**Example displays**:
```
🇸🇪 Sweden - Alberta, Roslagen (1) 🔄🔒🚀 • ProtonVPN
    └─ P2P support, Secure Core multi-hop, VPN Accelerator

🇺🇸 United States - Washington, Seattle (27) 🔄🤡🗡️ • ProtonVPN
    └─ P2P support, Free tier, NetShield Level 1

🇸🇪 Sweden - Alberta, Stockholm (31) 🔄🧅🗡️ • ProtonVPN
    └─ P2P support, Tor routing, NetShield Level 1
```

**Note**: Feature detection optimized for ProtonVPN configs. Support for other providers may be added in future updates.

**Secure Core**: Entry countries are always privacy-friendly jurisdictions (Switzerland 🇨🇭, Iceland 🇮🇸, or Sweden 🇸🇪) that route to your chosen exit country.

---

## Usage & Menu Structure

**Open Menu**: `SUPER+L`
**Navigate**: Arrow keys and Enter. Esc to go back or exit.
**In fzf pickers**: `Ctrl+A` to select/deselect all when adding or removing servers. Type to filter.

### Main Menu

#### When Disconnected:
- **🔌 Connect** → Connection submenu
- **🛡️ Killswitch** → Killswitch configuration
- **⚙️ Autostart** → Autostart configuration
- **🧪 Tests** → Testing submenu
- **⚙️ Options** → Server management and settings

#### When Connected:
- **🟢 Status Bar**: Shows connected server and public IP
- **🔌 Disconnect** → Disconnect from VPN
- **🔄 Switch Server** → Connection submenu
- **🛡️ Killswitch** → Killswitch configuration
- **⚙️ Autostart** → Autostart configuration
- **🧪 Tests** → Testing submenu
- **⚙️ Options** → Server management and settings

### Connection Submenu
- **⚡ Lowest Latency** → Test all servers, connect to fastest
- **🎲 Random Server** → Connect to random server
- **🌍 Choose Server** → `fzf` picker with filtering and preview
- **🔄 Last Used Server** → Reconnect to most recently used

### Killswitch Submenu
Shows state: `🟢 ENABLED` or `🔴 DISABLED`
- **Toggle Killswitch** → Enable/disable
- **📶 Local Network Access** → Toggle LAN access when killswitch active
  - Status: `🟢 Allowed` or `🔴 Blocked`
- **⚙️ Disconnect Behavior** → Configure disconnect behavior
  - `🟢 AUTO` - Automatically disable killswitch
  - `🟡 PROMPT` - Ask whether to disable
  - `🔴 NEVER` - Keep active (internet blocked until reconnect)

### Autostart Submenu
Shows state: `🟢 ENABLED` or `🔴 DISABLED`
- **Toggle Autostart** → Enable/disable autoconnect on boot
- **Autoconnect Mode** → Choose server selection method
  - `⚡ Lowest Latency` - Test all, connect to fastest
  - `🔄 Last Used` - Connect to most recent
  - `🎲 Random` - Connect to random server
  - `🎯 Specific Server` - Connect to chosen server (opens picker)

### Tests Submenu

**When Disconnected**:
- **⏱️ Latency Test (All Servers)** → Parallel ping test with optional non-VPN comparison
- **📈 Performance History** → View historical test results

**When Connected**:
- **⏱️ Latency Test** → Test current server
- **⏱️ Latency Test (All Servers)** → Parallel test with optional non-VPN comparison
- **💨 Speed Test** → Download speed test on current server
- **💨 Speed Test (All Servers)** → Sequential test of all servers with optional non-VPN comparison
- **🧪 DNS Leak Test** → Verify DNS routes through VPN
- **📈 Performance History** → View historical test results

### Options Submenu
- **➕ Add New Server** → Import `.conf` files from `~/Downloads`
- **➖ Remove Server** → Remove servers with cleanup
- **🔁 Auto-Recover** → Toggle auto-reconnect daemon
  - Status: `🟢 Active` or `🔴 Inactive`
- **🔀 Auto-Failover** → Toggle automatic failover to fastest server after 3 failed reconnect attempts
  - Status: `🟢 Enabled` or `🔴 Disabled` (default: disabled)
- **🔒 IPv6 Protection** → Toggle IPv6 leak protection
  - Status: `🟢 Enabled` or `🔴 Disabled`
- **✏️ Rename Interface** → Change network interface name
  - Shows current name, e.g., `(wg0)`
- **🗑️ Uninstall LazyVPN** → Complete uninstallation

### Performance History
- **Summary view**: All servers with average speeds, latencies, test counts
- **Detailed view**: Last 20 test results with timestamps for specific server
- **Non-VPN data**: Direct connection tests appear as `🌐 Direct (Non-VPN)`

---

## Technical Details

**Network Stack**: Uses `systemd-networkd` for WireGuard interface management (not `wg-quick`)
**Firewall**: Custom iptables chains (`LAZYVPN_OUT` for IPv4, `LAZYVPN_OUT6` for IPv6)
**DNS**: Integrates with `systemd-resolved` for DNS privacy
**Privilege Model**: Minimal sudo scope via `/etc/sudoers.d/lazyvpn` - only specific VPN-related commands

**Security Architecture**:
- Input validation (path traversal, symlink attacks, injection prevention)
- Atomic file operations (prevents corruption from concurrent access)
- Secure file helper (privileged operations isolated in validated wrapper)
- 3-pass shred for sensitive data deletion

**Performance**:
- Parallel latency testing across all servers
- WireGuard kernel module auto-loaded on-demand
- Atomic server switching (firewall updates before connecting - no traffic leaks)

**Configuration Files**:
- Server configs: `~/.config/lazyvpn/wireguard/*.conf`
- Settings: `~/.config/lazyvpn/config`
- Performance history: `~/.config/lazyvpn/performance/`
- Auto-recover log: `~/.config/lazyvpn/auto-recover.log`
- Server list cache: `~/.config/lazyvpn/.server-list-cache`

---

## Uninstallation

**Access**:
-   Run `lazyvpn-uninstall` from terminal
-   Or: Menu → `⚙️ Options` → `🗑️ Uninstall LazyVPN`

**Features**:
-   Auto-disconnects if connected (no need to leave the screen)
-   Automatic cleanup on installation failures

**Secure Deletion** (with confirmation prompts):
-   **Always deleted** (shredded with 3-pass overwrite):
    -   Performance history logs (usage metadata)
    -   LazyVPN config files (settings)
    -   systemd-networkd files (private keys)
    -   Shell history (VPN commands removed from bash/zsh/fish)
-   **User choice**:
    -   Server configs (private keys)
    -   System journal logs (surgical removal - only files containing VPN logs)

**Removed**:
-   All LazyVPN scripts from `~/.local/share/lazyvpn/bin/`
-   Firewall killswitch rules
-   Sudoers configuration (`/etc/sudoers.d/lazyvpn`)
-   Desktop integrations (menu entries, autostart files, keybindings)
-   Omarchy menu modifications

**Privacy Result**: Choosing "yes" to all prompts leaves zero recoverable traces of VPN usage.

---

## Troubleshooting

**Killswitch blocks all traffic**
- Check killswitch configuration in menu
- **Disable temporarily**: `lazyvpn-disable-killswitch` from terminal
- Verify disconnect behavior setting isn't set to NEVER

**Can't access local network (printer, NAS) while connected**
- **Enable**: Menu → `🛡️ Killswitch` → `📶 Local Network Access` → `🟢 Allowed`

**Speed test fails or returns zero**
- Check internet connectivity
- Verify VPN connection is active
- Some servers may have restrictive firewall rules

**Auto-recover daemon not working**
- Check status: Menu → `⚙️ Options` → `🔁 Auto-Recover`
- View logs: `cat ~/.config/lazyvpn/auto-recover.log`
- Verify daemon running: `pgrep -f lazyvpn-auto-recover-daemon`

---

## Roadmap

### 🔐 Encrypted Configuration Storage (Planned)
-   Optional toggle-able encryption for stored `.conf` files
-   Automatic encryption when storing in `~/.config/lazyvpn/wireguard/`
-   Transparent decryption when connecting
-   Password/passphrase protection

### Other Considerations
-   Support for additional VPN providers' feature detection

**Suggestions welcome!** Open an issue on GitHub.

---

## License

MIT License - Copyright (c) 2025 blank-query

---

*WireGuard is a registered trademark of Jason A. Donenfeld.*

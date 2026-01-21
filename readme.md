# LazyVPN

**LazyVPN** is a powerful, script-based utility for managing WireGuard VPN connections, built for Omarchy Linux. It replaces manual `systemd-networkd` configuration with a fast, keyboard-driven TUI.

## Table of Contents

- [Quick Start](#quick-start)
- [Screenshots](#screenshots)
- [Requirements](#requirements)
- [Installation](#installation)
- [Features](#features)
  - [Dynamic Server Browser](#-dynamic-server-browser)
  - [My Servers](#-my-servers)
  - [Connection Management](#-connection-management)
  - [Security & Privacy](#-security--privacy)
  - [Automation](#-automation)
  - [Testing](#-testing)
  - [System Integration](#-system-integration)
- [Usage & Menu Structure](#usage--menu-structure)
- [Server Naming & Features](#server-naming--features)
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
2. Select `Dynamic Server List` - you'll be prompted to set up a provider
3. Load a WireGuard config file from your provider (credentials are extracted automatically)
4. Browse thousands of servers, filter by features, and connect
5. Your connection is verified with IP checks and DNS leak protection

---

## Screenshots

### Main Menu
![Main Menu - Disconnected](images/01-main-menu-disconnected.png)
![Main Menu - Connected](images/04-main-menu-connected.png)

### Dynamic Server Browser
![Dynamic Server Browser](images/02-dynamic-server-browser.png)

### My Servers
![My Servers](images/05-my-servers.png)

### Connection Flow
![Connecting](images/03-connecting.png)
![Disconnecting](images/07-disconnecting.png)

### Settings
![Settings Menu](images/06-settings.png)

---

## Requirements

- **Omarchy Linux** (this tool is built specifically for Omarchy and will not work on other distributions)
- VPN provider that supports WireGuard connections

**Supported Providers**:
- ProtonVPN (tested)
- Mullvad
- IVPN
- PIA (Private Internet Access)
- NordVPN
- Surfshark
- Windscribe

*Note: Only ProtonVPN has been thoroughly tested. Other providers should work but are untested. We'd love help testing - please [open an issue](https://github.com/blank-query/lazyVPN-for-Omarchy/issues) if you encounter problems with your provider.*

**Dependencies** (auto-installed by installer):
- `curl` - Speed tests and public IP detection
- `bc` - Speed calculations
- `iptables` - Killswitch functionality
- `jaq` - Fast JSON processing for dynamic server browser
- `fzf` - Interactive menus and server selection

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

---

## Features

### 🌐 Dynamic Server Browser

- **Provider Integration**: Configure your VPN provider once, browse thousands of servers instantly
  - Server data sourced from [gluetun](https://github.com/qdm12/gluetun) (MIT License)
  - 24-hour cache with on-demand refresh

- **Feature Filtering**:
  - Filter by: P2P, Tor, Secure Core, Streaming, Free
  - Multi-select uses AND logic (P2P + Streaming = servers with both)
  - Switch providers without leaving the browser

- **Hotkeys in Browser**:
  - `Enter` - Connect to selected server
  - `1-5` - Toggle feature filters (P2P, Tor, Secure Core, Streaming, Free)
  - `6` - Connect to random server (from current filter)
  - `7` - Connect to quickest server (latency test all filtered servers)
  - `8` - Latency test all filtered servers (without connecting)
  - `9` - Toggle favorite (adds to My Servers)
  - `0` - Switch provider (if multiple configured)

- **Secure Core Display**: Shows both entry and exit countries
  - `🇨🇭 Switzerland → 🇦🇷 Argentina (CH-AR#2) 🔒`

### 📁 My Servers

Combines your **favorite dynamic servers** and **manually imported configs** in one place:

- **Favorites**: Star servers from the Dynamic Server Browser with `9` hotkey
- **Manual Configs**: Import WireGuard `.conf` files via Settings → Import WireGuard Config
- Quick access from main menu

### 🔄 Connection Management

- **Connection Verification**:
  - IP verification before and after connection
  - Automatic failure detection if traffic not routing through VPN
  - Intelligent retry logic with prompts
  - Automatic cleanup of failed connections

- **Post-Connection Options**: After connecting, hotkeys for quick actions:
  - `d` - DNS Leak Test (opens ipleak.net)
  - `s` - Speedtest (10MB download test)
  - `l` - Latency test (ping to server)
  - `Enter` - Done

- **Seamless Server Switching**: Change servers without disconnecting - firewall rules update automatically before connecting to new server

### 🛡️ Security & Privacy

- **Firewall Killswitch**:
  - iptables-based killswitch blocks all traffic if VPN disconnects
  - **Dynamic updates**: Automatically allows traffic to new VPN endpoint *before* connecting
  - **Configurable local network access**: Toggle LAN device access (printers, NAS)
  - **Disconnect behavior**: Three modes:
    - `Auto`: Automatically disable killswitch on disconnect
    - `Prompt`: Ask whether to disable
    - `Never`: Keep killswitch active (internet blocked until reconnect)
  - **Boot persistence**: Killswitch activates before network stack on reboot (zero leaks)

- **🔁 Auto-Recover Daemon**:
  - Background daemon monitors VPN connection health (10-second interval)
  - 3-strike failure threshold before triggering reconnection
  - **Auto-failover** (optional): After failed reconnects, switches to alternate server
    - If killswitch active: picks random server (instant)
    - If killswitch inactive: picks lowest latency server (tests all servers)

- **🔒 IPv6 Leak Protection**: Blocks IPv6 traffic to prevent leaks (enabled by default)

- **🗑️ Secure Deletion**:
  - Provider setup offers to shred source config after extracting credentials
  - Server configs shredded (3-pass overwrite) when removed
  - Uninstaller offers secure deletion of all sensitive data
  - Optional surgical removal of VPN-related system journal logs

- **🔐 Security Architecture**:
  - Input validation (path traversal, symlink attacks, injection prevention)
  - Atomic file operations (prevents corruption from concurrent access)
  - Secure file helper (privileged operations isolated in validated wrapper)

### ⚙️ Automation

- **🔌 Autoconnect on Boot**:
  - Four modes: `Last Used`, `Fastest`, `Random`, or `Specific Server`
  - `Fastest` tests latency to all servers (may take 30-60s with large server lists)
  - Waits for network connectivity before connecting
  - Fallback to random if killswitch blocks latency testing

- **Provider Credentials**: Set up once, stored securely in `~/.config/lazyvpn/providers/`

### 🧪 Testing

Available from Settings menu when connected:

- **Latency Test**: Ping test to current server endpoint
- **Speedtest**: 10MB file download with real progress bar
- **IP & DNS Leak Test**: Opens ipleak.net in browser for comprehensive external validation

### ✨ System Integration

- **Omarchy Menu**: Adds LazyVPN entry to main Omarchy menu (`SUPER+ALT+SPACE`)
- **Dedicated Keybinding**: `SUPER+L` (registered in Omarchy keybind help at `SUPER+K`)
- **Desktop Notifications**: Clear notifications for connection events
- **Passwordless Operation (Optional)**: Specific VPN commands only (not blanket sudo access)

---

## Usage & Menu Structure

**Open Menu**: `SUPER+L`
**Navigate**: Arrow keys and Enter. Esc to go back or exit.

### Main Menu

#### When Disconnected:
- **🌐 Dynamic Server List** → Browse and connect to provider servers
- **📁 My Servers** → Your favorites and manual configs
- **🔄 Reconnect** → Reconnect to last used server (if available)
- **⚙️ Settings** → All configuration options

#### When Connected:
- **🔌 Disconnect** → Disconnect from VPN
- **🌐 Dynamic Server List** → Switch to different server
- **📁 My Servers** → Switch to favorite/manual server
- **⚙️ Settings** → All configuration options

### Settings Menu

Unified fzf-based settings interface with all options:

**Dynamic Server Providers**
- Set Up Provider → Load a config file once to extract credentials
- Refresh Server List → Re-download server data from providers

**Protection**
- Killswitch → Block all traffic if VPN disconnects
- KS Local Network → Allow LAN when killswitch active
- KS on Disconnect → Behavior when you manually disconnect
- IPv6 Leak Protection → Disable IPv6 to prevent leaks

**Automation**
- Autoconnect on Startup → Connect to VPN when system boots
- AC Startup Server → Which server to use (Last Used/Fastest/Random/Specific)
- Auto-Recover Connection → Reconnect if connection drops
- Auto-Failover → Try new server if current one fails

**Manual Servers**
- Import WireGuard Config → Add manual .conf files
- Remove Server → Delete a manual server config

**Testing** (only shown when connected)
- Latency Test → Ping test to current server
- Speedtest → Download speed test (10MB file)
- IP & DNS Leak Test → Open ipleak.net in browser

**Advanced**
- WireGuard Interface → Change the network interface name
- Uninstall LazyVPN → Remove LazyVPN and all settings
- Show Tutorial → Learn how to use LazyVPN
- Show Github → Open project page for help or issues

---

## Server Naming & Features

### Feature Emojis

LazyVPN displays server features with emoji indicators:

| Emoji | Feature |
|-------|---------|
| 🔄 | **P2P / Port Forward** |
| 🔒 | **Secure Core** (multi-hop) |
| 🧅 | **Tor Routing** |
| 📺 | **Streaming Optimized** |
| 🤡 | **Free Tier** |
| ⭐ | **Favorite** (in My Servers) |

### Secure Core Servers

Entry countries are always privacy-friendly jurisdictions (Switzerland 🇨🇭, Iceland 🇮🇸, or Sweden 🇸🇪) that route to your chosen exit country.

Display format: `🇨🇭 Switzerland → 🇺🇸 United States (CH-US#5) 🔒`

---

## Technical Details

**Network Stack**: Uses `systemd-networkd` for WireGuard interface management (not `wg-quick`)
**Firewall**: Custom iptables chains (`LAZYVPN_OUT` for IPv4/IPv6)
**DNS**: Integrates with `systemd-resolved` for DNS privacy
**Privilege Model**: Minimal sudo scope via `/etc/sudoers.d/lazyvpn`
**Provider Detection**: Auto-detected from config file by DNS server IP (e.g., 10.2.0.1 = ProtonVPN), with fallback to endpoint domain

**Configuration Files**:
- Settings: `~/.config/lazyvpn/config`
- Manual server configs: `~/.config/lazyvpn/wireguard/*.conf`
- Provider credentials: `~/.config/lazyvpn/providers/*.conf`
- Dynamic server cache: `~/.config/lazyvpn/cache/*_servers.json`
- Favorites: `~/.config/lazyvpn/favorites`
- Auto-recover log: `~/.config/lazyvpn/auto-recover.log`

---

## Uninstallation

**Access**:
- Run `lazyvpn-uninstall` from terminal
- Or: Settings → Uninstall LazyVPN

**Features**:
- Auto-disconnects if connected
- Stops auto-recover daemon

**Secure Deletion** (with confirmation prompts):
- **Always deleted** (shredded with 3-pass overwrite):
  - Provider credentials (private keys)
  - LazyVPN config files
  - systemd-networkd files
  - Shell history (VPN commands removed)
- **User choice**:
  - Manual server configs (private keys)
  - System journal logs (surgical removal)

**Removed**:
- All LazyVPN scripts
- Firewall killswitch rules
- Sudoers configuration
- Desktop integrations (menu entries, autostart, keybindings)

---

## Troubleshooting

**Killswitch blocks all traffic**
- Check killswitch configuration in Settings
- **Disable temporarily**: `lazyvpn-disable-killswitch` from terminal
- Verify disconnect behavior setting isn't set to "Never"

**Can't access local network (printer, NAS) while connected**
- Settings → KS Local Network → Enable

**Auto-recover daemon not working**
- Check status in Settings → Auto-Recover Connection
- View logs: `cat ~/.config/lazyvpn/auto-recover.log`
- Verify daemon running: `pgrep -f lazyvpn-auto-recover-daemon`

**Provider setup shows "Invalid or sanitized private key"**
- ProtonVPN: Re-downloading an existing config gives a sanitized key - you must generate a new config
- Other providers may have similar behavior

**Provider setup not working**
- Ensure you have a WireGuard config file from your VPN provider
- Check provider credentials in `~/.config/lazyvpn/providers/`

---

## Roadmap

### Planned Features
- Encrypted configuration storage for `.conf` files
- Support for additional VPN providers

**Suggestions welcome!** Open an issue on GitHub.

---

## License

MIT License - Copyright (c) 2025 blank-query

---

*WireGuard is a registered trademark of Jason A. Donenfeld.*

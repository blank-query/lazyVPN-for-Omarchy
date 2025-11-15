# LazyVPN

**LazyVPN** is a powerful, script-based utility for managing WireGuard® VPN connections, meticulously crafted for the Omarchy Linux environment. It replaces manual `wg-quick` and `systemd-networkd` configuration with a fast, keyboard-driven TUI, providing a comprehensive suite of tools for power users.

## Table of Contents

- [Core Philosophy](#core-philosophy)
- [Feature Matrix](#feature-matrix)
  - [Connection Management](#-connection-management)
  - [Security & Privacy](#-security--privacy)
  - [Automation & Configuration](#-automation--configuration)
  - [Performance & Testing](#-performance--testing)
  - [System Integration](#-system-integration)
- [Requirements](#requirements)
- [Installation](#installation)
- [First-Time Setup](#first-time-setup)
- [Usage](#usage)
- [Menu Structure](#menu-structure)
- [Uninstallation](#uninstallation)
- [Roadmap](#roadmap)
- [License](#license)

---

## Core Philosophy

-   **Speed & Efficiency**: Every action is a few keystrokes away. No mouse required.
-   **Control**: Granular control over your connection, security, and automation.
-   **Intelligence**: The system is smart. It detects providers, parses server names, and automatically handles complex tasks.
-   **Resilience**: With features like the auto-recover daemon and atomic configuration saves, LazyVPN is built to be reliable.
-   **Transparency**: Understand your connection with detailed status info, performance tests, and leak protection.

---

## Feature Matrix

### 🔄 Connection Management

-   **Multiple Connection Modes**:
    -   **⚡ Lowest Latency**: Automatically performs parallel latency tests against all servers and connects to the one with the lowest ping.
    -   **🎲 Random Server**: Connect to a randomly selected server for effortless privacy.
    -   **🌍 Choose Server**: Select a server from a filterable, `fzf`-powered list with a detailed preview panel.
    -   **🔄 Last Used Server**: Instantly reconnect to your most recent server.
-   **Smart Server Display**:
    -   **Pretty Names**: Automatically parses filenames (e.g., `Proton-US-NY#123.conf`) into beautifully formatted names with country flags (e.g., `🇺🇸 US-NY #123 - ProtonVPN`).
    -   **Provider Detection**: Intelligently detects the VPN provider (ProtonVPN, Mullvad, IVPN, etc.) from the filename, endpoint, DNS, or even comments within the `.conf` file.
-   **Connection Status**: The menu bar always shows your real-time status (`🟢 CONNECTED` or `🔴 DISCONNECTED`) and the currently connected server.
-   **Seamless Server Switching**: Switches between servers gracefully, automatically updating firewall rules and routes.

### 🛡️ Security & Privacy

-   **Advanced Firewall Killswitch**:
    -   An `iptables`-based killswitch that blocks all internet traffic if the VPN disconnects, preventing any data leaks.
    -   **Dynamic Updates**: The killswitch is smart. It automatically allows traffic to the new VPN endpoint *before* connecting, ensuring seamless server switching without ever disabling the killswitch.
    -   **Configurable Local Network Access**: Toggle whether to allow access to local network devices (printers, NAS, etc.) while the killswitch is active.
    -   **Configurable Disconnect Behavior**: Choose what happens when you manually disconnect:
        -   `🟢 AUTO`: Automatically disable the killswitch.
        -   `🟡 PROMPT`: Ask whether to disable the killswitch.
        -   `🔴 NEVER`: Keep the killswitch active, ensuring the internet remains blocked until you reconnect.
-   **🔁 Auto-Recover Daemon**:
    -   A background daemon constantly monitors the health of your VPN connection.
    -   If it detects a drop or stall, it will automatically attempt to reconnect to the same server.
    -   Toggle from `⚙️ Options` → `🔁 Auto-Recover`.
-   **🔒 IPv6 Leak Protection**:
    -   Actively checks for and prevents IPv6 leaks by default.
    -   Can be toggled from the menu if you need to use IPv6.
-   **🧪 DNS Leak Test**:
    -   A built-in test to verify that your DNS queries are being correctly routed through the VPN's DNS servers, not your ISP's.
-   **📁 Configuration Storage**:
    -   Server configurations are currently stored in plaintext in `~/.config/lazyvpn/wireguard/`
    -   **Note**: Encrypted storage is a planned optional feature (see [Roadmap](#roadmap))

### ⚙️ Automation & Configuration

-   **🔌 Autoconnect on Boot**:
    -   Set LazyVPN to automatically connect when you log in.
    -   **Multiple Autoconnect Modes**:
        -   Connect to the `last used` server.
        -   Connect to the `lowest latency` server.
        -   Connect to a `random` server.
        -   Connect to a `specific` server of your choice.
-   **➕ Easy Server Management**:
    -   **Add Servers**: A guided `fzf` interface to import `.conf` files from `~/Downloads` with automatic validation and duplicate detection.
    -   **Remove Servers**: Safely remove servers with automatic cleanup of performance history and configuration references.
    -   Both accessible from `⚙️ Options` submenu.
-   **✏️ Interface Renaming**: Easily rename the network interface (e.g., from `wg0` to `lazyvpn`) directly from the menu.
-   **Robust Configuration**:
    -   Uses atomic file writes to prevent configuration corruption.
    -   **Interactive Recovery**: If the config file is ever deleted or corrupted, LazyVPN will guide you through an interactive prompt to recreate it.
    -   **Automatic Migration**: Handles upgrades and configuration changes from older versions seamlessly.

### 📊 Performance & Testing

-   **⏱️ Latency Testing**:
    -   Test the latency of the currently connected server.
    -   **Test All Servers**: Run parallel latency tests on all servers to find the quickest.
-   **💨 Speed Testing**:
    -   Run a download speed test on the currently connected server.
    -   **Test All Servers**: A comprehensive test that connects to *each server one-by-one*, runs a speed test, and presents a sorted list of the fastest servers.
    -   Both "Test All" features include an option to test your direct, non-VPN connection for comparison.
    -   Non-VPN results are recorded in performance history as `🌐 Direct (Non-VPN)`.
-   **📈 Performance History**:
    -   Automatically records the results of every latency and speed test.
    -   View a summary of average speeds and latencies for all servers.
    -   View a detailed log of the last 20 tests for any specific server.

### ✨ System Integration

-   **Omarchy Menu**: Adds a "LazyVPN" entry to the main Omarchy menu (`SUPER+ALT+SPACE`).
-   **Dedicated Keybinding**: Launch the menu instantly with `SUPER+L` (automatically registered in the Omarchy keybind help menu at `SUPER+K`).
-   **Passwordless Operation**: A secure `sudoers` configuration covers all VPN operations (connections, disconnections, killswitch updates). Password only required during installation and uninstallation.
-   **Desktop Notifications**: Provides clear notifications for connects, disconnects, and other key events.
-   **Smart Change Detection**: Automatically detects when you add or remove `.conf` files and notifies you.

---

## Requirements

-   **Omarchy Linux** (Arch-based distribution)
-   **systemd-networkd** (enabled and running)
-   **systemd-resolved** (enabled and running)
-   **wireguard-tools** or WireGuard kernel module
-   **curl** (for speed tests and public IP detection)
-   **bc** (for latency/speed calculations)
-   **iptables** (for killswitch functionality)
-   **bind-tools** (provides `dig` for DNS leak testing)
-   **fzf** (provided by Omarchy)
-   **omarchy-launch-walker** (Omarchy menu system)
-   **omarchy-launch-floating-terminal-with-presentation** (Omarchy terminal launcher)
-   **omarchy-notification-dismiss** (Omarchy notification system)

**Note**: The installer automatically installs missing dependencies (except Omarchy itself).

---

## Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/blank-query/lazyVPN-for-Omarchy.git
    cd lazyVPN-for-Omarchy
    ```

2.  **Run the Installer**:
    ```bash
    ./install_lazyVPN.sh
    ```
    The installer handles everything: dependencies, script installation, `sudo` rights, and desktop integration.

## First-Time Setup

1.  **Get WireGuard Files**: Download `.conf` files from your VPN provider.
2.  **Add Servers**:
    -   Place the `.conf` files in `~/.config/lazyvpn/wireguard/`.
    -   **OR**, run LazyVPN (`SUPER+L`) and choose `➕ Add New Server` to import them from your `~/Downloads` folder.
3.  **Rename Files (Recommended)**: For the best experience, rename your files for the smart parser.
    -   **Format**: `[Provider-]CountryCode-City#Number.conf`
    -   **Examples**: `Proton-US-NY#123.conf`, `Mullvad-SE-Stockholm#5.conf`

## Usage

-   **Open the Menu**: Press `SUPER+L`.
-   **Navigate**: Use arrow keys and `Enter`. `Esc` to go back or exit.
-   **In fzf pickers**: Use `Ctrl+A` to select/deselect all when adding or removing servers.
-   **Server filtering**: In the "Choose Server" picker, type to filter by country, city, or provider.
-   All features are accessible through the menu.

## Menu Structure

LazyVPN's menu is organized hierarchically with dynamic options that change based on your connection state.

### Main Menu

#### When Disconnected:
- **🔌 Connect** → Connection submenu (choose how to connect)
- **🛡️ Killswitch** → Killswitch configuration submenu
- **⚙️ Autostart** → Autostart configuration submenu
- **🧪 Tests** → Testing submenu
- **⚙️ Options** → Options submenu (server management, advanced settings)

#### When Connected:
- **🟢 Status Bar**: Shows connected server and public IP
- **🔌 Disconnect** → Disconnects from current VPN
- **🔄 Switch Server** → Connection submenu (switch to different server)
- **🛡️ Killswitch** → Killswitch configuration submenu
- **⚙️ Autostart** → Autostart configuration submenu
- **🧪 Tests** → Testing submenu
- **⚙️ Options** → Options submenu

### Connection Submenu (🔌 Connect / 🔄 Switch Server)
- **⚡ Lowest Latency** → Automatically tests all servers and connects to fastest
- **🎲 Random Server** → Connects to random server
- **🌍 Choose Server** → `fzf` picker with server preview and filtering
- **🔄 Last Used Server** → Reconnects to most recently used server

### Killswitch Submenu (🛡️)
Shows current killswitch state (`🟢 ENABLED` or `🔴 DISABLED`)
- **Toggle Killswitch** → Enable/disable killswitch
- **📶 Local Network Access** → Toggle LAN device access when killswitch active
  - Status indicator: `🟢 Allowed` or `🔴 Blocked`
- **⚙️ Disconnect Behavior** → Configure what happens when manually disconnecting
  - `🟢 AUTO` - Automatically disable killswitch
  - `🟡 PROMPT` - Ask whether to disable
  - `🔴 NEVER` - Keep killswitch active (internet blocked until reconnect)

### Autostart Submenu (⚙️)
Shows current autostart state (`🟢 ENABLED` or `🔴 DISABLED`)
- **Toggle Autostart** → Enable/disable autoconnect on boot
- **Autoconnect Mode** → Choose which server to connect to at boot
  - `⚡ Lowest Latency` - Test all servers and connect to fastest
  - `🔄 Last Used` - Connect to most recently used server
  - `🎲 Random` - Connect to random server
  - `🎯 Specific Server` - Connect to a specific chosen server (opens `fzf` picker)

### Tests Submenu (🧪)

#### When Disconnected:
- **⏱️ Latency Test (All Servers)** → Parallel ping test of all servers with optional non-VPN comparison
- **📈 Performance History** → View historical test results and averages

#### When Connected:
- **⏱️ Latency Test** → Test ping to current server
- **⏱️ Latency Test (All Servers)** → Parallel ping test of all servers with optional non-VPN comparison
- **💨 Speed Test** → Download speed test on current server
- **💨 Speed Test (All Servers)** → Sequential speed test of all servers with optional non-VPN comparison
- **🧪 DNS Leak Test** → Verify DNS queries route through VPN, not ISP
- **📈 Performance History** → View historical test results and averages

### Options Submenu (⚙️)
- **➕ Add New Server** → Import `.conf` files from `~/Downloads` with validation and duplicate detection
- **➖ Remove Server** → Remove installed servers (with safety checks and cleanup)
- **🔁 Auto-Recover** → Toggle auto-reconnect daemon
  - Status indicator: `🟢 Active` or `🔴 Inactive`
- **🔒 IPv6 Protection** → Toggle IPv6 leak protection
  - Status indicator: `🟢 Enabled` or `🔴 Disabled`
- **✏️ Rename Interface** → Change network interface name (default: `wg0`)
  - Shows current name: e.g., `(wg0)`
- **🗑️ Uninstall LazyVPN** → Complete uninstallation with confirmation

### Performance History Details
When viewing performance history:
- **Summary View** (no arguments): Shows all servers with average speeds, latencies, and test counts
- **Detailed View** (with server name): Shows last 20 test results with timestamps
- **Non-VPN Data**: Direct connection tests appear as `🌐 Direct (Non-VPN)`

## Uninstallation

LazyVPN includes a comprehensive uninstaller that ensures clean removal:

-   **Access Methods**:
    -   Run `lazyvpn-uninstall` from a terminal
    -   Select `⚙️ Options` → `🗑️ Uninstall LazyVPN` from the menu
-   **Automatic Cleanup**: The installer detects installation failures and automatically runs the uninstaller to clean up partial installations.
-   **Config Preservation**: During uninstallation, you'll be asked whether to keep your configuration files (VPN configs and performance history) or remove everything.
-   **What Gets Removed**:
    -   All LazyVPN scripts from `~/.local/share/omarchy/bin/`
    -   Firewall killswitch rules
    -   Sudoers configuration
    -   Desktop integrations (menu entries, autostart files, keybindings)
    -   Omarchy menu modifications
-   **Safe Uninstall**: If connected to a VPN, the uninstaller offers to disconnect for you - no need to leave the screen.

**Note**: The uninstaller is installed first during installation to ensure cleanup capability even if installation fails.

---

## Roadmap

Future features and enhancements under consideration:

### 🔐 Encrypted Configuration Storage (Optional Feature)
-   **Toggle-able Security**: Optional encryption for stored `.conf` files (disabled by default)
-   **Automatic Encryption**: When enabled, encrypt `.conf` files before storing them in `~/.config/lazyvpn/wireguard/`
-   **Secure Cleanup**: Offer to securely delete plaintext `.conf` files from `~/Downloads` after import
-   **Transparent Decryption**: Decrypt configs on-the-fly when connecting, completely transparent to the user
-   **Password Protection**: Password/passphrase protection for the encrypted config vault

### 🔄 Auto-Failover (Partially Implemented)
-   Currently, the auto-recover daemon reconnects to the same server if a connection drops
-   **Planned**: If reconnection fails repeatedly, automatically failover to the next-quickest server to minimize downtime

### Suggestions Welcome!
Have ideas for LazyVPN? Open an issue on the GitHub repository with your feature requests.

---

## License

LazyVPN is released under the [MIT License](LICENSE).

Copyright (c) 2025 blank-query

---
*WireGuard is a registered trademark of Jason A. Donenfeld.*

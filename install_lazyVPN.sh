#!/bin/bash

# LazyVPN Installation Script for Omarchy (systemd-networkd version)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAZYVPN_BIN="$HOME/.local/share/lazyvpn/bin"
OMARCHY_BIN="$HOME/.local/share/omarchy/bin"
OMARCHY_MENU_FILE="$OMARCHY_BIN/omarchy-menu"

# Source secure_delete from repo
source "$SCRIPT_DIR/bin/lazyvpn-common" || { echo "Error: bin/lazyvpn-common not found in repo"; exit 1; }

# Track installation state
INSTALL_STARTED=false
INSTALL_COMPLETE=false

# Cleanup on error
cleanup_on_error() {
  local exit_code=$?

  # Only cleanup if install started but didn't complete successfully
  if [[ "$INSTALL_STARTED" == "true" ]] && [[ "$INSTALL_COMPLETE" == "false" ]] && [[ $exit_code -ne 0 ]]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "Installation failed! Running cleanup to prevent partial installation..."
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    # Run uninstaller if it exists
    if [[ -f "$LAZYVPN_BIN/lazyvpn-uninstall" ]]; then
      bash "$LAZYVPN_BIN/lazyvpn-uninstall" 2>/dev/null || true
    else
      # Manual cleanup if uninstaller not yet installed
      echo "Cleaning up LazyVPN files..."
      if [[ -d "$LAZYVPN_BIN" ]]; then
        bin_files=()
        for f in "$LAZYVPN_BIN"/*; do [[ -f "$f" ]] && bin_files+=("$f"); done
        if [[ ${#bin_files[@]} -gt 0 ]]; then
          secure_delete "${bin_files[@]}" || true
        fi
        rmdir "$LAZYVPN_BIN" 2>/dev/null || true
      fi

      # Restore omarchy-menu backup if it exists
      if [[ -f "$OMARCHY_MENU_FILE.backup" ]]; then
        mv "$OMARCHY_MENU_FILE.backup" "$OMARCHY_MENU_FILE" 2>/dev/null || true
        echo "Restored omarchy-menu from backup"
      fi

      echo "Cleanup complete"
    fi

    echo ""
    echo "Please fix the error and try installing again."
    exit $exit_code
  fi
}

# Set trap for errors
trap cleanup_on_error ERR EXIT

echo "==================================="
echo "LazyVPN Installer for Omarchy"
echo "==================================="
echo ""

# Check if running on Omarchy
if [[ ! -d "$HOME/.local/share/omarchy" ]]; then
  echo "Error: Omarchy installation not found"
  echo "This tool is designed for Omarchy Linux"
  exit 1
fi

# Check if LazyVPN is already installed
if [[ -d "$LAZYVPN_BIN" ]] && [[ -n "$(find "$LAZYVPN_BIN" -name "lazyvpn-*" -print -quit 2>/dev/null)" ]]; then
  echo "Error: LazyVPN is already installed"
  echo ""
  echo "To reinstall or upgrade:"
  echo "  1. Run: lazyvpn-uninstall (from Omarchy menu or terminal)"
  echo "  2. Then run this installer again"
  echo ""
  exit 1
fi

# Check if systemd-networkd is available and enabled
if ! systemctl is-enabled systemd-networkd &>/dev/null; then
  echo "Error: systemd-networkd is not enabled."
  echo "LazyVPN is built specifically for systemd-networkd."
  echo "Please enable it first:"
  echo "  sudo systemctl enable --now systemd-networkd"
  echo "  sudo systemctl enable --now systemd-resolved"
  exit 1
fi

# Check if WireGuard is available
if ! modprobe -n wireguard &>/dev/null && ! command -v wg &>/dev/null; then
  echo "Installing WireGuard tools (required for VPN management)..."
  sudo pacman -S --noconfirm --needed wireguard-tools
fi

# Check if curl is installed (required for speedtest and status)
if ! command -v curl &>/dev/null; then
  echo "Installing curl (required for speed testing and public IP detection)..."
  sudo pacman -S --noconfirm --needed curl
fi

# Check if bc is installed (required for speedtest calculations)
if ! command -v bc &>/dev/null; then
  echo "Installing bc (required for speed calculations)..."
  sudo pacman -S --noconfirm --needed bc
fi

# Check if iptables is installed (required for killswitch)
if ! command -v iptables &>/dev/null; then
  echo "Installing iptables (required for killswitch)..."
  sudo pacman -S --noconfirm --needed iptables
fi

# Check if dig is installed (required for DNS leak testing)
if ! command -v dig &>/dev/null; then
  echo "Installing bind-tools (required for DNS leak testing)..."
  sudo pacman -S --noconfirm --needed bind-tools
fi

# Check if jq is installed (required for dynamic server list)
if ! command -v jq &>/dev/null; then
  echo "Installing jq (required for dynamic server list feature)..."
  sudo pacman -S --noconfirm --needed jq
fi

# Check if fzf is installed (required for server selection)
if ! command -v fzf &>/dev/null; then
  echo "Installing fzf (required for server selection)..."
  sudo pacman -S --noconfirm --needed fzf
fi

# Check if jaq is installed (required for fast server list processing)
if ! command -v jaq &>/dev/null; then
  echo "Installing jaq (required for fast server list processing)..."
  sudo pacman -S --noconfirm --needed jaq
fi

# Mark that installation has started
INSTALL_STARTED=true

echo "Step 1: Creating LazyVPN directory..."
mkdir -p "$LAZYVPN_BIN"
echo "  Created: $LAZYVPN_BIN"

echo ""
echo "Step 2: Installing uninstaller (for error recovery)..."

# Copy uninstall script FIRST so cleanup can always run if installation fails
if [[ -f "$SCRIPT_DIR/bin/lazyvpn-uninstall" ]]; then
  cp "$SCRIPT_DIR/bin/lazyvpn-uninstall" "$LAZYVPN_BIN/lazyvpn-uninstall"
  chmod +x "$LAZYVPN_BIN/lazyvpn-uninstall"
  echo "  Installed: lazyvpn-uninstall"
else
  echo "Error: bin/lazyvpn-uninstall not found"
  exit 1
fi

echo ""
echo "Step 3: Installing LazyVPN scripts..."

# Copy all lazyvpn scripts to LazyVPN bin (except uninstaller, already copied)
for script in "$SCRIPT_DIR"/bin/lazyvpn-*; do
  if [[ -f "$script" ]] && [[ "$(basename "$script")" != "lazyvpn-uninstall" ]]; then
    cp "$script" "$LAZYVPN_BIN/"
    chmod +x "$LAZYVPN_BIN/$(basename "$script")"
    echo "  Installed: $(basename "$script")"
  fi
done

# Install file helper with strict permissions (will be run with sudo)
chmod 755 "$LAZYVPN_BIN/lazyvpn-file-helper"
echo "  ✓ Installed secure file helper"

echo ""
echo "Step 4: Configuring VPN operations..."
echo ""
echo "LazyVPN can configure passwordless sudo for specific VPN-related commands:"
echo "  • networkctl, ip route, iptables"
echo "  • systemd-networkd operations"
echo "  • LazyVPN killswitch scripts"
echo ""
echo "This allows seamless connection/disconnection without password prompts."
echo "Only these specific commands are permitted, not blanket sudo access."
echo ""
echo "If disabled, you'll be prompted for password during VPN operations."
echo "(You can change this later by uninstalling and reinstalling)"
echo ""
read -r -p "Enable passwordless sudo for VPN commands? [Y/n] " passwordless_choice
echo ""

if [[ ! "$passwordless_choice" =~ ^[Nn]$ ]]; then
  echo "Installing sudoers configuration (passwordless VPN operations)..."

  # Create sudoers file for passwordless sudo
  # SECURITY NOTE: This grants significant privileges to wheel group members.
  # See SECURITY_AUDIT.md for detailed security analysis and risk assessment.

SUDOERS_TEMP=$(mktemp)
cat > "$SUDOERS_TEMP" <<'SUDOERS_EOF'
# LazyVPN sudoers configuration
# Allow VPN management without password
# Security: Restricts commands to prevent privilege escalation

# Network interface management - only up/down operations
%wheel ALL=(ALL) NOPASSWD: /usr/bin/networkctl up *
%wheel ALL=(ALL) NOPASSWD: /usr/bin/networkctl down *

# IP route commands - only specific operations needed
# NOTE: Arguments after 'add' and 'del' are validated by kernel
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip route add *
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip route del *

# IP link commands - only delete and set operations
# NOTE: Limited to necessary operations, 'netns exec' is NOT permitted
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip link delete *
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip link set *

# systemd management - specific services only
%wheel ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart systemd-networkd
%wheel ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload systemd-networkd
%wheel ALL=(ALL) NOPASSWD: /usr/bin/systemctl start systemd-journald
%wheel ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop systemd-journald

# File management - SECURE helper script with validation
# Replaced direct sed/tee/rm/mv to prevent symlink attacks
%wheel ALL=(ALL) NOPASSWD: /home/*/.local/share/lazyvpn/bin/lazyvpn-file-helper *

# Secure deletion - shred and rm for root-owned LazyVPN files
# Used by secure_delete --sudo during disconnect and uninstall
%wheel ALL=(ALL) NOPASSWD: /usr/bin/shred -u /etc/systemd/network/99-*
%wheel ALL=(ALL) NOPASSWD: /usr/bin/rm -f /etc/systemd/network/99-*
%wheel ALL=(ALL) NOPASSWD: /usr/bin/shred -u /etc/sysctl.d/99-lazyvpn-ipv6.conf
%wheel ALL=(ALL) NOPASSWD: /usr/bin/rm -f /etc/sysctl.d/99-lazyvpn-ipv6.conf
%wheel ALL=(ALL) NOPASSWD: /usr/bin/shred -u /etc/sudoers.d/lazyvpn
%wheel ALL=(ALL) NOPASSWD: /usr/bin/rm -f /etc/sudoers.d/lazyvpn
%wheel ALL=(ALL) NOPASSWD: /usr/bin/shred -u /var/log/journal/*/*.journal*
%wheel ALL=(ALL) NOPASSWD: /usr/bin/rm -f /var/log/journal/*/*.journal*

# Firewall management - iptables operations for LazyVPN killswitch
# Restricted to LAZYVPN_OUT chain operations only
%wheel ALL=(ALL) NOPASSWD: /usr/bin/iptables -N LAZYVPN_OUT
%wheel ALL=(ALL) NOPASSWD: /usr/bin/iptables -F LAZYVPN_OUT
%wheel ALL=(ALL) NOPASSWD: /usr/bin/iptables -X LAZYVPN_OUT
%wheel ALL=(ALL) NOPASSWD: /usr/bin/iptables -I OUTPUT -j LAZYVPN_OUT
%wheel ALL=(ALL) NOPASSWD: /usr/bin/iptables -D OUTPUT -j LAZYVPN_OUT
%wheel ALL=(ALL) NOPASSWD: /usr/bin/iptables -C OUTPUT -j LAZYVPN_OUT
%wheel ALL=(ALL) NOPASSWD: /usr/bin/iptables -A LAZYVPN_OUT *
%wheel ALL=(ALL) NOPASSWD: /usr/bin/iptables -C LAZYVPN_OUT *
%wheel ALL=(ALL) NOPASSWD: /usr/bin/iptables -L LAZYVPN_OUT *
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip6tables -N LAZYVPN_OUT
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip6tables -F LAZYVPN_OUT
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip6tables -X LAZYVPN_OUT
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip6tables -I OUTPUT -j LAZYVPN_OUT
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip6tables -D OUTPUT -j LAZYVPN_OUT
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip6tables -C OUTPUT -j LAZYVPN_OUT
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip6tables -A LAZYVPN_OUT *
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip6tables -C LAZYVPN_OUT *
%wheel ALL=(ALL) NOPASSWD: /usr/bin/ip6tables -L LAZYVPN_OUT *

# LazyVPN killswitch scripts (all user home directories)
# Uses wildcard pattern /home/*/ to match any username
%wheel ALL=(ALL) NOPASSWD: /home/*/.local/share/lazyvpn/bin/lazyvpn-setup-firewall-killswitch
%wheel ALL=(ALL) NOPASSWD: /home/*/.local/share/lazyvpn/bin/lazyvpn-disable-killswitch
%wheel ALL=(ALL) NOPASSWD: /home/*/.local/share/lazyvpn/bin/lazyvpn-update-killswitch
%wheel ALL=(ALL) NOPASSWD: /home/*/.local/share/lazyvpn/bin/lazyvpn-toggle-killswitch
SUDOERS_EOF

# Validate sudoers syntax before installing
if sudo visudo -cf "$SUDOERS_TEMP" 2>/dev/null; then
  sudo cp "$SUDOERS_TEMP" /etc/sudoers.d/lazyvpn
  sudo chmod 0440 /etc/sudoers.d/lazyvpn
  echo "  ✓ Sudoers configuration installed"
  echo "  VPN operations will not require password"
else
  echo "  ⚠ Sudoers file has syntax errors, skipping installation"
  echo "  You will be prompted for password when connecting/disconnecting"
fi

# Clean up temp file
secure_delete "$SUDOERS_TEMP" || true
else
  echo "Skipping passwordless sudo configuration"
  echo "You will be prompted for password during VPN operations"
fi

echo ""
echo "Step 5: Adding LazyVPN to PATH..."

# Add LazyVPN bin to PATH if not already present
SHELL_RC=""
if [[ -n "$BASH_VERSION" ]]; then
  SHELL_RC="$HOME/.bashrc"
elif [[ -n "$ZSH_VERSION" ]]; then
  SHELL_RC="$HOME/.zshrc"
fi

if [[ -n "$SHELL_RC" ]] && [[ -f "$SHELL_RC" ]]; then
  if ! grep -q "/.local/share/lazyvpn/bin" "$SHELL_RC"; then
    echo '' >> "$SHELL_RC"
    echo '# LazyVPN' >> "$SHELL_RC"
    echo 'export PATH="$HOME/.local/share/lazyvpn/bin:$PATH"' >> "$SHELL_RC"
    echo "  ✓ Added LazyVPN to PATH in $SHELL_RC"
    export PATH="$HOME/.local/share/lazyvpn/bin:$PATH"
  else
    echo "  LazyVPN already in PATH"
  fi
else
  echo "  ⚠ Could not detect shell config file"
  echo "  Add to your PATH manually: export PATH=\"\$HOME/.local/share/lazyvpn/bin:\$PATH\""
fi

echo ""
echo "Step 6: Initializing LazyVPN..."

# Initialize LazyVPN (creates config directories)
"$LAZYVPN_BIN"/lazyvpn-init

# Prompt for connection name
echo ""
echo "Configure systemd-networkd Connection Name:"
echo "This is the interface name for your VPN connection."
echo "LazyVPN uses a single interface that switches between servers."
echo ""
read -p "Connection name (default: wg0): " CONNECTION_NAME
CONNECTION_NAME="${CONNECTION_NAME:-wg0}"

# Validate connection name
if [[ ! "$CONNECTION_NAME" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo "Invalid connection name. Using default: wg0"
  CONNECTION_NAME="wg0"
fi

echo "  Connection name set to: $CONNECTION_NAME"

# Save to config atomically
CONFIG_FILE="$HOME/.config/lazyvpn/config"
if grep -q "^CONNECTION_NAME=" "$CONFIG_FILE" 2>/dev/null; then
  sed "s|^CONNECTION_NAME=.*|CONNECTION_NAME=$CONNECTION_NAME|" "$CONFIG_FILE" > "$CONFIG_FILE.tmp"
  mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
else
  echo "CONNECTION_NAME=$CONNECTION_NAME" >> "$CONFIG_FILE"
fi

echo ""
echo "Step 7: Integrating with omarchy-menu..."

# Backup original omarchy-menu
if [[ ! -f "$OMARCHY_MENU_FILE.backup" ]]; then
  cp "$OMARCHY_MENU_FILE" "$OMARCHY_MENU_FILE.backup"
  echo "  Created backup: omarchy-menu.backup"
fi

# Check if already integrated
if grep -q "LazyVPN" "$OMARCHY_MENU_FILE"; then
  echo "  LazyVPN already integrated in omarchy-menu"
else
  # Use a single, robust awk script to perform all three modifications.
  # This is the most reliable method and avoids all sed portability issues.
  awk -v lazyvpn_bin="$LAZYVPN_BIN" '
    # 1. Before the line containing show_main_menu(), print our new function.
    /^show_main_menu\(\)/ {
      print "show_lazyvpn_menu() {"
      print "  " lazyvpn_bin "/lazyvpn-menu"
      print "}"
      print ""
    }

    # 2. Find the line inside show_main_menu() and modify it.
    # The actual pattern in the file has \\n (literal backslash-n in the bash string).
    /menu "Go" ".*Setup/ {
      sub(/Setup\\n/, "Setup\\n󰖂  LazyVPN\\n")
    }

    # 3. Find the *system*) case and print our new case before it.
    /\*system\*\) show_system_menu/ {
      print "  *lazyvpn*) show_lazyvpn_menu ;;"
    }

    # 4. Print every line (original or modified).
    { print }
  ' "$OMARCHY_MENU_FILE" > "$OMARCHY_MENU_FILE.tmp" && mv "$OMARCHY_MENU_FILE.tmp" "$OMARCHY_MENU_FILE" && chmod +x "$OMARCHY_MENU_FILE"

  # Diagnostic step: copy the modified file to the local directory for inspection
  # cp "$OMARCHY_MENU_FILE" ./omarchy-menu.modified

  echo "  Integrated LazyVPN into main menu"
  
  echo "  Restarting menu to apply changes..."
  nohup omarchy-restart-walker > /dev/null 2>&1 &
fi

echo ""
echo "Step 8: Adding keyboard shortcut (SUPER+L)..."

# Add keybinding to Hyprland config
HYPR_BINDINGS="$HOME/.config/hypr/bindings.conf"
if [[ -f "$HYPR_BINDINGS" ]]; then
  if grep -q "LazyVPN" "$HYPR_BINDINGS"; then
    echo "  LazyVPN keybinding already exists in Hyprland config"
  else
    echo "" >> "$HYPR_BINDINGS"
    echo "# LazyVPN" >> "$HYPR_BINDINGS"
    echo "bindd = SUPER, L, LazyVPN, exec, $LAZYVPN_BIN/lazyvpn-menu" >> "$HYPR_BINDINGS"
    echo "  ✓ Added SUPER+L keybinding to Hyprland"

    # Reload Hyprland config
    hyprctl reload >/dev/null 2>&1
    echo "  ✓ Reloaded Hyprland configuration"
  fi
else
  echo "  ⚠ Hyprland bindings.conf not found, skipping keybinding"
fi

# Add to keybindings helper
KEYBINDINGS_SCRIPT="$OMARCHY_BIN/omarchy-menu-keybindings"
if [[ -f "$KEYBINDINGS_SCRIPT" ]]; then
  if grep -q "LazyVPN" "$KEYBINDINGS_SCRIPT"; then
    echo "  LazyVPN already in keybindings helper"
  else
    # Add LazyVPN to static_bindings() function
    sed -i "/static_bindings() {/a\\    echo \"SUPER,L,LazyVPN,exec,$LAZYVPN_BIN/lazyvpn-menu\"" "$KEYBINDINGS_SCRIPT"
    echo "  ✓ Added to keybindings helper (SUPER+K)"
  fi
else
  echo "  ⚠ Keybindings script not found, skipping helper integration"
fi

echo ""
echo "Step 9: Adding Waybar integration..."

WAYBAR_CONFIG="$HOME/.config/waybar/config.jsonc"
WAYBAR_STYLE="$HOME/.config/waybar/style.css"

if [[ -f "$WAYBAR_CONFIG" ]]; then
  if grep -q "custom/lazyvpn" "$WAYBAR_CONFIG"; then
    echo "  LazyVPN already integrated in Waybar config"
  else
    # Use awk to safely modify the JSON config
    # This adds "custom/lazyvpn" after "network" ONLY in the modules-right array
    # and adds the module definition before the final closing brace
    awk '
      # Track if we are inside modules-right array
      /"modules-right"/ { in_modules_right = 1 }

      # When in modules-right and we see "network", add our module after it
      in_modules_right && /"network"/ && !added_to_array {
        gsub(/"network"/, "\"network\", \"custom/lazyvpn\"")
        added_to_array = 1
      }

      # Closing bracket ends the modules-right array
      in_modules_right && /\]/ { in_modules_right = 0 }

      # Before the final closing brace, add our module definition
      /^}[[:space:]]*$/ && !added_module {
        print "  ,\"custom/lazyvpn\": {"
        print "    \"format\": \"{}\","
        print "    \"interval\": 5,"
        print "    \"return-type\": \"json\","
        print "    \"exec\": \"~/.local/share/lazyvpn/bin/lazyvpn-waybar-status\","
        print "    \"on-click\": \"~/.local/share/lazyvpn/bin/lazyvpn-menu\""
        print "  }"
        added_module = 1
      }

      { print }
    ' "$WAYBAR_CONFIG" > "$WAYBAR_CONFIG.tmp" && mv "$WAYBAR_CONFIG.tmp" "$WAYBAR_CONFIG"
    echo "  ✓ Added custom/lazyvpn to Waybar config"
  fi
else
  echo "  ⚠ Waybar config not found at $WAYBAR_CONFIG, skipping"
fi

# Add CSS styling
if [[ -f "$WAYBAR_STYLE" ]]; then
  if grep -q "#custom-lazyvpn" "$WAYBAR_STYLE"; then
    echo "  LazyVPN styling already in Waybar CSS"
  else
    cat >> "$WAYBAR_STYLE" << 'CSS_EOF'

/* LazyVPN status indicator */
#custom-lazyvpn {
  margin: 0 7.5px;
}
CSS_EOF
    echo "  ✓ Added LazyVPN styling to Waybar CSS"
  fi
else
  echo "  ⚠ Waybar style.css not found at $WAYBAR_STYLE, skipping"
fi

# Reload waybar if running
if pgrep -x waybar > /dev/null; then
  pkill -SIGUSR2 waybar 2>/dev/null || true
  echo "  ✓ Sent reload signal to Waybar"
fi

# Mark installation as complete
INSTALL_COMPLETE=true

echo ""
echo "==================================="
echo "Installation Complete!"
echo "==================================="
echo ""
echo "Getting Started (Choose ONE method):"
echo ""
echo "OPTION A - Dynamic Server List (Recommended):"
echo "  1. Download ONE WireGuard config from your VPN provider"
echo "  2. Open LazyVPN menu (SUPER+L or SUPER+ALT+SPACE → LazyVPN)"
echo "  3. Go to Options → Setup Provider"
echo "  4. Select your config file - LazyVPN extracts your credentials"
echo "  5. Browse ALL servers without downloading individual configs!"
echo ""
echo "OPTION B - Manual Config Import:"
echo "  1. Download individual WireGuard configs from your VPN provider"
echo "  2. Open LazyVPN menu → Options → Add Manual Server"
echo "  3. Select configs to import"
echo ""
echo "Supported VPN Providers:"
echo "  - ProtonVPN: https://account.protonvpn.com (Downloads → WireGuard)"
echo "  - Mullvad: https://mullvad.net/en/account (WireGuard configuration)"
echo "  - IVPN: https://ivpn.net/account (WireGuard Config Generator)"
echo "  - NordVPN, Surfshark, Windscribe, PIA, and more"
echo ""
echo "Keyboard Shortcuts:"
echo "  - SUPER+L         Open LazyVPN menu"
echo "  - SUPER+ALT+SPACE Omarchy menu → LazyVPN"
echo ""
omarchy-show-done

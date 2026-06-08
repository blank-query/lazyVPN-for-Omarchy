package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/daemon"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/firewall"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/latency"
	netlinkpkg "github.com/blank-query/lazyVPN-for-Omarchy/internal/netlink"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/notify"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/security"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/ui"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/update"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/util"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/term"
)

// Version is set at build time via -ldflags="-X main.Version=X.Y.Z" (no "v" prefix).
var Version = "dev"

const (
	bootNetworkWaitSecs = 30 // seconds to wait for network at boot
)

func main() {
	if len(os.Args) < 2 {
		// No arguments - detect context
		if isTerminal() {
			runTUI()
		} else {
			runLauncher()
		}
		return
	}

	// Handle subcommands
	switch os.Args[1] {
	case "wg-helper":
		runWGHelper()
	case "killswitch":
		runKillswitch()
	case "daemon":
		runDaemon()
	case "boot":
		runBoot()
	case "waybar":
		runWaybar()
	case "install":
		runInstall()
	case "uninstall":
		runUninstall()
	case "random":
		runRandom()
	case "quickest":
		runQuickest()
	case "update":
		runUpdate()
	case "version":
		fmt.Println(Version)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printHelp()
		os.Exit(1)
	}
}

// isAnotherTUIRunning checks if another lazyvpn TUI process is already running.
// Returns true if a duplicate is found (caller should exit).
func isAnotherTUIRunning() bool {
	myPID := os.Getpid()
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	baseName := filepath.Base(exe)

	// Read all PIDs from /proc
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == myPID {
			continue
		}
		// Check if this process is the same executable. matchesExeBaseName
		// strips the kernel's " (deleted)" suffix so a TUI running the
		// previous-version binary (after `lazyvpn update` atomic-renamed
		// it) still matches and the single-instance check works.
		link, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil {
			continue
		}
		if !matchesExeBaseName(link, baseName) {
			continue
		}
		// Check cmdline — only block if it's a TUI instance (no subcommand args)
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		// cmdline is null-separated; a TUI instance has only the binary name (1 arg)
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		if len(args) <= 1 {
			return true
		}
	}
	return false
}

// isTerminal returns true if stdin is attached to a real terminal (TTY).
// Uses ioctl TCGETS check, not ModeCharDevice (which is true for /dev/null).
func isTerminal() bool {
	return term.IsTerminal(os.Stdin.Fd())
}

// hyprClient represents a window from hyprctl clients output.
type hyprClient struct {
	Class   string `json:"class"`
	Address string `json:"address"`
}

// runLauncher handles the case when lazyvpn is invoked without a terminal (e.g. from a keybinding).
// It focuses an existing LazyVPN window if one exists, otherwise spawns a new terminal with the TUI.
func runLauncher() {
	// Bail early if there's no graphical session — otherwise we'd chain into
	// uwsm-app → xdg-terminal-exec → a Wayland-based terminal that crashes
	// with a raw `WAYLAND_DISPLAY not set` error. A clean message is more
	// useful than a Rust panic from a transitive dependency.
	if os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DISPLAY") == "" {
		fmt.Fprintln(os.Stderr, "lazyvpn: no terminal detected and no graphical session ($WAYLAND_DISPLAY/$DISPLAY unset). Run lazyvpn from a terminal.")
		os.Exit(1)
	}

	// Check if a LazyVPN window already exists (Hyprland). Bound this
	// with a context timeout: a wedged Hyprland would otherwise stall
	// `lazyvpn` startup forever instead of falling through to the
	// terminal-spawn path. 2s is generous for the IPC roundtrip.
	hyprctlCtx, hyprctlCancel := context.WithTimeout(context.Background(), 2*time.Second)
	out, err := exec.CommandContext(hyprctlCtx, "hyprctl", "clients", "-j").Output()
	hyprctlCancel()
	if err == nil {
		var clients []hyprClient
		if json.Unmarshal(out, &clients) == nil {
			for _, c := range clients {
				if c.Class == "org.lazyvpn" {
					focusCtx, focusCancel := context.WithTimeout(context.Background(), 2*time.Second)
					exec.CommandContext(focusCtx, "hyprctl", "dispatch", "focuswindow", "class:org.lazyvpn").Run()
					focusCancel()
					return
				}
			}
		}
	}

	execPath, err := os.Executable()
	if err != nil {
		notify.Send(notify.Notification{Title: "LazyVPN", Message: "Failed to determine binary path", Icon: notify.IconError, Timeout: 5000})
		return
	}

	// Try uwsm-app (Omarchy/Hyprland path)
	if uwsmPath, err := exec.LookPath("uwsm-app"); err == nil {
		err = syscall.Exec(uwsmPath, []string{"uwsm-app", "--", "xdg-terminal-exec",
			"--app-id=org.lazyvpn", "--title=LazyVPN",
			"-e", execPath}, os.Environ())
		// syscall.Exec only returns on error
		notify.Send(notify.Notification{Title: "LazyVPN", Message: fmt.Sprintf("Failed to launch: %v", err), Icon: notify.IconError, Timeout: 5000})
		return
	}

	// Try xdg-terminal-exec directly
	if xdgPath, err := exec.LookPath("xdg-terminal-exec"); err == nil {
		err = syscall.Exec(xdgPath, []string{"xdg-terminal-exec", "-e", execPath}, os.Environ())
		notify.Send(notify.Notification{Title: "LazyVPN", Message: fmt.Sprintf("Failed to launch: %v", err), Icon: notify.IconError, Timeout: 5000})
		return
	}

	// Try common terminal emulators
	terminals := []struct {
		bin  string
		args []string
	}{
		{"alacritty", []string{"alacritty", "--title", "LazyVPN", "-e", execPath}},
		{"kitty", []string{"kitty", "--title", "LazyVPN", execPath}},
		{"ghostty", []string{"ghostty", "-e", execPath}},
		{"gnome-terminal", []string{"gnome-terminal", "--", execPath}},
	}
	for _, t := range terminals {
		if binPath, err := exec.LookPath(t.bin); err == nil {
			err = syscall.Exec(binPath, t.args, os.Environ())
			notify.Send(notify.Notification{Title: "LazyVPN", Message: fmt.Sprintf("Failed to launch: %v", err), Icon: notify.IconError, Timeout: 5000})
			return
		}
	}

	// Last resort
	notify.Send(notify.Notification{Title: "LazyVPN", Message: "No terminal emulator found. Run 'lazyvpn' in your terminal.", Icon: notify.IconError, Timeout: 10000})
}

func runTUI() {
	if isAnotherTUIRunning() {
		os.Exit(0)
	}

	ui.Version = Version
	ui.InitTheme()
	model := ui.NewLayout()

	p := tea.NewProgram(model, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Check if we should run uninstall after TUI exits
	if layout, ok := finalModel.(*ui.Layout); ok && layout.ShouldRunUninstall() {
		runUninstall()
	}
}

// printSudoersHintIfMissing emits a one-line hint when the user's last error
// is likely caused by missing sudoers entries. CLI subcommands fail with raw
// "sudo authentication required" otherwise, which doesn't tell the user
// what to do about it.
func printSudoersHintIfMissing() {
	cfg, err := config.Load()
	if err != nil || cfg.SudoersInstalled {
		return
	}
	fmt.Fprintln(os.Stderr, "Hint: NOPASSWD sudoers entries are not installed. Run 'lazyvpn install' to add them, or use the TUI which prompts for the password interactively.")
}

func runKillswitch() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: lazyvpn killswitch <enable|disable|off|status>")
		os.Exit(1)
	}

	switch os.Args[2] {
	case "enable", "on":
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}

		ksCfg := &firewall.KillswitchConfig{
			InterfaceName: cfg.ConnectionName,
		}

		// Get DNS and endpoint if connected
		if cfg.LastConnectedServer != "" {
			if strings.HasPrefix(cfg.LastConnectedServer, "dynamic:") {
				// Dynamic server - get endpoint from cache
				parts := strings.SplitN(cfg.LastConnectedServer, ":", 3)
				if len(parts) == 3 {
					providerCfg, err := config.LoadProvider(cfg.ConfigDir, parts[1])
					if err == nil {
						// Zero the loaded PrivateKey on return — we only
						// need DNS here, but the load also pulled in the
						// key. Without ZeroKey the bytes linger on heap
						// until GC. Defense-in-depth matching the pattern
						// in wireguard.ConnectDynamic and elsewhere.
						defer providerCfg.ZeroKey()
						ksCfg.DNS = providerCfg.DNS
					}
					serverData, err := config.LoadServerFromCache(cfg.ConfigDir, parts[1], parts[2])
					if err == nil && serverData.IP != "" {
						ksCfg.Endpoint = serverData.IP
					}
				}
			} else {
				// Manual server - load from config file
				wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
				wgCfg, _ := wireguard.LoadConfig(wgDir, cfg.LastConnectedServer)
				if wgCfg != nil {
					// We only need DNS + Endpoint here; the load also
					// pulled in PrivateKey + PresharedKey. Mirror the
					// dynamic-server LoadProvider site above (which
					// defers ZeroKey) and the wireguard.Connect path
					// that wipes after use.
					defer wgCfg.ZeroKeys()
					ksCfg.DNS = wgCfg.DNS
					ksCfg.Endpoint = wgCfg.EndpointIP()
				}
			}
		}

		if wireguard.IsConnected(cfg.ConnectionName) {
			if err := firewall.Enable(ksCfg); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				printSudoersHintIfMissing()
				os.Exit(1)
			}
		} else {
			if err := firewall.EnableSimple(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				printSudoersHintIfMissing()
				os.Exit(1)
			}
		}
		fmt.Println("Killswitch enabled")

	case "disable", "off":
		if err := firewall.Disable(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			printSudoersHintIfMissing()
			os.Exit(1)
		}
		fmt.Println("Killswitch disabled")

	case "status":
		if firewall.IsActive() {
			fmt.Println("Killswitch: Active")
		} else {
			fmt.Println("Killswitch: Inactive")
		}

	default:
		fmt.Printf("Unknown killswitch command: %s\n", os.Args[2])
		fmt.Println("Usage: lazyvpn killswitch <enable|disable|off|status>")
		os.Exit(1)
	}
}

func runDaemon() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: lazyvpn daemon <stop|status>")
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	switch os.Args[2] {
	case "run":
		// Internal command - spawned by TUI/CLI to run daemon process
		// Usage: lazyvpn daemon run <server> [--provider <provider>] [--dynamic]
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: lazyvpn daemon run <server> [--provider <provider>] [--dynamic]\n")
			os.Exit(1)
		}
		server := os.Args[3]
		var provider string
		var isDynamic bool

		// Parse flags
		for i := 4; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--provider":
				if i+1 < len(os.Args) {
					provider = os.Args[i+1]
					i++
				}
			case "--dynamic":
				isDynamic = true
			}
		}

		// Run daemon with connection
		if err := daemon.RunWithConnect(cfg, server, provider, isDynamic); err != nil {
			fmt.Fprintf(os.Stderr, "Daemon error: %v\n", err)
			os.Exit(1)
		}

	case "stop":
		if err := daemon.StopDaemon(cfg.ConfigDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Daemon stopped (VPN disconnected)")

	case "status":
		if daemon.IsDaemonRunning(cfg.ConfigDir) {
			status, err := daemon.QuickStatus(cfg.ConfigDir)
			if err != nil {
				fmt.Println("Daemon: Running (status unavailable)")
			} else {
				fmt.Println("Daemon: Running")
				if status.Server != "" {
					fmt.Printf("Server: %s\n", status.Server)
				}
				if status.PublicIP != "" {
					fmt.Printf("Public IP: %s\n", status.PublicIP)
				}
			}
		} else {
			fmt.Println("Daemon: Not running")
		}

	default:
		fmt.Printf("Unknown daemon command: %s\n", os.Args[2])
		fmt.Println("Usage: lazyvpn daemon <stop|status>")
		os.Exit(1)
	}
}

func runBoot() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("LazyVPN autostart handler starting...")

	// Only proceed if autostart is enabled
	if !cfg.Autostart {
		fmt.Println("Autostart disabled, exiting")
		return
	}

	// Killswitch state persists via UFW (its rules survive reboot if ufw.service
	// is enabled). Nothing to "re-enable" on boot — UFW is already enforcing
	// whatever state it was left in.
	if firewall.IsActive() {
		fmt.Println("✓ Killswitch active (preserved from previous session)")
	}

	// IPv6 protection state persists via UFW rules + /etc/sysctl.d — nothing
	// to re-apply on boot. UFW is the source of truth.
	if firewall.IsIPv6Disabled() {
		fmt.Println("✓ IPv6 leak protection active (preserved from previous session)")
	}

	// Wait for NIC to be ready (DHCP complete, default route assigned)
	fmt.Println("Waiting for network interface...")
	nicReady := false
	for i := 0; i < bootNetworkWaitSecs; i++ {
		if iface, _, err := firewall.GetPhysicalInterface(); err == nil && iface != "" {
			fmt.Printf("Network interface ready (%s) after %d seconds\n", iface, i+1)
			nicReady = true
			break
		}
		time.Sleep(time.Second)
	}

	if !nicReady {
		fmt.Printf("Warning: No network interface after %d seconds, attempting autoconnect anyway...\n", bootNetworkWaitSecs)
	}

	// Send notification
	notify.Info("LazyVPN", "Autoconnect starting...")

	// Connect based on autostart mode
	var connectErr error
	switch cfg.AutostartMode {
	case "quickest":
		// Check if killswitch is blocking (prevents latency test)
		if firewall.IsActive() && !wireguard.IsConnected(cfg.ConnectionName) {
			fmt.Println("Killswitch is active - cannot test latency, falling back to random")
			notify.Info("LazyVPN", "Autoconnecting to random server (killswitch prevents latency test)")
			connectErr = connectRandom(cfg)
		} else {
			fmt.Println("Finding quickest server...")
			connectErr = connectQuickest(cfg)
		}

	case "random":
		fmt.Println("Connecting to random server...")
		connectErr = connectRandom(cfg)

	case "last_used":
		if cfg.LastConnectedServer != "" {
			fmt.Printf("Connecting to last used server: %s\n", cfg.LastConnectedServer)
			connectErr = connectToServer(cfg, cfg.LastConnectedServer)
		} else {
			fmt.Println("No last used server, falling back to random")
			connectErr = connectRandom(cfg)
		}

	case "specific":
		if cfg.AutostartServer != "" {
			fmt.Printf("Connecting to specific server: %s\n", cfg.AutostartServer)
			connectErr = connectToServer(cfg, cfg.AutostartServer)
		} else {
			fmt.Println("No specific server configured")
		}

	default:
		fmt.Printf("Unknown autostart mode: %s\n", cfg.AutostartMode)
	}

	if connectErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", connectErr)
		notify.Error("Autoconnect failed: " + connectErr.Error())
		os.Exit(1)
	}

	fmt.Println("Autostart complete!")
}

// Helper functions for boot
func connectRandom(cfg *config.Config) error {
	server, err := latency.GetRandomServer(cfg)
	if err != nil {
		return err
	}
	return connectServerObj(cfg, server)
}

func connectQuickest(cfg *config.Config) error {
	server, latencyMs, err := latency.FindQuickestServer(cfg, 50, func(tested, total, reachable int) {
		fmt.Printf("\r  Tested %d/%d servers (%d reachable)", tested, total, reachable)
	})
	fmt.Println()
	if err != nil {
		return err
	}
	fmt.Printf("Quickest server: %s (%dms)\n", server.Name, latencyMs)
	return connectServerObj(cfg, server)
}

func connectToServer(cfg *config.Config, serverSpec string) error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	// Parse dynamic server format: "dynamic:provider:server_name"
	if strings.HasPrefix(serverSpec, "dynamic:") {
		parts := strings.SplitN(serverSpec, ":", 3)
		if len(parts) != 3 {
			return fmt.Errorf("invalid dynamic server format: %s", serverSpec)
		}
		client, err := daemon.SpawnAndWaitForConnect(cfg.ConfigDir, execPath, parts[2], parts[1], true, func(e daemon.Event) {
			fmt.Printf("  %s\n", e.Message)
		})
		if client != nil {
			client.Close()
		}
		return err
	}

	// Manual server
	client, err := daemon.SpawnAndWaitForConnect(cfg.ConfigDir, execPath, serverSpec, "", false, func(e daemon.Event) {
		fmt.Printf("  %s\n", e.Message)
	})
	if client != nil {
		client.Close()
	}
	return err
}

func connectServerObj(cfg *config.Config, server *latency.ServerEntry) error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	isDynamic := server.Type == "dynamic"
	client, err := daemon.SpawnAndWaitForConnect(cfg.ConfigDir, execPath, server.Name, server.Provider, isDynamic, func(e daemon.Event) {
		fmt.Printf("  %s\n", e.Message)
	})
	if client != nil {
		client.Close()
	}
	return err
}

func runRandom() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Selecting random server...")
	if err := connectRandom(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Connected!")
}

func runQuickest() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Warn if killswitch would block latency tests
	if firewall.IsActive() && !wireguard.IsConnected(cfg.ConnectionName) {
		fmt.Println("Warning: Killswitch active - latency tests may be blocked")
		fmt.Println("Falling back to random server...")
		if err := connectRandom(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Connected!")
		return
	}

	fmt.Println("Finding quickest server...")
	if err := connectQuickest(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Connected!")
}

func runInstall() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}
	srcExecPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine executable path: %v\n", err)
		os.Exit(1)
	}
	srcExecPath, _ = filepath.EvalSymlinks(srcExecPath)

	// Detect system
	distro := config.DetectDistro()
	fsType := config.DetectFSType(homeDir)
	isOmarchy := distro == "omarchy"
	_, hyprErr := exec.LookPath("hyprctl")
	isHyprland := hyprErr == nil
	_, waybarErr := exec.LookPath("waybar")
	isWaybar := waybarErr == nil

	fmt.Println("===================================")
	fmt.Println("LazyVPN Installer")
	fmt.Println("===================================")
	fmt.Println()
	fmt.Println("Detecting system...")
	fmt.Printf("  Distro:     %s\n", distro)
	fmt.Printf("  Filesystem: %s\n", fsType)
	fmt.Printf("  Hyprland:   %v\n", isHyprland)
	fmt.Printf("  Waybar:     %v\n", isWaybar)
	fmt.Println()

	// Check for leftover LazyVPN files from a prior install. Only report
	// what we actually find — don't claim "installed" if state is partial,
	// since a stale binary or empty config dir can persist after a botched
	// uninstall. Exact, observable wording avoids the false-positive
	// "already installed" message when the user knows they uninstalled.
	installedBinary := filepath.Join(homeDir, ".local", "bin", "lazyvpn")
	installedConfig := filepath.Join(homeDir, ".config", "lazyvpn", "config.json")
	_, binErr := os.Stat(installedBinary)
	_, cfgErr := os.Stat(installedConfig)
	binExists := binErr == nil
	cfgExists := cfgErr == nil
	if binExists || cfgExists {
		switch {
		case binExists && cfgExists:
			fmt.Println("LazyVPN looks already installed:")
		case binExists:
			fmt.Println("Found a leftover LazyVPN binary (no config):")
		case cfgExists:
			fmt.Println("Found a leftover LazyVPN config (no binary):")
		}
		if binExists {
			fmt.Printf("  Binary: %s\n", installedBinary)
		}
		if cfgExists {
			fmt.Printf("  Config: %s\n", installedConfig)
		}
		fmt.Println()
		fmt.Println("What would you like to do?")
		fmt.Println("  1) Abort")
		fmt.Println("  2) Run uninstaller to clean up")
		fmt.Println("  3) Reinstall over existing")
		fmt.Print("Choice [1]: ")
		var choice string
		fmt.Scanln(&choice)
		switch choice {
		case "2":
			fmt.Println()
			runUninstall()
			return
		case "3":
			fmt.Println()
			fmt.Println("Continuing with reinstall...")
			fmt.Println()
		default:
			fmt.Println("Aborted.")
			return
		}
	}

	// Check if systemd-networkd is enabled
	cmd := exec.Command("systemctl", "is-enabled", "systemd-networkd")
	if err := cmd.Run(); err != nil {
		fmt.Println("Error: systemd-networkd is not enabled.")
		fmt.Println("LazyVPN is built specifically for systemd-networkd.")
		fmt.Println("Please enable it first:")
		fmt.Println("  sudo systemctl enable --now systemd-networkd")
		fmt.Println("  sudo systemctl enable --now systemd-resolved")
		os.Exit(1)
	}

	// Install binary to ~/.local/bin/lazyvpn
	installDir := filepath.Join(homeDir, ".local", "bin")
	execPath := filepath.Join(installDir, "lazyvpn")
	fmt.Println("Step 1: Installing binary...")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot create %s: %v\n", installDir, err)
		os.Exit(1)
	}
	if srcExecPath != execPath {
		srcData, err := os.ReadFile(srcExecPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot read binary: %v\n", err)
			os.Exit(1)
		}
		// Atomic write via random-suffix temp + rename. The previous fixed
		// "<path>.tmp" name let two concurrent installers stomp each other
		// mid-write, producing an unexecutable half-written binary at the
		// final path on rename. CreateTemp gives each writer its own slot.
		tmp, err := os.CreateTemp(installDir, "lazyvpn.*.tmp")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot create temp file in %s: %v\n", installDir, err)
			os.Exit(1)
		}
		tmpPath := tmp.Name()
		if _, err := tmp.Write(srcData); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			fmt.Fprintf(os.Stderr, "Error: cannot write to %s: %v\n", tmpPath, err)
			os.Exit(1)
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmpPath)
			fmt.Fprintf(os.Stderr, "Error: cannot close %s: %v\n", tmpPath, err)
			os.Exit(1)
		}
		if err := os.Chmod(tmpPath, 0755); err != nil {
			os.Remove(tmpPath)
			fmt.Fprintf(os.Stderr, "Error: cannot chmod %s: %v\n", tmpPath, err)
			os.Exit(1)
		}
		if err := os.Rename(tmpPath, execPath); err != nil {
			os.Remove(tmpPath)
			fmt.Fprintf(os.Stderr, "Error: cannot install binary to %s: %v\n", execPath, err)
			os.Exit(1)
		}
		fmt.Printf("  Installed: %s\n", execPath)
	} else {
		fmt.Printf("  Already at %s\n", execPath)
	}

	// Step 2: Create config directories
	fmt.Println()
	fmt.Println("Step 2: Creating config directories...")
	configDir := filepath.Join(homeDir, ".config/lazyvpn")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot create config directory %s: %v\n", configDir, err)
		os.Exit(1)
	}
	// Enforce 0700 permissions on existing dirs (MkdirAll doesn't update
	// them, and providers/ holds private keys — degraded perms here would
	// silently leave credentials world-readable).
	for _, dir := range []string{
		configDir,
		filepath.Join(configDir, "wireguard"),
		filepath.Join(configDir, "providers"),
		filepath.Join(configDir, "cache"),
	} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot create %s: %v\n", dir, err)
			os.Exit(1)
		}
		if err := os.Chmod(dir, 0700); err != nil {
			// Surface but don't exit — chmod can fail on noexec/nosuid
			// mounts where the dir is still usable. Worth warning so the
			// user notices their sensitive credential dir is wider open.
			fmt.Fprintf(os.Stderr, "  ⚠ Could not enforce 0700 on %s: %v\n", dir, err)
		}
	}
	fmt.Printf("  Created: %s\n", configDir)

	// Create or update config
	configFile := filepath.Join(configDir, "config.json")
	cfg, loadErr := config.Load()
	if loadErr != nil {
		fmt.Println("  ⚠ Config file is corrupted, resetting to defaults")
	}

	// Store detected system info
	cfg.Distro = distro
	cfg.FSType = fsType

	// Detect and save install source directory (git clone location)
	cwd, _ := os.Getwd()
	gitDir := filepath.Join(cwd, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		// We're running from a git clone directory
		cfg.InstallSourceDir = cwd
		fmt.Printf("  Detected install source: %s\n", cwd)
	}

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Failed to create default configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("  Created default configuration")
	} else {
		// Always save to persist distro/fstype detection. Log-only on
		// failure — config already exists with some values; user can
		// still proceed.
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Failed to refresh configuration (distro/FS detection): %v\n", err)
		}
	}

	// Step 3: Interface name
	// Loop until the user enters a valid custom name or accepts the default
	// (empty input). Rejections explain *why* the input was invalid and
	// re-prompt instead of silently falling back to the default — otherwise
	// a user who typed a bad name wouldn't get a chance to correct it.
	fmt.Println()
	fmt.Println("Step 3: WireGuard interface name...")
	fmt.Println()
	connName := cfg.ConnectionName
	validName := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	for {
		fmt.Printf("  Interface name [%s]: ", connName)
		var nameChoice string
		fmt.Scanln(&nameChoice)
		nameChoice = strings.TrimSpace(nameChoice)
		if nameChoice == "" {
			// User pressed Enter — accept default
			break
		}
		if !validName.MatchString(nameChoice) {
			fmt.Printf("  ⚠ '%s' contains invalid characters — only letters, digits, '.', '_', and '-' are allowed. Please enter another name.\n", nameChoice)
			continue
		}
		if len(nameChoice) > 15 {
			fmt.Printf("  ⚠ '%s' is too long (%d characters) — Linux interface names max out at 15. Please enter a shorter name.\n", nameChoice, len(nameChoice))
			continue
		}
		if isExistingInterface(nameChoice) {
			fmt.Printf("  ⚠ '%s' is already a network interface on this system. The VPN tunnel needs a unique name — pick something that isn't a physical NIC (e.g. wg0, wg-vpn, proton0).\n", nameChoice)
			continue
		}
		connName = nameChoice
		break
	}
	if connName != cfg.ConnectionName {
		cfg.ConnectionName = connName
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Failed to persist interface name: %v\n", err)
		}
	}
	fmt.Printf("  Interface: %s\n", connName)

	// Step 4: Sudoers configuration
	fmt.Println()
	fmt.Println("Step 4: Configuring VPN operations...")
	fmt.Println()
	fmt.Println("LazyVPN can configure passwordless sudo for specific VPN-related commands:")
	fmt.Println("  • ip link/addr/route (scoped to interface: " + connName + ")")
	fmt.Println("  • resolvectl, ufw, systemd-networkd")
	fmt.Println()
	fmt.Println("This allows seamless connection/disconnection without password prompts.")
	fmt.Println("Only specific commands are permitted, not blanket sudo access.")
	fmt.Println()
	fmt.Print("Enable passwordless sudo for VPN commands? [Y/n] ")

	var choice string
	fmt.Scanln(&choice)
	if choice != "n" && choice != "N" {
		if installSudoers(execPath, connName, fsType == "btrfs") {
			cfg.SudoersInstalled = true
			// Critical save: the SudoersInstalled flag gates whether
			// rename-interface refreshes the sudoers file. Silent failure
			// here would resurrect the 0750-EACCES rename bug.
			if err := cfg.Save(); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ Sudoers installed but failed to persist flag: %v\n", err)
				fmt.Fprintln(os.Stderr, "     Rename-interface will not regenerate sudoers until the config saves successfully.")
			}
		}
	} else {
		fmt.Println("Skipping passwordless sudo configuration")
		fmt.Println("You will be prompted for password during VPN operations")
	}

	// Always set capabilities on the binary regardless of sudoers choice.
	// This enables native netlink operations without sudo.
	setCapabilities(execPath)

	// IPv6 default. Most VPNs and almost all consumer software run fine
	// over IPv4 alone, and a live IPv6 stack is the most common source of
	// silent leaks on installs that haven't tuned the killswitch yet.
	// Ask the user explicitly — silent system-state changes break trust.
	fmt.Println()
	fmt.Println("Block IPv6 system-wide?")
	fmt.Println("  Almost everything works fine on IPv4 alone, and the IPv6 stack")
	fmt.Println("  is the most common source of silent VPN leaks.")
	fmt.Println("  Decline only if you specifically need IPv6 (Tailscale, local v6 services).")
	fmt.Println("  Toggleable later from the TUI dashboard.")
	fmt.Print("Block IPv6? [Y/n] ")
	var ipv6Choice string
	fmt.Scanln(&ipv6Choice)
	if ipv6Choice != "n" && ipv6Choice != "N" {
		if err := firewall.DisableIPv6(); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Failed to block IPv6: %v\n", err)
			fmt.Fprintln(os.Stderr, "     You can retry from the TUI dashboard (IPv6 toggle).")
		} else {
			fmt.Println("  ✓ IPv6 blocked (sysctl + UFW deny rules + persistent /etc/sysctl.d entry)")
		}
	} else {
		fmt.Println("  - IPv6 left enabled. Killswitch will still block v6 leaks for v4-only VPNs.")
	}

	// Step 4b: Create autostart desktop file if autoconnect is enabled
	if cfg.Autostart {
		autostartDir := filepath.Join(homeDir, ".config", "autostart")
		if err := os.MkdirAll(autostartDir, 0755); err != nil {
			fmt.Printf("  ⚠ Failed to create autostart dir %s: %v (autoconnect at boot won't fire)\n", autostartDir, err)
		}
		desktopContent := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=LazyVPN Autostart
Exec="%s" boot
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
`, execPath)
		desktopFile := filepath.Join(autostartDir, "lazyvpn.desktop")
		if err := writeFileAtomic(desktopFile, []byte(desktopContent), 0644); err != nil {
			fmt.Printf("  ⚠ Failed to create autostart desktop file: %v\n", err)
		} else {
			fmt.Println("  ✓ Created autostart desktop file")
		}
	}

	// Step 5: Hyprland keybinding
	launchCmd := execPath
	if !isHyprland {
		fmt.Println()
		fmt.Println("Step 5: Skipping Hyprland keybindings (Hyprland not detected)")
	} else {
		fmt.Println()
		fmt.Println("Step 5: Adding keyboard shortcut (SUPER+SHIFT+L)...")
		hyprBindings := filepath.Join(homeDir, ".config/hypr/bindings.conf")
		if _, err := os.Stat(hyprBindings); err == nil {
			content, _ := os.ReadFile(hyprBindings)
			contentStr := string(content)

			// Migrate old SUPER, L binding to SUPER SHIFT, L
			if migrated, changed := migrateHyprBinding(contentStr, launchCmd); changed {
				if err := writeFileAtomic(hyprBindings, []byte(migrated), 0644); err != nil {
					fmt.Printf("  ⚠ Failed to migrate keybinding: %v\n", err)
				} else {
					fmt.Println("  ✓ Migrated SUPER+L → SUPER+SHIFT+L keybinding")
					hyprctlReload()
					fmt.Println("  ✓ Reloaded Hyprland configuration")
				}
			} else if !hyprBindingExists(contentStr) {
				f, err := os.OpenFile(hyprBindings, os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					fmt.Printf("  ⚠ Failed to open Hyprland bindings.conf: %v\n", err)
				} else {
					_, writeErr := f.WriteString(appendHyprBinding(launchCmd))
					closeErr := f.Close()
					switch {
					case writeErr != nil:
						fmt.Printf("  ⚠ Failed to write Hyprland keybinding: %v\n", writeErr)
					case closeErr != nil:
						fmt.Printf("  ⚠ Failed to flush Hyprland keybinding: %v\n", closeErr)
					default:
						fmt.Println("  ✓ Added SUPER+SHIFT+L keybinding to Hyprland (floating window)")
						hyprctlReload()
						fmt.Println("  ✓ Reloaded Hyprland configuration")
					}
				}
			} else {
				fmt.Println("  LazyVPN keybinding already exists")
			}
		} else {
			fmt.Println("  ⚠ Hyprland bindings.conf not found, skipping")
		}

		// Add window rules to hyprland.conf (part of Step 5)
		hyprlandConf := filepath.Join(homeDir, ".config/hypr/hyprland.conf")
		if _, err := os.Stat(hyprlandConf); err == nil {
			content, readErr := os.ReadFile(hyprlandConf)
			if readErr != nil {
				// Don't proceed to write — addHyprWindowRules on empty input
				// would corrupt the existing file (truncate to bare rules).
				fmt.Printf("  ⚠ Failed to read hyprland.conf: %v\n", readErr)
			} else {
				contentStr := addHyprWindowRules(string(content))
				// Atomic write: a crash mid-write would otherwise leave a
				// truncated hyprland.conf and break the user's WM on next login.
				if err := writeFileAtomic(hyprlandConf, []byte(contentStr), 0644); err != nil {
					fmt.Printf("  ⚠ Failed to write hyprland.conf: %v\n", err)
				} else {
					fmt.Println("  ✓ Added LazyVPN window rules to Hyprland config")
				}
			}
		}

		// Clean up any stale LazyVPN entries from keybindings helper (Omarchy-specific)
		if isOmarchy {
			keybindingsScript := filepath.Join(homeDir, ".local/share/omarchy/bin/omarchy-menu-keybindings")
			if content, err := os.ReadFile(keybindingsScript); err == nil {
				if strings.Contains(string(content), "LazyVPN") {
					lines := strings.Split(string(content), "\n")
					var newLines []string
					for _, line := range lines {
						if !strings.Contains(line, "LazyVPN") {
							newLines = append(newLines, line)
						}
					}
					if err := writeFileAtomic(keybindingsScript, []byte(strings.Join(newLines, "\n")), 0755); err != nil {
						fmt.Printf("  ⚠ Failed to clean keybindings helper: %v\n", err)
					} else {
						fmt.Println("  ✓ Cleaned stale LazyVPN entries from keybindings helper")
					}
				}
			}
		}
	} // end isHyprland step 5

	// Step 6: Clean up legacy Omarchy menu integration (replaced by .desktop file)
	fmt.Println()
	if isOmarchy {
		fmt.Println("Step 6: Cleaning up legacy Omarchy menu integration...")
		omarchyMenuFile := filepath.Join(homeDir, ".local/share/omarchy/bin/omarchy-menu")
		backupFile := omarchyMenuFile + ".backup"
		if _, err := os.Stat(backupFile); err == nil {
			if err := os.Rename(backupFile, omarchyMenuFile); err != nil {
				fmt.Printf("  ⚠ Failed to restore omarchy-menu from backup: %v\n", err)
				fmt.Printf("    Backup file remains at: %s\n", backupFile)
			} else {
				if err := os.Chmod(omarchyMenuFile, 0755); err != nil {
					fmt.Printf("  ⚠ Restored omarchy-menu but chmod 0755 failed: %v\n", err)
				} else {
					fmt.Println("  ✓ Restored omarchy-menu from backup")
				}
				exec.Command("omarchy-restart-walker").Start()
			}
		} else if content, err := os.ReadFile(omarchyMenuFile); err == nil {
			if strings.Contains(string(content), "LazyVPN") {
				fmt.Println("  ⚠ LazyVPN found in menu but no backup available")
				fmt.Println("    You may need to reinstall Omarchy to restore the menu")
			} else {
				fmt.Println("  No legacy menu integration found")
			}
		} else {
			fmt.Println("  No legacy menu integration found")
		}
		fmt.Println("  (LazyVPN is now available via app launcher / .desktop file)")
	} else {
		fmt.Println("Step 6: Skipping Omarchy menu cleanup (not Omarchy)")
	}

	// Step 7: Waybar integration
	if !isWaybar {
		fmt.Println()
		fmt.Println("Step 7: Skipping Waybar integration (Waybar not detected)")
	} else {
		fmt.Println()
		fmt.Println("Step 7: Adding Waybar integration...")
		waybarConfig := filepath.Join(homeDir, ".config/waybar/config.jsonc")
		waybarStyle := filepath.Join(homeDir, ".config/waybar/style.css")

		if _, err := os.Stat(waybarConfig); err == nil {
			content, _ := os.ReadFile(waybarConfig)
			if strings.Contains(string(content), "custom/lazyvpn") {
				fmt.Println("  LazyVPN already integrated in Waybar config")
			} else {
				// Add module to modules-right and add module definition.
				newContent := string(content)

				// First try: insert after the existing "network" entry in
				// modules-right. This is the common case and keeps positioning
				// next to other status indicators. The inner [^\]]*? bounds
				// the lazy match so we don't cross out of the modules-right
				// array — without that, a later module definition like
				// `"network": { ... }` would steal the match and the
				// replacement would insert outside the array, corrupting JSON.
				modulesRightAfterNetwork := regexp.MustCompile(`("modules-right"\s*:\s*\[[^\]]*?)"network"([^\]]*?\])`)
				afterNetwork := modulesRightAfterNetwork.ReplaceAllString(newContent, `$1"network", "custom/lazyvpn"$2`)
				referenced := false
				if afterNetwork != newContent {
					newContent = afterNetwork
					referenced = true
				} else {
					// Fallback: user removed "network" from modules-right (or
					// renamed it). Append "custom/lazyvpn" as the last element
					// of the modules-right array. Without this fallback the
					// module definition gets added but never referenced and
					// Waybar logs an error on every reload.
					modulesRightAppend := regexp.MustCompile(`(?s)("modules-right"\s*:\s*\[(?:[^\]]*[^\s\[])?)\s*(\])`)
					appended := modulesRightAppend.ReplaceAllStringFunc(newContent, func(match string) string {
						sub := modulesRightAppend.FindStringSubmatch(match)
						prefix, closing := sub[1], sub[2]
						// If the array already has elements, prepend a comma; if
						// it was empty (`[]`), no leading comma.
						if strings.HasSuffix(strings.TrimSpace(strings.TrimSuffix(prefix, ",")), "[") {
							return prefix + `"custom/lazyvpn"` + closing
						}
						return prefix + `, "custom/lazyvpn"` + closing
					})
					if appended != newContent {
						newContent = appended
						referenced = true
					}
				}

				if !referenced {
					// modules-right array not found at all — without a referencer
					// the module definition is just dead config. Skip the write
					// and surface why so the user can fix it manually.
					fmt.Println("  ⚠ Could not find a modules-right array in waybar config; skipping integration.")
					fmt.Println("    Add \"custom/lazyvpn\" to modules-right manually if you want the indicator.")
				} else {
					// Add module definition before final }
					execJSON, _ := json.Marshal(execPath + " waybar")
					clickJSON, _ := json.Marshal(launchCmd)
					moduleDef := fmt.Sprintf(`  ,"custom/lazyvpn": {
    "format": "{}",
    "interval": 2,
    "return-type": "json",
    "exec": %s,
    "on-click": %s
  }
}`, string(execJSON), string(clickJSON))
					lastBrace := strings.LastIndex(newContent, "}")
					if lastBrace > 0 {
						newContent = newContent[:lastBrace] + moduleDef
					}

					if err := writeFileAtomic(waybarConfig, []byte(newContent), 0644); err != nil {
						fmt.Printf("  ⚠ Failed to write waybar config: %v\n", err)
					} else {
						fmt.Println("  ✓ Added custom/lazyvpn to Waybar config")
					}
				}
			}
		} else {
			fmt.Println("  ⚠ Waybar config not found, skipping")
		}

		// Add CSS styling
		if _, err := os.Stat(waybarStyle); err == nil {
			content, _ := os.ReadFile(waybarStyle)
			if !strings.Contains(string(content), "#custom-lazyvpn {") {
				f, err := os.OpenFile(waybarStyle, os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					fmt.Printf("  ⚠ Failed to open Waybar CSS: %v\n", err)
				} else {
					_, writeErr := f.WriteString("\n/* LazyVPN status indicator */\n#custom-lazyvpn {\n  margin: 0 7.5px;\n}\n#custom-lazyvpn.connected {\n}\n#custom-lazyvpn.connecting {\n  animation: lazyvpn-blink 1s ease-in-out infinite;\n}\n#custom-lazyvpn.disconnected {\n  color: transparent;\n  margin: 0;\n  padding: 0;\n  font-size: 0;\n}\n#custom-lazyvpn.ks-blocking {\n  color: #ff5555;\n  animation: lazyvpn-blink 1s ease-in-out infinite;\n}\n#custom-lazyvpn.error {\n  color: #ff5555;\n}\n@keyframes lazyvpn-blink {\n  from { opacity: 1; }\n  50% { opacity: 0.3; }\n  to { opacity: 1; }\n}\n")
					closeErr := f.Close()
					switch {
					case writeErr != nil:
						fmt.Printf("  ⚠ Failed to write Waybar CSS: %v\n", writeErr)
					case closeErr != nil:
						fmt.Printf("  ⚠ Failed to flush Waybar CSS: %v\n", closeErr)
					default:
						fmt.Println("  ✓ Added LazyVPN styling to Waybar CSS")
					}
				}
			}
		}

		// Reload Waybar
		exec.Command("pkill", "-SIGUSR2", "waybar").Run()
		fmt.Println("  ✓ Sent reload signal to Waybar")
	} // end isWaybar step 7

	// Step 8: Add application launcher entry (.desktop file)
	fmt.Println()
	fmt.Println("Step 8: Adding application launcher entry...")
	appsDir := filepath.Join(homeDir, ".local", "share", "applications")
	os.MkdirAll(appsDir, 0755)
	desktopFile := filepath.Join(appsDir, "lazyvpn.desktop")
	desktopContent := fmt.Sprintf(`[Desktop Entry]
Version=1.0
Type=Application
Name=LazyVPN
Comment=WireGuard VPN Manager
Exec=%s
Icon=network-vpn
Terminal=false
Categories=Network;System;
Keywords=vpn;wireguard;privacy;
StartupNotify=false
`, execPath)
	if err := writeFileAtomic(desktopFile, []byte(desktopContent), 0644); err != nil {
		fmt.Printf("  ⚠ Failed to create lazyvpn.desktop: %v\n", err)
	} else {
		fmt.Println("  ✓ Created lazyvpn.desktop (available in app launchers)")
	}

	// Step 9: Add to PATH
	fmt.Println()
	fmt.Println("Step 9: Adding LazyVPN to PATH...")
	binDir := filepath.Dir(execPath)

	// Detect shell RC file
	var shellRC string
	shell := os.Getenv("SHELL")
	if strings.Contains(shell, "zsh") {
		shellRC = filepath.Join(homeDir, ".zshrc")
	} else {
		shellRC = filepath.Join(homeDir, ".bashrc")
	}

	pathLine := fmt.Sprintf(`export PATH="%s:$PATH"`, binDir)
	if content, err := os.ReadFile(shellRC); err == nil {
		// Match the actual export line, not just the directory string —
		// otherwise a comment, alias, or unrelated reference to ~/.local/bin
		// elsewhere in the rc file silently passes the idempotency check
		// and leaves the binary unreachable in new shells.
		if !strings.Contains(string(content), pathLine) {
			f, err := os.OpenFile(shellRC, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Printf("  ⚠ Failed to open %s: %v\n", filepath.Base(shellRC), err)
			} else {
				_, writeErr := f.WriteString("\n# LazyVPN\n" + pathLine + "\n")
				closeErr := f.Close()
				switch {
				case writeErr != nil:
					fmt.Printf("  ⚠ Failed to write PATH to %s: %v\n", filepath.Base(shellRC), writeErr)
				case closeErr != nil:
					fmt.Printf("  ⚠ Failed to flush %s: %v\n", filepath.Base(shellRC), closeErr)
				default:
					fmt.Printf("  ✓ Added LazyVPN to PATH in %s\n", filepath.Base(shellRC))
					// Also export for current session
					os.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
				}
			}
		} else {
			fmt.Println("  LazyVPN already in PATH")
		}
	} else {
		fmt.Println("  ⚠ Could not detect shell config file")
		fmt.Printf("  Add to your PATH manually: %s\n", pathLine)
	}

	// Step 10: Verify and install dependencies
	fmt.Println()
	fmt.Println("Step 10: Verifying dependencies...")
	deps := []struct {
		cmd string
		pkg string
	}{
		{"resolvectl", "systemd"},
		{"ufw", "ufw"},
		{"ip", "iproute2"},
	}
	var missing []string
	for _, dep := range deps {
		if _, err := exec.LookPath(dep.cmd); err != nil {
			fmt.Printf("  ⚠ Missing: %s\n", dep.cmd)
			missing = append(missing, dep.pkg)
		} else {
			fmt.Printf("  ✓ Found: %s\n", dep.cmd)
		}
	}
	if len(missing) > 0 {
		pkgs := strings.Join(missing, " ")
		fmt.Printf("\n  Missing packages: %s\n", pkgs)
		// Detect package manager
		var pkgMgrCmd string
		var pkgMgrArgs []string
		if _, err := exec.LookPath("pacman"); err == nil {
			pkgMgrCmd = "pacman"
			pkgMgrArgs = []string{"sudo", "pacman", "-S", "--noconfirm"}
		} else if _, err := exec.LookPath("apt-get"); err == nil {
			pkgMgrCmd = "apt-get"
			pkgMgrArgs = []string{"sudo", "apt-get", "install", "-y"}
		} else if _, err := exec.LookPath("dnf"); err == nil {
			pkgMgrCmd = "dnf"
			pkgMgrArgs = []string{"sudo", "dnf", "install", "-y"}
		}

		if pkgMgrCmd != "" {
			fmt.Printf("  Install now using %s? [Y/n] ", pkgMgrCmd)
			var answer string
			fmt.Scanln(&answer)
			if answer == "" || strings.ToLower(answer) == "y" {
				installCmd := exec.Command(pkgMgrArgs[0], append(pkgMgrArgs[1:], missing...)...)
				installCmd.Stdout = os.Stdout
				installCmd.Stderr = os.Stderr
				installCmd.Stdin = os.Stdin
				if err := installCmd.Run(); err != nil {
					fmt.Printf("  ⚠ Failed to install packages: %v\n", err)
				} else {
					fmt.Println("  ✓ Dependencies installed.")
				}
			}
		} else {
			fmt.Println("  No supported package manager found.")
			fmt.Printf("  Please install manually: %s\n", pkgs)
		}
	} else {
		fmt.Println("  All dependencies found.")
	}

	// Step 11: Verify color emoji font for flag glyphs.
	//
	// Country flags in the dashboard are encoded as regional indicator pairs
	// (e.g. 🇺🇸 = U+1F1FA + U+1F1F8). Without a color emoji font that
	// composes these pairs into flag glyphs, alacritty falls back to drawing
	// each indicator as its base codepoint — which renders as the bare two
	// letters "U", "S" and looks nothing like a flag. JetBrainsMono Nerd Font
	// (and other programming fonts) don't ship flag glyphs; you need a
	// dedicated color emoji font in the fontconfig fallback chain.
	fmt.Println()
	fmt.Println("Step 11: Verifying color emoji font...")
	installEmojiFont()

	// Final summary
	fmt.Println()
	fmt.Println("===================================")
	fmt.Println("Installation Complete!")
	fmt.Println("===================================")
	fmt.Println()
	fmt.Println("Getting Started (Choose ONE method):")
	fmt.Println()
	fmt.Println("OPTION A - Dynamic Server List (Recommended):")
	fmt.Println("  1. Download ONE WireGuard config from your VPN provider")
	if isHyprland {
		fmt.Println("  2. Open LazyVPN (SUPER+SHIFT+L or search 'LazyVPN' in app launcher)")
	} else {
		fmt.Println("  2. Run 'lazyvpn' or search 'LazyVPN' in your app launcher")
	}
	fmt.Println("  3. Go to Options → Setup Provider")
	fmt.Println("  4. Select your config file - LazyVPN extracts your credentials")
	fmt.Println("  5. Browse ALL servers without downloading individual configs!")
	fmt.Println()
	fmt.Println("OPTION B - Manual Config Import:")
	fmt.Println("  1. Download individual WireGuard configs from your VPN provider")
	if isHyprland {
		fmt.Println("  2. Open LazyVPN → Options → Add Manual Server")
	} else {
		fmt.Println("  2. Run 'lazyvpn' → Options → Add Manual Server")
	}
	fmt.Println("  3. Select configs to import")
	fmt.Println()
	fmt.Println("How to Launch:")
	if isHyprland {
		fmt.Println("  - SUPER+SHIFT+L       Keyboard shortcut")
	}
	if isOmarchy {
		fmt.Println("  - SUPER+ALT+SPACE     Omarchy menu → LazyVPN")
	}
	fmt.Println("  - App launcher          Search 'LazyVPN'")
	fmt.Println("  - Terminal              Run 'lazyvpn'")
	fmt.Println()

	// Offer to remove the git clone / build directory
	sourceDir := filepath.Dir(srcExecPath)
	gitDir = filepath.Join(sourceDir, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		fmt.Println("───────────────────────────────────────────────────────────")
		fmt.Println("The installation source directory can now be removed:")
		fmt.Printf("  %s\n", sourceDir)
		fmt.Println()
		fmt.Print("Remove the git clone directory? [y/N]: ")

		reader := bufio.NewReader(os.Stdin)
		removeChoice, _ := reader.ReadString('\n')
		removeChoice = strings.TrimSpace(removeChoice)

		if strings.ToLower(removeChoice) == "y" {
			fmt.Println()
			fmt.Println("Removing installation source...")
			os.Chdir(homeDir)

			// Collect all files for secure deletion
			var repoFiles []string
			filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if !info.IsDir() {
					repoFiles = append(repoFiles, path)
				}
				return nil
			})

			if len(repoFiles) > 0 {
				result := security.DeleteForFS(fsType == "btrfs")(repoFiles, security.NoSudo)
				for _, e := range result.Events {
					reportDelete(os.Stdout, e)
				}
				if result.Failed > 0 {
					fmt.Printf("  ⚠ %d file(s) failed to delete; remove %s manually if needed.\n", result.Failed, sourceDir)
				}
			}

			// Remove empty directories (depth-first)
			var dirs []string
			filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if info.IsDir() {
					dirs = append(dirs, path)
				}
				return nil
			})
			// Reverse order to delete deepest first
			for i := len(dirs) - 1; i >= 0; i-- {
				os.Remove(dirs[i])
			}
			os.RemoveAll(sourceDir) // Final cleanup

			fmt.Printf("✓ Removed: %s\n", sourceDir)
		}
	}
	fmt.Println()

	// Show completion notification (Omarchy only)
	if isOmarchy {
		exec.Command("omarchy-show-done").Run()
	}
}

// installSudoers prompts for sudo if needed and installs the sudoers file.
// Returns true on success so the caller can persist that into the config
// (cfg.SudoersInstalled), which downstream code reads as the source of truth
// — os.Stat on /etc/sudoers.d/lazyvpn fails with EACCES from non-root because
// the parent dir is 0750.
func installSudoers(execPath, connName string, cowFilesystem bool) bool {
	// Prime sudo cache so InstallSudoers (which uses sudo -n) succeeds.
	// In the installer we have a TTY, so interactive sudo prompt works.
	if !sudo.ProbeCache() {
		fmt.Println("  Sudo access needed to install sudoers file...")
		if err := exec.Command("sudo", "-v").Run(); err != nil {
			fmt.Printf("  ⚠ Failed to authenticate: %v\n", err)
			return false
		}
	}
	if err := sudo.InstallSudoers(execPath, connName, cowFilesystem); err != nil {
		fmt.Printf("  ⚠ %v\n", err)
		return false
	}
	fmt.Println("  ✓ Sudoers configuration installed")
	fmt.Printf("  VPN interface: %s\n", connName)
	physIfaces := sudo.DetectPhysicalInterfaces()
	if len(physIfaces) > 0 {
		fmt.Printf("  Physical interfaces: %s\n", strings.Join(physIfaces, ", "))
	}
	fmt.Println("  VPN operations will not require password")
	return true
}

// isExistingInterface checks if a name matches an existing network interface.
func isExistingInterface(name string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return true
		}
	}
	return false
}

// setCapabilities sets CAP_NET_ADMIN and CAP_NET_RAW on the lazyvpn binary.
// This enables native netlink operations and ICMP ping without sudo.
// Called regardless of whether the user installs the sudoers file.
func setCapabilities(execPath string) {
	fmt.Println("  Setting network capabilities on binary...")
	if !sudo.ProbeCache() {
		fmt.Println("  Sudo access needed to set file capabilities...")
		if err := exec.Command("sudo", "-v").Run(); err != nil {
			fmt.Println("  ⚠ Failed to authenticate — VPN operations may require sudo")
			return
		}
	}
	if err := sudo.SetCapabilities(execPath); err != nil {
		fmt.Println("  ⚠ Failed to set capabilities — VPN operations may require sudo")
	} else {
		fmt.Println("  ✓ Network capabilities set (NET_ADMIN + NET_RAW)")
	}
}

func runUninstall() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}
	configDir := filepath.Join(homeDir, ".config/lazyvpn")
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=======================================")
	fmt.Println("  LazyVPN Uninstaller")
	fmt.Println("=======================================")
	fmt.Println()

	// Load config and detect system
	cfg, _ := config.Load()
	connName := "wg0"
	isOmarchy := false
	cowFS := false
	if cfg != nil {
		connName = cfg.ConnectionName
		isOmarchy = cfg.IsOmarchy()
		cowFS = cfg.IsCOWFilesystem()
	}
	// If config doesn't have distro info, detect at uninstall time
	if !isOmarchy {
		isOmarchy = config.DetectDistro() == "omarchy"
	}
	if !cowFS {
		cowFS = config.DetectFSType(homeDir) == "btrfs"
	}
	_, hyprErr := exec.LookPath("hyprctl")
	isHyprland := hyprErr == nil
	_, waybarErr := exec.LookPath("waybar")
	isWaybar := waybarErr == nil

	// Delete-pipeline context: drives shred-vs-rm choice per FS, per-file
	// rendering, interactive retry prompts, and the final summary banner.
	deleteCtx := newDeleteContext(cowFS)
	primaryFn := security.DeleteForFS(cowFS)
	gs := newGlobalSummary(deleteCtx)

	// Step 0: Check for active VPN connection
	fmt.Println("Checking for active VPN connection...")
	if cfg != nil && wireguard.IsConnected(connName) {
		fmt.Println()
		fmt.Println("⚠️  WARNING: VPN connection is currently ACTIVE!")
		fmt.Println()
		fmt.Println("You are currently connected to a VPN server.")
		fmt.Println("If you uninstall while connected, you may experience:")
		fmt.Println("  • Loss of internet connectivity")
		fmt.Println("  • Difficulty disconnecting from the VPN")
		fmt.Println("  • Network routing issues")
		fmt.Println()
		fmt.Print("Disconnect from VPN before uninstalling? [Y/n] ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		if choice == "" || strings.ToLower(choice) == "y" {
			fmt.Println()
			fmt.Println("Disconnecting from VPN...")
			if err := wireguard.Disconnect(cfg); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ Disconnect error: %v\n", err)
				fmt.Println("  Proceeding with uninstall anyway (manual cleanup may be needed)")
			} else {
				fmt.Println("  ✓ Disconnected successfully")
			}
		} else {
			fmt.Println()
			fmt.Println("⚠️  Proceeding with uninstall while VPN is connected.")
		}
	} else {
		fmt.Println("  - No active VPN connection detected.")
	}
	fmt.Println()

	// Step 0b: Ask about WireGuard configs.
	// Two state bits, not one:
	//   - deleteConfigs:    user explicitly said yes → delete the .conf files
	//   - preservedConfigs: user explicitly said no  → keep the dir & its contents
	// A third case (no prompt fired because wireguard/ is empty) leaves both
	// false, which means "no WG configs to deal with — go ahead and tear down
	// configDir at end of Step 9". Without this distinction the empty-dir case
	// would survive uninstall and require a manual rm -rf.
	wgConfigDir := filepath.Join(configDir, "wireguard")
	deleteConfigs := false
	preservedConfigs := false
	if entries, err := os.ReadDir(wgConfigDir); err == nil && len(entries) > 0 {
		fmt.Println("Your WireGuard server configurations are stored in:")
		fmt.Println(wgConfigDir)
		fmt.Println()
		fmt.Println("The following WireGuard config files were found:")
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				fmt.Printf("  - %s\n", e.Name())
			}
		}
		fmt.Println()
		fmt.Print("Delete these .conf files? (Contains private keys) [y/N] ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		deleteConfigs = strings.ToLower(choice) == "y"
		preservedConfigs = !deleteConfigs
		if deleteConfigs {
			fmt.Println("-> WireGuard configs will be deleted.")
		} else {
			fmt.Println("-> WireGuard configs will be kept.")
		}
	} else {
		fmt.Println("No WireGuard config files found.")
	}
	fmt.Println()

	// Step 1: Clean up firewall rules
	fmt.Println("Step 1: Cleaning up firewall rules...")

	// Track failures so the user is warned if cleanup didn't complete.
	// Killswitch in particular CAN'T be left on by accident — that would
	// leave the user with no internet after a "successful" uninstall.
	var firewallErrs []string
	if firewall.IsActive() {
		fmt.Println("  - Found active killswitch. Disabling...")
		if err := firewall.Disable(); err != nil {
			fmt.Fprintf(os.Stderr, "    ⚠ Killswitch disable FAILED: %v\n", err)
			firewallErrs = append(firewallErrs, fmt.Sprintf("killswitch: %v", err))
		} else {
			fmt.Println("    - Killswitch disabled")
		}
	}
	if firewall.IsLANBlockActive() {
		fmt.Println("  - Found active LAN block. Removing...")
		if err := firewall.DisableLANBlock(); err != nil {
			fmt.Fprintf(os.Stderr, "    ⚠ LAN block disable FAILED: %v\n", err)
			firewallErrs = append(firewallErrs, fmt.Sprintf("LAN block: %v", err))
		} else {
			fmt.Println("    - LAN block removed")
		}
	}
	if firewall.IsLANStealthActive() {
		fmt.Println("  - Found active LAN stealth. Removing...")
		if err := firewall.DisableLANStealth(); err != nil {
			fmt.Fprintf(os.Stderr, "    ⚠ LAN stealth disable FAILED: %v\n", err)
			firewallErrs = append(firewallErrs, fmt.Sprintf("LAN stealth: %v", err))
		} else {
			fmt.Println("    - LAN stealth removed")
		}
	}
	// Remove all LazyVPN rules and restore safe defaults
	if err := firewall.Teardown(); err != nil {
		fmt.Fprintf(os.Stderr, "    ⚠ Teardown FAILED: %v\n", err)
		firewallErrs = append(firewallErrs, fmt.Sprintf("teardown: %v", err))
	}
	// Reset UFW logging to default
	if firewall.GetLoggingLevel() != "off" {
		fmt.Println("  - Resetting UFW logging to off...")
		if err := firewall.SetLogging("off"); err != nil {
			fmt.Fprintf(os.Stderr, "    ⚠ UFW logging reset FAILED: %v\n", err)
			firewallErrs = append(firewallErrs, fmt.Sprintf("UFW logging: %v", err))
		} else {
			fmt.Println("    - UFW logging disabled")
		}
	}
	if len(firewallErrs) > 0 {
		fmt.Fprintf(os.Stderr, "  ⚠ Firewall cleanup completed with errors. You may need to manually run 'sudo ufw default allow outgoing' to restore internet access.\n")
	} else {
		fmt.Println("  ✓ Firewall cleanup complete.")
	}

	// Re-enable IPv6 if it was disabled
	if _, err := os.Stat("/etc/sysctl.d/99-lazyvpn-ipv6.conf"); err == nil {
		fmt.Println("  - Re-enabling IPv6...")
		ipv6Err := firewall.EnableIPv6()
		if ipv6Err != nil {
			fmt.Fprintf(os.Stderr, "    ⚠ IPv6 re-enable FAILED: %v\n", ipv6Err)
		}
		runDeleteStep(os.Stdout, reader,
			[]string{"/etc/sysctl.d/99-lazyvpn-ipv6.conf"},
			primaryFn, security.SudoSilent, deleteCtx, gs)
		if ipv6Err == nil {
			fmt.Println("    - IPv6 re-enabled")
		}
	}

	fmt.Println()

	// Step 2: Stop daemon. Verify the PID in the pidfile actually points
	// to our binary before sending SIGTERM — otherwise a recycled PID
	// (daemon crashed, kernel reused the number for an unrelated process)
	// would get signaled here, which would be actively harmful.
	fmt.Println("Step 2: Stopping connection daemon...")
	pidFile := filepath.Join(configDir, ".daemon.pid")
	if data, err := os.ReadFile(pidFile); err == nil {
		pidStr := strings.TrimSpace(string(data))
		pid, atoiErr := strconv.Atoi(pidStr)
		switch {
		case atoiErr != nil || pid <= 0:
			fmt.Println("  - Invalid PID file, skipping kill")
		case !daemon.IsLazyvpnPid(pid):
			// Either the PID no longer exists (stale file) or it's
			// been recycled to an unrelated process. Don't signal.
			fmt.Printf("  - Stale PID file (PID %d is not lazyvpn), skipping kill\n", pid)
		default:
			proc, findErr := os.FindProcess(pid)
			if findErr != nil {
				fmt.Printf("  - Could not find daemon process %d: %v\n", pid, findErr)
			} else if err := proc.Signal(syscall.SIGTERM); err != nil {
				fmt.Printf("  - SIGTERM to daemon (PID %d) failed: %v\n", pid, err)
			} else {
				// Wait for the daemon to actually exit before continuing.
				// Its signal handler runs ForceDisconnect → cfg.Save(), which
				// races Step 9's config.json delete; if Save lands after the
				// delete, the file is recreated and uninstall finishes with a
				// stale config. Poll up to 10s, then SIGKILL as a backstop.
				exited := false
				for i := 0; i < 100; i++ {
					time.Sleep(100 * time.Millisecond)
					if proc.Signal(syscall.Signal(0)) != nil {
						exited = true
						break
					}
				}
				if exited {
					fmt.Printf("  - Stopped daemon (PID: %d)\n", pid)
				} else {
					fmt.Printf("  - Daemon (PID %d) did not exit within 10s, SIGKILL\n", pid)
					proc.Signal(syscall.SIGKILL)
					time.Sleep(500 * time.Millisecond)
				}
			}
		}
	} else {
		// No PID file. Try a broad pkill in case a daemon is running without
		// having recorded its PID (older install, manual launch). pkill is
		// best-effort; we still wait briefly so any signal handler that calls
		// cfg.Save() finishes before Step 9 deletes config.json.
		if err := exec.Command("pkill", "-f", "lazyvpn daemon").Run(); err == nil {
			fmt.Println("  - Stopped stray daemon process(es) via pkill")
			time.Sleep(2 * time.Second)
		} else {
			fmt.Println("  - Connection daemon not running")
		}
	}
	fmt.Println()

	// Step 3: Remove Omarchy menu integration (Omarchy only)
	if !isOmarchy {
		fmt.Println("Step 3: Skipping Omarchy menu cleanup (not Omarchy)")
	} else {
		fmt.Println("Step 3: Removing LazyVPN integration from omarchy-menu...")
		omarchyMenuFile := filepath.Join(homeDir, ".local/share/omarchy/bin/omarchy-menu")
		backupFile := omarchyMenuFile + ".backup"
		if _, err := os.Stat(backupFile); err == nil {
			if err := os.Rename(backupFile, omarchyMenuFile); err != nil {
				fmt.Printf("  ⚠ Failed to restore omarchy-menu from backup: %v\n", err)
				fmt.Printf("    Backup file remains at: %s\n", backupFile)
			} else {
				if err := os.Chmod(omarchyMenuFile, 0755); err != nil {
					fmt.Printf("  ⚠ Restored omarchy-menu but chmod 0755 failed: %v\n", err)
				} else {
					fmt.Println("  - Restored omarchy-menu from backup")
				}
				exec.Command("omarchy-restart-walker").Start()
			}
		} else if content, err := os.ReadFile(omarchyMenuFile); err == nil {
			if strings.Contains(string(content), "LazyVPN") {
				fmt.Println("  - LazyVPN found in menu but no backup available")
				fmt.Println("    You may need to reinstall Omarchy to restore the menu")
			}
		}
	}
	fmt.Println()

	// Step 4: Remove keyboard shortcut and window rules
	if !isHyprland {
		fmt.Println("Step 4: Skipping Hyprland cleanup (Hyprland not detected)")
	} else {
		fmt.Println("Step 4: Removing keyboard shortcut...")
		hyprBindings := filepath.Join(homeDir, ".config/hypr/bindings.conf")
		if content, err := os.ReadFile(hyprBindings); err == nil {
			if strings.Contains(string(content), "LazyVPN") {
				cleaned := removeLazyvpnFromHyprBindings(string(content))
				if err := writeFileAtomic(hyprBindings, []byte(cleaned), 0644); err != nil {
					fmt.Printf("  ⚠ Failed to remove keybinding from Hyprland config: %v\n", err)
				} else {
					fmt.Println("  - Removed LazyVPN keybinding from Hyprland")
				}
			} else {
				fmt.Println("  - No LazyVPN keybinding found in Hyprland config")
			}
		}

		// Remove LazyVPN window rules from hyprland.conf
		hyprlandConf := filepath.Join(homeDir, ".config/hypr/hyprland.conf")
		if content, err := os.ReadFile(hyprlandConf); err == nil {
			s := string(content)
			if strings.Contains(s, "lazyvpn") || strings.Contains(s, "LazyVPN") {
				cleaned := removeLazyvpnFromHyprlandConf(s)
				// Atomic write: a crash mid-uninstall would otherwise leave
				// hyprland.conf truncated and break the user's WM on next login.
				if err := writeFileAtomic(hyprlandConf, []byte(cleaned), 0644); err != nil {
					fmt.Printf("  ⚠ Failed to remove window rules from hyprland.conf: %v\n", err)
				} else {
					fmt.Println("  - Removed LazyVPN window rules from Hyprland config")
				}
			}
		}

		hyprctlReload()
		fmt.Println("  - Reloaded Hyprland configuration")

		// Clean up keybindings helper (Omarchy-specific)
		if isOmarchy {
			keybindingsScript := filepath.Join(homeDir, ".local/share/omarchy/bin/omarchy-menu-keybindings")
			if content, err := os.ReadFile(keybindingsScript); err == nil {
				if strings.Contains(string(content), "LazyVPN") {
					cleaned := removeLazyvpnFromKeybindings(string(content))
					if err := writeFileAtomic(keybindingsScript, []byte(cleaned), 0755); err != nil {
						fmt.Printf("  ⚠ Failed to remove from keybindings helper: %v\n", err)
					} else {
						fmt.Println("  - Removed from keybindings helper")
					}
				}
			}
		}
	} // end isHyprland step 4
	fmt.Println()

	// Step 5: Remove Waybar integration
	if !isWaybar {
		fmt.Println("Step 5: Skipping Waybar cleanup (Waybar not detected)")
	} else {
		fmt.Println("Step 5: Removing Waybar integration...")
		waybarConfig := filepath.Join(homeDir, ".config/waybar/config.jsonc")
		if content, err := os.ReadFile(waybarConfig); err == nil {
			if strings.Contains(string(content), "custom/lazyvpn") {
				newContent := removeWaybarLazyvpnModule(string(content))
				if err := writeFileAtomic(waybarConfig, []byte(newContent), 0644); err != nil {
					fmt.Printf("  ⚠ Failed to write waybar config: %v\n", err)
				} else {
					fmt.Println("  - Removed custom/lazyvpn from Waybar config")
					exec.Command("pkill", "-SIGUSR2", "waybar").Run()
					fmt.Println("  - Sent reload signal to Waybar")
				}
			} else {
				fmt.Println("  - No LazyVPN integration found in Waybar config")
			}
		}

		waybarStyle := filepath.Join(homeDir, ".config/waybar/style.css")
		if content, err := os.ReadFile(waybarStyle); err == nil {
			s := string(content)
			if strings.Contains(s, "#custom-lazyvpn") {
				// Remove all LazyVPN CSS from comment marker through @keyframes block
				if idx := strings.Index(s, "/* LazyVPN status indicator */"); idx >= 0 {
					end := len(s)
					// Find the @keyframes lazyvpn-blink block and its closing brace
					if kfIdx := strings.Index(s[idx:], "@keyframes lazyvpn-blink"); kfIdx >= 0 {
						abs := idx + kfIdx
						depth := 0
						for i := abs; i < len(s); i++ {
							if s[i] == '{' {
								depth++
							}
							if s[i] == '}' {
								depth--
								if depth == 0 {
									end = i + 1
									// Consume trailing newline
									if end < len(s) && s[end] == '\n' {
										end++
									}
									break
								}
							}
						}
					}
					s = s[:idx] + s[end:]
				} else {
					// No comment marker — remove individual rules by selector
					for _, sel := range []string{
						"#custom-lazyvpn {", "#custom-lazyvpn.connected {",
						"#custom-lazyvpn.connecting {", "#custom-lazyvpn.disconnected {",
						"#custom-lazyvpn.ks-blocking {", "#custom-lazyvpn.error {",
						"@keyframes lazyvpn-blink {",
					} {
						if start := strings.Index(s, sel); start >= 0 {
							depth := 0
							for i := start; i < len(s); i++ {
								if s[i] == '{' {
									depth++
								}
								if s[i] == '}' {
									depth--
									if depth == 0 {
										end := i + 1
										if end < len(s) && s[end] == '\n' {
											end++
										}
										s = s[:start] + s[end:]
										break
									}
								}
							}
						}
					}
				}
				if err := writeFileAtomic(waybarStyle, []byte(s), 0644); err != nil {
					fmt.Printf("  ⚠ Failed to write waybar style: %v\n", err)
				} else {
					fmt.Println("  - Removed LazyVPN styling from Waybar CSS")
				}
			}
		}
	} // end isWaybar step 5
	fmt.Println()

	// Step 6: Remove from PATH
	fmt.Println("Step 6: Removing LazyVPN from PATH...")
	shellRCs := []string{
		filepath.Join(homeDir, ".bashrc"),
		filepath.Join(homeDir, ".zshrc"),
	}
	for _, rc := range shellRCs {
		if content, err := os.ReadFile(rc); err == nil {
			if strings.Contains(string(content), "# LazyVPN") {
				cleaned := removeLazyvpnFromShellRC(string(content))
				if err := writeFileAtomic(rc, []byte(cleaned), 0644); err != nil {
					fmt.Printf("  ⚠ Failed to remove from PATH in %s: %v\n", filepath.Base(rc), err)
				} else {
					fmt.Printf("  - Removed LazyVPN from PATH in %s\n", filepath.Base(rc))
				}
			}
		}
	}
	fmt.Println()

	// Step 7: Remove autostart and launcher entries.
	// Autostart entry is conditional (only written when the user enables
	// Autostart in settings), so absence is normal — gate with os.Stat and
	// print a positive "no entry found" line rather than letting
	// runDeleteStep emit a NotPresent event that reads like an error.
	// The parent dir ~/.config/autostart/ is user-owned so stat is reliable.
	fmt.Println("Step 7: Removing Autostart and launcher entries...")
	autostartFile := filepath.Join(homeDir, ".config/autostart/lazyvpn.desktop")
	if _, err := os.Stat(autostartFile); err != nil {
		fmt.Println("  - No autostart entry found.")
	} else {
		runDeleteStep(os.Stdout, reader, []string{autostartFile},
			primaryFn, security.NoSudo, deleteCtx, gs)
	}
	desktopFile := filepath.Join(homeDir, ".local", "share", "applications", "lazyvpn.desktop")
	if _, err := os.Stat(desktopFile); err == nil {
		os.Remove(desktopFile)
		fmt.Println("  - Removed application launcher entry")
	}
	fmt.Println()

	// Step 8: Debug log handling. Self-contained — stat, decide, maybe ask,
	// maybe delete. If the file isn't there we say so and move on; if it is,
	// the user gets a size-and-path confirmation with delete as the default.
	fmt.Println("Step 8: Debug log cleanup...")
	debugLogFile := filepath.Join(configDir, "debug.log")
	if info, err := os.Stat(debugLogFile); err != nil {
		fmt.Println("  - No debug log found.")
	} else {
		fmt.Printf("  Debug log found (%d bytes): %s\n", info.Size(), debugLogFile)
		fmt.Print("  Delete debug log? [Y/n] ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))
		if choice == "n" {
			fmt.Println("  - Keeping debug log.")
		} else {
			runDeleteStep(os.Stdout, reader, []string{debugLogFile},
				primaryFn, security.NoSudo, deleteCtx, gs)
		}
	}
	fmt.Println()

	// Step 9: Optional journal cleanup. Log destruction deliberately has no
	// NOPASSWD entry (sudoers policy), so SudoInteractive upfront — skip the
	// noisy silent-first → prompt-on-failure cascade.
	//
	// MUST run before sudoers removal (Step 10): CleanJournalLogs uses
	// `sudo -n systemctl stop systemd-journald`, which depends on the
	// NOPASSWD entry that Step 10 deletes.
	fmt.Println("Step 9: System log cleanup (optional)...")
	fmt.Println("  Systemd journal files may contain VPN connection events.")
	fmt.Println("  Cleaning them requires stopping journald and your sudo password.")
	fmt.Print("  Scan and clean journal files? [Y/n] ")
	jchoice, _ := reader.ReadString('\n')
	jchoice = strings.TrimSpace(strings.ToLower(jchoice))
	if jchoice == "" || jchoice == "y" || jchoice == "yes" {
		jres, jerr := security.CleanJournalLogs(connName, primaryFn, security.SudoInteractive)
		if jerr != nil {
			fmt.Printf("  ✗ Journal cleanup: %v\n", jerr)
		} else if jres.WithEvidence > 0 {
			resolveAndMerge(os.Stdout, reader, jres.Delete, deleteCtx, gs)
		}
	} else {
		fmt.Println("  - Skipped journal cleanup.")
	}
	fmt.Println()

	// Step 10: Remove sudoers (must run AFTER journal cleanup — see Step 9).
	// /etc/sudoers.d/ is 0750 root:root on Arch/modern systemd so we can't
	// os.Stat to check existence from a non-root user. Instead we rely on
	// cfg.SudoersInstalled, which is set true at install time iff the user
	// opted into the sudoers file. If they declined, there's nothing to
	// remove and we skip cleanly; if they opted in, NotPresent at this point
	// would be an anomaly worth surfacing (Category A).
	fmt.Println("Step 10: Removing sudoers configuration...")
	if cfg != nil && cfg.SudoersInstalled {
		runDeleteStep(os.Stdout, reader,
			[]string{"/etc/sudoers.d/lazyvpn"},
			primaryFn, security.SudoSilent, deleteCtx, gs)
	} else {
		fmt.Println("  - Sudoers was not installed.")
	}
	fmt.Println()

	// Step 11: Clean shell history
	fmt.Println("Step 11: Cleaning shell history...")
	security.CleanShellHistory(connName)
	fmt.Println()

	// Step 12: Remove installation directory (bash scripts / git clone)
	fmt.Println("Step 12: Removing LazyVPN installation directory...")
	lazyvpnShare := filepath.Join(homeDir, ".local/share/lazyvpn")
	if _, err := os.Stat(lazyvpnShare); err == nil {
		// Collect all files in the installation directory
		var installFiles []string
		filepath.Walk(lazyvpnShare, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				installFiles = append(installFiles, path)
			}
			return nil
		})

		if len(installFiles) > 0 {
			fmt.Printf("  Found installation directory: %s\n", lazyvpnShare)
			fmt.Printf("  Contains %d file(s)\n", len(installFiles))
			fmt.Print("  Delete installation directory? [Y/n] ")
			choice, _ := reader.ReadString('\n')
			choice = strings.TrimSpace(choice)
			if choice == "" || strings.ToLower(choice) == "y" {
				fmt.Println("  - Deleting installation files...")
				runDeleteStep(os.Stdout, reader, installFiles,
					primaryFn, security.NoSudo, deleteCtx, gs)
				// Remove empty directories
				filepath.Walk(lazyvpnShare, func(path string, info os.FileInfo, err error) error {
					if err == nil && info.IsDir() {
						os.Remove(path) // Will only succeed if empty
					}
					return nil
				})
				os.RemoveAll(lazyvpnShare) // Final cleanup
				fmt.Println("  ✓ Installation directory removed")
			} else {
				fmt.Println("  - Installation directory preserved")
			}
		}
	} else {
		fmt.Println("  - No installation directory found")
	}
	fmt.Println()

	// Step 13: Offer to remove the git clone source directory
	fmt.Println("Step 13: Remove git clone source directory...")
	if cfg != nil && cfg.InstallSourceDir != "" {
		if _, err := os.Stat(cfg.InstallSourceDir); err == nil {
			// Verify it's actually a git clone
			gitDir := filepath.Join(cfg.InstallSourceDir, ".git")
			if _, err := os.Stat(gitDir); err == nil {
				fmt.Printf("  Install source directory: %s\n", cfg.InstallSourceDir)
				fmt.Print("  Delete git clone directory? [y/N] ")
				choice, _ := reader.ReadString('\n')
				choice = strings.TrimSpace(choice)
				if strings.ToLower(choice) == "y" {
					fmt.Println("  - Removing git clone directory...")
					var sourceFiles []string
					filepath.Walk(cfg.InstallSourceDir, func(path string, info os.FileInfo, err error) error {
						if err == nil && !info.IsDir() {
							sourceFiles = append(sourceFiles, path)
						}
						return nil
					})
					runDeleteStep(os.Stdout, reader, sourceFiles,
						primaryFn, security.NoSudo, deleteCtx, gs)
					os.RemoveAll(cfg.InstallSourceDir)
					fmt.Println("  ✓ Git clone directory removed")
				} else {
					fmt.Println("  - Git clone directory preserved")
				}
			} else {
				fmt.Println("  - Source directory no longer exists or is not a git clone")
			}
		} else {
			fmt.Println("  - Source directory no longer exists")
		}
	} else {
		fmt.Println("  - No source directory recorded")
	}
	fmt.Println()

	// Step 14: Remove the installed binary
	fmt.Println("Step 14: Removing installed binary...")
	installedBinary := filepath.Join(homeDir, ".local", "bin", "lazyvpn")
	runDeleteStep(os.Stdout, reader, []string{installedBinary},
		primaryFn, security.NoSudo, deleteCtx, gs)
	fmt.Println()

	// Step 15: Snapshot awareness. Only shown when the filesystem actually
	// has snapshot base dirs on disk — CoW alone isn't enough; the user may
	// not run snapper, or no snapshot history exists yet. Skipping the step
	// entirely (no header, no prompt) when there's nothing to scan keeps
	// the uninstall output focused.
	if cowFS && hasSnapshotDirs() {
		fmt.Println("Step 15: Checking for filesystem snapshots...")
		checkSnapperSnapshots(reader)
		fmt.Println()
	}

	// Step 16: Remove config files. Runs LAST so that anything earlier in the
	// uninstall (notably the daemon's signal handler at Step 2, which calls
	// cfg.Save() during ForceDisconnect) can't race the delete and re-create
	// config.json after the fact. By this point the daemon is dead, the TUI
	// is long gone, and no remaining step writes to ~/.config/lazyvpn/.
	//
	// config.json is unconditional (always written at install) — Category A,
	// a genuine absence here signals an anomaly and NotPresent is informative.
	// The daemon runtime files are conditional (present only while the daemon
	// is running), so we include them only when actually present to avoid
	// benign NotPresent noise in the summary.
	fmt.Println("Step 16: Removing LazyVPN configuration files...")
	if _, err := os.Stat(configDir); err == nil {
		sensitiveFiles := []string{
			filepath.Join(configDir, "config.json"),
		}
		for _, name := range []string{".daemon.pid", ".daemon.sock"} {
			p := filepath.Join(configDir, name)
			if _, err := os.Stat(p); err == nil {
				sensitiveFiles = append(sensitiveFiles, p)
			}
		}
		fmt.Println("  - Deleting LazyVPN config and cache files...")
		runDeleteStep(os.Stdout, reader, sensitiveFiles,
			primaryFn, security.NoSudo, deleteCtx, gs)

		// Provider credentials
		providersDir := filepath.Join(configDir, "providers")
		if entries, err := os.ReadDir(providersDir); err == nil && len(entries) > 0 {
			fmt.Println("  - Deleting provider credentials (contain private keys)...")
			var providerFiles []string
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".conf") || strings.HasSuffix(e.Name(), ".json") {
					providerFiles = append(providerFiles, filepath.Join(providersDir, e.Name()))
				}
			}
			runDeleteStep(os.Stdout, reader, providerFiles,
				primaryFn, security.NoSudo, deleteCtx, gs)
			os.Remove(providersDir)
		}

		// Server cache
		cacheDir := filepath.Join(configDir, "cache")
		if entries, err := os.ReadDir(cacheDir); err == nil && len(entries) > 0 {
			fmt.Println("  - Deleting server cache...")
			var cacheFiles []string
			for _, e := range entries {
				cacheFiles = append(cacheFiles, filepath.Join(cacheDir, e.Name()))
			}
			runDeleteStep(os.Stdout, reader, cacheFiles,
				primaryFn, security.NoSudo, deleteCtx, gs)
			os.Remove(cacheDir)
		}

		// WireGuard configs (opt-in delete — separate from the tear-down
		// logic so "empty wireguard/" still cleans up configDir).
		if deleteConfigs {
			if entries, err := os.ReadDir(wgConfigDir); err == nil && len(entries) > 0 {
				fmt.Println("  - Deleting WireGuard server configs...")
				var wgFiles []string
				for _, e := range entries {
					if strings.HasSuffix(e.Name(), ".conf") {
						wgFiles = append(wgFiles, filepath.Join(wgConfigDir, e.Name()))
					}
				}
				runDeleteStep(os.Stdout, reader, wgFiles,
					primaryFn, security.NoSudo, deleteCtx, gs)
			}
		}

		// Sweep LazyVPN atomic-write orphans (config.Save uses .config.tmp.*,
		// the logger uses .log.tmp.*) regardless of whether we're keeping
		// the wireguard/ tree. Otherwise these orphan files linger in the
		// preserved configDir forever after a crash mid-rename.
		if matches, err := filepath.Glob(filepath.Join(configDir, ".*.tmp.*")); err == nil {
			for _, m := range matches {
				os.Remove(m)
			}
		}

		// Tear-down: remove empty subdirs and the configDir itself, unless
		// the user asked us to preserve the wireguard/ tree. os.Remove on a
		// directory only succeeds when it's empty — so this is safe; it
		// won't silently nuke unexpected leftovers.
		if preservedConfigs {
			fmt.Printf("  - Preserved WireGuard server configs in: %s\n", wgConfigDir)
		} else {
			for _, sub := range []string{"providers", "cache", "wireguard"} {
				os.Remove(filepath.Join(configDir, sub))
			}
			os.Remove(configDir)
			if _, err := os.Stat(configDir); os.IsNotExist(err) {
				fmt.Println("  - Removed configuration directory")
			}
		}
	}
	fmt.Println()

	// Deletion summary banner — always rendered before the outro so the user
	// can see which files used which tool, which fell back, and which were
	// skipped (bug-worthy lists included for easy copy-paste).
	gs.render(os.Stdout)
	fmt.Println()

	fmt.Println("=======================================")
	fmt.Println("  Uninstallation Complete")
	fmt.Println("=======================================")
	fmt.Println("LazyVPN has been removed from your system.")
	fmt.Println("Thank you for using LazyVPN!")
}

// checkSnapperSnapshots asks the user whether to scan CoW snapshots for
// LazyVPN artifacts and, if so, offers to purge the snapshots that match.
//
// Implementation note: snapshot base dirs (/.snapshots, /home/.snapshots)
// are typically 0750 root:root, so user-level os.Stat/os.ReadDir fails with
// EACCES and can't tell "exists-and-empty" from "no-access". The scan uses
// `sudo find` to bypass that — same attempt-with-a-privileged-tool pattern
// that replaced os.Stat for /etc/sudoers.d/lazyvpn.
//
// Runs AFTER Step 11 (sudoers removal), so there's no NOPASSWD shortcut —
// sudo prompts interactively. Sudo caches the timestamp, so the prompt fires
// once per ~5 minutes and subsequent `sudo snapper delete` calls reuse it.
func checkSnapperSnapshots(reader *bufio.Reader) {
	fmt.Println("  Filesystem snapshots (btrfs/snapper) retain copies of files as")
	fmt.Println("  they existed at snapshot time. LazyVPN data from before uninstall")
	fmt.Println("  persists in older snapshots until those snapshots are deleted.")
	fmt.Println()
	fmt.Print("  Scan snapshots for LazyVPN data? [Y/n] ")
	choice, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(choice)) == "n" {
		fmt.Println("  - Skipped snapshot scan.")
		return
	}

	configBases := snapperSnapshotBases()
	if len(configBases) == 0 {
		fmt.Println("  - No snapper configurations found.")
		return
	}
	var searchDirs []string
	for _, base := range configBases {
		searchDirs = append(searchDirs, base)
	}

	fmt.Println("  - Scanning snapshots (requires sudo)...")
	args := append([]string{"find"}, searchDirs...)
	args = append(args, "-iname", "*lazyvpn*", "-print")
	cmd := exec.Command("sudo", args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Printf("  ✗ Snapshot scan failed: %v\n", err)
		return
	}

	hits := groupSnapshotHits(stdout.String(), configBases)
	total := 0
	for _, nums := range hits {
		total += len(nums)
	}
	if total == 0 {
		fmt.Println("  - No LazyVPN data found in snapshots.")
		return
	}

	fmt.Println()
	fmt.Printf("  ⚠ Found LazyVPN data in %d snapshot(s):\n", total)
	for cfg, nums := range hits {
		fmt.Printf("    - %s: %s\n", cfg, strings.Join(sortedNums(nums), ", "))
	}
	fmt.Println()
	fmt.Print("  Delete these snapshots? [y/N] ")
	choice, _ = reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(choice)) != "y" {
		fmt.Println("  - Kept snapshots. LazyVPN data persists until they're deleted.")
		return
	}

	for cfg, nums := range hits {
		for _, num := range sortedNums(nums) {
			del := exec.Command("sudo", "snapper", "-c", cfg, "delete", num)
			del.Stderr = os.Stderr
			del.Stdin = os.Stdin
			if err := del.Run(); err != nil {
				fmt.Printf("  ✗ %s/%s: %v\n", cfg, num, err)
			} else {
				fmt.Printf("  ✓ Deleted %s/%s\n", cfg, num)
			}
		}
	}
}

// hasSnapshotDirs returns true iff any of the snapper-configured snapshot
// base dirs exist on disk. Used to skip Step 16 entirely when the FS has
// no snapshot history to audit. os.Stat on a 0750 root:root dir succeeds
// from any user because stat only needs exec on parents (not on the target
// itself), so this works without sudo.
func hasSnapshotDirs() bool {
	bases := snapperSnapshotBases()
	for _, base := range bases {
		if info, err := os.Stat(base); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

// snapperSnapshotBases queries `snapper list-configs` for the (config,
// subvolume) map and returns config → snapshot-base-dir. Snapper's base
// dir is the subvolume's `.snapshots` subdirectory.
func snapperSnapshotBases() map[string]string {
	out, err := exec.Command("snapper", "list-configs", "--columns", "config,subvolume").Output()
	if err != nil {
		return nil
	}
	result := make(map[string]string)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i, line := range lines {
		if i < 2 { // skip header + separator
			continue
		}
		// snapper renders the table with box-drawing pipes between columns
		// (`config │ subvolume`), so drop any single-char separator tokens
		// before reading positional fields.
		fields := strings.Fields(line)
		// Use a fresh slice rather than fields[:0] — the latter aliases
		// the same backing array and the appends would write into
		// `fields`'s memory. Today this happens to be harmless because
		// each append slot was already occupied by the `fields` value
		// being read, but it's a fragile invariant: any future change
		// (e.g. a multi-pass filter) would silently corrupt.
		clean := make([]string, 0, len(fields))
		for _, f := range fields {
			if f == "│" || f == "|" {
				continue
			}
			clean = append(clean, f)
		}
		if len(clean) < 2 {
			continue
		}
		cfg, subvol := clean[0], clean[1]
		result[cfg] = filepath.Join(subvol, ".snapshots")
	}
	return result
}

// groupSnapshotHits parses `find` output into config → set-of-snapshot-numbers.
// Each hit has the form <base>/<num>/snapshot/<path-inside>; we match the
// longest base prefix and extract <num> as the first path segment after it.
func groupSnapshotHits(findOutput string, configBases map[string]string) map[string]map[string]bool {
	hits := make(map[string]map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(findOutput), "\n") {
		if line == "" {
			continue
		}
		var bestCfg, bestBase string
		for cfg, base := range configBases {
			if strings.HasPrefix(line, base+"/") && len(base) > len(bestBase) {
				bestCfg, bestBase = cfg, base
			}
		}
		if bestCfg == "" {
			continue
		}
		rest := strings.TrimPrefix(line, bestBase+"/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) == 0 || parts[0] == "" {
			continue
		}
		if hits[bestCfg] == nil {
			hits[bestCfg] = make(map[string]bool)
		}
		hits[bestCfg][parts[0]] = true
	}
	return hits
}

// sortedNums returns the keys of a set as a numerically-sorted slice (falls
// back to lexical sort for non-numeric keys, which shouldn't occur for
// snapper snapshot numbers but keeps the function total).
func sortedNums(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		ni, errI := strconv.Atoi(out[i])
		nj, errJ := strconv.Atoi(out[j])
		if errI == nil && errJ == nil {
			return ni < nj
		}
		return out[i] < out[j]
	})
	return out
}

// providerDisplayMap maps provider IDs to display names for waybar tooltip
var providerDisplayMap = map[string]string{
	"protonvpn":  "ProtonVPN",
	"mullvad":    "Mullvad",
	"ivpn":       "IVPN",
	"airvpn":     "AirVPN",
	"nordvpn":    "NordVPN",
	"surfshark":  "Surfshark",
	"windscribe": "Windscribe",
	"fastestvpn": "FastestVPN",
}

func runWaybar() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Println("{}")
		return
	}

	connected := wireguard.IsConnected(cfg.ConnectionName)
	ksActive := firewall.IsActive()

	// Query daemon state if running. Use a tight dial timeout — waybar
	// re-runs us every 2s and the default 5s would let stalled invocations
	// pile up if the daemon is wedged. 200ms is plenty when daemon is
	// healthy (sub-millisecond on a real system) and fails fast otherwise.
	var daemonState daemon.DaemonState
	client := daemon.NewClient(cfg.ConfigDir)
	client.SetDialTimeout(200 * time.Millisecond)
	if err := client.Connect(); err == nil {
		client.RequestStatus()
		if event, err := client.ReadEventWithTimeout(500 * time.Millisecond); err == nil {
			daemonState = event.DaemonState
		}
		client.Close()
	}

	// 5-state waybar system:
	//   connected      = solid monochrome icon
	//   connecting     = blinking monochrome icon (CSS animation)
	//   disconnected   = hidden (no icon)
	//   ks-blocking    = blinking red icon (CSS animation + color)
	//   error          = solid red icon
	var status struct {
		Text    string `json:"text"`
		Tooltip string `json:"tooltip"`
		Class   string `json:"class"`
		Alt     string `json:"alt"`
	}

	switch {
	case connected && (daemonState == "" || daemonState == daemon.StateConnected):
		// State 1: Connected — solid monochrome
		status.Text = "󰖂"
		status.Class = "connected"
		status.Alt = "connected"
		status.Tooltip = waybarConnectedTooltip(cfg, ksActive)

	case daemonState == daemon.StateConnecting ||
		daemonState == daemon.StateRetrying ||
		daemonState == daemon.StateFailover ||
		daemonState == daemon.StateDisconnecting ||
		daemonState == daemon.StateUnhealthy:
		// State 2: Connecting/reconnecting — blinking monochrome
		status.Text = "󰖂"
		status.Class = "connecting"
		status.Alt = "connecting"
		status.Tooltip = "VPN: " + string(daemonState)

	case daemonState == daemon.StateFailed || daemonState == daemon.StateSwitchFailed:
		// State 5: Error — solid red (must be checked before ks-blocking)
		status.Text = "󰖂"
		status.Class = "error"
		status.Alt = "error"
		tooltip := "VPN: " + string(daemonState)
		if ksActive {
			tooltip += "\nKillswitch: Active (Blocking)"
		}
		status.Tooltip = tooltip

	case !connected && ksActive:
		// State 4: Disconnected with killswitch blocking — blinking red
		status.Text = "󰖂"
		status.Class = "ks-blocking"
		status.Alt = "ks-blocking"
		status.Tooltip = "VPN: Disconnected\nKillswitch: Active (Blocking)"

	default:
		// State 3: Disconnected, no killswitch — hidden
		status.Text = ""
		status.Class = "disconnected"
		status.Alt = "disconnected"
		status.Tooltip = "VPN: Disconnected"
	}

	output, _ := json.Marshal(status)
	fmt.Println(string(output))
}

// waybarConnectedTooltip builds the rich tooltip for the connected state
func waybarConnectedTooltip(cfg *config.Config, ksActive bool) string {
	tooltip := ""
	if cfg.LastConnectedServer != "" {
		server := cfg.LastConnectedServer
		providerID := ""
		if strings.HasPrefix(server, "dynamic:") {
			parts := strings.SplitN(server, ":", 3)
			if len(parts) == 3 {
				providerID = parts[1]
				server = parts[2]
			}
		}

		displayProvider := ""
		if providerID != "" {
			if dp, ok := providerDisplayMap[providerID]; ok {
				displayProvider = dp
			} else {
				displayProvider = providerID
			}
		}
		if displayProvider != "" {
			tooltip += displayProvider + "\n"
		}

		info := wireguard.ParseServerName(server)
		if info.Country != "Unknown" && info.Country != "" {
			flag := util.CountryFlag(info.Country)
			countryName := util.ExpandCountryName(info.Country)
			location := flag + " " + countryName
			if info.State != "" {
				location += " - " + util.ExpandLocationName(info.State)
			}
			if info.City != "" {
				location += " - " + util.ExpandLocationName(info.City)
			}
			if info.Number != "" {
				location += " (#" + info.Number + ")"
			}
			for _, svc := range info.Services {
				if emoji, ok := util.FeatureEmojis[svc]; ok {
					location += " " + emoji
				}
			}
			tooltip += location
		} else {
			tooltip += server
		}
	}
	if cfg.LastPublicIP != "" {
		tooltip += "\n" + cfg.LastPublicIP
	}
	if ksActive {
		tooltip += "\nKillswitch: Active"
	}
	return tooltip
}

// runWGHelper handles the "wg-helper" subcommand.
// Usage: lazyvpn wg-helper configure <interface-name>
// Reads WGHelperConfig JSON from stdin and configures the WireGuard device.
func runWGHelper() {
	if len(os.Args) < 4 || os.Args[2] != "configure" {
		fmt.Fprintln(os.Stderr, "usage: lazyvpn wg-helper configure <interface>")
		os.Exit(1)
	}
	ifaceName := os.Args[3]
	if err := netlinkpkg.RunConfigureHelper(ifaceName, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runUpdate() {
	fmt.Printf("LazyVPN %s\n", Version)
	fmt.Println("Checking for updates...")

	rel, err := update.Check(Version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if rel == nil {
		fmt.Println("Already up to date.")
		return
	}

	fmt.Printf("\nUpdate available: %s → %s\n", Version, rel.TagName)
	if rel.PublishedAt != "" {
		fmt.Printf("Released: %s\n", rel.PublishedAt)
	}
	if rel.Body != "" {
		fmt.Println("\n─── Release Notes ───")
		fmt.Println(rel.Body)
		fmt.Println("─────────────────────")
	}

	if rel.AssetURL == "" {
		fmt.Println("\nNo binary available for download. Visit GitHub to update manually.")
		return
	}

	fmt.Print("\nDownload and install? [y/N] ")
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "y" && answer != "yes" {
		fmt.Println("Update cancelled.")
		return
	}

	binaryPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding binary path: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Downloading...")
	if err := update.Apply(rel, binaryPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Updated to %s successfully.\n", rel.TagName)
}

func printHelp() {
	fmt.Println(`LazyVPN - WireGuard VPN Manager for Omarchy

Usage: lazyvpn [command]

Commands:
  (no command)     Launch the TUI
  random           Connect to a random server (manual + dynamic)
  quickest         Connect to the lowest-latency server
  killswitch       Emergency killswitch control (enable|disable|off|status)
  update           Check for and install updates
  version          Show version
  install          Set up LazyVPN (config, menu, keybindings, Waybar)
  uninstall        Remove LazyVPN from system
  help             Show this help message

Internal commands (used by system/TUI):
  daemon           Connection daemon (run|stop|status)
  boot             Autostart handler
  waybar           Waybar status module

Examples:
  lazyvpn                      # Launch TUI (main interface)
  lazyvpn random               # Connect to a random server
  lazyvpn quickest             # Connect to the fastest server
  lazyvpn update               # Check for and install updates
  lazyvpn killswitch disable   # Emergency: disable killswitch from terminal
  lazyvpn killswitch off       # Same as above`)
}

// hasFlagEmojiFont reports whether fontconfig knows about a font that
// covers regional indicator codepoints (used to render country flags).
// We check U+1F1FA (REGIONAL INDICATOR SYMBOL LETTER U) — present in any
// flag-capable color emoji font and absent from programming fonts like
// JetBrainsMono Nerd Font.
func hasFlagEmojiFont() bool {
	if _, err := exec.LookPath("fc-list"); err != nil {
		// fontconfig isn't installed; can't determine — assume yes to
		// avoid bogus prompts on systems where fc-list is unavailable.
		return true
	}
	out, err := exec.Command("fc-list", ":charset=1f1fa", "family").Output()
	if err != nil {
		return true
	}
	return len(strings.TrimSpace(string(out))) > 0
}

// emojiPackageForPkgMgr returns the emoji-font package name for the
// detected package manager. Returns "" if no supported pkg mgr is found.
func emojiPackageForPkgMgr() (cmd string, args []string, pkg string) {
	if _, err := exec.LookPath("pacman"); err == nil {
		return "pacman", []string{"sudo", "pacman", "-S", "--noconfirm"}, "noto-fonts-emoji"
	}
	if _, err := exec.LookPath("apt-get"); err == nil {
		return "apt-get", []string{"sudo", "apt-get", "install", "-y"}, "fonts-noto-color-emoji"
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		return "dnf", []string{"sudo", "dnf", "install", "-y"}, "google-noto-color-emoji-fonts"
	}
	return "", nil, ""
}

// installEmojiFont detects whether a flag-capable color emoji font is
// available and offers to install one if not. The dashboard uses flag
// emoji throughout (server lists, status line); without this font the
// flags render as raw two-letter regional indicator pairs ("US", "AR")
// which looks broken even though it's technically correct fallback.
func installEmojiFont() {
	if hasFlagEmojiFont() {
		fmt.Println("  ✓ Color emoji font with flag support found.")
		return
	}

	pkgMgr, pkgMgrArgs, pkg := emojiPackageForPkgMgr()
	if pkgMgr == "" {
		fmt.Println("  ⚠ No flag-capable color emoji font found.")
		fmt.Println("    Country flags in the dashboard will render as raw two-letter codes.")
		fmt.Println("    Install a color emoji font manually (e.g. Noto Color Emoji) and re-run if you want flags.")
		return
	}

	fmt.Printf("  ⚠ No flag-capable color emoji font found.\n")
	fmt.Printf("    Country flags in the dashboard will render as raw two-letter codes (e.g. \"US\" instead of 🇺🇸).\n")

	// Without a TTY we cannot ask for consent. fmt.Scanln returns immediately
	// with io.EOF on piped/closed stdin and answer stays "", which would
	// silently proceed past the [Y/n] guard and run a sudo package install
	// without the user agreeing. Skip with a clear message instead.
	if !isTerminal() {
		fmt.Printf("    Non-interactive install detected; skipping. Run `sudo %s %s` manually.\n",
			strings.Join(pkgMgrArgs[1:], " "), pkg)
		return
	}

	fmt.Printf("    Install %s now using %s? [Y/n] ", pkg, pkgMgr)
	var answer string
	fmt.Scanln(&answer)
	if answer != "" && strings.ToLower(answer) != "y" {
		fmt.Printf("    Skipped. Install %s manually if you want flag rendering.\n", pkg)
		return
	}

	installCmd := exec.Command(pkgMgrArgs[0], append(pkgMgrArgs[1:], pkg)...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	installCmd.Stdin = os.Stdin
	if err := installCmd.Run(); err != nil {
		fmt.Printf("  ⚠ Failed to install %s: %v\n", pkg, err)
		return
	}
	// Distro font packages run a fontconfig post-install hook that rebuilds
	// the system cache; a user-level `fc-cache` here would only refresh
	// ~/.cache/fontconfig and is misleading about where the work happens.
	fmt.Printf("  ✓ %s installed.\n", pkg)
}

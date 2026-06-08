package netlink

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	nl "github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
)

// Key is a type alias for wgtypes.Key for external use
type Key = wgtypes.Key

// WireGuardInterface manages a WireGuard interface using native netlink
type WireGuardInterface struct {
	Name       string
	PrivateKey wgtypes.Key
	Address    net.IPNet
	DNS        net.IP
	Peer       WireGuardPeer
}

// WireGuardPeer represents a WireGuard peer configuration
type WireGuardPeer struct {
	PublicKey           wgtypes.Key
	PresharedKey        *wgtypes.Key // Optional preshared key
	Endpoint            *net.UDPAddr
	AllowedIPs          []net.IPNet
	PersistentKeepalive time.Duration
}

// isPermError returns true if the error chain contains EPERM
func isPermError(err error) bool {
	if os.IsPermission(err) {
		return true
	}
	// Check for wrapped EPERM from netlink/wgctrl
	for e := err; e != nil; {
		if se, ok := e.(*os.SyscallError); ok {
			return se.Err == syscall.EPERM || se.Err == syscall.EACCES
		}
		if u, ok := e.(interface{ Unwrap() error }); ok {
			e = u.Unwrap()
		} else {
			break
		}
	}
	return strings.Contains(err.Error(), "operation not permitted") ||
		strings.Contains(err.Error(), "permission denied")
}

// CreateInterface creates a WireGuard interface using native netlink.
// Falls back to sudo ip if netlink returns EPERM.
func (w *WireGuardInterface) CreateInterface() error {
	la := nl.NewLinkAttrs()
	la.Name = w.Name

	link := &nl.GenericLink{
		LinkAttrs: la,
		LinkType:  "wireguard",
	}

	if err := nlLinkAdd(link); err != nil {
		if !skipSysCommands && isPermError(err) {
			return w.createInterfaceSudo()
		}
		return fmt.Errorf("failed to create interface: %w", err)
	}

	return nil
}

func (w *WireGuardInterface) createInterfaceSudo() error {
	out, err := runSudoCmd("sudo", "-n", "ip", "link", "add", "dev", w.Name, "type", "wireguard")
	if err != nil {
		if sudo.IsAuthError(out) {
			return fmt.Errorf("failed to create interface: %w", sudo.ErrAuthRequired)
		}
		return fmt.Errorf("failed to create interface: %w: %s", err, string(out))
	}
	return nil
}

// ConfigureInterface configures the WireGuard interface using wgctrl.
// Returns sudo.ErrAuthRequired if the process lacks CAP_NET_ADMIN.
func (w *WireGuardInterface) ConfigureInterface() error {
	keepalive := w.Peer.PersistentKeepalive
	peerConfig := wgtypes.PeerConfig{
		PublicKey:                   w.Peer.PublicKey,
		PresharedKey:                w.Peer.PresharedKey,
		Endpoint:                    w.Peer.Endpoint,
		AllowedIPs:                  w.Peer.AllowedIPs,
		PersistentKeepaliveInterval: &keepalive,
		ReplaceAllowedIPs:           true,
	}

	cfg := wgtypes.Config{
		PrivateKey:   &w.PrivateKey,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{peerConfig},
	}

	// Use injected wgctrl runner if available
	if wgRunner != nil {
		if err := wgRunner.ConfigureDevice(w.Name, cfg); err != nil {
			return fmt.Errorf("failed to configure wireguard: %w", err)
		}
		return nil
	}

	client, err := wgctrl.New()
	if err != nil {
		if isPermError(err) {
			return w.configureInterfaceSelf()
		}
		return fmt.Errorf("failed to open wgctrl: %w", err)
	}
	defer client.Close()

	if err := client.ConfigureDevice(w.Name, cfg); err != nil {
		if isPermError(err) {
			return w.configureInterfaceSelf()
		}
		return fmt.Errorf("failed to configure wireguard: %w", err)
	}

	return nil
}

// AssignAddress assigns the IP address to the interface.
// Falls back to sudo ip if netlink returns EPERM.
func (w *WireGuardInterface) AssignAddress() error {
	link, err := nlLinkByName(w.Name)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}

	addr := &nl.Addr{
		IPNet: &w.Address,
	}

	if err := nlAddrAdd(link, addr); err != nil {
		if !skipSysCommands && isPermError(err) {
			return w.assignAddressSudo()
		}
		return fmt.Errorf("failed to add address: %w", err)
	}

	return nil
}

func (w *WireGuardInterface) assignAddressSudo() error {
	cidr := fmt.Sprintf("%s/%d", w.Address.IP.String(), maskBits(w.Address.Mask))
	out, err := runSudoCmd("sudo", "-n", "ip", "addr", "add", cidr, "dev", w.Name)
	if err != nil {
		if sudo.IsAuthError(out) {
			return fmt.Errorf("failed to add address: %w", sudo.ErrAuthRequired)
		}
		return fmt.Errorf("failed to add address: %w: %s", err, string(out))
	}
	return nil
}

// BringUp brings the interface up.
// Falls back to sudo ip if netlink returns EPERM.
func (w *WireGuardInterface) BringUp() error {
	link, err := nlLinkByName(w.Name)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}

	if err := nlLinkSetUp(link); err != nil {
		if !skipSysCommands && isPermError(err) {
			return w.bringUpSudo()
		}
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	return nil
}

func (w *WireGuardInterface) bringUpSudo() error {
	out, err := runSudoCmd("sudo", "-n", "ip", "link", "set", "dev", w.Name, "up")
	if err != nil {
		if sudo.IsAuthError(out) {
			return fmt.Errorf("failed to bring up interface: %w", sudo.ErrAuthRequired)
		}
		return fmt.Errorf("failed to bring up interface: %w: %s", err, string(out))
	}
	return nil
}

// ClearPeers removes all peers from a WireGuard interface without tearing the
// interface down. After this call the kernel's peer list is empty, which means
// `wgctrl.Device(name).Peers` returns [] and any LastHandshakeTime that was
// previously recorded is gone from kernel state. Used on sleep to prevent the
// wake path from trusting a stale-but-recent handshake timestamp.
func ClearPeers(name string) error {
	cfg := wgtypes.Config{ReplacePeers: true, Peers: []wgtypes.PeerConfig{}}
	if wgRunner != nil {
		return wgRunner.ConfigureDevice(name, cfg)
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl: %w", err)
	}
	defer client.Close()
	return client.ConfigureDevice(name, cfg)
}

// Delete removes the interface
func (w *WireGuardInterface) Delete() error {
	link, err := nlLinkByName(w.Name)
	if err != nil {
		// Interface doesn't exist, that's fine
		return nil
	}

	if err := nlLinkDel(link); err != nil {
		if !skipSysCommands && isPermError(err) {
			out, sudoErr := runSudoCmd("sudo", "-n", "ip", "link", "delete", "dev", w.Name)
			if sudoErr != nil {
				if sudo.IsAuthError(out) {
					return fmt.Errorf("failed to delete interface: %w", sudo.ErrAuthRequired)
				}
				return fmt.Errorf("failed to delete interface: %w: %s", sudoErr, string(out))
			}
			return nil
		}
		return fmt.Errorf("failed to delete interface: %w", err)
	}

	return nil
}

// SetMTU sets the MTU for the interface
func (w *WireGuardInterface) SetMTU(mtu int) error {
	link, err := nlLinkByName(w.Name)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}

	if err := nlLinkSetMTU(link, mtu); err != nil {
		if !skipSysCommands && isPermError(err) {
			out, sudoErr := runSudoCmd("sudo", "-n", "ip", "link", "set", "dev", w.Name, "mtu", strconv.Itoa(mtu))
			if sudoErr != nil {
				if sudo.IsAuthError(out) {
					return fmt.Errorf("failed to set MTU: %w", sudo.ErrAuthRequired)
				}
				return fmt.Errorf("failed to set MTU: %w: %s", sudoErr, string(out))
			}
			return nil
		}
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	return nil
}

// GetDeviceInfo returns the current WireGuard device configuration
func GetDeviceInfo(name string) (*wgtypes.Device, error) {
	// Use injected wgctrl runner if available
	if wgRunner != nil {
		device, err := wgRunner.Device(name)
		if err != nil {
			return nil, fmt.Errorf("failed to get device: %w", err)
		}
		return device, nil
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to open wgctrl: %w", err)
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	return device, nil
}

// ParsePrivateKey converts raw private key bytes into a wgtypes.Key.
// The caller is responsible for zeroing the input slice after this returns.
func ParsePrivateKey(key []byte) (wgtypes.Key, error) {
	if len(key) != wgtypes.KeyLen {
		return wgtypes.Key{}, fmt.Errorf("invalid key length: got %d, want %d", len(key), wgtypes.KeyLen)
	}

	var k wgtypes.Key
	copy(k[:], key)
	return k, nil
}

// ParsePublicKey parses a base64-encoded WireGuard public key string.
func ParsePublicKey(key string) (wgtypes.Key, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("invalid base64 key: %w", err)
	}

	if len(decoded) != wgtypes.KeyLen {
		return wgtypes.Key{}, fmt.Errorf("invalid key length: got %d, want %d", len(decoded), wgtypes.KeyLen)
	}

	var k wgtypes.Key
	copy(k[:], decoded)
	return k, nil
}

// ParseEndpoint parses a host:port endpoint string
func ParseEndpoint(endpoint string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr("udp", endpoint)
}

// ParseAllowedIPs parses a comma-separated list of CIDRs
func ParseAllowedIPs(allowedIPs string) ([]net.IPNet, error) {
	if allowedIPs == "" {
		return nil, nil
	}

	var result []net.IPNet
	parts := splitAndTrim(allowedIPs, ",")

	for _, part := range parts {
		_, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", part, err)
		}
		result = append(result, *ipnet)
	}

	return result, nil
}

func splitAndTrim(s string, sep string) []string {
	var result []string
	for _, part := range strings.Split(s, sep) {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// maskBits returns the number of leading 1-bits in the mask
func maskBits(mask net.IPMask) int {
	bits, _ := mask.Size()
	return bits
}

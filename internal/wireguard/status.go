package wireguard

import (
	"net"
	"time"

	netlinkpkg "github.com/blank-query/lazyVPN-for-Omarchy/internal/netlink"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// MaxHandshakeAge is the maximum age of a handshake before considering connection stale
// WireGuard performs handshakes every 2 minutes, so 3 minutes is a reasonable threshold
const MaxHandshakeAge = 3 * time.Minute

// Function variables for testing - replaced by test stubs
var (
	statusLinkByName = netlink.LinkByName
	statusAddrList   = netlink.AddrList
	statusGetDevice  = func(name string) (*wgtypes.Device, bool, error) {
		// Default implementation: use netlinkpkg.GetDeviceInfo
		dev, err := netlinkpkg.GetDeviceInfo(name)
		if err != nil {
			return nil, false, err
		}
		return dev, true, nil
	}
	timeNow = time.Now
)

// IsConnected checks if the WireGuard interface exists, is up, and has a configured peer
func IsConnected(interfaceName string) bool {
	if interfaceName == "" {
		interfaceName = "wg0"
	}

	link, err := statusLinkByName(interfaceName)
	if err != nil {
		return false
	}

	// Check if interface is up
	attrs := link.Attrs()
	if attrs == nil {
		return false
	}

	// Check IFF_UP flag
	if attrs.Flags&net.FlagUp == 0 {
		return false
	}

	// Check if interface has an IP address assigned
	addrs, err := statusAddrList(link, netlink.FAMILY_V4)
	if err != nil || len(addrs) == 0 {
		return false
	}

	// Use wgctrl to verify the interface has a configured peer with handshake
	device, ok, err := statusGetDevice(interfaceName)
	if err != nil {
		// If we can't check wgctrl, rely on interface state
		return true
	}
	if !ok {
		return true
	}

	// Check if there's at least one peer configured
	if len(device.Peers) == 0 {
		return false
	}

	// Check if any peer has a recent handshake (within MaxHandshakeAge)
	// WireGuard handshakes should happen every 2 minutes at most
	now := timeNow()
	for _, peer := range device.Peers {
		if !peer.LastHandshakeTime.IsZero() {
			handshakeAge := now.Sub(peer.LastHandshakeTime)
			if handshakeAge < MaxHandshakeAge {
				return true // Recent handshake = connected
			}
			// Stale handshake - connection might be dead
		}
	}

	// No recent handshakes - check if we're still trying to connect
	// If interface is up and has peers but no handshakes, might be initial connection
	// Give benefit of doubt for new connections (no handshake time = just configured)
	for _, peer := range device.Peers {
		if peer.LastHandshakeTime.IsZero() {
			return true // New peer, no handshake yet
		}
	}

	// All peers have stale handshakes - likely disconnected
	return false
}

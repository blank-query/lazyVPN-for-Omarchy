package netlink

import (
	"fmt"
	"net"
	"os"

	nl "github.com/vishvananda/netlink"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
)

// AddSplitRoutes adds 0.0.0.0/1 and 128.0.0.0/1 routes through the specified interface.
// These two routes cover the entire IPv4 address space and are more specific than any
// default route (0.0.0.0/0), so they always take priority regardless of existing default
// route metrics. This is the same approach used by wg-quick.
func AddSplitRoutes(ifaceName string) error {
	link, err := nlLinkByName(ifaceName)
	if err != nil {
		return err
	}

	cidrs := []string{"0.0.0.0/1", "128.0.0.0/1"}
	for _, cidr := range cidrs {
		_, dst, _ := net.ParseCIDR(cidr)
		route := &nl.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
		}

		if err := nlRouteAdd(route); err != nil {
			if !skipSysCommands && isPermError(err) {
				out, sudoErr := runSudoCmd("sudo", "-n", "ip", "route", "add", cidr, "dev", ifaceName)
				if sudoErr != nil {
					if sudo.IsAuthError(out) {
						return fmt.Errorf("failed to add split route %s: %w", cidr, sudo.ErrAuthRequired)
					}
					return fmt.Errorf("failed to add split route %s: %w: %s", cidr, sudoErr, string(out))
				}
				continue
			}
			return fmt.Errorf("failed to add split route %s: %w", cidr, err)
		}
	}
	return nil
}

// DeleteSplitRoutes removes the 0.0.0.0/1 and 128.0.0.0/1 split routes,
// plus any legacy default route (0.0.0.0/0) through the specified interface.
func DeleteSplitRoutes(ifaceName string) error {
	link, err := nlLinkByName(ifaceName)
	if err != nil {
		return err // interface already gone, routes are cleaned up
	}

	cidrs := []string{"0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/0"}
	for _, cidr := range cidrs {
		_, dst, _ := net.ParseCIDR(cidr)
		route := &nl.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
		}
		if err := nlRouteDel(route); err != nil {
			if !skipSysCommands && isPermError(err) {
				out, sudoErr := runSudoCmd("sudo", "-n", "ip", "route", "del", cidr, "dev", ifaceName)
				if sudoErr != nil && sudo.IsAuthError(out) {
					// Auth failure is actionable (the user needs to reinstall
					// sudoers or run with privileges). Route-doesn't-exist
					// errors stay silent — that's the expected "already clean".
					fmt.Fprintf(os.Stderr, "warning: could not delete split route %s dev %s (sudo auth required)\n", cidr, ifaceName)
				}
			}
			// Ignore non-auth errors - route might not exist
		}
	}
	return nil
}

// AddHostRoute adds a route to a specific host via a gateway.
// Falls back to sudo ip if netlink returns EPERM.
func AddHostRoute(host string, gateway string, ifaceName string) error {
	if host == "" {
		return fmt.Errorf("empty host address")
	}
	if gateway == "" {
		return fmt.Errorf("empty gateway address")
	}

	link, err := nlLinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	gw := net.ParseIP(gateway)
	if gw == nil {
		return fmt.Errorf("invalid gateway IP: %s", gateway)
	}

	// Host route: x.x.x.x/32
	hostIP := net.ParseIP(host)
	if hostIP == nil {
		return fmt.Errorf("invalid host IP: %s", host)
	}

	// Determine mask based on IP version
	mask := net.CIDRMask(32, 32)
	if hostIP.To4() == nil {
		mask = net.CIDRMask(128, 128)
	}

	route := &nl.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   hostIP,
			Mask: mask,
		},
		Gw: gw,
	}

	if err := nlRouteAdd(route); err != nil {
		if !skipSysCommands && isPermError(err) {
			out, sudoErr := runSudoCmd("sudo", "-n", "ip", "route", "add", host, "via", gateway, "dev", ifaceName)
			if sudoErr != nil {
				if sudo.IsAuthError(out) {
					return fmt.Errorf("failed to add host route: %w", sudo.ErrAuthRequired)
				}
				return fmt.Errorf("failed to add host route: %w: %s", sudoErr, string(out))
			}
			return nil
		}
		return err
	}
	return nil
}

// DeleteHostRoute removes a host route added by AddHostRoute.
// Matches on destination IP only; the kernel deletes the first matching route.
// Falls back to sudo ip if netlink returns EPERM. Missing routes are not errors.
func DeleteHostRoute(host string) error {
	if host == "" {
		return nil
	}

	hostIP := net.ParseIP(host)
	if hostIP == nil {
		return fmt.Errorf("invalid host IP: %s", host)
	}

	mask := net.CIDRMask(32, 32)
	if hostIP.To4() == nil {
		mask = net.CIDRMask(128, 128)
	}

	route := &nl.Route{
		Dst: &net.IPNet{
			IP:   hostIP,
			Mask: mask,
		},
	}

	if err := nlRouteDel(route); err != nil {
		if !skipSysCommands && isPermError(err) {
			// Sudo fallback — auth failures surfaced; route-missing stays silent.
			out, sudoErr := runSudoCmd("sudo", "-n", "ip", "route", "del", host)
			if sudoErr != nil && sudo.IsAuthError(out) {
				fmt.Fprintf(os.Stderr, "warning: could not delete host route %s (sudo auth required)\n", host)
			}
			return nil
		}
		// Route may not exist (already deleted, never added) — not an error
	}
	return nil
}

// GetDefaultGateway returns the current default gateway IP and interface
func GetDefaultGateway() (gateway string, iface string, err error) {
	routes, err := nlRouteList(nil, nl.FAMILY_V4)
	if err != nil {
		return "", "", err
	}

	for _, route := range routes {
		if route.Dst == nil || route.Dst.IP.Equal(net.IPv4zero) {
			if route.Gw != nil {
				gateway = route.Gw.String()
			}
			if route.LinkIndex > 0 {
				link, err := nlLinkByIndex(route.LinkIndex)
				if err == nil {
					iface = link.Attrs().Name
				}
			}
			// Only return when we have an actual gateway IP.
			// Link-scope default routes (Gw == nil) may appear before
			// the real gateway route in the routing table.
			if gateway != "" {
				return gateway, iface, nil
			}
		}
	}

	return "", "", nil
}

// DeleteLinkInterface deletes a network interface.
// Falls back to sudo ip if netlink returns EPERM.
func DeleteLinkInterface(name string) error {
	link, err := nlLinkByName(name)
	if err != nil {
		return err
	}
	if err := nlLinkDel(link); err != nil {
		if !skipSysCommands && isPermError(err) {
			out, sudoErr := runSudoCmd("sudo", "-n", "ip", "link", "delete", "dev", name)
			if sudoErr != nil {
				if sudo.IsAuthError(out) {
					return fmt.Errorf("failed to delete interface: %w", sudo.ErrAuthRequired)
				}
				return fmt.Errorf("failed to delete interface: %w: %s", sudoErr, string(out))
			}
			return nil
		}
		return err
	}
	return nil
}

// InterfaceExists checks if a network interface exists
func InterfaceExists(name string) bool {
	_, err := nlLinkByName(name)
	return err == nil
}

// LinkByName returns a network link by name
func LinkByName(name string) (nl.Link, error) {
	return nlLinkByName(name)
}

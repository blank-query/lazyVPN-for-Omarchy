package provider

import (
	"os"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
)

// SupportedProviders are the providers LazyVPN's dynamic server browser can
// populate — i.e. the ones present in the gluetun server data we mirror. A
// valid config for any other provider still works via manual import, but the
// dynamic browser has no server list to fetch for it.
var SupportedProviders = []string{
	"protonvpn", "mullvad", "ivpn", "airvpn", "nordvpn", "surfshark", "windscribe", "fastestvpn",
}

// DetectProvider identifies which supported provider a WireGuard config belongs
// to — by DNS, endpoint domain, file content, interface address range, and a
// port hint. Returns the provider id (one of SupportedProviders) or "" if the
// config doesn't match any provider the dynamic server browser supports.
//
// This is the single source of truth for provider detection: the TUI's provider
// setup and the confcheck diagnostic both call it, so their verdicts can't drift.
func DetectProvider(cfg *wireguard.Config, path string) string {
	// Method 1: DNS detection (check if DNS contains or starts with known server)
	dns := strings.ToLower(cfg.DNS)
	dnsCheck := func(target string) bool {
		return dns == target ||
			strings.HasPrefix(dns, target+",") ||
			strings.HasPrefix(dns, target+" ") ||
			strings.Contains(dns, ","+target) ||
			strings.Contains(dns, " "+target)
	}
	switch {
	case dnsCheck("10.2.0.1"):
		return "protonvpn"
	case dnsCheck("10.64.0.1"), dnsCheck("193.138.218.74"):
		return "mullvad"
	case dnsCheck("172.16.0.1"):
		return "ivpn"
	case dnsCheck("10.128.0.1"):
		return "airvpn"
	case dnsCheck("103.86.96.100"):
		return "nordvpn"
	case dnsCheck("162.252.172.57"):
		return "surfshark"
	case dnsCheck("10.255.255.1"):
		return "windscribe"
	case dnsCheck("10.8.0.1"):
		return "fastestvpn"
	}

	// Method 2: Endpoint domain
	endpoint := strings.ToLower(cfg.Endpoint)
	switch {
	case strings.Contains(endpoint, "protonvpn"):
		return "protonvpn"
	case strings.Contains(endpoint, "mullvad"):
		return "mullvad"
	case strings.Contains(endpoint, "ivpn"):
		return "ivpn"
	case strings.Contains(endpoint, "airvpn"):
		return "airvpn"
	case strings.Contains(endpoint, "nordvpn"):
		return "nordvpn"
	case strings.Contains(endpoint, "surfshark"):
		return "surfshark"
	case strings.Contains(endpoint, "windscribe"):
		return "windscribe"
	case strings.Contains(endpoint, "fastestvpn"),
		strings.Contains(endpoint, "jumptoserver"):
		return "fastestvpn"
	}

	// Method 3: File content search (covers comment-stamped configs)
	content, _ := os.ReadFile(path)
	contentLower := strings.ToLower(string(content))
	switch {
	case strings.Contains(contentLower, "protonvpn"):
		return "protonvpn"
	case strings.Contains(contentLower, "mullvad"):
		return "mullvad"
	case strings.Contains(contentLower, "ivpn"):
		return "ivpn"
	case strings.Contains(contentLower, "airvpn"):
		return "airvpn"
	case strings.Contains(contentLower, "nordvpn"),
		strings.Contains(contentLower, "nordlynx"):
		return "nordvpn"
	case strings.Contains(contentLower, "surfshark"):
		return "surfshark"
	case strings.Contains(contentLower, "windscribe"):
		return "windscribe"
	case strings.Contains(contentLower, "fastestvpn"),
		strings.Contains(contentLower, "fastest vpn"),
		strings.Contains(contentLower, "jumptoserver"):
		return "fastestvpn"
	}

	// Method 4: Interface Address range — covers stripped configs where
	// DNS/endpoint/content are absent.
	addr := cfg.Address
	switch {
	case strings.HasPrefix(addr, "10.2."):
		return "protonvpn"
	case strings.HasPrefix(addr, "10.64."), strings.HasPrefix(addr, "10.65."),
		strings.HasPrefix(addr, "10.66."), strings.HasPrefix(addr, "10.67."):
		return "mullvad"
	case strings.HasPrefix(addr, "172.16."):
		return "ivpn"
	case strings.HasPrefix(addr, "10.128."):
		return "airvpn"
	case strings.HasPrefix(addr, "10.255.255."):
		return "windscribe"
	case strings.HasPrefix(addr, "10.8."):
		return "fastestvpn"
	}

	// Method 5: Port hint — AirVPN's 1637 is uncommon enough to fingerprint.
	if strings.HasSuffix(endpoint, ":1637") {
		return "airvpn"
	}

	return ""
}

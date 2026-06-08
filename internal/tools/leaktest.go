package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Go 1.20+ auto-seeds math/rand from crypto/rand

// DNSProvider describes a DNS reflection service that returns the resolver's
// IP address via IN-class TXT records (compatible with Go's net.LookupTXT).
type DNSProvider struct {
	ID          string // config key, e.g. "powerdns"
	Name        string // display name, e.g. "PowerDNS"
	Domain      string // TXT lookup domain
	Description string // shown in settings
}

// DNSProviderRegistry lists all known DNS reflection providers.
// All use IN-class TXT records — compatible with Go's net.LookupTXT().
// OpenDNS excluded: returns A records and only works against its own resolvers.
// Cloudflare excluded: requires CH (CHAOS) class, incompatible with stdlib.
var DNSProviderRegistry = []DNSProvider{
	{ID: "powerdns", Name: "PowerDNS", Domain: "whoami.v4.powerdns.org", Description: "Open source (GPL v2)"},
	{ID: "akamai", Name: "Akamai", Domain: "whoami.ds.akahelp.net", Description: "Major CDN infrastructure"},
	{ID: "google", Name: "Google", Domain: "o-o.myaddr.l.google.com", Description: "Google Public DNS"},
	{ID: "dnscrypt", Name: "DNSCrypt", Domain: "resolver.dnscrypt.info", Description: "DNSCrypt project (privacy-focused)"},
	{ID: "addrtools", Name: "addr.tools", Domain: "test.dnscheck.tools", Description: "Open source DNS checker"},
	{ID: "00f", Name: "00f.net", Domain: "resolver.00f.net", Description: "DNSCrypt mirror (jedisct1)"},
	{ID: "local", Name: "Local Analysis", Domain: "", Description: "Inspect system DNS config & EDNS Client Subnet"},
}

// DefaultDNSProviders is the default set of enabled provider IDs.
var DefaultDNSProviders = []string{"powerdns", "akamai", "local"}

// Injectable variables for testing. These allow tests to override network
// calls without needing real connectivity or external services.
var (
	// ipInfoURL is the endpoint for public IP lookups.
	ipInfoURL = "https://ipinfo.io/json"

	// ifconfigURL is the fallback endpoint for public IP lookups.
	ifconfigURL = "https://ifconfig.me/all.json"

	// ipAPIURL is the second fallback endpoint for public IP lookups.
	ipAPIURL = "http://ip-api.com/json"

	// netInterfaces wraps net.Interfaces for testability.
	netInterfaces = net.Interfaces

	// webrtcDialFunc wraps the TCP dial used in testWebRTC leak detection.
	webrtcDialFunc = func(dialer *net.Dialer, network, address string) (net.Conn, error) {
		return dialer.Dial(network, address)
	}

	// ipv6DialFunc wraps the IPv6 dial used in testIPv6.
	ipv6DialFunc = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: timeout}
		return dialer.DialContext(ctx, network, address)
	}

	// resolvectlOutput runs resolvectl dns and returns its output.
	// Replaced in tests to avoid needing systemd-resolved.
	resolvectlOutput = func(ctx context.Context) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "resolvectl", "dns")
		return cmd.Output()
	}

	// resolvectlStatusOutput runs resolvectl status and returns per-link DNS details.
	// Separate from resolvectlOutput because they parse different formats.
	resolvectlStatusOutput = func(ctx context.Context) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "resolvectl", "status")
		return cmd.Output()
	}

	// readResolvConf reads the resolv.conf file.
	readResolvConf = func() ([]byte, error) {
		return os.ReadFile("/etc/resolv.conf")
	}

	// lookupTXTFunc wraps net.LookupTXT for testability.
	lookupTXTFunc = net.LookupTXT

	// lookupAddrFunc wraps net.LookupAddr for reverse DNS (testability).
	lookupAddrFunc = net.LookupAddr

	// dnsLookupHost wraps the DNS lookup used in checkLocalDNS for the
	// systemd-resolved stub resolver fallback path.
	dnsLookupHost = func(ctx context.Context, host string) ([]string, error) {
		resolver := &net.Resolver{PreferGo: true}
		return resolver.LookupHost(ctx, host)
	}

	// dialTimeoutFunc wraps net.DialTimeout for testability in TestKillswitch.
	dialTimeoutFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(network, address, timeout)
	}

	// dropInterfaceFunc wraps dropInterface for testability in TestKillswitch.
	dropInterfaceFunc = dropInterfaceReal

	// bringUpInterfaceFunc wraps bringUpInterface for testability in TestKillswitch.
	bringUpInterfaceFunc = bringUpInterfaceReal

	// interfaceByNameFunc wraps net.InterfaceByName for testability.
	interfaceByNameFunc = net.InterfaceByName

	// execCommandFunc wraps exec.CommandContext output for testability.
	execCommandFunc = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		return cmd.CombinedOutput()
	}

	// testUDPMTUFunc wraps testUDPMTU for testability in TestMTU.
	testUDPMTUFunc = testUDPMTUReal

	// killswitchSleepFunc allows tests to skip time.Sleep in TestKillswitch.
	killswitchSleepFunc = time.Sleep
)

// LeakTestResult represents the result of a leak test
type LeakTestResult struct {
	IP       string
	Provider string
	Country  string
	IsVPN    bool
	IsSafe   bool
	IsError  bool // true = test couldn't run (network error), not a detected leak
}

// LeakTest performs a comprehensive leak test
type LeakTest struct {
	ID               string
	VPNInterface     string   // Name of VPN interface to exclude from leak checks
	Providers        []string // IDs of enabled DNS reflection providers
	BaselineIP       string   // ISP public IP to detect leaks against
	BaselineOrg      string   // ISP org name
	BaselineDNS      []string // ISP DNS resolver IPs
	KillswitchActive bool     // Whether UFW killswitch is currently enforcing
	DNSResults       []LeakTestResult
	IPResult         *LeakTestResult
	WebRTCResult     *WebRTCLeakResult
	IPv6Result       *IPv6LeakResult
	Error            error
	Stage            string
}

// WebRTCLeakResult represents WebRTC/interface leak test results
type WebRTCLeakResult struct {
	LocalIPs        []string
	CanBindPhysical bool // True = leak: can bind to physical interface
	IsSafe          bool
	Message         string
}

// IPv6LeakResult represents IPv6 leak test results
type IPv6LeakResult struct {
	IPv6Available bool
	IPv6Blocked   bool
	IsSafe        bool
	Message       string
}

// NewLeakTest creates a new leak test instance with the given DNS provider IDs
// and ISP baseline fingerprint for leak comparison.
func NewLeakTest(providers []string, baselineIP, baselineOrg string, baselineDNS []string) *LeakTest {
	// #nosec G404 -- session-local correlation ID embedded in leak-test DNS
	// subdomains; not a security or privacy boundary, math/rand is fine.
	id := fmt.Sprintf("%d", mathrand.Int63())
	return &LeakTest{
		ID:          id,
		Providers:   providers,
		BaselineIP:  baselineIP,
		BaselineOrg: baselineOrg,
		BaselineDNS: baselineDNS,
	}
}

// Run executes the full leak test
func (lt *LeakTest) Run() {
	lt.Stage = "Checking public IP..."
	lt.checkPublicIP()
	if lt.Error != nil {
		// Record as failed IP result instead of aborting — remaining tests
		// (DNS, WebRTC, IPv6) can still provide useful information.
		lt.IPResult = &LeakTestResult{
			IP:       "Unavailable",
			Provider: lt.Error.Error(),
			IsSafe:   false,
			IsError:  true,
		}
		lt.Error = nil
	}

	lt.Stage = "Testing DNS resolution..."
	lt.testDNS()

	lt.Stage = "Testing WebRTC/interface isolation..."
	lt.testWebRTC()

	lt.Stage = "Testing IPv6 leakage..."
	lt.testIPv6()

	lt.Stage = "Complete"
}

// ipResult holds the parsed fields from any IP lookup service.
type ipResult struct {
	ip      string
	org     string
	country string
}

// ipService describes a single IP lookup endpoint and how to parse its response.
type ipService struct {
	url   string
	parse func([]byte) (ipResult, error)
}

// ipLookupServices returns the ordered list of IP services to try.
// Defined as a function so tests can override the URL vars.
func ipLookupServices() []ipService {
	return []ipService{
		{url: ipInfoURL, parse: parseIPInfo},
		{url: ifconfigURL, parse: parseIfconfig},
		{url: ipAPIURL, parse: parseIPAPI},
	}
}

// validateIPField rejects responses whose 'ip' field isn't a parseable
// IP. Without this guard, garbage from a captive portal / compromised
// endpoint / malformed JSON would propagate into LeakTest.IPResult.IP
// and break the leak-detection comparison (which is string-equality
// against cfg.BaselineIP).
func validateIPField(s, field string) error {
	if s == "" {
		return fmt.Errorf("empty %s in response", field)
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("invalid IP in %s field: %q", field, s)
	}
	return nil
}

func parseIPInfo(body []byte) (ipResult, error) {
	var v struct {
		IP      string `json:"ip"`
		Org     string `json:"org"`
		Country string `json:"country"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return ipResult{}, err
	}
	if err := validateIPField(v.IP, "ip"); err != nil {
		return ipResult{}, err
	}
	return ipResult{ip: v.IP, org: v.Org, country: v.Country}, nil
}

func parseIfconfig(body []byte) (ipResult, error) {
	var v struct {
		IPAddr  string `json:"ip_addr"`
		Country string `json:"country"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return ipResult{}, err
	}
	if err := validateIPField(v.IPAddr, "ip_addr"); err != nil {
		return ipResult{}, err
	}
	return ipResult{ip: v.IPAddr, country: v.Country}, nil
}

func parseIPAPI(body []byte) (ipResult, error) {
	var v struct {
		Query       string `json:"query"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		CountryCode string `json:"countryCode"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return ipResult{}, err
	}
	if err := validateIPField(v.Query, "query"); err != nil {
		return ipResult{}, err
	}
	org := v.ISP
	if org == "" {
		org = v.Org
	}
	return ipResult{ip: v.Query, org: org, country: v.CountryCode}, nil
}

// fetchIPFromService fetches and parses IP info from a single service.
// The parent context lets the caller cancel in-flight requests as soon as
// another service has produced a usable result — without it, losing
// goroutines run to their own 10s timeout past the caller's return.
//
// A private Transport with keep-alives disabled is used so the HTTP/2
// connection pool from the default transport doesn't accumulate idle
// connections for the ~90s default idle timeout. checkPublicIP runs on
// every leak test; under repeated calls the default-transport pool
// would hold open connections to ipinfo.io / ifconfig.me / ip-api.com
// long after the function returned. CloseIdleConnections at defer time
// guarantees the pool is empty when we leave.
func fetchIPFromService(ctx context.Context, svc ipService) (ipResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", svc.url, nil)
	if err != nil {
		return ipResult{}, err
	}

	transport := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	defer transport.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return ipResult{}, err
	}
	defer resp.Body.Close()

	const maxSize = 4 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return ipResult{}, err
	}

	return svc.parse(body)
}

// checkPublicIP checks the current public IP by querying all services in
// parallel and using the first successful response.
func (lt *LeakTest) checkPublicIP() {
	services := ipLookupServices()

	type fetchResult struct {
		res ipResult
		err error
	}
	ch := make(chan fetchResult, len(services))

	// Shared cancel: once we have a winner (or all services have errored
	// and we're returning), drop the remaining in-flight HTTP requests
	// instead of letting them run to their own 10s timeouts.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, svc := range services {
		go func(s ipService) {
			r, err := fetchIPFromService(ctx, s)
			ch <- fetchResult{r, err}
		}(svc)
	}

	var lastErr error
	remaining := len(services)
	for remaining > 0 {
		fr := <-ch
		remaining--
		if fr.err != nil {
			lastErr = fr.err
			continue
		}

		// First success wins — determine safety by comparing against ISP
		// baseline. Use the IP alone: it's the authoritative leak signal.
		// Org-name comparison was previously AND'd in, which produced false
		// positives whenever the VPN provider's org name happened to match
		// the ISP's (e.g. both reported as the same upstream AS by ipinfo).
		// Switching the AND to OR would swap that for a worse failure mode
		// (same IP + different org → labelled safe = false negative on a
		// real leak), so the right move is to drop org from isSafe entirely.
		// Provider/Country are still surfaced in the result for the user.
		var isSafe bool
		if lt.BaselineIP != "" {
			isSafe = fr.res.ip != lt.BaselineIP
		} else {
			isSafe = true
		}

		lt.IPResult = &LeakTestResult{
			IP:       fr.res.ip,
			Provider: fr.res.org,
			Country:  fr.res.country,
			IsVPN:    isSafe,
			IsSafe:   isSafe,
		}
		return
	}

	lt.Error = fmt.Errorf("all IP lookup services failed: %w", lastErr)
}

// testDNS performs DNS leak testing using DNS reflection services.
// Queries selected providers' whoami TXT records in parallel — these return
// the IP of the DNS resolver that handled the query. No HTTP requests to
// third-party tracking sites. Falls back to local config inspection.
func (lt *LeakTest) testDNS() {
	lt.Stage = "Querying DNS reflection services..."

	// Check if "local" provider is enabled
	localEnabled := false
	for _, id := range lt.Providers {
		if id == "local" {
			localEnabled = true
			break
		}
	}

	// Resolve provider IDs to domains, skipping "local" (empty Domain)
	var domains []string
	for _, id := range lt.Providers {
		for _, p := range DNSProviderRegistry {
			if p.ID == id && p.Domain != "" {
				domains = append(domains, p.Domain)
				break
			}
		}
	}
	if len(domains) == 0 {
		domains = []string{DNSProviderRegistry[0].Domain} // fallback
	}

	type reflectionResult struct {
		domain     string
		resolverIP string
		provider   string // reverse DNS identity
		err        error
	}

	results := make(chan reflectionResult, len(domains))

	// Capture lookupTXTFunc into a local before spawning the goroutines
	// so the goroutines don't read the package var concurrently with
	// tests that mutate it via t.Cleanup. The race detector flags
	// pkg-var read/write across goroutines even when the read clearly
	// happens-before the write at runtime — and the
	// TestTestDNS_HangingLookupBoundedByDeadline test deliberately
	// leaves the goroutines parked inside the stub forever, so the
	// reads never get a chance to retire before cleanup writes.
	lookupTXT := lookupTXTFunc

	for _, domain := range domains {
		go func(d string) {
			// Query TXT record — response contains the resolver's IP
			txts, err := lookupTXT(d)
			if err != nil {
				results <- reflectionResult{domain: d, err: err}
				return
			}

			// Extract IP from TXT response (may be wrapped in text like
			// "Your IP address is X.X.X.X")
			resolverIP := extractIPFromTXT(txts)
			if resolverIP == "" {
				results <- reflectionResult{domain: d, err: fmt.Errorf("no IP in TXT response")}
				return
			}

			// Reverse DNS to identify the resolver
			provider := resolverIP
			if names, err := lookupAddrFunc(resolverIP); err == nil && len(names) > 0 {
				provider = strings.TrimSuffix(names[0], ".")
			}

			results <- reflectionResult{domain: d, resolverIP: resolverIP, provider: provider}
		}(domain)
	}

	// Also run local DNS check in parallel
	localDone := make(chan struct{})
	var localResults []LeakTestResult
	go func() {
		// Propagate every field that downstream local-DNS / interface-scan
		// helpers might consult — currently checkLocalDNS* uses BaselineDNS
		// directly, but sub-helpers also read VPNInterface (to exclude the
		// VPN tunnel from interface-listing checks) and KillswitchActive
		// (to gate certain leak categories). Copying only one field worked
		// today by coincidence and would silently break the moment any of
		// those helpers grow a use.
		localLT := &LeakTest{
			BaselineDNS:      lt.BaselineDNS,
			BaselineIP:       lt.BaselineIP,
			BaselineOrg:      lt.BaselineOrg,
			VPNInterface:     lt.VPNInterface,
			KillswitchActive: lt.KillswitchActive,
			Providers:        lt.Providers,
		}
		if localEnabled {
			localLT.checkLocalDNSEnhanced()
		} else {
			localLT.checkLocalDNS()
		}
		localResults = localLT.DNSResults
		close(localDone)
	}()

	lt.Stage = "Analyzing DNS responses..."

	// Collect reflection results with a hard deadline. net.LookupTXT
	// has no context-based timeout, so a hung DNS server would leave
	// the goroutine parked forever and the entire leak test stuck on
	// <-results. The Go resolver's internal per-query timeout
	// eventually kicks in (~5s × N retries) but we don't want to wait
	// for the worst case. 8s is comfortably above a healthy lookup
	// (typically <50ms) and well below the test-runs-forever case.
	const dnsCollectTimeout = 8 * time.Second
	deadline := time.After(dnsCollectTimeout)
loop:
	for i := 0; i < len(domains); i++ {
		select {
		case r := <-results:
			if r.err != nil {
				continue
			}
			// Safe if resolver IP is NOT one of the ISP baseline DNS servers
			isISP := false
			for _, baseline := range lt.BaselineDNS {
				if r.resolverIP == baseline {
					isISP = true
					break
				}
			}
			isSafe := !isISP
			if len(lt.BaselineDNS) == 0 {
				isSafe = true // no baseline to compare
			}
			lt.DNSResults = append(lt.DNSResults, LeakTestResult{
				IP:       r.resolverIP,
				Provider: r.provider,
				IsVPN:    isSafe,
				IsSafe:   isSafe,
			})
		case <-deadline:
			// Outstanding lookup goroutines may still be parked in
			// net.LookupTXT — they'll deliver into the buffered
			// results channel eventually and be garbage-collected
			// when no reader remains, no leak.
			break loop
		}
	}

	// Merge local DNS results, also bounded.
	select {
	case <-localDone:
	case <-time.After(dnsCollectTimeout):
		// Local DNS check hung — proceed with whatever we have.
	}
	if len(lt.DNSResults) == 0 {
		// All reflection failed — use local results as primary
		lt.DNSResults = localResults
	} else if len(localResults) > 0 {
		// Add local results as supplementary data
		for _, lr := range localResults {
			// Avoid duplicating IPs already found via reflection
			duplicate := false
			for _, existing := range lt.DNSResults {
				if existing.IP == lr.IP {
					duplicate = true
					break
				}
			}
			if !duplicate {
				lt.DNSResults = append(lt.DNSResults, lr)
			}
		}
	}
}

// extractIPFromTXT parses an IPv4 or IPv6 address from DNS TXT records.
// Handles formats like "Your IP address is X.X.X.X" or plain "X.X.X.X".
func extractIPFromTXT(txts []string) string {
	for _, txt := range txts {
		// Try the whole string first (plain IP)
		trimmed := strings.TrimSpace(txt)
		if net.ParseIP(trimmed) != nil {
			return trimmed
		}
		// Split on whitespace and try each word
		for _, word := range strings.Fields(txt) {
			cleaned := strings.Trim(word, ".,;:\"'()")
			if net.ParseIP(cleaned) != nil {
				return cleaned
			}
		}
	}
	return ""
}

// isBaselineDNS checks if the given DNS IP matches any ISP baseline DNS server.
func (lt *LeakTest) isBaselineDNS(ip string) bool {
	for _, baseline := range lt.BaselineDNS {
		if ip == baseline {
			return true
		}
	}
	return false
}

// checkLocalDNS checks the locally configured DNS servers against the ISP baseline.
func (lt *LeakTest) checkLocalDNS() {
	// Try resolvectl first (systemd-resolved)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	output, err := resolvectlOutput(ctx)
	if err == nil {
		// Parse resolvectl output for DNS IPs
		for _, lineStr := range strings.Split(string(output), "\n") {
			for _, word := range strings.Fields(lineStr) {
				if net.ParseIP(word) == nil {
					continue
				}
				isISP := lt.isBaselineDNS(word)
				isSafe := !isISP
				if len(lt.BaselineDNS) == 0 {
					isSafe = true
				}
				lt.DNSResults = append(lt.DNSResults, LeakTestResult{
					IP:       word,
					Provider: "Local DNS (" + word + ")",
					IsSafe:   isSafe,
					IsVPN:    isSafe,
				})
				return
			}
		}
	}

	// Fallback: Read /etc/resolv.conf directly
	data, err := readResolvConf()
	if err == nil {
		content := string(data)
		// Check for stub resolver (systemd-resolved)
		if strings.Contains(content, "127.0.0.53") {
			// systemd-resolved is in use but we couldn't get details
			testCtx, testCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer testCancel()
			_, resolveErr := dnsLookupHost(testCtx, "cloudflare.com")
			if resolveErr != nil {
				lt.DNSResults = append(lt.DNSResults, LeakTestResult{
					IP:       "systemd-resolved",
					Provider: "DNS blocked (likely VPN)",
					IsSafe:   true,
					IsVPN:    true,
				})
				return
			}
		}

		// Check nameserver lines against baseline
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "nameserver") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			dns := fields[1]
			if dns == "127.0.0.53" {
				continue // skip stub resolver
			}
			isISP := lt.isBaselineDNS(dns)
			isSafe := !isISP
			if len(lt.BaselineDNS) == 0 {
				isSafe = true
			}
			lt.DNSResults = append(lt.DNSResults, LeakTestResult{
				IP:       dns,
				Provider: "Local DNS (" + dns + ")",
				IsSafe:   isSafe,
				IsVPN:    isSafe,
			})
			return
		}
	}

	// If we got here, we couldn't determine DNS status definitively
	lt.DNSResults = append(lt.DNSResults, LeakTestResult{
		IP:       "Check manually",
		Provider: "Could not determine",
		IsSafe:   false,
		IsVPN:    false,
		IsError:  true,
	})
}

// resolvedLink represents a parsed link section from resolvectl status output.
type resolvedLink struct {
	name           string
	dnsServers     []string
	isDefaultRoute bool
}

// parseResolvectlStatus parses the output of `resolvectl status` into per-link structs.
// It splits on "Link N (name)" headers and extracts DNS Servers and DefaultRoute info.
func parseResolvectlStatus(output string) []resolvedLink {
	var links []resolvedLink
	var current *resolvedLink

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)

		// Match "Link N (name)" headers
		if strings.HasPrefix(trimmed, "Link ") && strings.Contains(trimmed, "(") && strings.Contains(trimmed, ")") {
			// Extract interface name from "Link N (name)"
			start := strings.Index(trimmed, "(")
			end := strings.Index(trimmed, ")")
			if start >= 0 && end > start {
				name := trimmed[start+1 : end]
				links = append(links, resolvedLink{name: name})
				current = &links[len(links)-1]
			}
			continue
		}

		if current == nil {
			continue
		}

		// Parse "DNS Servers:" line
		if strings.HasPrefix(trimmed, "DNS Servers:") {
			servers := strings.TrimPrefix(trimmed, "DNS Servers:")
			for _, s := range strings.Fields(servers) {
				if net.ParseIP(s) == nil {
					continue
				}
				// Dedup against existing entries
				dup := false
				for _, existing := range current.dnsServers {
					if existing == s {
						dup = true
						break
					}
				}
				if !dup {
					current.dnsServers = append(current.dnsServers, s)
				}
			}
			continue
		}

		// Also parse "Current DNS Server:" for single-server configs
		if strings.HasPrefix(trimmed, "Current DNS Server:") {
			server := strings.TrimSpace(strings.TrimPrefix(trimmed, "Current DNS Server:"))
			if net.ParseIP(server) != nil {
				// Only add if not already in dnsServers
				found := false
				for _, s := range current.dnsServers {
					if s == server {
						found = true
						break
					}
				}
				if !found {
					current.dnsServers = append(current.dnsServers, server)
				}
			}
			continue
		}

		// Parse "Protocols:" line for DefaultRoute flag
		if strings.HasPrefix(trimmed, "Protocols:") {
			if strings.Contains(trimmed, "+DefaultRoute") {
				current.isDefaultRoute = true
			} else if strings.Contains(trimmed, "-DefaultRoute") {
				current.isDefaultRoute = false
			}
			continue
		}
	}

	return links
}

// checkLocalDNSEnhanced performs deep local DNS inspection using resolvectl status.
// It detects split-DNS leaks (physical interface still has ISP DNS despite VPN)
// and EDNS Client Subnet leaks. Falls back to checkLocalDNS() if resolvectl status fails.
func (lt *LeakTest) checkLocalDNSEnhanced() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	output, err := resolvectlStatusOutput(ctx)
	if err != nil {
		// Fall back to basic check
		lt.checkLocalDNS()
		lt.checkECS()
		return
	}

	links := parseResolvectlStatus(string(output))
	if len(links) == 0 {
		// No links parsed, fall back
		lt.checkLocalDNS()
		lt.checkECS()
		return
	}

	// Check each link with DefaultRoute for DNS configuration
	for _, link := range links {
		if !link.isDefaultRoute || len(link.dnsServers) == 0 {
			continue
		}

		for _, dns := range link.dnsServers {
			isISP := lt.isBaselineDNS(dns)
			isSafe := !isISP
			if len(lt.BaselineDNS) == 0 {
				isSafe = true // no baseline to compare
			}
			label := "DNS (" + link.name + ")"
			if isISP {
				label = "ISP DNS (" + link.name + ")"
			}
			lt.DNSResults = append(lt.DNSResults, LeakTestResult{
				IP:       dns,
				Provider: label,
				IsSafe:   isSafe,
				IsVPN:    isSafe,
			})
		}
	}

	// If no DefaultRoute links had DNS, fall back to basic
	if len(lt.DNSResults) == 0 {
		lt.checkLocalDNS()
	}

	// Run ECS detection
	lt.checkECS()
}

// checkECS queries whoami-ecs.v4.powerdns.org to detect EDNS Client Subnet leaking.
// If the resolver forwards the client's subnet to authoritative servers, the response
// will contain a netmask value revealing approximate location.
func (lt *LeakTest) checkECS() {
	txts, err := lookupTXTFunc("whoami-ecs.v4.powerdns.org")
	if err != nil {
		return // silently skip — ECS check is supplementary
	}
	for _, txt := range txts {
		if strings.Contains(txt, "netmask:") {
			if !strings.Contains(txt, "no ECS") {
				// ECS is being forwarded — privacy concern
				lt.DNSResults = append(lt.DNSResults, LeakTestResult{
					IP:       extractIPFromECS(txt),
					Provider: "ECS leak detected",
					IsSafe:   false,
					IsVPN:    false,
				})
				return
			}
			// No ECS — good
			lt.DNSResults = append(lt.DNSResults, LeakTestResult{
				IP:       extractIPFromECS(txt),
				Provider: "No ECS (safe)",
				IsSafe:   true,
				IsVPN:    true,
			})
			return
		}
	}
}

// extractIPFromECS parses "ip: X.X.X.X, netmask: ..." and returns the IP.
func extractIPFromECS(txt string) string {
	// Format: "ip: X.X.X.X, netmask: ..."
	txt = strings.TrimSpace(txt)
	if !strings.HasPrefix(txt, "ip:") {
		return ""
	}
	rest := strings.TrimPrefix(txt, "ip:")
	rest = strings.TrimSpace(rest)
	// Take everything before the comma
	if idx := strings.Index(rest, ","); idx >= 0 {
		rest = rest[:idx]
	}
	rest = strings.TrimSpace(rest)
	if net.ParseIP(rest) != nil {
		return rest
	}
	return ""
}

// testWebRTC tests for WebRTC/STUN leaks by checking local interface binding.
//
// The test's premise is "can a process reach the physical NIC despite the VPN?"
// When the killswitch is OFF, that's trivially true for every userspace VPN —
// there's no firewall enforcement to bypass — so we report the test as Safe
// with a note pointing users at the killswitch. When KS is ON, the probe runs
// for real: any success is a genuine bypass of our UFW rules.
func (lt *LeakTest) testWebRTC() {
	result := &WebRTCLeakResult{
		IsSafe: true,
	}

	if !lt.KillswitchActive {
		result.Message = "Not tested — killswitch off (enable killswitch to block non-VPN traffic paths)"
		lt.WebRTCResult = result
		return
	}

	// Get all network interfaces
	ifaces, err := netInterfaces()
	if err != nil {
		result.Message = "Could not enumerate interfaces"
		lt.WebRTCResult = result
		return
	}

	// Collect all local IPs
	for _, iface := range ifaces {
		// Skip loopback and VPN interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "wg") || iface.Name == lt.VPNInterface {
			continue
		}
		// Skip virtual/container interfaces — these are not real WebRTC leak vectors
		if isVirtualInterface(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			// This is a non-VPN local IP
			if ip.To4() != nil {
				result.LocalIPs = append(result.LocalIPs, ip.String())

				// Try a TCP connect from this interface to external servers.
				// Bind to the physical IP and use SO_BINDTODEVICE to force
				// traffic through the physical interface (not the VPN tunnel).
				// Without device binding, split routes send the traffic through
				// wg0 even when bound to a physical IP, causing false positives.
				dialFn := webrtcDialFunc
				targets := []string{"8.8.8.8:53", "1.1.1.1:53"}
				leaked := make(chan bool, len(targets))
				for _, target := range targets {
					go func(t string) {
						dialer := &net.Dialer{
							LocalAddr: &net.TCPAddr{IP: ip, Port: 0},
							Timeout:   5 * time.Second,
							Control: func(network, address string, c syscall.RawConn) error {
								var err error
								c.Control(func(fd uintptr) {
									err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface.Name)
								})
								return err
							},
						}
						conn, err := dialFn(dialer, "tcp4", t)
						if err == nil {
							conn.Close()
							leaked <- true
						} else {
							leaked <- false
						}
					}(target)
				}
				for range targets {
					if <-leaked {
						result.CanBindPhysical = true
						result.IsSafe = false
						result.Message = fmt.Sprintf("LEAK: Can connect from %s (%s)", iface.Name, ip.String())
						break
					}
				}
			}
			if !result.IsSafe {
				break // stop checking more addresses on this interface
			}
		}
		if !result.IsSafe {
			break // stop checking more interfaces
		}
	}

	if result.IsSafe {
		result.Message = "Physical interface access blocked"
	}

	lt.WebRTCResult = result
}

// testIPv6 tests for IPv6 leakage
func (lt *LeakTest) testIPv6() {
	result := &IPv6LeakResult{
		IsSafe: true,
	}

	// Check if system has IPv6 addresses
	ifaces, err := netInterfaces()
	if err != nil {
		result.Message = "Could not check interfaces"
		lt.IPv6Result = result
		return
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP
				if ip.To4() == nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
					// Has a global IPv6 address
					result.IPv6Available = true
				}
			}
		}
	}

	if !result.IPv6Available {
		result.IPv6Blocked = true
		result.Message = "No global IPv6 addresses (safe)"
		lt.IPv6Result = result
		return
	}

	// Try to connect to an IPv6-only host
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try resolving and connecting to IPv6
	conn, err := ipv6DialFunc(ctx, "tcp6", "[2001:4860:4860::8888]:53", 5*time.Second)
	if err != nil {
		// Good: IPv6 is blocked
		result.IPv6Blocked = true
		result.IsSafe = true
		result.Message = "IPv6 properly blocked"
	} else {
		// Bad: IPv6 connection succeeded
		conn.Close()
		result.IPv6Blocked = false
		result.IsSafe = false
		result.Message = "LEAK: IPv6 traffic not blocked"
	}

	lt.IPv6Result = result
}

// HasLeaks returns true if any leaks were detected (excludes error results)
func (lt *LeakTest) HasLeaks() bool {
	if lt.IPResult != nil && !lt.IPResult.IsError && !lt.IPResult.IsSafe {
		return true
	}
	for _, dns := range lt.DNSResults {
		if !dns.IsError && !dns.IsSafe {
			return true
		}
	}
	if lt.WebRTCResult != nil && !lt.WebRTCResult.IsSafe {
		return true
	}
	if lt.IPv6Result != nil && !lt.IPv6Result.IsSafe {
		return true
	}
	return false
}

// Summary returns a human-readable summary
func (lt *LeakTest) Summary() string {
	if lt.Error != nil {
		return fmt.Sprintf("Error: %s", lt.Error)
	}
	if lt.HasLeaks() {
		return "WARNING: Leaks detected!"
	}
	return "No leaks detected"
}

// KillswitchTestResult represents the result of a killswitch fire drill
type KillswitchTestResult struct {
	Attempts         int
	Successes        int // Packets that got through (should be 0)
	PreTestLeaks     int // Leaks before dropping interface
	PostDropLeaks    int // Leaks while interface is down
	IsSafe           bool
	InterfaceDropped bool
	Message          string
}

// TestKillswitch performs a "fire drill" - drops the VPN interface and checks if packets leak
// This is a DESTRUCTIVE test that will temporarily disconnect the VPN
func TestKillswitch(interfaceName string) *KillswitchTestResult {
	result := &KillswitchTestResult{
		Attempts: 10,
	}

	// Phase 1: Pre-test - verify we can reach internet through VPN
	preTestSuccess := false
	for i := 0; i < 3; i++ {
		conn, err := dialTimeoutFunc("tcp", "8.8.8.8:53", 1*time.Second)
		if err == nil {
			conn.Close()
			preTestSuccess = true
			break
		}
	}

	if !preTestSuccess {
		result.IsSafe = true
		result.Message = "Cannot reach internet (killswitch may already be blocking or VPN is down)"
		return result
	}

	// Phase 2: Drop the interface using netlink
	dropped, err := dropInterfaceFunc(interfaceName)
	if err != nil {
		result.Message = fmt.Sprintf("Could not drop interface: %v", err)
		return result
	}
	result.InterfaceDropped = dropped

	// Phase 3: Test for leaks while interface is down
	// Start multiple goroutines trying to connect simultaneously
	var wg sync.WaitGroup
	leakChan := make(chan bool, result.Attempts)

	for i := 0; i < result.Attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Try to connect to multiple endpoints
			endpoints := []string{"8.8.8.8:53", "1.1.1.1:53", "208.67.222.222:53"}
			for _, ep := range endpoints {
				conn, err := dialTimeoutFunc("tcp", ep, 500*time.Millisecond)
				if err == nil {
					conn.Close()
					leakChan <- true
					return
				}
			}
			leakChan <- false
		}()
	}

	// Wait for all tests to complete
	wg.Wait()
	close(leakChan)

	// Count leaks
	for leaked := range leakChan {
		if leaked {
			result.PostDropLeaks++
		}
	}
	result.Successes = result.PostDropLeaks

	// Phase 4: Restore the interface (critical - don't leave VPN down)
	if dropped {
		var restoreErr error
		for attempts := 0; attempts < 3; attempts++ {
			if err := bringUpInterfaceFunc(interfaceName); err == nil {
				restoreErr = nil
				break
			} else {
				restoreErr = err
				killswitchSleepFunc(200 * time.Millisecond)
			}
		}
		if restoreErr != nil {
			// Interface restore failed - this is serious, include in result
			result.Message = fmt.Sprintf("WARNING: Failed to restore VPN interface: %v", restoreErr)
			result.IsSafe = false
			return result
		}
		// Give it a moment to come back up
		killswitchSleepFunc(500 * time.Millisecond)
	}

	// Evaluate results
	if result.Successes == 0 {
		result.IsSafe = true
		result.Message = fmt.Sprintf("Killswitch verified: 0/%d packets leaked while interface was down", result.Attempts)
	} else {
		result.IsSafe = false
		result.Message = fmt.Sprintf("FAIL: %d/%d packets leaked while interface was down!", result.Successes, result.Attempts)
	}

	return result
}

// dropInterfaceReal brings down a network interface using ip command.
// This is the real implementation; dropInterfaceFunc is the injectable wrapper.
func dropInterfaceReal(name string) (bool, error) {
	iface, err := interfaceByNameFunc(name)
	if err != nil {
		return false, fmt.Errorf("interface %s not found: %w", name, err)
	}

	// Check if interface is up
	if iface.Flags&net.FlagUp == 0 {
		return false, nil // Already down
	}

	// Try sudo ip (sudoers requires "dev" keyword)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if out, err := execCommandFunc(ctx, "sudo", "-n", "ip", "link", "set", "dev", name, "down"); err != nil {
		return false, fmt.Errorf("failed to bring down interface: %w: %s", err, string(out))
	}

	return true, nil
}

// bringUpInterfaceReal brings up a network interface.
// This is the real implementation; bringUpInterfaceFunc is the injectable wrapper.
func bringUpInterfaceReal(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := execCommandFunc(ctx, "sudo", "-n", "ip", "link", "set", "dev", name, "up")
	if err != nil {
		return fmt.Errorf("failed to bring up interface: %w: %s", err, string(out))
	}
	return nil
}

// MTUTestResult represents MTU analysis results
type MTUTestResult struct {
	CurrentMTU  int
	OptimalMTU  int
	TestedMTUs  []int // MTUs that were tested
	SuccessMTUs []int // MTUs that worked
	NeedsFix    bool
	Message     string
}

// TestMTU performs Path MTU Discovery using UDP probes
func TestMTU(interfaceName string) *MTUTestResult {
	result := &MTUTestResult{
		CurrentMTU: 1420, // WireGuard default
		OptimalMTU: 1420,
	}

	// Get current MTU from interface
	ifaces, err := netInterfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Name == interfaceName {
				result.CurrentMTU = iface.MTU
				break
			}
		}
	}

	// Perform PMTUD by sending UDP packets of decreasing size
	// We use UDP because it doesn't require raw sockets
	// Test against a reliable DNS server
	testHost := "8.8.8.8:53"

	// WireGuard overhead calculation:
	// - IPv4 header: 20 bytes (no options)
	// - UDP header: 8 bytes
	// - WireGuard header: 32 bytes (type, reserved, counter, auth tag start)
	// - WireGuard auth tag: 16 bytes
	// Total: 20 + 8 + 32 + 16 = 76 bytes, rounded to 80 for safety
	// Standard guidance: 1500 MTU link -> 1420 WG MTU (80 byte overhead)
	overhead := 80

	// Test MTUs from high to low
	testMTUs := []int{1500, 1472, 1450, 1420, 1400, 1380, 1350, 1300, 1280}

	for _, mtu := range testMTUs {
		result.TestedMTUs = append(result.TestedMTUs, mtu)

		// Calculate payload size (MTU - IP header - UDP header)
		// IP header = 20 bytes, UDP header = 8 bytes
		payloadSize := mtu - 28

		if payloadSize <= 0 {
			continue
		}

		// Try to send a UDP packet of this size
		if testUDPMTUFunc(testHost, payloadSize) {
			result.SuccessMTUs = append(result.SuccessMTUs, mtu)
			// Account for WireGuard overhead
			result.OptimalMTU = mtu - overhead
			if result.OptimalMTU < 1280 {
				result.OptimalMTU = 1280 // IPv6 minimum
			}
			break
		}
	}

	// If no MTU worked, use conservative default
	if len(result.SuccessMTUs) == 0 {
		result.OptimalMTU = 1280 // IPv6 minimum, very conservative
		result.Message = "Could not determine optimal MTU, using conservative 1280"
		result.NeedsFix = result.CurrentMTU != result.OptimalMTU
		return result
	}

	// Check for mismatch
	if result.CurrentMTU != result.OptimalMTU {
		result.NeedsFix = true
		result.Message = fmt.Sprintf("MTU mismatch: current=%d, optimal=%d", result.CurrentMTU, result.OptimalMTU)
	} else {
		result.NeedsFix = false
		result.Message = fmt.Sprintf("MTU optimal: %d", result.CurrentMTU)
	}

	return result
}

// testUDPMTUReal tests whether a UDP packet of payloadSize can traverse the
// path without IP fragmentation. The previous implementation just called
// Write without setting the don't-fragment bit, so the kernel silently
// fragmented oversized payloads — Write succeeded for any payload up to
// the local MTU, and the test always returned true. OptimalMTU then
// reported the maximum probed value (~1420) regardless of actual path MTU.
//
// We now set IP_MTU_DISCOVER=PMTUDISC_DO via the dialer's Control callback,
// which forces the DF bit on outbound packets. An oversized payload now
// returns EMSGSIZE / "message too long" and the probe reports failure
// honestly. Path MTU discovery via ICMP frag-needed completes the picture.
func testUDPMTUReal(host string, payloadSize int) bool {
	dialer := net.Dialer{
		Timeout: 2 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var setErr error
			ctlErr := c.Control(func(fd uintptr) {
				setErr = syscall.SetsockoptInt(int(fd),
					syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)
			})
			if ctlErr != nil {
				return ctlErr
			}
			return setErr
		},
	}
	conn, err := dialer.Dial("udp", host)
	if err != nil {
		return false
	}
	defer conn.Close()

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(payload)
	if err != nil {
		// EMSGSIZE / "message too long" means the path can't carry this
		// payload without fragmentation — exactly the signal we want.
		return false
	}
	return true
}

// isVirtualInterface returns true for container/VM/bridge interfaces that
// should be excluded from WebRTC leak tests (they are not real leak vectors).
func isVirtualInterface(name string) bool {
	virtualPrefixes := []string{
		"docker", "br-", "veth", "virbr", "lxc", "lxd",
		"cni", "flannel", "calico", "podman", "cali",
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

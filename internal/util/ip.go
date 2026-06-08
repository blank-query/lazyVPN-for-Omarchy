package util

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	IPifyURL   = "https://api.ipify.org"
	IPify64URL = "https://api64.ipify.org"
	IPInfoURL  = "https://ipinfo.io/json"
)

// IPv4FallbackURLs are alternative IP lookup services tried when ipify fails.
var IPv4FallbackURLs = []string{
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
	"https://checkip.amazonaws.com",
}

// GetPublicIPv4 returns the current public IPv4 address
func GetPublicIPv4() (string, error) {
	return getPublicIP(IPifyURL, "tcp4")
}

// GetPublicIPv6 returns the current public IPv6 address (if available)
func GetPublicIPv6() (string, error) {
	return getPublicIP(IPify64URL, "tcp6")
}

// GetPublicIPInfo returns the current public IPv4 address and ISP org name
// from ipinfo.io. Used to capture the ISP baseline before VPN connect.
func GetPublicIPInfo() (ip, org string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", IPInfoURL, nil)
	if err != nil {
		return "", "", err
	}

	// Private transport with keep-alives off so we don't accumulate idle
	// HTTP/2 connections in the default pool across repeated baseline /
	// reconnect probes (see fetchIPFromService for the same pattern).
	transport := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	defer transport.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("ipinfo.io returned status %d", resp.StatusCode)
	}

	const maxSize = 4 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return "", "", err
	}

	var info struct {
		IP  string `json:"ip"`
		Org string `json:"org"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", "", fmt.Errorf("failed to parse ipinfo.io response: %w", err)
	}

	// Validate the IP — getPublicIP's plaintext path already does this,
	// but GetPublicIPInfo accepted whatever the JSON 'ip' field
	// contained verbatim. Garbage here would land in cfg.RealPublicIP
	// and cfg.BaselineIP, then break the leak-detection comparison
	// (which is string-equality on those fields).
	if net.ParseIP(info.IP) == nil {
		return "", "", fmt.Errorf("invalid IP address in ipinfo.io response: %q", info.IP)
	}

	return info.IP, info.Org, nil
}

func getPublicIP(url string, network string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a custom transport that forces IPv4 or IPv6
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, addr)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IP lookup returned status %d", resp.StatusCode)
	}

	// Limit response size to 1KB (IP addresses are small)
	const maxSize = 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return "", err
	}

	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP address in response: %q", ip)
	}

	return ip, nil
}

// GetPublicIPv4WithRetry tries multiple IP lookup services across multiple rounds.
// Each round tries ipify first, then each fallback URL. Rounds are separated by
// a 1-second sleep. Returns the first successful result.
func GetPublicIPv4WithRetry(maxAttempts int) (string, error) {
	urls := append([]string{IPifyURL}, IPv4FallbackURLs...)
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Second)
		}
		for _, url := range urls {
			ip, err := getPublicIP(url, "tcp4")
			if err == nil {
				return ip, nil
			}
			lastErr = err
		}
	}
	return "", fmt.Errorf("all IP lookup attempts failed after %d rounds: %w", maxAttempts, lastErr)
}

// GetPublicIP returns the current public IP address (prefers IPv4).
// IPv4 and IPv6 lookups run in parallel. On v4 success we return
// immediately without waiting for v6 — on v6-less networks this saves
// the ~30s v6-lookup timeout per call.
//
// The URL globals (IPifyURL, IPify64URL) are snapshotted into locals
// before spawning goroutines so tests swapping the vars during cleanup
// don't race with in-flight requests. Buffered chans (size 1) ensure
// goroutines always finish without blocking, regardless of whether the
// caller reads the result.
func GetPublicIP() (string, error) {
	v4URL, v6URL := IPifyURL, IPify64URL

	type result struct {
		ip  string
		err error
	}

	v4ch := make(chan result, 1)
	v6ch := make(chan result, 1)

	go func() {
		ip, err := getPublicIP(v4URL, "tcp4")
		v4ch <- result{ip, err}
	}()
	go func() {
		ip, err := getPublicIP(v6URL, "tcp6")
		v6ch <- result{ip, err}
	}()

	// Wait for v4 first (preferred). If v4 succeeds, return without
	// waiting for v6 — its goroutine drains into the buffered chan
	// and exits on its own.
	v4 := <-v4ch
	if v4.err == nil {
		return v4.ip, nil
	}
	// v4 failed — fall through to v6.
	v6 := <-v6ch
	if v6.err == nil {
		return v6.ip, nil
	}
	return "", v4.err
}

// CheckIPv6Leak checks if IPv6 traffic is leaking (returns IPv6 address if leaking)
func CheckIPv6Leak() (string, bool) {
	ip, err := GetPublicIPv6()
	if err != nil {
		return "", false // No leak if we can't get IPv6
	}
	if ip != "" {
		return ip, true // Leak detected
	}
	return "", false
}

// CheckInternetConnectivity verifies internet access by trying to reach common servers
func CheckInternetConnectivity() bool {
	// Try multiple endpoints
	endpoints := []string{
		"8.8.8.8:53",        // Google DNS
		"1.1.1.1:53",        // Cloudflare DNS
		"9.9.9.9:53",        // Quad9 DNS
		"208.67.222.222:53", // OpenDNS
	}

	for _, endpoint := range endpoints {
		conn, err := net.DialTimeout("tcp", endpoint, 3*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// WaitForConnectivity waits for internet connectivity with retries
func WaitForConnectivity(maxAttempts int, interval time.Duration) bool {
	for i := 0; i < maxAttempts; i++ {
		if CheckInternetConnectivity() {
			return true
		}
		if i < maxAttempts-1 {
			time.Sleep(interval)
		}
	}
	return false
}

package latency

import (
	"fmt"
	cryptorand "crypto/rand"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
	probing "github.com/prometheus-community/pro-bing"
)

// Go 1.20+ auto-seeds math/rand from crypto/rand

// Pinger abstracts the pro-bing pinger for testing.
type Pinger interface {
	SetCount(int)
	SetTimeout(time.Duration)
	SetPrivileged(bool)
	Run() error
	Statistics() *probing.Statistics
}

// pingerWrapper wraps *probing.Pinger to implement our Pinger interface
type pingerWrapper struct {
	p *probing.Pinger
}

func (pw *pingerWrapper) SetCount(n int)                  { pw.p.Count = n }
func (pw *pingerWrapper) SetTimeout(d time.Duration)      { pw.p.Timeout = d }
func (pw *pingerWrapper) SetPrivileged(b bool)            { pw.p.SetPrivileged(b) }
func (pw *pingerWrapper) Run() error                      { return pw.p.Run() }
func (pw *pingerWrapper) Statistics() *probing.Statistics { return pw.p.Statistics() }

var newPinger = func(addr string) (Pinger, error) {
	p, err := probing.NewPinger(addr)
	if err != nil {
		return nil, err
	}
	return &pingerWrapper{p: p}, nil
}

// ServerEntry represents a server to test
type ServerEntry struct {
	Type     string // "manual" or "dynamic"
	Provider string // provider name for dynamic servers
	Name     string // server name
	IP       string // IP address to ping
}

// TestResult holds the latency test result for a server
type TestResult struct {
	Server  ServerEntry
	Latency int // milliseconds, -1 if unreachable
	Success bool
}

// ProgressCallback is called with progress updates during testing
type ProgressCallback func(tested, total, reachable int)

// TestAllServers tests latency to all available servers
func TestAllServers(cfg *config.Config, batchSize int, progress ProgressCallback) ([]TestResult, error) {
	servers := collectServers(cfg)
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers found")
	}

	results := make([]TestResult, 0, len(servers))
	reachable := 0

	// Process in batches
	for i := 0; i < len(servers); i += batchSize {
		end := i + batchSize
		if end > len(servers) {
			end = len(servers)
		}

		batch := servers[i:end]
		batchResults := testBatch(batch)

		for _, result := range batchResults {
			results = append(results, result)
			if result.Success {
				reachable++
			}
		}

		if progress != nil {
			progress(end, len(servers), reachable)
		}
	}

	return results, nil
}

// testBatch tests a batch of servers in parallel
func testBatch(servers []ServerEntry) []TestResult {
	results := make([]TestResult, len(servers))
	var wg sync.WaitGroup

	for i, server := range servers {
		wg.Add(1)
		go func(idx int, srv ServerEntry) {
			defer wg.Done()
			latency := PingServer(srv.IP)
			results[idx] = TestResult{
				Server:  srv,
				Latency: latency,
				Success: latency >= 0,
			}
		}(i, server)
	}

	wg.Wait()
	return results
}

// ProbePing tries a single privileged ICMP ping to check if raw sockets work.
// Returns true if privileged ping is available (CAP_NET_RAW or root).
func ProbePing() bool {
	p, err := newPinger("127.0.0.1")
	if err != nil {
		return false
	}
	p.SetCount(1)
	p.SetTimeout(1 * time.Second)
	p.SetPrivileged(true)
	return p.Run() == nil
}

// ProbePingUnprivileged tries a single unprivileged ICMP ping to check if
// datagram sockets work. Returns true if unprivileged ping is available
// (requires net.ipv4.ping_group_range to include the user's GID).
func ProbePingUnprivileged() bool {
	p, err := newPinger("127.0.0.1")
	if err != nil {
		return false
	}
	p.SetCount(1)
	p.SetTimeout(1 * time.Second)
	p.SetPrivileged(false)
	return p.Run() == nil
}

// PingServerUnprivileged pings a server using unprivileged ICMP sockets.
// Does not require CAP_NET_RAW but needs net.ipv4.ping_group_range to
// include the user's GID (default on Arch Linux).
// Returns average latency in ms, or -1 if unreachable.
func PingServerUnprivileged(ip string) int {
	pinger, err := newPinger(ip)
	if err != nil {
		return -1
	}

	pinger.SetCount(2)
	pinger.SetTimeout(2 * time.Second)
	pinger.SetPrivileged(false)

	if err := pinger.Run(); err != nil {
		return -1
	}

	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return -1
	}

	return int(stats.AvgRtt.Milliseconds())
}

// PingServer pings a server and returns average latency in ms using native ICMP.
// Returns -1 if the server is unreachable. Requires CAP_NET_RAW or root.
func PingServer(ip string) int {
	pinger, err := newPinger(ip)
	if err != nil {
		return -1
	}

	pinger.SetCount(2)
	pinger.SetTimeout(2 * time.Second)
	pinger.SetPrivileged(true) // Use raw ICMP socket (requires CAP_NET_RAW or root)

	err = pinger.Run()
	if err != nil {
		return -1
	}

	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return -1
	}

	// Return average RTT in milliseconds
	return int(stats.AvgRtt.Milliseconds())
}

// collectServers gathers all available servers from manual configs and dynamic caches
func collectServers(cfg *config.Config) []ServerEntry {
	var servers []ServerEntry

	// Manual configs
	wgDir := filepath.Join(cfg.ConfigDir, "wireguard")
	configs, _ := wireguard.ListConfigs(wgDir)
	for _, wgCfg := range configs {
		ip := wgCfg.EndpointIP()
		if ip != "" {
			servers = append(servers, ServerEntry{
				Type: "manual",
				Name: wgCfg.Name,
				IP:   ip,
			})
		}
	}

	// Dynamic servers from configured providers
	providers, _ := config.ListProviders(cfg.ConfigDir)
	for _, provider := range providers {
		cachedServers, err := config.LoadServerCache(cfg.ConfigDir, provider)
		if err != nil {
			continue
		}
		for _, srv := range cachedServers {
			if srv.IP != "" {
				name := srv.ServerName
				if name == "" {
					name = srv.Hostname
				}
				servers = append(servers, ServerEntry{
					Type:     "dynamic",
					Provider: provider,
					Name:     name,
					IP:       srv.IP,
				})
			}
		}
	}

	return servers
}

// FindQuickestServer finds the server with lowest latency
func FindQuickestServer(cfg *config.Config, batchSize int, progress ProgressCallback) (*ServerEntry, int, error) {
	results, err := TestAllServers(cfg, batchSize, progress)
	if err != nil {
		return nil, 0, err
	}

	var best *TestResult
	for i := range results {
		if results[i].Success {
			if best == nil || results[i].Latency < best.Latency {
				best = &results[i]
			}
		}
	}

	if best == nil {
		return nil, 0, fmt.Errorf("no reachable servers found")
	}

	return &best.Server, best.Latency, nil
}

// GetRandomServer returns a random server from all available servers.
// Uses crypto/rand: VPN server selection is a privacy-sensitive choice and
// math/rand's seeded PRNG can theoretically be replayed by an attacker who
// knows the process start time + a few prior selections. crypto/rand has
// no such correlation. The performance cost (a single getrandom syscall)
// is negligible for an interactive command.
func GetRandomServer(cfg *config.Config) (*ServerEntry, error) {
	servers := collectServers(cfg)
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers found")
	}

	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(len(servers))))
	if err != nil {
		// Per docs: only fails if the OS RNG is broken (extremely unlikely).
		// Surface as error rather than silently picking servers[0].
		return nil, fmt.Errorf("crypto/rand failed: %w", err)
	}

	return &servers[n.Int64()], nil
}

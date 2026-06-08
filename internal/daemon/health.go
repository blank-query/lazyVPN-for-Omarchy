package daemon

import (
	"math"
	"time"
)

const (
	pingWindowSize = 20 // sliding window for packet loss calculation
)

// healthTracker computes health scores from raw probe data.
// All methods are called from the daemon's select loop (single goroutine),
// except computeScore which is also called from sendStatus under stateMu.
// The caller must hold stateMu when accessing the tracker from client goroutines.
type healthTracker struct {
	// Handshake
	lastHandshake time.Time

	// DNS
	dnsConsecFails int

	// Ping / latency (circular buffer)
	pingResults [pingWindowSize]pingResult
	pingIdx     int
	pingCount   int

	// Network stats (for broadcasting to dashboard)
	rxBytes        uint64
	txBytes        uint64
	rxPackets      uint64
	txPackets      uint64
	statsTimestamp time.Time

	// WireGuard peer info
	endpoint string
}

type pingResult struct {
	ok        bool
	latencyMs int
}

func newHealthTracker() *healthTracker {
	return &healthTracker{}
}

// recordHandshake updates the last handshake time from wgctrl.
func (h *healthTracker) recordHandshake(t time.Time) {
	h.lastHandshake = t
}

// recordStats updates network stats from netlink.
func (h *healthTracker) recordStats(rx, tx uint64, rxPkt, txPkt uint64, ts time.Time) {
	h.rxBytes = rx
	h.txBytes = tx
	h.rxPackets = rxPkt
	h.txPackets = txPkt
	h.statsTimestamp = ts
}

// recordEndpoint updates the peer endpoint string.
func (h *healthTracker) recordEndpoint(ep string) {
	h.endpoint = ep
}

// recordPing records a TCP ping result into the sliding window.
func (h *healthTracker) recordPing(ok bool, latencyMs int) {
	h.pingResults[h.pingIdx] = pingResult{ok: ok, latencyMs: latencyMs}
	h.pingIdx = (h.pingIdx + 1) % pingWindowSize
	if h.pingCount < pingWindowSize {
		h.pingCount++
	}
}

// recordDNS records a DNS probe result.
// On failure, consecutive fail counter increments.
// On success, it resets to zero.
func (h *healthTracker) recordDNS(ok bool) {
	if ok {
		h.dnsConsecFails = 0
	} else {
		h.dnsConsecFails++
	}
}

// computeScore computes a HealthState snapshot from current tracker state.
func (h *healthTracker) computeScore() HealthState {
	hs := HealthState{
		HandshakeScore:  h.handshakeScore(),
		DNSScore:        h.dnsScore(),
		LatencyScore:    h.latencyScore(),
		PacketLossScore: h.packetLossScore(),

		HandshakeAgeSec: h.handshakeAgeSec(),
		LatencyMs:       h.lastLatencyMs(),
		PacketLossPct:   h.packetLossPct(),
		DNSConsecFails:  h.dnsConsecFails,

		RxBytes:        h.rxBytes,
		TxBytes:        h.txBytes,
		RxPackets:      h.rxPackets,
		TxPackets:      h.txPackets,
		StatsTimestamp: h.statsTimestamp,

		Endpoint:      h.endpoint,
		LastHandshake: h.lastHandshake,
	}

	hs.Score = (hs.HandshakeScore + hs.DNSScore + hs.LatencyScore + hs.PacketLossScore) / 4
	if hs.Score > 100 {
		hs.Score = 100
	}

	switch {
	case hs.Score >= 90:
		hs.Grade = "Excellent"
	case hs.Score >= 80:
		hs.Grade = "Good"
	case hs.Score >= 70:
		hs.Grade = "Fair"
	case hs.Score >= 60:
		hs.Grade = "Poor"
	default:
		hs.Grade = "Bad"
	}

	return hs
}

// reset clears all tracker state (call on connect/disconnect).
func (h *healthTracker) reset() {
	h.lastHandshake = time.Time{}
	h.dnsConsecFails = 0
	h.pingIdx = 0
	h.pingCount = 0
	h.pingResults = [pingWindowSize]pingResult{}
	h.rxBytes = 0
	h.txBytes = 0
	h.rxPackets = 0
	h.txPackets = 0
	h.statsTimestamp = time.Time{}
	h.endpoint = ""
}

// --- Scoring functions ---

// handshakeScore: 100 if <3min, linear decay 3-7min, 0 if >7min or zero.
func (h *healthTracker) handshakeScore() int {
	if h.lastHandshake.IsZero() {
		// New peer with no handshake yet — give benefit of doubt
		return 100
	}
	ageSec := time.Since(h.lastHandshake).Seconds()
	ageMin := ageSec / 60.0

	if ageMin < 3 {
		return 100
	}
	if ageMin > 7 {
		return 0
	}
	// Linear decay from 100 at 3min to 0 at 7min
	return int(math.Round(100 * (7 - ageMin) / 4))
}

// dnsScore: starts at 100, drops 33 per consecutive failure, minimum 0.
func (h *healthTracker) dnsScore() int {
	if h.dnsConsecFails == 0 {
		return 100
	}
	score := 100 - h.dnsConsecFails*33
	if score < 0 {
		return 0
	}
	return score
}

// latencyScore: 100 if <100ms, linear decay to 50 at 300ms, to 0 at 1000ms.
func (h *healthTracker) latencyScore() int {
	ms := h.lastLatencyMs()
	if ms <= 0 {
		// No ping data yet — benefit of doubt
		return 100
	}
	if ms <= 100 {
		return 100
	}
	if ms <= 300 {
		// Linear from 100 at 100ms to 50 at 300ms
		return int(math.Round(100 - 50*float64(ms-100)/200))
	}
	if ms >= 1000 {
		return 0
	}
	// Linear from 50 at 300ms to 0 at 1000ms
	return int(math.Round(50 * float64(1000-ms) / 700))
}

// packetLossScore: (successes / total) * 100 over sliding window.
func (h *healthTracker) packetLossScore() int {
	if h.pingCount == 0 {
		// No data yet — benefit of doubt
		return 100
	}
	successes := 0
	for i := 0; i < h.pingCount; i++ {
		if h.pingResults[i].ok {
			successes++
		}
	}
	return int(math.Round(float64(successes) / float64(h.pingCount) * 100))
}

// --- Helper methods ---

func (h *healthTracker) handshakeAgeSec() float64 {
	if h.lastHandshake.IsZero() {
		return 0
	}
	return time.Since(h.lastHandshake).Seconds()
}

// lastLatencyMs returns the most recent successful ping latency, or 0 if none.
func (h *healthTracker) lastLatencyMs() int {
	if h.pingCount == 0 {
		return 0
	}
	// Walk backward from most recent
	for i := 0; i < h.pingCount; i++ {
		idx := (h.pingIdx - 1 - i + pingWindowSize) % pingWindowSize
		if h.pingResults[idx].ok {
			return h.pingResults[idx].latencyMs
		}
	}
	return 0
}

// packetLossPct returns the packet loss percentage over the sliding window.
func (h *healthTracker) packetLossPct() float64 {
	if h.pingCount == 0 {
		return 0
	}
	failures := 0
	for i := 0; i < h.pingCount; i++ {
		if !h.pingResults[i].ok {
			failures++
		}
	}
	return float64(failures) / float64(h.pingCount) * 100
}

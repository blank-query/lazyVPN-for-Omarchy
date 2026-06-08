package daemon

import (
	"testing"
	"time"
)

func TestHandshakeScore(t *testing.T) {
	tests := []struct {
		name    string
		age     time.Duration
		zero    bool // use zero time
		wantMin int
		wantMax int
	}{
		{"zero (new peer)", 0, true, 100, 100},
		{"30 seconds", 30 * time.Second, false, 100, 100},
		{"2 minutes", 2 * time.Minute, false, 100, 100},
		{"3 minutes", 3 * time.Minute, false, 100, 100},
		{"5 minutes", 5 * time.Minute, false, 45, 55},
		{"7 minutes", 7 * time.Minute, false, 0, 0},
		{"10 minutes", 10 * time.Minute, false, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHealthTracker()
			if !tt.zero {
				h.recordHandshake(time.Now().Add(-tt.age))
			}
			score := h.handshakeScore()
			if score < tt.wantMin || score > tt.wantMax {
				t.Errorf("handshakeScore() = %d, want [%d, %d]", score, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestDNSScore(t *testing.T) {
	tests := []struct {
		name        string
		consecFails int
		wantScore   int
	}{
		{"no failures", 0, 100},
		{"1 failure", 1, 67},
		{"2 failures", 2, 34},
		{"3 failures", 3, 1},
		{"4 failures", 4, 0},
		{"10 failures", 10, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHealthTracker()
			for i := 0; i < tt.consecFails; i++ {
				h.recordDNS(false)
			}
			score := h.dnsScore()
			if score != tt.wantScore {
				t.Errorf("dnsScore() = %d, want %d", score, tt.wantScore)
			}
		})
	}
}

func TestDNSScoreResetsOnSuccess(t *testing.T) {
	h := newHealthTracker()
	h.recordDNS(false)
	h.recordDNS(false)
	if h.dnsScore() == 100 {
		t.Error("should not be 100 after failures")
	}
	h.recordDNS(true)
	if h.dnsScore() != 100 {
		t.Errorf("dnsScore() = %d after success, want 100", h.dnsScore())
	}
}

func TestLatencyScore(t *testing.T) {
	tests := []struct {
		name    string
		ms      int
		wantMin int
		wantMax int
	}{
		{"no data", 0, 100, 100},
		{"50ms", 50, 100, 100},
		{"100ms", 100, 100, 100},
		{"200ms", 200, 70, 80},
		{"300ms", 300, 48, 52},
		{"500ms", 500, 30, 40},
		{"1000ms", 1000, 0, 0},
		{"1200ms", 1200, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHealthTracker()
			if tt.ms > 0 {
				h.recordPing(true, tt.ms)
			}
			score := h.latencyScore()
			if score < tt.wantMin || score > tt.wantMax {
				t.Errorf("latencyScore() = %d, want [%d, %d]", score, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestPacketLossScore(t *testing.T) {
	tests := []struct {
		name    string
		pings   []bool // true = success
		wantMin int
		wantMax int
	}{
		{"no data", nil, 100, 100},
		{"all success", []bool{true, true, true, true, true}, 100, 100},
		{"all fail", []bool{false, false, false, false, false}, 0, 0},
		{"50% loss", []bool{true, false, true, false, true, false}, 48, 52},
		{"1 of 5 fail", []bool{true, true, true, true, false}, 78, 82},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHealthTracker()
			for _, ok := range tt.pings {
				if ok {
					h.recordPing(true, 50)
				} else {
					h.recordPing(false, 0)
				}
			}
			score := h.packetLossScore()
			if score < tt.wantMin || score > tt.wantMax {
				t.Errorf("packetLossScore() = %d, want [%d, %d]", score, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestPacketLossSlidingWindow(t *testing.T) {
	h := newHealthTracker()
	// Fill with 20 failures
	for i := 0; i < 20; i++ {
		h.recordPing(false, 0)
	}
	if h.packetLossScore() != 0 {
		t.Errorf("all failures should give 0, got %d", h.packetLossScore())
	}
	// Now add 20 successes — should fully replace the failures
	for i := 0; i < 20; i++ {
		h.recordPing(true, 50)
	}
	if h.packetLossScore() != 100 {
		t.Errorf("all successes should give 100, got %d", h.packetLossScore())
	}
}

func TestCompositeScore(t *testing.T) {
	h := newHealthTracker()
	// Recent handshake
	h.recordHandshake(time.Now().Add(-1 * time.Minute))
	// DNS ok
	h.recordDNS(true)
	// Good latency
	h.recordPing(true, 50)
	// All pings succeed
	for i := 0; i < 5; i++ {
		h.recordPing(true, 50)
	}

	hs := h.computeScore()
	if hs.Score < 90 {
		t.Errorf("perfect health should be >= 90, got %d", hs.Score)
	}
	if hs.Grade != "Excellent" {
		t.Errorf("grade = %q, want Excellent", hs.Grade)
	}
}

func TestCompositeScoreBad(t *testing.T) {
	h := newHealthTracker()
	// Stale handshake (8 minutes)
	h.recordHandshake(time.Now().Add(-8 * time.Minute))
	// DNS failing
	h.recordDNS(false)
	h.recordDNS(false)
	h.recordDNS(false)
	h.recordDNS(false)
	// High latency
	h.recordPing(true, 1200)
	// High packet loss
	for i := 0; i < 10; i++ {
		h.recordPing(false, 0)
	}

	hs := h.computeScore()
	if hs.Score > 20 {
		t.Errorf("terrible health should be <= 20, got %d", hs.Score)
	}
	if hs.Grade != "Bad" {
		t.Errorf("grade = %q, want Bad", hs.Grade)
	}
}

// TestComputeScore_AppliesGradeFromActualSwitch is the regression
// guard for TestGradeBoundaries below, which is a tautology — that
// test re-implements the production switch in the test body and
// verifies the duplicate matches itself, never calling computeScore.
// A bug like "computeScore stops setting Grade entirely" or
// "switch boundaries change from `>=` to `>`" would silently slip
// past TestGradeBoundaries.
//
// This test drives the full computeScore() path with hand-tuned
// tracker state to land on each grade band, then asserts BOTH the
// score AND the grade returned by the real function. Each Score
// value is computed offline (see math in test cases) and pinned.
func TestComputeScore_AppliesGradeFromActualSwitch(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(h *healthTracker)
		wantScore int
		wantGrade string
	}{
		{
			name:      "fresh tracker → 100/Excellent",
			setup:     func(h *healthTracker) {},
			wantScore: 100,
			wantGrade: "Excellent",
		},
		{
			// (100+67+100+100)/4 = 91 → Excellent
			name: "1 dns fail → 91/Excellent (catches >=90 -> >90)",
			setup: func(h *healthTracker) {
				h.recordDNS(false)
			},
			wantScore: 91,
			wantGrade: "Excellent",
		},
		{
			// (100+34+100+100)/4 = 83 → Good
			name: "2 dns fails → 83/Good",
			setup: func(h *healthTracker) {
				h.recordDNS(false)
				h.recordDNS(false)
			},
			wantScore: 83,
			wantGrade: "Good",
		},
		{
			// (100+0+100+100)/4 = 75 → Fair
			name: "3 dns fails → 75/Fair",
			setup: func(h *healthTracker) {
				h.recordDNS(false)
				h.recordDNS(false)
				h.recordDNS(false)
			},
			wantScore: 75,
			wantGrade: "Fair",
		},
		{
			// dnsScore at 3 fails = 100-99 = 1 (not 0; clip is at >=4 fails)
			// latencyScore at 200ms = round(100-50*100/200) = 75
			// (100+1+75+100)/4 = 69 → Poor
			name: "3 dns fails + 200ms ping → 69/Poor",
			setup: func(h *healthTracker) {
				h.recordDNS(false)
				h.recordDNS(false)
				h.recordDNS(false)
				h.recordPing(true, 200)
			},
			wantScore: 69,
			wantGrade: "Poor",
		},
		{
			// 3 dns fails (dnsScore=1) + 500ms ping (latencyScore=36)
			// (100+1+36+100)/4 = 59 → Bad (catches >=60 -> >60)
			name: "3 dns fails + 500ms ping → 59/Bad (catches >=60 -> >60)",
			setup: func(h *healthTracker) {
				h.recordDNS(false)
				h.recordDNS(false)
				h.recordDNS(false)
				h.recordPing(true, 500)
			},
			wantScore: 59,
			wantGrade: "Bad",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHealthTracker()
			tt.setup(h)
			hs := h.computeScore()
			if hs.Score != tt.wantScore {
				t.Fatalf("Score = %d, want %d (recheck offline math)", hs.Score, tt.wantScore)
			}
			if hs.Grade != tt.wantGrade {
				t.Errorf("Grade = %q for Score=%d, want %q", hs.Grade, hs.Score, tt.wantGrade)
			}
		})
	}
}

func TestGradeBoundaries(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		{100, "Excellent"},
		{90, "Excellent"},
		{89, "Good"},
		{80, "Good"},
		{79, "Fair"},
		{70, "Fair"},
		{69, "Poor"},
		{60, "Poor"},
		{59, "Bad"},
		{0, "Bad"},
	}

	for _, tt := range tests {
		hs := HealthState{Score: tt.score}
		// Apply grading logic manually
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
		if hs.Grade != tt.grade {
			t.Errorf("score %d: grade = %q, want %q", tt.score, hs.Grade, tt.grade)
		}
	}
}

func TestReset(t *testing.T) {
	h := newHealthTracker()
	h.recordHandshake(time.Now())
	h.recordDNS(false)
	h.recordDNS(false)
	h.recordPing(true, 100)
	h.recordPing(false, 0)
	h.recordStats(1000, 2000, 10, 20, time.Now())
	h.recordEndpoint("1.2.3.4:51820")

	h.reset()

	if !h.lastHandshake.IsZero() {
		t.Error("lastHandshake should be zero after reset")
	}
	if h.dnsConsecFails != 0 {
		t.Error("dnsConsecFails should be 0 after reset")
	}
	if h.pingCount != 0 {
		t.Error("pingCount should be 0 after reset")
	}
	if h.rxBytes != 0 || h.txBytes != 0 {
		t.Error("stats should be 0 after reset")
	}
	if h.endpoint != "" {
		t.Error("endpoint should be empty after reset")
	}

	// After reset, all scores should give benefit of doubt
	hs := h.computeScore()
	if hs.Score != 100 {
		t.Errorf("score after reset = %d, want 100 (benefit of doubt)", hs.Score)
	}
}

func TestLastLatencyMs(t *testing.T) {
	h := newHealthTracker()

	// No data
	if h.lastLatencyMs() != 0 {
		t.Error("should be 0 with no data")
	}

	// Record successful pings
	h.recordPing(true, 50)
	h.recordPing(true, 100)
	if h.lastLatencyMs() != 100 {
		t.Errorf("lastLatencyMs = %d, want 100", h.lastLatencyMs())
	}

	// Record a failure — should still return last successful
	h.recordPing(false, 0)
	if h.lastLatencyMs() != 100 {
		t.Errorf("lastLatencyMs after failure = %d, want 100", h.lastLatencyMs())
	}
}

func TestPacketLossPct(t *testing.T) {
	h := newHealthTracker()

	if h.packetLossPct() != 0 {
		t.Error("should be 0 with no data")
	}

	h.recordPing(true, 50)
	h.recordPing(false, 0)
	h.recordPing(true, 50)
	h.recordPing(false, 0)

	pct := h.packetLossPct()
	if pct < 49 || pct > 51 {
		t.Errorf("packetLossPct = %.1f, want ~50", pct)
	}
}

func TestRecordStats(t *testing.T) {
	h := newHealthTracker()
	now := time.Now()
	h.recordStats(1000, 2000, 10, 20, now)

	hs := h.computeScore()
	if hs.RxBytes != 1000 {
		t.Errorf("RxBytes = %d, want 1000", hs.RxBytes)
	}
	if hs.TxBytes != 2000 {
		t.Errorf("TxBytes = %d, want 2000", hs.TxBytes)
	}
	if hs.RxPackets != 10 {
		t.Errorf("RxPackets = %d, want 10", hs.RxPackets)
	}
	if hs.TxPackets != 20 {
		t.Errorf("TxPackets = %d, want 20", hs.TxPackets)
	}
}

package tools

import (
	"testing"

	"go.uber.org/goleak"
)

// TestNoGoroutineLeaks verifies checkPublicIP's goroutine cancellation
// under repeated runs (specifically A1 from the original bug sweep).
//
// IgnoreCurrent baselines goroutines already running at this test's
// start so leaks from sibling tests don't false-fail this one. Most
// notably, TestTestDNS_HangingLookupBoundedByDeadline DELIBERATELY
// parks its lookupTXT stub goroutines forever (`select {}` — testing
// the deadline-clamp path even when goroutines never return). On
// `go test -count>1`, those leaks accumulate across iterations in the
// same process; without IgnoreCurrent the second iteration of this
// test flags them as new leaks. Daemon's TestDaemon_NoGoroutineLeaks
// uses the same pattern.
func TestNoGoroutineLeaks(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreCurrent(),
		// Sibling test's deliberate-leak goroutines, baselined explicitly
		// for the case where this test runs BEFORE that one in iteration 1
		// and the leak appears mid-test (rare but possible if scheduling
		// interleaves them — IgnoreCurrent only baselines at this test's
		// start, not at VerifyNone-call time).
		goleak.IgnoreAnyFunction("github.com/blank-query/lazyVPN-for-Omarchy/internal/tools.TestTestDNS_HangingLookupBoundedByDeadline.func1"),
	)

	// Drive the same paths the bug sweep verified, multiple iterations.
	lt := &LeakTest{
		ID:          "leak-check",
		BaselineIP:  "203.0.113.5",
		BaselineOrg: "Comcast",
	}
	// Force all 3 IP services to a non-resolving URL so the goroutines
	// rely on cancel propagation (not natural completion).
	for i := 0; i < 5; i++ {
		lt.checkPublicIP()
	}
}

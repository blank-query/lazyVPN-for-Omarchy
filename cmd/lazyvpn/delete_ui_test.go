package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/security"
)

// --- helpers ---

// withReader returns a *bufio.Reader backed by the supplied input. Tests
// feed prompt answers this way to exercise handleFailures.
func withReader(input string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(input))
}

// mockDelete returns a deleteFn that produces canned outcomes in order.
// Each call consumes len(files) entries; if the script runs out, the test
// fails. Handy for driving handleFailures retries.
func mockDelete(t *testing.T, scripted []security.DeleteEvent) deleteFn {
	t.Helper()
	cursor := 0
	return func(files []string, mode security.SudoMode) security.DeleteResult {
		t.Helper()
		res := security.DeleteResult{}
		for _, f := range files {
			if cursor >= len(scripted) {
				t.Fatalf("mockDelete ran out of scripted events at file %q", f)
			}
			e := scripted[cursor]
			cursor++
			// Fill in path for convenience so tests don't have to.
			if e.Path == "" {
				e.Path = f
			}
			res.Events = append(res.Events, e)
			switch e.Outcome {
			case security.Deleted:
				res.Deleted++
			case security.NotPresent:
				res.NotPresent++
			case security.Failed:
				res.Failed++
			}
		}
		return res
	}
}

// --- reportDelete ---

func TestReportDeleteFormats(t *testing.T) {
	cases := []struct {
		name  string
		event security.DeleteEvent
		want  string
	}{
		{
			"shredded",
			security.DeleteEvent{Path: "/a", Mode: "shred", Outcome: security.Deleted},
			"  - shredded /a\n",
		},
		{
			"shredded sudo",
			security.DeleteEvent{Path: "/a", Mode: "sudo-shred", Outcome: security.Deleted},
			"  - shredded (sudo) /a\n",
		},
		{
			"removed",
			security.DeleteEvent{Path: "/a", Mode: "rm", Outcome: security.Deleted},
			"  - removed /a\n",
		},
		{
			"removed sudo",
			security.DeleteEvent{Path: "/a", Mode: "sudo-rm", Outcome: security.Deleted},
			"  - removed (sudo) /a\n",
		},
		{
			"not present",
			security.DeleteEvent{Path: "/a", Mode: "rm", Outcome: security.NotPresent},
			"  - file not found: /a\n",
		},
		{
			"failed with error",
			security.DeleteEvent{Path: "/a", Mode: "shred", Outcome: security.Failed, Err: errors.New("permission denied")},
			"  ✗ failed: /a\n      permission denied\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			reportDelete(&buf, c.event)
			if buf.String() != c.want {
				t.Errorf("got %q, want %q", buf.String(), c.want)
			}
		})
	}
}

// --- handleFailures ---

func TestHandleFailuresRetrySucceedsFirstTry(t *testing.T) {
	ctx := deleteContext{primary: ShredMode}
	result := security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "shred", Outcome: security.Failed, Err: errors.New("busy")},
		},
		Failed: 1,
	}
	secure := mockDelete(t, []security.DeleteEvent{
		{Mode: "sudo-shred", Outcome: security.Deleted},
	})
	plain := mockDelete(t, nil)

	var out bytes.Buffer
	skipped := handleFailures(&out, withReader("1\n"), &result, secure, plain, ctx)

	if len(skipped) != 0 {
		t.Errorf("skipped = %v, want empty", skipped)
	}
	if result.Failed != 1 || result.Deleted != 1 {
		t.Errorf("counters after retry: Deleted=%d Failed=%d; want Deleted=1 Failed=1 (original + retry event)", result.Deleted, result.Failed)
	}
	// Final per-file resolution should pick the retry's Deleted event.
	if resolveStep(result, nil, ctx).shredded != 1 {
		t.Errorf("expected shredded=1 after successful retry, got %+v", resolveStep(result, nil, ctx))
	}
}

func TestHandleFailuresRetryFailsThenRmSucceeds(t *testing.T) {
	ctx := deleteContext{primary: ShredMode}
	result := security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "shred", Outcome: security.Failed, Err: errors.New("busy")},
		},
		Failed: 1,
	}
	// First retry (shred) still fails; second retry via rm succeeds.
	secure := mockDelete(t, []security.DeleteEvent{
		{Mode: "sudo-shred", Outcome: security.Failed, Err: errors.New("still busy")},
	})
	plain := mockDelete(t, []security.DeleteEvent{
		{Mode: "sudo-rm", Outcome: security.Deleted},
	})

	var out bytes.Buffer
	// User picks [1] (retry), then [1] again — after retry consumed,
	// the option list is [rm-fallback, skip]; [1] selects rm-fallback.
	skipped := handleFailures(&out, withReader("1\n1\n"), &result, secure, plain, ctx)

	if len(skipped) != 0 {
		t.Errorf("skipped = %v, want empty", skipped)
	}
	// The final resolution for /a should be rm-fallback (bug-worthy).
	res := resolveStep(result, skipped, ctx)
	if res.removedFallback != 1 || len(res.rmFallbackPaths) != 1 || res.rmFallbackPaths[0] != "/a" {
		t.Errorf("expected 1 rm-fallback for /a, got %+v", res)
	}
}

func TestHandleFailuresSkipExits(t *testing.T) {
	ctx := deleteContext{primary: ShredMode}
	result := security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "shred", Outcome: security.Failed, Err: errors.New("oops")},
			{Path: "/b", Mode: "shred", Outcome: security.Failed, Err: errors.New("oops")},
		},
		Failed: 2,
	}
	secure := mockDelete(t, nil)
	plain := mockDelete(t, nil)

	var out bytes.Buffer
	// Non-CoW offered = [retry, rm-fallback, skip]; "3" = skip.
	skipped := handleFailures(&out, withReader("3\n"), &result, secure, plain, ctx)

	if len(skipped) != 2 {
		t.Errorf("skipped = %v, want 2 entries", skipped)
	}
}

func TestHandleFailuresInvalidInputReprompts(t *testing.T) {
	ctx := deleteContext{primary: RmMode}
	result := security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "rm", Outcome: security.Failed, Err: errors.New("x")},
		},
		Failed: 1,
	}
	secure := mockDelete(t, nil)
	plain := mockDelete(t, []security.DeleteEvent{
		{Mode: "sudo-rm", Outcome: security.Deleted},
	})

	var out bytes.Buffer
	// Feed: "99\n" (invalid), then "foo\n" (invalid), then "1\n" (retry).
	skipped := handleFailures(&out, withReader("99\nfoo\n1\n"), &result, secure, plain, ctx)

	if len(skipped) != 0 {
		t.Errorf("skipped = %v, want empty", skipped)
	}
	if !strings.Contains(out.String(), "Invalid input") {
		t.Errorf("expected invalid-input message in output:\n%s", out.String())
	}
}

func TestHandleFailuresEOFSkipsRemaining(t *testing.T) {
	ctx := deleteContext{primary: ShredMode}
	result := security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "shred", Outcome: security.Failed, Err: errors.New("x")},
		},
		Failed: 1,
	}
	// Empty reader → immediate EOF.
	skipped := handleFailures(new(bytes.Buffer), withReader(""), &result,
		mockDelete(t, nil), mockDelete(t, nil), ctx)
	if len(skipped) != 1 || skipped[0] != "/a" {
		t.Errorf("EOF should skip remaining, got %v", skipped)
	}
}

func TestHandleFailuresEnterSelectsFirstOption(t *testing.T) {
	ctx := deleteContext{primary: RmMode}
	result := security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "rm", Outcome: security.Failed, Err: errors.New("x")},
		},
		Failed: 1,
	}
	secure := mockDelete(t, nil)
	plain := mockDelete(t, []security.DeleteEvent{
		{Mode: "sudo-rm", Outcome: security.Deleted},
	})

	// Bare newline → default to [1] (retry).
	skipped := handleFailures(new(bytes.Buffer), withReader("\n"), &result, secure, plain, ctx)
	if len(skipped) != 0 {
		t.Errorf("expected no skips when Enter selects retry, got %v", skipped)
	}
}

func TestHandleFailuresCoWOnlyRetryAndSkip(t *testing.T) {
	ctx := deleteContext{primary: RmMode}
	result := security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "rm", Outcome: security.Failed, Err: errors.New("x")},
		},
		Failed: 1,
	}
	secure := mockDelete(t, nil)
	plain := mockDelete(t, nil) // no retry attempt — first pick is skip

	var out bytes.Buffer
	// CoW offered = [retry, skip]; "2" = skip.
	skipped := handleFailures(&out, withReader("2\n"), &result, secure, plain, ctx)
	if len(skipped) != 1 {
		t.Errorf("skipped = %v, want [/a]", skipped)
	}
	// Verify no rm-fallback line was offered on CoW.
	if strings.Contains(out.String(), "Fall back to rm") {
		t.Error("CoW variant should not offer rm-fallback option")
	}
}

// --- printStepSummary ---

func TestPrintStepSummaryClean(t *testing.T) {
	ctx := deleteContext{primary: ShredMode}
	result := security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "shred", Outcome: security.Deleted},
			{Path: "/b", Mode: "shred", Outcome: security.Deleted},
			{Path: "/c", Mode: "shred", Outcome: security.NotPresent},
		},
	}
	var buf bytes.Buffer
	printStepSummary(&buf, result, nil, ctx)
	got := buf.String()
	if !strings.Contains(got, "✓ 3 file(s) processed") {
		t.Errorf("missing clean marker:\n%s", got)
	}
	if !strings.Contains(got, "2 shredded") {
		t.Errorf("missing shredded count:\n%s", got)
	}
	if !strings.Contains(got, "1 not present") {
		t.Errorf("missing not-present count:\n%s", got)
	}
	if strings.Contains(got, "please report as a bug") {
		t.Errorf("clean summary should not mention bug report:\n%s", got)
	}
}

func TestPrintStepSummaryWithFallback(t *testing.T) {
	ctx := deleteContext{primary: ShredMode}
	// /a shredded, /b went through retry (shred failed) then rm-fallback.
	result := security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "shred", Outcome: security.Deleted},
			{Path: "/b", Mode: "shred", Outcome: security.Failed, Err: errors.New("x")},
			{Path: "/b", Mode: "sudo-rm", Outcome: security.Deleted},
		},
	}
	var buf bytes.Buffer
	printStepSummary(&buf, result, nil, ctx)
	got := buf.String()
	if !strings.Contains(got, "⚠ 2 file(s) processed") {
		t.Errorf("missing warning marker:\n%s", got)
	}
	if !strings.Contains(got, "1 shredded") || !strings.Contains(got, "1 removed (insecure fallback)") {
		t.Errorf("missing mixed counts:\n%s", got)
	}
	if !strings.Contains(got, "/b") || !strings.Contains(got, "please report as a bug") {
		t.Errorf("fallback file should be listed with bug-report note:\n%s", got)
	}
}

func TestPrintStepSummaryWithSkip(t *testing.T) {
	ctx := deleteContext{primary: ShredMode}
	result := security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "shred", Outcome: security.Deleted},
			{Path: "/b", Mode: "shred", Outcome: security.Failed, Err: errors.New("x")},
		},
	}
	var buf bytes.Buffer
	printStepSummary(&buf, result, []string{"/b"}, ctx)
	got := buf.String()
	if !strings.Contains(got, "⚠ 2 file(s) processed") {
		t.Errorf("missing warning marker:\n%s", got)
	}
	if !strings.Contains(got, "1 skipped") {
		t.Errorf("missing skipped count:\n%s", got)
	}
	if !strings.Contains(got, "files were skipped") {
		t.Errorf("skipped list header missing:\n%s", got)
	}
}

func TestPrintStepSummaryZeroEventsPrintsNothing(t *testing.T) {
	ctx := deleteContext{primary: RmMode}
	var buf bytes.Buffer
	printStepSummary(&buf, security.DeleteResult{}, nil, ctx)
	if buf.Len() != 0 {
		t.Errorf("expected no output for empty result, got %q", buf.String())
	}
}

// --- globalSummary ---

func TestGlobalSummaryMergeAcrossSteps(t *testing.T) {
	ctx := deleteContext{primary: ShredMode}
	gs := newGlobalSummary(ctx)

	// Step 1: 2 shredded, 1 not present
	gs.merge(security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "shred", Outcome: security.Deleted},
			{Path: "/b", Mode: "shred", Outcome: security.Deleted},
			{Path: "/c", Mode: "shred", Outcome: security.NotPresent},
		},
	}, nil)

	// Step 2: 1 rm-fallback
	gs.merge(security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/d", Mode: "shred", Outcome: security.Failed, Err: errors.New("x")},
			{Path: "/d", Mode: "sudo-rm", Outcome: security.Deleted},
		},
	}, nil)

	// Step 3: 1 skipped
	gs.merge(security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/e", Mode: "shred", Outcome: security.Failed, Err: errors.New("x")},
		},
	}, []string{"/e"})

	if gs.shredded != 2 {
		t.Errorf("shredded = %d, want 2", gs.shredded)
	}
	if gs.removedFallback != 1 || len(gs.rmFallbackPaths) != 1 {
		t.Errorf("rm fallback counts/paths: %+v", gs)
	}
	if gs.notPresent != 1 {
		t.Errorf("notPresent = %d, want 1", gs.notPresent)
	}
	if gs.skipped != 1 || len(gs.skippedPaths) != 1 {
		t.Errorf("skipped counts/paths: %+v", gs)
	}
}

func TestGlobalSummaryRenderCoW(t *testing.T) {
	gs := newGlobalSummary(deleteContext{primary: RmMode})
	gs.merge(security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "rm", Outcome: security.Deleted},
			{Path: "/b", Mode: "rm", Outcome: security.NotPresent},
		},
	}, nil)

	var buf bytes.Buffer
	gs.render(&buf)
	got := buf.String()
	if !strings.Contains(got, "1 removed") {
		t.Errorf("missing removed count:\n%s", got)
	}
	if !strings.Contains(got, "1 not present") {
		t.Errorf("missing not-present count:\n%s", got)
	}
	if strings.Contains(got, "shredded") {
		t.Errorf("CoW render should not mention shredded:\n%s", got)
	}
	if strings.Contains(got, "please report as a bug") {
		t.Errorf("clean summary should not mention bug report:\n%s", got)
	}
}

func TestGlobalSummaryRenderNonCoWWithFallback(t *testing.T) {
	gs := newGlobalSummary(deleteContext{primary: ShredMode})
	gs.merge(security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "shred", Outcome: security.Deleted},
			{Path: "/b", Mode: "shred", Outcome: security.Failed, Err: errors.New("x")},
			{Path: "/b", Mode: "sudo-rm", Outcome: security.Deleted},
		},
	}, nil)

	var buf bytes.Buffer
	gs.render(&buf)
	got := buf.String()
	if !strings.Contains(got, "1 shredded") || !strings.Contains(got, "1 removed (insecure fallback)") {
		t.Errorf("missing counts:\n%s", got)
	}
	if !strings.Contains(got, "/b") {
		t.Errorf("/b should be listed as rm-fallback bug:\n%s", got)
	}
	if !strings.Contains(got, "please report as a bug") {
		t.Errorf("fallback should include bug-report note:\n%s", got)
	}
}

func TestGlobalSummaryRenderEmpty(t *testing.T) {
	gs := newGlobalSummary(deleteContext{primary: ShredMode})
	var buf bytes.Buffer
	gs.render(&buf)
	if buf.Len() != 0 {
		t.Errorf("expected no output for empty global summary, got %q", buf.String())
	}
}

// --- classifyPath ---

func TestClassifyPathShredModePrimaryWins(t *testing.T) {
	ctx := deleteContext{primary: ShredMode}
	events := []security.DeleteEvent{
		{Mode: "shred", Outcome: security.Failed, Err: errors.New("x")},
		{Mode: "sudo-shred", Outcome: security.Deleted},
	}
	if got := classifyPath(events, ctx); got != kindShredded {
		t.Errorf("got %v, want kindShredded", got)
	}
}

func TestClassifyPathShredModeRmIsFallback(t *testing.T) {
	ctx := deleteContext{primary: ShredMode}
	events := []security.DeleteEvent{
		{Mode: "shred", Outcome: security.Failed, Err: errors.New("x")},
		{Mode: "sudo-rm", Outcome: security.Deleted},
	}
	if got := classifyPath(events, ctx); got != kindRemovedFallback {
		t.Errorf("got %v, want kindRemovedFallback", got)
	}
}

func TestClassifyPathRmModeRmIsPrimary(t *testing.T) {
	ctx := deleteContext{primary: RmMode}
	events := []security.DeleteEvent{
		{Mode: "rm", Outcome: security.Deleted},
	}
	if got := classifyPath(events, ctx); got != kindRemovedPrimary {
		t.Errorf("got %v, want kindRemovedPrimary", got)
	}
}

func TestClassifyPathNotPresentOnly(t *testing.T) {
	ctx := deleteContext{primary: ShredMode}
	events := []security.DeleteEvent{
		{Mode: "shred", Outcome: security.NotPresent},
	}
	if got := classifyPath(events, ctx); got != kindNotPresent {
		t.Errorf("got %v, want kindNotPresent", got)
	}
}

// --- Sanity: counters and ordering invariants ---

func TestAppendRetryEventsUpdatesCounters(t *testing.T) {
	result := security.DeleteResult{}
	retry := security.DeleteResult{
		Events: []security.DeleteEvent{
			{Path: "/a", Mode: "shred", Outcome: security.Deleted},
			{Path: "/b", Mode: "shred", Outcome: security.Failed, Err: errors.New("x")},
			{Path: "/c", Mode: "shred", Outcome: security.NotPresent},
		},
		Deleted: 1, NotPresent: 1, Failed: 1,
	}
	appendRetryEvents(&result, retry)
	if result.Deleted != 1 || result.NotPresent != 1 || result.Failed != 1 {
		t.Errorf("counters after append: %+v", result)
	}
	if len(result.Events) != 3 {
		t.Errorf("expected 3 events, got %d", len(result.Events))
	}
}

func TestUnresolvedFailuresReflectsLatestOutcome(t *testing.T) {
	events := []security.DeleteEvent{
		{Path: "/a", Outcome: security.Failed},
		{Path: "/a", Outcome: security.Deleted},
		{Path: "/b", Outcome: security.Failed},
	}
	got := unresolvedFailures(events, nil)
	want := []string{"/b"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestUnresolvedFailuresSkippedExcluded(t *testing.T) {
	events := []security.DeleteEvent{
		{Path: "/a", Outcome: security.Failed},
		{Path: "/b", Outcome: security.Failed},
	}
	skipped := map[string]bool{"/a": true}
	got := unresolvedFailures(events, skipped)
	want := []string{"/b"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRemoveOptionAt(t *testing.T) {
	opts := []failureOption{optRetry, optRmFallback, optSkip}
	got := removeOptionAt(opts, 1)
	want := []failureOption{optRetry, optSkip}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// --- runDeleteStep ---

// TestRunDeleteStep_EmptyFilesSkipsPrimaryFn verifies the early-return
// guard on empty file lists: primaryFn must NOT be called and gs must
// stay untouched. Without this guard, callers that opportunistically
// pass empty lists (e.g. "no sudoers file installed, skip this step")
// would print spurious "no files affected" UX and waste a delete-fn
// invocation that might still touch the filesystem with stat probes.
func TestRunDeleteStep_EmptyFilesSkipsPrimaryFn(t *testing.T) {
	var w bytes.Buffer
	r := withReader("")
	primaryCalled := false
	primaryFn := func(files []string, mode security.SudoMode) security.DeleteResult {
		primaryCalled = true
		return security.DeleteResult{}
	}
	ctx := newDeleteContext(false)
	gs := newGlobalSummary(ctx)

	result := runDeleteStep(&w, r, []string{}, primaryFn, security.NoSudo, ctx, gs)

	if primaryCalled {
		t.Error("primaryFn was called for empty file list")
	}
	if len(result.Events) != 0 || result.Deleted != 0 || result.Failed != 0 || result.NotPresent != 0 {
		t.Errorf("expected zero result for empty input, got %+v", result)
	}
	if gs.shredded != 0 || gs.removedPrimary != 0 || gs.skipped != 0 {
		t.Errorf("gs should be untouched, got %+v", gs)
	}
	if w.Len() != 0 {
		t.Errorf("expected no output for empty input, got: %q", w.String())
	}
}

// TestRunDeleteStep_DelegatesAndMerges verifies the non-empty path: the
// primary function is invoked exactly once with the files+mode, and the
// resulting events propagate into the global summary.
func TestRunDeleteStep_DelegatesAndMerges(t *testing.T) {
	var w bytes.Buffer
	r := withReader("")
	gotFiles := []string(nil)
	gotMode := security.NoSudo
	primaryFn := func(files []string, mode security.SudoMode) security.DeleteResult {
		gotFiles = files
		gotMode = mode
		return security.DeleteResult{
			Deleted: 2,
			Events: []security.DeleteEvent{
				{Path: "/a", Mode: "rm", Outcome: security.Deleted},
				{Path: "/b", Mode: "rm", Outcome: security.Deleted},
			},
		}
	}
	ctx := newDeleteContext(true) // CoW → RmMode primary
	gs := newGlobalSummary(ctx)

	files := []string{"/a", "/b"}
	result := runDeleteStep(&w, r, files, primaryFn, security.SudoSilent, ctx, gs)

	if fmt.Sprint(gotFiles) != fmt.Sprint(files) {
		t.Errorf("primaryFn files = %v, want %v", gotFiles, files)
	}
	if gotMode != security.SudoSilent {
		t.Errorf("primaryFn mode = %v, want SudoSilent", gotMode)
	}
	if result.Deleted != 2 {
		t.Errorf("result.Deleted = %d, want 2", result.Deleted)
	}
	// On CoW (RmMode primary), successful deletes count as removedPrimary.
	if gs.removedPrimary != 2 {
		t.Errorf("gs.removedPrimary = %d, want 2", gs.removedPrimary)
	}
}

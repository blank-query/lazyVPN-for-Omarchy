package main

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/security"
)

// PrimaryMode identifies the primary delete tool for the detected filesystem.
// The uninstaller computes this once and threads it through helpers so each
// step's summary knows whether "Deleted" means "shredded" or "removed" and
// whether a rm event is the primary path (CoW) or an insecure fallback
// (non-CoW — bug-worthy).
type PrimaryMode int

const (
	// ShredMode: non-CoW filesystem. shred is the primary tool; rm events
	// are fallback events and get flagged for bug reports.
	ShredMode PrimaryMode = iota
	// RmMode: CoW filesystem. rm is the primary tool; shred is never used
	// (granting unused privilege is pure downside, so sudoers doesn't even
	// contain shred entries on CoW installs).
	RmMode
)

// deleteContext threads the primary-mode decision through the rendering and
// summary layer.
type deleteContext struct {
	primary PrimaryMode
}

// newDeleteContext picks the primary mode from the detected filesystem.
func newDeleteContext(cowFilesystem bool) deleteContext {
	if cowFilesystem {
		return deleteContext{primary: RmMode}
	}
	return deleteContext{primary: ShredMode}
}

// deleteFn is the shared signature of security.SecureDelete and
// security.PlainDelete. Aliased here so call sites don't need to import
// the security package solely to spell the type.
type deleteFn = security.DeleteFunc

// reportDelete renders one DeleteEvent in plain language. No "securely
// deleted" / "scrubbed" buzzwords — just the command and the result.
func reportDelete(w io.Writer, e security.DeleteEvent) {
	switch e.Outcome {
	case security.Deleted:
		switch e.Mode {
		case "shred":
			fmt.Fprintf(w, "  - shredded %s\n", e.Path)
		case "sudo-shred":
			fmt.Fprintf(w, "  - shredded (sudo) %s\n", e.Path)
		case "rm":
			fmt.Fprintf(w, "  - removed %s\n", e.Path)
		case "sudo-rm":
			fmt.Fprintf(w, "  - removed (sudo) %s\n", e.Path)
		default:
			fmt.Fprintf(w, "  - deleted (%s) %s\n", e.Mode, e.Path)
		}
	case security.NotPresent:
		fmt.Fprintf(w, "  - file not found: %s\n", e.Path)
	case security.Failed:
		fmt.Fprintf(w, "  ✗ failed: %s\n", e.Path)
		if e.Err != nil {
			for _, line := range strings.Split(strings.TrimSpace(e.Err.Error()), "\n") {
				fmt.Fprintf(w, "      %s\n", line)
			}
		}
	}
}

// failureOption is one offer in the handleFailures prompt cascade.
type failureOption int

const (
	optRetry failureOption = iota
	optRmFallback
	optSkip
)

// initialFailureOptions is the starting option set for a new prompt cascade,
// keyed on the primary mode. On non-CoW we offer retry → rm-fallback → skip;
// on CoW rm is already the primary so the fallback line drops.
func initialFailureOptions(ctx deleteContext) []failureOption {
	if ctx.primary == ShredMode {
		return []failureOption{optRetry, optRmFallback, optSkip}
	}
	return []failureOption{optRetry, optSkip}
}

// labelForOption returns the user-facing text for one option.
func labelForOption(opt failureOption, ctx deleteContext) string {
	switch opt {
	case optRetry:
		if ctx.primary == ShredMode {
			return "Retry with shred (prompts for password)"
		}
		return "Retry with rm (prompts for password)"
	case optRmFallback:
		return "Fall back to rm (insecure — leaves original content on disk until overwritten)"
	case optSkip:
		return "Skip (leave these files in place)"
	}
	return "<unknown>"
}

// handleFailures runs an interactive retry/fallback/skip loop on any Failed
// events currently in result. It appends events from retries back into
// result and returns the paths the user chose to skip, so callers can
// attribute them correctly in step and global summaries.
//
// Option cascade (each option is removed after being used; numbers re-flow
// so [1] is always the top remaining option; Enter = [1] = default):
//
//   - Non-CoW: [1] Retry with shred  [2] Fall back to rm  [3] Skip
//   - CoW:     [1] Retry with rm     [2] Skip
//
// Invalid input re-prompts. EOF treats every still-pending path as skipped.
// If all options get consumed before the failures clear, the remaining
// failures are auto-skipped (same as choosing skip).
func handleFailures(
	w io.Writer,
	r *bufio.Reader,
	result *security.DeleteResult,
	secureFn, plainFn deleteFn,
	ctx deleteContext,
) []string {
	skipped := make(map[string]bool)
	offered := initialFailureOptions(ctx)

	for {
		pending := unresolvedFailures(result.Events, skipped)
		if len(pending) == 0 {
			return sortedKeys(skipped)
		}

		printFailureBatch(w, result.Events, pending)

		if len(offered) == 0 {
			// Exhausted all recovery options — auto-skip whatever's left.
			for _, p := range pending {
				skipped[p] = true
			}
			return sortedKeys(skipped)
		}

		choice, ok := promptFailureChoice(w, r, offered, ctx)
		if !ok {
			// EOF or unreadable — treat as skip-remaining. We never want
			// to leave the uninstaller hung on a half-deleted state.
			for _, p := range pending {
				skipped[p] = true
			}
			return sortedKeys(skipped)
		}

		chosen := offered[choice]

		switch chosen {
		case optRetry, optRmFallback:
			fn := secureFn
			if chosen == optRmFallback || ctx.primary == RmMode {
				fn = plainFn
			}
			before := len(result.Events)
			retry := fn(pending, security.SudoInteractive)
			appendRetryEvents(result, retry)
			for _, e := range result.Events[before:] {
				reportDelete(w, e)
			}
		case optSkip:
			for _, p := range pending {
				skipped[p] = true
			}
			return sortedKeys(skipped)
		}

		offered = removeOptionAt(offered, choice)
	}
}

// promptFailureChoice prints the numbered menu and reads the user's pick.
// Returns the chosen index and ok=true; on EOF returns ok=false. Invalid
// input (non-number, out-of-range) re-prompts without returning.
func promptFailureChoice(w io.Writer, r *bufio.Reader, offered []failureOption, ctx deleteContext) (int, bool) {
	for {
		fmt.Fprintln(w)
		for i, opt := range offered {
			fmt.Fprintf(w, "  [%d] %s\n", i+1, labelForOption(opt, ctx))
		}
		fmt.Fprintf(w, "  Choose [1]: ")

		line, err := r.ReadString('\n')
		raw := strings.TrimSpace(line)
		if err == io.EOF && raw == "" {
			return 0, false
		}
		// Blank line after the prompt so subsequent output doesn't jam up
		// against "Choose [1]: " when stdin is piped (no terminal echo to
		// break the line for us). Harmless extra blank on a real TTY.
		fmt.Fprintln(w)
		if raw == "" {
			return 0, true // Enter → default to [1]
		}
		n, cvErr := strconv.Atoi(raw)
		if cvErr == nil && n >= 1 && n <= len(offered) {
			return n - 1, true
		}
		fmt.Fprintln(w, "  Invalid input, please enter a number from the list.")
		if err == io.EOF {
			return 0, false
		}
	}
}

// unresolvedFailures returns the paths whose latest (non-skipped) event is
// still Failed. A path that was once Failed but later retried to Deleted or
// NotPresent is resolved and excluded; a path marked skipped is excluded.
func unresolvedFailures(events []security.DeleteEvent, skipped map[string]bool) []string {
	latest := make(map[string]security.Outcome)
	order := make([]string, 0) // preserve first-seen order for stable output
	for _, e := range events {
		if _, seen := latest[e.Path]; !seen {
			order = append(order, e.Path)
		}
		latest[e.Path] = e.Outcome
	}
	var out []string
	for _, p := range order {
		if skipped[p] {
			continue
		}
		if latest[p] == security.Failed {
			out = append(out, p)
		}
	}
	return out
}

// printFailureBatch renders the pending-failure list, using each path's
// latest event to pull the most-recent error text.
func printFailureBatch(w io.Writer, events []security.DeleteEvent, pending []string) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %d file(s) failed to delete:\n", len(pending))
	pendingSet := make(map[string]bool, len(pending))
	for _, p := range pending {
		pendingSet[p] = true
	}
	// Walk events in reverse to find the most recent event per path.
	seen := make(map[string]bool, len(pending))
	lastEvent := make(map[string]security.DeleteEvent, len(pending))
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if !pendingSet[e.Path] || seen[e.Path] {
			continue
		}
		seen[e.Path] = true
		lastEvent[e.Path] = e
	}
	for _, p := range pending {
		e := lastEvent[p]
		fmt.Fprintf(w, "    - %s\n", e.Path)
		if e.Err != nil {
			for _, line := range strings.Split(strings.TrimSpace(e.Err.Error()), "\n") {
				fmt.Fprintf(w, "        %s\n", line)
			}
		}
	}
}

// appendRetryEvents merges retry events into the result, updating counters.
func appendRetryEvents(result *security.DeleteResult, retry security.DeleteResult) {
	for _, e := range retry.Events {
		result.Events = append(result.Events, e)
		switch e.Outcome {
		case security.Deleted:
			result.Deleted++
		case security.NotPresent:
			result.NotPresent++
		case security.Failed:
			result.Failed++
		}
	}
}

// removeOptionAt returns a copy of opts with index i removed.
func removeOptionAt(opts []failureOption, i int) []failureOption {
	out := make([]failureOption, 0, len(opts)-1)
	out = append(out, opts[:i]...)
	out = append(out, opts[i+1:]...)
	return out
}

// sortedKeys returns the keys of a set as a sorted slice.
func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- Summaries ---

// pathKind is the per-file resolution classification.
type pathKind int

const (
	kindShredded        pathKind = iota
	kindRemovedPrimary           // rm as primary (CoW)
	kindRemovedFallback          // rm as fallback (non-CoW — bug-worthy)
	kindNotPresent
	kindSkipped
)

// stepResolution holds per-file resolution counts for one uninstaller step.
type stepResolution struct {
	shredded        int
	removedPrimary  int
	removedFallback int
	notPresent      int
	skipped         int
	rmFallbackPaths []string
	skippedPaths    []string
}

// resolveStep computes per-file resolutions from the events list plus the
// set of paths the user explicitly skipped. Per-file counting reflects the
// user's concern ("was this file dealt with?"), not per-event counts.
func resolveStep(result security.DeleteResult, skipped []string, ctx deleteContext) stepResolution {
	skipSet := make(map[string]bool, len(skipped))
	for _, p := range skipped {
		skipSet[p] = true
	}
	byPath := make(map[string][]security.DeleteEvent)
	order := make([]string, 0)
	for _, e := range result.Events {
		if _, seen := byPath[e.Path]; !seen {
			order = append(order, e.Path)
		}
		byPath[e.Path] = append(byPath[e.Path], e)
	}

	res := stepResolution{}
	for _, p := range order {
		if skipSet[p] {
			res.skipped++
			res.skippedPaths = append(res.skippedPaths, p)
			continue
		}
		switch classifyPath(byPath[p], ctx) {
		case kindShredded:
			res.shredded++
		case kindRemovedPrimary:
			res.removedPrimary++
		case kindRemovedFallback:
			res.removedFallback++
			res.rmFallbackPaths = append(res.rmFallbackPaths, p)
		case kindNotPresent:
			res.notPresent++
		case kindSkipped:
			// reached only for explicit skipSet lookup above; can't land here
		}
	}
	return res
}

// classifyPath picks the most favorable resolution from all events for one
// path. Preference order: primary-deleted > rm-fallback-deleted > not-present.
// A path whose events never reach any of these (i.e. only Failed, no skip)
// falls back to NotPresent — should not happen if handleFailures drained
// properly, but we want no panics in the summary path.
func classifyPath(events []security.DeleteEvent, ctx deleteContext) pathKind {
	var sawDeletedPrimary, sawDeletedRmFallback, sawNotPresent bool
	for _, e := range events {
		switch e.Outcome {
		case security.Deleted:
			switch e.Mode {
			case "shred", "sudo-shred":
				if ctx.primary == ShredMode {
					sawDeletedPrimary = true
				}
			case "rm", "sudo-rm":
				if ctx.primary == RmMode {
					sawDeletedPrimary = true
				} else {
					sawDeletedRmFallback = true
				}
			}
		case security.NotPresent:
			sawNotPresent = true
		}
	}
	switch {
	case sawDeletedPrimary:
		if ctx.primary == ShredMode {
			return kindShredded
		}
		return kindRemovedPrimary
	case sawDeletedRmFallback:
		return kindRemovedFallback
	case sawNotPresent:
		return kindNotPresent
	default:
		return kindNotPresent
	}
}

// printStepSummary prints one step's resolution summary in the refactor-plan
// format: a counter line, then optional bug-report blocks for rm-fallback
// and skipped paths.
func printStepSummary(w io.Writer, result security.DeleteResult, skipped []string, ctx deleteContext) {
	res := resolveStep(result, skipped, ctx)
	total := res.shredded + res.removedPrimary + res.removedFallback + res.notPresent + res.skipped
	if total == 0 {
		return
	}
	marker := "✓"
	if res.removedFallback > 0 || res.skipped > 0 {
		marker = "⚠"
	}
	fmt.Fprintf(w, "  %s %d file(s) processed: %s\n", marker, total, formatStepCounts(res))

	if res.removedFallback > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  The following files required rm fallback (please report as a bug")
		fmt.Fprintln(w, "  at https://github.com/blank-query/lazyVPN-for-Omarchy/issues):")
		for _, p := range res.rmFallbackPaths {
			fmt.Fprintf(w, "    - %s\n", p)
		}
	}
	if res.skipped > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  The following files were skipped (please report as a bug")
		fmt.Fprintln(w, "  at https://github.com/blank-query/lazyVPN-for-Omarchy/issues):")
		for _, p := range res.skippedPaths {
			fmt.Fprintf(w, "    - %s\n", p)
		}
	}
}

// formatStepCounts joins non-zero counts from a resolution into a
// comma-separated phrase. Zero-counts are omitted so the line stays readable.
func formatStepCounts(res stepResolution) string {
	var parts []string
	if res.shredded > 0 {
		parts = append(parts, fmt.Sprintf("%d shredded", res.shredded))
	}
	if res.removedPrimary > 0 {
		parts = append(parts, fmt.Sprintf("%d removed", res.removedPrimary))
	}
	if res.removedFallback > 0 {
		parts = append(parts, fmt.Sprintf("%d removed (insecure fallback)", res.removedFallback))
	}
	if res.notPresent > 0 {
		parts = append(parts, fmt.Sprintf("%d not present", res.notPresent))
	}
	if res.skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", res.skipped))
	}
	return strings.Join(parts, ", ")
}

// globalSummary accumulates per-file resolutions across every uninstall step
// and renders the final banner. Counter lines with zero counts are omitted;
// bug-worthy path lists are always shown when non-empty.
type globalSummary struct {
	ctx             deleteContext
	shredded        int
	removedPrimary  int
	removedFallback int
	notPresent      int
	skipped         int
	rmFallbackPaths []string
	skippedPaths    []string
}

func newGlobalSummary(ctx deleteContext) *globalSummary {
	return &globalSummary{ctx: ctx}
}

func (g *globalSummary) merge(result security.DeleteResult, skipped []string) {
	res := resolveStep(result, skipped, g.ctx)
	g.shredded += res.shredded
	g.removedPrimary += res.removedPrimary
	g.removedFallback += res.removedFallback
	g.notPresent += res.notPresent
	g.skipped += res.skipped
	g.rmFallbackPaths = append(g.rmFallbackPaths, res.rmFallbackPaths...)
	g.skippedPaths = append(g.skippedPaths, res.skippedPaths...)
}

func (g *globalSummary) render(w io.Writer) {
	total := g.shredded + g.removedPrimary + g.removedFallback + g.notPresent + g.skipped
	if total == 0 {
		return
	}
	fmt.Fprintln(w, "Deletion summary:")
	if g.shredded > 0 {
		fmt.Fprintf(w, "  %d shredded\n", g.shredded)
	}
	if g.removedPrimary > 0 {
		fmt.Fprintf(w, "  %d removed\n", g.removedPrimary)
	}
	if g.removedFallback > 0 {
		fmt.Fprintf(w, "  %d removed (insecure fallback)\n", g.removedFallback)
	}
	if g.notPresent > 0 {
		fmt.Fprintf(w, "  %d not present\n", g.notPresent)
	}
	if g.skipped > 0 {
		fmt.Fprintf(w, "  %d skipped\n", g.skipped)
	}

	if len(g.rmFallbackPaths) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Files that required rm fallback (please report as a bug")
		fmt.Fprintln(w, "at https://github.com/blank-query/lazyVPN-for-Omarchy/issues):")
		for _, p := range g.rmFallbackPaths {
			fmt.Fprintf(w, "  - %s\n", p)
		}
	}
	if len(g.skippedPaths) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Files that were skipped (please report as a bug")
		fmt.Fprintln(w, "at https://github.com/blank-query/lazyVPN-for-Omarchy/issues):")
		for _, p := range g.skippedPaths {
			fmt.Fprintf(w, "  - %s\n", p)
		}
	}
}

// --- Step helper ---

// runDeleteStep is the common uninstaller step template: call fn(files,
// mode), report each initial event, resolve failures via the prompt loop,
// print the step summary, and merge into the global summary. Callers supply
// the primary fn (SecureDelete or PlainDelete per FS), the mode, and the
// paths; handleFailures escalates to SudoInteractive when it retries.
func runDeleteStep(
	w io.Writer,
	r *bufio.Reader,
	files []string,
	primaryFn deleteFn,
	mode security.SudoMode,
	ctx deleteContext,
	gs *globalSummary,
) security.DeleteResult {
	if len(files) == 0 {
		return security.DeleteResult{}
	}
	result := primaryFn(files, mode)
	return resolveAndMerge(w, r, result, ctx, gs)
}

// resolveAndMerge runs the post-delete UX sequence on an already-computed
// DeleteResult: report events, drive the failure prompt loop, print the
// step summary, and merge into the global summary. Useful for helpers that
// already invoked the primary delete (e.g. security.CleanJournalLogs) where
// the caller only owns the post-processing.
func resolveAndMerge(
	w io.Writer,
	r *bufio.Reader,
	result security.DeleteResult,
	ctx deleteContext,
	gs *globalSummary,
) security.DeleteResult {
	for _, e := range result.Events {
		reportDelete(w, e)
	}
	skipped := handleFailures(w, r, &result, security.SecureDelete, security.PlainDelete, ctx)
	printStepSummary(w, result, skipped, ctx)
	gs.merge(result, skipped)
	return result
}

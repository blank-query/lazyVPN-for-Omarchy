package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryFirewallImporterHasTestMainGuard is a static regression guard
// for the documented test-safety contract in CLAUDE.md:
//
//   Every package that imports `firewall` MUST have `testmain_test.go`
//   calling `firewall.SetTestMode(firewall.NoopRunner{})`.
//
// Without that, tests will run real `sudo ufw` commands and mutate
// the host firewall — confirmed in past incidents where missing
// stubs left 18 lazyvpn:lb rules in the live firewall after a test
// run. The runtime SetTestMode(nil) panic catches one footgun, but
// only enforcement at the package boundary catches the worse case
// (an importer that simply forgets to install the noop runner).
//
// This test walks the repo, finds every non-test source file that
// imports the firewall package, and verifies the importing package
// has a *_test.go file containing a SetTestMode(NoopRunner{}) call.
//
// To bypass intentionally (e.g. a package that imports firewall only
// for type definitions but never calls runUFW-backed code in tests),
// add the package to the allowlist below.
func TestEveryFirewallImporterHasTestMainGuard(t *testing.T) {
	// Find the repo root by walking up from this test's directory.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := dir
	for {
		if _, err := os.Stat(filepath.Join(repoRoot, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(repoRoot)
		if parent == repoRoot {
			t.Fatal("could not find go.mod walking up from test dir")
		}
		repoRoot = parent
	}

	// Allowlist: packages that import firewall but legitimately
	// don't need SetTestMode (e.g. they only reference types or
	// only call the package from main, not from any test).
	allowlist := map[string]bool{
		// cmd/lazyvpn: main.go uses firewall, but unit tests
		// (delete_ui_test.go, installhelpers_test.go) don't
		// exercise firewall code paths. If a test that does is
		// ever added, remove from allowlist and add a TestMain.
		"cmd/lazyvpn": true,
	}

	// Find packages that import internal/firewall (skipping the
	// firewall package itself).
	importPath := "blank-query/lazyVPN-for-Omarchy/internal/firewall"
	importerPkgs := map[string]bool{}
	err = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(data), importPath) {
			return nil
		}
		pkgDir := filepath.Dir(path)
		// Skip the firewall package itself (its TestMain is in the same dir).
		if filepath.Base(pkgDir) == "firewall" {
			return nil
		}
		rel, _ := filepath.Rel(repoRoot, pkgDir)
		importerPkgs[rel] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// For each importer, verify some test file calls SetTestMode(NoopRunner{}).
	var violations []string
	for pkg := range importerPkgs {
		if allowlist[pkg] {
			continue
		}
		pkgDir := filepath.Join(repoRoot, pkg)
		entries, err := os.ReadDir(pkgDir)
		if err != nil {
			violations = append(violations, pkg+": cannot read dir: "+err.Error())
			continue
		}
		hasGuard := false
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, "_test.go") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(pkgDir, name))
			if err != nil {
				continue
			}
			content := string(data)
			// Match either firewall.SetTestMode(...) or SetTestMode(...)
			// inside the firewall package itself (already excluded).
			// Importers must use the qualified form.
			if strings.Contains(content, "firewall.SetTestMode(firewall.NoopRunner{})") ||
				strings.Contains(content, "firewall.SetTestMode(&firewall.NoopRunner{})") ||
				strings.Contains(content, "firewall.SetTestMode(") {
				hasGuard = true
				break
			}
		}
		if !hasGuard {
			violations = append(violations, pkg+": no test file calls firewall.SetTestMode(NoopRunner{})")
		}
	}

	if len(violations) > 0 {
		t.Errorf("packages importing firewall without test-safety guard (see CLAUDE.md):\n  %s\n\nFix: add a testmain_test.go with TestMain that calls firewall.SetTestMode(firewall.NoopRunner{}). Or, if no test exercises firewall code paths, add to allowlist in this test.",
			strings.Join(violations, "\n  "))
	}
}

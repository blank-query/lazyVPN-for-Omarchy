package sudo

import (
	"fmt"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// stubGroups points group detection at a fixed membership list and a fixed
// set of existing groups, restoring the real seams on cleanup. Detection
// must never depend on the host the tests run on — that's the exact class
// of bug the firewall sysctl tests had.
func stubGroups(t *testing.T, member []string, existing []string) {
	t.Helper()
	oldNames := userGroupNames
	oldLookup := lookupGroup
	userGroupNames = func() ([]string, error) { return member, nil }
	lookupGroup = func(name string) (*user.Group, error) {
		for _, g := range existing {
			if g == name {
				return &user.Group{Name: name}, nil
			}
		}
		return nil, fmt.Errorf("group %q not found", name)
	}
	t.Cleanup(func() {
		userGroupNames = oldNames
		lookupGroup = oldLookup
	})
}

// stubBinaries makes lookPath resolve only the given name→path map and
// statPath succeed only for the given existing absolute paths.
func stubBinaries(t *testing.T, pathHits map[string]string, statHits []string) {
	t.Helper()
	oldLook := lookPath
	oldStat := statPath
	lookPath = func(name string) (string, error) {
		if p, ok := pathHits[name]; ok {
			return p, nil
		}
		return "", fmt.Errorf("%q not in PATH", name)
	}
	statPath = func(path string) error {
		for _, p := range statHits {
			if p == path {
				return nil
			}
		}
		return fmt.Errorf("stat %q: no such file", path)
	}
	t.Cleanup(func() {
		lookPath = oldLook
		statPath = oldStat
	})
}

// ---------------------------------------------------------------------------
// DetectSudoGroup
// ---------------------------------------------------------------------------

func TestDetectSudoGroup(t *testing.T) {
	cases := []struct {
		name       string
		member     []string
		existing   []string
		wantGroup  string
		wantMember bool
	}{
		{"arch wheel member", []string{"rigs", "wheel", "docker"}, []string{"wheel"}, "wheel", true},
		{"debian sudo member", []string{"user", "sudo", "adm"}, []string{"sudo"}, "sudo", true},
		{"member of both prefers wheel", []string{"sudo", "wheel"}, []string{"wheel", "sudo"}, "wheel", true},
		{"member of neither, wheel exists", []string{"user"}, []string{"wheel"}, "wheel", false},
		{"member of neither, only sudo exists", []string{"user"}, []string{"sudo"}, "sudo", false},
		{"member of neither, neither exists", []string{"user"}, nil, "wheel", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubGroups(t, tc.member, tc.existing)
			group, isMember := DetectSudoGroup()
			if group != tc.wantGroup || isMember != tc.wantMember {
				t.Errorf("DetectSudoGroup() = (%q, %v), want (%q, %v)",
					group, isMember, tc.wantGroup, tc.wantMember)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FindSystemBinary
// ---------------------------------------------------------------------------

func TestFindSystemBinary(t *testing.T) {
	cases := []struct {
		name      string
		cmd       string
		family    string
		pathHits  map[string]string
		statHits  []string
		wantPath  string
		wantFound bool
	}{
		{"PATH hit wins", "ufw", "arch",
			map[string]string{"ufw": "/usr/bin/ufw"}, nil, "/usr/bin/ufw", true},
		{"PATH miss, sbin stat hit (Debian user PATH omits sbin)", "ufw", "debian",
			nil, []string{"/usr/sbin/ufw"}, "/usr/sbin/ufw", true},
		{"usr/bin stat preferred over usr/sbin (merged-usr)", "sysctl", "arch",
			nil, []string{"/usr/bin/sysctl", "/usr/sbin/sysctl"}, "/usr/bin/sysctl", true},
		{"not installed, debian sbin command guess", "ufw", "debian",
			nil, nil, "/usr/sbin/ufw", false},
		{"not installed, arch guess", "ufw", "arch",
			nil, nil, "/usr/bin/ufw", false},
		{"not installed, debian non-sbin command", "resolvectl", "debian",
			nil, nil, "/usr/bin/resolvectl", false},
		{"not installed, unknown family", "ufw", "unknown",
			nil, nil, "/usr/sbin/ufw", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubBinaries(t, tc.pathHits, tc.statHits)
			path, found := FindSystemBinary(tc.cmd, tc.family)
			if path != tc.wantPath || found != tc.wantFound {
				t.Errorf("FindSystemBinary(%q, %q) = (%q, %v), want (%q, %v)",
					tc.cmd, tc.family, path, found, tc.wantPath, tc.wantFound)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DetectSudoersEnv
// ---------------------------------------------------------------------------

// Arch shape: everything found at /usr/bin → Paths stays empty, so the
// generated file is byte-identical to the historic output.
func TestDetectSudoersEnvArchShape(t *testing.T) {
	stubGroups(t, []string{"wheel"}, []string{"wheel"})
	hits := map[string]string{}
	for _, cmd := range sudoersCommands {
		hits[cmd] = "/usr/bin/" + cmd
	}
	stubBinaries(t, hits, nil)

	env := DetectSudoersEnv("arch")
	if env.Group != "wheel" {
		t.Errorf("Group = %q, want wheel", env.Group)
	}
	if len(env.Paths) != 0 {
		t.Errorf("Paths should be empty when everything is at /usr/bin, got %v", env.Paths)
	}
}

// Debian shape: sudo group, sbin trio relocated, the rest untouched.
func TestDetectSudoersEnvDebianShape(t *testing.T) {
	stubGroups(t, []string{"sudo"}, []string{"sudo"})
	hits := map[string]string{}
	for _, cmd := range sudoersCommands {
		if familySbinCommands[cmd] {
			hits[cmd] = "/usr/sbin/" + cmd
		} else {
			hits[cmd] = "/usr/bin/" + cmd
		}
	}
	stubBinaries(t, hits, nil)

	env := DetectSudoersEnv("debian")
	if env.Group != "sudo" {
		t.Errorf("Group = %q, want sudo", env.Group)
	}
	want := map[string]string{
		"ufw":    "/usr/sbin/ufw",
		"sysctl": "/usr/sbin/sysctl",
		"setcap": "/usr/sbin/setcap",
	}
	if len(env.Paths) != len(want) {
		t.Errorf("Paths = %v, want exactly %v", env.Paths, want)
	}
	for cmd, p := range want {
		if env.Paths[cmd] != p {
			t.Errorf("Paths[%q] = %q, want %q", cmd, env.Paths[cmd], p)
		}
	}
}

// ---------------------------------------------------------------------------
// GenerateSudoersContent with a non-default env
// ---------------------------------------------------------------------------

func debianEnv() SudoersEnv {
	return SudoersEnv{
		Group: "sudo",
		Paths: map[string]string{
			"ufw":    "/usr/sbin/ufw",
			"sysctl": "/usr/sbin/sysctl",
			"setcap": "/usr/sbin/setcap",
		},
	}
}

func TestGenerateSudoersContentDebianEnv(t *testing.T) {
	content, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"eth0"}, true, debianEnv())
	if err != nil {
		t.Fatalf("GenerateSudoersContent: %v", err)
	}

	// Every grant line targets %sudo; no %wheel grant survives.
	if strings.Contains(content, "%wheel") {
		t.Error("debian env output still contains %wheel grants")
	}
	for _, want := range []string{
		"%sudo ALL=(ALL) NOPASSWD: /usr/sbin/ufw --force enable",
		"%sudo ALL=(ALL) NOPASSWD: /usr/sbin/ufw delete *",
		"%sudo ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -p /etc/sysctl.d/99-lazyvpn-ipv6.conf",
		"%sudo ALL=(ALL) NOPASSWD: /usr/bin/resolvectl dns wg0",
		"%sudo ALL=(ALL) NOPASSWD: /usr/bin/ip link add dev wg0 type wireguard",
		"%sudo ALL=(ALL) NOPASSWD: /usr/bin/ip route add * via * dev eth0",
		"%sudo ALL=(ALL) NOPASSWD: /usr/bin/rm /etc/sudoers.d/lazyvpn",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("debian env output missing %q", want)
		}
	}
	// Relocated binaries leave no stale /usr/bin grants behind.
	for _, stale := range []string{"/usr/bin/ufw ", "/usr/bin/sysctl ", "/usr/bin/setcap "} {
		if strings.Contains(content, stale) {
			t.Errorf("debian env output still grants stale path %q", stale)
		}
	}
	// setcap grants the relocated path with the exec path intact.
	if !strings.Contains(content, "/usr/sbin/setcap cap_net_admin") {
		t.Error("debian env output missing relocated setcap grant")
	}
}

// Empty group means wheel; DefaultSudoersEnv reproduces the historic file.
func TestGenerateSudoersContentDefaultEnvUnchanged(t *testing.T) {
	def, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"eth0"}, false, DefaultSudoersEnv())
	if err != nil {
		t.Fatalf("default env: %v", err)
	}
	empty, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"eth0"}, false, SudoersEnv{})
	if err != nil {
		t.Fatalf("zero env: %v", err)
	}
	if def != empty {
		t.Error("zero-value SudoersEnv must produce the same output as DefaultSudoersEnv()")
	}
	if !strings.Contains(def, "%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw status") {
		t.Error("default env output lost the historic wheel//usr/bin shape")
	}
}

// Injection guards: env values land in a privileged file, so anything that
// could smuggle sudoers syntax is refused at the source (same posture as
// connName/iface validation).
func TestGenerateSudoersContentRejectsBadEnv(t *testing.T) {
	cases := []struct {
		name string
		env  SudoersEnv
	}{
		{"group with newline injection", SudoersEnv{Group: "sudo\nALL ALL=(ALL) NOPASSWD: ALL"}},
		{"group with space", SudoersEnv{Group: "sudo users"}},
		{"path for unknown command", SudoersEnv{Group: "wheel", Paths: map[string]string{"bash": "/usr/bin/bash"}}},
		{"path with space", SudoersEnv{Group: "wheel", Paths: map[string]string{"ufw": "/usr/sbin/ufw ALL"}}},
		{"path with newline", SudoersEnv{Group: "wheel", Paths: map[string]string{"ufw": "/usr/sbin/ufw\n%wheel ALL=(ALL) NOPASSWD: ALL"}}},
		{"relative path", SudoersEnv{Group: "wheel", Paths: map[string]string{"ufw": "usr/sbin/ufw"}}},
		{"basename mismatch is a privilege rewrite", SudoersEnv{Group: "wheel", Paths: map[string]string{"ufw": "/usr/bin/bash"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"eth0"}, false, tc.env); err == nil {
				t.Error("expected rejection, got nil error")
			}
		})
	}
}

// The rewrite must be total: with a relocating env, no granted line may
// keep the template path for a relocated command — a partial rewrite is a
// dead grant that fails at the sudo layer at runtime, far from the cause.
func TestDebianEnvRewriteIsTotal(t *testing.T) {
	content, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", []string{"eth0", "wlan0"}, false, debianEnv())
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, "NOPASSWD:") {
			continue
		}
		for cmd, want := range debianEnv().Paths {
			stale := "/usr/bin/" + cmd + " "
			if strings.Contains(line, stale) {
				t.Errorf("grant line kept stale path for %q (want %s): %s", cmd, want, line)
			}
		}
		if !strings.HasPrefix(line, "%sudo ") {
			t.Errorf("grant line does not target %%sudo: %s", line)
		}
	}
}

// filepath.Base is the basename guard's implementation; pin the trailing-
// slash edge so a path like "/usr/sbin/" can't slip past as a match for
// any command.
func TestBasenameGuardTrailingSlash(t *testing.T) {
	if filepath.Base("/usr/sbin/") == "ufw" {
		t.Fatal("impossible")
	}
	env := SudoersEnv{Group: "wheel", Paths: map[string]string{"ufw": "/usr/sbin/"}}
	if _, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", nil, false, env); err == nil {
		t.Error("trailing-slash path must be rejected")
	}
}

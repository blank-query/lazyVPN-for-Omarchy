package sudo

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
)

// SudoersEnv carries the host conventions a sudoers file must match:
// which admin group receives the NOPASSWD grants, and where the granted
// binaries actually live. sudoers matches commands by the path sudo
// resolves at runtime, so a grant written for /usr/bin/ufw is dead on a
// Debian-family system where ufw is /usr/sbin/ufw — the sudo call then
// fails with an auth error at first use (typically the connect DNS step)
// even though the file installed and validated cleanly.
type SudoersEnv struct {
	// Group is the admin group to grant to ("wheel" on Arch/Fedora
	// families, "sudo" on Debian family). Empty means "wheel".
	Group string
	// Paths maps a granted command name (e.g. "ufw") to its absolute
	// path when it differs from the template's /usr/bin/<name> default.
	// Nil/empty means the template's paths are used as-is.
	Paths map[string]string
}

// DefaultSudoersEnv returns the historic Arch-shaped environment: %wheel
// grants with every binary at /usr/bin. Existing behavior on Arch-family
// systems (Omarchy included) is exactly this.
func DefaultSudoersEnv() SudoersEnv {
	return SudoersEnv{Group: "wheel"}
}

// sudoersCommands are the command names the template grants. A Paths key
// outside this list is refused — every entry in the privileged file must
// map to something the runtime actually invokes.
var sudoersCommands = []string{
	"ip", "resolvectl", "setcap", "ufw", "sysctl", "tee",
	"systemctl", "rm", "shred",
}

func isSudoersCommand(name string) bool {
	for _, c := range sudoersCommands {
		if c == name {
			return true
		}
	}
	return false
}

// groupRe / binPathRe are defense-in-depth guards, same rationale as
// connNameRe: env values are interpolated into a privileged file with no
// escaping, so anything with whitespace or newlines is refused at the
// source rather than trusted to visudo.
var (
	groupRe   = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$`)
	binPathRe = regexp.MustCompile(`^/[a-zA-Z0-9._+/-]+$`)
)

// Injectable seams for deterministic tests — group/path detection must
// never make test results depend on the host the tests run on.
var (
	lookPath = exec.LookPath
	statPath = func(path string) error {
		_, err := os.Stat(path)
		return err
	}
	userGroupNames = currentUserGroupNames
	lookupGroup    = user.LookupGroup
)

// currentUserGroupNames returns the names of the groups the current user
// belongs to. Best-effort: an unresolvable GID is skipped, not fatal.
func currentUserGroupNames() ([]string, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, gid := range gids {
		g, err := user.LookupGroupId(gid)
		if err != nil {
			continue
		}
		names = append(names, g.Name)
	}
	return names, nil
}

// sudoGroupCandidates in preference order: wheel (Arch, Fedora, openSUSE
// convention) then sudo (Debian/Ubuntu convention).
var sudoGroupCandidates = []string{"wheel", "sudo"}

// DetectSudoGroup returns the admin group the sudoers grants should
// target and whether the current user is actually a member. Membership
// wins: a Debian user in "sudo" gets "sudo" even if a "wheel" group also
// exists. When the user is in neither candidate group, the first existing
// group is returned with false — the installer must surface that to the
// user (the grants would apply to nobody they can act as) instead of
// writing a file that silently does nothing.
func DetectSudoGroup() (string, bool) {
	names, err := userGroupNames()
	if err == nil {
		for _, candidate := range sudoGroupCandidates {
			for _, n := range names {
				if n == candidate {
					return candidate, true
				}
			}
		}
	}
	for _, candidate := range sudoGroupCandidates {
		if _, lookupErr := lookupGroup(candidate); lookupErr == nil {
			return candidate, false
		}
	}
	return "wheel", false
}

// systemBinDirs are searched in order when PATH doesn't surface a binary.
// /usr/bin first: on merged-usr Arch, /usr/sbin is a symlink to /usr/bin,
// and sudo's secure_path resolves to /usr/bin there — preferring /usr/bin
// keeps the granted path identical to what sudo matches at runtime. On
// Debian family the sbin binaries exist ONLY under /usr/sbin (user PATH
// often omits sbin entirely, which is exactly why LookPath misses them).
var systemBinDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"}

// familySbinCommands: commands that live in sbin on non-Arch families.
// Consulted only as a last resort when the binary isn't installed yet
// (sudoers is written at install Step 4; missing deps are offered for
// install at Step 10).
var familySbinCommands = map[string]bool{
	"ufw":    true,
	"sysctl": true,
	"setcap": true,
}

// FindSystemBinary resolves where a granted command lives on this system.
// Resolution order: PATH lookup, then the fixed system dirs, then a
// family-informed guess. found reports whether the binary actually exists
// (false means the returned path is the guess — usable for a sudoers
// grant written before Step 10 installs the package, but a dependency
// check should treat it as missing).
func FindSystemBinary(name, family string) (path string, found bool) {
	if p, err := lookPath(name); err == nil {
		return filepath.Clean(p), true
	}
	for _, dir := range systemBinDirs {
		p := filepath.Join(dir, name)
		if statPath(p) == nil {
			return p, true
		}
	}
	if family != "arch" && family != "" && familySbinCommands[name] {
		return "/usr/sbin/" + name, false
	}
	return "/usr/bin/" + name, false
}

// DetectSudoersEnv builds the SudoersEnv for this host: detected admin
// group plus resolved paths for every granted command. family comes from
// config.Family() ("arch", "debian", ...) and only steers the guess for
// binaries that aren't installed yet. Membership is NOT checked here —
// callers that need the bounce-to-user prompt call DetectSudoGroup()
// directly.
func DetectSudoersEnv(family string) SudoersEnv {
	group, _ := DetectSudoGroup()
	env := SudoersEnv{Group: group}
	for _, cmd := range sudoersCommands {
		p, _ := FindSystemBinary(cmd, family)
		if p != "/usr/bin/"+cmd {
			if env.Paths == nil {
				env.Paths = make(map[string]string)
			}
			env.Paths[cmd] = p
		}
	}
	return env
}

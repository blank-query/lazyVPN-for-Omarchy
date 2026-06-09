package firewall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// mockUFW implements UFWRunner for testing.
// It tracks all calls and maintains simulated state for rules and policies.
type mockUFW struct {
	mu              sync.Mutex
	calls           [][]string     // all args passed to Run()
	rules           []string       // active rules (as "ufw <action> ..." strings)
	defaultOutgoing string         // "allow" or "deny"
	defaultIncoming string         // "allow" or "deny"
	loggingLevel    string         // "off", "low", "medium", "high", "full"
	errors          map[int]error  // inject error at call N (0-based)
	outputs         map[int][]byte // inject raw output at call N (0-based) — bypasses normal mock logic
	callCount       int
}

func newMockUFW() *mockUFW {
	return &mockUFW{
		defaultOutgoing: "allow",
		defaultIncoming: "allow",
		loggingLevel:    "off",
		errors:          make(map[int]error),
		outputs:         make(map[int][]byte),
	}
}

func (m *mockUFW) Run(args ...string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	callIdx := m.callCount
	m.callCount++
	m.calls = append(m.calls, args)

	// Check for injected error
	if err, ok := m.errors[callIdx]; ok {
		return nil, err
	}
	// Check for injected raw output (bypasses normal mock formatting).
	// Lets tests exercise output-format edge cases (e.g. older ufw versions
	// emitting "Logging: on" without a parenthetical level).
	if out, ok := m.outputs[callIdx]; ok {
		return out, nil
	}

	if len(args) == 0 {
		return nil, nil
	}

	switch args[0] {
	case "status":
		if len(args) > 1 && args[1] == "verbose" {
			logLine := "Logging: off"
			if m.loggingLevel != "" && m.loggingLevel != "off" {
				logLine = fmt.Sprintf("Logging: on (%s)", m.loggingLevel)
			}
			return []byte(fmt.Sprintf("Status: active\n%s\nDefault: %s (incoming), %s (outgoing), disabled (routed)\n",
				logLine, m.defaultIncoming, m.defaultOutgoing)), nil
		}
		return []byte("Status: active\n"), nil

	case "show":
		if len(args) > 1 && args[1] == "added" {
			var sb strings.Builder
			for _, rule := range m.rules {
				// Real UFW wraps comment values in single quotes in
				// "show added" output, e.g. comment 'lazyvpn:ks'
				display := rule
				if idx := strings.Index(rule, " comment "); idx >= 0 {
					commentStart := idx + len(" comment ")
					display = rule[:commentStart] + "'" + rule[commentStart:] + "'"
				}
				sb.WriteString(display)
				sb.WriteString("\n")
			}
			return []byte(sb.String()), nil
		}
		return nil, nil

	case "default":
		if len(args) >= 3 {
			switch args[2] {
			case "outgoing":
				m.defaultOutgoing = args[1]
			case "incoming":
				m.defaultIncoming = args[1]
			}
		}
		return nil, nil

	case "logging":
		if len(args) >= 2 {
			m.loggingLevel = args[1]
		}
		return nil, nil

	case "delete":
		// Delete a rule: reconstruct the rule string from args after "delete"
		ruleStr := "ufw " + strings.Join(args[1:], " ")
		for i, r := range m.rules {
			if r == ruleStr {
				m.rules = append(m.rules[:i], m.rules[i+1:]...)
				return nil, nil
			}
		}
		return []byte("Could not delete non-existent rule"), fmt.Errorf("rule not found")

	default:
		// Any other command (allow, deny, reject, etc.) — add as a rule
		ruleStr := "ufw " + strings.Join(args, " ")
		m.rules = append(m.rules, ruleStr)
		return nil, nil
	}
}

// injectErrorAt sets an error to be returned at the Nth call (0-based).
func (m *mockUFW) injectErrorAt(callN int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[callN] = err
}

// injectOutputAt sets raw output bytes to return at the Nth call (0-based).
// Used to exercise unusual ufw output formats — older versions, distro
// variants, degraded states — that the normal mock can't synthesize.
func (m *mockUFW) injectOutputAt(callN int, out []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outputs[callN] = out
}

// getRules returns a copy of active rules.
func (m *mockUFW) getRules() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.rules...)
}

// hasRule checks if a rule string exists.
func (m *mockUFW) hasRule(rule string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rules {
		if r == rule {
			return true
		}
	}
	return false
}

// countRulesWithTag counts rules containing a tag.
func (m *mockUFW) countRulesWithTag(tag string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, r := range m.rules {
		if strings.Contains(r, tag) {
			count++
		}
	}
	return count
}

// setupMock creates a mock UFW runner and installs it.
func setupMock(t *testing.T) *mockUFW {
	t.Helper()
	mock := newMockUFW()
	SetTestMode(mock)
	// Sandbox the "UFW enabled by lazyvpn" marker so no test can write to the
	// real $HOME if ensureUFWEnabled ever runs the enable path.
	oldMarker := ufwStateMarker
	ufwStateMarker = filepath.Join(t.TempDir(), ".ufw-enabled-by-lazyvpn")
	t.Cleanup(func() {
		SetTestMode(NoopRunner{})
		SetLogFunc(nil)
		ufwStateMarker = oldMarker
	})
	return mock
}

// ---------------------------------------------------------------------------
// Enable tests
// ---------------------------------------------------------------------------

func TestEnableAddsRules(t *testing.T) {
	mock := setupMock(t)

	cfg := &KillswitchConfig{
		InterfaceName: "wg0",
		DNS:           "10.2.0.1",
		Endpoint:      "198.51.100.1",
	}

	// Use fake route so GetPhysicalInterface returns something
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	os.WriteFile(routeFile, []byte(content), 0644)
	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	if err := Enable(cfg); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// Default should be deny
	if mock.defaultOutgoing != "deny" {
		t.Errorf("Expected default outgoing 'deny', got %q", mock.defaultOutgoing)
	}

	// Should have loopback rule
	if !mock.hasRule("ufw allow out on lo comment lazyvpn:ks") {
		t.Error("Missing loopback rule")
	}

	// Should have DNS rules
	if !mock.hasRule("ufw allow out proto udp to 10.2.0.1 port 53 comment lazyvpn:ks") {
		t.Error("Missing DNS UDP rule")
	}
	if !mock.hasRule("ufw allow out proto tcp to 10.2.0.1 port 53 comment lazyvpn:ks") {
		t.Error("Missing DNS TCP rule")
	}

	// Should have endpoint rule
	if !mock.hasRule("ufw allow out to 198.51.100.1 comment lazyvpn:ks") {
		t.Error("Missing endpoint rule")
	}

	// The killswitch must NOT own LAN rules — those belong to the independent
	// Local Network layer (la/st/lb). A killswitch-tagged LAN allow would mean
	// the two layers are entangled again.
	if mock.hasRule("ufw allow out to 192.168.0.0/16 comment lazyvpn:ks") {
		t.Error("Killswitch should not emit LAN rules (now owned by Local Network layer)")
	}
	if mock.hasRule("ufw allow in from 192.168.0.0/16 comment lazyvpn:ks") {
		t.Error("Killswitch should not emit LAN inbound rules (now owned by Local Network layer)")
	}

	// Should have VPN interface rule
	if !mock.hasRule("ufw allow out on wg0 comment lazyvpn:ks") {
		t.Error("Missing VPN interface rule")
	}

	// Should have WebRTC isolation rules
	if !mock.hasRule("ufw allow out on eth0 to 198.51.100.1 comment lazyvpn:ks") {
		t.Error("Missing WebRTC endpoint rule on physical interface")
	}
	if !mock.hasRule("ufw reject out on eth0 comment lazyvpn:ks") {
		t.Error("Missing WebRTC reject rule on physical interface")
	}
}

// ruleIndex returns the position of the first active rule containing substr,
// or -1. Rule order is UFW's first-match evaluation order.
func (m *mockUFW) ruleIndex(substr string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.rules {
		if strings.Contains(r, substr) {
			return i
		}
	}
	return -1
}

// THE ordering invariant: a LAN allow-out rule must sit BEFORE the killswitch's
// physical-interface reject, or first-match would let the reject swallow LAN
// egress. Holds when LAN is established before the killswitch (install order).
func TestLANAllowOutPrecedesKillswitchReject(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0")

	// LAN constant first (as install establishes it), then killswitch.
	if err := EnableLANStealth(); err != nil {
		t.Fatalf("EnableLANStealth failed: %v", err)
	}
	if err := Enable(&KillswitchConfig{InterfaceName: "wg0", Endpoint: "198.51.100.1"}); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	allowOut := mock.ruleIndex("allow out to 192.168.0.0/16 comment lazyvpn:st")
	reject := mock.ruleIndex("reject out on eth0 comment lazyvpn:ks")
	if allowOut < 0 {
		t.Fatal("stealth allow-out rule missing")
	}
	if reject < 0 {
		t.Fatal("killswitch reject rule missing")
	}
	if allowOut >= reject {
		t.Errorf("LAN allow-out (idx %d) must precede killswitch reject (idx %d)", allowOut, reject)
	}
}

// When the LAN mode changes WHILE the killswitch is active, the fresh LAN
// allow-out rules get appended after the existing reject (wrong order). The
// dashboard fixes this by re-applying the killswitch, which deletes+re-adds the
// reject so it lands last again. This pins that recovery at the firewall level.
func TestReapplyKillswitchRestoresRejectLast(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0")

	// Killswitch on first, then a late LAN mode add.
	if err := Enable(&KillswitchConfig{InterfaceName: "wg0", Endpoint: "198.51.100.1"}); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if err := EnableLANStealth(); err != nil {
		t.Fatalf("EnableLANStealth failed: %v", err)
	}

	// Late add leaves allow-out AFTER the reject — the broken state.
	if mock.ruleIndex("allow out to 192.168.0.0/16 comment lazyvpn:st") <= mock.ruleIndex("reject out on eth0 comment lazyvpn:ks") {
		t.Fatal("precondition: late LAN add should leave allow-out after reject")
	}

	// Re-apply the killswitch (what the dashboard does on LAN change).
	if err := Update(&KillswitchConfig{InterfaceName: "wg0", Endpoint: "198.51.100.1"}); err != nil {
		t.Fatalf("Update (reapply) failed: %v", err)
	}

	allowOut := mock.ruleIndex("allow out to 192.168.0.0/16 comment lazyvpn:st")
	reject := mock.ruleIndex("reject out on eth0 comment lazyvpn:ks")
	if allowOut >= reject {
		t.Errorf("after reapply, LAN allow-out (idx %d) must precede reject (idx %d)", allowOut, reject)
	}
}

func TestEnableCommaSeparatedDNS(t *testing.T) {
	mock := setupMock(t)

	cfg := &KillswitchConfig{
		InterfaceName: "wg0",
		DNS:           "10.2.0.1, 10.2.0.2",
	}

	if err := Enable(cfg); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	if !mock.hasRule("ufw allow out proto udp to 10.2.0.1 port 53 comment lazyvpn:ks") {
		t.Error("Missing first DNS UDP rule")
	}
	if !mock.hasRule("ufw allow out proto tcp to 10.2.0.1 port 53 comment lazyvpn:ks") {
		t.Error("Missing first DNS TCP rule")
	}
	if !mock.hasRule("ufw allow out proto udp to 10.2.0.2 port 53 comment lazyvpn:ks") {
		t.Error("Missing second DNS UDP rule")
	}
	if !mock.hasRule("ufw allow out proto tcp to 10.2.0.2 port 53 comment lazyvpn:ks") {
		t.Error("Missing second DNS TCP rule")
	}
}

func TestEnableMixedDNS(t *testing.T) {
	mock := setupMock(t)

	cfg := &KillswitchConfig{
		InterfaceName: "wg0",
		DNS:           "10.2.0.1, 2606:4700:4700::1111",
	}

	if err := Enable(cfg); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// IPv4 DNS
	if !mock.hasRule("ufw allow out proto udp to 10.2.0.1 port 53 comment lazyvpn:ks") {
		t.Error("Missing IPv4 DNS rule")
	}
	// IPv6 DNS
	if !mock.hasRule("ufw allow out proto udp to 2606:4700:4700::1111 port 53 comment lazyvpn:ks") {
		t.Error("Missing IPv6 DNS rule")
	}
}

func TestEnableEmptyDNS(t *testing.T) {
	mock := setupMock(t)

	cfg := &KillswitchConfig{
		InterfaceName: "wg0",
		DNS:           "",
	}

	if err := Enable(cfg); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// Should not have any DNS rules
	for _, r := range mock.getRules() {
		if strings.Contains(r, "port 53") {
			t.Errorf("Should not have DNS rule when DNS is empty, found: %s", r)
		}
	}
}

func TestEnableEmptyEndpoint(t *testing.T) {
	mock := setupMock(t)

	cfg := &KillswitchConfig{
		InterfaceName: "wg0",
		Endpoint:      "",
	}

	if err := Enable(cfg); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// Should not have endpoint-specific rules
	for _, r := range mock.getRules() {
		if strings.Contains(r, "to ") && !strings.Contains(r, "/") && !strings.Contains(r, "lo") && !strings.Contains(r, "on wg0") {
			// Allow loopback and VPN interface rules
			if strings.Contains(r, "allow out to") {
				t.Errorf("Should not have bare endpoint rule when Endpoint is empty, found: %s", r)
			}
		}
	}
}

func TestEnableEmptyInterface(t *testing.T) {
	mock := setupMock(t)

	cfg := &KillswitchConfig{
		InterfaceName: "",
		Endpoint:      "198.51.100.1",
	}

	if err := Enable(cfg); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// Should not have VPN interface rules (except loopback)
	for _, r := range mock.getRules() {
		if strings.Contains(r, "on wg") {
			t.Errorf("Should not have VPN interface rule when InterfaceName is empty, found: %s", r)
		}
	}
}

// withFakeRoute points GetPhysicalInterface at a fake /proc/net/route so the
// LAN-layer functions (which require a physical interface) can run under test.
func withFakeRoute(t *testing.T, iface string) {
	t.Helper()
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		iface + "\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	os.WriteFile(routeFile, []byte(content), 0644)
	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })
}

// The killswitch is leak-prevention only; LAN access is the independent Local
// Network layer's job. Enabling the killswitch must not add any LAN rules.
func TestEnableEmitsNoLANRules(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0")

	if err := Enable(&KillswitchConfig{InterfaceName: "wg0", Endpoint: "198.51.100.1"}); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	for _, cidr := range append(append([]string{}, privateCIDRsV4...), privateCIDRsV6...) {
		if mock.hasRule("ufw allow out to " + cidr + " comment lazyvpn:ks") {
			t.Errorf("killswitch must not emit LAN out rule for %s", cidr)
		}
		if mock.hasRule("ufw allow in from " + cidr + " comment lazyvpn:ks") {
			t.Errorf("killswitch must not emit LAN in rule for %s", cidr)
		}
	}
}

// EnableLANAllow lays down explicit allow in+out rules for every private range,
// so "full LAN access" is a real, inspectable posture rather than a reliance on
// the base policy.
func TestEnableLANAllowAddsExplicitRules(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0")

	if err := EnableLANAllow(); err != nil {
		t.Fatalf("EnableLANAllow failed: %v", err)
	}

	for _, cidr := range privateCIDRsV4 {
		if !mock.hasRule("ufw allow out to " + cidr + " comment lazyvpn:la") {
			t.Errorf("Missing LAN allow-out rule for %s", cidr)
		}
		if !mock.hasRule("ufw allow in on eth0 from " + cidr + " comment lazyvpn:la") {
			t.Errorf("Missing LAN allow-in rule for %s", cidr)
		}
	}
	for _, cidr := range privateCIDRsV6 {
		if !mock.hasRule("ufw allow out to " + cidr + " comment lazyvpn:la") {
			t.Errorf("Missing LAN allow-out rule for %s", cidr)
		}
		if !mock.hasRule("ufw allow in on eth0 from " + cidr + " comment lazyvpn:la") {
			t.Errorf("Missing LAN allow-in rule for %s", cidr)
		}
	}
}

func TestDisableLANAllow(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0")

	if err := EnableLANAllow(); err != nil {
		t.Fatalf("EnableLANAllow failed: %v", err)
	}
	if mock.countRulesWithTag(TagLANAllow) == 0 {
		t.Fatal("expected LAN allow rules after EnableLANAllow")
	}
	if err := DisableLANAllow(); err != nil {
		t.Fatalf("DisableLANAllow failed: %v", err)
	}
	if mock.countRulesWithTag(TagLANAllow) != 0 {
		t.Errorf("expected 0 LAN allow rules after DisableLANAllow, got %d", mock.countRulesWithTag(TagLANAllow))
	}
}

func TestIsLANAllowActive(t *testing.T) {
	setupMock(t)
	withFakeRoute(t, "eth0")

	if IsLANAllowActive() {
		t.Error("IsLANAllowActive should be false before enabling")
	}
	if err := EnableLANAllow(); err != nil {
		t.Fatalf("EnableLANAllow failed: %v", err)
	}
	if !IsLANAllowActive() {
		t.Error("IsLANAllowActive should be true after enabling")
	}
}

// Stealth lays down an explicit allow-out per private range, plus ONE broad
// deny-in on the physical interface (blocks unsolicited inbound from any
// source, LAN or internet — replies/NDP survive via UFW's before.rules).
func TestEnableLANStealthAddsExplicitAllowOut(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0")

	if err := EnableLANStealth(); err != nil {
		t.Fatalf("EnableLANStealth failed: %v", err)
	}
	for _, cidr := range privateCIDRsV4 {
		if !mock.hasRule("ufw allow out to " + cidr + " comment lazyvpn:st") {
			t.Errorf("Missing stealth allow-out rule for %s", cidr)
		}
	}
	if !mock.hasRule("ufw deny in on eth0 comment lazyvpn:st") {
		t.Error("Missing broad stealth deny-in rule (deny in on eth0)")
	}
	// And it must NOT use the old per-CIDR inbound deny.
	if mock.hasRule("ufw deny in on eth0 from 192.168.0.0/16 comment lazyvpn:st") {
		t.Error("Stealth should use a broad deny-in, not per-CIDR")
	}
}

func TestEnableWithDNSContainingEmptyEntries(t *testing.T) {
	mock := setupMock(t)

	cfg := &KillswitchConfig{
		InterfaceName: "wg0",
		DNS:           "10.2.0.1,,  , 10.2.0.2",
	}

	if err := Enable(cfg); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// Count DNS rules
	dnsRuleCount := 0
	for _, r := range mock.getRules() {
		if strings.Contains(r, "port 53") {
			dnsRuleCount++
		}
	}
	// 2 valid addresses * 2 (UDP + TCP) = 4
	if dnsRuleCount != 4 {
		t.Errorf("Expected 4 DNS rules (2 addresses * UDP/TCP), got %d", dnsRuleCount)
	}
}

// TestEnable_InvalidDNSIsSkippedNotFatal mirrors
// TestEnableLANBlock_InvalidDNSIsSkippedNotFatal for the killswitch
// proper. Same contract: a malformed DNS entry in the comma list MUST
// be skipped, valid entries MUST go through, and the killswitch MUST
// still come up. A regression here would prevent users from enabling
// the killswitch at all if their DNS field has a typo.
func TestEnable_InvalidDNSIsSkippedNotFatal(t *testing.T) {
	mock := setupMock(t)

	cfg := &KillswitchConfig{
		InterfaceName: "wg0",
		Endpoint:      "198.51.100.1",
		DNS:           "1.2.3.4,bad-dns,5.6.7.8",
	}
	if err := Enable(cfg); err != nil {
		t.Fatalf("Enable with one invalid DNS: returned %v, want nil", err)
	}

	rules := mock.getRules()
	hasRuleFor := func(ip string) bool {
		for _, r := range rules {
			if strings.Contains(r, " to "+ip+" ") {
				return true
			}
		}
		return false
	}
	if !hasRuleFor("1.2.3.4") {
		t.Error("expected rule for valid DNS 1.2.3.4")
	}
	if !hasRuleFor("5.6.7.8") {
		t.Error("expected rule for valid DNS 5.6.7.8")
	}
	if hasRuleFor("bad-dns") {
		t.Error("rule was added for invalid DNS — validation skipped?")
	}
	if mock.defaultOutgoing != "deny" {
		t.Errorf("default outgoing = %q, want deny (Enable should have completed despite skipped DNS)", mock.defaultOutgoing)
	}
}

func TestEnableInvalidEndpoint(t *testing.T) {
	setupMock(t)

	cfg := &KillswitchConfig{
		InterfaceName: "wg0",
		Endpoint:      "not-an-ip",
	}

	err := Enable(cfg)
	if err == nil {
		t.Error("Enable should fail with invalid endpoint IP")
	}
}

// ---------------------------------------------------------------------------
// Disable tests
// ---------------------------------------------------------------------------

func TestDisableRestoresDefaultAllow(t *testing.T) {
	mock := setupMock(t)

	// Enable first
	cfg := &KillswitchConfig{InterfaceName: "wg0", Endpoint: "198.51.100.1"}
	Enable(cfg)

	if mock.defaultOutgoing != "deny" {
		t.Fatal("Default should be deny after Enable")
	}

	// Disable
	if err := Disable(); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}

	if mock.defaultOutgoing != "allow" {
		t.Errorf("Default outgoing should be 'allow' after Disable, got %q", mock.defaultOutgoing)
	}

	// Should have no killswitch rules
	if mock.countRulesWithTag(TagKillswitch) != 0 {
		t.Error("Should have no killswitch rules after Disable")
	}
}

// TestDisable_RuleDeletionErrorStillRestoresDefault proves Disable
// continues to restore default-allow even when deleteRulesByTag fails.
// This is the unwedge contract: if the user runs `lazyvpn killswitch
// disable` to recover from a stuck state, Disable MUST clear
// default=deny no matter what — otherwise the user is locked out
// of the network and can't even run UFW commands to fix it.
//
// Regression target: refactoring the deleteRulesByTag error to bubble
// up via early-return would break the contract.
func TestDisable_RuleDeletionErrorStillRestoresDefault(t *testing.T) {
	mock := setupMock(t)

	// Pre-existing state: default deny outgoing (killswitch active),
	// some lazyvpn:ks rules present.
	mock.defaultOutgoing = "deny"
	addRule("allow", "out", "on", "lo", "comment", TagKillswitch) // call 0

	// Inject error on the next `show added` call (call 1) — that's the
	// one Disable->deleteRulesByTag will make.
	mock.injectErrorAt(1, fmt.Errorf("ufw show added blew up"))

	if err := Disable(); err != nil {
		t.Fatalf("Disable returned error despite delete failure being non-fatal: %v", err)
	}
	if mock.defaultOutgoing != "allow" {
		t.Errorf("default outgoing = %q, want allow (Disable must unwedge even after delete failure)", mock.defaultOutgoing)
	}
}

// TestDisable_DefaultAllowFailureIsReturned proves the inverse: when
// the `ufw default allow outgoing` itself fails, Disable returns the
// wrapped error so the caller knows the system is still in default-deny
// (a partially-disabled state — rules cleared but user still locked out
// of the network). The caller can then surface this to the user.
func TestDisable_DefaultAllowFailureIsReturned(t *testing.T) {
	mock := setupMock(t)
	mock.defaultOutgoing = "deny"

	// No rules exist, so deleteRulesByTag's `show added` returns empty
	// and no per-rule deletes happen. Calls during Disable:
	//   call 0: show added (succeeds, empty)
	//   call 1: default allow outgoing (we inject error here)
	mock.injectErrorAt(1, fmt.Errorf("synthetic default-allow failure"))

	err := Disable()
	if err == nil {
		t.Fatal("expected error from default-allow failure, got nil")
	}
	if !strings.Contains(err.Error(), "ufw default allow outgoing") {
		t.Errorf("error doesn't mention failed op: %v", err)
	}
	// Default should remain deny since the restoration command failed.
	if mock.defaultOutgoing != "deny" {
		t.Errorf("default outgoing = %q, want deny (no restoration happened)", mock.defaultOutgoing)
	}
}

func TestDisableWhenNotActive(t *testing.T) {
	setupMock(t)

	// Disable when nothing is active should not error
	if err := Disable(); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// IsActive tests
// ---------------------------------------------------------------------------

func TestIsActiveReflectsState(t *testing.T) {
	setupMock(t)

	// Initially not active
	if IsActive() {
		t.Error("Should not be active initially")
	}

	// After Enable
	Enable(&KillswitchConfig{InterfaceName: "wg0"})
	if !IsActive() {
		t.Error("Should be active after Enable")
	}

	// After Disable
	Disable()
	if IsActive() {
		t.Error("Should not be active after Disable")
	}
}

// ---------------------------------------------------------------------------
// Update tests
// ---------------------------------------------------------------------------

func TestUpdateOnlyWhenActive(t *testing.T) {
	setupMock(t)

	// Update when killswitch is not active should be no-op
	newCfg := &KillswitchConfig{InterfaceName: "wg1", Endpoint: "203.0.113.1"}
	if err := Update(newCfg); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if IsActive() {
		t.Error("Update when inactive should not activate killswitch")
	}
}

func TestUpdateWhenActive(t *testing.T) {
	mock := setupMock(t)

	// Enable with first config
	Enable(&KillswitchConfig{InterfaceName: "wg0", Endpoint: "198.51.100.1"})
	if !mock.hasRule("ufw allow out to 198.51.100.1 comment lazyvpn:ks") {
		t.Fatal("Should have old endpoint rule")
	}

	// Update with new endpoint
	Update(&KillswitchConfig{InterfaceName: "wg0", Endpoint: "203.0.113.1"})

	if mock.hasRule("ufw allow out to 198.51.100.1 comment lazyvpn:ks") {
		t.Error("Old endpoint rule should be gone after Update")
	}
	if !mock.hasRule("ufw allow out to 203.0.113.1 comment lazyvpn:ks") {
		t.Error("New endpoint rule should exist after Update")
	}
}

func TestUpdateChangesInterface(t *testing.T) {
	mock := setupMock(t)

	Enable(&KillswitchConfig{InterfaceName: "wg0", Endpoint: "198.51.100.1"})
	if !mock.hasRule("ufw allow out on wg0 comment lazyvpn:ks") {
		t.Fatal("Should have old interface rule")
	}

	Update(&KillswitchConfig{InterfaceName: "wg1", Endpoint: "198.51.100.1"})

	if mock.hasRule("ufw allow out on wg0 comment lazyvpn:ks") {
		t.Error("Old interface rule should be gone")
	}
	if !mock.hasRule("ufw allow out on wg1 comment lazyvpn:ks") {
		t.Error("New interface rule should exist")
	}
}

// ---------------------------------------------------------------------------
// EnableSimple tests
// ---------------------------------------------------------------------------

func TestEnableSimpleBlocksAll(t *testing.T) {
	mock := setupMock(t)

	if err := EnableSimple(); err != nil {
		t.Fatalf("EnableSimple failed: %v", err)
	}

	// Default should be deny
	if mock.defaultOutgoing != "deny" {
		t.Errorf("Default outgoing should be 'deny', got %q", mock.defaultOutgoing)
	}

	// Loopback allowed both directions
	if !mock.hasRule("ufw allow out on lo comment lazyvpn:ks") {
		t.Error("Missing loopback out rule")
	}
	if !mock.hasRule("ufw allow in on lo comment lazyvpn:ks") {
		t.Error("Missing loopback in rule")
	}

	// Simple mode emits NO LAN rules — the independent Local Network layer owns
	// LAN, and its allow-out rules (lower numbers) beat this default-deny so
	// LAN/SSH survive while disconnected.
	if mock.hasRule("ufw allow in from 192.168.0.0/16 comment lazyvpn:ks") {
		t.Error("Simple killswitch must not emit LAN rules")
	}

	// loopback out + loopback in = 2 (no LAN rules anymore)
	if mock.countRulesWithTag(TagKillswitch) != 2 {
		t.Errorf("Expected 2 killswitch rules, got %d", mock.countRulesWithTag(TagKillswitch))
	}
}

// TestEnableSimpleRollsBackOnLoopbackFailure verifies that if the
// loopback addRule fails, EnableSimple restores the previous default
// outgoing policy instead of leaving the system half-configured
// (existing killswitch rules deleted, default policy unchanged from
// pre-call state).
//
// Pre-fix the function returned early on loopback failure WITHOUT
// the deferred rollback in place — so a caller that had prior
// killswitch rules (now deleted) and a "deny" default policy would
// end up with no rules but the policy stuck at whatever it was
// before. The rollback's hardcoded "allow" also meant a deny-state
// caller got silently downgraded to allow.
func TestEnableSimpleRollsBackOnLoopbackFailure(t *testing.T) {
	mock := setupMock(t)
	// Pre-set the policy to "deny" (simulating an already-active
	// killswitch). EnableSimple should restore this on rollback,
	// not downgrade to "allow".
	mock.defaultOutgoing = "deny"

	// Inject error at the addRule for loopback. Call sequence:
	//   call 0: status verbose (getDefaultOutgoingPolicy)
	//   call 1: show added (deleteRulesByTag)
	//   call 2: allow out on lo ... (loopback) <- inject here
	mock.errors[2] = fmt.Errorf("simulated ufw failure")

	if err := EnableSimple(); err == nil {
		t.Fatal("EnableSimple should return error when loopback addRule fails")
	}

	if mock.defaultOutgoing != "deny" {
		t.Errorf("defaultOutgoing = %q after failure, want %q (rollback should restore prev policy)",
			mock.defaultOutgoing, "deny")
	}
	if mock.countRulesWithTag(TagKillswitch) != 0 {
		t.Errorf("expected 0 killswitch rules after rollback, got %d", mock.countRulesWithTag(TagKillswitch))
	}
}

func TestEnableSimpleIsActive(t *testing.T) {
	setupMock(t)

	if err := EnableSimple(); err != nil {
		t.Fatalf("EnableSimple failed: %v", err)
	}

	if !IsActive() {
		t.Error("IsActive should return true after EnableSimple")
	}
}

// ---------------------------------------------------------------------------
// LAN Block tests
// ---------------------------------------------------------------------------

func TestEnableLANBlock(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0")

	if err := EnableLANBlock("wg0", "198.51.100.1", "192.168.1.1", "10.2.0.1"); err != nil {
		t.Fatalf("EnableLANBlock failed: %v", err)
	}

	// Should have loopback rule
	if !mock.hasRule("ufw allow out on lo comment lazyvpn:lb") {
		t.Error("Missing loopback rule")
	}

	// Should have VPN interface rule
	if !mock.hasRule("ufw allow out on wg0 comment lazyvpn:lb") {
		t.Error("Missing VPN interface rule")
	}

	// Should have endpoint rule
	if !mock.hasRule("ufw allow out to 198.51.100.1 comment lazyvpn:lb") {
		t.Error("Missing endpoint rule")
	}

	// Should have gateway rule
	if !mock.hasRule("ufw allow out to 192.168.1.1/32 comment lazyvpn:lb") {
		t.Error("Missing gateway rule")
	}

	// Should have DNS allow rules
	if !mock.hasRule("ufw allow out proto udp to 10.2.0.1 port 53 comment lazyvpn:lb") {
		t.Error("Missing DNS UDP allow rule")
	}
	if !mock.hasRule("ufw allow out proto tcp to 10.2.0.1 port 53 comment lazyvpn:lb") {
		t.Error("Missing DNS TCP allow rule")
	}

	// Should have DHCP rule
	if !mock.hasRule("ufw allow out proto udp to any port 67:68 comment lazyvpn:lb") {
		t.Error("Missing DHCP rule")
	}

	// Should have outbound deny rules for private CIDRs
	for _, cidr := range privateCIDRsV4 {
		if !mock.hasRule("ufw deny out to " + cidr + " comment lazyvpn:lb") {
			t.Errorf("Missing outbound deny rule for %s", cidr)
		}
	}
	for _, cidr := range privateCIDRsV6 {
		if !mock.hasRule("ufw deny out to " + cidr + " comment lazyvpn:lb") {
			t.Errorf("Missing outbound deny rule for %s", cidr)
		}
	}

	// Should have ONE broad inbound deny on the physical interface (blocks all
	// unsolicited inbound — LAN and internet, SSH included; replies survive).
	if !mock.hasRule("ufw deny in on eth0 comment lazyvpn:lb") {
		t.Error("Missing broad inbound deny rule (deny in on eth0)")
	}
	if mock.hasRule("ufw deny in from 192.168.0.0/16 comment lazyvpn:lb") {
		t.Error("Block should use a broad deny-in, not per-CIDR")
	}
}

func TestDisableLANBlock(t *testing.T) {
	mock := setupMock(t)

	EnableLANBlock("wg0", "198.51.100.1", "192.168.1.1", "10.2.0.1")

	if mock.countRulesWithTag(TagLANBlock) == 0 {
		t.Fatal("Should have LAN block rules after enable")
	}

	if err := DisableLANBlock(); err != nil {
		t.Fatalf("DisableLANBlock failed: %v", err)
	}

	if mock.countRulesWithTag(TagLANBlock) != 0 {
		t.Error("Should have no LAN block rules after disable")
	}
}

func TestIsLANBlockActive(t *testing.T) {
	setupMock(t)

	if IsLANBlockActive() {
		t.Error("Should not be active initially")
	}

	EnableLANBlock("wg0", "198.51.100.1", "192.168.1.1", "10.2.0.1")
	if !IsLANBlockActive() {
		t.Error("Should be active after enable")
	}

	DisableLANBlock()
	if IsLANBlockActive() {
		t.Error("Should not be active after disable")
	}
}

func TestEnableLANBlockEmptyVPNInterface(t *testing.T) {
	mock := setupMock(t)

	if err := EnableLANBlock("", "198.51.100.1", "192.168.1.1", "10.2.0.1"); err != nil {
		t.Fatalf("EnableLANBlock failed: %v", err)
	}

	// Should not have VPN interface rule
	for _, r := range mock.getRules() {
		if strings.Contains(r, "on wg") {
			t.Errorf("Should not have VPN interface rule, found: %s", r)
		}
	}
}

func TestEnableLANBlockEmptyEndpoint(t *testing.T) {
	mock := setupMock(t)

	if err := EnableLANBlock("wg0", "", "192.168.1.1", "10.2.0.1"); err != nil {
		t.Fatalf("EnableLANBlock failed: %v", err)
	}

	// Should not have endpoint rule (but should have gateway)
	for _, r := range mock.getRules() {
		if strings.Contains(r, "198.51.100.1") {
			t.Errorf("Should not have endpoint rule, found: %s", r)
		}
	}
}

func TestEnableLANBlockEmptyGateway(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0") // detected gateway = 192.168.1.1

	if err := EnableLANBlock("wg0", "198.51.100.1", "", "10.2.0.1"); err != nil {
		t.Fatalf("EnableLANBlock failed: %v", err)
	}

	// Block must always be able to reach the gateway (it's the one local
	// exception). With no gateway passed, it falls back to the detected default.
	if !mock.hasRule("ufw allow out to 192.168.1.1/32 comment lazyvpn:lb") {
		t.Error("Block should fall back to the detected gateway when none is passed")
	}
}

func TestEnableLANBlockEmptyDNS(t *testing.T) {
	mock := setupMock(t)

	if err := EnableLANBlock("wg0", "198.51.100.1", "192.168.1.1", ""); err != nil {
		t.Fatalf("EnableLANBlock failed: %v", err)
	}

	// Should not have any DNS port 53 rules
	for _, r := range mock.getRules() {
		if strings.Contains(r, "port 53") {
			t.Errorf("Should not have DNS rule with empty dns param, found: %s", r)
		}
	}
}

// TestEnableLANBlock_InvalidDNSIsSkippedNotFatal confirms the
// validation contract for DNS entries: malformed addresses (e.g. a
// stale config typo or copy-paste artifact) MUST be skipped with a
// log warning and the function MUST still succeed. A regression that
// returned an error here would disable LAN-block entirely on any
// config with a single bad DNS entry — a cliff-edge UX failure.
//
// Mirror coverage gap: enableLocked has the same invalid-DNS skip;
// the pattern matters wherever a user-controlled comma-separated
// IP list reaches addRule.
func TestEnableLANBlock_InvalidDNSIsSkippedNotFatal(t *testing.T) {
	mock := setupMock(t)

	err := EnableLANBlock(
		"", // no vpn iface — keeps rule count predictable
		"",
		"",
		"1.2.3.4,not-an-ip,5.6.7.8",
	)
	if err != nil {
		t.Fatalf("EnableLANBlock with one invalid DNS: returned %v, want nil (invalid entries should be skipped)", err)
	}

	rules := mock.getRules()
	hasRuleFor := func(ip string) bool {
		for _, r := range rules {
			if strings.Contains(r, " to "+ip+" ") {
				return true
			}
		}
		return false
	}
	if !hasRuleFor("1.2.3.4") {
		t.Error("expected rule for valid DNS 1.2.3.4")
	}
	if !hasRuleFor("5.6.7.8") {
		t.Error("expected rule for valid DNS 5.6.7.8")
	}
	if hasRuleFor("not-an-ip") {
		t.Error("rule was added for invalid DNS — validation skipped?")
	}
}

// TestEnableLANBlock_RollbackOnAddRuleFailure verifies that when an
// addRule fails partway through EnableLANBlock, the deferred rollback
// at the top of the function deletes any rules that did get added.
// Pre-fix the rollback didn't exist and a partial-failure left
// stranded TagLANBlock rules — half-block + still-allowed surface.
//
// Coverage gap closer for EnableLANBlock's defer body (lines 608-613).
// Sibling to TestEnableSimpleRollbackPreservesPrevPolicy.
func TestEnableLANBlock_RollbackOnAddRuleFailure(t *testing.T) {
	mock := setupMock(t)

	// Call sequence for EnableLANBlock entry:
	//   call 0: show added (deleteRulesByTag scan, returns no rules)
	//   call 1: status      (ensureUFWEnabled check — UFW reported active)
	//   call 2: addRule allow loopback     <-- inject here
	mock.errors[2] = fmt.Errorf("simulated ufw failure on loopback")

	err := EnableLANBlock("wg0", "198.51.100.1", "192.168.1.1", "10.2.0.1")
	if err == nil {
		t.Fatal("EnableLANBlock should return error when an addRule fails")
	}

	// Rollback must have removed any TagLANBlock rules that managed to
	// land before the failure (in this scenario, none — the very first
	// addRule failed — but we still want to confirm the count is 0
	// rather than something larger).
	if got := mock.countRulesWithTag(TagLANBlock); got != 0 {
		t.Errorf("expected 0 LAN-block rules after rollback, got %d", got)
	}
}

// TestEnableLANBlock_RollbackRemovesPartialRules confirms rollback when
// the failure happens MID-sequence (after several rules have already
// been added). The rollback must delete every rule with TagLANBlock,
// not just the most recent.
func TestEnableLANBlock_RollbackRemovesPartialRules(t *testing.T) {
	mock := setupMock(t)

	// Inject at call 5 — gives the loopback / vpn-tunnel / endpoint /
	// gateway addRules a chance to land, then fails on the DHCP rule.
	// After the failure, rollback should clear ALL TagLANBlock rules
	// (loopback + vpn + endpoint + gateway), not just the failed one.
	//   call 0: show added
	//   call 1: addRule allow loopback         (lands)
	//   call 2: addRule allow out on wg0       (lands)
	//   call 3: addRule allow out to endpoint  (lands)
	//   call 4: addRule allow out to gw/32     (lands)
	//   call 5: addRule allow out udp port 53  <-- inject here (FAIL on DNS)
	mock.errors[5] = fmt.Errorf("simulated ufw failure on DNS rule")

	err := EnableLANBlock("wg0", "198.51.100.1", "192.168.1.1", "10.2.0.1")
	if err == nil {
		t.Fatal("EnableLANBlock should return error when DNS addRule fails")
	}

	// Every TagLANBlock rule must be gone — including the four that
	// successfully landed before the failure.
	if got := mock.countRulesWithTag(TagLANBlock); got != 0 {
		t.Errorf("expected 0 LAN-block rules after rollback, got %d (rollback didn't clean partials)", got)
	}
}

func TestEnableLANBlockMultipleDNS(t *testing.T) {
	mock := setupMock(t)

	if err := EnableLANBlock("wg0", "198.51.100.1", "192.168.1.1", "10.2.0.1, 10.2.0.2"); err != nil {
		t.Fatalf("EnableLANBlock failed: %v", err)
	}

	// Should have DNS rules for both servers
	if !mock.hasRule("ufw allow out proto udp to 10.2.0.1 port 53 comment lazyvpn:lb") {
		t.Error("Missing DNS UDP rule for 10.2.0.1")
	}
	if !mock.hasRule("ufw allow out proto udp to 10.2.0.2 port 53 comment lazyvpn:lb") {
		t.Error("Missing DNS UDP rule for 10.2.0.2")
	}
	if !mock.hasRule("ufw allow out proto tcp to 10.2.0.1 port 53 comment lazyvpn:lb") {
		t.Error("Missing DNS TCP rule for 10.2.0.1")
	}
	if !mock.hasRule("ufw allow out proto tcp to 10.2.0.2 port 53 comment lazyvpn:lb") {
		t.Error("Missing DNS TCP rule for 10.2.0.2")
	}
}

// ---------------------------------------------------------------------------
// LAN Stealth tests
// ---------------------------------------------------------------------------

func TestEnableLANStealth(t *testing.T) {
	mock := setupMock(t)

	// Set up a fake route
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	os.WriteFile(routeFile, []byte(content), 0644)
	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	if err := EnableLANStealth(); err != nil {
		t.Fatalf("EnableLANStealth failed: %v", err)
	}

	// Should have DHCP allow
	if !mock.hasRule("ufw allow in on eth0 proto udp from any port 67:68 comment lazyvpn:st") {
		t.Error("Missing DHCP inbound allow rule")
	}

	// Should have one broad deny-in on the physical interface (blocks all
	// unsolicited inbound, any source — replies/NDP survive via before.rules).
	if !mock.hasRule("ufw deny in on eth0 comment lazyvpn:st") {
		t.Error("Missing broad deny-in rule (deny in on eth0)")
	}
}

func TestDisableLANStealth(t *testing.T) {
	mock := setupMock(t)

	// Set up a fake route
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	os.WriteFile(routeFile, []byte(content), 0644)
	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	EnableLANStealth()

	if mock.countRulesWithTag(TagStealth) == 0 {
		t.Fatal("Should have stealth rules after enable")
	}

	if err := DisableLANStealth(); err != nil {
		t.Fatalf("DisableLANStealth failed: %v", err)
	}

	if mock.countRulesWithTag(TagStealth) != 0 {
		t.Error("Should have no stealth rules after disable")
	}
}

func TestIsLANStealthActive(t *testing.T) {
	setupMock(t)

	// Set up a fake route
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	os.WriteFile(routeFile, []byte(content), 0644)
	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	if IsLANStealthActive() {
		t.Error("Should not be active initially")
	}

	EnableLANStealth()
	if !IsLANStealthActive() {
		t.Error("Should be active after enable")
	}

	DisableLANStealth()
	if IsLANStealthActive() {
		t.Error("Should not be active after disable")
	}
}

// TestSysctlIPv6ConfPath_MatchesSudoersEntries is the cross-package
// consistency pin between:
//
//   internal/firewall/killswitch.go:
//     var sysctlIPv6ConfPath = "/etc/sysctl.d/99-lazyvpn-ipv6.conf"
//
//   internal/sudo/sudoers.go (3 NOPASSWD entries referencing the path):
//     /usr/bin/shred -u /etc/sysctl.d/99-lazyvpn-ipv6.conf  (non-CoW)
//     /usr/bin/sysctl -p /etc/sysctl.d/99-lazyvpn-ipv6.conf
//     /usr/bin/tee     /etc/sysctl.d/99-lazyvpn-ipv6.conf
//
// A regression that renamed the path (e.g. to "/etc/sysctl.d/lazyvpn.conf")
// in only one file would silently break the runtime — sudo denies the
// call to the new path because the sudoers entry still references the
// old one. Symptom: IPv6 toggle UI says "applied" but the persistent
// conf doesn't get written / sysctl never reloaded.
//
// Source-scan reads both files and verifies the path appears in BOTH.
// Same family as 2c2c8d7 (sudo↔sudoers capability string) and
// 5344841 (ipv6ProcPaths↔sysctlContent).
func TestSysctlIPv6ConfPath_MatchesSudoersEntries(t *testing.T) {
	// sysctlIPv6ConfPath is a package-private var, so we can read it directly.
	pathLiteral := sysctlIPv6ConfPath

	// Scan sibling package source for the same path string.
	sudoersSrc, err := os.ReadFile("../sudo/sudoers.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sudoersSrc), pathLiteral) {
		t.Errorf("internal/sudo/sudoers.go missing path %q — runtime sudo calls would be denied (renamed in one file but not the other)", pathLiteral)
	}

	// All three NOPASSWD entries should reference the path. Count
	// occurrences — if anyone reduced the count, surface it (helps
	// catch a refactor that swapped tee/sysctl/shred for one entry).
	wantOccurrences := 3
	if got := strings.Count(string(sudoersSrc), pathLiteral); got < wantOccurrences {
		t.Errorf("internal/sudo/sudoers.go references path %q only %d times, want >=%d (one per sudoers entry: shred + sysctl -p + tee)",
			pathLiteral, got, wantOccurrences)
	}
}

// TestIPv6Sources_ConsistencyAcrossProcPathsAndSysctlContent is the
// cross-source consistency pin for DisableIPv6. Two parallel lists
// must stay in sync:
//
//   ipv6ProcPaths slice (var):
//     "/proc/sys/net/ipv6/conf/all/disable_ipv6"
//     "/proc/sys/net/ipv6/conf/default/disable_ipv6"
//     "/proc/sys/net/ipv6/conf/lo/disable_ipv6"
//
//   sysctlContent string literal (inside DisableIPv6):
//     net.ipv6.conf.all.disable_ipv6 = 1
//     net.ipv6.conf.default.disable_ipv6 = 1
//     net.ipv6.conf.lo.disable_ipv6 = 1
//
// Each /proc path corresponds to a sysctl key. Layer 1 (proc writes)
// and Layer 2 (persistent sysctl conf) must cover the same interfaces;
// drift means kernel runtime and persistent state diverge.
//
// 9e8cc3e pinned the ipv6ProcPaths contents alone. This pin enforces
// the cross-source equivalence — extracts the interface name from
// each /proc path and verifies sysctlContent in killswitch.go source
// contains a matching "net.ipv6.conf.<name>.disable_ipv6 = 1" line.
//
// Same family as 2c2c8d7 (sudo/sudoers capability string).
func TestIPv6Sources_ConsistencyAcrossProcPathsAndSysctlContent(t *testing.T) {
	src, err := os.ReadFile("killswitch.go")
	if err != nil {
		t.Fatal(err)
	}
	srcStr := string(src)

	// For each /proc path in ipv6ProcPaths, derive the matching
	// sysctl key and verify both forms appear in the source file.
	for _, p := range ipv6ProcPaths {
		// Path shape: /proc/sys/net/ipv6/conf/<iface>/disable_ipv6
		// Extract <iface> between "conf/" and "/disable_ipv6".
		const prefix = "/proc/sys/net/ipv6/conf/"
		const suffix = "/disable_ipv6"
		if !strings.HasPrefix(p, prefix) || !strings.HasSuffix(p, suffix) {
			t.Fatalf("ipv6ProcPaths entry %q has unexpected shape", p)
		}
		iface := strings.TrimSuffix(strings.TrimPrefix(p, prefix), suffix)

		// Verify the matching sysctl line appears in the source file's
		// sysctlContent block. Tolerate any " = 1" formatting variation
		// (with or without spaces).
		want := "net.ipv6.conf." + iface + ".disable_ipv6"
		if !strings.Contains(srcStr, want+" = 1") {
			t.Errorf("sysctlContent in killswitch.go missing %q = 1 line — drift from ipv6ProcPaths[%q]", want, p)
		}
	}
}

// TestPrivateCIDRs_ContentsPinned locks the exact set of CIDRs used
// for LAN block / LAN stealth deny rules. Both lists need to cover
// every private/link-local range for the protection to be complete:
//
//   IPv4 RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
//   IPv4 RFC3927: 169.254.0.0/16 (link-local — often forgotten!)
//   IPv6 RFC4291: fe80::/10 (link-local)
//   IPv6 RFC4193: fc00::/7  (ULA)
//
// A regression that dropped 169.254.0.0/16 would let APIPA-assigned
// IPv4 addresses bypass LAN block (a real attack surface on WiFi
// with no DHCP). A regression dropping fe80::/10 would let IPv6
// link-local discovery still work — defeats LAN stealth's "appear
// offline" purpose.
//
// The existing loops in EnableLANBlock / EnableLANStealth tests
// iterate over these lists, so missing entries would silently leave
// rules unset without test failure. Pinning catches it directly.
func TestPrivateCIDRs_ContentsPinned(t *testing.T) {
	wantV4 := []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "169.254.0.0/16"}
	wantV6 := []string{"fe80::/10", "fc00::/7"}

	if len(privateCIDRsV4) != len(wantV4) {
		t.Fatalf("len(privateCIDRsV4) = %d, want %d", len(privateCIDRsV4), len(wantV4))
	}
	for i, want := range wantV4 {
		if privateCIDRsV4[i] != want {
			t.Errorf("privateCIDRsV4[%d] = %q, want %q", i, privateCIDRsV4[i], want)
		}
	}

	if len(privateCIDRsV6) != len(wantV6) {
		t.Fatalf("len(privateCIDRsV6) = %d, want %d", len(privateCIDRsV6), len(wantV6))
	}
	for i, want := range wantV6 {
		if privateCIDRsV6[i] != want {
			t.Errorf("privateCIDRsV6[%d] = %q, want %q", i, privateCIDRsV6[i], want)
		}
	}
}

// TestIPv6ProcPaths_ContentsPinned locks the exact set of /proc paths
// DisableIPv6 writes to. Three interfaces (all, default, lo) must all
// be disabled for IPv6 protection to actually prevent leaks:
//
//   - "all":     blocks NEW IPv6 sockets at default kernel level
//   - "default": new interfaces inherit this setting
//   - "lo":      loopback (so localhost-only IPv6 services can't bind)
//
// Without "lo", IPv6 still works on the loopback — services that
// bind to "::1" continue to function and the user might think
// IPv6 is OFF when in fact half-on. Without "default", new
// interfaces (e.g. wg0 itself) come up with IPv6 enabled.
//
// The persistent sysctl config string (in DisableIPv6) lists the
// same three interfaces — a regression that ADDED a path here but
// not in sysctlContent (or vice versa) would leave the kernel
// runtime state and the persistent config out of sync. Pin both
// the count and the contents.
func TestIPv6ProcPaths_ContentsPinned(t *testing.T) {
	want := []string{
		"/proc/sys/net/ipv6/conf/all/disable_ipv6",
		"/proc/sys/net/ipv6/conf/default/disable_ipv6",
		"/proc/sys/net/ipv6/conf/lo/disable_ipv6",
	}
	if len(ipv6ProcPaths) != len(want) {
		t.Fatalf("len(ipv6ProcPaths) = %d, want %d (regression: count diverged from sysctl conf string?)", len(ipv6ProcPaths), len(want))
	}
	for i, p := range want {
		if ipv6ProcPaths[i] != p {
			t.Errorf("ipv6ProcPaths[%d] = %q, want %q", i, ipv6ProcPaths[i], p)
		}
	}
}

// TestIsActive_FunctionsAreTagIsolated pins the cross-tag isolation
// contract: each Is*Active function checks its OWN tag (or
// default-policy), not another mode's tag. A regression that swapped
// tags (e.g. IsLANBlockActive checks lazyvpn:st instead of lazyvpn:lb)
// would silently misreport state, sending the user into "why is my
// LAN block on when I never enabled it" spirals.
//
// The contract:
//   IsActive():          getDefaultOutgoingPolicy() == "deny"  (NOT a tag)
//   IsLANBlockActive():  hasRulesWithTag(TagLANBlock)
//   IsLANStealthActive():hasRulesWithTag(TagStealth)
//
// Test: enable LAN Block, verify IsLANBlockActive=true AND
// IsLANStealthActive=false AND IsActive=false. Then swap: enable LAN
// Stealth, verify the other two arms are false.
func TestIsActive_FunctionsAreTagIsolated(t *testing.T) {
	// Set up a fake route so EnableLANStealth (needs physIface) doesn't fail.
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	os.WriteFile(routeFile, []byte(content), 0644)
	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	t.Run("LANBlock_isolated_from_Stealth_and_KS", func(t *testing.T) {
		setupMock(t)

		if err := EnableLANBlock("wg0", "198.51.100.1", "192.168.1.1", "10.2.0.1"); err != nil {
			t.Fatalf("EnableLANBlock: %v", err)
		}

		if !IsLANBlockActive() {
			t.Error("IsLANBlockActive() = false after EnableLANBlock — own tag not checked")
		}
		if IsLANStealthActive() {
			t.Error("IsLANStealthActive() = true after EnableLANBlock — wrong tag detected!")
		}
		if IsActive() {
			t.Error("IsActive() = true after EnableLANBlock — killswitch policy mistakenly active")
		}
	})

	t.Run("Stealth_isolated_from_LANBlock_and_KS", func(t *testing.T) {
		setupMock(t)

		if err := EnableLANStealth(); err != nil {
			t.Fatalf("EnableLANStealth: %v", err)
		}

		if !IsLANStealthActive() {
			t.Error("IsLANStealthActive() = false after EnableLANStealth — own tag not checked")
		}
		if IsLANBlockActive() {
			t.Error("IsLANBlockActive() = true after EnableLANStealth — wrong tag detected!")
		}
		if IsActive() {
			t.Error("IsActive() = true after EnableLANStealth — killswitch policy mistakenly active")
		}
	})
}

// TestEnableLANStealth_RollbackOnAddRuleFailure verifies the deferred
// rollback at the top of EnableLANStealth fires when an addRule fails.
// Sibling to TestEnableLANBlock_RollbackOnAddRuleFailure — same bug
// class, same risk if the rollback ever regresses.
func TestEnableLANStealth_RollbackOnAddRuleFailure(t *testing.T) {
	mock := setupMock(t)

	// Stub procNetRoutePath so GetPhysicalInterface returns a real
	// iface name (otherwise EnableLANStealth bails before any addRule).
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	os.WriteFile(routeFile, []byte(content), 0644)
	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	// Call sequence:
	//   call 0: show added (deleteRulesByTag scan, no rules)
	//   call 1: status      (ensureUFWEnabled check — UFW reported active)
	//   call 2: addRule allow in DHCP on eth0  <-- inject here
	mock.errors[2] = fmt.Errorf("simulated ufw failure on DHCP allow")

	if err := EnableLANStealth(); err == nil {
		t.Fatal("EnableLANStealth should return error when DHCP addRule fails")
	}

	if got := mock.countRulesWithTag(TagStealth); got != 0 {
		t.Errorf("expected 0 stealth rules after rollback, got %d", got)
	}
}

// TestEnableLANStealth_RollbackRemovesPartialRules sandwiches the
// failure at a mid-sequence addRule (after DHCP and one deny landed)
// and verifies the rollback removes ALL TagStealth rules.
func TestEnableLANStealth_RollbackRemovesPartialRules(t *testing.T) {
	mock := setupMock(t)

	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	os.WriteFile(routeFile, []byte(content), 0644)
	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	// Call sequence (broadened stealth: DHCP-in, allow-out per range, then ONE
	// broad deny-in):
	//   call 0: show added (deleteRulesByTag scan)
	//   call 1: status     (ensureUFWEnabled check)
	//   call 2: addRule allow in DHCP on eth0              (lands)
	//   call 3..8: addRule allow out to <6 private CIDRs>  (land)
	//   call 9: addRule deny in on eth0 (broad)            <-- inject (FAIL)
	// By now DHCP + all allow-out rules have landed, so the rollback must wipe a
	// mix of rule types, not just the failed one.
	mock.errors[9] = fmt.Errorf("simulated ufw failure mid-sequence")

	if err := EnableLANStealth(); err == nil {
		t.Fatal("EnableLANStealth should return error when mid-sequence addRule fails")
	}

	// Both the DHCP allow AND the first deny that landed must be wiped
	// by the rollback — not just the failed rule.
	if got := mock.countRulesWithTag(TagStealth); got != 0 {
		t.Errorf("expected 0 stealth rules after rollback, got %d (rollback didn't clean partials)", got)
	}
}

func TestEnableLANStealthNoPhysicalInterface(t *testing.T) {
	setupMock(t)

	// Point to nonexistent route file
	oldPath := procNetRoutePath
	procNetRoutePath = "/nonexistent/route"
	t.Cleanup(func() { procNetRoutePath = oldPath })

	err := EnableLANStealth()
	if err == nil {
		t.Error("EnableLANStealth should fail when no physical interface found")
	}
}

// ---------------------------------------------------------------------------
// Teardown tests
// ---------------------------------------------------------------------------

func TestTeardown(t *testing.T) {
	mock := setupMock(t)

	// Set up fake route for stealth
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	os.WriteFile(routeFile, []byte(content), 0644)
	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	// Enable everything, including the explicit LAN allow layer (tag la).
	Enable(&KillswitchConfig{InterfaceName: "wg0", Endpoint: "198.51.100.1"})
	EnableLANBlock("wg0", "198.51.100.1", "192.168.1.1", "10.2.0.1")
	EnableLANStealth()
	EnableLANAllow()

	if err := Teardown(); err != nil {
		t.Fatalf("Teardown failed: %v", err)
	}

	// Outgoing was set to deny by the killswitch enable; Teardown must
	// restore it (lazyvpn changed it, lazyvpn must reset it).
	if mock.defaultOutgoing != "allow" {
		t.Errorf("Default outgoing should be 'allow', got %q", mock.defaultOutgoing)
	}
	// lazyvpn never sets the incoming default explicitly (it relies on UFW's
	// own deny-incoming default when activating UFW), so the mock's incoming
	// default is untouched and remains "allow" — Teardown must not change it.
	if mock.defaultIncoming != "allow" {
		t.Errorf("Default incoming should be 'allow' (untouched), got %q", mock.defaultIncoming)
	}

	// All tagged rules should be removed
	for _, tag := range []string{TagKillswitch, TagLANBlock, TagStealth, TagLANAllow, TagIPv6} {
		if mock.countRulesWithTag(tag) != 0 {
			t.Errorf("Should have no rules with tag %s after Teardown", tag)
		}
	}
}

// The killswitch is OUTBOUND-ONLY: it flips the outgoing default to deny and
// never touches the incoming policy (inbound is owned by the Local Network
// layer). Teardown resets only what it changed — outgoing back to allow,
// incoming left exactly as the user had it.
func TestKillswitchIsOutboundOnly(t *testing.T) {
	mock := setupMock(t)
	mock.defaultIncoming = "allow" // user's policy — must never be touched
	mock.defaultOutgoing = "allow"

	if err := EnableSimple(); err != nil {
		t.Fatalf("EnableSimple failed: %v", err)
	}
	if mock.defaultOutgoing != "deny" {
		t.Fatalf("outgoing should be 'deny' after EnableSimple, got %q", mock.defaultOutgoing)
	}
	if mock.defaultIncoming != "allow" {
		t.Errorf("killswitch is outbound-only: incoming must stay 'allow', got %q", mock.defaultIncoming)
	}

	if err := Teardown(); err != nil {
		t.Fatalf("Teardown failed: %v", err)
	}
	if mock.defaultOutgoing != "allow" {
		t.Errorf("outgoing should be restored to 'allow' after Teardown, got %q", mock.defaultOutgoing)
	}
	if mock.defaultIncoming != "allow" {
		t.Errorf("incoming must remain untouched after Teardown, got %q", mock.defaultIncoming)
	}
}

// ---------------------------------------------------------------------------
// IPv6 disable/enable tests
// ---------------------------------------------------------------------------

func TestDisableIPv6WritesToProcAndAddsRule(t *testing.T) {
	mock := setupMock(t)

	tmpDir := t.TempDir()
	procPaths := []string{
		filepath.Join(tmpDir, "all_disable_ipv6"),
		filepath.Join(tmpDir, "default_disable_ipv6"),
		filepath.Join(tmpDir, "lo_disable_ipv6"),
	}
	for _, p := range procPaths {
		os.WriteFile(p, []byte("0"), 0644)
	}

	sysctlPath := filepath.Join(tmpDir, "99-lazyvpn-ipv6.conf")

	oldProcPaths := ipv6ProcPaths
	oldSysctl := sysctlIPv6ConfPath
	oldWriteFile := writeFile
	oldWriteSysctl := writeSysctlConf
	ipv6ProcPaths = procPaths
	sysctlIPv6ConfPath = sysctlPath
	writeFile = os.WriteFile
	// Bypass sudo: write directly to the temp sysctlPath.
	writeSysctlConf = func(content string) error {
		return os.WriteFile(sysctlIPv6ConfPath, []byte(content), 0644)
	}
	t.Cleanup(func() {
		ipv6ProcPaths = oldProcPaths
		sysctlIPv6ConfPath = oldSysctl
		writeFile = oldWriteFile
		writeSysctlConf = oldWriteSysctl
	})

	if err := DisableIPv6(); err != nil {
		t.Fatalf("DisableIPv6 failed: %v", err)
	}

	// Verify proc files were written with "1"
	for _, p := range procPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("Failed to read %s: %v", p, err)
		}
		if string(data) != "1" {
			t.Errorf("Expected '1' in %s, got %q", p, string(data))
		}
	}

	// Verify sysctl config was created
	data, err := os.ReadFile(sysctlPath)
	if err != nil {
		t.Fatalf("Failed to read sysctl config: %v", err)
	}
	if !strings.Contains(string(data), "net.ipv6.conf.all.disable_ipv6 = 1") {
		t.Error("Sysctl config should contain IPv6 disable settings")
	}

	// Verify UFW deny rule was added
	if !mock.hasRule("ufw deny out to ::/0 comment lazyvpn:v6") {
		t.Error("Should have IPv6 deny rule")
	}
}

// DisableIPv6 must be tolerant of Layer 1 (/proc write) failure during
// install: file caps on the binary don't activate until next exec, so the
// install process EACCES on /proc and falls through to the persistent conf
// + `sudo -n sysctl -p` path. With writeSysctlConf stubbed to succeed and
// no real sudo available, the fallback's sysctl -p call will fail — but
// only IF Layer 1 also failed. The test verifies the fallback IS attempted
// in that combo (function returns the sysctl error, not nil).
func TestDisableIPv6ProcWriteFailure_FallsBackToSysctlP(t *testing.T) {
	setupMock(t)

	oldProcPaths := ipv6ProcPaths
	oldWriteFile := writeFile
	oldWriteSysctl := writeSysctlConf
	ipv6ProcPaths = []string{"/nonexistent/dir/disable_ipv6"}
	writeFile = os.WriteFile
	writeSysctlConf = func(string) error { return nil } // pretend persistent conf wrote OK
	t.Cleanup(func() {
		ipv6ProcPaths = oldProcPaths
		writeFile = oldWriteFile
		writeSysctlConf = oldWriteSysctl
	})

	err := DisableIPv6()
	// sysctl -p fallback runs `sudo -n sysctl -p ...` which will fail in
	// the test env (no NOPASSWD). What matters is that DisableIPv6 surfaces
	// the failure rather than swallowing both layers silently.
	if err == nil {
		t.Error("expected error: Layer 1 failed and sysctl -p fallback should also fail in test env")
	}
}

// Regression: when BOTH Layer 1 (/proc write) AND Layer 2 (writeSysctlConf)
// fail, the kernel state is untouched — IPv6 is still permitted system-wide.
// Pre-fix DisableIPv6 returned nil in this combination because the
// "if procFailed { ... sysctl -p ... }" branch was gated on
// writeSysctlConf having succeeded; with both failing we fell through to
// Layer 3 (UFW deny rules, which alone don't block local processes' IPv6
// sockets) and returned nil. The TUI then displayed "IPv6 protection ON"
// while the kernel still leaked.
func TestDisableIPv6_BothLayer1AndLayer2Fail_ReturnsError(t *testing.T) {
	setupMock(t)

	oldProcPaths := ipv6ProcPaths
	oldWriteFile := writeFile
	oldWriteSysctl := writeSysctlConf
	ipv6ProcPaths = []string{"/nonexistent/dir/disable_ipv6"}
	writeFile = os.WriteFile
	writeSysctlConf = func(string) error { return fmt.Errorf("simulated sudo denied") }
	t.Cleanup(func() {
		ipv6ProcPaths = oldProcPaths
		writeFile = oldWriteFile
		writeSysctlConf = oldWriteSysctl
	})

	err := DisableIPv6()
	if err == nil {
		t.Fatal("expected error: both kernel-write paths failed; kernel state untouched but DisableIPv6 returned nil")
	}
	// Error message should reference both failure modes so the user/log
	// can see what happened, not just a generic "ipv6 disable failed".
	msg := err.Error()
	if !strings.Contains(msg, "sysctl") {
		t.Errorf("error should mention the persistent sysctl write failure, got: %v", err)
	}
}

func TestEnableIPv6WritesToProcAndRemovesRule(t *testing.T) {
	mock := setupMock(t)

	tmpDir := t.TempDir()
	procPaths := []string{
		filepath.Join(tmpDir, "all_disable_ipv6"),
		filepath.Join(tmpDir, "default_disable_ipv6"),
		filepath.Join(tmpDir, "lo_disable_ipv6"),
	}
	for _, p := range procPaths {
		os.WriteFile(p, []byte("1"), 0644)
	}

	sysctlPath := filepath.Join(tmpDir, "99-lazyvpn-ipv6.conf")
	os.WriteFile(sysctlPath, []byte("sysctl content"), 0644)

	oldProcPaths := ipv6ProcPaths
	oldSysctl := sysctlIPv6ConfPath
	oldWriteFile := writeFile
	oldWriteSysctl := writeSysctlConf
	oldRemoveSysctl := removeSysctlConf
	ipv6ProcPaths = procPaths
	sysctlIPv6ConfPath = sysctlPath
	writeFile = os.WriteFile
	writeSysctlConf = func(content string) error {
		return os.WriteFile(sysctlIPv6ConfPath, []byte(content), 0644)
	}
	removeSysctlConf = func() error { return os.Remove(sysctlIPv6ConfPath) }
	t.Cleanup(func() {
		ipv6ProcPaths = oldProcPaths
		sysctlIPv6ConfPath = oldSysctl
		writeFile = oldWriteFile
		writeSysctlConf = oldWriteSysctl
		removeSysctlConf = oldRemoveSysctl
	})

	// Add the IPv6 rule first so EnableIPv6 can remove it
	DisableIPv6()

	if !mock.hasRule("ufw deny out to ::/0 comment lazyvpn:v6") {
		t.Fatal("IPv6 deny rule should exist before EnableIPv6")
	}

	if err := EnableIPv6(); err != nil {
		t.Fatalf("EnableIPv6 failed: %v", err)
	}

	// Verify proc files were written with "0"
	for _, p := range procPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("Failed to read %s: %v", p, err)
		}
		if string(data) != "0" {
			t.Errorf("Expected '0' in %s, got %q", p, string(data))
		}
	}

	// Verify sysctl config was removed
	if _, err := os.Stat(sysctlPath); !os.IsNotExist(err) {
		t.Error("Sysctl config should be removed")
	}

	// Verify IPv6 deny rule was removed
	if mock.hasRule("ufw deny out to ::/0 comment lazyvpn:v6") {
		t.Error("IPv6 deny rule should be removed")
	}
}

// TestEnableIPv6_PartialProcFailure_DoesNotEarlyReturn reproduces the bug
// where the original code did `for ... if err return` — a failure on the
// second proc path skipped the third path AND skipped Layer 2 (sysctl
// conf removal) and Layer 3 (UFW rule cleanup), leaving partial kernel +
// firewall state. After the fix, all three paths are attempted and
// Layers 2+3 always run, with the error surfaced at the end.
func TestEnableIPv6_PartialProcFailure_DoesNotEarlyReturn(t *testing.T) {
	mock := setupMock(t)

	tmpDir := t.TempDir()
	pathOK1 := filepath.Join(tmpDir, "all_disable_ipv6")
	pathOK2 := filepath.Join(tmpDir, "lo_disable_ipv6")
	os.WriteFile(pathOK1, []byte("1"), 0644)
	os.WriteFile(pathOK2, []byte("1"), 0644)

	sysctlPath := filepath.Join(tmpDir, "99-lazyvpn-ipv6.conf")
	os.WriteFile(sysctlPath, []byte("sysctl content"), 0644)

	failPath := "/should-fail/disable_ipv6"

	oldProcPaths := ipv6ProcPaths
	oldSysctl := sysctlIPv6ConfPath
	oldWriteFile := writeFile
	oldWriteSysctl := writeSysctlConf
	oldRemoveSysctl := removeSysctlConf
	t.Cleanup(func() {
		ipv6ProcPaths = oldProcPaths
		sysctlIPv6ConfPath = oldSysctl
		writeFile = oldWriteFile
		writeSysctlConf = oldWriteSysctl
		removeSysctlConf = oldRemoveSysctl
	})

	// Phase 1: DisableIPv6 with all-success paths so the UFW rule lands
	// in the mock. We're testing EnableIPv6's behavior, not Disable's.
	ipv6ProcPaths = []string{pathOK1, pathOK2}
	sysctlIPv6ConfPath = sysctlPath
	writeFile = os.WriteFile
	writeSysctlConf = func(content string) error {
		return os.WriteFile(sysctlIPv6ConfPath, []byte(content), 0644)
	}
	removeSysctlConf = func() error { return os.Remove(sysctlIPv6ConfPath) }

	if err := DisableIPv6(); err != nil {
		t.Fatalf("DisableIPv6 setup failed: %v", err)
	}
	if !mock.hasRule("ufw deny out to ::/0 comment lazyvpn:v6") {
		t.Fatal("IPv6 deny rule should exist before EnableIPv6")
	}

	// Phase 2: swap to a path list where the middle one fails, and inject
	// a writeFile that records every attempt.
	var attempts []string
	mockWrite := func(p string, data []byte, mode os.FileMode) error {
		attempts = append(attempts, p)
		if p == failPath {
			return fmt.Errorf("synthetic write failure")
		}
		return os.WriteFile(p, data, mode)
	}
	ipv6ProcPaths = []string{pathOK1, failPath, pathOK2}
	writeFile = mockWrite

	err := EnableIPv6()
	if err == nil {
		t.Error("EnableIPv6 should report a failure when one /proc write fails")
	}

	// All three proc paths must have been attempted (no early return).
	if len(attempts) != 3 {
		t.Errorf("expected 3 write attempts (one per proc path), got %d: %v", len(attempts), attempts)
	}

	if data, _ := os.ReadFile(pathOK1); string(data) != "0" {
		t.Errorf("pathOK1 expected '0' (write succeeded), got %q", string(data))
	}

	// Layer 2 must have run despite the proc write failure.
	if _, err := os.Stat(sysctlPath); !os.IsNotExist(err) {
		t.Error("sysctl conf should have been removed despite proc write failure (Layer 2 must run)")
	}

	// Layer 3 must have run despite the proc write failure.
	if mock.hasRule("ufw deny out to ::/0 comment lazyvpn:v6") {
		t.Error("UFW IPv6 deny rule should have been removed despite proc write failure (Layer 3 must run)")
	}
}

func TestEnableIPv6ProcWriteFailure(t *testing.T) {
	setupMock(t)

	oldProcPaths := ipv6ProcPaths
	oldWriteFile := writeFile
	ipv6ProcPaths = []string{"/nonexistent/dir/disable_ipv6"}
	writeFile = os.WriteFile
	t.Cleanup(func() {
		ipv6ProcPaths = oldProcPaths
		writeFile = oldWriteFile
	})

	err := EnableIPv6()
	if err == nil {
		t.Error("EnableIPv6 should fail when proc write fails")
	}
	if !strings.Contains(err.Error(), "failed to enable IPv6") {
		t.Errorf("Error should mention IPv6 enable failure, got: %v", err)
	}
}

// IsIPv6Disabled is the authoritative signal for "did the user enable IPv6
// Leak Protection" — checks for the lazyvpn:v6 UFW rule tag rather than
// IsIPv6Disabled reads /proc/sys/net/ipv6/conf/all/disable_ipv6 directly
// so the dashboard reflects actual kernel state regardless of who flipped
// the bit. The test points ipv6ReadPath at a temp file so it doesn't
// depend on (or perturb) the host's real v6 state.
func TestIsIPv6Disabled(t *testing.T) {
	setupMock(t)

	tmpFile := filepath.Join(t.TempDir(), "disable_ipv6")
	orig := ipv6ReadPath
	ipv6ReadPath = tmpFile
	t.Cleanup(func() { ipv6ReadPath = orig })

	// File missing → treat as "disabled" (kernel built without v6).
	if !IsIPv6Disabled() {
		t.Error("missing /proc path should report disabled")
	}

	if err := os.WriteFile(tmpFile, []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if IsIPv6Disabled() {
		t.Error("'0' should report enabled (not disabled)")
	}

	if err := os.WriteFile(tmpFile, []byte("1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !IsIPv6Disabled() {
		t.Error("'1' should report disabled")
	}
}

func TestIPv6DisableEnableLifecycle(t *testing.T) {
	mock := setupMock(t)

	tmpDir := t.TempDir()
	procPaths := []string{
		filepath.Join(tmpDir, "all"),
		filepath.Join(tmpDir, "default"),
		filepath.Join(tmpDir, "lo"),
	}
	for _, p := range procPaths {
		os.WriteFile(p, []byte("0"), 0644)
	}
	sysctlPath := filepath.Join(tmpDir, "sysctl.conf")

	oldProcPaths := ipv6ProcPaths
	oldSysctl := sysctlIPv6ConfPath
	oldWriteFile := writeFile
	oldWriteSysctl := writeSysctlConf
	oldRemoveSysctl := removeSysctlConf
	ipv6ProcPaths = procPaths
	sysctlIPv6ConfPath = sysctlPath
	writeFile = os.WriteFile
	writeSysctlConf = func(content string) error {
		return os.WriteFile(sysctlIPv6ConfPath, []byte(content), 0644)
	}
	removeSysctlConf = func() error { return os.Remove(sysctlIPv6ConfPath) }
	t.Cleanup(func() {
		ipv6ProcPaths = oldProcPaths
		sysctlIPv6ConfPath = oldSysctl
		writeFile = oldWriteFile
		writeSysctlConf = oldWriteSysctl
		removeSysctlConf = oldRemoveSysctl
	})

	// Disable IPv6
	if err := DisableIPv6(); err != nil {
		t.Fatalf("DisableIPv6 failed: %v", err)
	}

	for _, p := range procPaths {
		data, _ := os.ReadFile(p)
		if string(data) != "1" {
			t.Errorf("Expected '1' in %s after disable", p)
		}
	}
	if !mock.hasRule("ufw deny out to ::/0 comment lazyvpn:v6") {
		t.Error("IPv6 deny rule should exist after DisableIPv6")
	}

	// Enable IPv6
	if err := EnableIPv6(); err != nil {
		t.Fatalf("EnableIPv6 failed: %v", err)
	}

	for _, p := range procPaths {
		data, _ := os.ReadFile(p)
		if string(data) != "0" {
			t.Errorf("Expected '0' in %s after enable", p)
		}
	}
	if mock.hasRule("ufw deny out to ::/0 comment lazyvpn:v6") {
		t.Error("IPv6 deny rule should be removed after EnableIPv6")
	}
	if _, err := os.Stat(sysctlPath); !os.IsNotExist(err) {
		t.Error("Sysctl config should be removed after EnableIPv6")
	}
}

// ---------------------------------------------------------------------------
// GetPhysicalInterface tests
// ---------------------------------------------------------------------------

func TestGetPhysicalInterfaceValidRoute(t *testing.T) {
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t00A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"

	if err := os.WriteFile(routeFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write route file: %v", err)
	}

	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	iface, gw, err := GetPhysicalInterface()
	if err != nil {
		t.Fatalf("GetPhysicalInterface failed: %v", err)
	}
	if iface != "eth0" {
		t.Errorf("Expected iface=eth0, got %q", iface)
	}
	if gw != "192.168.1.1" {
		t.Errorf("Expected gateway=192.168.1.1, got %q", gw)
	}
}

func TestGetPhysicalInterfaceNoDefaultRoute(t *testing.T) {
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"

	if err := os.WriteFile(routeFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write route file: %v", err)
	}

	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	_, _, err := GetPhysicalInterface()
	if err == nil {
		t.Error("Expected error for no default route")
	}
	if !strings.Contains(err.Error(), "no default route found") {
		t.Errorf("Expected 'no default route found' error, got: %v", err)
	}
}

func TestGetPhysicalInterfaceShortGatewayHex(t *testing.T) {
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"wlan0\t00000000\t01A8\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"

	if err := os.WriteFile(routeFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write route file: %v", err)
	}

	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	iface, gw, err := GetPhysicalInterface()
	if err != nil {
		t.Fatalf("GetPhysicalInterface failed: %v", err)
	}
	if iface != "wlan0" {
		t.Errorf("Expected iface=wlan0, got %q", iface)
	}
	if gw != "" {
		t.Errorf("Expected empty gateway for short hex, got %q", gw)
	}
}

func TestGetPhysicalInterfaceFileNotFound(t *testing.T) {
	oldPath := procNetRoutePath
	procNetRoutePath = "/nonexistent/path/route"
	t.Cleanup(func() { procNetRoutePath = oldPath })

	_, _, err := GetPhysicalInterface()
	if err == nil {
		t.Error("Expected error when route file doesn't exist")
	}
}

func TestGetPhysicalInterfaceEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"

	if err := os.WriteFile(routeFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write route file: %v", err)
	}

	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	_, _, err := GetPhysicalInterface()
	if err == nil {
		t.Error("Expected error for empty route table")
	}
}

func TestGetPhysicalInterfaceMultipleRoutes(t *testing.T) {
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" +
		"eth0\tACA80100\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" +
		"wlan0\t00000000\tFE01A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"

	if err := os.WriteFile(routeFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write route file: %v", err)
	}

	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	iface, gw, err := GetPhysicalInterface()
	if err != nil {
		t.Fatalf("GetPhysicalInterface failed: %v", err)
	}
	if iface != "wlan0" {
		t.Errorf("Expected iface=wlan0 (default route), got %q", iface)
	}
	if gw != "192.168.1.254" {
		t.Errorf("Expected gateway=192.168.1.254, got %q", gw)
	}
}

func TestGetPhysicalInterfaceSkipsVPN(t *testing.T) {
	tmpDir := t.TempDir()
	routeFile := filepath.Join(tmpDir, "route")
	// wg0 is default route but should be skipped; eth0 should be picked
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"wg0\t00000000\t00000000\t0003\t0\t0\t50\t00000000\t0\t0\t0\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"

	if err := os.WriteFile(routeFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write route file: %v", err)
	}

	oldPath := procNetRoutePath
	procNetRoutePath = routeFile
	t.Cleanup(func() { procNetRoutePath = oldPath })

	iface, _, err := GetPhysicalInterface()
	if err != nil {
		t.Fatalf("GetPhysicalInterface failed: %v", err)
	}
	if iface != "eth0" {
		t.Errorf("Expected iface=eth0 (should skip wg0), got %q", iface)
	}
}

// ---------------------------------------------------------------------------
// isVPNInterface tests
// ---------------------------------------------------------------------------

func TestIsVPNInterface(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"wg0", true},
		{"wg-lazyvpn", true},
		{"tun0", true},
		{"tap0", true},
		{"nordlynx0", true},
		{"proton0", true},
		{"mullvad0", true},
		{"eth0", false},
		{"wlan0", false},
		{"lo", false},
		{"enp0s3", false},
	}

	for _, tt := range tests {
		if got := isVPNInterface(tt.name); got != tt.want {
			t.Errorf("isVPNInterface(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Logging integration tests
// ---------------------------------------------------------------------------

func TestEnableLogsMessages(t *testing.T) {
	setupMock(t)

	var messages []string
	SetLogFunc(func(format string, args ...interface{}) {
		messages = append(messages, fmt.Sprintf(format, args...))
	})

	cfg := &KillswitchConfig{InterfaceName: "wg0", Endpoint: "198.51.100.1"}
	if err := Enable(cfg); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	foundEnabling := false
	foundSuccess := false
	for _, msg := range messages {
		if strings.Contains(msg, "Enabling killswitch") {
			foundEnabling = true
		}
		if strings.Contains(msg, "enabled successfully") {
			foundSuccess = true
		}
	}

	if !foundEnabling {
		t.Error("Expected 'Enabling killswitch' log message")
	}
	if !foundSuccess {
		t.Error("Expected 'enabled successfully' log message")
	}
}

func TestDisableLogsMessages(t *testing.T) {
	setupMock(t)

	var messages []string
	SetLogFunc(func(format string, args ...interface{}) {
		messages = append(messages, fmt.Sprintf(format, args...))
	})

	Enable(&KillswitchConfig{InterfaceName: "wg0"})
	messages = nil

	if err := Disable(); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}

	foundDisabling := false
	foundSuccess := false
	for _, msg := range messages {
		if strings.Contains(msg, "Disabling killswitch") {
			foundDisabling = true
		}
		if strings.Contains(msg, "disabled successfully") {
			foundSuccess = true
		}
	}

	if !foundDisabling {
		t.Error("Expected 'Disabling killswitch' log message")
	}
	if !foundSuccess {
		t.Error("Expected 'disabled successfully' log message")
	}
}

// ---------------------------------------------------------------------------
// Full lifecycle test
// ---------------------------------------------------------------------------

func TestFullLifecycle(t *testing.T) {
	mock := setupMock(t)

	if IsActive() {
		t.Error("Should not be active before Enable")
	}

	// 1. Enable
	cfg := &KillswitchConfig{
		InterfaceName: "wg0",
		DNS:           "10.2.0.1",
		Endpoint:      "198.51.100.1",
	}
	if err := Enable(cfg); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if !IsActive() {
		t.Error("Should be active after Enable")
	}

	// 2. Update
	newCfg := &KillswitchConfig{
		InterfaceName: "wg1",
		DNS:           "10.3.0.1",
		Endpoint:      "203.0.113.1",
	}
	if err := Update(newCfg); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if !IsActive() {
		t.Error("Should still be active after Update")
	}
	if mock.hasRule("ufw allow out to 198.51.100.1 comment lazyvpn:ks") {
		t.Error("Old endpoint should be gone after Update")
	}
	if !mock.hasRule("ufw allow out to 203.0.113.1 comment lazyvpn:ks") {
		t.Error("New endpoint should exist after Update")
	}

	// 3. Disable
	if err := Disable(); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	if IsActive() {
		t.Error("Should not be active after Disable")
	}
	if mock.countRulesWithTag(TagKillswitch) != 0 {
		t.Error("No killswitch rules should remain after Disable")
	}

	// 4. EnableSimple
	if err := EnableSimple(); err != nil {
		t.Fatalf("EnableSimple failed: %v", err)
	}
	if !IsActive() {
		t.Error("Should be active after EnableSimple")
	}
	// loopback out + loopback in = 2 (no LAN rules anymore)
	if mock.countRulesWithTag(TagKillswitch) != 2 {
		t.Errorf("Expected 2 killswitch rules, got %d", mock.countRulesWithTag(TagKillswitch))
	}

	// 5. Update when active with EnableSimple should work
	if err := Update(cfg); err != nil {
		t.Fatalf("Update after EnableSimple failed: %v", err)
	}
	if !IsActive() {
		t.Error("Should still be active after Update")
	}
}

// ---------------------------------------------------------------------------
// Concurrent access test
// ---------------------------------------------------------------------------

func TestConcurrentEnableDisable(t *testing.T) {
	setupMock(t)

	var wg sync.WaitGroup
	cfg := &KillswitchConfig{InterfaceName: "wg0", Endpoint: "198.51.100.1"}

	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			Enable(cfg)
		}()
		go func() {
			defer wg.Done()
			Disable()
		}()
	}
	wg.Wait()

	// Should not panic or deadlock
	_ = IsActive()
}

// ---------------------------------------------------------------------------
// deleteRulesByTag tests
// ---------------------------------------------------------------------------

func TestDeleteRulesByTag(t *testing.T) {
	mock := setupMock(t)

	// Add some rules with different tags
	addRule("allow", "out", "on", "lo", "comment", TagKillswitch)
	addRule("allow", "out", "to", "198.51.100.1", "comment", TagKillswitch)
	addRule("deny", "out", "to", "192.168.0.0/16", "comment", TagLANBlock)

	if mock.countRulesWithTag(TagKillswitch) != 2 {
		t.Fatalf("Expected 2 killswitch rules, got %d", mock.countRulesWithTag(TagKillswitch))
	}

	if err := deleteRulesByTag(TagKillswitch); err != nil {
		t.Fatalf("deleteRulesByTag failed: %v", err)
	}

	if mock.countRulesWithTag(TagKillswitch) != 0 {
		t.Error("Should have no killswitch rules after delete")
	}

	// LAN block rule should still be present
	if mock.countRulesWithTag(TagLANBlock) != 1 {
		t.Error("LAN block rule should still exist")
	}
}

// TestDeleteRulesByTag_ShowAddedError verifies that when `ufw show added`
// fails (e.g. ufw command itself errored), deleteRulesByTag returns a
// wrapped error and does NOT silently treat the empty output as "no rules
// to delete". A regression where this error was swallowed would mask
// rule-leak bugs because callers rely on the error to know cleanup failed.
func TestDeleteRulesByTag_ShowAddedError(t *testing.T) {
	mock := setupMock(t)
	mock.injectErrorAt(0, fmt.Errorf("ufw not running"))

	err := deleteRulesByTag(TagKillswitch)
	if err == nil {
		t.Fatal("expected error from show-added failure, got nil")
	}
	if !strings.Contains(err.Error(), "ufw show added") {
		t.Errorf("error doesn't mention failed op, got: %v", err)
	}
}

// TestDeleteRulesByTag_PartialDeleteFailureContinuesRest verifies that
// when a per-rule delete fails, deleteRulesByTag:
//   1) returns the FIRST error (not the last, not nil)
//   2) STILL attempts subsequent deletes — does not bail early
// A regression that bailed on first failure would leave partially-cleaned
// state, breaking subsequent re-enable flows that assume a clean slate.
func TestDeleteRulesByTag_PartialDeleteFailureContinuesRest(t *testing.T) {
	mock := setupMock(t)

	// Three rules with same tag. The middle rule's delete will be made to fail.
	addRule("allow", "out", "on", "lo", "comment", TagKillswitch)
	addRule("allow", "out", "to", "198.51.100.1", "comment", TagKillswitch)
	addRule("allow", "out", "to", "any", "port", "53", "comment", TagKillswitch)

	if mock.countRulesWithTag(TagKillswitch) != 3 {
		t.Fatalf("setup: want 3 rules, got %d", mock.countRulesWithTag(TagKillswitch))
	}

	// Calls so far: 3 addRule calls consumed indexes 0-2.
	// During deleteRulesByTag:
	//   call 3: show added (succeeds → returns 3 rules)
	//   call 4: delete rule 1 (we make this fail)
	//   call 5: delete rule 2 (succeeds)
	//   call 6: delete rule 3 (succeeds)
	mock.injectErrorAt(4, fmt.Errorf("synthetic delete failure"))

	err := deleteRulesByTag(TagKillswitch)
	if err == nil {
		t.Fatal("expected error from injected delete failure, got nil")
	}
	if !strings.Contains(err.Error(), "synthetic delete failure") {
		t.Errorf("error doesn't wrap original, got: %v", err)
	}

	// Critical: the OTHER rules MUST still have been deleted (only the
	// failing one remains). If deleteRulesByTag bailed on first failure
	// these counts would still be 3.
	remaining := mock.countRulesWithTag(TagKillswitch)
	if remaining != 1 {
		t.Errorf("after partial-failure delete: want 1 rule remaining, got %d (loop bailed early?)", remaining)
	}
}

// ---------------------------------------------------------------------------
// hasRulesWithTag tests
// ---------------------------------------------------------------------------

func TestHasRulesWithTag(t *testing.T) {
	setupMock(t)

	if hasRulesWithTag(TagKillswitch) {
		t.Error("Should have no rules initially")
	}

	addRule("allow", "out", "on", "lo", "comment", TagKillswitch)

	if !hasRulesWithTag(TagKillswitch) {
		t.Error("Should have rules after adding one")
	}
}

// ---------------------------------------------------------------------------
// getDefaultOutgoingPolicy tests
// ---------------------------------------------------------------------------

func TestGetDefaultOutgoingPolicy(t *testing.T) {
	mock := setupMock(t)

	if got := getDefaultOutgoingPolicy(); got != "allow" {
		t.Errorf("Expected 'allow' initially, got %q", got)
	}

	mock.defaultOutgoing = "deny"
	if got := getDefaultOutgoingPolicy(); got != "deny" {
		t.Errorf("Expected 'deny', got %q", got)
	}
}

// TestGetDefaultOutgoingPolicy_UFWErrorReturnsEmpty covers the error
// path. IsActive() (the killswitch-detection probe) consults this
// function; if ufw is broken we must return "" rather than crash, so
// IsActive can short-circuit to false instead of misreading garbage
// as "deny" and falsely reporting an active killswitch.
func TestGetDefaultOutgoingPolicy_UFWErrorReturnsEmpty(t *testing.T) {
	mock := setupMock(t)
	mock.injectErrorAt(0, fmt.Errorf("ufw not running"))

	if got := getDefaultOutgoingPolicy(); got != "" {
		t.Errorf("getDefaultOutgoingPolicy() with ufw error = %q, want empty string", got)
	}
}

// TestGetDefaultOutgoingPolicy_NoDefaultLineReturnsEmpty covers the
// case where ufw output is present but lacks a "Default:" line —
// could happen with truncated output, an unusual locale, or a
// stripped-down ufw build. The contract is "" so callers
// (specifically IsActive) safely short-circuit.
func TestGetDefaultOutgoingPolicy_NoDefaultLineReturnsEmpty(t *testing.T) {
	mock := setupMock(t)
	mock.injectOutputAt(0, []byte("Status: active\nLogging: on (low)\n"))

	if got := getDefaultOutgoingPolicy(); got != "" {
		t.Errorf("getDefaultOutgoingPolicy() with no Default: line = %q, want empty string", got)
	}
}

// TestGetDefaultOutgoingPolicy_DefaultLineMissingOutgoingReturnsEmpty
// covers the case where a Default: line exists but doesn't mention
// "(outgoing)" — could happen if ufw output format ever changes or
// in a degraded ufw state. Must return "" and not, e.g., return the
// (incoming) policy by mistake.
func TestGetDefaultOutgoingPolicy_DefaultLineMissingOutgoingReturnsEmpty(t *testing.T) {
	mock := setupMock(t)
	mock.injectOutputAt(0, []byte("Status: active\nDefault: deny (incoming), disabled (routed)\n"))

	if got := getDefaultOutgoingPolicy(); got != "" {
		t.Errorf("getDefaultOutgoingPolicy() with no '(outgoing)' marker = %q, want empty string", got)
	}
}

// ---------------------------------------------------------------------------
// SetLogFunc and log tests (duplicated from killswitch_test.go for coverage)
// ---------------------------------------------------------------------------

func TestSetLogFuncSetsCallback(t *testing.T) {
	var captured string
	SetLogFunc(func(format string, args ...interface{}) {
		captured = fmt.Sprintf(format, args...)
	})
	t.Cleanup(func() { SetLogFunc(nil) })

	log("hello %s", "world")
	if captured != "hello world" {
		t.Errorf("Expected 'hello world', got %q", captured)
	}
}

func TestSetLogFuncNilClearsCallback(t *testing.T) {
	var captured string
	SetLogFunc(func(format string, args ...interface{}) {
		captured = fmt.Sprintf(format, args...)
	})

	log("first")
	if captured != "first" {
		t.Fatalf("Expected 'first', got %q", captured)
	}

	SetLogFunc(nil)
	captured = ""
	log("second")
	if captured != "" {
		t.Errorf("Expected empty after nil SetLogFunc, got %q", captured)
	}
}

func TestLogWithNilFuncDoesNotPanic(t *testing.T) {
	SetLogFunc(nil)
	log("test %d", 42)
}

// ---------------------------------------------------------------------------
// Rollback tests
// ---------------------------------------------------------------------------

// TestEnable_RollbackPreservesPrevDenyPolicy is the missing companion
// to TestEnableSimpleRollbackPreservesPrevPolicy: when the user already
// had `default deny outgoing` before Enable was called (uncommon but
// real — manual hardening, prior killswitch from another tool), a
// failed Enable must NOT silently downgrade the default to "allow"
// during rollback. enableLocked captures prevPolicy at function entry
// for exactly this reason.
//
// The existing TestEnableRollbackOnError doesn't catch this regression
// because it starts with mock.defaultOutgoing="allow", so both the
// captured prevPolicy AND the rollback target are "allow" — the
// assertion passes whether or not the prev-policy preservation works.
func TestEnable_RollbackPreservesPrevDenyPolicy(t *testing.T) {
	mock := setupMock(t)

	// Pre-set the default to deny — simulating a user who's already
	// hardened their firewall (or a prior killswitch from another tool)
	// before Enable runs and fails.
	mock.defaultOutgoing = "deny"

	// Inject error on the DNS allow rule (same call index as the
	// existing TestEnableRollbackOnError).
	// Call 0: status verbose (getDefaultOutgoingPolicy)
	// Call 1: show added (deleteRulesByTag)
	// Call 2: allow out on lo (loopback)
	// Call 3: allow out proto udp (DNS) <-- inject
	mock.injectErrorAt(3, fmt.Errorf("injected DNS rule failure"))

	cfg := &KillswitchConfig{InterfaceName: "wg0", DNS: "10.2.0.1"}
	if err := Enable(cfg); err == nil {
		t.Fatal("Enable should have failed")
	}

	// The rollback must restore the prev-policy "deny", NOT downgrade
	// to "allow". The bug this guards against would set restorePolicy
	// to "allow" unconditionally and silently strip the user's
	// pre-existing hardening.
	if mock.defaultOutgoing != "deny" {
		t.Errorf("defaultOutgoing = %q after rollback, want %q (prev-policy preservation broken)",
			mock.defaultOutgoing, "deny")
	}
	// And no killswitch rules should remain.
	if got := mock.countRulesWithTag(TagKillswitch); got != 0 {
		t.Errorf("expected 0 killswitch rules after rollback, got %d", got)
	}
}

func TestEnableRollbackOnError(t *testing.T) {
	mock := setupMock(t)

	// Capture original default so the post-rollback assertion verifies
	// PRESERVATION rather than tautologically reading the same default
	// value back. The dedicated TestEnable_RollbackPreservesPrevDenyPolicy
	// covers the prev=deny case; this one covers the prev=allow case
	// non-tautologically by capturing the actual baseline.
	origDefault := mock.defaultOutgoing

	// Inject error on the DNS allow rule.
	// Call 0: status verbose (getDefaultOutgoingPolicy for prevPolicy)
	// Call 1: show added (deleteRulesByTag)
	// Call 2: allow out on lo (loopback)
	// Call 3: allow out proto udp (DNS) — inject error here
	mock.injectErrorAt(3, fmt.Errorf("injected error"))

	cfg := &KillswitchConfig{
		InterfaceName: "wg0",
		DNS:           "10.2.0.1",
	}

	err := Enable(cfg)
	if err == nil {
		t.Fatal("Enable should have failed")
	}

	// Default policy is restored to whatever it was before Enable ran.
	if mock.defaultOutgoing != origDefault {
		t.Errorf("defaultOutgoing = %q after rollback, want %q (original)",
			mock.defaultOutgoing, origDefault)
	}
	// And no killswitch rules should remain.
	if got := mock.countRulesWithTag(TagKillswitch); got != 0 {
		t.Errorf("expected 0 killswitch rules after rollback, got %d", got)
	}
}

func TestEnableSimpleRollbackOnError(t *testing.T) {
	mock := setupMock(t)

	// Capture original default so the post-rollback assertion verifies
	// PRESERVATION rather than tautologically reading the same default
	// value back. Pre-fix this test asserted `== "allow"` which was
	// trivially true regardless of whether the rollback ran (mock
	// starts at "allow"; the dedicated PreservesPrevPolicy test covers
	// the deny-baseline case).
	origDefault := mock.defaultOutgoing

	// Call 0: show added (deleteRulesByTag)
	// Call 1: default deny outgoing  (the killswitch flip)
	// Call 2: allow out on lo — inject error
	//
	// Wait — EnableSimple's actual call order is:
	//   call 0: status verbose (getDefaultOutgoingPolicy for prevPolicy)
	//   call 1: show added (deleteRulesByTag)
	//   call 2: allow out on lo (loopback)  <-- inject here
	// The original comment misnumbered; fixed.
	mock.injectErrorAt(2, fmt.Errorf("injected error on loopback addRule"))

	err := EnableSimple()
	if err == nil {
		t.Fatal("EnableSimple should have failed")
	}

	// Default policy is restored to whatever it was before EnableSimple ran.
	if mock.defaultOutgoing != origDefault {
		t.Errorf("defaultOutgoing = %q after rollback, want %q (original)",
			mock.defaultOutgoing, origDefault)
	}
	// And no killswitch rules should remain — rollback's deleteRulesByTag
	// must have run.
	if got := mock.countRulesWithTag(TagKillswitch); got != 0 {
		t.Errorf("expected 0 killswitch rules after rollback, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// UFW Logging tests
// ---------------------------------------------------------------------------

func TestGetLoggingLevelMedium(t *testing.T) {
	mock := setupMock(t)
	mock.loggingLevel = "medium"

	got := GetLoggingLevel()
	if got != "medium" {
		t.Errorf("GetLoggingLevel() = %q, want 'medium'", got)
	}
}

func TestGetLoggingLevelOff(t *testing.T) {
	setupMock(t)
	// default loggingLevel is "off"

	got := GetLoggingLevel()
	if got != "off" {
		t.Errorf("GetLoggingLevel() = %q, want 'off'", got)
	}
}

func TestGetLoggingLevelFull(t *testing.T) {
	mock := setupMock(t)
	mock.loggingLevel = "full"

	got := GetLoggingLevel()
	if got != "full" {
		t.Errorf("GetLoggingLevel() = %q, want 'full'", got)
	}
}

// TestGetLoggingLevel_UFWErrorReturnsOff covers the runUFW.Run error
// path. If ufw itself errors (e.g. uninstalled, daemon down,
// permission denied without sudoers), GetLoggingLevel must return
// "off" rather than crashing or returning empty — callers iterate the
// known-level set { off, low, medium, high, full } and would mishandle
// an empty string.
func TestGetLoggingLevel_UFWErrorReturnsOff(t *testing.T) {
	mock := setupMock(t)
	mock.injectErrorAt(0, fmt.Errorf("ufw not running"))

	if got := GetLoggingLevel(); got != "off" {
		t.Errorf("GetLoggingLevel() with ufw error = %q, want 'off'", got)
	}
}

// TestGetLoggingLevel_OnWithoutParentheticalDefaultsToLow covers the
// degraded-output branch: older ufw versions and some distro builds
// emit "Logging: on" without a parenthetical level. The contract is
// that this falls back to "low" — anything else (e.g. an empty string
// returned to a TUI cycle) would silently misreport firewall posture.
func TestGetLoggingLevel_OnWithoutParentheticalDefaultsToLow(t *testing.T) {
	mock := setupMock(t)
	mock.injectOutputAt(0, []byte("Status: active\nLogging: on\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"))

	if got := GetLoggingLevel(); got != "low" {
		t.Errorf("GetLoggingLevel() with bare 'Logging: on' = %q, want 'low'", got)
	}
}

// TestGetLoggingLevel_NoLoggingLineReturnsOff covers the no-match path.
// If `ufw status verbose` output ever omits the Logging: line entirely
// (truncated, garbage), GetLoggingLevel must fall back to "off" — the
// safe default for a TUI cycle that maps levels to actions.
func TestGetLoggingLevel_NoLoggingLineReturnsOff(t *testing.T) {
	mock := setupMock(t)
	mock.injectOutputAt(0, []byte("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"))

	if got := GetLoggingLevel(); got != "off" {
		t.Errorf("GetLoggingLevel() with no Logging: line = %q, want 'off'", got)
	}
}

// TestUpdate_NoOpWhenKillswitchInactive pins the critical safety
// contract of Update():
//
//   if getDefaultOutgoingPolicy() != "deny" {
//     return nil // Killswitch not active, nothing to update
//   }
//
// Update is called from wireguard.Connect when switching endpoints,
// to refresh allow-rules for the new server. The guard ensures it's
// a NO-OP when the killswitch wasn't active in the first place —
// without this, calling Update would silently TURN ON the killswitch
// (enableLocked sets default deny outgoing), locking the user out
// of the network.
//
// A regression that dropped the early-return would convert Update
// from "refresh existing killswitch" into "turn on killswitch
// unconditionally." Catastrophic UX failure.
func TestUpdate_NoOpWhenKillswitchInactive(t *testing.T) {
	mock := setupMock(t)
	// Default is "allow" — killswitch not active.

	cfg := &KillswitchConfig{
		InterfaceName: "wg0",
		Endpoint:      "198.51.100.1",
	}
	if err := Update(cfg); err != nil {
		t.Fatalf("Update should return nil when killswitch inactive: %v", err)
	}

	// Critical: defaultOutgoing must NOT have been flipped to "deny".
	if mock.defaultOutgoing != "allow" {
		t.Errorf("default outgoing = %q, want allow (Update must NOT silently turn killswitch on)", mock.defaultOutgoing)
	}
	// No killswitch rules should have been added either.
	if mock.countRulesWithTag(TagKillswitch) != 0 {
		t.Errorf("got %d killswitch rules after Update on inactive killswitch, want 0", mock.countRulesWithTag(TagKillswitch))
	}
}

// TestUpdate_RefreshesRulesWhenKillswitchActive pins the active-path
// half: when killswitch IS active, Update must invoke enableLocked
// to refresh the rule set for the new config. Pair with the no-op
// test above.
func TestUpdate_RefreshesRulesWhenKillswitchActive(t *testing.T) {
	mock := setupMock(t)
	// Bring up killswitch first.
	if err := Enable(&KillswitchConfig{InterfaceName: "wg0", Endpoint: "198.51.100.1"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if mock.defaultOutgoing != "deny" {
		t.Fatalf("setup: defaultOutgoing = %q, want deny", mock.defaultOutgoing)
	}

	// Update to a new endpoint — should refresh the allow rule.
	newCfg := &KillswitchConfig{
		InterfaceName: "wg0",
		Endpoint:      "203.0.113.99", // different endpoint
	}
	if err := Update(newCfg); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Default outgoing should still be deny (killswitch still active).
	if mock.defaultOutgoing != "deny" {
		t.Errorf("default outgoing = %q after Update, want deny", mock.defaultOutgoing)
	}
	// New endpoint allow rule should be present.
	if !mock.hasRule("ufw allow out to 203.0.113.99 comment lazyvpn:ks") {
		t.Errorf("missing allow rule for new endpoint after Update; rules: %v", mock.getRules())
	}
}

func TestSetLogging(t *testing.T) {
	mock := setupMock(t)

	if err := SetLogging("high"); err != nil {
		t.Fatalf("SetLogging failed: %v", err)
	}

	if mock.loggingLevel != "high" {
		t.Errorf("loggingLevel = %q, want 'high'", mock.loggingLevel)
	}

	// Verify via GetLoggingLevel
	got := GetLoggingLevel()
	if got != "high" {
		t.Errorf("GetLoggingLevel() = %q after SetLogging('high')", got)
	}
}

func TestSetLoggingCycle(t *testing.T) {
	mock := setupMock(t)
	levels := []string{"off", "low", "medium", "high", "full"}

	for _, level := range levels {
		if err := SetLogging(level); err != nil {
			t.Fatalf("SetLogging(%q) failed: %v", level, err)
		}
		got := GetLoggingLevel()
		if got != level {
			t.Errorf("After SetLogging(%q), GetLoggingLevel() = %q", level, got)
		}
	}
	_ = mock
}

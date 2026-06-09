package firewall

import "testing"

// The whole point of Reconcile: LAN allow-out lands before the killswitch
// reject, in one rebuild, with no post-hoc reordering.
func TestReconcileOrderingLANBeforeReject(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0")

	if err := Reconcile(State{
		Killswitch: true, Connected: true,
		InterfaceName: "wg0", Endpoint: "198.51.100.1",
		LANMode: LANStealth,
	}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	allowOut := mock.ruleIndex("allow out to 192.168.0.0/16 comment lazyvpn:st")
	reject := mock.ruleIndex("reject out on eth0 comment lazyvpn:ks")
	if allowOut < 0 || reject < 0 {
		t.Fatalf("missing rules: allowOut=%d reject=%d", allowOut, reject)
	}
	if allowOut >= reject {
		t.Errorf("LAN allow-out (%d) must precede killswitch reject (%d)", allowOut, reject)
	}
}

// Killswitch on → outgoing default deny (outbound-only). Off → back to allow.
// The killswitch never touches the incoming policy.
func TestReconcileKillswitchDenyOutgoing(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0")
	mock.defaultIncoming = "allow" // user's policy — must stay untouched

	if err := Reconcile(State{Killswitch: true, Connected: true, InterfaceName: "wg0", Endpoint: "198.51.100.1", LANMode: LANStealth}); err != nil {
		t.Fatalf("Reconcile on failed: %v", err)
	}
	if mock.defaultOutgoing != "deny" {
		t.Errorf("killswitch on: outgoing should be deny, got %q", mock.defaultOutgoing)
	}
	if mock.defaultIncoming != "allow" {
		t.Errorf("killswitch is outbound-only: incoming should be untouched (allow), got %q", mock.defaultIncoming)
	}

	if err := Reconcile(State{Killswitch: false, LANMode: LANStealth}); err != nil {
		t.Fatalf("Reconcile off failed: %v", err)
	}
	if mock.defaultOutgoing != "allow" {
		t.Errorf("killswitch off: outgoing should be allow, got %q", mock.defaultOutgoing)
	}
}

// The DHCP-in collision is structurally fixed by rebuild: after a killswitch
// on→off cycle in Stealth, Stealth's DHCP-in rule is present (re-emitted), not
// orphaned. (Real UFW dedups the identical ks/st rule; the mock doesn't, but the
// rebuild re-emitting Stealth's copy is what matters and is verified live too.)
func TestReconcileStealthDHCPSurvivesKillswitchToggle(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0")

	for _, on := range []bool{false, true, false} {
		if err := Reconcile(State{
			Killswitch: on, Connected: on,
			InterfaceName: "wg0", Endpoint: "198.51.100.1",
			LANMode: LANStealth,
		}); err != nil {
			t.Fatalf("Reconcile(killswitch=%v) failed: %v", on, err)
		}
	}

	if !mock.hasRule("ufw allow in on eth0 proto udp from any port 67:68 comment lazyvpn:st") {
		t.Error("Stealth DHCP-in rule must survive a killswitch on→off cycle (rebuild re-emits it)")
	}
}

// Reconcile is idempotent: rebuilding the same state twice does not accumulate
// rules (it tears down first every time).
func TestReconcileIdempotent(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0")

	st := State{Killswitch: true, Connected: true, InterfaceName: "wg0", Endpoint: "198.51.100.1", LANMode: LANStealth}
	if err := Reconcile(st); err != nil {
		t.Fatalf("first Reconcile failed: %v", err)
	}
	ks1, lan1 := mock.countRulesWithTag(TagKillswitch), mock.countRulesWithTag(TagStealth)

	if err := Reconcile(st); err != nil {
		t.Fatalf("second Reconcile failed: %v", err)
	}
	ks2, lan2 := mock.countRulesWithTag(TagKillswitch), mock.countRulesWithTag(TagStealth)

	if ks1 != ks2 || lan1 != lan2 {
		t.Errorf("rule counts drifted across identical rebuilds: ks %d→%d, st %d→%d", ks1, ks2, lan1, lan2)
	}
}

// Simple killswitch (no tunnel): deny defaults, but no physical-interface reject
// (there's no tunnel to protect leaks around) and no endpoint allow.
func TestReconcileSimpleKillswitchNoReject(t *testing.T) {
	mock := setupMock(t)
	withFakeRoute(t, "eth0")

	if err := Reconcile(State{Killswitch: true, Connected: false, LANMode: LANStealth}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if mock.defaultOutgoing != "deny" {
		t.Errorf("simple killswitch should deny outgoing, got %q", mock.defaultOutgoing)
	}
	if mock.ruleIndex("reject out on eth0 comment lazyvpn:ks") >= 0 {
		t.Error("simple killswitch (no tunnel) must not add a physical-interface reject")
	}
}

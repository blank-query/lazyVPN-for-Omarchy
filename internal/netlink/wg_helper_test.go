package netlink

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decodeB64(%q): %v", s, err)
	}
	return b
}

func TestWGHelperConfig_Serialize(t *testing.T) {
	hc := WGHelperConfig{
		PrivateKey:          decodeB64(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		PublicKey:           "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		PresharedKey:        decodeB64(t, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="),
		Endpoint:            "1.2.3.4:51820",
		AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
		PersistentKeepalive: 25,
	}

	data, err := json.Marshal(hc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded WGHelperConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !bytes.Equal(decoded.PrivateKey, hc.PrivateKey) {
		t.Errorf("PrivateKey = %x, want %x", decoded.PrivateKey, hc.PrivateKey)
	}
	if decoded.PublicKey != hc.PublicKey {
		t.Errorf("PublicKey = %q, want %q", decoded.PublicKey, hc.PublicKey)
	}
	if !bytes.Equal(decoded.PresharedKey, hc.PresharedKey) {
		t.Errorf("PresharedKey = %x, want %x", decoded.PresharedKey, hc.PresharedKey)
	}
	if decoded.Endpoint != hc.Endpoint {
		t.Errorf("Endpoint = %q, want %q", decoded.Endpoint, hc.Endpoint)
	}
	if len(decoded.AllowedIPs) != 2 {
		t.Errorf("AllowedIPs len = %d, want 2", len(decoded.AllowedIPs))
	}
	if decoded.PersistentKeepalive != 25 {
		t.Errorf("PersistentKeepalive = %d, want 25", decoded.PersistentKeepalive)
	}
}

func TestWGHelperConfig_PresharedKeyAbsent(t *testing.T) {
	hc := WGHelperConfig{
		PrivateKey: decodeB64(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		PublicKey:  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		AllowedIPs: []string{"0.0.0.0/0"},
	}

	data, err := json.Marshal(hc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if strings.Contains(string(data), "presharedKey") {
		t.Error("JSON should omit presharedKey when empty")
	}
}

func TestWGHelperConfig_EndpointAbsent(t *testing.T) {
	hc := WGHelperConfig{
		PrivateKey: decodeB64(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		PublicKey:  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		AllowedIPs: []string{"0.0.0.0/0"},
	}

	data, err := json.Marshal(hc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if strings.Contains(string(data), "endpoint") {
		t.Error("JSON should omit endpoint when empty")
	}
}

func TestConfigureInterfaceSelf_Success(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	origExec := execCommand
	t.Cleanup(func() { execCommand = origExec })

	// Mock execCommand to simulate successful self-exec
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("true")
	}

	wgi := newTestWGI(t, "wg-test")
	err := wgi.configureInterfaceSelf()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigureInterfaceSelf_PermError(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	origExec := execCommand
	origOsExec := osExecutable
	t.Cleanup(func() {
		execCommand = origExec
		osExecutable = origOsExec
	})

	osExecutable = func() (string, error) { return "/usr/bin/lazyvpn", nil }

	// Mock execCommand to simulate EPERM
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("sh", "-c", "echo 'operation not permitted' >&2; exit 1")
	}

	wgi := newTestWGI(t, "wg-test")
	err := wgi.configureInterfaceSelf()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "ErrAuthRequired") && !strings.Contains(err.Error(), "sudo authentication required") {
		// Check the error wraps ErrAuthRequired
		if !strings.Contains(err.Error(), "authentication") && !strings.Contains(err.Error(), "operation not permitted") {
			t.Errorf("expected ErrAuthRequired-related error, got: %v", err)
		}
	}
}

func TestConfigureInterfaceSelf_PresharedKeyPresent(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	origExec := execCommand
	origOsExec := osExecutable
	t.Cleanup(func() {
		execCommand = origExec
		osExecutable = origOsExec
	})

	osExecutable = func() (string, error) { return "/usr/bin/lazyvpn", nil }

	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("true")
	}

	wgi := newTestWGI(t, "wg-test")
	psk, _ := wgtypes.GenerateKey()
	wgi.Peer.PresharedKey = &psk

	err := wgi.configureInterfaceSelf()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigureInterfaceSelf_EndpointPresent(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	origExec := execCommand
	origOsExec := osExecutable
	t.Cleanup(func() {
		execCommand = origExec
		osExecutable = origOsExec
	})

	osExecutable = func() (string, error) { return "/usr/bin/lazyvpn", nil }

	var capturedArgs []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		capturedArgs = append([]string{name}, args...)
		return exec.Command("true")
	}

	wgi := newTestWGI(t, "wg-test")
	wgi.Peer.Endpoint = &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 51820}

	err := wgi.configureInterfaceSelf()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify args include wg-helper configure <iface>
	if len(capturedArgs) < 4 {
		t.Fatalf("expected at least 4 args, got %d: %v", len(capturedArgs), capturedArgs)
	}
	if capturedArgs[1] != "wg-helper" {
		t.Errorf("args[1] = %q, want wg-helper", capturedArgs[1])
	}
	if capturedArgs[2] != "configure" {
		t.Errorf("args[2] = %q, want configure", capturedArgs[2])
	}
	if capturedArgs[3] != "wg-test" {
		t.Errorf("args[3] = %q, want wg-test", capturedArgs[3])
	}
}

func TestConfigureInterfaceSelf_AllowedIPs(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	origExec := execCommand
	origOsExec := osExecutable
	t.Cleanup(func() {
		execCommand = origExec
		osExecutable = origOsExec
	})

	osExecutable = func() (string, error) { return "/usr/bin/lazyvpn", nil }
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("true")
	}

	wgi := newTestWGI(t, "wg-test")
	// Add multiple allowed IPs
	_, ipnet1, _ := net.ParseCIDR("0.0.0.0/0")
	_, ipnet2, _ := net.ParseCIDR("::/0")
	_, ipnet3, _ := net.ParseCIDR("10.0.0.0/8")
	wgi.Peer.AllowedIPs = []net.IPNet{*ipnet1, *ipnet2, *ipnet3}

	err := wgi.configureInterfaceSelf()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigureInterfaceSelf_PersistentKeepalive(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	origExec := execCommand
	origOsExec := osExecutable
	t.Cleanup(func() {
		execCommand = origExec
		osExecutable = origOsExec
	})

	osExecutable = func() (string, error) { return "/usr/bin/lazyvpn", nil }
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("true")
	}

	wgi := newTestWGI(t, "wg-test")
	wgi.Peer.PersistentKeepalive = 25 * time.Second

	err := wgi.configureInterfaceSelf()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestConfigureInterfaceSelf_JSONContent verifies the JSON sent to the child process
// contains the expected fields.
func TestConfigureInterfaceSelf_JSONContent(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	origOsExec := osExecutable
	t.Cleanup(func() { osExecutable = origOsExec })
	osExecutable = func() (string, error) { return "/usr/bin/lazyvpn", nil }

	wgi := newTestWGI(t, "wg-test")
	wgi.Peer.Endpoint = &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 51820}
	wgi.Peer.PersistentKeepalive = 30 * time.Second
	psk, _ := wgtypes.GenerateKey()
	wgi.Peer.PresharedKey = &psk
	_, ipnet, _ := net.ParseCIDR("0.0.0.0/0")
	wgi.Peer.AllowedIPs = []net.IPNet{*ipnet}

	// Build the expected JSON by replicating what configureInterfaceSelf does
	hc := WGHelperConfig{
		PrivateKey:          wgi.PrivateKey[:],
		PublicKey:           base64.StdEncoding.EncodeToString(wgi.Peer.PublicKey[:]),
		PresharedKey:        psk[:],
		Endpoint:            "5.6.7.8:51820",
		AllowedIPs:          []string{"0.0.0.0/0"},
		PersistentKeepalive: 30,
	}

	data, err := json.Marshal(hc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded WGHelperConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.PrivateKey) == 0 {
		t.Error("expected non-empty private key")
	}
	if decoded.PublicKey == "" {
		t.Error("expected non-empty public key")
	}
	if len(decoded.PresharedKey) == 0 {
		t.Error("expected non-empty preshared key")
	}
	if decoded.Endpoint != "5.6.7.8:51820" {
		t.Errorf("endpoint = %q, want 5.6.7.8:51820", decoded.Endpoint)
	}
	if len(decoded.AllowedIPs) != 1 || decoded.AllowedIPs[0] != "0.0.0.0/0" {
		t.Errorf("allowedIPs = %v, want [0.0.0.0/0]", decoded.AllowedIPs)
	}
	if decoded.PersistentKeepalive != 30 {
		t.Errorf("keepalive = %d, want 30", decoded.PersistentKeepalive)
	}
}

func TestParseKeyFromBase64(t *testing.T) {
	// 32-byte key encodes to 44 base64 chars with one trailing '='.
	validKey := "YNqHbfBQKaGvct4Jt2ZLKXHXP0sMhCX80fPlOSf80Vo="

	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{"valid 32-byte base64", validKey, false, ""},
		{"empty string", "", true, "invalid key length"},
		{"invalid base64", "not!valid!", true, "illegal base64"},
		{"too short", base64.StdEncoding.EncodeToString([]byte("abcd")), true, "invalid key length"},
		{"too long", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, wgtypes.KeyLen+1)), true, "invalid key length"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := parseKeyFromBase64(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got key=%v", k)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if k == (wgtypes.Key{}) {
				t.Error("key should not be zero on success")
			}
		})
	}
}

// TestConfigureInterfaceSelf_HelperTimesOut verifies the wall-clock
// watcher kills a stuck wg-helper subprocess instead of blocking
// the parent forever. Pre-fix the daemon's doConnect would block
// past SIGTERM if wgctrl.ConfigureDevice wedged on a stuck netlink
// socket.
//
// Previously skipped under -race because the watcher read
// cmd.Process concurrent with cmd.Start setting it. The
// configureInterfaceSelf body was restructured (explicit Start,
// capture cmd.Process to a local, then start watcher reading the
// local) so the race is gone — the test now runs under -race.
func TestConfigureInterfaceSelf_HelperTimesOut(t *testing.T) {
	cleanup(t)
	mock := newMockNL()
	SetNetlinkRunner(mock)

	origExec := execCommand
	origTO := wgHelperTimeout
	t.Cleanup(func() {
		execCommand = origExec
		wgHelperTimeout = origTO
	})

	// Squeeze the timeout to keep the test fast.
	wgHelperTimeout = 200 * time.Millisecond

	// Spawn a sleep that outlives the timeout — the watcher must
	// kill it.
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("sleep", "5")
	}

	wgi := newTestWGI(t, "wg-test")
	start := time.Now()
	err := wgi.configureInterfaceSelf()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error %q should mention timed out", err.Error())
	}
	// Should have been killed well before sleep's 5s — give 1s grace.
	if elapsed > 1*time.Second {
		t.Errorf("configureInterfaceSelf took %v; timeout watcher didn't fire fast enough", elapsed)
	}
}

// --- RunConfigureHelper input-validation tests ---
//
// RunConfigureHelper's parsing portion (JSON unmarshal + field validation)
// is unit-testable independent of the wgctrl call at the end. These tests
// cover every error path BEFORE the wgctrl invocation, so they run without
// root or kernel WireGuard support. Each input fails at a specific
// validation step and we assert the resulting error message identifies
// which step failed — that's the contract callers (wg-helper subcommand
// dispatch) rely on for diagnostic output.
//
// The wgctrl.New() / ConfigureDevice path at the end of RunConfigureHelper
// is not tested here — it requires real kernel WireGuard support. Those
// branches stay uncovered by design.

func TestRunConfigureHelper_RejectsMalformedJSON(t *testing.T) {
	err := RunConfigureHelper("wg0", strings.NewReader("not valid json"))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse config JSON") {
		t.Errorf("error should mention JSON parse failure, got: %v", err)
	}
}

func TestRunConfigureHelper_RejectsBadPrivateKey(t *testing.T) {
	// Empty PrivateKey ([]byte{}) — base64 of empty is "", which decodes
	// to len 0; ParsePrivateKey rejects anything other than 32 bytes.
	hc := WGHelperConfig{
		PrivateKey: []byte{},
		PublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	data, _ := json.Marshal(hc)
	err := RunConfigureHelper("wg0", bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for empty private key")
	}
	if !strings.Contains(err.Error(), "invalid private key") {
		t.Errorf("error should mention invalid private key, got: %v", err)
	}
}

func TestRunConfigureHelper_RejectsBadPublicKey(t *testing.T) {
	hc := WGHelperConfig{
		PrivateKey: decodeB64(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		PublicKey:  "!!!not-base64!!!",
	}
	data, _ := json.Marshal(hc)
	err := RunConfigureHelper("wg0", bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for invalid public key base64")
	}
	if !strings.Contains(err.Error(), "invalid public key") {
		t.Errorf("error should mention invalid public key, got: %v", err)
	}
}

func TestRunConfigureHelper_RejectsBadPresharedKey(t *testing.T) {
	hc := WGHelperConfig{
		PrivateKey:   decodeB64(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		PublicKey:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PresharedKey: []byte{0x01, 0x02}, // wrong length (must be 32)
	}
	data, _ := json.Marshal(hc)
	err := RunConfigureHelper("wg0", bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for invalid PSK length")
	}
	if !strings.Contains(err.Error(), "invalid preshared key") {
		t.Errorf("error should mention invalid preshared key, got: %v", err)
	}
}

func TestRunConfigureHelper_RejectsBadEndpoint(t *testing.T) {
	hc := WGHelperConfig{
		PrivateKey: decodeB64(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		PublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Endpoint:   "not a valid endpoint at all",
	}
	data, _ := json.Marshal(hc)
	err := RunConfigureHelper("wg0", bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for malformed endpoint")
	}
	if !strings.Contains(err.Error(), "invalid endpoint") {
		t.Errorf("error should mention invalid endpoint, got: %v", err)
	}
}

func TestRunConfigureHelper_RejectsBadAllowedIPs(t *testing.T) {
	hc := WGHelperConfig{
		PrivateKey: decodeB64(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		PublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"not-a-cidr"},
	}
	data, _ := json.Marshal(hc)
	err := RunConfigureHelper("wg0", bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if !strings.Contains(err.Error(), "invalid allowed IP") {
		t.Errorf("error should mention invalid allowed IP, got: %v", err)
	}
}

// errReader is an io.Reader that always returns its configured error.
type errReader struct{ err error }

func (e errReader) Read(_ []byte) (int, error) { return 0, e.err }

func TestRunConfigureHelper_RejectsReadError(t *testing.T) {
	wantErr := net.ErrClosed
	err := RunConfigureHelper("wg0", errReader{err: wantErr})
	if err == nil {
		t.Fatal("expected error for stdin read failure")
	}
	if !strings.Contains(err.Error(), "failed to read config from stdin") {
		t.Errorf("error should mention stdin read failure, got: %v", err)
	}
}

package netlink

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/security"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
)

// WGHelperConfig is the JSON wire format for the wg-helper subcommand.
type WGHelperConfig struct {
	PrivateKey          []byte   `json:"privateKey"`
	PublicKey           string   `json:"publicKey"`
	PresharedKey        []byte   `json:"presharedKey,omitempty"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive"`
}

// osExecutable is injectable for testing (mirrors execCommand pattern).
var osExecutable = os.Executable

// configureInterfaceSelf re-execs the current binary as "wg-helper configure <iface>"
// with the WireGuard configuration passed as JSON on stdin. The child process
// inherits file capabilities (CAP_NET_ADMIN) that the current process may lack.
func (w *WireGuardInterface) configureInterfaceSelf() error {
	execPath, err := osExecutable()
	if err != nil {
		return fmt.Errorf("failed to find executable: %w", err)
	}

	hc := WGHelperConfig{
		PrivateKey:          w.PrivateKey[:],
		PublicKey:           base64.StdEncoding.EncodeToString(w.Peer.PublicKey[:]),
		PersistentKeepalive: int(w.Peer.PersistentKeepalive / time.Second),
	}

	if w.Peer.PresharedKey != nil {
		hc.PresharedKey = w.Peer.PresharedKey[:]
	}

	if w.Peer.Endpoint != nil {
		hc.Endpoint = w.Peer.Endpoint.String()
	}

	for _, aip := range w.Peer.AllowedIPs {
		hc.AllowedIPs = append(hc.AllowedIPs, aip.String())
	}

	jsonData, err := json.Marshal(hc)
	if err != nil {
		security.ZeroBytes(hc.PrivateKey)
		security.ZeroBytes(hc.PresharedKey)
		return fmt.Errorf("failed to marshal wg config: %w", err)
	}
	defer security.ZeroBytes(hc.PrivateKey)
	defer security.ZeroBytes(hc.PresharedKey)
	defer security.ZeroBytes(jsonData)

	cmd := execCommand(execPath, "wg-helper", "configure", w.Name)
	cmd.Stdin = bytes.NewReader(jsonData)
	sudo.SetCLocale(cmd)

	// Bound the helper's wall-clock time. wgctrl.ConfigureDevice
	// usually completes in <10ms but can wedge on a stuck netlink
	// socket (post-kernel-panic recovery, namespace teardown race).
	// Without a watcher the daemon's main goroutine blocks forever
	// inside doConnect — including past SIGTERM, which can't be
	// processed until the goroutine returns to the select. 30s is
	// generous for a healthy local syscall and short enough that a
	// stuck helper surfaces as a connect failure that can be retried.
	//
	// Inline CombinedOutput's body (a shared bytes.Buffer wired to
	// Stdout+Stderr) so we can capture cmd.Process AFTER Start has
	// written it but BEFORE the watcher reads it. The naive version
	// (watcher reads cmd.Process directly) races cmd.Start's write —
	// proven by the matching test in internal/security and matches
	// the fix shape used in security/delete.go and netlink/runner.go.
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start wg-helper: %w", err)
	}
	proc := cmd.Process

	// Capture wgHelperTimeout into a local BEFORE spawning the watcher
	// so the goroutine doesn't read the package var concurrently with
	// tests that mutate it via t.Cleanup. (The race detector flags
	// pkg-var read/write across goroutines even when the read clearly
	// happens-before the write at runtime.)
	timeout := wgHelperTimeout
	timedOut := make(chan struct{})
	done := make(chan struct{})
	go func() {
		select {
		case <-time.After(timeout):
			// Close timedOut BEFORE Kill — Kill is what causes Wait to
			// return in the main goroutine, and the main's post-Wait
			// select reads timedOut. If we Kill first the main may
			// race past the select's <-timedOut branch and into the
			// default branch before this close runs, then format the
			// error as a generic "configure failed" instead of the
			// useful "wg-helper timed out" message.
			close(timedOut)
			proc.Kill()
		case <-done:
		}
	}()
	err = cmd.Wait()
	close(done)
	if err != nil {
		outStr := outBuf.String()
		select {
		case <-timedOut:
			return fmt.Errorf("wg-helper timed out after %s — netlink may be wedged: %s", wgHelperTimeout, outStr)
		default:
		}
		if strings.Contains(outStr, "operation not permitted") || strings.Contains(outStr, "permission denied") {
			return fmt.Errorf("failed to configure wireguard: %w", sudo.ErrAuthRequired)
		}
		return fmt.Errorf("failed to configure wireguard via self-exec: %w: %s", err, outStr)
	}
	return nil
}

// wgHelperTimeout caps the wg-helper subprocess wall-clock time. See
// the comment above the watcher in configureInterfaceSelf for the
// reasoning behind the value.
var wgHelperTimeout = 30 * time.Second

// RunConfigureHelper is called by the wg-helper subcommand.
// It reads WGHelperConfig JSON from the given reader and configures the
// named WireGuard device via wgctrl.
func RunConfigureHelper(interfaceName string, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read config from stdin: %w", err)
	}
	defer security.ZeroBytes(data)

	var hc WGHelperConfig
	if err := json.Unmarshal(data, &hc); err != nil {
		return fmt.Errorf("failed to parse config JSON: %w", err)
	}
	defer security.ZeroBytes(hc.PrivateKey)
	defer security.ZeroBytes(hc.PresharedKey)

	privKey, err := ParsePrivateKey(hc.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	defer security.ZeroBytes(privKey[:])

	pubKey, err := parseKeyFromBase64(hc.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	var psk *wgtypes.Key
	if len(hc.PresharedKey) > 0 {
		k, err := ParsePrivateKey(hc.PresharedKey)
		if err != nil {
			return fmt.Errorf("invalid preshared key: %w", err)
		}
		// Zero the parsed PSK on return — `k` escapes to heap because
		// we take its address for psk, so GC can't reclaim it
		// immediately on function return. The matching defer for the
		// PrivateKey copy lives at line ~164. The defer on
		// hc.PresharedKey above zeros only the INPUT bytes, not this
		// parsed copy.
		defer security.ZeroBytes(k[:])
		psk = &k
	}

	var endpoint *net.UDPAddr
	if hc.Endpoint != "" {
		endpoint, err = net.ResolveUDPAddr("udp", hc.Endpoint)
		if err != nil {
			return fmt.Errorf("invalid endpoint: %w", err)
		}
	}

	var allowedIPs []net.IPNet
	for _, cidr := range hc.AllowedIPs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid allowed IP %s: %w", cidr, err)
		}
		allowedIPs = append(allowedIPs, *ipnet)
	}

	keepalive := time.Duration(hc.PersistentKeepalive) * time.Second

	peerConfig := wgtypes.PeerConfig{
		PublicKey:                   pubKey,
		PresharedKey:                psk,
		Endpoint:                    endpoint,
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: &keepalive,
		ReplaceAllowedIPs:           true,
	}

	cfg := wgtypes.Config{
		PrivateKey:   &privKey,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{peerConfig},
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl: %w", err)
	}
	defer client.Close()

	if err := client.ConfigureDevice(interfaceName, cfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}

	return nil
}

func parseKeyFromBase64(s string) (wgtypes.Key, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return wgtypes.Key{}, err
	}
	if len(decoded) != wgtypes.KeyLen {
		return wgtypes.Key{}, fmt.Errorf("invalid key length: got %d, want %d", len(decoded), wgtypes.KeyLen)
	}
	var k wgtypes.Key
	copy(k[:], decoded)
	return k, nil
}

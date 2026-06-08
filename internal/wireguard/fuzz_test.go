package wireguard

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzParseConfig(f *testing.F) {
	f.Add([]byte("[Interface]\nPrivateKey = " + "AAAA" + "\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = BBBB\nEndpoint = 1.1.1.1:51820\nAllowedIPs = 0.0.0.0/0\n"))
	f.Add([]byte(""))
	f.Add([]byte("garbage"))
	f.Add([]byte("[Interface]\n"))
	f.Add([]byte("[Interface]\nKey=val\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "f.conf")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Skip()
		}
		// Must not panic on any input
		_, _ = ParseConfig(path)
	})
}

func FuzzParseServerName(f *testing.F) {
	f.Add("US-NY#1")
	f.Add("Proton-US-NY-P2P#42")
	f.Add("se-sto-wg-001")
	f.Add("")
	f.Add("\x00\x00\x00")
	f.Add("toronto-tor")
	f.Fuzz(func(t *testing.T, name string) {
		_ = ParseServerName(name)
	})
}

// FuzzParseAddress hardens the connect path: Address values come from
// user-edited WG configs and should never crash parseAddress, and an
// error return must come with nil ip + nil ipnet (no half-parsed state).
func FuzzParseAddress(f *testing.F) {
	f.Add("10.0.0.1/24")
	f.Add("10.0.0.1")
	f.Add("fd00::1/128")
	f.Add("10.0.0.1/24, fd00::1/128")
	f.Add("")
	f.Add("/")
	f.Add(",")
	f.Add("10.0.0.1/")
	f.Add("/24")
	f.Fuzz(func(t *testing.T, addr string) {
		ip, ipnet, err := parseAddress(addr)
		if err != nil && (ip != nil || ipnet != nil) {
			t.Errorf("parseAddress(%q): err=%v but ip=%v ipnet=%v (must be nil on err)",
				addr, err, ip, ipnet)
		}
	})
}

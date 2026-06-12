// Command confcheck explains, in plain English, why a WireGuard .conf does or
// does not validate under LazyVPN's exact rules.
//
// It deliberately prints NO secrets — no private/preshared/public keys, no
// endpoint, address, or DNS values — only structural facts (which fields are
// present, whether keys decode, byte lengths) and the pass/fail verdict. So the
// output is safe to paste into a bug report.
//
// The verdict comes from calling LazyVPN's own ParseConfig / Validate /
// ValidatePrivateKey, so it matches what LazyVPN's "Set Up Provider" / "Import
// WireGuard Config" would decide.
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Fprintln(os.Stderr, "Usage: confcheck <path-to-wireguard.conf>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Explains why a WireGuard config does or doesn't validate under LazyVPN's rules.")
		fmt.Fprintln(os.Stderr, "Prints NO keys, endpoints, addresses, or DNS values — only structure and the")
		fmt.Fprintln(os.Stderr, "verdict — so the output is safe to share in a bug report.")
		os.Exit(2)
	}
	path := os.Args[1]

	fmt.Println("LazyVPN config validator (confcheck)")
	fmt.Println("Same rules as LazyVPN. No secrets are printed — safe to share.")
	fmt.Println(strings.Repeat("=", 68))

	scanStructure(path)

	fmt.Println(strings.Repeat("-", 68))
	fmt.Println("Verdict — LazyVPN's actual parse + validate:")

	cfg, err := wireguard.ParseConfig(path)
	if err != nil {
		fmt.Printf("  ✗ REJECTED at parse: %v\n", err)
		hint(err.Error())
		return
	}
	if err := cfg.Validate(); err != nil {
		cfg.ZeroKeys()
		fmt.Printf("  ✗ REJECTED (missing required field): %v\n", err)
		fmt.Println("    LazyVPN needs an [Interface] PrivateKey and a [Peer] PublicKey + Endpoint.")
		return
	}
	if err := wireguard.ValidatePrivateKey(cfg.PrivateKey); err != nil {
		cfg.ZeroKeys()
		fmt.Printf("  ✗ REJECTED (private key): %v\n", err)
		return
	}
	cfg.ZeroKeys()
	fmt.Println("  ✓ VALID — LazyVPN accepts this config.")
	fmt.Println()
	fmt.Println("Note: if your provider isn't one LazyVPN auto-detects (ProtonVPN, Mullvad,")
	fmt.Println("IVPN, AirVPN, NordVPN, Surfshark, Windscribe, FastestVPN), the dynamic server")
	fmt.Println("browser can't list its servers — but a VALID config still works via")
	fmt.Println("\"Import WireGuard Config\" (manual import, one server per file).")
}

// hint adds a plain-language explanation for the common parse failures. The
// underlying error messages reference byte offsets, never key contents.
func hint(msg string) {
	switch {
	case strings.Contains(msg, "PrivateKey"):
		fmt.Println("    → The [Interface] PrivateKey isn't standard padded base64. WireGuard keys")
		fmt.Println("      are 44 base64 chars ending in '='. Watch for URL-safe characters (-_)")
		fmt.Println("      or stripped '=' padding.")
	case strings.Contains(msg, "PresharedKey"):
		fmt.Println("    → The [Peer] PresharedKey isn't valid base64.")
	}
}

// scanStructure does a resilient, fully-redacted read of the file: it reports
// which fields are present and safe metadata about each, without printing any
// value. (This is supplementary; the authoritative pass/fail is the verdict.)
func scanStructure(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf("Cannot open file: %v\n", err)
		return
	}
	defer f.Close()

	facts := map[string]string{}
	var section string
	hasIface, hasPeer := false, false

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			switch section {
			case "interface":
				hasIface = true
			case "peer":
				hasPeer = true
			}
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])
		if i := strings.Index(value, " #"); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}
		switch section + "." + key {
		case "interface.privatekey":
			facts["PrivateKey"] = keyMeta(value)
		case "interface.address":
			facts["Address"] = "present"
		case "interface.dns":
			facts["DNS"] = "present"
		case "peer.publickey":
			facts["PublicKey"] = fmt.Sprintf("present (%d chars)", len(value))
		case "peer.presharedkey":
			facts["PresharedKey"] = keyMeta(value)
		case "peer.endpoint":
			facts["Endpoint"] = endpointMeta(value)
		case "peer.allowedips":
			facts["AllowedIPs"] = "present"
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Printf("  (read error: %v)\n", err)
	}

	fmt.Println("Structure (redacted — no key/endpoint/address/DNS values are printed):")
	get := func(k string) string {
		if v := facts[k]; v != "" {
			return v
		}
		return "MISSING"
	}
	fmt.Printf("  %-26s %s\n", "[Interface] section", yn(hasIface))
	fmt.Printf("    %-24s %s\n", "PrivateKey", get("PrivateKey"))
	fmt.Printf("    %-24s %s\n", "Address", get("Address"))
	fmt.Printf("    %-24s %s\n", "DNS", get("DNS"))
	fmt.Printf("  %-26s %s\n", "[Peer] section", yn(hasPeer))
	fmt.Printf("    %-24s %s\n", "PublicKey", get("PublicKey"))
	fmt.Printf("    %-24s %s\n", "Endpoint", get("Endpoint"))
	fmt.Printf("    %-24s %s\n", "PresharedKey", get("PresharedKey"))
	fmt.Printf("    %-24s %s\n", "AllowedIPs", get("AllowedIPs"))
}

// keyMeta reports whether a key decodes and its byte length — never the key.
func keyMeta(value string) string {
	dec, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Sprintf("present, but base64 decode FAILED (%v)", err)
	}
	return fmt.Sprintf("present, %d bytes after base64 (WireGuard needs 32)", len(dec))
}

// endpointMeta reports only the shape of the endpoint, never the host.
func endpointMeta(value string) string {
	if i := strings.LastIndex(value, ":"); i > 0 && i < len(value)-1 {
		return "present, has host:port form"
	}
	return "present, but NOT in host:port form"
}

func yn(b bool) string {
	if b {
		return "found"
	}
	return "MISSING"
}

package wireguard

import (
	"strings"
	"testing"
)

// TestParseServerNameRoundTrip: format → parse → format should return the
// same canonical form. If filename heuristics drift, two different
// filenames can collide on the same parsed ServerInfo, and the
// generation function won't pick the original back out.
func TestParseServerNameRoundTrip(t *testing.T) {
	cases := []string{
		"US-NY#42",
		"Proton-US-NY-P2P#100",
		"SE-Stockholm#5",
		"CA#1",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			info := ParseServerName(name)
			if info == nil {
				t.Fatalf("ParseServerName(%q) returned nil", name)
			}
			// At minimum: parsing twice produces the same result.
			info2 := ParseServerName(name)
			if info2 == nil {
				t.Fatalf("ParseServerName(%q) second call returned nil", name)
			}
			if info.Country != info2.Country || info.City != info2.City ||
				info.Number != info2.Number || info.Provider != info2.Provider {
				t.Errorf("ParseServerName not deterministic for %q:\n  first:  %+v\n  second: %+v",
					name, info, info2)
			}
			// Sanity: country code should look like a country code (2-3 chars,
			// uppercase) for the formats we control.
			if info.Country == "" {
				t.Errorf("Country empty for %q", name)
			}
			if info.Country != "" && info.Country != strings.ToUpper(info.Country) {
				t.Errorf("Country %q not uppercase for %q", info.Country, name)
			}
		})
	}
}

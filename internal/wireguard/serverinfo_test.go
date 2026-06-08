package wireguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseServerName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		country  string
		state    string
		city     string
		number   string
		provider string
	}{
		{"country-state-city", "Proton-US-DC-Washington#1", "US", "DC", "Washington", "1", "Proton"},
		{"country-state", "US-NY#123", "US", "NY", "", "123", ""},
		{"country-city", "SE-Stockholm#130", "SE", "", "Stockholm", "130", ""},
		{"country-number hash", "SE#130", "SE", "", "", "130", ""},
		{"country-number old", "SE-130", "SE", "", "", "130", ""},
		{"country-state-number dash", "US-DC-127", "US", "DC", "", "127", ""},
		{"mullvad prefix", "Mullvad-SE-Stockholm#5", "SE", "", "Stockholm", "5", "Mullvad"},
		{"features ignored", "US-NY-P2P#456", "US", "NY", "", "456", ""},
		{"unknown format", "random-server-name", "Unknown", "", "", "", ""},
		// Mullvad hostname format
		{"mullvad hostname se-sto", "se-sto-wg-001", "SE", "", "Stockholm", "001", "Mullvad"},
		{"mullvad hostname de-ber", "de-ber-wg-101", "DE", "", "Berlin", "101", "Mullvad"},
		{"mullvad hostname al-tia", "al-tia-wg-003", "AL", "", "Tirana", "003", "Mullvad"},
		{"mullvad hostname au-syd", "au-syd-wg-001", "AU", "", "Sydney", "001", "Mullvad"},
		{"mullvad hostname unknown city", "xx-zzz-wg-001", "XX", "", "ZZZ", "001", "Mullvad"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ParseServerName(tt.input)
			if info.Country != tt.country {
				t.Errorf("Country = %q, want %q", info.Country, tt.country)
			}
			if info.State != tt.state {
				t.Errorf("State = %q, want %q", info.State, tt.state)
			}
			if info.City != tt.city {
				t.Errorf("City = %q, want %q", info.City, tt.city)
			}
			if info.Number != tt.number {
				t.Errorf("Number = %q, want %q", info.Number, tt.number)
			}
			if info.Provider != tt.provider {
				t.Errorf("Provider = %q, want %q", info.Provider, tt.provider)
			}
		})
	}
}

func TestDetectServices(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		comments []string
		want     []string
	}{
		{"P2P in name", "US-NY-P2P#42", nil, []string{"p2p"}},
		{"Tor boundary", "US-Tor-P2P#1", nil, []string{"p2p", "tor"}},
		{"Toronto no tor", "CA-Toronto#1", nil, nil},
		{"SecureCore name", "CH-US-SecureCore#1", nil, []string{"securecore"}},
		{"SC pattern CH-US", "CH-US#5", nil, []string{"securecore"}},
		{"SC pattern IS-FR", "IS-FR#3", nil, []string{"securecore"}},
		{"SC pattern SE-DE", "SE-DE#1", nil, []string{"securecore"}},
		{"free", "US-FREE#1", nil, []string{"free"}},
		{"NAT-PMP comment", "US-NY#42", []string{"# NAT-PMP = on"}, []string{"p2p"}},
		{"accelerator comment", "US-NY#42", []string{"# VPN Accelerator = on"}, []string{"accelerator"}},
		{"plain server", "US-NY#42", nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectServices(tt.input, tt.comments)
			if len(got) != len(tt.want) {
				t.Errorf("detectServices() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("services[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestContainsString(t *testing.T) {
	if !containsString([]string{"a", "b"}, "b") {
		t.Error("should find 'b'")
	}
	if containsString([]string{"a", "b"}, "c") {
		t.Error("should not find 'c'")
	}
	if containsString(nil, "a") {
		t.Error("nil slice should return false")
	}
}

func TestPrettyName(t *testing.T) {
	tests := []struct {
		name  string
		info  ServerInfo
		check func(string) bool
	}{
		{
			"US-NY",
			ServerInfo{Name: "US-NY#123", Country: "US", State: "NY", Number: "123"},
			func(s string) bool {
				return strings.Contains(s, "United States") && strings.Contains(s, "New York") && strings.Contains(s, "(123)")
			},
		},
		{
			"country only",
			ServerInfo{Name: "SE#5", Country: "SE", Number: "5"},
			func(s string) bool { return strings.Contains(s, "Sweden") && strings.Contains(s, "(5)") },
		},
		{
			"with provider",
			ServerInfo{Name: "SE#5", Country: "SE", Number: "5", Provider: "Proton"},
			func(s string) bool { return strings.Contains(s, "ProtonVPN") },
		},
		{
			"unknown country",
			ServerInfo{Name: "random-name", Country: "Unknown"},
			func(s string) bool { return s == "random-name" },
		},
		{
			"with city",
			ServerInfo{Name: "SE-Stockholm#130", Country: "SE", City: "Stockholm", Number: "130"},
			func(s string) bool { return strings.Contains(s, "Sweden") && strings.Contains(s, "Stockholm") },
		},
		{
			"DC special case",
			ServerInfo{Name: "US-DC-Washington#1", Country: "US", State: "DC", City: "Washington", Number: "1"},
			func(s string) bool { return strings.Contains(s, "Washington DC") },
		},
		{
			"mullvad hostname",
			ServerInfo{Name: "se-sto-wg-001", Country: "SE", City: "Stockholm", Number: "001", Provider: "Mullvad"},
			func(s string) bool {
				return strings.Contains(s, "Sweden") && strings.Contains(s, "Stockholm") && strings.Contains(s, "Mullvad")
			},
		},
		{
			"with feature emojis",
			ServerInfo{Name: "US-NY-P2P#42", Country: "US", State: "NY", Number: "42", Services: []string{"p2p"}},
			func(s string) bool { return strings.Contains(s, "🔄") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.info.PrettyName()
			if !tt.check(got) {
				t.Errorf("PrettyName() = %q, check failed", got)
			}
		})
	}
}

func TestNewServer(t *testing.T) {
	cfg := &Config{
		Name:     "Proton-US-NY#42",
		Endpoint: "1.2.3.4:51820",
		DNS:      "10.2.0.1",
		Comments: []string{"# NAT-PMP = on"},
	}

	srv := NewServer(cfg)
	if srv.Info.Country != "US" {
		t.Errorf("Country = %q", srv.Info.Country)
	}
	if srv.Info.State != "NY" {
		t.Errorf("State = %q", srv.Info.State)
	}
	if srv.Info.Provider != "Proton" {
		t.Errorf("Provider = %q", srv.Info.Provider)
	}
	if srv.Info.Endpoint != "1.2.3.4:51820" {
		t.Errorf("Endpoint = %q", srv.Info.Endpoint)
	}
	if !containsString(srv.Info.Services, "p2p") {
		t.Error("expected p2p service from NAT-PMP comment")
	}
}

func TestGenerateStandardServerName(t *testing.T) {
	cfg := &Config{Name: "US-NY#42", Endpoint: ""}
	result := GenerateStandardServerName(cfg, "protonvpn", "")
	if result != "Proton-US-NY#42" {
		t.Errorf("got %q, want 'Proton-US-NY#42'", result)
	}
}

func TestGenerateStandardServerNameNoCountry(t *testing.T) {
	cfg := &Config{Name: "random-garbage-name", Endpoint: ""}
	result := GenerateStandardServerName(cfg, "", "")
	if result != "random-garbage-name" {
		t.Errorf("got %q, want original name", result)
	}
}

func TestGenerateStandardServerNameWithNumber(t *testing.T) {
	cfg := &Config{Name: "US-42", Endpoint: ""}
	result := GenerateStandardServerName(cfg, "protonvpn", "")
	if result != "Proton-US#42" {
		t.Errorf("got %q, want 'Proton-US#42'", result)
	}
}

// ===========================================================================
// Mutation-killing tests for serverinfo.go
// ===========================================================================

// Kills CONDITIONALS_NEGATION at serverinfo.go:250:29
// Mutation: s.Country == "Unknown" -> s.Country != "Unknown" in PrettyName.
// When Country IS "Unknown", PrettyName should return s.Name unchanged.
// When Country is a known value (e.g., "US"), PrettyName should return a formatted name.
// If mutation flips, known countries would return raw name and unknown would get formatted.
func TestPrettyName_Unknown_ReturnsRawName(t *testing.T) {
	info := ServerInfo{Name: "my-raw-name", Country: "Unknown"}
	got := info.PrettyName()
	if got != "my-raw-name" {
		t.Errorf("PrettyName() = %q, want %q for Unknown country", got, "my-raw-name")
	}

	// Also verify a known country does NOT return the raw name
	info2 := ServerInfo{Name: "US#1", Country: "US", Number: "1"}
	got2 := info2.PrettyName()
	if got2 == "US#1" {
		t.Errorf("PrettyName() = %q, should be formatted for known country", got2)
	}
	if !strings.Contains(got2, "United States") {
		t.Errorf("PrettyName() = %q, should contain 'United States'", got2)
	}
}

// Kills CONDITIONALS_NEGATION at serverinfo.go:264:20 and serverinfo.go:264:36
// Mutation: isSecureCore && s.State != "" -> negated conditions.
// Line 260: if isSecureCore && s.State != "" -> Secure Core format
// Line 264: else if s.State != "" && s.City != "" -> State+City format
// We need:
// 1. SecureCore WITH State -> should produce "Country -> ExitCountry" format
// 2. SecureCore WITHOUT State -> should NOT produce arrow format
// 3. Non-SecureCore WITH State AND City -> should produce state+city format
func TestPrettyName_SecureCore_WithState(t *testing.T) {
	info := ServerInfo{
		Name:     "CH-US#1",
		Country:  "CH",
		State:    "US",
		Number:   "1",
		Services: []string{"securecore"},
	}
	got := info.PrettyName()
	// Must contain the arrow format
	if !strings.Contains(got, "→") {
		t.Errorf("PrettyName() = %q, expected arrow for SecureCore with State", got)
	}
	if !strings.Contains(got, "Switzerland") {
		t.Errorf("PrettyName() = %q, expected Switzerland", got)
	}
	if !strings.Contains(got, "United States") {
		t.Errorf("PrettyName() = %q, expected United States", got)
	}
}

func TestPrettyName_SecureCore_WithoutState(t *testing.T) {
	info := ServerInfo{
		Name:     "CH#1",
		Country:  "CH",
		Number:   "1",
		Services: []string{"securecore"},
	}
	got := info.PrettyName()
	// Without State, should NOT produce the arrow format
	if strings.Contains(got, "→") {
		t.Errorf("PrettyName() = %q, should NOT have arrow when State is empty", got)
	}
	if !strings.Contains(got, "Switzerland") {
		t.Errorf("PrettyName() = %q, expected Switzerland", got)
	}
}

func TestPrettyName_NonSecureCore_StateAndCity(t *testing.T) {
	info := ServerInfo{
		Name:    "US-CA-LosAngeles#1",
		Country: "US",
		State:   "CA",
		City:    "LosAngeles",
		Number:  "1",
		// No securecore service
	}
	got := info.PrettyName()
	if strings.Contains(got, "→") {
		t.Errorf("PrettyName() = %q, should NOT have arrow without SecureCore", got)
	}
	if !strings.Contains(got, "California") {
		t.Errorf("PrettyName() = %q, expected California for state", got)
	}
	// Must also contain the city - this kills mutations that skip the State+City branch
	if !strings.Contains(got, "LosAngeles") {
		t.Errorf("PrettyName() = %q, expected LosAngeles for city", got)
	}
	// Must have comma separator (State+City format uses "stateName," + cityName)
	if !strings.Contains(got, ",") {
		t.Errorf("PrettyName() = %q, expected comma separator in State+City format", got)
	}
}

// Kills CONDITIONALS_NEGATION at serverinfo.go:269:14, 269:33, 269:59
// Line 269: if s.State == "DC" && (s.City == "Washington" || s.City == "DC")
// We need tests that verify:
// 1. State=DC, City=Washington -> "Washington DC" format
// 2. State=DC, City=DC -> "Washington DC" format
// 3. State=DC, City=SomethingElse -> NOT "Washington DC" format (state+city format)
// 4. State=NY, City=Washington -> NOT "Washington DC" format
func TestPrettyName_DC_Washington(t *testing.T) {
	info := ServerInfo{
		Name:    "US-DC-Washington#1",
		Country: "US",
		State:   "DC",
		City:    "Washington",
		Number:  "1",
	}
	got := info.PrettyName()
	if !strings.Contains(got, "Washington DC") {
		t.Errorf("PrettyName() = %q, expected 'Washington DC'", got)
	}
}

func TestPrettyName_DC_CityDC(t *testing.T) {
	info := ServerInfo{
		Name:    "US-DC-DC#1",
		Country: "US",
		State:   "DC",
		City:    "DC",
		Number:  "1",
	}
	got := info.PrettyName()
	if !strings.Contains(got, "Washington DC") {
		t.Errorf("PrettyName() = %q, expected 'Washington DC' for State=DC,City=DC", got)
	}
}

func TestPrettyName_DC_OtherCity(t *testing.T) {
	info := ServerInfo{
		Name:    "US-DC-Georgetown#1",
		Country: "US",
		State:   "DC",
		City:    "Georgetown",
		Number:  "1",
	}
	got := info.PrettyName()
	// Should NOT use the special case path (which omits the city).
	// The non-special-case path includes the city name after a comma.
	if !strings.Contains(got, "Georgetown") {
		t.Errorf("PrettyName() = %q, expected Georgetown in output", got)
	}
	// Ensure the city is included (special case path would omit it)
	if !strings.Contains(got, ",") {
		t.Errorf("PrettyName() = %q, expected comma-separated state and city", got)
	}
}

func TestPrettyName_NonDC_StateWithWashington(t *testing.T) {
	info := ServerInfo{
		Name:    "US-WA-Washington#1",
		Country: "US",
		State:   "WA",
		City:    "Washington",
		Number:  "1",
	}
	got := info.PrettyName()
	// State is WA not DC, so "Washington DC" special case should NOT apply
	if strings.Contains(got, "Washington DC") {
		t.Errorf("PrettyName() = %q, should NOT say 'Washington DC' for State=WA", got)
	}
}

// Kills CONDITIONALS_NEGATION at serverinfo.go:404:30 and serverinfo.go:404:44
// Line 404: if serverIP != "" && (state == "" || city == "")
// Mutation could flip serverIP != "" to serverIP == "" or negate the inner conditions.
// Test: when serverIP IS empty, geo lookup should NOT be called.
// Test: when state AND city are both filled, geo lookup should NOT be called.
func TestGenerateStandardServerName_NoGeoWhenNoEndpoint(t *testing.T) {
	saveFuncVars(t)

	geoCalled := false
	lookupGeoFunc = func(ip string) *geoResponse {
		geoCalled = true
		return &geoResponse{
			Status:      "success",
			CountryCode: "US",
			Region:      "CA",
			City:        "LA",
		}
	}

	cfg := &Config{
		Name:     "US-CA-LA#1",
		Endpoint: "", // empty endpoint
	}
	GenerateStandardServerName(cfg, "", "")
	if geoCalled {
		t.Error("lookupGeo should NOT be called when endpoint is empty")
	}
}

func TestGenerateStandardServerName_NoGeoWhenStateAndCityFilled(t *testing.T) {
	saveFuncVars(t)

	geoCalled := false
	lookupGeoFunc = func(ip string) *geoResponse {
		geoCalled = true
		return nil
	}

	// US-DC-Washington-1 matches reCountryStateCity: country=US, state=DC, city=Washington, number=1
	// Both state and city are non-empty, so geo lookup should be skipped
	cfg := &Config{
		Name:     "US-DC-Washington-1",
		Endpoint: "1.2.3.4:51820",
	}
	GenerateStandardServerName(cfg, "", "")
	if geoCalled {
		t.Error("lookupGeo should NOT be called when both state and city are already filled")
	}
}

func TestGenerateStandardServerName_GeoCalledWhenMissingStateOrCity(t *testing.T) {
	saveFuncVars(t)

	geoCalled := false
	lookupGeoFunc = func(ip string) *geoResponse {
		geoCalled = true
		return &geoResponse{
			Status:      "success",
			CountryCode: "US",
			Region:      "NY",
			City:        "NewYork",
		}
	}

	// US-42 matches reCountryNum: country=US, number=42, state="", city=""
	cfg := &Config{
		Name:     "US-42",
		Endpoint: "1.2.3.4:51820",
	}
	GenerateStandardServerName(cfg, "", "")
	if !geoCalled {
		t.Error("lookupGeo should be called when state or city is missing")
	}
}

// Kills CONDITIONALS_NEGATION at serverinfo.go:412:35 and serverinfo.go:412:54
// Line 412: if country == "US" || country == "CA" || country == "SE"
// Region code should only be used for US, CA, SE. For other countries, no state is set.
func TestGenerateStandardServerName_GeoRegion_US(t *testing.T) {
	saveFuncVars(t)

	lookupGeoFunc = func(ip string) *geoResponse {
		return &geoResponse{
			Status:      "success",
			CountryCode: "US",
			Region:      "CA",
			City:        "LosAngeles",
		}
	}

	cfg := &Config{
		Name:     "US-42",
		Endpoint: "1.2.3.4:51820",
	}
	result := GenerateStandardServerName(cfg, "", "")
	if !strings.Contains(result, "CA") {
		t.Errorf("result = %q, expected CA region for US country", result)
	}
}

func TestGenerateStandardServerName_GeoRegion_CA(t *testing.T) {
	saveFuncVars(t)

	lookupGeoFunc = func(ip string) *geoResponse {
		return &geoResponse{
			Status:      "success",
			CountryCode: "CA",
			Region:      "ON",
			City:        "Toronto",
		}
	}

	cfg := &Config{
		Name:     "CA-42",
		Endpoint: "1.2.3.4:51820",
	}
	result := GenerateStandardServerName(cfg, "", "")
	if !strings.Contains(result, "ON") {
		t.Errorf("result = %q, expected ON region for CA country", result)
	}
}

func TestGenerateStandardServerName_GeoRegion_SE(t *testing.T) {
	saveFuncVars(t)

	lookupGeoFunc = func(ip string) *geoResponse {
		return &geoResponse{
			Status:      "success",
			CountryCode: "SE",
			Region:      "AB",
			City:        "Stockholm",
		}
	}

	cfg := &Config{
		Name:     "SE-42",
		Endpoint: "1.2.3.4:51820",
	}
	result := GenerateStandardServerName(cfg, "", "")
	if !strings.Contains(result, "AB") {
		t.Errorf("result = %q, expected AB region for SE country", result)
	}
}

func TestGenerateStandardServerName_GeoRegion_DE_NotUsed(t *testing.T) {
	saveFuncVars(t)

	lookupGeoFunc = func(ip string) *geoResponse {
		return &geoResponse{
			Status:      "success",
			CountryCode: "DE",
			Region:      "BE",
			City:        "Berlin",
		}
	}

	cfg := &Config{
		Name:     "DE-42",
		Endpoint: "1.2.3.4:51820",
	}
	result := GenerateStandardServerName(cfg, "", "")
	// DE is not US/CA/SE, so region should NOT be used as state
	// The result should be "DE-Berlin#42", not "DE-BE-Berlin#42"
	if strings.Contains(result, "-BE-") || strings.Contains(result, "-BE#") {
		t.Errorf("result = %q, should NOT include region for DE country", result)
	}
	if !strings.Contains(result, "Berlin") {
		t.Errorf("result = %q, expected Berlin from geo city", result)
	}
}

// Kills CONDITIONALS_BOUNDARY at serverinfo.go:473:56
// Mutation: n > maxNum -> n >= maxNum
//
// This is an equivalent mutant. With unique server numbers (#1, #2, #3),
// both > and >= produce the same maxNum and therefore the same next number.
//
// With a #0 file:
//   - Original (>):  n=0, 0>0 false, maxNum stays 0, next=1
//   - Mutant   (>=): n=0, 0>=0 true, maxNum=0, next=1
//
// Both produce #1. The boundary change has no observable effect because
// maxNum starts at 0 and re-assigning maxNum=0 is a no-op.
// Test below exercises the path to document the analysis.
func TestGenerateStandardServerName_NumberAutoGen_ZeroExists(t *testing.T) {
	saveFuncVars(t)

	lookupGeoFunc = func(ip string) *geoResponse {
		return &geoResponse{
			Status:      "success",
			CountryCode: "US",
		}
	}

	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "US#0.conf"), []byte(""), 0600)

	cfg := &Config{
		Name:     "myserver",
		Endpoint: "1.2.3.4:51820",
	}
	result := GenerateStandardServerName(cfg, "", tmpDir)
	if !strings.Contains(result, "#") {
		t.Errorf("result = %q, expected auto-generated number", result)
	}
}

// TestLookupGeo_RejectsInvalidIP verifies the function bails out
// before hitting the network when given a malformed IP. Pre-fix, an
// IP like "../../admin" was sprintf'd into the URL path, giving
// path traversal that hit a different ipapi.co endpoint.
func TestLookupGeo_RejectsInvalidIP(t *testing.T) {
	cases := []string{
		"",
		"not-an-ip",
		"../../admin",
		"hostname.example.com",
		"127.0.0.1?injected=true",
	}
	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			// Real lookupGeo (not lookupGeoFunc which tests stub).
			// Must return nil without making any network call.
			start := time.Now()
			got := lookupGeo(ip)
			elapsed := time.Since(start)
			if got != nil {
				t.Errorf("lookupGeo(%q) = %+v, want nil", ip, got)
			}
			// If it had reached the network the dial alone would
			// take longer than this — proves we short-circuited.
			if elapsed > 100*time.Millisecond {
				t.Errorf("lookupGeo(%q) took %v — appears to have hit the network", ip, elapsed)
			}
		})
	}
}

// TestPrettyName_StateAndCityWinsOverStateOnly pins the if-else-if
// priority in PrettyName's location-build chain:
//
//   if isSecureCore && s.State != "" { ... }
//   else if s.State != "" && s.City != "" { ... }
//   else if s.State != "" { ... }
//   else if s.City != "" { ... }
//   else { ... country only }
//
// The State+City branch must be tried BEFORE the State-only branch.
// A regression that swapped them, or changed `else if` to bare `if`,
// would let State-only win for a server with both — silently dropping
// the city from the display ("United States - California" instead of
// "United States - California, Los Angeles").
//
// Existing TestPrettyName has a "DC special case" test that exercises
// State+City, but it goes through the DC-only sub-branch which would
// independently match in the "else if s.State != \"\"" branch via
// the State==DC check. The generic state+city path was unpinned.
//
// Sibling to 90348d9 (daemon Hint priority).
func TestPrettyName_StateAndCityWinsOverStateOnly(t *testing.T) {
	// Use CA + literal city name (avoids both the DC special case AND
	// any code-collision in ExpandLocationName — e.g. "LA" expands to
	// "Louisiana" via USStates lookup, not "Los Angeles" via CityCodes).
	info := &ServerInfo{
		Name:    "US-CA-Sacramento#1",
		Country: "US",
		State:   "CA",
		City:    "Sacramento",
		Number:  "1",
	}
	got := info.PrettyName()
	// Must contain BOTH the expanded state name AND the city.
	// State-only branch (priority regression) would emit
	// "United States - California" WITHOUT the city.
	if !strings.Contains(got, "California") {
		t.Errorf("PrettyName() = %q, want to contain 'California'", got)
	}
	if !strings.Contains(got, "Sacramento") {
		t.Errorf("PrettyName() = %q, want to contain 'Sacramento' (State+City priority regressed? state-only branch swallowed the city)", got)
	}
}

// TestProviderPrefixToDisplayName_CoversAllPrefixes pins the
// chained-lookup invariant between providerIDToPrefix and
// providerPrefixToDisplayName:
//
//   providerID → providerIDToPrefix[id] = prefix
//   prefix → providerPrefixToDisplayName[prefix] = "ProtonVPN" etc.
//
// Every prefix produced by providerIDToPrefix MUST be a key in
// providerPrefixToDisplayName. Otherwise the TUI's server-info
// rendering falls back to the raw prefix ("Proton" instead of
// "ProtonVPN") — a subtle UX regression that's easy to introduce
// when adding a new provider and forgetting one of the two maps.
//
// providerPrefixToDisplayName may legitimately have EXTRA keys
// (defensive entries for filename prefixes that arrive from other
// sources), so this contract is one-directional only: prefixes from
// providerIDToPrefix must all be looked-up-able in
// providerPrefixToDisplayName.
//
// Sibling pattern to TestProviderMapsHaveSameKeySet in provider/
// and TestProviderDNSAndPort_SameKeySet in config/.
func TestProviderPrefixToDisplayName_CoversAllPrefixes(t *testing.T) {
	for id, prefix := range providerIDToPrefix {
		if _, ok := providerPrefixToDisplayName[prefix]; !ok {
			t.Errorf("providerPrefixToDisplayName missing %q (used by providerIDToPrefix[%q]) — TUI would show raw prefix", prefix, id)
		}
	}
}

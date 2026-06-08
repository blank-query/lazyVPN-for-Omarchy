package wireguard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/util"
)

// Function variables for testing
var (
	lookupGeoFunc = lookupGeo
)

// ServerInfo contains parsed information about a server
type ServerInfo struct {
	Name     string
	Country  string
	State    string
	City     string
	Number   string
	Provider string
	Services []string
	Endpoint string
	DNS      string
}

// Provider prefixes to strip from server names
var providerPrefixes = []string{
	"Proton-", "Mullvad-", "IVPN-", "Nord-", "Surf-", "Windscribe-", "Fastest-",
	"wg-", "vpn-", "server-", "conf-",
}

// providerIDToPrefix maps internal provider IDs to filename prefixes
var providerIDToPrefix = map[string]string{
	"protonvpn":  "Proton",
	"mullvad":    "Mullvad",
	"ivpn":       "IVPN",
	"nordvpn":    "Nord",
	"surfshark":  "Surf",
	"windscribe": "Windscribe",
	"fastestvpn": "Fastest",
}

// providerPrefixToDisplayName maps raw prefix names to pretty display names
var providerPrefixToDisplayName = map[string]string{
	"Proton":     "ProtonVPN",
	"Mullvad":    "Mullvad",
	"IVPN":       "IVPN",
	"Nord":       "NordVPN",
	"Surf":       "Surfshark",
	"Windscribe": "Windscribe",
	"Fastest":    "FastestVPN",
}

// Patterns for parsing server names (most specific first)
var (
	// US-DC-Washington#1 or US-DC-Washington-P2P#1 (country-state-city-features-number)
	patternCountryStateCity = regexp.MustCompile(`^([A-Z]{2})-([A-Z]{2})-([A-Za-z]+)(?:-[A-Za-z0-9-]+)?#(\d+)$`)
	// US-NY#123 or US-NY-P2P#456 (country-state-features-number)
	patternCountryState = regexp.MustCompile(`^([A-Z]{2})-([A-Z]{2})(?:-[A-Za-z0-9-]+)?#(\d+)$`)
	// SE-Stockholm#130 or SE-Stockholm-P2P#456 (country-city-features-number)
	patternCountryCity = regexp.MustCompile(`^([A-Z]{2})-([A-Za-z]+)(?:-[A-Za-z0-9-]+)?#(\d+)$`)
	// US-DC-127 (country-state-number, dash separator)
	patternCountryStateNum = regexp.MustCompile(`^([A-Z]{2})-([A-Z]{2})-(\d+)$`)
	// SE#130 (country-number)
	patternCountryNum = regexp.MustCompile(`^([A-Z]{2})#(\d+)$`)
	// SE-130 (country-number, old style)
	patternCountryNumOld = regexp.MustCompile(`^([A-Z]{2})-(\d+)$`)
	// se-sto-wg-001 (Mullvad hostname format: country-city-wg-number)
	patternMullvadHostname = regexp.MustCompile(`^([a-z]{2})-([a-z]{2,4})-wg-(\d+)$`)
)

// ParseServerName extracts location info from a server name
func ParseServerName(name string) *ServerInfo {
	info := &ServerInfo{
		Name:    name,
		Country: "Unknown",
	}

	// Strip provider prefix (case-insensitive matching)
	parseName := name
	nameLowerForPrefix := strings.ToLower(parseName)
	for _, prefix := range providerPrefixes {
		if strings.HasPrefix(nameLowerForPrefix, strings.ToLower(prefix)) {
			info.Provider = strings.TrimSuffix(prefix, "-")
			parseName = parseName[len(prefix):]
			break
		}
	}

	// Try each pattern
	if m := patternCountryStateCity.FindStringSubmatch(parseName); m != nil {
		info.Country = m[1]
		info.State = m[2]
		info.City = m[3]
		info.Number = m[4]
	} else if m := patternCountryState.FindStringSubmatch(parseName); m != nil {
		info.Country = m[1]
		info.State = m[2]
		info.Number = m[3]
	} else if m := patternCountryCity.FindStringSubmatch(parseName); m != nil {
		info.Country = m[1]
		info.City = m[2]
		info.Number = m[3]
	} else if m := patternCountryStateNum.FindStringSubmatch(parseName); m != nil {
		info.Country = m[1]
		info.State = m[2]
		info.Number = m[3]
	} else if m := patternCountryNum.FindStringSubmatch(parseName); m != nil {
		info.Country = m[1]
		info.Number = m[2]
	} else if m := patternCountryNumOld.FindStringSubmatch(parseName); m != nil {
		info.Country = m[1]
		info.Number = m[2]
	}

	// Try Mullvad hostname format on original name (lowercase: se-sto-wg-001)
	if info.Country == "Unknown" {
		if m := patternMullvadHostname.FindStringSubmatch(strings.ToLower(name)); m != nil {
			info.Country = strings.ToUpper(m[1])
			cityCode := m[2]
			if cityName, ok := util.MullvadCityCodes[cityCode]; ok {
				info.City = cityName
			} else {
				info.City = strings.ToUpper(cityCode)
			}
			info.Number = m[3]
			info.Provider = "Mullvad"
		}
	}

	// Detect services from name (no comments available from name-only parse)
	info.Services = detectServices(name, nil)

	return info
}

// detectServices detects VPN features from server name
func detectServices(name string, comments []string) []string {
	nameLower := strings.ToLower(name)
	var services []string

	// Join comments for searching
	commentBlock := strings.ToLower(strings.Join(comments, "\n"))

	// Check name and comments for features
	if strings.Contains(nameLower, "p2p") || strings.Contains(commentBlock, "p2p") {
		services = append(services, "p2p")
	}
	// Boundary-aware Tor detection to avoid false positives (e.g., "Toronto")
	torPattern := regexp.MustCompile(`(?i)(?:^|[-_])tor(?:[-_]|$)`)
	if torPattern.MatchString(name) {
		services = append(services, "tor")
	}
	if strings.Contains(nameLower, "securecore") || strings.Contains(nameLower, "secure-core") {
		services = append(services, "securecore")
	}
	if strings.Contains(nameLower, "streaming") || strings.Contains(nameLower, "stream") ||
		strings.Contains(commentBlock, "streaming") {
		services = append(services, "streaming")
	}
	if strings.Contains(nameLower, "free") {
		services = append(services, "free")
	}

	// Check for Secure Core pattern: CH-US, IS-FR, SE-DE (entry country -> exit country)
	secureCorePattern := regexp.MustCompile(`^(CH|IS|SE)-([A-Z]{2})`)
	if secureCorePattern.MatchString(name) {
		if !containsString(services, "securecore") {
			services = append(services, "securecore")
		}
	}

	// Check config comments for ProtonVPN feature metadata
	for _, comment := range comments {
		lower := strings.ToLower(comment)
		if strings.Contains(lower, "nat-pmp") && strings.Contains(lower, "= on") {
			if !containsString(services, "p2p") {
				services = append(services, "p2p")
			}
		}
		if strings.Contains(lower, "vpn accelerator") && strings.Contains(lower, "= on") {
			if !containsString(services, "accelerator") {
				services = append(services, "accelerator")
			}
		}
		if strings.Contains(lower, "moderate nat") && strings.Contains(lower, "= on") {
			if !containsString(services, "moderatenat") {
				services = append(services, "moderatenat")
			}
		}
		if strings.Contains(lower, "netshield") {
			if strings.Contains(lower, "= 1") {
				services = append(services, "netshield1")
			} else if strings.Contains(lower, "= 2") {
				services = append(services, "netshield2")
			}
		}
	}

	// Check peer comments for Secure Core pattern (e.g., "# SE-RO#1")
	for _, comment := range comments {
		trimmed := strings.TrimPrefix(comment, "# ")
		trimmed = strings.TrimPrefix(trimmed, "#")
		trimmed = strings.TrimSpace(trimmed)
		scPattern := regexp.MustCompile(`^(CH|IS|SE)-([A-Z]{2})[#\d]`)
		if m := scPattern.FindStringSubmatch(trimmed); m != nil {
			exit := m[2]
			// Exclude false positives (TO=Tor, FR=Free, SC=SecureCore text)
			if exit != "TO" && exit != "FR" && exit != "SC" {
				if !containsString(services, "securecore") {
					services = append(services, "securecore")
				}
			}
		}
	}

	return services
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// PrettyName returns a formatted display name for the server
func (s *ServerInfo) PrettyName() string {
	if s.Country == "Unknown" || s.Country == "" {
		return s.Name
	}

	var parts []string

	// Flag
	flag := util.CountryFlag(s.Country)

	// Check for Secure Core (dual flag)
	isSecureCore := containsString(s.Services, "securecore")
	if isSecureCore && s.State != "" {
		// Entry -> Exit format
		exitFlag := util.CountryFlag(s.State)
		flag = flag + "→" + exitFlag
	}

	// Country name
	countryName := util.ExpandCountryName(s.Country)

	// Build location string
	if isSecureCore && s.State != "" {
		// Secure Core: "Switzerland → United States"
		exitCountry := util.ExpandCountryName(s.State)
		parts = append(parts, flag, countryName, "→", exitCountry)
	} else if s.State != "" && s.City != "" {
		// State + City: "United States - California, Los Angeles"
		stateName := util.ExpandLocationName(s.State)
		cityName := util.ExpandLocationName(s.City)
		// Special case for DC
		if s.State == "DC" && (s.City == "Washington" || s.City == "DC") {
			parts = append(parts, flag, countryName, "- Washington DC")
		} else {
			parts = append(parts, flag, countryName, "-", stateName+",", cityName)
		}
	} else if s.State != "" {
		// Just state: "United States - New York"
		stateName := util.ExpandLocationName(s.State)
		parts = append(parts, flag, countryName, "-", stateName)
	} else if s.City != "" {
		// Just city: "Sweden - Stockholm"
		cityName := util.ExpandLocationName(s.City)
		parts = append(parts, flag, countryName, "-", cityName)
	} else {
		// Just country: "Sweden"
		parts = append(parts, flag, countryName)
	}

	result := strings.Join(parts, " ")

	// Add server number
	if s.Number != "" {
		result += " (" + s.Number + ")"
	}

	// Add feature emojis
	featureEmojis := ""
	for _, svc := range s.Services {
		if emoji, ok := util.FeatureEmojis[svc]; ok {
			featureEmojis += emoji
		}
	}
	if featureEmojis != "" {
		result += " " + featureEmojis
	}

	// Add provider (use display name if available)
	if s.Provider != "" {
		displayName := s.Provider
		if dn, ok := providerPrefixToDisplayName[s.Provider]; ok {
			displayName = dn
		}
		result += " • " + displayName
	}

	return result
}

// Server represents a VPN server with config and info
type Server struct {
	Config *Config
	Info   *ServerInfo
}

// NewServer creates a Server from a config
func NewServer(cfg *Config) *Server {
	info := ParseServerName(cfg.Name)
	info.Endpoint = cfg.Endpoint
	info.DNS = cfg.DNS
	// Re-detect services with config comments for full feature detection
	info.Services = detectServices(cfg.Name, cfg.Comments)
	return &Server{
		Config: cfg,
		Info:   info,
	}
}

// DisplayName returns the pretty formatted name
func (s *Server) DisplayName() string {
	return s.Info.PrettyName()
}

// geoResponse represents the ip-api.com response
type geoResponse struct {
	// Fields populated by ipapi.co JSON response
	CountryCode string `json:"country_code"`
	Region      string `json:"region_code"`
	City        string `json:"city"`

	// Error detection (ipapi.co returns {"error": true, "reason": "..."} on failure)
	Error  bool   `json:"error"`
	Reason string `json:"reason"`

	// Status is set internally for test compatibility (not from JSON)
	Status string `json:"-"`
}

// GenerateStandardServerName auto-renames an imported config file to the
// standardized format: [Provider-]Country[-State][-City][-Features]#Number
// If location can't be determined, returns the original name unchanged.
func GenerateStandardServerName(cfg *Config, providerID string, destDir string) string {
	originalName := cfg.Name

	// Determine provider prefix
	provPrefix := ""
	if providerID != "" {
		if p, ok := providerIDToPrefix[providerID]; ok {
			provPrefix = p
		}
	}

	// Parse location from original filename
	parseName := originalName
	// Strip known prefixes (case-insensitive)
	parseNameLower := strings.ToLower(parseName)
	stripPrefixes := []string{"proton-", "mullvad-", "ivpn-", "nord-", "surf-", "windscribe-", "fastest-", "wg-", "vpn-", "server-"}
	for _, sp := range stripPrefixes {
		if strings.HasPrefix(parseNameLower, sp) {
			parseName = parseName[len(sp):]
			break
		}
	}

	country, state, city, number := "", "", "", ""

	// Regex patterns for filename parsing (most specific first)
	reCountryStateCity := regexp.MustCompile(`^([A-Z]{2})[-_]([A-Z]{2})[-_]([A-Za-z]+)[-_#](\d+)`)
	reCountryState := regexp.MustCompile(`^([A-Z]{2})[-_]([A-Z]{2})[-_#](\d+)`)
	reCountryCity := regexp.MustCompile(`^([A-Z]{2,})[-_]([A-Za-z]+)[-_#](\d+)`)
	reCountryNum := regexp.MustCompile(`^([A-Z]{2,})[-_](\d+)`)
	reCountryHashNum := regexp.MustCompile(`^([A-Z]{2,})#(\d+)`)

	if m := reCountryStateCity.FindStringSubmatch(parseName); m != nil {
		country, state, city, number = m[1], m[2], m[3], m[4]
	} else if m := reCountryState.FindStringSubmatch(parseName); m != nil {
		country, state, number = m[1], m[2], m[3]
	} else if m := reCountryCity.FindStringSubmatch(parseName); m != nil {
		country, city, number = m[1], m[2], m[3]
	} else if m := reCountryNum.FindStringSubmatch(parseName); m != nil {
		country, number = m[1], m[2]
	} else if m := reCountryHashNum.FindStringSubmatch(parseName); m != nil {
		country, number = m[1], m[2]
	}

	// Filter out tier keywords from location fields
	tierKeywords := map[string]bool{"FREE": true, "PLUS": true, "PREMIUM": true, "PRO": true}
	if tierKeywords[strings.ToUpper(city)] {
		city = ""
	}
	if tierKeywords[strings.ToUpper(state)] {
		state = ""
	}

	// Use IP geolocation to fill in missing location info
	serverIP := cfg.EndpointIP()
	if serverIP != "" && (state == "" || city == "") {
		geo := lookupGeoFunc(serverIP)
		if geo != nil {
			if country == "" && geo.CountryCode != "" {
				country = geo.CountryCode
			}
			if state == "" && geo.Region != "" {
				// Use region code for US/CA/SE
				if country == "US" || country == "CA" || country == "SE" {
					state = geo.Region
				}
			}
			if city == "" && geo.City != "" {
				// Clean city for filename (remove spaces)
				city = strings.ReplaceAll(geo.City, " ", "")
			}
		}
	}

	// If we couldn't determine country, return original name
	if country == "" {
		return originalName
	}

	// Detect features from filename and config
	var features []string
	nameAndComments := strings.ToLower(originalName + "\n" + strings.Join(cfg.Comments, "\n"))
	if strings.Contains(nameAndComments, "p2p") {
		features = append(features, "P2P")
	}
	torPattern := regexp.MustCompile(`(?i)(?:^|[-_])tor(?:[-_]|$)`)
	if torPattern.MatchString(originalName) || regexp.MustCompile(`(?i)\btor\b`).MatchString(strings.Join(cfg.Comments, "\n")) {
		features = append(features, "Tor")
	}
	if regexp.MustCompile(`(?i)secure[_-]?core`).MatchString(nameAndComments) {
		features = append(features, "SC")
	}
	if strings.Contains(nameAndComments, "streaming") {
		features = append(features, "Stream")
	}

	// Generate number if missing (find next available)
	if number == "" && destDir != "" {
		featureStr := strings.Join(features, "-")
		searchPrefix := ""
		if provPrefix != "" {
			searchPrefix += provPrefix + "-"
		}
		searchPrefix += country
		if state != "" {
			searchPrefix += "-" + state
		}
		if city != "" {
			searchPrefix += "-" + city
		}
		if featureStr != "" {
			searchPrefix += "-" + featureStr
		}
		searchPrefix += "#"

		maxNum := 0
		entries, _ := os.ReadDir(destDir)
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			base := strings.TrimSuffix(entry.Name(), ".conf")
			if strings.HasPrefix(base, searchPrefix) {
				numStr := base[len(searchPrefix):]
				if n, err := strconv.Atoi(numStr); err == nil && n > maxNum {
					maxNum = n
				}
			}
		}
		number = strconv.Itoa(maxNum + 1)
	}

	// Build standardized name
	var parts []string
	if provPrefix != "" {
		parts = append(parts, provPrefix)
	}
	parts = append(parts, country)
	if state != "" {
		parts = append(parts, state)
	}
	if city != "" {
		parts = append(parts, city)
	}
	if len(features) > 0 {
		parts = append(parts, strings.Join(features, "-"))
	}

	stdName := strings.Join(parts, "-")
	if number != "" {
		stdName += "#" + number
	}

	return stdName
}

// lookupGeo performs an IP geolocation lookup via ipapi.co (HTTPS).
// Uses ipapi.co instead of ip-api.com because the latter's free tier
// only supports plaintext HTTP, which leaks server IPs on the network.
func lookupGeo(ip string) *geoResponse {
	// Validate the IP before formatting it into the URL path. A
	// malformed value (e.g. from a corrupt WG config with garbage
	// Endpoint) would otherwise produce a malformed URL — at best
	// a 404, at worst path traversal that hits a different ipapi.co
	// endpoint than intended.
	if net.ParseIP(ip) == nil {
		return nil
	}
	// Private transport with keep-alives off so geo lookups during
	// server import don't accumulate idle HTTP/2 connections in the
	// default pool (matches the pattern in fetchIPFromService /
	// GetPublicIPInfo / runSingleTest).
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	// NewRequestWithContext threads the deadline into the underlying
	// transport so HTTP/2 reads are actually bounded (client.Get +
	// client.Timeout don't propagate cancel into in-flight reads on h2).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://ipapi.co/%s/json/", ip), nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Bound the response — without LimitReader a hostile or
	// misbehaving server could feed json.Decoder an unbounded stream.
	// Real ipapi.co responses are <2KB; 16KB is generous.
	const maxGeoRespBytes = 16 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGeoRespBytes))
	if err != nil {
		return nil
	}
	var geo geoResponse
	if err := json.Unmarshal(body, &geo); err != nil {
		return nil
	}
	if geo.Error || geo.CountryCode == "" {
		return nil
	}
	geo.Status = "success"
	return &geo
}

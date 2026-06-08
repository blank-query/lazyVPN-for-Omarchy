package util

import (
	"strings"
)

// CountryFlag returns the flag emoji for a country code
func CountryFlag(code string) string {
	code = strings.ToUpper(code)

	// Map common non-ISO codes
	if code == "UK" {
		code = "GB"
	}

	if len(code) != 2 {
		return ""
	}

	// Convert to regional indicator symbols
	// A = 🇦 (U+1F1E6), B = 🇧, etc.
	var flag strings.Builder
	for _, c := range code {
		if c >= 'A' && c <= 'Z' {
			// Regional indicator base is 0x1F1E6, A starts at 'A' (65)
			indicator := 0x1F1E6 + int(c-'A')
			flag.WriteRune(rune(indicator))
		}
	}
	return flag.String()
}

// Countries maps country codes to full names
var Countries = map[string]string{
	"US": "United States", "GB": "United Kingdom", "UK": "United Kingdom", "CA": "Canada", "AU": "Australia", "NZ": "New Zealand",
	"DE": "Germany", "FR": "France", "IT": "Italy", "ES": "Spain", "PT": "Portugal", "NL": "Netherlands",
	"BE": "Belgium", "CH": "Switzerland", "AT": "Austria", "SE": "Sweden", "NO": "Norway", "DK": "Denmark",
	"FI": "Finland", "IS": "Iceland", "IE": "Ireland", "PL": "Poland", "CZ": "Czech Republic",
	"HU": "Hungary", "RO": "Romania", "BG": "Bulgaria", "GR": "Greece", "TR": "Turkey", "IL": "Israel",
	"IN": "India", "JP": "Japan", "KR": "South Korea", "CN": "China", "HK": "Hong Kong", "TW": "Taiwan",
	"SG": "Singapore", "MY": "Malaysia", "TH": "Thailand", "VN": "Vietnam", "ID": "Indonesia", "PH": "Philippines",
	"BR": "Brazil", "AR": "Argentina", "CL": "Chile", "MX": "Mexico", "CO": "Colombia", "PE": "Peru",
	"ZA": "South Africa", "EG": "Egypt", "KE": "Kenya", "NG": "Nigeria", "MA": "Morocco",
	"RU": "Russia", "UA": "Ukraine", "BY": "Belarus", "KZ": "Kazakhstan",
	"AE": "UAE", "SA": "Saudi Arabia", "QA": "Qatar", "OM": "Oman", "KW": "Kuwait",
	"CR": "Costa Rica", "PA": "Panama", "UY": "Uruguay", "VE": "Venezuela",
	"LU": "Luxembourg", "LV": "Latvia", "LT": "Lithuania", "EE": "Estonia", "SK": "Slovakia",
	"SI": "Slovenia", "HR": "Croatia", "RS": "Serbia", "BA": "Bosnia", "MK": "North Macedonia",
	"AL": "Albania", "MT": "Malta", "CY": "Cyprus", "GE": "Georgia", "AM": "Armenia", "AZ": "Azerbaijan",
}

// USStates maps US state codes to full names
var USStates = map[string]string{
	"AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California",
	"CO": "Colorado", "CT": "Connecticut", "DE": "Delaware", "FL": "Florida", "GA": "Georgia",
	"HI": "Hawaii", "ID": "Idaho", "IL": "Illinois", "IN": "Indiana", "IA": "Iowa",
	"KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine", "MD": "Maryland",
	"MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi", "MO": "Missouri",
	"MT": "Montana", "NE": "Nebraska", "NV": "Nevada", "NH": "New Hampshire", "NJ": "New Jersey",
	"NM": "New Mexico", "NY": "New York", "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio",
	"OK": "Oklahoma", "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina",
	"SD": "South Dakota", "TN": "Tennessee", "TX": "Texas", "UT": "Utah", "VT": "Vermont",
	"VA": "Virginia", "WA": "Washington", "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming",
	"DC": "Washington DC",
}

// CanadianProvinces maps Canadian province codes to full names
var CanadianProvinces = map[string]string{
	"AB": "Alberta", "BC": "British Columbia", "MB": "Manitoba", "NB": "New Brunswick",
	"NL": "Newfoundland", "NS": "Nova Scotia", "ON": "Ontario", "PE": "Prince Edward Island",
	"QC": "Quebec", "SK": "Saskatchewan", "NT": "Northwest Territories", "NU": "Nunavut",
	"YT": "Yukon",
}

// SwedishRegions maps Swedish region codes
var SwedishRegions = map[string]string{
	"RO": "Roslagen", "SK": "Skåne", "ST": "Stockholm", "VS": "Västmanland",
	"VG": "Västra Götaland", "NO": "Norrland", "GO": "Göteborg", "MA": "Malmö",
}

// CityCodes maps common city abbreviations
var CityCodes = map[string]string{
	"NYC": "New York City", "LA": "Los Angeles", "SF": "San Francisco", "CHI": "Chicago",
	"MIA": "Miami", "SEA": "Seattle", "DEN": "Denver", "ATL": "Atlanta", "PHX": "Phoenix",
	"DAL": "Dallas", "PHI": "Philadelphia", "HOU": "Houston", "BOS": "Boston", "DET": "Detroit",
	"LV": "Las Vegas", "PDX": "Portland", "SLC": "Salt Lake City", "SAN": "San Diego",
	"LON": "London", "PAR": "Paris", "BER": "Berlin", "AMS": "Amsterdam", "ZUR": "Zurich",
	"FRA": "Frankfurt", "MIL": "Milan", "ROM": "Rome", "MAD": "Madrid", "BAR": "Barcelona",
	"VIE": "Vienna", "BRU": "Brussels", "OSL": "Oslo", "STO": "Stockholm", "HEL": "Helsinki",
	"WAR": "Warsaw", "PRA": "Prague", "BUD": "Budapest", "DUB": "Dublin", "CPH": "Copenhagen",
	"LIS": "Lisbon", "ATH": "Athens", "BUC": "Bucharest", "SOF": "Sofia", "IST": "Istanbul",
	"TYO": "Tokyo", "SEO": "Seoul", "SIN": "Singapore", "HKG": "Hong Kong", "SYD": "Sydney",
	"MEL": "Melbourne", "TOR": "Toronto", "MON": "Montreal", "VAN": "Vancouver",
	"Tor": "Tor", "Malmoe": "Malmö", "Goeteborg": "Göteborg",
}

// ExpandCountryName expands a country code to its full name
func ExpandCountryName(code string) string {
	code = strings.ToUpper(code)
	if name, ok := Countries[code]; ok {
		return name
	}
	return code
}

// ExpandLocationName expands a location code (state, province, city) to its full name
func ExpandLocationName(code string) string {
	// Check US states
	if name, ok := USStates[code]; ok {
		return name
	}
	// Check Canadian provinces
	if name, ok := CanadianProvinces[code]; ok {
		return name
	}
	// Check Swedish regions
	if name, ok := SwedishRegions[code]; ok {
		return name
	}
	// Check city codes
	if name, ok := CityCodes[code]; ok {
		return name
	}
	return code
}

// MullvadCityCodes maps Mullvad's 3-4 letter city abbreviations to full city names
var MullvadCityCodes = map[string]string{
	"ams": "Amsterdam", "ath": "Athens", "atl": "Atlanta", "akl": "Auckland",
	"beg": "Belgrade", "ber": "Berlin", "bog": "Bogota", "bos": "Boston",
	"bne": "Brisbane", "bru": "Brussels", "bts": "Bratislava", "bud": "Budapest",
	"chi": "Chicago", "cph": "Copenhagen", "dal": "Dallas", "den": "Denver",
	"dub": "Dublin", "dus": "Dusseldorf", "fra": "Frankfurt", "got": "Gothenburg",
	"hel": "Helsinki", "hkg": "Hong Kong", "hou": "Houston", "ist": "Istanbul",
	"jnb": "Johannesburg", "lax": "Los Angeles", "lis": "Lisbon", "lon": "London",
	"mad": "Madrid", "man": "Manchester", "mel": "Melbourne", "mia": "Miami",
	"mil": "Milan", "mma": "Malmö", "mrs": "Marseille", "mow": "Moscow",
	"mtr": "Montreal", "nyc": "New York", "osl": "Oslo", "par": "Paris",
	"phx": "Phoenix", "prg": "Prague", "rom": "Rome", "sea": "Seattle",
	"sin": "Singapore", "sjc": "San Jose", "slc": "Salt Lake City",
	"sof": "Sofia", "sto": "Stockholm", "syd": "Sydney", "tia": "Tirana",
	"tll": "Tallinn", "tky": "Tokyo", "tor": "Toronto", "van": "Vancouver",
	"vie": "Vienna", "war": "Warsaw", "zag": "Zagreb", "zrh": "Zurich",
	"rig": "Riga", "bkk": "Bangkok", "hnd": "Tokyo", "svg": "Stavanger",
	"tpe": "Taipei", "uyk": "Uyuni", "qas": "Ashburn",
}

// FeatureEmojis maps feature names to emojis
var FeatureEmojis = map[string]string{
	"p2p":         "🔄",
	"tor":         "🧅",
	"securecore":  "🔒",
	"streaming":   "📺",
	"free":        "🤡",
	"accelerator": "🚀",
	"netshield1":  "🗡️",
	"netshield2":  "⚔️",
	"moderatenat": "🎮",
}

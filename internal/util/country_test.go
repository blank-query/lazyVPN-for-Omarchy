package util

import (
	"testing"
)

func TestCountryFlag(t *testing.T) {
	tests := []struct {
		code string
		want string
	}{
		{"US", "\U0001F1FA\U0001F1F8"},
		{"GB", "\U0001F1EC\U0001F1E7"},
		{"UK", "\U0001F1EC\U0001F1E7"}, // UK -> GB mapping
		{"SE", "\U0001F1F8\U0001F1EA"},
		{"", ""},
		{"A", ""},                      // too short
		{"ABC", ""},                    // too long
		{"us", "\U0001F1FA\U0001F1F8"}, // lowercase should work (ToUpper)
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := CountryFlag(tt.code)
			if got != tt.want {
				t.Errorf("CountryFlag(%q) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestExpandCountryName(t *testing.T) {
	tests := []struct {
		code string
		want string
	}{
		{"US", "United States"},
		{"GB", "United Kingdom"},
		{"UK", "United Kingdom"},
		{"SE", "Sweden"},
		{"DE", "Germany"},
		{"XX", "XX"},            // unknown returns code
		{"us", "United States"}, // lowercase
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := ExpandCountryName(tt.code)
			if got != tt.want {
				t.Errorf("ExpandCountryName(%q) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestExpandLocationName(t *testing.T) {
	tests := []struct {
		code string
		want string
	}{
		{"NY", "New York"},         // US state
		{"CA", "California"},       // US state
		{"DC", "Washington DC"},    // US state
		{"ON", "Ontario"},          // Canadian province
		{"BC", "British Columbia"}, // Canadian province
		{"ST", "Stockholm"},        // Swedish region
		{"NYC", "New York City"},   // City code
		{"LON", "London"},          // City code
		{"XX", "XX"},               // unknown returns code
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := ExpandLocationName(tt.code)
			if got != tt.want {
				t.Errorf("ExpandLocationName(%q) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestFeatureEmojisMap(t *testing.T) {
	expectedKeys := []string{"p2p", "tor", "securecore", "streaming", "free", "accelerator", "netshield1", "netshield2", "moderatenat"}
	for _, k := range expectedKeys {
		if _, ok := FeatureEmojis[k]; !ok {
			t.Errorf("FeatureEmojis missing key %q", k)
		}
	}
}

func TestCountriesMapCoverage(t *testing.T) {
	// Spot-check a few entries
	checks := map[string]string{
		"US": "United States",
		"JP": "Japan",
		"BR": "Brazil",
		"ZA": "South Africa",
	}
	for code, name := range checks {
		if Countries[code] != name {
			t.Errorf("Countries[%q] = %q, want %q", code, Countries[code], name)
		}
	}
}

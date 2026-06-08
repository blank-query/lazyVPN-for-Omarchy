package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/provider"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
)

// --- helpers ---

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	// ConfigFile must be set to a writable path within ConfigDir so
	// cfg.Save's atomic-rename succeeds. Without this, Save fails
	// silently and any test that mutates cfg.Favorites then asserts
	// the new value passes only because the old code ignored Save's
	// return value. With error-checking introduced, the revert path
	// fires and the assertion fails.
	return &config.Config{
		ConfigDir:  dir,
		ConfigFile: dir + "/config.json",
		Favorites:  []string{},
	}
}

func makeManualItem(name, endpoint string, fav bool, services ...string) browserItem {
	cfg := &wireguard.Config{Name: name, Endpoint: endpoint}
	info := wireguard.ParseServerName(name)
	info.Services = services
	srv := &wireguard.Server{Config: cfg, Info: info}
	item := browserItem{
		manualServer: srv,
		display:      srv.DisplayName(),
		favorite:     fav,
	}
	for _, svc := range services {
		switch svc {
		case "p2p":
			item.portForward = true
		case "tor":
			item.tor = true
		case "securecore":
			item.secureCore = true
		case "streaming":
			item.stream = true
		case "free":
			item.free = true
		}
	}
	return item
}

func makeDynamicItem(srvName, provName, country, city string, features ...string) browserItem {
	srv := provider.Server{
		ServerName: srvName,
		Country:    country,
		City:       city,
		IPs:        []string{"10.0.0.1"},
	}
	for _, f := range features {
		switch f {
		case "p2p":
			srv.PortForward = true
		case "tor":
			srv.Tor = true
		case "securecore":
			srv.SecureCore = true
		case "streaming":
			srv.Stream = true
		case "free":
			srv.Free = true
		}
	}
	return browserItem{
		providerServer: &srv,
		providerName:   provName,
		display:        formatProviderServer(srv) + " • " + provName,
		portForward:    srv.PortForward,
		tor:            srv.Tor,
		secureCore:     srv.SecureCore,
		stream:         srv.Stream,
		free:           srv.Free,
	}
}

func makeFavDynamicItem(provName, srvName string) browserItem {
	return browserItem{
		isDynamic:       true,
		dynamicProvider: provName,
		dynamicName:     srvName,
		display:         srvName + " • " + provName,
		favorite:        true,
	}
}

func makeInvalidItem(name, errMsg string) browserItem {
	return browserItem{
		manualServer: &wireguard.Server{
			Config: &wireguard.Config{Name: name, ParseError: errMsg},
			Info:   wireguard.ParseServerName(name),
		},
		display:  name,
		invalid:  true,
		errorMsg: errMsg,
	}
}

// populateBrowser sets up a ServerBrowser with pre-built items (skipping disk I/O).
func populateBrowser(mode BrowseMode, cfg *config.Config, items []browserItem) *ServerBrowser {
	m := &ServerBrowser{
		mode:     mode,
		cfg:      cfg,
		servers:  items,
		filtered: append([]browserItem{}, items...),
		auth:     &AuthPrompt{},
	}
	return m
}

// --- Tests ---

func TestItemKey(t *testing.T) {
	cfg := testConfig(t)

	tests := []struct {
		name string
		item browserItem
		want string
	}{
		{
			"manual server",
			makeManualItem("US-NY#1", "1.2.3.4:51820", false),
			"US-NY#1",
		},
		{
			"dynamic provider server",
			makeDynamicItem("US-NY#42", "protonvpn", "United States", "New York"),
			"US-NY#42",
		},
		{
			"favorited dynamic in MyServers",
			makeFavDynamicItem("mullvad", "SE#130"),
			"dynamic:mullvad:SE#130",
		},
		{
			"fallback to display",
			browserItem{display: "some-display"},
			"some-display",
		},
	}

	m := populateBrowser(BrowseMyServers, cfg, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.itemKey(tt.item)
			if got != tt.want {
				t.Errorf("itemKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestItemDisplayName(t *testing.T) {
	cfg := testConfig(t)

	tests := []struct {
		name string
		item browserItem
		want string
	}{
		{
			"manual",
			makeManualItem("SE-Stockholm#5", "5.6.7.8:51820", false),
			"SE-Stockholm#5",
		},
		{
			"dynamic provider",
			makeDynamicItem("US-NY#42", "protonvpn", "United States", "New York"),
			"US-NY#42",
		},
		{
			"favorited dynamic",
			makeFavDynamicItem("mullvad", "SE#130"),
			"SE#130",
		},
	}

	m := populateBrowser(BrowseMyServers, cfg, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.itemDisplayName(tt.item)
			if got != tt.want {
				t.Errorf("itemDisplayName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatProviderServer(t *testing.T) {
	tests := []struct {
		name string
		srv  provider.Server
		want []string // substrings that must appear
	}{
		{
			"basic server",
			provider.Server{ServerName: "US-NY#42", Country: "United States", City: "New York"},
			[]string{"United States", "New York", "(US-NY#42)"},
		},
		{
			"server with P2P",
			provider.Server{ServerName: "SE#5", Country: "Sweden", PortForward: true},
			[]string{"Sweden", "(SE#5)", "🔄"},
		},
		{
			"server with all features",
			provider.Server{
				ServerName:  "DE#1",
				Country:     "Germany",
				PortForward: true,
				Tor:         true,
				SecureCore:  true,
				Stream:      true,
				Free:        true,
			},
			[]string{"🔄", "🧅", "🔒", "📺", "🤡"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatProviderServer(tt.srv)
			for _, sub := range tt.want {
				if !strings.Contains(got, sub) {
					t.Errorf("formatProviderServer() = %q, missing %q", got, sub)
				}
			}
		})
	}
}

func TestFormatDynamicDisplay(t *testing.T) {
	srv := provider.Server{ServerName: "US-NY#42", Country: "United States", City: "New York"}
	got := formatDynamicDisplay(srv, "protonvpn")
	if !strings.Contains(got, "ProtonVPN") {
		t.Errorf("formatDynamicDisplay() = %q, missing provider display name", got)
	}
	if !strings.Contains(got, "United States") {
		t.Errorf("formatDynamicDisplay() = %q, missing country", got)
	}
}

func TestFilterServers_FeatureFilters(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US-NY#1", "protonvpn", "US", "NY", "p2p"),
		makeDynamicItem("SE#2", "protonvpn", "SE", "", "tor"),
		makeDynamicItem("DE#3", "protonvpn", "DE", "", "streaming"),
		makeDynamicItem("FR#4", "protonvpn", "FR", "", "free"),
		makeDynamicItem("CH#5", "protonvpn", "CH", ""),
	}

	tests := []struct {
		name      string
		setFilter func(m *ServerBrowser)
		wantCount int
		wantName  string
	}{
		{"P2P filter", func(m *ServerBrowser) { m.filterP2P = true }, 1, "US-NY#1"},
		{"Tor filter", func(m *ServerBrowser) { m.filterTor = true }, 1, "SE#2"},
		{"Stream filter", func(m *ServerBrowser) { m.filterStream = true }, 1, "DE#3"},
		{"Free filter", func(m *ServerBrowser) { m.filterFree = true }, 1, "FR#4"},
		{"no filter", func(m *ServerBrowser) {}, 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := populateBrowser(BrowseDynamic, cfg, items)
			tt.setFilter(m)
			m.filterServers()
			if len(m.filtered) != tt.wantCount {
				t.Errorf("filtered count = %d, want %d", len(m.filtered), tt.wantCount)
			}
			if tt.wantName != "" && len(m.filtered) > 0 {
				got := m.itemKey(m.filtered[0])
				if got != tt.wantName {
					t.Errorf("first filtered item key = %q, want %q", got, tt.wantName)
				}
			}
		})
	}
}

func TestFilterServers_ProviderFilter(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US-NY#1", "protonvpn", "US", "NY"),
		makeDynamicItem("SE#2", "mullvad", "SE", ""),
		makeDynamicItem("DE#3", "protonvpn", "DE", ""),
	}

	m := populateBrowser(BrowseDynamic, cfg, items)
	m.multiProvider = true
	m.providers = []string{"protonvpn", "mullvad"}
	m.providerFilter = "mullvad"
	m.filterServers()

	if len(m.filtered) != 1 {
		t.Fatalf("filtered count = %d, want 1", len(m.filtered))
	}
	if m.filtered[0].providerName != "mullvad" {
		t.Errorf("filtered provider = %q, want mullvad", m.filtered[0].providerName)
	}
}

func TestFilterServers_ProviderFilterIgnoredInMyServers(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeManualItem("US-NY#1", "1.2.3.4:51820", false),
		makeManualItem("SE#2", "5.6.7.8:51820", false),
	}

	m := populateBrowser(BrowseMyServers, cfg, items)
	m.providerFilter = "protonvpn" // should be ignored
	m.filterServers()

	if len(m.filtered) != 2 {
		t.Errorf("filtered count = %d, want 2 (provider filter should be ignored in MyServers)", len(m.filtered))
	}
}

func TestFilterServers_FuzzySearch(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US-NY#1", "protonvpn", "United States", "New York"),
		makeDynamicItem("SE#2", "protonvpn", "Sweden", ""),
		makeDynamicItem("DE#3", "protonvpn", "Germany", "Berlin"),
	}

	m := populateBrowser(BrowseDynamic, cfg, items)
	m.query = "Sweden"
	m.filterServers()

	if len(m.filtered) != 1 {
		t.Fatalf("filtered count = %d, want 1", len(m.filtered))
	}
	if m.filtered[0].providerServer.ServerName != "SE#2" {
		t.Errorf("got %q, want SE#2", m.filtered[0].providerServer.ServerName)
	}
}

func TestSortServers(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US-NY#1", "protonvpn", "US", "NY"),
		makeDynamicItem("SE#2", "protonvpn", "SE", ""),
		makeDynamicItem("DE#3", "protonvpn", "DE", ""),
	}
	items[0].latency = 100 * time.Millisecond
	items[1].latency = 50 * time.Millisecond
	// items[2] has 0 latency — should go to end

	m := populateBrowser(BrowseDynamic, cfg, items)
	m.sortServers()

	if m.filtered[0].providerServer.ServerName != "SE#2" {
		t.Errorf("first = %q, want SE#2 (50ms)", m.filtered[0].providerServer.ServerName)
	}
	if m.filtered[1].providerServer.ServerName != "US-NY#1" {
		t.Errorf("second = %q, want US-NY#1 (100ms)", m.filtered[1].providerServer.ServerName)
	}
	if m.filtered[2].providerServer.ServerName != "DE#3" {
		t.Errorf("third = %q, want DE#3 (unmeasured)", m.filtered[2].providerServer.ServerName)
	}
}

func TestIsFavoriteItem_DynamicMode(t *testing.T) {
	cfg := testConfig(t)
	cfg.Favorites = []string{"dynamic:protonvpn:US-NY#42"}

	items := []browserItem{
		makeDynamicItem("US-NY#42", "protonvpn", "US", "NY"),
		makeDynamicItem("SE#2", "protonvpn", "SE", ""),
	}

	m := populateBrowser(BrowseDynamic, cfg, items)
	if !m.isFavoriteItem(m.filtered[0]) {
		t.Error("US-NY#42 should be favorite")
	}
	if m.isFavoriteItem(m.filtered[1]) {
		t.Error("SE#2 should not be favorite")
	}
}

func TestIsFavoriteItem_MyServersMode(t *testing.T) {
	cfg := testConfig(t)
	fav := makeManualItem("US-NY#1", "1.2.3.4:51820", true)
	notFav := makeManualItem("SE#2", "5.6.7.8:51820", false)

	m := populateBrowser(BrowseMyServers, cfg, []browserItem{fav, notFav})
	if !m.isFavoriteItem(m.filtered[0]) {
		t.Error("US-NY#1 should be favorite (flag=true)")
	}
	if m.isFavoriteItem(m.filtered[1]) {
		t.Error("SE#2 should not be favorite (flag=false)")
	}
}

func TestToggleFavorite_DynamicMode(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US-NY#42", "protonvpn", "US", "NY"),
	}

	m := populateBrowser(BrowseDynamic, cfg, items)

	// Toggle on
	m.toggleFavorite(0)
	found := false
	for _, f := range cfg.Favorites {
		if f == "dynamic:protonvpn:US-NY#42" {
			found = true
		}
	}
	if !found {
		t.Error("favorites should contain dynamic:protonvpn:US-NY#42 after toggle on")
	}

	// Toggle off
	m.toggleFavorite(0)
	for _, f := range cfg.Favorites {
		if f == "dynamic:protonvpn:US-NY#42" {
			t.Error("favorites should not contain dynamic:protonvpn:US-NY#42 after toggle off")
		}
	}
}

func TestToggleFavorite_MyServersManual(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeManualItem("US-NY#1", "1.2.3.4:51820", false),
	}

	m := populateBrowser(BrowseMyServers, cfg, items)

	m.toggleFavorite(0)
	if !m.servers[0].favorite {
		t.Error("servers[0].favorite should be true after toggle on")
	}
	if !m.filtered[0].favorite {
		t.Error("filtered[0].favorite should be true after toggle on")
	}
	found := false
	for _, f := range cfg.Favorites {
		if f == "US-NY#1" {
			found = true
		}
	}
	if !found {
		t.Error("cfg.Favorites should contain US-NY#1")
	}

	m.toggleFavorite(0)
	if m.servers[0].favorite {
		t.Error("servers[0].favorite should be false after toggle off")
	}
}

func TestToggleFavorite_MyServersDynamic(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeFavDynamicItem("mullvad", "SE#130"),
	}

	m := populateBrowser(BrowseMyServers, cfg, items)

	// Toggle off (starts as favorite)
	m.toggleFavorite(0)
	if m.filtered[0].favorite {
		t.Error("should be unfavorited after toggle")
	}

	// Toggle back on
	m.toggleFavorite(0)
	if !m.filtered[0].favorite {
		t.Error("should be favorited after second toggle")
	}
	found := false
	for _, f := range cfg.Favorites {
		if f == "dynamic:mullvad:SE#130" {
			found = true
		}
	}
	if !found {
		t.Error("cfg.Favorites should contain dynamic:mullvad:SE#130")
	}
}

func TestConnectCmd_Dynamic(t *testing.T) {
	cfg := testConfig(t)
	item := makeDynamicItem("US-NY#42", "protonvpn", "US", "NY")
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})

	cmd := m.connectCmd(item)
	if cmd == nil {
		t.Fatal("connectCmd returned nil")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.View != "connect-progress" {
		t.Errorf("View = %q, want connect-progress", sv.View)
	}
	if sv.Server != "US-NY#42" {
		t.Errorf("Server = %q, want US-NY#42", sv.Server)
	}
	if sv.Provider != "protonvpn" {
		t.Errorf("Provider = %q, want protonvpn", sv.Provider)
	}
	if !sv.Dynamic {
		t.Error("Dynamic should be true")
	}
}

func TestConnectCmd_Manual(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("SE-Stockholm#5", "5.6.7.8:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})

	cmd := m.connectCmd(item)
	if cmd == nil {
		t.Fatal("connectCmd returned nil")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.Server != "SE-Stockholm#5" {
		t.Errorf("Server = %q, want SE-Stockholm#5", sv.Server)
	}
	if sv.Dynamic {
		t.Error("Dynamic should be false for manual")
	}
}

func TestConnectCmd_FavDynamic(t *testing.T) {
	cfg := testConfig(t)
	item := makeFavDynamicItem("mullvad", "SE#130")
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})

	cmd := m.connectCmd(item)
	if cmd == nil {
		t.Fatal("connectCmd returned nil")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.Server != "SE#130" {
		t.Errorf("Server = %q, want SE#130", sv.Server)
	}
	if sv.Provider != "mullvad" {
		t.Errorf("Provider = %q, want mullvad", sv.Provider)
	}
	if !sv.Dynamic {
		t.Error("Dynamic should be true for favorited dynamic")
	}
}

// --- Update message handling tests ---

func TestUpdate_BrowserLoadMsg(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:     BrowseDynamic,
		cfg:      cfg,
		loading:  true,
		provider: "protonvpn",
	}

	servers := []provider.Server{
		{ServerName: "US-NY#1", Country: "United States", City: "New York", IPs: []string{"1.1.1.1"}},
		{ServerName: "SE#2", Country: "Sweden", IPs: []string{"2.2.2.2"}},
	}
	result, _ := m.Update(BrowserLoadMsg{Servers: servers})
	m = result.(*ServerBrowser)

	if m.loading {
		t.Error("should not be loading after BrowserLoadMsg")
	}
	if len(m.servers) != 2 {
		t.Errorf("servers count = %d, want 2", len(m.servers))
	}
	if len(m.filtered) != 2 {
		t.Errorf("filtered count = %d, want 2", len(m.filtered))
	}
}

func TestUpdate_BrowserLoadMsg_Error(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:    BrowseDynamic,
		cfg:     cfg,
		loading: true,
	}

	result, _ := m.Update(BrowserLoadMsg{Err: errTestLoad})
	m = result.(*ServerBrowser)

	if m.loading {
		t.Error("should not be loading")
	}
	if m.err == nil {
		t.Error("err should be set")
	}
}

var errTestLoad = &testError{"test load error"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

func TestUpdate_BrowserLoadMultiMsg(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:          BrowseDynamic,
		cfg:           cfg,
		loading:       true,
		multiProvider: true,
		providers:     []string{"protonvpn", "mullvad"},
	}

	byProv := map[string][]provider.Server{
		"protonvpn": {{ServerName: "US-NY#1", Country: "United States", IPs: []string{"1.1.1.1"}}},
		"mullvad":   {{ServerName: "SE#2", Country: "Sweden", IPs: []string{"2.2.2.2"}}},
	}
	result, _ := m.Update(BrowserLoadMultiMsg{ServersByProvider: byProv})
	m = result.(*ServerBrowser)

	if m.loading {
		t.Error("should not be loading")
	}
	if len(m.servers) != 2 {
		t.Errorf("servers count = %d, want 2", len(m.servers))
	}
}

func TestUpdate_BrowserLatencyMsg(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US-NY#1", "protonvpn", "US", "NY"),
		makeDynamicItem("SE#2", "protonvpn", "SE", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.measuringPing = true

	latencies := map[string]time.Duration{
		"US-NY#1": 100 * time.Millisecond,
		"SE#2":    50 * time.Millisecond,
	}
	result, _ := m.Update(BrowserLatencyMsg{Latencies: latencies})
	m = result.(*ServerBrowser)

	if m.measuringPing {
		t.Error("measuringPing should be false")
	}
	// Should be sorted: SE#2 (50ms) first, US-NY#1 (100ms) second
	if m.filtered[0].providerServer.ServerName != "SE#2" {
		t.Errorf("first = %q, want SE#2", m.filtered[0].providerServer.ServerName)
	}
	if m.filtered[0].latency != 50*time.Millisecond {
		t.Errorf("first latency = %v, want 50ms", m.filtered[0].latency)
	}
}

func TestUpdate_BrowserQuickConnectMsg(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US-NY#1", "protonvpn", "US", "NY"),
		makeDynamicItem("SE#2", "protonvpn", "SE", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)

	result, _ := m.Update(BrowserQuickConnectMsg{ServerName: "SE#2", Provider: "protonvpn"})
	m = result.(*ServerBrowser)

	if m.pendingConnect == nil {
		t.Fatal("pendingConnect should be set")
	}
	if m.pendingConnect.providerServer.ServerName != "SE#2" {
		t.Errorf("pending = %q, want SE#2", m.pendingConnect.providerServer.ServerName)
	}
	if m.confirmLabel != "Quickest" {
		t.Errorf("confirmLabel = %q, want Quickest", m.confirmLabel)
	}
}

// --- Key handling tests ---

func TestUpdate_Navigation(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
		makeDynamicItem("SE#2", "protonvpn", "SE", ""),
		makeDynamicItem("DE#3", "protonvpn", "DE", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)

	// Down
	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyDown}))
	m = result.(*ServerBrowser)
	if m.cursor != 1 {
		t.Errorf("cursor = %d, want 1", m.cursor)
	}

	// Down again
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyDown}))
	m = result.(*ServerBrowser)
	if m.cursor != 2 {
		t.Errorf("cursor = %d, want 2", m.cursor)
	}

	// Down at bottom (should stay)
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyDown}))
	m = result.(*ServerBrowser)
	if m.cursor != 2 {
		t.Errorf("cursor = %d, want 2 (at bottom)", m.cursor)
	}

	// Up
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyUp}))
	m = result.(*ServerBrowser)
	if m.cursor != 1 {
		t.Errorf("cursor = %d, want 1", m.cursor)
	}

	// Home
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyHome}))
	m = result.(*ServerBrowser)
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0", m.cursor)
	}

	// End
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyEnd}))
	m = result.(*ServerBrowser)
	if m.cursor != 2 {
		t.Errorf("cursor = %d, want 2", m.cursor)
	}
}

func TestUpdate_SearchQuery(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US-NY#1", "protonvpn", "United States", "New York"),
		makeDynamicItem("SE#2", "protonvpn", "Sweden", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)

	// Type 'S', 'w', 'e' to search "Swe"
	for _, ch := range "Swe" {
		result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{ch}}))
		m = result.(*ServerBrowser)
	}
	if m.query != "Swe" {
		t.Errorf("query = %q, want Swe", m.query)
	}
	if len(m.filtered) != 1 {
		t.Errorf("filtered = %d, want 1", len(m.filtered))
	}

	// Backspace
	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyBackspace}))
	m = result.(*ServerBrowser)
	if m.query != "Sw" {
		t.Errorf("query = %q, want Sw", m.query)
	}

	// Esc clears query
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyEsc}))
	m = result.(*ServerBrowser)
	if m.query != "" {
		t.Errorf("query = %q, want empty after esc", m.query)
	}
}

func TestUpdate_EscEmptyQuery_NoBack(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)

	result, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyEsc}))
	m = result.(*ServerBrowser)
	if m.cancelled {
		t.Error("esc on primary nav view should not cancel")
	}
	if cmd != nil {
		t.Error("esc on primary nav view should not produce a command")
	}
}

func TestUpdate_EnterConnect_Dynamic(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US-NY#42", "protonvpn", "US", "NY"),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)

	_, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyEnter}))
	if cmd == nil {
		t.Fatal("cmd should not be nil on enter")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.Server != "US-NY#42" || !sv.Dynamic {
		t.Errorf("SwitchViewMsg = %+v", sv)
	}
}

func TestUpdate_EnterSkipsInvalid(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeInvalidItem("bad-server", "missing private key"),
	}
	m := populateBrowser(BrowseMyServers, cfg, items)

	_, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyEnter}))
	if cmd != nil {
		t.Error("enter on invalid item should not produce a command")
	}
}

func TestUpdate_FeatureFilterToggle(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", "", "p2p"),
		makeDynamicItem("SE#2", "protonvpn", "SE", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)

	// Press '1' to toggle P2P filter
	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'1'}}))
	m = result.(*ServerBrowser)
	if !m.filterP2P {
		t.Error("filterP2P should be true")
	}
	if len(m.filtered) != 1 {
		t.Errorf("filtered = %d, want 1", len(m.filtered))
	}

	// Press '1' again to toggle off
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'1'}}))
	m = result.(*ServerBrowser)
	if m.filterP2P {
		t.Error("filterP2P should be false")
	}
	if len(m.filtered) != 2 {
		t.Errorf("filtered = %d, want 2", len(m.filtered))
	}
}

func TestUpdate_ProviderCycle(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
		makeDynamicItem("SE#2", "mullvad", "SE", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.multiProvider = true
	m.providers = []string{"protonvpn", "mullvad"}

	// Press '0' — should go to protonvpn
	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'0'}}))
	m = result.(*ServerBrowser)
	if m.providerFilter != "protonvpn" {
		t.Errorf("providerFilter = %q, want protonvpn", m.providerFilter)
	}
	if len(m.filtered) != 1 {
		t.Errorf("filtered = %d, want 1", len(m.filtered))
	}

	// Press '0' again — should go to mullvad
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'0'}}))
	m = result.(*ServerBrowser)
	if m.providerFilter != "mullvad" {
		t.Errorf("providerFilter = %q, want mullvad", m.providerFilter)
	}

	// Press '0' again — should go back to all
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'0'}}))
	m = result.(*ServerBrowser)
	if m.providerFilter != "" {
		t.Errorf("providerFilter = %q, want empty (all)", m.providerFilter)
	}
	if len(m.filtered) != 2 {
		t.Errorf("filtered = %d, want 2", len(m.filtered))
	}
}

func TestUpdate_ProviderCycle_NoopInMyServers(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeManualItem("US#1", "1.2.3.4:51820", false),
	}
	m := populateBrowser(BrowseMyServers, cfg, items)
	m.multiProvider = true
	m.providers = []string{"protonvpn", "mullvad"}

	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'0'}}))
	m = result.(*ServerBrowser)
	if m.providerFilter != "" {
		t.Errorf("providerFilter = %q, want empty (no-op in MyServers)", m.providerFilter)
	}
}

func TestUpdate_ConfirmPrompt_Accept(t *testing.T) {
	cfg := testConfig(t)
	item := makeDynamicItem("US-NY#42", "protonvpn", "US", "NY")
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})
	m.pendingConnect = &item
	m.confirmLabel = "Random"
	m.sortMessage = "Connect to US-NY#42? (y/n)"

	_, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'y'}}))
	if cmd == nil {
		t.Fatal("cmd should not be nil on confirm")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.Server != "US-NY#42" {
		t.Errorf("Server = %q, want US-NY#42", sv.Server)
	}
}

func TestUpdate_ConfirmPrompt_Cancel(t *testing.T) {
	cfg := testConfig(t)
	item := makeDynamicItem("US-NY#42", "protonvpn", "US", "NY")
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})
	m.pendingConnect = &item
	m.confirmLabel = "Random"

	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'n'}}))
	m = result.(*ServerBrowser)
	if m.pendingConnect != nil {
		t.Error("pendingConnect should be nil after cancel")
	}
	if m.confirmLabel != "" {
		t.Error("confirmLabel should be empty after cancel")
	}
}

func TestUpdate_WindowSizeMsg(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)

	result, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = result.(*ServerBrowser)
	if m.width != 120 {
		t.Errorf("width = %d, want 120", m.width)
	}
	if m.height != 40 {
		t.Errorf("height = %d, want 40", m.height)
	}
}

// --- View tests ---

func TestView_MyServersTitle(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, nil)
	v := m.View()
	if !strings.Contains(v, "My Servers") {
		t.Error("MyServers view should contain 'My Servers' title")
	}
}

func TestView_DynamicTitle(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)
	v := m.View()
	if !strings.Contains(v, "Dynamic Servers") {
		t.Error("Dynamic view should contain 'Dynamic Servers' title")
	}
}

func TestView_DynamicTitleWithProvider(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)
	m.provider = "protonvpn"
	v := m.View()
	if !strings.Contains(v, "ProtonVPN") {
		t.Error("Dynamic view with provider should show provider display name")
	}
}

func TestView_LoadingState(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{mode: BrowseDynamic, cfg: cfg, loading: true}
	v := m.View()
	if !strings.Contains(v, "Loading servers") {
		t.Error("loading view should show 'Loading servers'")
	}
}

func TestView_ErrorState(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{mode: BrowseDynamic, cfg: cfg, err: errTestLoad}
	v := m.View()
	if !strings.Contains(v, "Error") {
		t.Error("error view should show error")
	}
}

func TestView_EmptyMyServers(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, nil)
	v := m.View()
	if !strings.Contains(v, "No servers configured") {
		t.Error("empty MyServers should show 'No servers configured'")
	}
}

func TestView_EmptyDynamic(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)
	v := m.View()
	if !strings.Contains(v, "No servers in cache") {
		t.Error("empty Dynamic should show 'No servers in cache'")
	}
}

func TestView_InvalidServerShown(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeInvalidItem("broken", "missing key"),
	}
	m := populateBrowser(BrowseMyServers, cfg, items)
	v := m.View()
	if !strings.Contains(v, "INVALID") {
		t.Error("view should show INVALID for bad config")
	}
	if !strings.Contains(v, "missing key") {
		t.Error("view should show the parse error message")
	}
}

func TestView_FilterBarShowsServerCount(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
		makeDynamicItem("SE#2", "protonvpn", "SE", ""),
		makeDynamicItem("DE#3", "protonvpn", "DE", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	v := m.View()
	if !strings.Contains(v, "3 servers") {
		t.Error("filter bar should show '3 servers'")
	}
}

func TestView_SortMessage(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)
	m.sortMessage = "Sorted by Latency"
	v := m.View()
	if !strings.Contains(v, "Sorted by Latency") {
		t.Error("view should show sort message")
	}
}

func TestView_SearchQueryShown(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)
	m.query = "test"
	v := m.View()
	if !strings.Contains(v, "Search:") || !strings.Contains(v, "test") {
		t.Error("view should show search query")
	}
}

func TestView_CursorHighlight(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
		makeDynamicItem("SE#2", "protonvpn", "SE", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.cursor = 0
	m.focused = true
	v := m.View()
	if !strings.Contains(v, ">") {
		t.Error("view should contain cursor indicator '>'")
	}
}

func TestView_LatencyShown(t *testing.T) {
	cfg := testConfig(t)
	item := makeDynamicItem("US#1", "protonvpn", "US", "")
	item.latency = 42 * time.Millisecond
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})
	v := m.View()
	if !strings.Contains(v, "42ms") {
		t.Error("view should show latency '42ms'")
	}
}

func TestView_PreviewPanel(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US-NY#1", "protonvpn", "United States", "New York"),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	v := m.View()
	if !strings.Contains(v, "Country: United States") {
		t.Error("preview should show country")
	}
	if !strings.Contains(v, "City: New York") {
		t.Error("preview should show city")
	}
}

func TestView_HelpLine(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)
	v := m.View()
	if !strings.Contains(v, "enter: connect") {
		t.Error("view should contain help text")
	}
}

// --- buildDynamicItems tests ---

func TestBuildDynamicItems(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{mode: BrowseDynamic, cfg: cfg, multiProvider: true}

	servers := []provider.Server{
		{ServerName: "US-NY#1", Country: "United States", City: "New York", IPs: []string{"1.1.1.1"}, PortForward: true},
		{ServerName: "SE#2", Country: "Sweden", IPs: []string{"2.2.2.2"}, Free: true},
	}

	items := m.buildDynamicItems(servers, "protonvpn")
	if len(items) != 2 {
		t.Fatalf("items count = %d, want 2", len(items))
	}

	if items[0].providerServer == nil {
		t.Fatal("providerServer should not be nil")
	}
	if items[0].providerServer.ServerName != "US-NY#1" {
		t.Errorf("server name = %q, want US-NY#1", items[0].providerServer.ServerName)
	}
	if items[0].providerName != "protonvpn" {
		t.Errorf("provider = %q, want protonvpn", items[0].providerName)
	}
	if !items[0].portForward {
		t.Error("US-NY#1 should have portForward=true")
	}
	if !items[1].free {
		t.Error("SE#2 should have free=true")
	}
	// Multi-provider should append provider suffix
	if !strings.Contains(items[0].display, "ProtonVPN") {
		t.Error("display should contain provider name in multi-provider mode")
	}
}

func TestBuildDynamicItems_SingleProvider(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{mode: BrowseDynamic, cfg: cfg, multiProvider: false}

	servers := []provider.Server{
		{ServerName: "US-NY#1", Country: "United States"},
	}

	items := m.buildDynamicItems(servers, "protonvpn")
	// Single-provider mode should NOT append provider suffix
	if strings.Contains(items[0].display, "ProtonVPN") {
		t.Error("display should not contain provider name in single-provider mode")
	}
}

// --- Additional Update key handling tests ---

func TestUpdate_PgUpPgDown(t *testing.T) {
	cfg := testConfig(t)
	items := make([]browserItem, 30)
	for i := range items {
		items[i] = makeDynamicItem(fmt.Sprintf("SRV#%d", i), "protonvpn", "US", "")
	}
	m := populateBrowser(BrowseDynamic, cfg, items)

	// PgDown from 0
	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyPgDown}))
	m = result.(*ServerBrowser)
	if m.cursor != 10 {
		t.Errorf("cursor = %d, want 10 after pgdown", m.cursor)
	}

	// PgDown again
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyPgDown}))
	m = result.(*ServerBrowser)
	if m.cursor != 20 {
		t.Errorf("cursor = %d, want 20 after second pgdown", m.cursor)
	}

	// PgDown clamps to last
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyPgDown}))
	m = result.(*ServerBrowser)
	if m.cursor != 29 {
		t.Errorf("cursor = %d, want 29 (clamped)", m.cursor)
	}

	// PgUp
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyPgUp}))
	m = result.(*ServerBrowser)
	if m.cursor != 19 {
		t.Errorf("cursor = %d, want 19 after pgup", m.cursor)
	}

	// PgUp clamps to 0
	m.cursor = 3
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyPgUp}))
	m = result.(*ServerBrowser)
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0 (clamped)", m.cursor)
	}
}

func TestUpdate_PgDownEmptyList(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)

	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyPgDown}))
	m = result.(*ServerBrowser)
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0 on empty list", m.cursor)
	}
}

func TestUpdate_FeatureFilter_AllKeys(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", "", "tor"),
		makeDynamicItem("SE#2", "protonvpn", "SE", "", "securecore"),
		makeDynamicItem("DE#3", "protonvpn", "DE", "", "streaming"),
		makeDynamicItem("FR#4", "protonvpn", "FR", "", "free"),
		makeDynamicItem("CH#5", "protonvpn", "CH", ""),
	}

	// Test key '2' (Tor filter)
	m := populateBrowser(BrowseDynamic, cfg, items)
	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'2'}}))
	m = result.(*ServerBrowser)
	if !m.filterTor {
		t.Error("key 2 should toggle tor filter")
	}
	if len(m.filtered) != 1 {
		t.Errorf("tor filter: filtered = %d, want 1", len(m.filtered))
	}

	// Test key '3' (SecureCore filter)
	m = populateBrowser(BrowseDynamic, cfg, items)
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'3'}}))
	m = result.(*ServerBrowser)
	if !m.filterSecureCore {
		t.Error("key 3 should toggle secure core filter")
	}
	if len(m.filtered) != 1 {
		t.Errorf("securecore filter: filtered = %d, want 1", len(m.filtered))
	}

	// Test key '4' (Stream filter)
	m = populateBrowser(BrowseDynamic, cfg, items)
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'4'}}))
	m = result.(*ServerBrowser)
	if !m.filterStream {
		t.Error("key 4 should toggle stream filter")
	}
	if len(m.filtered) != 1 {
		t.Errorf("stream filter: filtered = %d, want 1", len(m.filtered))
	}

	// Test key '5' (Free filter)
	m = populateBrowser(BrowseDynamic, cfg, items)
	result, _ = m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'5'}}))
	m = result.(*ServerBrowser)
	if !m.filterFree {
		t.Error("key 5 should toggle free filter")
	}
	if len(m.filtered) != 1 {
		t.Errorf("free filter: filtered = %d, want 1", len(m.filtered))
	}
}

func TestUpdate_RandomServer(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
		makeDynamicItem("SE#2", "protonvpn", "SE", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)

	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'6'}}))
	m = result.(*ServerBrowser)
	if m.pendingConnect == nil {
		t.Fatal("key 6 should set pendingConnect for random server")
	}
	if m.confirmLabel != "Random" {
		t.Errorf("confirmLabel = %q, want Random", m.confirmLabel)
	}
	if !strings.Contains(m.sortMessage, "(y/n)") {
		t.Errorf("sortMessage = %q, should contain (y/n)", m.sortMessage)
	}
}

func TestUpdate_RandomServerSkipsInvalid(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeInvalidItem("bad1", "error1"),
		makeDynamicItem("US#1", "protonvpn", "US", ""),
	}
	m := populateBrowser(BrowseMyServers, cfg, items)

	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'6'}}))
	m = result.(*ServerBrowser)
	if m.pendingConnect == nil {
		t.Fatal("should find a valid server to connect to")
	}
	// The pendingConnect should not be the invalid one
	if m.pendingConnect.invalid {
		t.Error("pendingConnect should not be invalid")
	}
}

func TestUpdate_RandomServerEmptyList(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)

	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'6'}}))
	m = result.(*ServerBrowser)
	if m.pendingConnect != nil {
		t.Error("should not set pendingConnect on empty list")
	}
}

func TestUpdate_QuickestServerWithLatency(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
		makeDynamicItem("SE#2", "protonvpn", "SE", ""),
	}
	items[0].latency = 100 * time.Millisecond
	items[1].latency = 50 * time.Millisecond
	m := populateBrowser(BrowseDynamic, cfg, items)

	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'7'}}))
	m = result.(*ServerBrowser)
	if m.pendingConnect == nil {
		t.Fatal("key 7 should set pendingConnect for quickest server")
	}
	if m.pendingConnect.providerServer.ServerName != "SE#2" {
		t.Errorf("quickest should be SE#2 (50ms), got %q", m.pendingConnect.providerServer.ServerName)
	}
	if m.confirmLabel != "Quickest" {
		t.Errorf("confirmLabel = %q, want Quickest", m.confirmLabel)
	}
}

func TestUpdate_QuickestServerNoLatency(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)

	result, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'7'}}))
	m = result.(*ServerBrowser)
	// No latency data - should trigger measureLatencyThenConnect
	if m.sortMessage == "" {
		t.Error("should set sort message about measuring latency")
	}
	if cmd == nil {
		t.Error("should return cmd to measure latency")
	}
}

func TestUpdate_MeasureLatency(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)

	result, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'8'}}))
	m = result.(*ServerBrowser)
	if !m.measuringPing {
		t.Error("key 8 should set measuringPing")
	}
	if m.sortMessage == "" {
		t.Error("should set sort message")
	}
	if cmd == nil {
		t.Error("should return cmd")
	}
}

func TestUpdate_MeasureLatencyAlreadyMeasuring(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.measuringPing = true

	_, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'8'}}))
	if cmd != nil {
		t.Error("should not start new measurement while already measuring")
	}
}

func TestUpdate_MeasureLatencyEmptyList(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)

	result, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'8'}}))
	m = result.(*ServerBrowser)
	if m.measuringPing {
		t.Error("should not measure with empty list")
	}
	if cmd != nil {
		t.Error("should not return cmd with empty list")
	}
}

func TestUpdate_ToggleFavoriteViaKey(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)

	m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'9'}}))

	// Should have added to favorites
	found := false
	for _, f := range cfg.Favorites {
		if f == "dynamic:protonvpn:US#1" {
			found = true
		}
	}
	if !found {
		t.Error("key 9 should toggle favorite for current item")
	}
}

// TestUpdate_ToggleFavoriteRevertsOnSaveFailure verifies that when
// cfg.Save fails, the in-memory Favorites slice is reverted to the
// pre-toggle value. cfg.Save is atomic; without revert, in-memory
// would say "added" while disk and the daemon's view stay unchanged.
//
// Force Save failure by pointing ConfigDir at a regular file
// (CreateTemp inside Save then errors).
func TestUpdate_ToggleFavoriteRevertsOnSaveFailure(t *testing.T) {
	cfg := testConfig(t)
	// Pre-populate one favorite so the snapshot has a non-trivial value.
	cfg.Favorites = []string{"existing-fav"}

	// Make Save fail by aiming ConfigDir at a regular file.
	dummyFile := cfg.ConfigDir + "/not-a-dir"
	if err := os.WriteFile(dummyFile, []byte("x"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg.ConfigDir = dummyFile

	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)

	m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'9'}}))

	if len(cfg.Favorites) != 1 || cfg.Favorites[0] != "existing-fav" {
		t.Errorf("Favorites = %v, want [existing-fav] (reverted to previous on Save failure)",
			cfg.Favorites)
	}
}

func TestUpdate_ToggleFavoriteSkipsInvalid(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeInvalidItem("bad", "error"),
	}
	m := populateBrowser(BrowseMyServers, cfg, items)

	m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'9'}}))
	if len(cfg.Favorites) != 0 {
		t.Error("should not toggle favorite for invalid item")
	}
}

func TestUpdate_EscDuringLoading(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{mode: BrowseDynamic, cfg: cfg, loading: true}

	result, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyEsc}))
	m = result.(*ServerBrowser)
	if !m.cancelled {
		t.Error("esc during loading should cancel")
	}
	if cmd == nil {
		t.Fatal("should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestUpdate_OtherKeyDuringLoading(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{mode: BrowseDynamic, cfg: cfg, loading: true}

	result, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyDown}))
	m = result.(*ServerBrowser)
	if m.cancelled {
		t.Error("non-esc key during loading should not cancel")
	}
	if cmd != nil {
		t.Error("should return nil cmd during loading for non-esc")
	}
}

func TestUpdate_EscDuringError(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{mode: BrowseDynamic, cfg: cfg, err: errTestLoad}

	result, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyEsc}))
	m = result.(*ServerBrowser)
	if !m.cancelled {
		t.Error("esc during error should cancel")
	}
	if cmd == nil {
		t.Fatal("should return cmd")
	}
}

func TestUpdate_ConfirmPromptEnter(t *testing.T) {
	cfg := testConfig(t)
	item := makeDynamicItem("US#42", "protonvpn", "US", "NY")
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})
	m.pendingConnect = &item
	m.confirmLabel = "Random"

	_, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyEnter}))
	if cmd == nil {
		t.Fatal("enter in confirm should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(SwitchViewMsg); !ok {
		t.Errorf("expected SwitchViewMsg, got %T", msg)
	}
}

func TestUpdate_BackspaceEmptyQuery(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)
	m.query = ""

	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyBackspace}))
	m = result.(*ServerBrowser)
	if m.query != "" {
		t.Error("backspace on empty query should stay empty")
	}
}

func TestUpdate_BrowserLoadMultiMsg_Error(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{mode: BrowseDynamic, cfg: cfg, loading: true}

	result, _ := m.Update(BrowserLoadMultiMsg{Err: errTestLoad})
	m = result.(*ServerBrowser)
	if m.loading {
		t.Error("should not be loading")
	}
	if m.err == nil {
		t.Error("err should be set")
	}
}

// --- Additional View tests ---

func TestView_FavoriteStarShown(t *testing.T) {
	cfg := testConfig(t)
	cfg.Favorites = []string{"dynamic:protonvpn:US#1"}
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	v := m.View()
	if !strings.Contains(v, "★") {
		t.Error("view should show favorite star")
	}
}

func TestView_NoMatchesMessage(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.query = "zzzznonexistent"
	m.filterServers()
	v := m.View()
	if !strings.Contains(v, "No matches found") {
		t.Error("should show 'No matches found' when query returns empty")
	}
}

func TestView_ScrollIndicator(t *testing.T) {
	cfg := testConfig(t)
	items := make([]browserItem, 50)
	for i := range items {
		items[i] = makeDynamicItem(fmt.Sprintf("SRV#%d", i), "protonvpn", "US", "")
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.height = 20
	m.cursor = 15
	v := m.View()
	if !strings.Contains(v, "/50") {
		t.Error("should show scroll indicator with total count")
	}
}

func TestView_ProviderFilterShown(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.multiProvider = true
	m.providerFilter = "protonvpn"
	v := m.View()
	if !strings.Contains(v, "ProtonVPN") {
		t.Error("should show active provider filter in filter bar")
	}
}

func TestView_FeatureFiltersHighlighted(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", "", "p2p"),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.filterP2P = true
	v := m.View()
	if !strings.Contains(v, "P2P") {
		t.Error("should show P2P filter in view")
	}
}

func TestView_TruncatedByHeight(t *testing.T) {
	cfg := testConfig(t)
	items := make([]browserItem, 100)
	for i := range items {
		items[i] = makeDynamicItem(fmt.Sprintf("SRV#%d", i), "protonvpn", "US", "")
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.height = 15
	v := m.View()
	lines := strings.Split(v, "\n")
	if len(lines) > 15 {
		t.Errorf("view should be truncated to height, got %d lines", len(lines))
	}
}

// --- buildPreview tests ---

func TestBuildPreview_ManualServer(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("Proton-US-NY-p2p#42", "1.2.3.4:51820", false, "p2p")
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})

	parts := m.buildPreview(item)
	if len(parts) == 0 {
		t.Fatal("buildPreview should return parts for manual server")
	}

	// Should contain endpoint
	foundEndpoint := false
	for _, p := range parts {
		if strings.Contains(p, "Endpoint:") {
			foundEndpoint = true
		}
	}
	if !foundEndpoint {
		t.Error("should contain endpoint in preview")
	}
}

func TestBuildPreview_DynamicServer(t *testing.T) {
	cfg := testConfig(t)
	item := makeDynamicItem("US-NY#42", "protonvpn", "United States", "New York", "p2p", "streaming")
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})

	parts := m.buildPreview(item)
	foundCountry := false
	foundCity := false
	foundFeatures := false
	for _, p := range parts {
		if strings.Contains(p, "United States") {
			foundCountry = true
		}
		if strings.Contains(p, "New York") {
			foundCity = true
		}
		if strings.Contains(p, "Features:") {
			foundFeatures = true
		}
	}
	if !foundCountry {
		t.Error("should contain country")
	}
	if !foundCity {
		t.Error("should contain city")
	}
	if !foundFeatures {
		t.Error("should contain features")
	}
}

func TestBuildPreview_WithLatencyAndFavorite(t *testing.T) {
	cfg := testConfig(t)
	cfg.Favorites = []string{"dynamic:protonvpn:US#1"}
	item := makeDynamicItem("US#1", "protonvpn", "US", "")
	item.latency = 42 * time.Millisecond
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})

	parts := m.buildPreview(item)
	foundLatency := false
	foundFav := false
	for _, p := range parts {
		if strings.Contains(p, "42ms") {
			foundLatency = true
		}
		if strings.Contains(p, "Favorite") {
			foundFav = true
		}
	}
	if !foundLatency {
		t.Error("should contain latency")
	}
	if !foundFav {
		t.Error("should contain favorite indicator")
	}
}

func TestBuildPreview_FavDynamic(t *testing.T) {
	cfg := testConfig(t)
	item := makeFavDynamicItem("protonvpn", "US-NY#42")
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})

	parts := m.buildPreview(item)
	// Should have provider info
	foundProvider := false
	for _, p := range parts {
		if strings.Contains(p, "Provider:") && strings.Contains(p, "dynamic") {
			foundProvider = true
		}
	}
	if !foundProvider {
		t.Error("should contain provider info for fav dynamic")
	}
}

// --- Format helpers ---

func TestFormatProviderServer_SecureCore(t *testing.T) {
	srv := provider.Server{
		ServerName: "CH-SE#1",
		Country:    "Sweden",
		SecureCore: true,
	}
	got := formatProviderServer(srv)
	if !strings.Contains(got, "→") {
		t.Error("secure core should contain arrow")
	}
	if !strings.Contains(got, "🔒") {
		t.Error("secure core should have lock icon")
	}
}

func TestFormatDynamicDisplay_UnknownProvider(t *testing.T) {
	srv := provider.Server{ServerName: "US#1", Country: "US"}
	got := formatDynamicDisplay(srv, "unknownprov")
	if !strings.Contains(got, "unknownprov") {
		t.Error("unknown provider should show raw name")
	}
}

func TestServerCountry(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)

	t.Run("provider server", func(t *testing.T) {
		item := makeDynamicItem("US#1", "protonvpn", "United States", "")
		got := m.serverCountry(item)
		if got != "United States" {
			t.Errorf("serverCountry = %q, want 'United States'", got)
		}
	})

	t.Run("non-provider", func(t *testing.T) {
		item := makeManualItem("US#1", "1.2.3.4:51820", false)
		got := m.serverCountry(item)
		if got != "" {
			t.Errorf("serverCountry = %q, want empty for manual", got)
		}
	})
}

func TestConnectCmd_NilItem(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)

	// Item with no server data should return nil
	item := browserItem{display: "empty"}
	cmd := m.connectCmd(item)
	if cmd != nil {
		t.Error("connectCmd should return nil for empty item")
	}
}

func TestToggleFavorite_OutOfBounds(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseDynamic, cfg, nil)

	// Should not panic
	m.toggleFavorite(999)
}

func TestToggleFavorite_DynamicNilProvider(t *testing.T) {
	cfg := testConfig(t)
	item := browserItem{display: "no-provider"}
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})

	// Should not panic - item has no providerServer
	m.toggleFavorite(0)
}

func TestFilterServers_SecureCoreFilter(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("CH-SE#1", "protonvpn", "SE", "", "securecore"),
		makeDynamicItem("US#2", "protonvpn", "US", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.filterSecureCore = true
	m.filterServers()
	if len(m.filtered) != 1 {
		t.Errorf("filtered = %d, want 1 for securecore filter", len(m.filtered))
	}
}

func TestFilterServers_CursorResetOnFilter(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
		makeDynamicItem("SE#2", "protonvpn", "SE", "", "p2p"),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.cursor = 1

	// Filter to only P2P, which has 1 item - cursor should reset
	m.filterP2P = true
	m.filterServers()
	if m.cursor >= len(m.filtered) {
		t.Error("cursor should be reset when it exceeds filtered list")
	}
}

func TestView_MyServersEmptyWithProviders(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, nil)
	m.hasProviders = true
	m.providerCount = 2
	v := m.View()
	if !strings.Contains(v, "No servers configured") {
		t.Error("should show empty message even with providers")
	}
}

func TestInitMyServers(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, nil)
	cmd := m.Init()
	if cmd != nil {
		t.Error("MyServers Init should return nil (no async load)")
	}
}

func TestInitDynamic(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{mode: BrowseDynamic, cfg: cfg, loading: true, provider: "protonvpn"}
	cmd := m.Init()
	if cmd == nil {
		t.Error("Dynamic Init should return cmd to load servers")
	}
}

func TestSortServers_AllZeroLatency(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("ZZ#1", "protonvpn", "ZZ", ""),
		makeDynamicItem("AA#2", "protonvpn", "AA", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.sortServers()
	// Both 0 latency - should sort alphabetically by display
	if m.filtered[0].providerServer.ServerName != "AA#2" {
		t.Errorf("first should be AA#2 (alphabetical), got %q", m.filtered[0].providerServer.ServerName)
	}
}

func TestUpdate_ProviderCycleNotFound(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeDynamicItem("US#1", "protonvpn", "US", ""),
	}
	m := populateBrowser(BrowseDynamic, cfg, items)
	m.multiProvider = true
	m.providers = []string{"protonvpn", "mullvad"}
	m.providerFilter = "nonexistent"

	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'0'}}))
	m = result.(*ServerBrowser)
	if m.providerFilter != "" {
		t.Errorf("providerFilter should reset to empty when current not found, got %q", m.providerFilter)
	}
}

// --- loadMyServers tests ---

func TestNewMyServersBrowser(t *testing.T) {
	dir := t.TempDir()
	wgDir := filepath.Join(dir, "wireguard")
	os.MkdirAll(wgDir, 0700)

	confContent := "[Interface]\nPrivateKey = aGVsbG8gd29ybGQ=\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\n\n[Peer]\nPublicKey = aGVsbG8gd29ybGQ=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
	os.WriteFile(filepath.Join(wgDir, "US-NY#1.conf"), []byte(confContent), 0600)
	os.WriteFile(filepath.Join(wgDir, "SE#5.conf"), []byte(confContent), 0600)

	cfg := &config.Config{ConfigDir: dir, Favorites: []string{}}

	// Mock configLoad so loadMyServers doesn't read the real user config
	orig := configLoad
	configLoad = func() (*config.Config, error) { return cfg, nil }
	t.Cleanup(func() { configLoad = orig })

	m := NewMyServersBrowser(cfg)

	if m.mode != BrowseMyServers {
		t.Errorf("mode = %d, want BrowseMyServers", m.mode)
	}
	if len(m.servers) != 2 {
		t.Errorf("servers = %d, want exactly 2", len(m.servers))
	}
}

func TestMyServersBrowserWithFavoritedDynamic(t *testing.T) {
	// Test that the MyServers browser correctly displays favorited dynamic servers.
	// We bypass NewMyServersBrowser (which calls config.Load from the global path)
	// and directly construct the browser with the expected items.
	cfg := testConfig(t)
	cfg.Favorites = []string{"manual", "dynamic:protonvpn:US-NY#42"}

	manualItem := makeManualItem("manual", "1.2.3.4:51820", true)
	dynamicItem := browserItem{
		favorite:        true,
		isDynamic:       true,
		dynamicProvider: "protonvpn",
		dynamicName:     "US-NY#42",
		portForward:     true,
		display:         "US-NY#42 • ProtonVPN",
	}
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{dynamicItem, manualItem})

	foundManual := false
	foundDynamic := false
	for _, srv := range m.servers {
		if srv.manualServer != nil && srv.manualServer.Config.Name == "manual" {
			foundManual = true
		}
		if srv.isDynamic && srv.dynamicProvider == "protonvpn" && srv.dynamicName == "US-NY#42" {
			foundDynamic = true
			if !srv.favorite {
				t.Error("favorited dynamic server should have favorite=true")
			}
			if !srv.portForward {
				t.Error("favorited dynamic server should have portForward from cache")
			}
		}
	}
	if !foundManual {
		t.Error("should contain manual server")
	}
	if !foundDynamic {
		t.Error("should contain favorited dynamic server")
	}
}

func TestMyServersBrowserFavDynamicCacheMiss(t *testing.T) {
	// Test favorited dynamic server with a fallback display (no cache data).
	// We bypass NewMyServersBrowser (which calls config.Load from the global path)
	// and construct the item the same way loadMyServers would for a cache miss.
	cfg := testConfig(t)
	cfg.Favorites = []string{"dynamic:protonvpn:US-NY#99"}

	// Simulate the fallback display that loadMyServers produces when cache is missing
	dynamicItem := browserItem{
		favorite:        true,
		isDynamic:       true,
		dynamicProvider: "protonvpn",
		dynamicName:     "US-NY#99",
		display:         "US-NY#99 • protonvpn", // fallback display
	}
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{dynamicItem})

	foundDynamic := false
	for _, srv := range m.servers {
		if srv.isDynamic && srv.dynamicName == "US-NY#99" {
			foundDynamic = true
			if srv.display == "" {
				t.Error("should have fallback display")
			}
		}
	}
	if !foundDynamic {
		t.Error("should contain favorited dynamic server even without cache")
	}
}

func TestNewMyServersBrowserEmptyDir(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{ConfigDir: dir, Favorites: []string{}}

	// Mock configLoad so loadMyServers doesn't read the real user config
	orig := configLoad
	configLoad = func() (*config.Config, error) { return cfg, nil }
	t.Cleanup(func() { configLoad = orig })

	m := NewMyServersBrowser(cfg)

	if len(m.servers) != 0 {
		t.Errorf("servers = %d, want 0 for empty dir", len(m.servers))
	}
}

func TestNewMyServersBrowserWithInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	wgDir := filepath.Join(dir, "wireguard")
	os.MkdirAll(wgDir, 0700)

	// Write an invalid WireGuard config (missing required fields)
	os.WriteFile(filepath.Join(wgDir, "bad.conf"), []byte("[Interface]\n# no private key\n"), 0600)

	cfg := &config.Config{ConfigDir: dir, Favorites: []string{}}

	// Mock configLoad so loadMyServers doesn't read the real user config
	orig := configLoad
	configLoad = func() (*config.Config, error) { return cfg, nil }
	t.Cleanup(func() { configLoad = orig })

	m := NewMyServersBrowser(cfg)

	if len(m.servers) != 1 {
		t.Fatalf("servers = %d, want 1", len(m.servers))
	}
	if !m.servers[0].invalid {
		t.Error("should mark server as invalid")
	}
	if m.servers[0].errorMsg == "" {
		t.Error("should have error message for invalid config")
	}
}

// --- loadDynamicServers tests ---

func TestLoadDynamicServersSingleProvider(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	os.MkdirAll(cacheDir, 0700)

	servers := []provider.Server{
		{ServerName: "US-NY#1", Country: "US", IPs: []string{"1.1.1.1"}},
		{ServerName: "SE#2", Country: "SE", IPs: []string{"2.2.2.2"}},
	}
	data, _ := json.Marshal(servers)
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), data, 0600)

	cfg := &config.Config{ConfigDir: dir}
	m := &ServerBrowser{
		mode:     BrowseDynamic,
		cfg:      cfg,
		provider: "protonvpn",
		loading:  true,
	}

	cmd := m.loadDynamicServers()
	if cmd == nil {
		t.Fatal("loadDynamicServers should return cmd")
	}
	msg := cmd()
	loadMsg, ok := msg.(BrowserLoadMsg)
	if !ok {
		t.Fatalf("expected BrowserLoadMsg, got %T", msg)
	}
	if loadMsg.Err != nil {
		t.Errorf("unexpected error: %v", loadMsg.Err)
	}
	if len(loadMsg.Servers) != 2 {
		t.Errorf("servers = %d, want 2", len(loadMsg.Servers))
	}
}

func TestLoadDynamicServersMultiProvider(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	os.MkdirAll(cacheDir, 0700)

	// Create cache for two providers
	for _, prov := range []string{"protonvpn", "mullvad"} {
		servers := []provider.Server{
			{ServerName: prov + "#1", Country: "US", IPs: []string{"1.1.1.1"}},
		}
		data, _ := json.Marshal(servers)
		os.WriteFile(filepath.Join(cacheDir, prov+"_servers.json"), data, 0600)
	}

	cfg := &config.Config{ConfigDir: dir}
	m := &ServerBrowser{
		mode:      BrowseDynamic,
		cfg:       cfg,
		provider:  "",
		loading:   true,
		providers: []string{"protonvpn", "mullvad"},
	}

	cmd := m.loadDynamicServers()
	if cmd == nil {
		t.Fatal("loadDynamicServers should return cmd")
	}
	msg := cmd()
	loadMsg, ok := msg.(BrowserLoadMultiMsg)
	if !ok {
		t.Fatalf("expected BrowserLoadMultiMsg, got %T", msg)
	}
	if loadMsg.Err != nil {
		t.Errorf("unexpected error: %v", loadMsg.Err)
	}
	if len(loadMsg.ServersByProvider) != 2 {
		t.Errorf("providers = %d, want 2", len(loadMsg.ServersByProvider))
	}
}

func TestLoadDynamicServersMultiProviderNoCache(t *testing.T) {
	dir := t.TempDir()
	// No cache files at all

	cfg := &config.Config{ConfigDir: dir}
	m := &ServerBrowser{
		mode:      BrowseDynamic,
		cfg:       cfg,
		provider:  "",
		loading:   true,
		providers: []string{"protonvpn", "mullvad"},
	}

	cmd := m.loadDynamicServers()
	msg := cmd()
	loadMsg, ok := msg.(BrowserLoadMultiMsg)
	if !ok {
		t.Fatalf("expected BrowserLoadMultiMsg, got %T", msg)
	}
	if loadMsg.Err == nil {
		t.Error("should return error when no cached servers found")
	}
}

// --- NewDynamicServerBrowser tests ---

func TestNewDynamicServerBrowserSingleProvider(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{ConfigDir: dir}

	m := NewDynamicServerBrowser(cfg, "protonvpn")
	if m.mode != BrowseDynamic {
		t.Errorf("mode = %d, want BrowseDynamic", m.mode)
	}
	if m.provider != "protonvpn" {
		t.Errorf("provider = %q, want protonvpn", m.provider)
	}
	if !m.loading {
		t.Error("should be loading")
	}
}

func TestNewDynamicServerBrowserEmptyProvider(t *testing.T) {
	dir := t.TempDir()
	provDir := filepath.Join(dir, "providers")
	os.MkdirAll(provDir, 0700)

	// Create two providers
	os.WriteFile(filepath.Join(provDir, "protonvpn.json"), []byte(`{"private_key":"test","address":"10.2.0.2/32"}`), 0600)
	os.WriteFile(filepath.Join(provDir, "mullvad.json"), []byte(`{"private_key":"test","address":"10.2.0.2/32"}`), 0600)

	cfg := &config.Config{ConfigDir: dir}
	m := NewDynamicServerBrowser(cfg, "")

	if m.provider != "" {
		t.Errorf("provider should be empty, got %q", m.provider)
	}
	if len(m.providers) != 2 {
		t.Errorf("providers = %d, want 2", len(m.providers))
	}
	if !m.multiProvider {
		t.Error("should be multiProvider when more than 1 provider")
	}
}

func TestNewDynamicServerBrowserEmptyProviderOneProvider(t *testing.T) {
	dir := t.TempDir()
	provDir := filepath.Join(dir, "providers")
	os.MkdirAll(provDir, 0700)

	os.WriteFile(filepath.Join(provDir, "protonvpn.json"), []byte(`{"private_key":"test","address":"10.2.0.2/32"}`), 0600)

	cfg := &config.Config{ConfigDir: dir}
	m := NewDynamicServerBrowser(cfg, "")

	if len(m.providers) != 1 {
		t.Errorf("providers = %d, want 1", len(m.providers))
	}
	if m.multiProvider {
		t.Error("should not be multiProvider with only 1 provider")
	}
}

// --- buildPreview for favorited dynamic with cache ---

func TestBuildPreview_FavDynamicWithCache(t *testing.T) {
	cfg := testConfig(t)

	// Create cache file so buildPreview can load server data
	cacheDir := filepath.Join(cfg.ConfigDir, "cache")
	os.MkdirAll(cacheDir, 0700)
	servers := []provider.Server{
		{ServerName: "US-NY#42", Country: "United States", City: "New York", IPs: []string{"1.1.1.1"}, PortForward: true},
	}
	data, _ := json.Marshal(servers)
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), data, 0600)

	item := browserItem{
		isDynamic:       true,
		dynamicProvider: "protonvpn",
		dynamicName:     "US-NY#42",
		favorite:        true,
		portForward:     true,
		display:         "US-NY#42 • ProtonVPN",
	}
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})

	parts := m.buildPreview(item)
	foundProvider := false
	foundFeatures := false
	for _, p := range parts {
		if strings.Contains(p, "Provider:") {
			foundProvider = true
		}
		if strings.Contains(p, "Features:") {
			foundFeatures = true
		}
	}
	if !foundProvider {
		t.Error("should contain provider info")
	}
	if !foundFeatures {
		t.Error("should contain features for fav dynamic with portForward")
	}
}

func TestBuildPreview_ManualServerWithServices(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("Proton-US-NY-tor-streaming#10", "1.2.3.4:51820", true, "tor", "streaming")
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})

	parts := m.buildPreview(item)
	foundFav := false
	foundFeatures := false
	for _, p := range parts {
		if strings.Contains(p, "Favorite") {
			foundFav = true
		}
		if strings.Contains(p, "Features:") {
			foundFeatures = true
		}
	}
	if !foundFav {
		t.Error("should show favorite indicator for favorited manual server")
	}
	if !foundFeatures {
		t.Error("should show features for manual server with services")
	}
}

// --- BrowseDynamic View tests ---

func TestServerBrowserViewDynamicLoading(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:    BrowseDynamic,
		cfg:     cfg,
		loading: true,
	}
	view := m.View()
	if !strings.Contains(view, "Dynamic Servers") {
		t.Error("should show Dynamic Servers title")
	}
	if !strings.Contains(view, "Loading servers...") {
		t.Error("should show loading message")
	}
}

func TestServerBrowserViewDynamicLoadingWithProvider(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:     BrowseDynamic,
		cfg:      cfg,
		provider: "protonvpn",
		loading:  true,
	}
	view := m.View()
	if !strings.Contains(view, "ProtonVPN") {
		t.Error("should show provider name in title")
	}
}

func TestServerBrowserViewDynamicError(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode: BrowseDynamic,
		cfg:  cfg,
		err:  errForTest("no cached servers"),
	}
	view := m.View()
	if !strings.Contains(view, "no cached servers") {
		t.Error("should show error message")
	}
	if !strings.Contains(view, "Press esc to go back") {
		t.Error("should show esc hint")
	}
}

func TestServerBrowserViewDynamicEmpty(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:    BrowseDynamic,
		cfg:     cfg,
		servers: []browserItem{},
	}
	view := m.View()
	if !strings.Contains(view, "No servers in cache") {
		t.Error("should show empty cache message for dynamic mode")
	}
}

func TestServerBrowserViewMyServersEmpty(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:    BrowseMyServers,
		cfg:     cfg,
		servers: []browserItem{},
	}
	view := m.View()
	if !strings.Contains(view, "No servers configured") {
		t.Error("should show empty message for my servers mode")
	}
}

func TestServerBrowserViewNoMatches(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	m.filtered = []browserItem{} // simulate no filter matches
	view := m.View()
	if !strings.Contains(view, "No matches found") {
		t.Error("should show no matches message when servers exist but filter clears all")
	}
}

func TestServerBrowserViewDynamicMultiProviderFilter(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:           BrowseDynamic,
		cfg:            cfg,
		multiProvider:  true,
		providers:      []string{"protonvpn", "mullvad"},
		providerFilter: "protonvpn",
	}
	view := m.View()
	// Should show the provider filter key as active
	if !strings.Contains(view, "0:") {
		t.Error("should show provider filter key")
	}
}

func TestServerBrowserViewInvalidItem(t *testing.T) {
	cfg := testConfig(t)
	item := browserItem{
		display:  "bad-server",
		invalid:  true,
		errorMsg: "missing private key",
	}
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	view := m.View()
	if !strings.Contains(view, "INVALID") {
		t.Error("should show INVALID for invalid items")
	}
	if !strings.Contains(view, "missing private key") {
		t.Error("should show error message for invalid items")
	}
}

func TestServerBrowserViewWithLatency(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	item.latency = 42 * time.Millisecond
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	view := m.View()
	if !strings.Contains(view, "[42ms]") {
		t.Error("should show latency in brackets")
	}
}

func TestServerBrowserViewWithSortMessage(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	m.sortMessage = "Sorted by Latency"
	view := m.View()
	if !strings.Contains(view, "Sorted by Latency") {
		t.Error("should show sort message")
	}
}

func TestServerBrowserViewScrollIndicator(t *testing.T) {
	cfg := testConfig(t)
	var items []browserItem
	for i := 0; i < 50; i++ {
		items = append(items, makeManualItem(fmt.Sprintf("US-NY#%d", i), "1.2.3.4:51820", false))
	}
	m := populateBrowser(BrowseMyServers, cfg, items)
	m.height = 30
	view := m.View()
	if !strings.Contains(view, "1/50 servers") {
		t.Error("should show scroll indicator for large lists")
	}
}

func TestServerBrowserViewPreviewProviderServer(t *testing.T) {
	cfg := testConfig(t)
	srv := provider.Server{
		ServerName:  "US-NY#42",
		Country:     "United States",
		City:        "New York",
		IPs:         []string{"1.1.1.1"},
		PortForward: true,
	}
	item := browserItem{
		providerServer: &srv,
		providerName:   "protonvpn",
		display:        "US United States - New York (US-NY#42)",
		portForward:    true,
	}
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})
	view := m.View()
	if !strings.Contains(view, "Country:") {
		t.Error("preview should show country for provider server")
	}
	if !strings.Contains(view, "P2P") {
		t.Error("preview should show features for provider server")
	}
}

func TestServerBrowserBuildPreviewManualServerMinimal(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	parts := m.buildPreview(item)
	foundEndpoint := false
	for _, p := range parts {
		if strings.Contains(p, "Endpoint:") {
			foundEndpoint = true
		}
	}
	if !foundEndpoint {
		t.Error("should show endpoint for manual server")
	}
}

func TestServerBrowserBuildPreviewWithLatency(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	item.latency = 42 * time.Millisecond
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	parts := m.buildPreview(item)
	foundLatency := false
	for _, p := range parts {
		if strings.Contains(p, "Latency:") {
			foundLatency = true
		}
	}
	if !foundLatency {
		t.Error("preview should show latency when measured")
	}
}

// --- Dynamic Update message tests ---

func TestServerBrowserUpdateBrowserLoadMsgError(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:    BrowseDynamic,
		cfg:     cfg,
		loading: true,
	}
	model, _ := m.Update(BrowserLoadMsg{Err: errForTest("fetch failed")})
	sb := model.(*ServerBrowser)
	if sb.loading {
		t.Error("should not be loading after error")
	}
	if sb.err == nil {
		t.Error("should set error")
	}
}

func TestServerBrowserUpdateBrowserLoadMultiMsgError(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:    BrowseDynamic,
		cfg:     cfg,
		loading: true,
	}
	model, _ := m.Update(BrowserLoadMultiMsg{Err: errForTest("no cache")})
	sb := model.(*ServerBrowser)
	if sb.loading {
		t.Error("should not be loading after error")
	}
	if sb.err == nil {
		t.Error("should set error")
	}
}

func TestServerBrowserUpdateBrowserLoadMultiMsgSuccess(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:          BrowseDynamic,
		cfg:           cfg,
		loading:       true,
		multiProvider: true,
	}
	servers := map[string][]provider.Server{
		"protonvpn": {{ServerName: "US-NY#1", Country: "US", IPs: []string{"1.1.1.1"}}},
		"mullvad":   {{ServerName: "SE#1", Country: "SE", IPs: []string{"2.2.2.2"}}},
	}
	model, _ := m.Update(BrowserLoadMultiMsg{ServersByProvider: servers})
	sb := model.(*ServerBrowser)
	if sb.loading {
		t.Error("should not be loading")
	}
	if len(sb.servers) != 2 {
		t.Errorf("servers = %d, want 2", len(sb.servers))
	}
}

func TestServerBrowserUpdateLatencyMsg(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	m.measuringPing = true

	latencies := map[string]time.Duration{
		"US-NY#1": 42 * time.Millisecond,
	}
	model, _ := m.Update(BrowserLatencyMsg{Latencies: latencies})
	sb := model.(*ServerBrowser)
	if sb.measuringPing {
		t.Error("should clear measuringPing")
	}
	if sb.sortMessage != "Sorted by Latency" {
		t.Errorf("sortMessage = %q, want 'Sorted by Latency'", sb.sortMessage)
	}
}

func TestServerBrowserUpdateQuickConnectMsg(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})

	model, _ := m.Update(BrowserQuickConnectMsg{ServerName: "US-NY#1"})
	sb := model.(*ServerBrowser)
	if sb.pendingConnect == nil {
		t.Error("should set pendingConnect for quickest server")
	}
	if sb.confirmLabel != "Quickest" {
		t.Errorf("confirmLabel = %q, want 'Quickest'", sb.confirmLabel)
	}
}

// --- Key handling tests ---

func TestServerBrowserEscDuringDynamicLoading(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:    BrowseDynamic,
		cfg:     cfg,
		loading: true,
	}
	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	sb := model.(*ServerBrowser)
	if !sb.cancelled {
		t.Error("esc during loading should cancel")
	}
	if cmd == nil {
		t.Fatal("should return BackMsg cmd")
	}
}

func TestServerBrowserEscDuringDynamicError(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode: BrowseDynamic,
		cfg:  cfg,
		err:  errForTest("failed"),
	}
	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	sb := model.(*ServerBrowser)
	if !sb.cancelled {
		t.Error("esc during error should cancel")
	}
	if cmd == nil {
		t.Fatal("should return BackMsg cmd")
	}
}

func TestServerBrowserConfirmConnect(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	m.pendingConnect = &item
	m.confirmLabel = "Random"
	m.sortMessage = "Connect?"

	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	sb := model.(*ServerBrowser)
	if sb.pendingConnect != nil {
		t.Error("should clear pendingConnect after confirming")
	}
	if cmd == nil {
		t.Error("should return connect cmd")
	}
}

func TestServerBrowserCancelConnect(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	m.pendingConnect = &item
	m.confirmLabel = "Random"

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	sb := model.(*ServerBrowser)
	if sb.pendingConnect != nil {
		t.Error("should clear pendingConnect after cancelling")
	}
	if sb.confirmLabel != "" {
		t.Error("should clear confirmLabel")
	}
}

func TestServerBrowserPgUpPgDown(t *testing.T) {
	cfg := testConfig(t)
	var items []browserItem
	for i := 0; i < 30; i++ {
		items = append(items, makeManualItem(fmt.Sprintf("US-NY#%d", i), "1.2.3.4:51820", false))
	}
	m := populateBrowser(BrowseMyServers, cfg, items)

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	sb := model.(*ServerBrowser)
	if sb.cursor != 10 {
		t.Errorf("cursor = %d, want 10 after pgdown", sb.cursor)
	}

	model, _ = sb.Update(tea.KeyMsg{Type: tea.KeyPgUp})
	sb = model.(*ServerBrowser)
	if sb.cursor != 0 {
		t.Errorf("cursor = %d, want 0 after pgup", sb.cursor)
	}
}

func TestServerBrowserHomeEnd(t *testing.T) {
	cfg := testConfig(t)
	var items []browserItem
	for i := 0; i < 10; i++ {
		items = append(items, makeManualItem(fmt.Sprintf("US-NY#%d", i), "1.2.3.4:51820", false))
	}
	m := populateBrowser(BrowseMyServers, cfg, items)

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnd})
	sb := model.(*ServerBrowser)
	if sb.cursor != 9 {
		t.Errorf("cursor = %d, want 9 after end", sb.cursor)
	}

	model, _ = sb.Update(tea.KeyMsg{Type: tea.KeyHome})
	sb = model.(*ServerBrowser)
	if sb.cursor != 0 {
		t.Errorf("cursor = %d, want 0 after home", sb.cursor)
	}
}

func TestServerBrowserEnterInvalid(t *testing.T) {
	cfg := testConfig(t)
	item := browserItem{display: "bad", invalid: true, errorMsg: "parse error"}
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Error("enter on invalid item should not return cmd")
	}
}

func TestServerBrowserBackspaceQuery(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	m.query = "US"

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	sb := model.(*ServerBrowser)
	if sb.query != "U" {
		t.Errorf("query = %q, want 'U' after backspace", sb.query)
	}
}

func TestServerBrowserEscClearsQuery(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	m.query = "US"

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	sb := model.(*ServerBrowser)
	if sb.query != "" {
		t.Errorf("query = %q, should be cleared by esc", sb.query)
	}
	if sb.cancelled {
		t.Error("should not cancel when query was non-empty")
	}
}

func TestServerBrowserEscWithEmptyQuery(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})

	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	sb := model.(*ServerBrowser)
	if sb.cancelled {
		t.Error("esc with empty query on primary nav view should not cancel")
	}
	if cmd != nil {
		t.Error("esc with empty query on primary nav view should not produce a command")
	}
}

func TestServerBrowserTypeToSearch(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeManualItem("US-NY#1", "1.2.3.4:51820", false),
		makeManualItem("SE-Stockholm#2", "2.2.2.2:51820", false),
	}
	m := populateBrowser(BrowseMyServers, cfg, items)

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'S'}})
	sb := model.(*ServerBrowser)
	if sb.query != "S" {
		t.Errorf("query = %q, want 'S'", sb.query)
	}
}

func TestServerBrowserFeatureFilterToggles(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeManualItem("US-NY-p2p#1", "1.2.3.4:51820", false, "p2p"),
		makeManualItem("SE#2", "2.2.2.2:51820", false),
	}
	m := populateBrowser(BrowseMyServers, cfg, items)

	// Toggle P2P filter (key "1")
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	sb := model.(*ServerBrowser)
	if !sb.filterP2P {
		t.Error("filterP2P should be true after pressing 1")
	}
	if len(sb.filtered) != 1 {
		t.Errorf("filtered = %d, want 1 (only P2P server)", len(sb.filtered))
	}

	// Toggle off
	model, _ = sb.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	sb = model.(*ServerBrowser)
	if sb.filterP2P {
		t.Error("filterP2P should be false after pressing 1 again")
	}
	if len(sb.filtered) != 2 {
		t.Errorf("filtered = %d, want 2", len(sb.filtered))
	}
}

func TestServerBrowserRandomServer(t *testing.T) {
	cfg := testConfig(t)
	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'6'}})
	sb := model.(*ServerBrowser)
	if sb.pendingConnect == nil {
		t.Error("key 6 should set pendingConnect for random server")
	}
	if sb.confirmLabel != "Random" {
		t.Errorf("confirmLabel = %q, want 'Random'", sb.confirmLabel)
	}
}

func TestServerBrowserCycleProviderFilter(t *testing.T) {
	cfg := testConfig(t)
	srv := provider.Server{ServerName: "US-NY#1", Country: "US", IPs: []string{"1.1.1.1"}}
	item := browserItem{
		providerServer: &srv,
		providerName:   "protonvpn",
		display:        "US-NY#1 • ProtonVPN",
	}
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})
	m.multiProvider = true
	m.providers = []string{"protonvpn", "mullvad"}

	// Press 0 to cycle provider filter
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'0'}})
	sb := model.(*ServerBrowser)
	if sb.providerFilter != "protonvpn" {
		t.Errorf("providerFilter = %q, want 'protonvpn'", sb.providerFilter)
	}
	if !strings.Contains(sb.sortMessage, "ProtonVPN") {
		t.Errorf("sortMessage = %q, should contain ProtonVPN", sb.sortMessage)
	}

	// Press 0 again to cycle to next
	model, _ = sb.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'0'}})
	sb = model.(*ServerBrowser)
	if sb.providerFilter != "mullvad" {
		t.Errorf("providerFilter = %q, want 'mullvad'", sb.providerFilter)
	}

	// Press 0 again to cycle back to ALL
	model, _ = sb.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'0'}})
	sb = model.(*ServerBrowser)
	if sb.providerFilter != "" {
		t.Errorf("providerFilter = %q, want empty (ALL)", sb.providerFilter)
	}
	if !strings.Contains(sb.sortMessage, "ALL") {
		t.Errorf("sortMessage = %q, should contain ALL", sb.sortMessage)
	}
}

func TestServerBrowserToggleFavoriteDynamic(t *testing.T) {
	cfg := testConfig(t)
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")
	os.MkdirAll(cfg.ConfigDir, 0700)

	srv := provider.Server{ServerName: "US-NY#1", Country: "US", IPs: []string{"1.1.1.1"}}
	item := browserItem{
		providerServer: &srv,
		providerName:   "protonvpn",
		display:        "US-NY#1",
	}
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})

	// Press 9 to toggle favorite
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'9'}})
	sb := model.(*ServerBrowser)

	// Should be added to favorites
	found := false
	for _, f := range sb.cfg.Favorites {
		if f == "dynamic:protonvpn:US-NY#1" {
			found = true
		}
	}
	if !found {
		t.Error("should add dynamic server to favorites")
	}
}

func TestServerBrowserToggleFavoriteManual(t *testing.T) {
	cfg := testConfig(t)
	cfg.ConfigDir = t.TempDir()
	cfg.ConfigFile = filepath.Join(cfg.ConfigDir, "config.json")
	os.MkdirAll(cfg.ConfigDir, 0700)

	item := makeManualItem("US-NY#1", "1.2.3.4:51820", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})

	// Press 9 to toggle favorite
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'9'}})
	sb := model.(*ServerBrowser)

	found := false
	for _, f := range sb.cfg.Favorites {
		if f == "US-NY#1" {
			found = true
		}
	}
	if !found {
		t.Error("should add manual server to favorites")
	}
}

func TestServerBrowserItemDisplayNameDynamic(t *testing.T) {
	cfg := testConfig(t)
	item := browserItem{
		isDynamic:       true,
		dynamicProvider: "protonvpn",
		dynamicName:     "US-NY#42",
		display:         "test",
	}
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	name := m.itemDisplayName(item)
	if name != "US-NY#42" {
		t.Errorf("itemDisplayName = %q, want 'US-NY#42'", name)
	}
}

func TestServerBrowserSortServersMixed(t *testing.T) {
	cfg := testConfig(t)
	items := []browserItem{
		makeManualItem("B-server#1", "1.2.3.4:51820", false),
		makeManualItem("A-server#2", "2.2.2.2:51820", false),
	}
	items[0].latency = 100 * time.Millisecond
	// items[1] has no latency (0)
	m := populateBrowser(BrowseMyServers, cfg, items)
	m.sortServers()

	// Server with latency should come first, unmeasured last
	if m.filtered[0].latency != 100*time.Millisecond {
		t.Error("measured server should come first in sort")
	}
	if m.filtered[1].latency != 0 {
		t.Error("unmeasured server should come last")
	}
}

func TestServerBrowserBuildDynamicItemsMultiProvider(t *testing.T) {
	cfg := testConfig(t)
	m := &ServerBrowser{
		mode:          BrowseDynamic,
		cfg:           cfg,
		multiProvider: true,
	}
	servers := []provider.Server{
		{ServerName: "US-NY#1", Country: "US", IPs: []string{"1.1.1.1"}},
	}
	items := m.buildDynamicItems(servers, "protonvpn")
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	if !strings.Contains(items[0].display, "ProtonVPN") {
		t.Error("multi-provider items should include provider name in display")
	}
}

func TestServerBrowserConnectCmdDynamic(t *testing.T) {
	cfg := testConfig(t)
	item := browserItem{
		isDynamic:       true,
		dynamicProvider: "protonvpn",
		dynamicName:     "US-NY#42",
	}
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})
	cmd := m.connectCmd(item)
	if cmd == nil {
		t.Fatal("connectCmd should return cmd for dynamic item")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.Server != "US-NY#42" {
		t.Errorf("Server = %q, want US-NY#42", sv.Server)
	}
	if sv.Provider != "protonvpn" {
		t.Errorf("Provider = %q, want protonvpn", sv.Provider)
	}
	if !sv.Dynamic {
		t.Error("should be dynamic")
	}
}

// mockPingServer temporarily replaces pingServer and mocks probePing to
// return true so the probe check passes and the given ping function is used.
func mockPingServer(t *testing.T, fn func(string) int) {
	t.Helper()
	origPing := pingServer
	origProbe := probePing
	pingServer = fn
	probePing = func() bool { return true }
	t.Cleanup(func() {
		pingServer = origPing
		probePing = origProbe
	})
}

// mockProbePing temporarily replaces probePing and probePingUnprivileged.
func mockProbePing(t *testing.T, privileged, unprivileged bool) {
	t.Helper()
	origProbe := probePing
	origUnpriv := probePingUnprivileged
	probePing = func() bool { return privileged }
	probePingUnprivileged = func() bool { return unprivileged }
	t.Cleanup(func() {
		probePing = origProbe
		probePingUnprivileged = origUnpriv
	})
}

// TestMeasureLatencyManualServers tests measureLatency with manual servers.
func TestMeasureLatencyManualServers(t *testing.T) {
	mockPingServer(t, func(ip string) int {
		switch ip {
		case "1.1.1.1":
			return 10
		case "2.2.2.2":
			return 20
		default:
			return -1
		}
	})

	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{
		makeManualItem("US-NY#1", "1.1.1.1:51820", false),
		makeManualItem("US-NY#2", "2.2.2.2:51820", false),
	})

	cmd := m.measureLatency()
	if cmd == nil {
		t.Fatal("measureLatency should return a cmd")
	}

	msg := cmd()
	latMsg, ok := msg.(BrowserLatencyMsg)
	if !ok {
		t.Fatalf("expected BrowserLatencyMsg, got %T", msg)
	}
	if len(latMsg.Latencies) != 2 {
		t.Errorf("expected 2 latencies, got %d", len(latMsg.Latencies))
	}
}

// TestMeasureLatencyEmptyList tests measureLatency with no servers.
func TestMeasureLatencyEmptyList(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, nil)

	cmd := m.measureLatency()
	msg := cmd()
	latMsg, ok := msg.(BrowserLatencyMsg)
	if !ok {
		t.Fatalf("expected BrowserLatencyMsg, got %T", msg)
	}
	if len(latMsg.Latencies) != 0 {
		t.Errorf("expected 0 latencies, got %d", len(latMsg.Latencies))
	}
}

// TestMeasureLatencyInvalidItems tests that invalid items are skipped.
func TestMeasureLatencyInvalidItems(t *testing.T) {
	mockPingServer(t, func(ip string) int { return 5 })

	cfg := testConfig(t)
	invalidItem := makeManualItem("bad", "3.3.3.3:51820", false)
	invalidItem.invalid = true
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{
		invalidItem,
		makeManualItem("US-NY#1", "1.1.1.1:51820", false),
	})

	cmd := m.measureLatency()
	msg := cmd()
	latMsg := msg.(BrowserLatencyMsg)
	// Only the valid item should be measured
	if len(latMsg.Latencies) != 1 {
		t.Errorf("expected 1 latency (invalid skipped), got %d", len(latMsg.Latencies))
	}
}

// TestMeasureLatencyProviderServers tests measureLatency with provider servers.
func TestMeasureLatencyProviderServers(t *testing.T) {
	mockPingServer(t, func(ip string) int { return 15 })

	cfg := testConfig(t)
	srv := provider.Server{ServerName: "US-NY#1", IPs: []string{"1.1.1.1"}}
	item := browserItem{
		providerServer: &srv,
		providerName:   "protonvpn",
		display:        "US-NY#1",
	}
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})

	cmd := m.measureLatency()
	msg := cmd()
	latMsg := msg.(BrowserLatencyMsg)
	if len(latMsg.Latencies) != 1 {
		t.Errorf("expected 1 latency, got %d", len(latMsg.Latencies))
	}
	if _, ok := latMsg.Latencies["US-NY#1"]; !ok {
		t.Error("expected latency for US-NY#1")
	}
}

// TestMeasureLatencyThenConnectSuccess tests measureLatencyThenConnect with
// manual servers and returns a QuickConnectMsg for the best server.
func TestMeasureLatencyThenConnectSuccess(t *testing.T) {
	mockPingServer(t, func(ip string) int {
		switch ip {
		case "1.1.1.1":
			return 30 // slower
		case "2.2.2.2":
			return 5 // fastest
		default:
			return -1
		}
	})

	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{
		makeManualItem("US-NY#1", "1.1.1.1:51820", false),
		makeManualItem("US-NY#2", "2.2.2.2:51820", false),
	})

	cmd := m.measureLatencyThenConnect()
	if cmd == nil {
		t.Fatal("measureLatencyThenConnect should return a cmd")
	}

	msg := cmd()
	qc, ok := msg.(BrowserQuickConnectMsg)
	if !ok {
		t.Fatalf("expected BrowserQuickConnectMsg, got %T", msg)
	}
	if qc.ServerName != "US-NY#2" {
		t.Errorf("ServerName = %q, want US-NY#2 (fastest)", qc.ServerName)
	}
}

// TestMeasureLatencyThenConnectEmpty tests measureLatencyThenConnect with no servers.
func TestMeasureLatencyThenConnectEmpty(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, nil)

	cmd := m.measureLatencyThenConnect()
	msg := cmd()
	latMsg, ok := msg.(BrowserLatencyMsg)
	if !ok {
		t.Fatalf("expected BrowserLatencyMsg (fallback), got %T", msg)
	}
	if len(latMsg.Latencies) != 0 {
		t.Errorf("expected 0 latencies, got %d", len(latMsg.Latencies))
	}
}

// TestMeasureLatencyThenConnectProviderServer tests with provider servers.
func TestMeasureLatencyThenConnectProviderServer(t *testing.T) {
	mockPingServer(t, func(ip string) int { return 8 })

	cfg := testConfig(t)
	srv := provider.Server{ServerName: "US-NY#1", IPs: []string{"1.1.1.1"}}
	item := browserItem{
		providerServer: &srv,
		providerName:   "protonvpn",
		display:        "US-NY#1",
	}
	m := populateBrowser(BrowseDynamic, cfg, []browserItem{item})

	cmd := m.measureLatencyThenConnect()
	msg := cmd()
	qc, ok := msg.(BrowserQuickConnectMsg)
	if !ok {
		t.Fatalf("expected BrowserQuickConnectMsg, got %T", msg)
	}
	if qc.ServerName != "US-NY#1" {
		t.Errorf("ServerName = %q, want US-NY#1", qc.ServerName)
	}
	if qc.Provider != "protonvpn" {
		t.Errorf("Provider = %q, want protonvpn", qc.Provider)
	}
	if !qc.IsDynamic {
		t.Error("should be dynamic for provider server")
	}
}

// TestMeasureLatencyThenConnectAllFail tests when all pings fail.
func TestMeasureLatencyThenConnectAllFail(t *testing.T) {
	mockPingServer(t, func(ip string) int { return -1 })

	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{
		makeManualItem("US-NY#1", "1.1.1.1:51820", false),
	})

	cmd := m.measureLatencyThenConnect()
	msg := cmd()
	// Should fall back to BrowserLatencyMsg since no best server found
	latMsg, ok := msg.(BrowserLatencyMsg)
	if !ok {
		t.Fatalf("expected BrowserLatencyMsg (fallback), got %T", msg)
	}
	if len(latMsg.Latencies) != 0 {
		t.Errorf("expected 0 latencies (all failed), got %d", len(latMsg.Latencies))
	}
}

// TestMeasureLatencySkipsEmptyIP tests that items with empty IP are skipped.
func TestMeasureLatencySkipsEmptyIP(t *testing.T) {
	mockPingServer(t, func(ip string) int { return 5 })

	cfg := testConfig(t)
	// Item with no endpoint
	item := makeManualItem("NoEndpoint", "", false)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{item})

	cmd := m.measureLatency()
	msg := cmd()
	latMsg := msg.(BrowserLatencyMsg)
	if len(latMsg.Latencies) != 0 {
		t.Errorf("expected 0 latencies (empty IP skipped), got %d", len(latMsg.Latencies))
	}
}

// --- Ping auth tests ---

// TestMeasureLatencyPingAuthNeeded tests that when both privileged and
// unprivileged ICMP fail, a BrowserPingAuthNeededMsg is returned.
func TestMeasureLatencyPingAuthNeeded(t *testing.T) {
	mockProbePing(t, false, false)

	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{
		makeManualItem("US-NY#1", "1.1.1.1:51820", false),
	})

	cmd := m.measureLatency()
	msg := cmd()
	authMsg, ok := msg.(BrowserPingAuthNeededMsg)
	if !ok {
		t.Fatalf("expected BrowserPingAuthNeededMsg, got %T", msg)
	}
	if authMsg.forQuickConnect {
		t.Error("forQuickConnect should be false for measureLatency")
	}
}

// TestMeasureLatencyThenConnectPingAuthNeeded tests the quick-connect path.
func TestMeasureLatencyThenConnectPingAuthNeeded(t *testing.T) {
	mockProbePing(t, false, false)

	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{
		makeManualItem("US-NY#1", "1.1.1.1:51820", false),
	})

	cmd := m.measureLatencyThenConnect()
	msg := cmd()
	authMsg, ok := msg.(BrowserPingAuthNeededMsg)
	if !ok {
		t.Fatalf("expected BrowserPingAuthNeededMsg, got %T", msg)
	}
	if !authMsg.forQuickConnect {
		t.Error("forQuickConnect should be true for measureLatencyThenConnect")
	}
}

// TestMeasureLatencyUnprivilegedFallback tests that when privileged ICMP fails
// but unprivileged works, the measurement proceeds with unprivileged ping.
func TestMeasureLatencyUnprivilegedFallback(t *testing.T) {
	mockProbePing(t, false, true)

	// Mock unprivileged ping
	origUnpriv := pingServerUnprivileged
	pingServerUnprivileged = func(ip string) int { return 25 }
	t.Cleanup(func() { pingServerUnprivileged = origUnpriv })

	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{
		makeManualItem("US-NY#1", "1.1.1.1:51820", false),
	})

	cmd := m.measureLatency()
	msg := cmd()
	latMsg, ok := msg.(BrowserLatencyMsg)
	if !ok {
		t.Fatalf("expected BrowserLatencyMsg, got %T", msg)
	}
	if len(latMsg.Latencies) != 1 {
		t.Errorf("expected 1 latency, got %d", len(latMsg.Latencies))
	}
}

// TestUpdate_BrowserPingAuthNeededMsg tests that BrowserPingAuthNeededMsg
// sets the pingAuthNeeded state.
func TestUpdate_BrowserPingAuthNeededMsg(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{
		makeManualItem("US-NY#1", "1.1.1.1:51820", false),
	})
	m.measuringPing = true

	result, _ := m.Update(BrowserPingAuthNeededMsg{forQuickConnect: false})
	sb := result.(*ServerBrowser)

	if !sb.pingAuthNeeded {
		t.Error("pingAuthNeeded should be true")
	}
	if sb.measuringPing {
		t.Error("measuringPing should be false")
	}
}

// TestPingAuthNeeded_EscCancels tests that esc dismisses the ping auth prompt.
func TestPingAuthNeeded_EscCancels(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{
		makeManualItem("US-NY#1", "1.1.1.1:51820", false),
	})
	m.pingAuthNeeded = true

	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyEsc}))
	sb := result.(*ServerBrowser)

	if sb.pingAuthNeeded {
		t.Error("pingAuthNeeded should be false after esc")
	}
}

// TestPingAuthNeeded_AShowsAuth tests that 'a' activates the auth prompt.
func TestPingAuthNeeded_AShowsAuth(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{
		makeManualItem("US-NY#1", "1.1.1.1:51820", false),
	})
	m.auth = &AuthPrompt{}
	m.pingAuthNeeded = true

	result, _ := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{'a'}}))
	sb := result.(*ServerBrowser)

	if !sb.auth.Active() {
		t.Error("auth prompt should be active after pressing 'a'")
	}
}

// TestPingAuthNeeded_ViewShowsPrompt tests that the View renders the auth prompt.
func TestPingAuthNeeded_ViewShowsPrompt(t *testing.T) {
	cfg := testConfig(t)
	m := populateBrowser(BrowseMyServers, cfg, []browserItem{
		makeManualItem("US-NY#1", "1.1.1.1:51820", false),
	})
	m.pingAuthNeeded = true

	view := m.View()
	if !strings.Contains(view, "elevated privileges") {
		t.Errorf("view should mention elevated privileges, got: %s", view)
	}
	if !strings.Contains(view, "Authenticate") {
		t.Errorf("view should show Authenticate option, got: %s", view)
	}
}

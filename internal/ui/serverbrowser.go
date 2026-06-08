package ui

import (
	"fmt"
	cryptorand "crypto/rand"
	"math/big"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/provider"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/sudo"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/util"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/sahilm/fuzzy"
)

// BrowseMode determines what data the ServerBrowser displays.
type BrowseMode int

const (
	BrowseMyServers BrowseMode = iota // manual .conf files + favorited dynamic servers
	BrowseDynamic                     // all provider servers from cache
)

// browserItem is the unified item type for both browse modes.
type browserItem struct {
	display  string
	latency  time.Duration
	favorite bool

	// Feature flags
	portForward bool
	tor         bool
	secureCore  bool
	stream      bool
	free        bool

	// Dynamic server data (non-nil when item comes from provider cache)
	providerServer *provider.Server
	providerName   string

	// Manual server data (non-nil when item comes from .conf file)
	manualServer *wireguard.Server

	// MyServers-specific: favorited dynamic servers living in the My Servers list
	isDynamic       bool   // true for favorited dynamic servers in MyServers mode
	dynamicProvider string // provider name for dynamic favorites
	dynamicName     string // e.g. "US-NY#42"
	invalid         bool   // parse error on .conf file
	errorMsg        string
}

// --- Consolidated message types (replace 6 with 4) ---

// BrowserLoadMsg carries single-provider server load results.
type BrowserLoadMsg struct {
	Servers []provider.Server
	Err     error
}

// BrowserLoadMultiMsg carries multi-provider server load results.
type BrowserLoadMultiMsg struct {
	ServersByProvider map[string][]provider.Server
	Err               error
}

// BrowserLatencyMsg carries latency measurement results.
type BrowserLatencyMsg struct {
	Latencies map[string]time.Duration
}

// BrowserQuickConnectMsg carries the quickest-server auto-connect result.
type BrowserQuickConnectMsg struct {
	ServerName string
	Provider   string
	IsDynamic  bool
}

// BrowserPingAuthNeededMsg signals that ICMP ping requires authentication.
type BrowserPingAuthNeededMsg struct {
	forQuickConnect bool
}

// --- ServerBrowser struct ---

// ServerBrowser is the unified server list / dynamic browser component.
type ServerBrowser struct {
	mode        BrowseMode
	servers     []browserItem
	filtered    []browserItem
	cursor      int
	query       string
	cfg         *config.Config
	width       int
	height      int
	cancelled   bool
	loading     bool
	err         error
	noProviders bool // true when no providers configured (distinct from empty cache)

	// Dynamic-mode fields
	provider       string   // single provider filter, or "" for all
	providers      []string // all configured providers (multi-provider mode)
	multiProvider  bool
	providerFilter string // cycling provider filter (key 0)

	// MyServers-mode fields
	hasProviders  bool
	providerCount int

	// Shared feature filters
	filterP2P        bool
	filterTor        bool
	filterSecureCore bool
	filterStream     bool
	filterFree       bool

	// Sorting & latency
	sortMessage   string
	measuringPing bool

	// Ping authentication
	auth             *AuthPrompt
	pingAuthNeeded   bool
	pendingQuickPing bool

	// Confirmation prompt
	pendingConnect *browserItem
	confirmLabel   string
	connecting     bool // guard against double-Enter

	// Spinner for loading state
	spinner Spinner

	// Focus state for cursor visibility
	focused bool
}

// --- Constructors ---

// NewMyServersBrowser creates a ServerBrowser in MyServers mode (manual .conf files + favorited dynamics).
func NewMyServersBrowser(cfg *config.Config) *ServerBrowser {
	m := &ServerBrowser{
		mode: BrowseMyServers,
		cfg:  cfg,
		auth: &AuthPrompt{},
	}
	m.loadMyServers()
	return m
}

// NewDynamicServerBrowser creates a ServerBrowser in Dynamic mode (provider cache).
func NewDynamicServerBrowser(cfg *config.Config, providerName string) *ServerBrowser {
	m := &ServerBrowser{
		mode:     BrowseDynamic,
		cfg:      cfg,
		provider: providerName,
		loading:  true,
		auth:     &AuthPrompt{},
	}
	if providerName == "" {
		providers, _ := configListProviders(cfg.ConfigDir)
		m.providers = providers
		m.multiProvider = len(providers) > 1
		if len(providers) == 0 {
			m.noProviders = true
			m.loading = false
		}
	}
	return m
}

// SetFocused sets the focus state for cursor visibility.
func (m *ServerBrowser) SetFocused(focused bool) {
	m.focused = focused
}

// --- Init ---

func (m *ServerBrowser) Init() tea.Cmd {
	if m.mode == BrowseDynamic && !m.noProviders {
		return m.loadDynamicServers()
	}
	return nil
}

// --- Data loading ---

// loadMyServers loads .conf files and favorited dynamic servers from disk.
func (m *ServerBrowser) loadMyServers() {
	wgDir := filepath.Join(m.cfg.ConfigDir, "wireguard")
	configs, err := wireguard.ListConfigs(wgDir)
	if err != nil {
		configs = nil
	}

	providers, _ := configListProviders(m.cfg.ConfigDir)
	m.hasProviders = len(providers) > 0
	m.providerCount = len(providers)

	// Reload favorites from config on disk
	freshCfg, err := configLoad()
	if err == nil {
		m.cfg.Favorites = freshCfg.Favorites
	}

	favMap := make(map[string]bool)
	for _, fav := range m.cfg.Favorites {
		favMap[fav] = true
	}

	var servers []browserItem
	for _, c := range configs {
		if c.ParseError != "" {
			servers = append(servers, browserItem{
				manualServer: &wireguard.Server{Config: c, Info: wireguard.ParseServerName(c.Name)},
				display:      c.Name,
				invalid:      true,
				errorMsg:     c.ParseError,
			})
			continue
		}
		srv := wireguard.NewServer(c)
		item := browserItem{
			manualServer: srv,
			display:      srv.DisplayName(),
			favorite:     favMap[c.Name],
		}
		for _, svc := range srv.Info.Services {
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
		servers = append(servers, item)
	}

	// Add favorited dynamic servers
	cacheDir := filepath.Join(m.cfg.ConfigDir, "cache")
	for _, fav := range m.cfg.Favorites {
		if !strings.HasPrefix(fav, "dynamic:") {
			continue
		}
		parts := strings.SplitN(fav, ":", 3)
		if len(parts) != 3 {
			continue
		}
		provName := parts[1]
		srvName := parts[2]

		item := browserItem{
			favorite:        true,
			isDynamic:       true,
			dynamicProvider: provName,
			dynamicName:     srvName,
		}

		cachedServers, err := loadProviderServers(cacheDir, provName)
		if err == nil {
			for _, cs := range cachedServers {
				if cs.Name() == srvName {
					item.portForward = cs.PortForward
					item.tor = cs.Tor
					item.secureCore = cs.SecureCore
					item.stream = cs.Stream
					item.free = cs.Free
					item.display = formatDynamicDisplay(cs, provName)
					break
				}
			}
		}

		// Fallback display if cache miss
		if item.display == "" {
			countryCode := ""
			if len(srvName) >= 2 && srvName[0] >= 'A' && srvName[0] <= 'Z' && srvName[1] >= 'A' && srvName[1] <= 'Z' {
				countryCode = srvName[:2]
			}
			flag := ""
			if countryCode != "" {
				flag = util.CountryFlag(countryCode) + " "
			}
			displayProv := provider.ProviderDisplayNames[provName]
			if displayProv == "" {
				displayProv = provName
			}
			item.display = flag + srvName + " • " + displayProv
		}

		servers = append(servers, item)
	}

	// Sort: favorites first, then alphabetically by display name
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].favorite != servers[j].favorite {
			return servers[i].favorite
		}
		return strings.ToLower(servers[i].display) < strings.ToLower(servers[j].display)
	})

	m.servers = servers
	m.filtered = servers
	m.cursor = 0
}

// loadDynamicServers returns a Cmd that loads servers from provider cache.
func (m *ServerBrowser) loadDynamicServers() tea.Cmd {
	if m.provider != "" {
		return func() tea.Msg {
			cacheDir := filepath.Join(m.cfg.ConfigDir, "cache")
			servers, err := loadProviderServers(cacheDir, m.provider)
			return BrowserLoadMsg{Servers: servers, Err: err}
		}
	}
	providers := m.providers
	return func() tea.Msg {
		cacheDir := filepath.Join(m.cfg.ConfigDir, "cache")
		result := make(map[string][]provider.Server)
		for _, p := range providers {
			servers, err := loadProviderServers(cacheDir, p)
			if err == nil {
				result[p] = servers
			}
		}
		if len(result) == 0 {
			return BrowserLoadMultiMsg{Err: fmt.Errorf("no cached servers found for any provider")}
		}
		return BrowserLoadMultiMsg{ServersByProvider: result}
	}
}

// buildDynamicItems converts provider.Server list into browserItems.
func (m *ServerBrowser) buildDynamicItems(servers []provider.Server, provName string) []browserItem {
	items := make([]browserItem, 0, len(servers))
	for _, srv := range servers {
		s := srv // local copy for pointer
		display := formatProviderServer(srv)
		if m.multiProvider {
			displayName := provider.ProviderDisplayNames[provName]
			if displayName == "" {
				displayName = provName
			}
			display += " • " + displayName
		}
		items = append(items, browserItem{
			providerServer: &s,
			providerName:   provName,
			display:        display,
			portForward:    srv.PortForward,
			tor:            srv.Tor,
			secureCore:     srv.SecureCore,
			stream:         srv.Stream,
			free:           srv.Free,
		})
	}
	return items
}

// --- Update ---

func (m *ServerBrowser) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	// Dynamic-mode load results. Bubbletea routes Cmd-produced messages
	// to the CURRENT content model — if the user navigated from Dynamic
	// to My Servers before the load returns, this BrowserLoadMsg lands on
	// the My Servers browser. Without the mode guard, it would clobber
	// m.servers (loaded from manual configs + favorites) with dynamic
	// data from the stale load.
	case BrowserLoadMsg:
		if m.mode != BrowseDynamic {
			return m, nil
		}
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
			return m, nil
		}
		m.servers = m.buildDynamicItems(msg.Servers, m.provider)
		m.filtered = m.servers
		return m, nil

	case BrowserLoadMultiMsg:
		if m.mode != BrowseDynamic {
			return m, nil
		}
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
			return m, nil
		}
		m.servers = nil
		for provName, servers := range msg.ServersByProvider {
			m.servers = append(m.servers, m.buildDynamicItems(servers, provName)...)
		}
		sort.Slice(m.servers, func(i, j int) bool {
			ci := m.serverCountry(m.servers[i])
			cj := m.serverCountry(m.servers[j])
			if ci != cj {
				return ci < cj
			}
			return m.itemKey(m.servers[i]) < m.itemKey(m.servers[j])
		})
		m.filtered = m.servers
		return m, nil

	// Latency results (shared)
	case BrowserLatencyMsg:
		m.measuringPing = false
		for i := range m.servers {
			key := m.itemKey(m.servers[i])
			if lat, ok := msg.Latencies[key]; ok {
				m.servers[i].latency = lat
			}
		}
		for i := range m.filtered {
			key := m.itemKey(m.filtered[i])
			if lat, ok := msg.Latencies[key]; ok {
				m.filtered[i].latency = lat
			}
		}
		m.sortMessage = "Sorted by Latency"
		m.sortServers()
		return m, nil

	// Quick connect result (shared)
	case BrowserQuickConnectMsg:
		for i := range m.filtered {
			key := m.itemKey(m.filtered[i])
			if key == msg.ServerName {
				item := m.filtered[i]
				m.pendingConnect = &item
				m.confirmLabel = "Quickest"
				m.sortMessage = fmt.Sprintf("Connect to %s? (y/n)", m.itemDisplayName(item))
				break
			}
		}
		return m, nil

	// Ping requires auth (both privileged and unprivileged ICMP failed)
	case BrowserPingAuthNeededMsg:
		m.measuringPing = false
		m.pingAuthNeeded = true
		m.pendingQuickPing = msg.forQuickConnect
		m.sortMessage = ""
		return m, nil

	// Auth result (from AuthPrompt after ping auth)
	case authResultMsg:
		if m.auth != nil && m.auth.Active() {
			if retryFn := m.auth.HandleAuthResult(msg); retryFn != nil {
				// Auth succeeded — set file caps for future sessions
				if execPath, err := osExecutable(); err == nil {
					_ = sudo.SetCapabilities(execPath)
				}
				m.pingAuthNeeded = false
				m.sortMessage = "Capabilities set — restart app for privileged ping"
				return m, nil
			}
			return m, nil
		}

	case tea.KeyMsg:
		// Route key events to auth prompt when active
		if m.auth != nil && m.auth.Active() {
			handled, cmd := m.auth.HandleKey(msg)
			if handled {
				if !m.auth.Active() {
					// User cancelled auth
					m.pingAuthNeeded = false
					m.sortMessage = ""
				}
				return m, cmd
			}
		}

		// Handle ping auth needed prompt
		if m.pingAuthNeeded {
			switch msg.String() {
			case "a":
				m.auth.Show(func() {}, func() { m.pingAuthNeeded = false })
				return m, nil
			case "esc":
				m.pingAuthNeeded = false
				m.sortMessage = ""
				return m, nil
			}
			return m, nil
		}

		// In dynamic mode with no providers, Enter opens setup, Esc goes back
		if m.noProviders {
			switch msg.String() {
			case "enter":
				return m, func() tea.Msg {
					return SwitchViewMsg{View: "provider-setup"}
				}
			case "esc":
				return m, func() tea.Msg { return BackMsg{} }
			}
			return m, nil
		}

		// In dynamic mode, allow esc during loading/error
		if m.mode == BrowseDynamic && (m.loading || m.err != nil) {
			if msg.String() == "esc" {
				m.cancelled = true
				return m, func() tea.Msg { return BackMsg{} }
			}
			return m, nil
		}

		// Handle confirmation prompt
		if m.pendingConnect != nil {
			switch msg.String() {
			case "y", "Y", "enter":
				if m.connecting {
					break
				}
				item := *m.pendingConnect
				m.pendingConnect = nil
				m.confirmLabel = ""
				m.sortMessage = ""
				cmd := m.connectCmd(item)
				if cmd != nil {
					m.connecting = true
				}
				return m, cmd
			default:
				m.pendingConnect = nil
				m.confirmLabel = ""
				m.sortMessage = ""
			}
			return m, nil
		}

		switch msg.String() {
		case "esc":
			if m.query != "" {
				m.query = ""
				m.filterServers()
			}
		case "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down":
			if m.cursor < len(m.filtered)-1 {
				m.cursor++
			}
		case "enter":
			if m.connecting {
				break
			}
			if len(m.filtered) > 0 && m.cursor < len(m.filtered) {
				item := m.filtered[m.cursor]
				if item.invalid {
					break
				}
				cmd := m.connectCmd(item)
				if cmd != nil {
					m.connecting = true
				}
				return m, cmd
			}
		case "backspace":
			if len(m.query) > 0 {
				runes := []rune(m.query)
				m.query = string(runes[:len(runes)-1])
				m.filterServers()
			}
		case "pgup":
			m.cursor -= 10
			if m.cursor < 0 {
				m.cursor = 0
			}
		case "pgdown":
			m.cursor += 10
			if len(m.filtered) == 0 {
				m.cursor = 0
			} else if m.cursor >= len(m.filtered) {
				m.cursor = len(m.filtered) - 1
			}
		case "home":
			m.cursor = 0
		case "end":
			if len(m.filtered) > 0 {
				m.cursor = len(m.filtered) - 1
			}

		// Feature filter keys
		case "1":
			m.filterP2P = !m.filterP2P
			m.filterServers()
		case "2":
			m.filterTor = !m.filterTor
			m.filterServers()
		case "3":
			m.filterSecureCore = !m.filterSecureCore
			m.filterServers()
		case "4":
			m.filterStream = !m.filterStream
			m.filterServers()
		case "5":
			m.filterFree = !m.filterFree
			m.filterServers()
		case "6":
			// Random server. crypto/rand (not math/rand) so the choice
			// can't be replayed by an observer who knows process start
			// time — relevant for a VPN where server selection is
			// privacy-sensitive.
			if len(m.filtered) > 0 {
				n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(len(m.filtered))))
				if err != nil {
					// OS RNG broken — break out rather than picking [0].
					break
				}
				idx := int(n.Int64())
				// Skip invalid servers (MyServers mode)
				for attempts := 0; attempts < len(m.filtered); attempts++ {
					if !m.filtered[idx].invalid {
						break
					}
					idx = (idx + 1) % len(m.filtered)
				}
				if !m.filtered[idx].invalid {
					item := m.filtered[idx]
					m.pendingConnect = &item
					m.confirmLabel = "Random"
					m.sortMessage = fmt.Sprintf("Connect to %s? (y/n)", m.itemDisplayName(item))
				}
			}
		case "7":
			// Quickest server
			if len(m.filtered) > 0 {
				var best *browserItem
				for i := range m.filtered {
					if m.filtered[i].invalid {
						continue
					}
					if m.filtered[i].latency > 0 {
						if best == nil || m.filtered[i].latency < best.latency {
							item := m.filtered[i]
							best = &item
						}
					}
				}
				if best != nil {
					m.pendingConnect = best
					m.confirmLabel = "Quickest"
					m.sortMessage = fmt.Sprintf("Connect to %s (%dms)? (y/n)", m.itemDisplayName(*best), best.latency.Milliseconds())
					return m, nil
				}
				m.sortMessage = "Measuring latency to find quickest server..."
				return m, m.measureLatencyThenConnect()
			}
		case "8":
			// Measure latency to all visible
			if len(m.filtered) > 0 && !m.measuringPing {
				m.measuringPing = true
				m.sortMessage = "Measuring latency to all servers..."
				return m, m.measureLatency()
			}
		case "9":
			// Toggle favorite
			if len(m.filtered) > 0 && m.cursor < len(m.filtered) && !m.filtered[m.cursor].invalid {
				m.toggleFavorite(m.cursor)
			}
		case "0":
			// Cycle provider filter (dynamic mode only)
			if m.mode == BrowseDynamic && m.multiProvider && len(m.providers) > 0 {
				if m.providerFilter == "" {
					m.providerFilter = m.providers[0]
				} else {
					found := false
					for i, p := range m.providers {
						if p == m.providerFilter {
							if i+1 < len(m.providers) {
								m.providerFilter = m.providers[i+1]
							} else {
								m.providerFilter = ""
							}
							found = true
							break
						}
					}
					if !found {
						m.providerFilter = ""
					}
				}
				m.filterServers()
				if m.providerFilter == "" {
					m.sortMessage = "Showing: ALL providers"
				} else {
					displayName := provider.ProviderDisplayNames[m.providerFilter]
					if displayName == "" {
						displayName = m.providerFilter
					}
					m.sortMessage = "Showing: " + displayName
				}
			}
		default:
			keyStr := msg.String()
			if len([]rune(keyStr)) == 1 {
				r := []rune(keyStr)[0]
				if unicode.IsPrint(r) && !unicode.IsControl(r) {
					m.query += string(r)
					m.filterServers()
				}
			}
		}

	case StatusUpdateMsg:
		m.spinner.Tick()

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if m.auth != nil {
			m.auth.SetWidth(msg.Width)
		}
	}

	return m, nil
}

// --- View ---

func (m *ServerBrowser) View() string {
	var b strings.Builder

	// Title varies by mode
	switch m.mode {
	case BrowseMyServers:
		b.WriteString(TitleStyle.Render("My Servers") + "\n\n")
	case BrowseDynamic:
		if m.provider != "" {
			displayName := provider.ProviderDisplayNames[m.provider]
			if displayName == "" {
				displayName = m.provider
			}
			b.WriteString(TitleStyle.Render(fmt.Sprintf("Dynamic Servers - %s", displayName)) + "\n\n")
		} else {
			b.WriteString(TitleStyle.Render("Dynamic Servers") + "\n\n")
		}
	}

	// Loading state (dynamic only)
	if m.loading {
		b.WriteString(MutedStyle.Render("  "+m.spinner.View()+" Loading servers...") + "\n")
		return b.String()
	}

	// No providers configured (dynamic only)
	if m.noProviders {
		b.WriteString(MutedStyle.Render("  No providers configured.") + "\n\n")
		b.WriteString(MutedStyle.Render("  Press Enter to set up a provider, or Esc to go back.") + "\n")
		return b.String()
	}

	// Error state (dynamic only)
	if m.err != nil {
		b.WriteString(ErrorStyle.Render(fmt.Sprintf("  Error: %s", m.err.Error())) + "\n")
		b.WriteString("\n" + MutedStyle.Render("  Press esc to go back") + "\n")
		return b.String()
	}

	// Auth prompt overlay (for ping authentication)
	if m.auth != nil && m.auth.Active() {
		b.WriteString(m.auth.View())
		return b.String()
	}

	// Ping auth needed prompt
	if m.pingAuthNeeded {
		b.WriteString(WarningStyle.Render("  Ping requires elevated privileges") + "\n\n")
		b.WriteString(MutedStyle.Render("  [a] Authenticate   [esc] Cancel") + "\n")
		return b.String()
	}

	// Filter bar line 1: feature filters + server count
	filterLine1 := "  "
	if m.filterP2P {
		filterLine1 += SelectedStyle.Render("1:🔄P2P")
	} else {
		filterLine1 += MutedStyle.Render("1:🔄P2P")
	}
	filterLine1 += "  "
	if m.filterTor {
		filterLine1 += SelectedStyle.Render("2:🧅Tor")
	} else {
		filterLine1 += MutedStyle.Render("2:🧅Tor")
	}
	filterLine1 += "  "
	if m.filterSecureCore {
		filterLine1 += SelectedStyle.Render("3:🔒MultiHop")
	} else {
		filterLine1 += MutedStyle.Render("3:🔒MultiHop")
	}
	filterLine1 += "  "
	if m.filterStream {
		filterLine1 += SelectedStyle.Render("4:📺Stream")
	} else {
		filterLine1 += MutedStyle.Render("4:📺Stream")
	}
	filterLine1 += "  "
	if m.filterFree {
		filterLine1 += SelectedStyle.Render("5:🤡Free")
	} else {
		filterLine1 += MutedStyle.Render("5:🤡Free")
	}
	filterLine1 += MutedStyle.Render(fmt.Sprintf("  │ %d servers", len(m.filtered)))
	b.WriteString(filterLine1 + "\n")

	// Filter bar line 2: action keys
	filterLine2 := MutedStyle.Render("  6:🎲Random  7:⚡Fastest  8:⏱️Latency  9:⭐Add Fav")
	if m.mode == BrowseDynamic && m.multiProvider {
		if m.providerFilter != "" {
			displayName := provider.ProviderDisplayNames[m.providerFilter]
			if displayName == "" {
				displayName = m.providerFilter
			}
			filterLine2 += "  " + SelectedStyle.Render("0:"+displayName)
		} else {
			filterLine2 += MutedStyle.Render("  0:Provider")
		}
	}
	b.WriteString(filterLine2 + "\n")

	// Search query
	if m.query != "" {
		b.WriteString("  " + MutedStyle.Render("Search: ") + m.query + "\n")
	}
	b.WriteString("\n")

	// Sort message (temporary feedback)
	if m.sortMessage != "" {
		b.WriteString(SuccessStyle.Render("  "+m.sortMessage) + "\n")
	}

	// Calculate visible area
	height := m.height
	if height == 0 {
		height = 24
	}
	visibleHeight := height - 14
	if visibleHeight < 5 {
		visibleHeight = 15
	}

	// Scroll offset
	start := 0
	if m.cursor >= visibleHeight {
		start = m.cursor - visibleHeight + 1
	}
	end := start + visibleHeight
	if end > len(m.filtered) {
		end = len(m.filtered)
	}

	// Server list
	if len(m.filtered) == 0 {
		if len(m.servers) == 0 {
			switch m.mode {
			case BrowseMyServers:
				b.WriteString(MutedStyle.Render("  No servers configured.") + "\n")
				b.WriteString(MutedStyle.Render("  Import WireGuard configs to get started.") + "\n")
			case BrowseDynamic:
				b.WriteString(MutedStyle.Render("  No servers in cache.") + "\n")
				b.WriteString(MutedStyle.Render("  Go to Settings > Refresh Server List to download servers.") + "\n")
			}
		} else {
			b.WriteString(MutedStyle.Render("  No matches found.") + "\n")
		}
	} else {
		for i := start; i < end; i++ {
			item := m.filtered[i]

			cursor := "  "
			if i == m.cursor && m.focused {
				cursor = "> "
			}

			if item.invalid {
				line := cursor + "  " + item.display + ErrorStyle.Render(" [INVALID: "+item.errorMsg+"]")
				b.WriteString(line + "\n")
				continue
			}

			// Favorite star
			star := "  "
			if m.isFavoriteItem(item) {
				star = "★ "
			}

			// Latency indicator (color-coded)
			latencyStr := ""
			if item.latency > 0 {
				ms := item.latency.Milliseconds()
				latText := fmt.Sprintf(" [%dms]", ms)
				switch {
				case ms < 100:
					latencyStr = SuccessStyle.Render(latText)
				case ms <= 300:
					latencyStr = WarningStyle.Render(latText)
				default:
					latencyStr = ErrorStyle.Render(latText)
				}
			}

			line := cursor + star + item.display + latencyStr
			if i == m.cursor && m.focused {
				line = SelectedStyle.Render(line)
			}

			b.WriteString(line + "\n")
		}
	}

	// Scroll indicator
	if len(m.filtered) > visibleHeight {
		b.WriteString(MutedStyle.Render(fmt.Sprintf("\n  %d/%d servers", m.cursor+1, len(m.filtered))))
	}

	// Preview panel
	if len(m.filtered) > 0 && m.cursor < len(m.filtered) && !m.filtered[m.cursor].invalid {
		item := m.filtered[m.cursor]
		b.WriteString("\n" + MutedStyle.Render("  ─────────────────────────────────") + "\n")

		previewParts := m.buildPreview(item)
		for _, part := range previewParts {
			// Color the label portion (before the colon) with accent
			if idx := strings.Index(part, ": "); idx >= 0 {
				label := part[:idx+1]
				value := part[idx+1:]
				b.WriteString("  " + accentStyle().Render(label) + value + "\n")
			} else {
				// No colon — items like "★ Favorite"
				b.WriteString("  " + accentStyle().Render(part) + "\n")
			}
		}
	}

	// Help
	b.WriteString("\n" + MutedStyle.Render("  enter: connect  ↑↓: navigate  type to search  esc: clear"))

	result := b.String()
	if m.height > 0 {
		result = TruncateLines(result, m.height)
	}
	return result
}

// --- Shared helper methods ---

// itemKey returns a unique string key for any item.
func (m *ServerBrowser) itemKey(item browserItem) string {
	if item.providerServer != nil {
		return item.providerServer.Name()
	}
	if item.isDynamic {
		return "dynamic:" + item.dynamicProvider + ":" + item.dynamicName
	}
	if item.manualServer != nil {
		return item.manualServer.Config.Name
	}
	return item.display
}

// itemDisplayName returns a short name suitable for confirmation prompts.
func (m *ServerBrowser) itemDisplayName(item browserItem) string {
	if item.providerServer != nil {
		return item.providerServer.Name()
	}
	if item.isDynamic {
		return item.dynamicName
	}
	if item.manualServer != nil {
		return item.manualServer.Config.Name
	}
	return item.display
}

// serverCountry returns country for sorting dynamic items.
func (m *ServerBrowser) serverCountry(item browserItem) string {
	if item.providerServer != nil {
		return item.providerServer.Country
	}
	return ""
}

// connectCmd returns a tea.Cmd that emits SwitchViewMsg for the given item.
func (m *ServerBrowser) connectCmd(item browserItem) tea.Cmd {
	if item.providerServer != nil {
		return func() tea.Msg {
			return SwitchViewMsg{
				View:     "connect-progress",
				Server:   item.providerServer.Name(),
				Provider: item.providerName,
				Dynamic:  true,
			}
		}
	}
	if item.isDynamic {
		return func() tea.Msg {
			return SwitchViewMsg{
				View:     "connect-progress",
				Server:   item.dynamicName,
				Provider: item.dynamicProvider,
				Dynamic:  true,
			}
		}
	}
	if item.manualServer != nil {
		name := item.manualServer.Config.Name
		return func() tea.Msg {
			return SwitchViewMsg{
				View:   "connect-progress",
				Server: name,
			}
		}
	}
	return nil
}

// isFavoriteItem checks whether an item is favorited.
func (m *ServerBrowser) isFavoriteItem(item browserItem) bool {
	// MyServers items carry their own favorite flag
	if m.mode == BrowseMyServers {
		return item.favorite
	}
	// Dynamic items: check cfg.Favorites
	if item.providerServer != nil {
		favKey := "dynamic:" + item.providerName + ":" + item.providerServer.Name()
		for _, f := range m.cfg.Favorites {
			if f == favKey {
				return true
			}
		}
	}
	return false
}

// filterServers applies provider filter, feature filters, and fuzzy search.
func (m *ServerBrowser) filterServers() {
	filtered := m.servers

	// Provider filter (dynamic mode only)
	if m.mode == BrowseDynamic && m.providerFilter != "" {
		newFiltered := make([]browserItem, 0)
		for _, item := range filtered {
			if item.providerName == m.providerFilter {
				newFiltered = append(newFiltered, item)
			}
		}
		filtered = newFiltered
	}

	// Feature filters (AND logic)
	if m.filterP2P || m.filterTor || m.filterSecureCore || m.filterStream || m.filterFree {
		newFiltered := make([]browserItem, 0)
		for _, item := range filtered {
			if m.filterP2P && !item.portForward {
				continue
			}
			if m.filterTor && !item.tor {
				continue
			}
			if m.filterSecureCore && !item.secureCore {
				continue
			}
			if m.filterStream && !item.stream {
				continue
			}
			if m.filterFree && !item.free {
				continue
			}
			newFiltered = append(newFiltered, item)
		}
		filtered = newFiltered
	}

	// Fuzzy search
	if m.query != "" {
		var names []string
		for _, s := range filtered {
			names = append(names, s.display)
		}
		matches := fuzzy.Find(m.query, names)
		newFiltered := make([]browserItem, 0, len(matches))
		for _, match := range matches {
			newFiltered = append(newFiltered, filtered[match.Index])
		}
		filtered = newFiltered
	}

	m.filtered = filtered
	if m.cursor >= len(m.filtered) {
		m.cursor = 0
	}
}

// sortServers sorts filtered by latency (unmeasured go to end).
func (m *ServerBrowser) sortServers() {
	sort.Slice(m.filtered, func(i, j int) bool {
		if m.filtered[i].latency == 0 && m.filtered[j].latency == 0 {
			return strings.ToLower(m.filtered[i].display) < strings.ToLower(m.filtered[j].display)
		}
		if m.filtered[i].latency == 0 {
			return false
		}
		if m.filtered[j].latency == 0 {
			return true
		}
		return m.filtered[i].latency < m.filtered[j].latency
	})
	m.cursor = 0
}

// determinePingFunc probes ICMP availability and returns the appropriate
// ping function. Returns nil if neither privileged nor unprivileged ICMP works.
func determinePingFunc() func(string) int {
	if probePing() {
		return pingServer
	}
	if probePingUnprivileged() {
		return pingServerUnprivileged
	}
	return nil
}

// measureLatency measures latency to all visible servers.
func (m *ServerBrowser) measureLatency() tea.Cmd {
	servers := make([]browserItem, len(m.filtered))
	copy(servers, m.filtered)

	cfgDir := m.cfg.ConfigDir

	return func() tea.Msg {
		if len(servers) == 0 {
			return BrowserLatencyMsg{Latencies: make(map[string]time.Duration)}
		}

		ping := determinePingFunc()
		if ping == nil {
			return BrowserPingAuthNeededMsg{forQuickConnect: false}
		}

		type latResult struct {
			key     string
			latency time.Duration
		}

		latencies := make(map[string]time.Duration)
		sem := make(chan struct{}, 50)
		resultChan := make(chan latResult, len(servers))
		var wg sync.WaitGroup
		cacheDir := filepath.Join(cfgDir, "cache")

		for _, item := range servers {
			if item.invalid {
				continue
			}
			wg.Add(1)
			go func(it browserItem) {
				defer wg.Done()

				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-time.After(3 * time.Second):
					return
				}

				var ip string
				if it.providerServer != nil {
					ip = it.providerServer.IP()
				} else if it.isDynamic {
					srvs, err := loadProviderServers(cacheDir, it.dynamicProvider)
					if err == nil {
						for _, s := range srvs {
							if s.Name() == it.dynamicName {
								ip = s.IP()
								break
							}
						}
					}
				} else if it.manualServer != nil {
					ip = it.manualServer.Config.EndpointIP()
				}

				if ip == "" {
					return
				}

				var key string
				if it.providerServer != nil {
					key = it.providerServer.Name()
				} else if it.isDynamic {
					key = "dynamic:" + it.dynamicProvider + ":" + it.dynamicName
				} else if it.manualServer != nil {
					key = it.manualServer.Config.Name
				}

				ms := ping(ip)
				if ms >= 0 {
					resultChan <- latResult{key, time.Duration(ms) * time.Millisecond}
				}
			}(item)
		}

		go func() {
			wg.Wait()
			close(resultChan)
		}()

		timeout := time.After(10 * time.Second)
		for {
			select {
			case result, ok := <-resultChan:
				if !ok {
					return BrowserLatencyMsg{Latencies: latencies}
				}
				if result.latency > 0 {
					latencies[result.key] = result.latency
				}
			case <-timeout:
				return BrowserLatencyMsg{Latencies: latencies}
			}
		}
	}
}

// measureLatencyThenConnect measures latency and returns a quick-connect message for the best server.
func (m *ServerBrowser) measureLatencyThenConnect() tea.Cmd {
	servers := make([]browserItem, len(m.filtered))
	copy(servers, m.filtered)

	cfgDir := m.cfg.ConfigDir

	return func() tea.Msg {
		if len(servers) == 0 {
			return BrowserLatencyMsg{Latencies: make(map[string]time.Duration)}
		}

		ping := determinePingFunc()
		if ping == nil {
			return BrowserPingAuthNeededMsg{forQuickConnect: true}
		}

		type latResult struct {
			key       string
			provider  string
			isDynamic bool
			latency   time.Duration
		}

		sem := make(chan struct{}, 50)
		resultChan := make(chan latResult, len(servers))
		cacheDir := filepath.Join(cfgDir, "cache")
		var wg sync.WaitGroup

		for _, item := range servers {
			if item.invalid {
				continue
			}
			wg.Add(1)
			go func(it browserItem) {
				defer wg.Done()

				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-time.After(3 * time.Second):
					return
				}

				var ip, key, prov string
				isDyn := false

				if it.providerServer != nil {
					ip = it.providerServer.IP()
					key = it.providerServer.Name()
					prov = it.providerName
					isDyn = true
				} else if it.isDynamic {
					srvs, err := loadProviderServers(cacheDir, it.dynamicProvider)
					if err == nil {
						for _, s := range srvs {
							if s.Name() == it.dynamicName {
								ip = s.IP()
								break
							}
						}
					}
					key = "dynamic:" + it.dynamicProvider + ":" + it.dynamicName
					prov = it.dynamicProvider
					isDyn = true
				} else if it.manualServer != nil {
					ip = it.manualServer.Config.EndpointIP()
					key = it.manualServer.Config.Name
				}

				if ip == "" {
					return
				}

				ms := ping(ip)
				if ms >= 0 {
					resultChan <- latResult{key, prov, isDyn, time.Duration(ms) * time.Millisecond}
				}
			}(item)
		}

		go func() {
			wg.Wait()
			close(resultChan)
		}()

		latencies := make(map[string]time.Duration)
		var bestKey, bestProvider string
		var bestDynamic bool
		var bestLatency time.Duration
		timeout := time.After(10 * time.Second)
	collectLoop:
		for {
			select {
			case result, ok := <-resultChan:
				if !ok {
					break collectLoop
				}
				if result.latency > 0 {
					latencies[result.key] = result.latency
					if bestKey == "" || result.latency < bestLatency {
						bestKey = result.key
						bestProvider = result.provider
						bestDynamic = result.isDynamic
						bestLatency = result.latency
					}
				}
			case <-timeout:
				break collectLoop
			}
		}

		if bestKey != "" {
			return BrowserQuickConnectMsg{ServerName: bestKey, Provider: bestProvider, IsDynamic: bestDynamic}
		}

		return BrowserLatencyMsg{Latencies: latencies}
	}
}

// toggleFavorite toggles the favorite status of the item at the given filtered index.
func (m *ServerBrowser) toggleFavorite(idx int) {
	if idx >= len(m.filtered) {
		return
	}
	item := m.filtered[idx]

	if m.mode == BrowseDynamic {
		// Dynamic browser: toggle in cfg.Favorites
		if item.providerServer == nil {
			return
		}
		favKey := "dynamic:" + item.providerName + ":" + item.providerServer.Name()
		isFav := false
		for _, f := range m.cfg.Favorites {
			if f == favKey {
				isFav = true
				break
			}
		}
		// Snapshot previous Favorites for revert-on-Save-failure. Deep-copy
		// because append may share the underlying array — modifying the
		// slice header would otherwise still mutate the snapshot.
		prev := append([]string(nil), m.cfg.Favorites...)
		if isFav {
			newFavs := make([]string, 0)
			for _, f := range m.cfg.Favorites {
				if f != favKey {
					newFavs = append(newFavs, f)
				}
			}
			m.cfg.Favorites = newFavs
		} else {
			m.cfg.Favorites = append(m.cfg.Favorites, favKey)
		}
		if err := m.cfg.Save(); err != nil {
			m.cfg.Favorites = prev
		}
		return
	}

	// MyServers mode
	if item.isDynamic {
		favKey := "dynamic:" + item.dynamicProvider + ":" + item.dynamicName
		newFav := !item.favorite

		m.filtered[idx].favorite = newFav
		for i := range m.servers {
			if m.servers[i].isDynamic && m.servers[i].dynamicProvider == item.dynamicProvider && m.servers[i].dynamicName == item.dynamicName {
				m.servers[i].favorite = newFav
				break
			}
		}

		prev := append([]string(nil), m.cfg.Favorites...)
		if newFav {
			m.cfg.Favorites = append(m.cfg.Favorites, favKey)
		} else {
			newFavs := make([]string, 0)
			for _, f := range m.cfg.Favorites {
				if f != favKey {
					newFavs = append(newFavs, f)
				}
			}
			m.cfg.Favorites = newFavs
		}
		if err := m.cfg.Save(); err != nil {
			// Disk save failed — revert cfg.Favorites to keep in-memory
			// consistent with disk. m.servers[i].favorite and
			// m.filtered[idx].favorite (per-row UI state) are left
			// reflecting the user's attempted toggle so the visual
			// feedback isn't ripped away mid-interaction; they'll
			// reconcile on next refresh.
			m.cfg.Favorites = prev
		}
		return
	}

	if item.manualServer == nil {
		return
	}
	serverName := item.manualServer.Config.Name

	for i := range m.servers {
		if !m.servers[i].isDynamic && m.servers[i].manualServer != nil && m.servers[i].manualServer.Config.Name == serverName {
			m.servers[i].favorite = !m.servers[i].favorite
			m.filtered[idx].favorite = m.servers[i].favorite

			prev := append([]string(nil), m.cfg.Favorites...)
			if m.servers[i].favorite {
				m.cfg.Favorites = append(m.cfg.Favorites, serverName)
			} else {
				newFavs := make([]string, 0)
				for _, f := range m.cfg.Favorites {
					if f != serverName {
						newFavs = append(newFavs, f)
					}
				}
				m.cfg.Favorites = newFavs
			}
			if err := m.cfg.Save(); err != nil {
				m.cfg.Favorites = prev
			}
			break
		}
	}
}

// buildPreview builds the detail preview lines for the highlighted item.
func (m *ServerBrowser) buildPreview(item browserItem) []string {
	var parts []string

	if item.providerServer != nil {
		// Dynamic server from provider cache
		srv := item.providerServer
		if srv.Country != "" {
			parts = append(parts, fmt.Sprintf("Country: %s", srv.Country))
		}
		if srv.City != "" {
			parts = append(parts, fmt.Sprintf("City: %s", srv.City))
		}
		if ip := srv.IP(); ip != "" {
			parts = append(parts, fmt.Sprintf("IP: %s", ip))
		}
		var features []string
		if srv.PortForward {
			features = append(features, "P2P")
		}
		if srv.Tor {
			features = append(features, "Tor")
		}
		if srv.SecureCore {
			features = append(features, "Secure Core")
		}
		if srv.Stream {
			features = append(features, "Streaming")
		}
		if srv.Free {
			features = append(features, "Free")
		}
		if len(features) > 0 {
			parts = append(parts, fmt.Sprintf("Features: %s", strings.Join(features, ", ")))
		}
	} else if item.isDynamic {
		// Favorited dynamic server in MyServers mode
		cacheDir := filepath.Join(m.cfg.ConfigDir, "cache")
		servers, err := loadProviderServers(cacheDir, item.dynamicProvider)
		if err == nil {
			for _, srv := range servers {
				if srv.Name() == item.dynamicName {
					if srv.Country != "" {
						parts = append(parts, fmt.Sprintf("Country: %s", srv.Country))
					}
					if srv.City != "" {
						parts = append(parts, fmt.Sprintf("City: %s", srv.City))
					}
					if ip := srv.IP(); ip != "" {
						parts = append(parts, fmt.Sprintf("IP: %s", ip))
					}
					var features []string
					if srv.PortForward {
						features = append(features, "P2P")
					}
					if srv.Tor {
						features = append(features, "Tor")
					}
					if srv.SecureCore {
						features = append(features, "Secure Core")
					}
					if srv.Stream {
						features = append(features, "Streaming")
					}
					if srv.Free {
						features = append(features, "Free")
					}
					if len(features) > 0 {
						parts = append(parts, fmt.Sprintf("Features: %s", strings.Join(features, ", ")))
					}
					break
				}
			}
		}
		displayProv := provider.ProviderDisplayNames[item.dynamicProvider]
		if displayProv == "" {
			displayProv = item.dynamicProvider
		}
		parts = append(parts, fmt.Sprintf("Provider: %s (dynamic)", displayProv))
	} else if item.manualServer != nil {
		// Manual .conf server
		info := item.manualServer.Info
		if info.Country != "" && info.Country != "Unknown" {
			parts = append(parts, fmt.Sprintf("Country: %s", util.ExpandCountryName(info.Country)))
		}
		if info.State != "" {
			parts = append(parts, fmt.Sprintf("State: %s", util.ExpandLocationName(info.State)))
		}
		if info.City != "" {
			parts = append(parts, fmt.Sprintf("City: %s", util.ExpandLocationName(info.City)))
		}
		if item.manualServer.Config.Endpoint != "" {
			parts = append(parts, fmt.Sprintf("Endpoint: %s", item.manualServer.Config.Endpoint))
		}
		if item.manualServer.Config.DNS != "" {
			parts = append(parts, fmt.Sprintf("DNS: %s", item.manualServer.Config.DNS))
		}
		if len(info.Services) > 0 {
			features := append([]string{}, info.Services...)
			parts = append(parts, fmt.Sprintf("Features: %s", strings.Join(features, ", ")))
		}
		if info.Provider != "" {
			parts = append(parts, fmt.Sprintf("Provider: %s", info.Provider))
		}
	}

	// Latency
	if item.latency > 0 {
		parts = append(parts, fmt.Sprintf("Latency: %dms", item.latency.Milliseconds()))
	}

	// Favorite status
	if m.isFavoriteItem(item) {
		parts = append(parts, "★ Favorite")
	}

	return parts
}

// --- Format helpers ---

// formatProviderServer formats a provider.Server for display (no provider suffix).
func formatProviderServer(srv provider.Server) string {
	var parts []string

	countryCode := ""
	name := srv.Name()
	if len(name) >= 2 && name[0] >= 'A' && name[0] <= 'Z' && name[1] >= 'A' && name[1] <= 'Z' {
		countryCode = name[:2]
	}

	flag := ""
	if countryCode != "" {
		flag = util.CountryFlag(countryCode)
	}

	if srv.SecureCore && len(name) >= 5 && name[2] == '-' {
		entryCode := name[:2]
		exitCode := name[3:5]
		entryFlag := util.CountryFlag(entryCode)
		exitFlag := util.CountryFlag(exitCode)
		entryName := util.ExpandCountryName(entryCode)
		parts = append(parts, entryFlag, entryName, "→", exitFlag, srv.Country)
	} else {
		if flag != "" {
			parts = append(parts, flag)
		}
		parts = append(parts, srv.Country)
	}

	if srv.City != "" {
		parts = append(parts, "-", srv.City)
	}

	parts = append(parts, fmt.Sprintf("(%s)", srv.Name()))

	var features string
	if srv.PortForward {
		features += "🔄"
	}
	if srv.Tor {
		features += "🧅"
	}
	if srv.SecureCore {
		features += "🔒"
	}
	if srv.Stream {
		features += "📺"
	}
	if srv.Free {
		features += "🤡"
	}
	if features != "" {
		parts = append(parts, features)
	}

	return strings.Join(parts, " ")
}

// formatDynamicDisplay formats a dynamic server with provider suffix (for MyServers favorited dynamics).
func formatDynamicDisplay(srv provider.Server, provName string) string {
	result := formatProviderServer(srv)
	displayProv := provider.ProviderDisplayNames[provName]
	if displayProv == "" {
		displayProv = provName
	}
	return result + " • " + displayProv
}

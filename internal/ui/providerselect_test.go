package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	"github.com/blank-query/lazyVPN-for-Omarchy/internal/provider"
	tea "github.com/charmbracelet/bubbletea"
)

func TestProviderSelectInit(t *testing.T) {
	ps := &ProviderSelect{cfg: &config.Config{}}
	if ps.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestProviderSelectEsc(t *testing.T) {
	ps := &ProviderSelect{cfg: &config.Config{}}
	_, cmd := ps.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestProviderSelectCursorNavigation(t *testing.T) {
	ps := &ProviderSelect{
		cfg: &config.Config{},
		providers: []providerItem{
			{name: "protonvpn", displayName: "ProtonVPN"},
			{name: "mullvad", displayName: "Mullvad"},
			{name: "ivpn", displayName: "IVPN"},
		},
	}

	model, _ := ps.Update(tea.KeyMsg{Type: tea.KeyDown})
	ps = model.(*ProviderSelect)
	if ps.cursor != 1 {
		t.Errorf("cursor = %d, want 1", ps.cursor)
	}

	model, _ = ps.Update(tea.KeyMsg{Type: tea.KeyDown})
	ps = model.(*ProviderSelect)
	if ps.cursor != 2 {
		t.Errorf("cursor = %d, want 2", ps.cursor)
	}

	// Clamp at end
	model, _ = ps.Update(tea.KeyMsg{Type: tea.KeyDown})
	ps = model.(*ProviderSelect)
	if ps.cursor != 2 {
		t.Errorf("cursor = %d, want 2 (clamped)", ps.cursor)
	}

	model, _ = ps.Update(tea.KeyMsg{Type: tea.KeyUp})
	ps = model.(*ProviderSelect)
	if ps.cursor != 1 {
		t.Errorf("cursor = %d, want 1", ps.cursor)
	}

	// arrow keys (continued)
	model, _ = ps.Update(tea.KeyMsg{Type: tea.KeyUp})
	ps = model.(*ProviderSelect)
	if ps.cursor != 0 {
		t.Errorf("cursor = %d, want 0", ps.cursor)
	}

	model, _ = ps.Update(tea.KeyMsg{Type: tea.KeyDown})
	ps = model.(*ProviderSelect)
	if ps.cursor != 1 {
		t.Errorf("cursor = %d, want 1", ps.cursor)
	}
}

func TestProviderSelectEnter(t *testing.T) {
	ps := &ProviderSelect{
		cfg: &config.Config{},
		providers: []providerItem{
			{name: "protonvpn", displayName: "ProtonVPN"},
			{name: "mullvad", displayName: "Mullvad"},
		},
		cursor: 1,
	}

	_, cmd := ps.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter should return cmd")
	}
	msg := cmd()
	sv, ok := msg.(SwitchViewMsg)
	if !ok {
		t.Fatalf("expected SwitchViewMsg, got %T", msg)
	}
	if sv.View != "dynamic-browser" {
		t.Errorf("View = %q, want dynamic-browser", sv.View)
	}
	if sv.Provider != "mullvad" {
		t.Errorf("Provider = %q, want mullvad", sv.Provider)
	}
}

func TestProviderSelectEnterEmpty(t *testing.T) {
	ps := &ProviderSelect{cfg: &config.Config{}}
	_, cmd := ps.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Error("enter on empty list should not return cmd")
	}
}

func TestProviderSelectSelected(t *testing.T) {
	ps := &ProviderSelect{
		cfg: &config.Config{},
		providers: []providerItem{
			{name: "protonvpn", displayName: "ProtonVPN"},
			{name: "mullvad", displayName: "Mullvad"},
		},
		cursor: 1,
	}

	if ps.Selected() != "mullvad" {
		t.Errorf("Selected() = %q, want mullvad", ps.Selected())
	}
}

func TestProviderSelectSelectedEmpty(t *testing.T) {
	ps := &ProviderSelect{cfg: &config.Config{}}
	if ps.Selected() != "" {
		t.Errorf("Selected() = %q, want empty", ps.Selected())
	}
}

func TestProviderSelectWindowSize(t *testing.T) {
	ps := &ProviderSelect{cfg: &config.Config{}}
	model, _ := ps.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	ps = model.(*ProviderSelect)
	if ps.width != 100 || ps.height != 30 {
		t.Errorf("size = %dx%d, want 100x30", ps.width, ps.height)
	}
}

func TestProviderSelectViewEmpty(t *testing.T) {
	ps := &ProviderSelect{cfg: &config.Config{}}
	view := ps.View()
	if !strings.Contains(view, "Select Provider") {
		t.Error("should contain title")
	}
	if !strings.Contains(view, "No providers configured") {
		t.Error("should show empty message")
	}
}

func TestProviderSelectViewWithProviders(t *testing.T) {
	ps := &ProviderSelect{
		cfg: &config.Config{},
		providers: []providerItem{
			{name: "protonvpn", displayName: "ProtonVPN", serverCount: 500},
			{name: "mullvad", displayName: "Mullvad", serverCount: 0},
		},
	}
	view := ps.View()
	if !strings.Contains(view, "ProtonVPN") {
		t.Error("should show provider name")
	}
	if !strings.Contains(view, "500 servers") {
		t.Error("should show server count")
	}
	if !strings.Contains(view, "Mullvad") {
		t.Error("should show second provider")
	}
}

func TestNewProviderSelectWithProviders(t *testing.T) {
	dir := t.TempDir()
	provDir := filepath.Join(dir, "providers")
	os.MkdirAll(provDir, 0700)

	// Create provider config file
	os.WriteFile(filepath.Join(provDir, "protonvpn.json"), []byte(`{"private_key":"test","address":"10.2.0.2/32","dns":"10.2.0.1"}`), 0600)

	// Create cache file with servers
	cacheDir := filepath.Join(dir, "cache")
	os.MkdirAll(cacheDir, 0700)
	servers := []provider.Server{
		{ServerName: "US#1", Country: "US", IPs: []string{"1.1.1.1"}},
		{ServerName: "SE#2", Country: "SE", IPs: []string{"2.2.2.2"}},
	}
	data, _ := json.Marshal(servers)
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), data, 0600)

	cfg := &config.Config{ConfigDir: dir}
	ps := NewProviderSelect(cfg)

	if len(ps.providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(ps.providers))
	}
	if ps.providers[0].name != "protonvpn" {
		t.Errorf("provider name = %q, want protonvpn", ps.providers[0].name)
	}
	if ps.providers[0].displayName != "ProtonVPN" {
		t.Errorf("displayName = %q, want ProtonVPN", ps.providers[0].displayName)
	}
	if ps.providers[0].serverCount != 2 {
		t.Errorf("serverCount = %d, want 2", ps.providers[0].serverCount)
	}
}

func TestNewProviderSelectNoProviders(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{ConfigDir: dir}
	ps := NewProviderSelect(cfg)

	if len(ps.providers) != 0 {
		t.Errorf("providers = %d, want 0", len(ps.providers))
	}
}

func TestNewProviderSelectUnknownProvider(t *testing.T) {
	dir := t.TempDir()
	provDir := filepath.Join(dir, "providers")
	os.MkdirAll(provDir, 0700)

	// Create unknown provider
	os.WriteFile(filepath.Join(provDir, "customprov.json"), []byte(`{"private_key":"test","address":"10.2.0.2/32"}`), 0600)

	cfg := &config.Config{ConfigDir: dir}
	ps := NewProviderSelect(cfg)

	if len(ps.providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(ps.providers))
	}
	// Unknown provider should use raw name as display name
	if ps.providers[0].displayName != "customprov" {
		t.Errorf("displayName = %q, want customprov", ps.providers[0].displayName)
	}
	if ps.providers[0].serverCount != 0 {
		t.Errorf("serverCount = %d, want 0 (no cache)", ps.providers[0].serverCount)
	}
}

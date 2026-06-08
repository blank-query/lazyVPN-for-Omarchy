package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

func TestRemoveProviderCleanupFavorites(t *testing.T) {
	t.Run("removes dynamic favorites for deleted provider", func(t *testing.T) {
		cfg := &config.Config{
			Favorites: []string{
				"manual-server",
				"dynamic:protonvpn:US-NY#42",
				"dynamic:mullvad:SE#5",
				"dynamic:protonvpn:DE#10",
			},
		}
		rp := &RemoveProvider{cfg: cfg}

		rp.cleanupFavorites([]string{"protonvpn"})

		if len(cfg.Favorites) != 2 {
			t.Fatalf("expected 2 favorites, got %d: %v", len(cfg.Favorites), cfg.Favorites)
		}
		if cfg.Favorites[0] != "manual-server" {
			t.Errorf("[0] = %q", cfg.Favorites[0])
		}
		if cfg.Favorites[1] != "dynamic:mullvad:SE#5" {
			t.Errorf("[1] = %q", cfg.Favorites[1])
		}
	})

	t.Run("removes multiple providers", func(t *testing.T) {
		cfg := &config.Config{
			Favorites: []string{
				"dynamic:protonvpn:US#1",
				"dynamic:mullvad:SE#5",
				"manual-server",
			},
		}
		rp := &RemoveProvider{cfg: cfg}

		rp.cleanupFavorites([]string{"protonvpn", "mullvad"})

		if len(cfg.Favorites) != 1 {
			t.Fatalf("expected 1 favorite, got %d: %v", len(cfg.Favorites), cfg.Favorites)
		}
		if cfg.Favorites[0] != "manual-server" {
			t.Errorf("[0] = %q", cfg.Favorites[0])
		}
	})

	t.Run("keeps all when no match", func(t *testing.T) {
		cfg := &config.Config{
			Favorites: []string{
				"manual-server",
				"dynamic:mullvad:SE#5",
			},
		}
		rp := &RemoveProvider{cfg: cfg}

		rp.cleanupFavorites([]string{"protonvpn"})

		if len(cfg.Favorites) != 2 {
			t.Errorf("expected 2 favorites unchanged, got %d", len(cfg.Favorites))
		}
	})

	t.Run("handles malformed dynamic entries", func(t *testing.T) {
		cfg := &config.Config{
			Favorites: []string{
				"dynamic:bad",
				"dynamic:protonvpn:US#1",
			},
		}
		rp := &RemoveProvider{cfg: cfg}

		rp.cleanupFavorites([]string{"protonvpn"})

		if len(cfg.Favorites) != 1 {
			t.Fatalf("expected 1 favorite, got %d: %v", len(cfg.Favorites), cfg.Favorites)
		}
		if cfg.Favorites[0] != "dynamic:bad" {
			t.Errorf("[0] = %q", cfg.Favorites[0])
		}
	})

	t.Run("empty favorites", func(t *testing.T) {
		cfg := &config.Config{}
		rp := &RemoveProvider{cfg: cfg}

		rp.cleanupFavorites([]string{"protonvpn"})
		// Should not panic or modify
	})
}

func TestRemoveProviderUpdate(t *testing.T) {
	t.Run("esc returns back", func(t *testing.T) {
		rp := &RemoveProvider{
			cfg: &config.Config{},
			providers: []providerToRemove{
				{name: "protonvpn", display: "ProtonVPN"},
			},
		}
		_, cmd := rp.Update(tea.KeyMsg{Type: tea.KeyEscape})
		if cmd == nil {
			t.Fatal("esc should return cmd")
		}
		msg := cmd()
		if _, ok := msg.(BackMsg); !ok {
			t.Errorf("expected BackMsg, got %T", msg)
		}
	})

	t.Run("cursor navigation", func(t *testing.T) {
		rp := &RemoveProvider{
			cfg: &config.Config{},
			providers: []providerToRemove{
				{name: "a", display: "A"},
				{name: "b", display: "B"},
				{name: "c", display: "C"},
			},
		}

		model, _ := rp.Update(tea.KeyMsg{Type: tea.KeyDown})
		rp = model.(*RemoveProvider)
		if rp.cursor != 1 {
			t.Errorf("cursor = %d, want 1", rp.cursor)
		}

		model, _ = rp.Update(tea.KeyMsg{Type: tea.KeyDown})
		rp = model.(*RemoveProvider)
		if rp.cursor != 2 {
			t.Errorf("cursor = %d, want 2", rp.cursor)
		}

		// Should not go past last
		model, _ = rp.Update(tea.KeyMsg{Type: tea.KeyDown})
		rp = model.(*RemoveProvider)
		if rp.cursor != 2 {
			t.Errorf("cursor = %d, want 2 (clamped)", rp.cursor)
		}

		model, _ = rp.Update(tea.KeyMsg{Type: tea.KeyUp})
		rp = model.(*RemoveProvider)
		if rp.cursor != 1 {
			t.Errorf("cursor = %d, want 1", rp.cursor)
		}
	})

	t.Run("toggle selection", func(t *testing.T) {
		rp := &RemoveProvider{
			cfg: &config.Config{},
			providers: []providerToRemove{
				{name: "a", display: "A"},
			},
		}

		// Space toggles selection.
		model, _ := rp.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
		rp = model.(*RemoveProvider)
		if !rp.providers[0].selected {
			t.Error("should be selected after space")
		}

		model, _ = rp.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
		rp = model.(*RemoveProvider)
		if rp.providers[0].selected {
			t.Error("should be deselected after second space")
		}

		// Tab is reserved for pane-switching at the dashboard level —
		// must NOT toggle the checkbox here.
		model, _ = rp.Update(tea.KeyMsg{Type: tea.KeyTab})
		rp = model.(*RemoveProvider)
		if rp.providers[0].selected {
			t.Error("tab should not toggle selection (reserved for pane switch)")
		}
	})

	t.Run("enter with no selection selects current and enters confirm", func(t *testing.T) {
		rp := &RemoveProvider{
			cfg: &config.Config{},
			providers: []providerToRemove{
				{name: "a", display: "A"},
				{name: "b", display: "B"},
			},
		}

		model, _ := rp.Update(tea.KeyMsg{Type: tea.KeyEnter})
		rp = model.(*RemoveProvider)
		if !rp.providers[0].selected {
			t.Error("enter should auto-select current item")
		}
		if !rp.confirmMode {
			t.Error("should enter confirm mode")
		}
	})

	t.Run("confirm mode cancel", func(t *testing.T) {
		rp := &RemoveProvider{
			cfg:         &config.Config{},
			confirmMode: true,
			providers: []providerToRemove{
				{name: "a", display: "A", selected: true},
			},
		}

		model, _ := rp.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
		rp = model.(*RemoveProvider)
		if rp.confirmMode {
			t.Error("n should cancel confirm mode")
		}
	})

	t.Run("window size", func(t *testing.T) {
		rp := &RemoveProvider{cfg: &config.Config{}}
		model, _ := rp.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
		rp = model.(*RemoveProvider)
		if rp.width != 100 || rp.height != 30 {
			t.Errorf("size = %dx%d", rp.width, rp.height)
		}
	})
}

func TestRemoveProviderView(t *testing.T) {
	t.Run("empty providers", func(t *testing.T) {
		rp := &RemoveProvider{cfg: &config.Config{}}
		view := rp.View()
		if !strings.Contains(view, "No providers configured") {
			t.Error("should show empty message")
		}
	})

	t.Run("with providers", func(t *testing.T) {
		rp := &RemoveProvider{
			cfg: &config.Config{},
			providers: []providerToRemove{
				{name: "protonvpn", display: "ProtonVPN"},
				{name: "mullvad", display: "Mullvad"},
			},
		}
		view := rp.View()
		if !strings.Contains(view, "Remove Provider") {
			t.Error("should contain title")
		}
		if !strings.Contains(view, "ProtonVPN") {
			t.Error("should show provider name")
		}
	})

	t.Run("confirm mode", func(t *testing.T) {
		rp := &RemoveProvider{
			cfg:         &config.Config{},
			confirmMode: true,
			providers: []providerToRemove{
				{name: "protonvpn", display: "ProtonVPN", selected: true},
			},
		}
		view := rp.View()
		if !strings.Contains(view, "Delete") {
			t.Error("should show delete confirmation")
		}
		if !strings.Contains(view, "ProtonVPN") {
			t.Error("should list provider to delete")
		}
	})

	t.Run("with message", func(t *testing.T) {
		rp := &RemoveProvider{
			cfg:     &config.Config{},
			message: "Removed 1 provider(s)",
			providers: []providerToRemove{
				{name: "mullvad", display: "Mullvad"},
			},
		}
		view := rp.View()
		if !strings.Contains(view, "Removed 1 provider(s)") {
			t.Error("should show success message")
		}
	})
}

func TestRemoveProviderInit(t *testing.T) {
	rp := &RemoveProvider{cfg: &config.Config{}}
	if rp.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestRemoveProviderSpaceToggle(t *testing.T) {
	rp := &RemoveProvider{
		cfg: &config.Config{},
		providers: []providerToRemove{
			{name: "a", display: "A"},
		},
	}

	model, _ := rp.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	rp = model.(*RemoveProvider)
	if !rp.providers[0].selected {
		t.Error("space should toggle selection")
	}
}

func TestRemoveProviderDKeyEntersConfirm(t *testing.T) {
	rp := &RemoveProvider{
		cfg: &config.Config{},
		providers: []providerToRemove{
			{name: "a", display: "A"},
		},
	}

	model, _ := rp.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	rp = model.(*RemoveProvider)
	if !rp.confirmMode {
		t.Error("d should enter confirm mode")
	}
}

func TestRemoveProviderConfirmYes(t *testing.T) {
	rp := &RemoveProvider{
		cfg:         &config.Config{},
		confirmMode: true,
		providers: []providerToRemove{
			{name: "protonvpn", display: "ProtonVPN", selected: true},
		},
	}

	_, cmd := rp.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if cmd == nil {
		t.Fatal("y in confirm should return cmd")
	}
}

func TestRemoveProviderConfirmEsc(t *testing.T) {
	rp := &RemoveProvider{
		cfg:         &config.Config{},
		confirmMode: true,
		providers: []providerToRemove{
			{name: "a", display: "A", selected: true},
		},
	}

	model, _ := rp.Update(tea.KeyMsg{Type: tea.KeyEscape})
	rp = model.(*RemoveProvider)
	if rp.confirmMode {
		t.Error("esc should cancel confirm mode")
	}
}

func TestRemoveProviderConfirmIgnoresOtherKeys(t *testing.T) {
	rp := &RemoveProvider{
		cfg:         &config.Config{},
		confirmMode: true,
		providers: []providerToRemove{
			{name: "a", display: "A", selected: true},
		},
	}

	model, cmd := rp.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	rp = model.(*RemoveProvider)
	if !rp.confirmMode {
		t.Error("other keys should not cancel confirm mode")
	}
	if cmd != nil {
		t.Error("other keys should return nil cmd")
	}
}

func TestRemoveProviderDoneMsgReloads(t *testing.T) {
	cfg := &config.Config{ConfigDir: t.TempDir()}
	rp := &RemoveProvider{
		cfg: cfg,
		providers: []providerToRemove{
			{name: "protonvpn", display: "ProtonVPN", selected: true},
		},
	}

	model, _ := rp.Update(removeProviderDoneMsg{removed: 1, deletedNames: []string{"protonvpn"}})
	rp = model.(*RemoveProvider)

	if rp.message != "Removed 1 provider(s)" {
		t.Errorf("message = %q", rp.message)
	}
	if rp.cursor != 0 {
		t.Errorf("cursor = %d, should be reset to 0", rp.cursor)
	}
}

func TestRemoveProviderDoneMsgSkippedConnected(t *testing.T) {
	cfg := &config.Config{ConfigDir: t.TempDir()}
	rp := &RemoveProvider{cfg: cfg}

	model, _ := rp.Update(removeProviderDoneMsg{removed: 0, skippedConnected: true})
	rp = model.(*RemoveProvider)

	if !strings.Contains(rp.message, "skipped") {
		t.Errorf("message = %q, should mention skipped", rp.message)
	}
}

func TestRemoveProviderDoneMsgEmptyProviders(t *testing.T) {
	cfg := &config.Config{ConfigDir: t.TempDir()}
	rp := &RemoveProvider{cfg: cfg}

	_, cmd := rp.Update(removeProviderDoneMsg{removed: 1, deletedNames: []string{"protonvpn"}})
	if cmd == nil {
		t.Fatal("should return BackMsg when no providers left")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestRemoveProviderEnterWithSelectedProviders(t *testing.T) {
	rp := &RemoveProvider{
		cfg: &config.Config{},
		providers: []providerToRemove{
			{name: "a", display: "A", selected: true},
			{name: "b", display: "B"},
		},
	}

	model, _ := rp.Update(tea.KeyMsg{Type: tea.KeyEnter})
	rp = model.(*RemoveProvider)
	if !rp.confirmMode {
		t.Error("enter with selected items should enter confirm mode")
	}
}

func TestRemoveProviderDoRemove(t *testing.T) {
	dir := t.TempDir()
	provDir := filepath.Join(dir, "providers")
	os.MkdirAll(provDir, 0700)
	cacheDir := filepath.Join(dir, "cache")
	os.MkdirAll(cacheDir, 0700)

	// Create provider config and cache files
	os.WriteFile(filepath.Join(provDir, "protonvpn.json"), []byte(`{"private_key":"test","address":"10.2.0.2/32"}`), 0600)
	os.WriteFile(filepath.Join(cacheDir, "protonvpn_servers.json"), []byte("[]"), 0600)

	cfg := &config.Config{
		ConfigDir:           dir,
		LastConnectedServer: "other-server",
	}

	rp := &RemoveProvider{
		cfg: cfg,
		providers: []providerToRemove{
			{name: "protonvpn", display: "ProtonVPN", selected: true},
		},
	}

	cmd := rp.doRemove()
	if cmd == nil {
		t.Fatal("doRemove should return cmd")
	}
	msg := cmd()
	done, ok := msg.(removeProviderDoneMsg)
	if !ok {
		t.Fatalf("expected removeProviderDoneMsg, got %T", msg)
	}
	if done.removed != 1 {
		t.Errorf("removed = %d, want 1", done.removed)
	}
	if done.skippedConnected {
		t.Error("should not have skipped connected")
	}
	if len(done.deletedNames) != 1 || done.deletedNames[0] != "protonvpn" {
		t.Errorf("deletedNames = %v, want [protonvpn]", done.deletedNames)
	}
}

func TestRemoveProviderDoRemoveSkipsConnected(t *testing.T) {
	dir := t.TempDir()
	provDir := filepath.Join(dir, "providers")
	os.MkdirAll(provDir, 0700)

	os.WriteFile(filepath.Join(provDir, "protonvpn.json"), []byte(`{"private_key":"test","address":"10.2.0.2/32"}`), 0600)

	cfg := &config.Config{
		ConfigDir:           dir,
		LastConnectedServer: "dynamic:protonvpn:US-NY#42",
	}

	rp := &RemoveProvider{
		cfg: cfg,
		providers: []providerToRemove{
			{name: "protonvpn", display: "ProtonVPN", selected: true},
		},
	}

	cmd := rp.doRemove()
	msg := cmd()
	done := msg.(removeProviderDoneMsg)
	if done.removed != 0 {
		t.Errorf("removed = %d, want 0 (connected provider should be skipped)", done.removed)
	}
	if !done.skippedConnected {
		t.Error("should have skipped connected provider")
	}
}

func TestRemoveProviderDoRemoveNoneSelected(t *testing.T) {
	cfg := &config.Config{ConfigDir: t.TempDir()}

	rp := &RemoveProvider{
		cfg: cfg,
		providers: []providerToRemove{
			{name: "protonvpn", display: "ProtonVPN", selected: false},
		},
	}

	cmd := rp.doRemove()
	msg := cmd()
	done := msg.(removeProviderDoneMsg)
	if done.removed != 0 {
		t.Errorf("removed = %d, want 0 (none selected)", done.removed)
	}
}

func TestNewRemoveProviderWithProviders(t *testing.T) {
	dir := t.TempDir()
	provDir := filepath.Join(dir, "providers")
	os.MkdirAll(provDir, 0700)

	// Create provider config files
	os.WriteFile(filepath.Join(provDir, "protonvpn.json"), []byte(`{"private_key":"test","address":"10.2.0.2/32"}`), 0600)
	os.WriteFile(filepath.Join(provDir, "mullvad.json"), []byte(`{"private_key":"test","address":"10.2.0.2/32"}`), 0600)

	cfg := &config.Config{ConfigDir: dir}
	rp := NewRemoveProvider(cfg)

	if len(rp.providers) != 2 {
		t.Fatalf("providers = %d, want 2", len(rp.providers))
	}

	// Check that known provider gets display name
	foundProton := false
	for _, p := range rp.providers {
		if p.name == "protonvpn" && p.display == "ProtonVPN" {
			foundProton = true
		}
	}
	if !foundProton {
		t.Error("protonvpn should have display name ProtonVPN")
	}
}

func TestNewRemoveProviderEmpty(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{ConfigDir: dir}
	rp := NewRemoveProvider(cfg)

	if len(rp.providers) != 0 {
		t.Errorf("providers = %d, want 0 for empty dir", len(rp.providers))
	}
}

func TestRemoveProviderViewSelected(t *testing.T) {
	rp := &RemoveProvider{
		cfg: &config.Config{},
		providers: []providerToRemove{
			{name: "protonvpn", display: "ProtonVPN", selected: true},
			{name: "mullvad", display: "Mullvad"},
		},
	}
	view := rp.View()
	if !strings.Contains(view, "[x]") {
		t.Error("should show selected checkbox")
	}
	if !strings.Contains(view, "[ ]") {
		t.Error("should show unselected checkbox")
	}
}

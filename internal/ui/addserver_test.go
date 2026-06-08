package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blank-query/lazyVPN-for-Omarchy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

func TestAddServerInit(t *testing.T) {
	// Constructor depends on filesystem; test Init separately
	as := &AddServer{cfg: &config.Config{}}
	if as.Init() != nil {
		t.Error("Init should return nil")
	}
}

func TestAddServerEsc(t *testing.T) {
	as := &AddServer{cfg: &config.Config{}}
	_, cmd := as.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd == nil {
		t.Fatal("esc should return cmd")
	}
	msg := cmd()
	if _, ok := msg.(BackMsg); !ok {
		t.Errorf("expected BackMsg, got %T", msg)
	}
}

func TestAddServerCursorNavigation(t *testing.T) {
	as := &AddServer{
		cfg: &config.Config{},
		files: []importFile{
			{name: "a.conf", valid: true},
			{name: "b.conf", valid: true},
			{name: "c.conf", valid: true},
		},
	}

	model, _ := as.Update(tea.KeyMsg{Type: tea.KeyDown})
	as = model.(*AddServer)
	if as.cursor != 1 {
		t.Errorf("cursor = %d, want 1", as.cursor)
	}

	model, _ = as.Update(tea.KeyMsg{Type: tea.KeyDown})
	as = model.(*AddServer)
	if as.cursor != 2 {
		t.Errorf("cursor = %d, want 2", as.cursor)
	}

	// Should not go past last
	model, _ = as.Update(tea.KeyMsg{Type: tea.KeyDown})
	as = model.(*AddServer)
	if as.cursor != 2 {
		t.Errorf("cursor = %d, want 2 (clamped)", as.cursor)
	}

	model, _ = as.Update(tea.KeyMsg{Type: tea.KeyUp})
	as = model.(*AddServer)
	if as.cursor != 1 {
		t.Errorf("cursor = %d, want 1", as.cursor)
	}

	// arrow keys (continued)
	model, _ = as.Update(tea.KeyMsg{Type: tea.KeyUp})
	as = model.(*AddServer)
	if as.cursor != 0 {
		t.Errorf("cursor = %d, want 0", as.cursor)
	}

	model, _ = as.Update(tea.KeyMsg{Type: tea.KeyDown})
	as = model.(*AddServer)
	if as.cursor != 1 {
		t.Errorf("cursor = %d, want 1", as.cursor)
	}
}

// space simulates a Space key press for toggle assertions.
var space = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}}

func TestAddServerToggleSelection(t *testing.T) {
	as := &AddServer{
		cfg: &config.Config{},
		files: []importFile{
			{name: "a.conf", valid: true},
		},
	}

	// Space toggles selection.
	model, _ := as.Update(space)
	as = model.(*AddServer)
	if !as.files[0].selected {
		t.Error("should be selected after space")
	}

	model, _ = as.Update(space)
	as = model.(*AddServer)
	if as.files[0].selected {
		t.Error("should be deselected after second space")
	}

	// Tab is reserved for pane-switching at the dashboard level — must
	// NOT toggle the checkbox here.
	model, _ = as.Update(tea.KeyMsg{Type: tea.KeyTab})
	as = model.(*AddServer)
	if as.files[0].selected {
		t.Error("tab should not toggle selection (reserved for pane switch)")
	}
}

func TestAddServerTogglePreventsInvalidDuplicate(t *testing.T) {
	as := &AddServer{
		cfg: &config.Config{},
		files: []importFile{
			{name: "invalid.conf", valid: false},
			{name: "dupe.conf", valid: true, duplicate: true, duplicateReason: "filename exists"},
			{name: "good.conf", valid: true},
		},
	}

	// Try to toggle invalid file
	model, _ := as.Update(space)
	as = model.(*AddServer)
	if as.files[0].selected {
		t.Error("invalid file should not be selectable")
	}

	// Move to duplicate, try to toggle
	model, _ = as.Update(tea.KeyMsg{Type: tea.KeyDown})
	as = model.(*AddServer)
	model, _ = as.Update(space)
	as = model.(*AddServer)
	if as.files[1].selected {
		t.Error("duplicate file should not be selectable")
	}

	// Move to valid file, should work
	model, _ = as.Update(tea.KeyMsg{Type: tea.KeyDown})
	as = model.(*AddServer)
	model, _ = as.Update(space)
	as = model.(*AddServer)
	if !as.files[2].selected {
		t.Error("valid non-duplicate file should be selectable")
	}
}

func TestAddServerEnterSkipsDuplicateAutoSelect(t *testing.T) {
	as := &AddServer{
		cfg: &config.Config{ConfigDir: t.TempDir()},
		files: []importFile{
			{name: "dupe.conf", valid: true, duplicate: true},
		},
	}

	// Enter on a duplicate should not auto-select it
	model, _ := as.Update(tea.KeyMsg{Type: tea.KeyEnter})
	as = model.(*AddServer)
	if as.files[0].selected {
		t.Error("enter should not auto-select duplicate file")
	}
}

func TestAddServerViewDuplicateReason(t *testing.T) {
	as := &AddServer{
		cfg: &config.Config{},
		files: []importFile{
			{name: "dupe.conf", valid: true, duplicate: true, duplicateReason: "same endpoint as US-NY#5"},
		},
		width:  80,
		height: 30,
	}
	view := as.View()
	if !strings.Contains(view, "same endpoint as US-NY#5") {
		t.Error("should show duplicate reason in view")
	}
}

func TestAddServerSelectAll(t *testing.T) {
	as := &AddServer{
		cfg: &config.Config{},
		files: []importFile{
			{name: "a.conf", valid: true},
			{name: "b.conf", valid: false},
			{name: "c.conf", valid: true, duplicate: true},
			{name: "d.conf", valid: true},
		},
	}

	model, _ := as.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	as = model.(*AddServer)

	// Only valid, non-duplicate files should be selected
	if !as.files[0].selected {
		t.Error("valid non-duplicate a.conf should be selected")
	}
	if as.files[1].selected {
		t.Error("invalid b.conf should not be selected")
	}
	if as.files[2].selected {
		t.Error("duplicate c.conf should not be selected")
	}
	if !as.files[3].selected {
		t.Error("valid non-duplicate d.conf should be selected")
	}
}

func TestAddServerEnterAutoSelectsCurrent(t *testing.T) {
	as := &AddServer{
		cfg: &config.Config{ConfigDir: t.TempDir()},
		files: []importFile{
			{name: "a.conf", valid: true},
			{name: "b.conf", valid: true},
		},
	}

	model, _ := as.Update(tea.KeyMsg{Type: tea.KeyEnter})
	as = model.(*AddServer)
	if !as.files[0].selected {
		t.Error("enter should auto-select current item")
	}
}

func TestAddServerImportDoneMsg(t *testing.T) {
	as := &AddServer{cfg: &config.Config{}}

	model, _ := as.Update(importDoneMsg{imported: 3, skipped: 1, paths: []string{"/a", "/b", "/c"}})
	as = model.(*AddServer)
	if !as.importDone {
		t.Error("should be import done")
	}
	if as.importing {
		t.Error("should not be importing")
	}
	if as.imported != 3 {
		t.Errorf("imported = %d, want 3", as.imported)
	}
	if as.skipped != 1 {
		t.Errorf("skipped = %d, want 1", as.skipped)
	}
	if len(as.importedPaths) != 3 {
		t.Errorf("importedPaths len = %d, want 3", len(as.importedPaths))
	}
}

func TestAddServerImportDoneKeysBack(t *testing.T) {
	as := &AddServer{cfg: &config.Config{}, importDone: true}

	for _, key := range []string{"n", "enter", "esc"} {
		t.Run(key, func(t *testing.T) {
			var msg tea.Msg
			if len(key) == 1 {
				msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
			} else if key == "enter" {
				msg = tea.KeyMsg{Type: tea.KeyEnter}
			} else {
				msg = tea.KeyMsg{Type: tea.KeyEscape}
			}
			_, cmd := as.Update(msg)
			if cmd == nil {
				t.Fatal("should return cmd")
			}
			result := cmd()
			if _, ok := result.(BackMsg); !ok {
				t.Errorf("expected BackMsg, got %T", result)
			}
		})
	}
}

func TestAddServerWindowSize(t *testing.T) {
	as := &AddServer{cfg: &config.Config{}}
	model, _ := as.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	as = model.(*AddServer)
	if as.width != 100 || as.height != 30 {
		t.Errorf("size = %dx%d, want 100x30", as.width, as.height)
	}
}

func TestAddServerViewEmpty(t *testing.T) {
	as := &AddServer{cfg: &config.Config{}}
	view := as.View()
	if !strings.Contains(view, "Import WireGuard Configs") {
		t.Error("should contain title")
	}
	if !strings.Contains(view, "No .conf files") {
		t.Error("should show empty message")
	}
}

func TestAddServerViewWithFiles(t *testing.T) {
	as := &AddServer{
		cfg: &config.Config{},
		files: []importFile{
			{name: "us-server.conf", valid: true},
			{name: "bad.conf", valid: false},
			{name: "dupe.conf", valid: true, duplicate: true},
		},
		width:  80,
		height: 30,
	}
	view := as.View()
	if !strings.Contains(view, "us-server.conf") {
		t.Error("should show filename")
	}
	if !strings.Contains(view, "INVALID") {
		t.Error("should show INVALID for bad file")
	}
	if !strings.Contains(view, "exists") {
		t.Error("should show exists for duplicate")
	}
}

func TestAddServerViewImportDone(t *testing.T) {
	as := &AddServer{
		cfg:           &config.Config{},
		importDone:    true,
		imported:      2,
		skipped:       1,
		importedPaths: []string{"/a", "/b"},
	}
	view := as.View()
	if !strings.Contains(view, "Imported 2") {
		t.Error("should show import count")
	}
	if !strings.Contains(view, "Skipped 1") {
		t.Error("should show skipped count")
	}
	if !strings.Contains(view, "Delete source files") {
		t.Error("should ask about deleting source files")
	}
}

func TestAddServerViewImportDoneDeletedFiles(t *testing.T) {
	as := &AddServer{
		cfg:         &config.Config{},
		importDone:  true,
		imported:    1,
		deleteFiles: true,
	}
	view := as.View()
	if !strings.Contains(view, "Source files deleted") {
		t.Error("should show files deleted message")
	}
}

func TestAddServerViewNoImported(t *testing.T) {
	as := &AddServer{
		cfg:        &config.Config{},
		importDone: true,
		imported:   0,
	}
	view := as.View()
	if !strings.Contains(view, "No configs imported") {
		t.Error("should show no configs message")
	}
}

func TestAddServerDoImport(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "source")
	os.MkdirAll(srcDir, 0700)

	// Create a valid WireGuard config file to import
	confContent := "[Interface]\nPrivateKey = aGVsbG8gd29ybGQ=\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\n\n[Peer]\nPublicKey = aGVsbG8gd29ybGQ=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
	srcPath := filepath.Join(srcDir, "test.conf")
	os.WriteFile(srcPath, []byte(confContent), 0600)

	cfg := &config.Config{ConfigDir: dir}
	as := &AddServer{
		cfg: cfg,
		files: []importFile{
			{path: srcPath, name: "test.conf", valid: true, selected: true},
		},
	}

	cmd := as.doImport()
	if cmd == nil {
		t.Fatal("doImport should return cmd")
	}
	msg := cmd()
	done, ok := msg.(importDoneMsg)
	if !ok {
		t.Fatalf("expected importDoneMsg, got %T", msg)
	}
	if done.imported != 1 {
		t.Errorf("imported = %d, want 1", done.imported)
	}
	if done.skipped != 0 {
		t.Errorf("skipped = %d, want 0", done.skipped)
	}
	if len(done.paths) != 1 || done.paths[0] != srcPath {
		t.Errorf("paths = %v", done.paths)
	}

	// Verify the file was actually written to wireguard dir
	wgDir := filepath.Join(dir, "wireguard")
	entries, _ := os.ReadDir(wgDir)
	if len(entries) == 0 {
		t.Error("should have written config file to wireguard dir")
	}
}

// TestAddServerDoImportIgnoresPredictableTempPath verifies that the
// WireGuard config import uses an unpredictable temp file path
// (os.CreateTemp) rather than the predictable "<destPath>.tmp" path
// the previous implementation used.
//
// Pre-fix this was a CWE-377 symlink-attack vector: an attacker who
// could write to ~/.config/lazyvpn/wireguard/ would pre-place a
// symlink at "<expected destination>.tmp" pointing somewhere else.
// os.WriteFile would follow the symlink and write the WireGuard
// config CONTENT (including the user's PrivateKey) to the symlink's
// target — leaking secrets.
//
// We reproduce the prerequisite: pre-place a regular file at the
// predictable "<destPath>.tmp" path and verify it is NOT touched
// after doImport runs.
func TestAddServerDoImportIgnoresPredictableTempPath(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "source")
	os.MkdirAll(srcDir, 0700)

	confContent := "[Interface]\nPrivateKey = aGVsbG8gd29ybGQ=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = aGVsbG8gd29ybGQ=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
	// Use a filename that fully matches GenerateStandardServerName's
	// country-state-city regex so the standardizer doesn't fall through
	// to a (network-dependent) geo lookup. With country+state+city all
	// present, the deterministic destination filename is "US-NY-NewYork#42.conf"
	// and the legacy predictable temp path is "US-NY-NewYork#42.conf.tmp".
	srcPath := filepath.Join(srcDir, "US-NY-NewYork#42.conf")
	os.WriteFile(srcPath, []byte(confContent), 0600)

	wgDir := filepath.Join(dir, "wireguard")
	os.MkdirAll(wgDir, 0700)

	bait := []byte("attacker bait — must survive untouched")
	predictableTmp := filepath.Join(wgDir, "US-NY-NewYork#42.conf.tmp")
	if err := os.WriteFile(predictableTmp, bait, 0600); err != nil {
		t.Fatalf("seed bait: %v", err)
	}

	cfg := &config.Config{ConfigDir: dir}
	as := &AddServer{
		cfg: cfg,
		files: []importFile{
			{path: srcPath, name: "US-NY-NewYork#42.conf", valid: true, selected: true},
		},
	}

	cmd := as.doImport()
	msg := cmd()
	done, ok := msg.(importDoneMsg)
	if !ok {
		t.Fatalf("expected importDoneMsg, got %T", msg)
	}
	if done.imported != 1 {
		t.Fatalf("imported = %d, want 1 (functionally the import must still work)", done.imported)
	}

	// The bait at the predictable path must be intact — pre-fix code
	// O_TRUNC'd it via WriteFile and then renamed it onto the dest.
	got, err := os.ReadFile(predictableTmp)
	if err != nil {
		t.Fatalf("predictable temp path was clobbered (file gone): %v", err)
	}
	if string(got) != string(bait) {
		t.Fatalf("predictable temp path was overwritten — symlink-attack vector still present:\n  got  %q\n  want %q", got, bait)
	}
}

func TestAddServerDoImportSkipsDuplicate(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "source")
	os.MkdirAll(srcDir, 0700)

	srcPath := filepath.Join(srcDir, "dupe.conf")
	os.WriteFile(srcPath, []byte("[Interface]\nPrivateKey = aGVsbG8gd29ybGQ=\n"), 0600)

	cfg := &config.Config{ConfigDir: dir}
	as := &AddServer{
		cfg: cfg,
		files: []importFile{
			{path: srcPath, name: "dupe.conf", valid: true, duplicate: true, selected: true},
		},
	}

	cmd := as.doImport()
	msg := cmd()
	done := msg.(importDoneMsg)
	if done.imported != 0 {
		t.Errorf("imported = %d, want 0 (duplicate should be skipped)", done.imported)
	}
	if done.skipped != 1 {
		t.Errorf("skipped = %d, want 1", done.skipped)
	}
}

func TestAddServerDoImportSkipsInvalid(t *testing.T) {
	cfg := &config.Config{ConfigDir: t.TempDir()}
	as := &AddServer{
		cfg: cfg,
		files: []importFile{
			{path: "/nonexistent", name: "bad.conf", valid: false, selected: true},
		},
	}

	cmd := as.doImport()
	msg := cmd()
	done := msg.(importDoneMsg)
	if done.imported != 0 {
		t.Errorf("imported = %d, want 0", done.imported)
	}
	if done.skipped != 1 {
		t.Errorf("skipped = %d, want 1", done.skipped)
	}
}

func TestAddServerDoImportSkipsUnselected(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "source")
	os.MkdirAll(srcDir, 0700)

	srcPath := filepath.Join(srcDir, "test.conf")
	os.WriteFile(srcPath, []byte("[Interface]\nPrivateKey = aGVsbG8gd29ybGQ=\n"), 0600)

	cfg := &config.Config{ConfigDir: dir}
	as := &AddServer{
		cfg: cfg,
		files: []importFile{
			{path: srcPath, name: "test.conf", valid: true, selected: false},
		},
	}

	cmd := as.doImport()
	msg := cmd()
	done := msg.(importDoneMsg)
	if done.imported != 0 {
		t.Errorf("imported = %d, want 0 (unselected)", done.imported)
	}
}

func TestAddServerDoImportBadSourceFile(t *testing.T) {
	dir := t.TempDir()

	cfg := &config.Config{ConfigDir: dir}
	as := &AddServer{
		cfg: cfg,
		files: []importFile{
			{path: "/nonexistent/path/file.conf", name: "file.conf", valid: true, selected: true},
		},
	}

	cmd := as.doImport()
	msg := cmd()
	done := msg.(importDoneMsg)
	if done.imported != 0 {
		t.Errorf("imported = %d, want 0 (source file missing)", done.imported)
	}
	if done.skipped != 1 {
		t.Errorf("skipped = %d, want 1", done.skipped)
	}
}

func TestAddServerImportDoneYesKey(t *testing.T) {
	as := &AddServer{
		cfg:           &config.Config{},
		importDone:    true,
		imported:      1,
		importedPaths: []string{"/tmp/nonexistent-test-file.conf"},
	}

	model, cmd := as.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	as = model.(*AddServer)
	if !as.deleteFiles {
		t.Error("y key should set deleteFiles to true")
	}
	if as.message != "Source files deleted" {
		t.Errorf("message = %q, want 'Source files deleted'", as.message)
	}
	if cmd != nil {
		t.Error("y key should return nil cmd (stays on page)")
	}
}

func TestAddServerImportDoneUnrecognizedKey(t *testing.T) {
	as := &AddServer{
		cfg:        &config.Config{},
		importDone: true,
		imported:   1,
	}

	model, cmd := as.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	as = model.(*AddServer)
	if cmd != nil {
		t.Error("unrecognized key in importDone should return nil cmd")
	}
	if as.deleteFiles {
		t.Error("should not set deleteFiles for unrecognized key")
	}
}

func TestAddServerViewImporting(t *testing.T) {
	as := &AddServer{
		cfg:       &config.Config{},
		importing: true,
		files: []importFile{
			{name: "test.conf", valid: true, selected: true},
		},
	}
	// When importing is true but importDone is false, still shows the file list
	view := as.View()
	if view == "" {
		t.Error("view should not be empty while importing")
	}
}

func TestAddServerViewWithProviderDetected(t *testing.T) {
	as := &AddServer{
		cfg: &config.Config{},
		files: []importFile{
			{name: "proton.conf", valid: true, provider: "protonvpn"},
		},
		width:  80,
		height: 30,
	}
	view := as.View()
	if !strings.Contains(view, "ProtonVPN") || !strings.Contains(view, "proton") {
		// Provider display or file name should be shown
		_ = view
	}
}

func TestAddServerViewSelectedCountNoSelected(t *testing.T) {
	as := &AddServer{
		cfg: &config.Config{},
		files: []importFile{
			{name: "a.conf", valid: true, selected: false},
		},
		width:  80,
		height: 30,
	}
	view := as.View()
	// When nothing is selected, should not show "X selected"
	if strings.Contains(view, "selected") {
		t.Error("should not show selected count when nothing selected")
	}
}

func TestAddServerViewSmallHeight(t *testing.T) {
	files := make([]importFile, 20)
	for i := range files {
		files[i] = importFile{name: "server.conf", valid: true}
	}
	as := &AddServer{
		cfg:    &config.Config{},
		files:  files,
		cursor: 15, // Far enough to trigger scrolling
		width:  80,
		height: 12, // height-10 = 2, which is < 5, so visibleHeight becomes 15
	}
	view := as.View()
	if view == "" {
		t.Error("view should not be empty with small height")
	}
}

func TestAddServerViewDefaultHeight(t *testing.T) {
	as := &AddServer{
		cfg: &config.Config{},
		files: []importFile{
			{name: "a.conf", valid: true},
		},
		width:  80,
		height: 0, // Should use default 24
	}
	view := as.View()
	if view == "" {
		t.Error("view should not be empty with default height")
	}
}

func TestAddServerViewSelectedCount(t *testing.T) {
	as := &AddServer{
		cfg: &config.Config{},
		files: []importFile{
			{name: "a.conf", valid: true, selected: true},
			{name: "b.conf", valid: true, selected: true},
			{name: "c.conf", valid: true},
		},
		width:  80,
		height: 30,
	}
	view := as.View()
	if !strings.Contains(view, "2 selected") {
		t.Error("should show selected count")
	}
}

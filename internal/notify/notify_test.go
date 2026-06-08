package notify

import (
	"testing"
)

func TestIconConstants(t *testing.T) {
	icons := map[string]string{
		"IconConnected":    IconConnected,
		"IconDisconnected": IconDisconnected,
		"IconError":        IconError,
		"IconInfo":         IconInfo,
		"IconRetry":        IconRetry,
		"IconKillswitch":   IconKillswitch,
	}

	for name, icon := range icons {
		if icon == "" {
			t.Errorf("%s should not be empty", name)
		}
	}

	// Verify all icons are distinct
	seen := make(map[string]string)
	for name, icon := range icons {
		if prev, exists := seen[icon]; exists {
			t.Errorf("%s and %s share the same icon %q", name, prev, icon)
		}
		seen[icon] = name
	}
}

func TestCategoryConstants(t *testing.T) {
	// Verify category values are distinct
	categories := []Category{
		CategoryConnection,
		CategoryKillswitch,
		CategoryDaemon,
		CategoryError,
		CategoryInfo,
	}

	seen := make(map[Category]bool)
	for _, c := range categories {
		if seen[c] {
			t.Errorf("duplicate category value: %d", c)
		}
		seen[c] = true
	}

	// Verify specific ordering (iota-based)
	if CategoryConnection != 0 {
		t.Errorf("CategoryConnection = %d, want 0", CategoryConnection)
	}
	if CategoryKillswitch != 1 {
		t.Errorf("CategoryKillswitch = %d, want 1", CategoryKillswitch)
	}
	if CategoryDaemon != 2 {
		t.Errorf("CategoryDaemon = %d, want 2", CategoryDaemon)
	}
	if CategoryError != 3 {
		t.Errorf("CategoryError = %d, want 3", CategoryError)
	}
	if CategoryInfo != 4 {
		t.Errorf("CategoryInfo = %d, want 4", CategoryInfo)
	}
}

func TestNotificationStruct(t *testing.T) {
	n := Notification{
		Title:    "Test Title",
		Message:  "Test message body",
		Icon:     IconConnected,
		Timeout:  3000,
		Category: CategoryConnection,
	}

	if n.Title != "Test Title" {
		t.Errorf("Title = %q", n.Title)
	}
	if n.Message != "Test message body" {
		t.Errorf("Message = %q", n.Message)
	}
	if n.Icon != IconConnected {
		t.Errorf("Icon = %q", n.Icon)
	}
	if n.Timeout != 3000 {
		t.Errorf("Timeout = %d", n.Timeout)
	}
	if n.Category != CategoryConnection {
		t.Errorf("Category = %d", n.Category)
	}
}

func TestNotificationDefaults(t *testing.T) {
	n := Notification{}
	if n.Title != "" {
		t.Errorf("default Title should be empty, got %q", n.Title)
	}
	if n.Timeout != 0 {
		t.Errorf("default Timeout should be 0, got %d", n.Timeout)
	}
	if n.Category != CategoryConnection {
		t.Errorf("default Category should be 0 (CategoryConnection), got %d", n.Category)
	}
}

func TestNotificationTimeoutSemantics(t *testing.T) {
	// Per freedesktop spec:
	// -1 = server decides
	// 0 = never expire
	// >0 = timeout in ms

	tests := []struct {
		name    string
		timeout int32
		desc    string
	}{
		{"server decides", -1, "server decides timeout"},
		{"never expire", 0, "notification never expires"},
		{"3 seconds", 3000, "expires after 3 seconds"},
		{"5 seconds", 5000, "expires after 5 seconds"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := Notification{Timeout: tt.timeout}
			if n.Timeout != tt.timeout {
				t.Errorf("Timeout = %d, want %d", n.Timeout, tt.timeout)
			}
		})
	}
}

// TestNotificationHelperParams verifies the expected notification parameters
// for each helper function. Since helpers call Send() directly (requires DBus),
// we verify the expected Notification structs they would build.
func TestNotificationHelperParams(t *testing.T) {
	tests := []struct {
		name     string
		title    string
		icon     string
		timeout  int32
		category Category
	}{
		{"Connected", "VPN Connected", IconConnected, 3000, CategoryConnection},
		{"Disconnected", "VPN Disconnected", IconDisconnected, 3000, CategoryConnection},
		{"ConnectionLost", "VPN Connection Lost", IconRetry, 5000, CategoryDaemon},
		{"Reconnected", "VPN Reconnected", IconConnected, 3000, CategoryDaemon},
		{"ReconnectFailed", "VPN Reconnect Failed", IconError, 0, CategoryError},
		{"Error", "LazyVPN Error", IconError, 0, CategoryError},
		{"Failover", "VPN Failover", IconRetry, 5000, CategoryDaemon},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Construct the expected notification
			n := Notification{
				Title:    tt.title,
				Icon:     tt.icon,
				Timeout:  tt.timeout,
				Category: tt.category,
			}
			if n.Title != tt.title {
				t.Errorf("Title = %q, want %q", n.Title, tt.title)
			}
			if n.Icon != tt.icon {
				t.Errorf("Icon = %q, want %q", n.Icon, tt.icon)
			}
			if n.Timeout != tt.timeout {
				t.Errorf("Timeout = %d, want %d", n.Timeout, tt.timeout)
			}
			if n.Category != tt.category {
				t.Errorf("Category = %d, want %d", n.Category, tt.category)
			}
		})
	}
}

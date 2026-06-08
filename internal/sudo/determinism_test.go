package sudo

import (
	"testing"
)

// TestGenerateSudoersIsDeterministic: same inputs must always produce
// byte-identical output. Map iteration order or time-based content
// would silently break the "did the sudoers file change?" check the
// install path uses for idempotency.
func TestGenerateSudoersIsDeterministic(t *testing.T) {
	for _, cow := range []bool{true, false} {
		t.Run("cow", func(t *testing.T) {
			ifaces := []string{"enp3s0", "wlan0", "enp1s0"}
			a, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", ifaces, cow)
			if err != nil {
				t.Fatalf("first: %v", err)
			}
			for i := 0; i < 5; i++ {
				b, err := GenerateSudoersContent("/usr/local/bin/lazyvpn", "wg0", ifaces, cow)
				if err != nil {
					t.Fatalf("iteration %d: %v", i, err)
				}
				if a != b {
					t.Errorf("iteration %d differs from first call (non-deterministic generation)", i)
				}
			}
		})
	}
}

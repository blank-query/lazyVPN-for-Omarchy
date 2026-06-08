package security

import "testing"

func TestZeroBytes(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0xFF, 0xAB}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: got %02x", i, v)
		}
	}
}

func TestZeroBytesNil(t *testing.T) {
	ZeroBytes(nil) // must not panic
}

func TestZeroBytesEmpty(t *testing.T) {
	ZeroBytes([]byte{}) // must not panic
}

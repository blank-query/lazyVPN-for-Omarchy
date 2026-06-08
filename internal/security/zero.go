package security

import "runtime"

// ZeroBytes overwrites a byte slice with zeros.
// Use this to clear sensitive key material from memory.
// runtime.KeepAlive prevents the compiler from eliding the stores
// as dead when the slice is not read after zeroing.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

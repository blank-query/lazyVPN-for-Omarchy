package daemon

import (
	"encoding/json"
	"testing"
)

// FuzzCommandParse hammers the IPC command parser with arbitrary bytes —
// the same code path handleClient runs on every line read from a client
// socket. Must not panic regardless of input shape (malformed JSON,
// unknown command types, missing fields, oversized payloads, control
// characters, embedded nulls, deeply-nested junk).
//
// Untrusted input here = anyone with a unix-socket handle to the daemon
// (which is 0600-owned by the user, so realistic threat = a misbehaving
// client lib, not a remote attacker — but defense in depth is cheap).
func FuzzCommandParse(f *testing.F) {
	// Seed corpus: representative valid + invalid shapes
	f.Add([]byte(`{"type":"CONNECT","server":"US-NY#42"}`))
	f.Add([]byte(`{"type":"DISCONNECT"}`))
	f.Add([]byte(`{"type":"STATUS"}`))
	f.Add([]byte(`{"type":"SWITCH","server":"DE#1","provider":"protonvpn","is_dynamic":true}`))
	f.Add([]byte(`{"type":"UNKNOWN_CMD"}`))
	f.Add([]byte(`{`))                  // truncated
	f.Add([]byte(`{}`))                 // empty object
	f.Add([]byte(`null`))               // null literal
	f.Add([]byte(`[]`))                 // wrong type (array)
	f.Add([]byte(`"string"`))           // wrong type (string)
	f.Add([]byte(``))                   // empty input
	f.Add([]byte("\x00\x00\x00"))       // null bytes
	f.Add([]byte(`{"type":"CONNECT"}`)) // missing required server

	f.Fuzz(func(t *testing.T, data []byte) {
		var cmd Command
		// Mirror handleClient's parse + validate pipeline. Both must be
		// panic-free for any input — that's the whole contract.
		if err := json.Unmarshal(data, &cmd); err != nil {
			return // invalid JSON is fine, just rejected
		}
		_ = cmd.Validate() // error is fine; panic is not
	})
}

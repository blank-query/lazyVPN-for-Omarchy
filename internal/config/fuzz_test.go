package config

import (
	"encoding/json"
	"testing"
)

func FuzzConfigJSON(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"connection_name":"wg0"}`))
	f.Add([]byte(`{"custom_mtu":-1}`))
	f.Add([]byte(`{"custom_mtu":99999}`))
	f.Add([]byte(`{"connection_name":"x"}`))
	f.Add([]byte(`{"ping_targets":null}`))
	f.Add([]byte(`{"baseline_dns":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse to shadow JSON struct, then convert + validate. Must not panic.
		cfg := DefaultConfig()
		j := cfg.toJSON()
		if err := json.Unmarshal(data, &j); err != nil {
			return
		}
		cfg.fromJSON(j)
		cfg.validate()
	})
}

func FuzzProviderJSON(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"private_key":"AAAA","address":"10.0.0.2/32"}`))
	f.Add([]byte(`{"private_key":null}`))
	f.Add([]byte(`{"address":""}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var pj providerJSON
		_ = json.Unmarshal(data, &pj)
	})
}

package daemon

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSocketPath(t *testing.T) {
	path := SocketPath("/home/user/.config/lazyvpn")
	if !strings.HasSuffix(path, ".daemon.sock") {
		t.Errorf("SocketPath = %q, should end with .daemon.sock", path)
	}
}

func TestPidPath(t *testing.T) {
	path := PidPath("/home/user/.config/lazyvpn")
	if !strings.HasSuffix(path, ".daemon.pid") {
		t.Errorf("PidPath = %q, should end with .daemon.pid", path)
	}
}

func TestCommandTypesDistinct(t *testing.T) {
	types := []CommandType{CmdConnect, CmdDisconnect, CmdSwitch, CmdStatus}
	seen := make(map[CommandType]bool)
	for _, ct := range types {
		if seen[ct] {
			t.Errorf("duplicate CommandType: %q", ct)
		}
		seen[ct] = true
	}
}

func TestEventTypesDistinct(t *testing.T) {
	types := []EventType{
		EventConnecting, EventConnected, EventHealthy, EventHealthFail,
		EventRetrying, EventReconnected, EventFailed, EventSwitching,
		EventSwitchFailed, EventDisconnecting, EventDisconnected,
		EventError, EventStatus,
	}
	seen := make(map[EventType]bool)
	for _, et := range types {
		if seen[et] {
			t.Errorf("duplicate EventType: %q", et)
		}
		seen[et] = true
	}
}

func TestDaemonStatesDistinct(t *testing.T) {
	states := []DaemonState{
		StateIdle, StateConnecting, StateConnected, StateUnhealthy,
		StateRetrying, StateFailover, StateFailed, StateSwitchFailed,
		StateDisconnecting,
	}
	seen := make(map[DaemonState]bool)
	for _, s := range states {
		if seen[s] {
			t.Errorf("duplicate DaemonState: %q", s)
		}
		seen[s] = true
	}
}

func TestCommandJSON(t *testing.T) {
	cmd := Command{Type: CmdConnect, Server: "US-NY#42", Provider: "protonvpn", IsDynamic: true}
	data, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Command
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Type != CmdConnect {
		t.Errorf("Type = %q", decoded.Type)
	}
	if decoded.Server != "US-NY#42" {
		t.Errorf("Server = %q", decoded.Server)
	}
	if decoded.Provider != "protonvpn" {
		t.Errorf("Provider = %q", decoded.Provider)
	}
	if !decoded.IsDynamic {
		t.Error("IsDynamic should be true")
	}
}

func TestEventJSON(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	event := Event{
		Type: EventConnected, Timestamp: now, Message: "connected",
		Server: "US-NY#42", PublicIP: "1.2.3.4", Latency: 42,
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Type != EventConnected {
		t.Errorf("Type = %q", decoded.Type)
	}
	if decoded.Latency != 42 {
		t.Errorf("Latency = %d", decoded.Latency)
	}
}

func TestStatusJSON(t *testing.T) {
	status := Status{
		State: StateConnected, Connected: true, Server: "US-NY#42",
		KillswitchActive: true, AutoReconnect: true,
	}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Status
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.State != StateConnected {
		t.Errorf("State = %q", decoded.State)
	}
	if !decoded.KillswitchActive {
		t.Error("KillswitchActive should be true")
	}
}

func TestCommandValidate(t *testing.T) {
	tests := []struct {
		name    string
		cmd     Command
		wantErr bool
	}{
		{"connect with server", Command{Type: CmdConnect, Server: "US-NY#42"}, false},
		{"connect without server", Command{Type: CmdConnect}, true},
		{"switch with server", Command{Type: CmdSwitch, Server: "SE#5"}, false},
		{"switch without server", Command{Type: CmdSwitch}, true},
		{"disconnect", Command{Type: CmdDisconnect}, false},
		{"status", Command{Type: CmdStatus}, false},
		{"unknown type", Command{Type: "bogus"}, true},
		{"empty type", Command{}, true},

		// Dynamic-server commands need a provider. Pre-fix Validate
		// passed these and the daemon went through full state-machine
		// ceremony (StateConnecting → broadcast EventConnecting → call
		// ConnectDynamic with empty provider → ValidateName fails deep
		// in config/provider.go → StateFailed → broadcast EventFailed)
		// for what is plainly a malformed command. Reject at the front.
		{"dynamic connect missing provider", Command{Type: CmdConnect, Server: "US-NY#42", IsDynamic: true}, true},
		{"dynamic switch missing provider", Command{Type: CmdSwitch, Server: "SE#5", IsDynamic: true}, true},
		{"dynamic connect with provider", Command{Type: CmdConnect, Server: "US-NY#42", Provider: "protonvpn", IsDynamic: true}, false},
		{"dynamic switch with provider", Command{Type: CmdSwitch, Server: "SE#5", Provider: "protonvpn", IsDynamic: true}, false},
		// Provider on a non-dynamic command is silently ignored (manual
		// configs are looked up by name only) — keep that lenient.
		{"non-dynamic connect with provider is OK", Command{Type: CmdConnect, Server: "US-NY#42", Provider: "ignored"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommandOmitEmpty(t *testing.T) {
	cmd := Command{Type: CmdStatus}
	data, _ := json.Marshal(cmd)
	s := string(data)
	if strings.Contains(s, "server") {
		t.Error("empty Server should be omitted")
	}
	if strings.Contains(s, "provider") {
		t.Error("empty Provider should be omitted")
	}
	if strings.Contains(s, "is_dynamic") {
		t.Error("false IsDynamic should be omitted")
	}
}

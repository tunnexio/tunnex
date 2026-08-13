package helper

import (
	"net"
	"testing"
)

func TestParseFileVaultStatus(t *testing.T) {
	if v := parseFileVaultStatus("FileVault is On.\n"); v == nil || !*v {
		t.Fatalf("On => true, got %v", v)
	}
	if v := parseFileVaultStatus("FileVault is Off.\n"); v == nil || *v {
		t.Fatalf("Off => false, got %v", v)
	}
	// Deferred-enablement output still contains the On line + detail; stays true.
	if v := parseFileVaultStatus("FileVault is On.\nDeferred enablement appears to be active for user 'x'.\n"); v == nil || !*v {
		t.Fatalf("On+detail => true, got %v", v)
	}
	// Unrecognized output is INDETERMINATE (nil) — reported absent, never guessed.
	if v := parseFileVaultStatus("fdesetup: something unexpected"); v != nil {
		t.Fatalf("garbage => nil, got %v", *v)
	}
	if v := parseFileVaultStatus(""); v != nil {
		t.Fatalf("empty => nil, got %v", *v)
	}
}

func TestParseProtectionStatus(t *testing.T) {
	if v := parseProtectionStatus("1\r\n"); v == nil || !*v {
		t.Fatalf("1 => true, got %v", v)
	}
	if v := parseProtectionStatus("0\n"); v == nil || *v {
		t.Fatalf("0 => false, got %v", v)
	}
	// 2 = WMI "unknown" — indeterminate, not a guess either way.
	if v := parseProtectionStatus("2"); v != nil {
		t.Fatalf("2 => nil, got %v", *v)
	}
	if v := parseProtectionStatus(""); v != nil {
		t.Fatalf("empty => nil, got %v", *v)
	}
}

// TestIPCPostureStatus drives the verb through the real dispatch (auth, envelope,
// framing) with an injected collector — the read must carry no config, mutate no
// tunnel state, and claim no connection ownership.
func TestIPCPostureStatus(t *testing.T) {
	srv, sup := newServer(t, &fakeBackend{}, trustedResolver)
	enc := true
	srv.posture = func() PostureStatus { return PostureStatus{DiskEncrypted: &enc} }
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	defer c1.Close()

	resp, err := Do(c1, req(VerbPostureStatus, nil))
	if err != nil || !resp.OK || resp.Posture == nil || resp.Posture.DiskEncrypted == nil || !*resp.Posture.DiskEncrypted {
		t.Fatalf("posture: err=%v resp=%+v", err, resp)
	}
	if sup.State() != StateDown {
		t.Fatalf("posture read must not touch tunnel state, got %s", sup.State())
	}

	// Config on a posture request is rejected by the envelope rule (no smuggling).
	resp, err = Do(c1, req(VerbPostureStatus, goodConfig()))
	if err != nil || resp.OK || resp.Code != "unexpected_config" {
		t.Fatalf("posture+config: err=%v resp=%+v", err, resp)
	}

	// An indeterminate fact round-trips as null, not a guess.
	srv.posture = func() PostureStatus { return PostureStatus{} }
	resp, err = Do(c1, req(VerbPostureStatus, nil))
	if err != nil || !resp.OK || resp.Posture == nil || resp.Posture.DiskEncrypted != nil {
		t.Fatalf("indeterminate posture: err=%v resp=%+v", err, resp)
	}
}

package authctx

import (
	"testing"

	"github.com/google/uuid"
)

// TestPrincipalAuditActor — S10.2 D3: a machine principal attributes to a SYSTEM actor (operator:<name>)
// with the credential as cause and NO user id; a human attributes to its user id with no system actor.
func TestPrincipalAuditActor(t *testing.T) {
	mid := uuid.New()
	m := &Principal{MachineID: mid, MachineName: "gitops", AuthMethod: AuthMachine}
	if !m.IsMachine() {
		t.Fatal("a principal with a MachineID must be a machine")
	}
	uid, sys, cause := m.AuditActor()
	if uid != uuid.Nil {
		t.Fatalf("a machine must have NO user id, got %v", uid)
	}
	if sys != "operator:gitops" {
		t.Fatalf("machine actor_system must be operator:<name>, got %q", sys)
	}
	if cause != "machine_credential:"+mid.String() {
		t.Fatalf("machine cause must name the credential, got %q", cause)
	}

	h := &Principal{UserID: uuid.New(), AuthMethod: AuthLocalPassword}
	if h.IsMachine() {
		t.Fatal("a user principal must not be a machine")
	}
	huid, hsys, hcause := h.AuditActor()
	if huid != h.UserID || hsys != "" || hcause != "" {
		t.Fatalf("a human must attribute (userID, \"\", \"\"), got (%v,%q,%q)", huid, hsys, hcause)
	}
}

// TestAuditActorCauseOverride — S10.2 Slice 4 (D2 cond 2): a machine may OVERRIDE the cause with the CR that
// drove the change; the actor_system (who) stays the operator. A human never carries a Cause.
func TestAuditActorCauseOverride(t *testing.T) {
	mid := uuid.New()
	m := &Principal{MachineID: mid, MachineName: "gitops", AuthMethod: AuthMachine, Cause: "tunnexcluster:default/prod"}
	_, sys, cause := m.AuditActor()
	if sys != "operator:gitops" {
		t.Fatalf("actor_system must still name the operator, got %q", sys)
	}
	if cause != "tunnexcluster:default/prod" {
		t.Fatalf("cause must name the CR when the machine sets one, got %q", cause)
	}

	// A human with a stray Cause (shouldn't happen — only MachineAuth sets it) still attributes cleanly.
	h := &Principal{UserID: uuid.New(), AuthMethod: AuthLocalPassword, Cause: "spoofed"}
	_, hsys, hcause := h.AuditActor()
	if hsys != "" || hcause != "" {
		t.Fatalf("a human must never emit a system actor/cause, got (%q,%q)", hsys, hcause)
	}
}

// TestSanitizeCause — control chars stripped (no audit-log injection), length capped.
func TestSanitizeCause(t *testing.T) {
	if got := SanitizeCause("  tunnexgrant:ns/g\n\rINJECTED  "); got != "tunnexgrant:ns/gINJECTED" {
		t.Fatalf("control chars must be stripped, got %q", got)
	}
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'a'
	}
	if got := SanitizeCause(string(long)); len(got) > 200 {
		t.Fatalf("cause must be length-capped, got len %d", len(got))
	}
}

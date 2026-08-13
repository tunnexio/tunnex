package nodes

import (
	"os"
	"strings"
	"testing"
)

// TestGateRunsBeforeCryptographicWork — the ruled ordering condition (D8), asserted structurally because there is
// no runtime observable for it.
//
// WHY THE ORDER IS A SECURITY PROPERTY. Re-key is an UNAUTHENTICATED endpoint. RSA signature verification is the
// expensive, timing-visible step in the handler; the D3 gate is a field comparison. If verification ran first, the
// response latency would differ measurably between "this serial belongs to a live gateway" and "this serial belongs
// to an expired one" — turning the endpoint into a liveness oracle for a fleet, queryable by anyone who can reach
// the API. Running the cheap gate first removes THAT oracle.
//
// WHAT IT DOES NOT DO, corrected here rather than left as a comfortable overstatement (review pass 1 #16). This
// guard used to claim the ordering makes "every refused request cost the same". IT DOES NOT. A WRONG-KEY refusal
// passes the gate and pays for a full RSA verification; an unknown-identifier or live-node refusal does not. So
// wrong-key remains distinguishable by latency from the other refusals — the one asymmetry the ordering cannot
// remove, because the work is the point of that check.
//
// The residual is bounded and stated in docs/S13.1-decisions.md: distinguishing "wrong key for a real, expired
// node" from "everything else" tells an attacker they have found a recoverable node — which the challenge
// endpoint already refuses to confirm, and which reaching this far already required. Equalising it would mean
// performing a decoy verification on every refusal, which trades a measurable oracle for a constant CPU cost on an
// unauthenticated route: the wrong trade for this surface, made deliberately.
//
// This guard asserts the ORDERING, which is real. It no longer vouches for equal cost, which was not.
//
// This is a source-order assertion, which is a blunt instrument — but the alternative is measuring timing in a test,
// which is flaky, and asserting nothing, which is how a refactor silently reverses it. Scoped to the Rekey function
// per the census law: matching these calls anywhere in the file would be matching a coincidence of the text.
func TestGateRunsBeforeCryptographicWork(t *testing.T) {
	raw, err := os.ReadFile("rekey.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)

	start := strings.Index(src, "func (s *Service) Rekey(")
	if start < 0 {
		t.Fatal("Rekey not found — the guard would vouch for nothing")
	}
	body := src[start:]
	// Statements only. The doc comment above Rekey describes this very ordering and names both calls, so matching
	// prose would satisfy the guard without the code satisfying the property.
	var stmts strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		stmts.WriteString(line + "\n")
	}
	code := stmts.String()

	gate := strings.Index(code, "RekeyAuthorized(")
	verify := strings.Index(code, "rekey.Verify(")
	if gate < 0 {
		t.Fatal("Rekey must consult RekeyAuthorized — without the gate there is no authorization at all")
	}
	if verify < 0 {
		t.Fatal("Rekey must verify proof of possession")
	}
	if gate > verify {
		t.Errorf("the D3 gate must run BEFORE rekey.Verify. Signature verification is the expensive, "+
			"timing-visible step on an UNAUTHENTICATED endpoint, so verifying first lets response latency reveal "+
			"whether a certificate serial belongs to a live gateway — a fleet liveness oracle for anyone who can "+
			"reach the API. (gate at %d, verify at %d)", gate, verify)
	}

	// The nonce must be consumed before either, so a probe cannot retry with the same challenge while tuning its
	// input. Consumption is single-use whether or not the attempt succeeds.
	consume := strings.Index(code, "ConsumeRekeyChallenge(")
	if consume < 0 || consume > gate {
		t.Errorf("the challenge must be consumed before the gate runs, so a refused attempt burns its nonce and "+
			"cannot be retried against a changing target (consume at %d, gate at %d)", consume, gate)
	}
}

// TestPushHappensAfterTheTransaction — the pre-ruled fork, asserted the same way.
//
// A database transaction must not depend on a network call to a fleet. Inside the transaction, success becomes
// hostage to gateway reachability: a slow or partitioned agent holds a write lock on the node row, and a failed push
// rolls back a re-key that already succeeded cryptographically. Outside, the CP's record is authoritative the
// instant it commits and the push is a retryable reconciliation — which is what every other desired-state change in
// this product already does.
func TestPushHappensAfterTheTransaction(t *testing.T) {
	raw, err := os.ReadFile("rekey.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func (s *Service) Rekey(")
	body := src[start:]
	var stmts strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		stmts.WriteString(line + "\n")
	}
	code := stmts.String()

	tx := strings.Index(code, "s.withTx(")
	push := strings.Index(code, "s.pushOrg(")
	if tx < 0 {
		t.Fatal("the identity change and its audit must share ONE transaction")
	}
	if push < 0 {
		t.Fatal("a re-key must trigger the full-sweep push — the WireGuard key changes, so every peer must reconcile")
	}
	if push < tx {
		t.Error("the push must happen AFTER the transaction, never inside it: a transaction that waits on a fleet " +
			"lets a partitioned gateway hold a write lock on the node row, and a failed push would roll back a " +
			"re-key that already succeeded cryptographically")
	}
	// The audit must be INSIDE the transaction — a re-key that happened must leave a record even if the push never
	// lands. Asserted by position: the audit call sits between the transaction's opening and the push.
	auditCall := strings.Index(code, `"node.rekeyed"`)
	if auditCall < 0 || auditCall < tx || auditCall > push {
		t.Errorf("the audited succession must commit WITH the transaction, not with the push (tx at %d, audit at "+
			"%d, push at %d)", tx, auditCall, push)
	}
}

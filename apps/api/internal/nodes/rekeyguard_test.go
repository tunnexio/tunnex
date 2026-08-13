package nodes

import (
	"strings"
	"testing"
	"time"
)

// TestRekeyRefusedAgainstALiveNode — THE FIRST RED OF SLICE 4, written before any re-key mechanism exists.
//
// Same ordering as S9.1's B1 boundary: prove the thing that must never happen is impossible, then build on it. A
// guard retrofitted after the mechanism works is a guard whose absence has already been shipped once.
//
// THE ATTACK. Re-key issues a fresh certificate for an EXISTING node id to a caller that proves possession of that
// node's original keypair. Against a live gateway that is a takeover: the caller's agent inherits the node's
// identity, site binding and policy, and the real gateway is silently displaced — it keeps running, keeps
// forwarding, and is no longer the node the control plane believes it is.
func TestRekeyRefusedAgainstALiveNode(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	ok, reason := RekeyAuthorized("active", now.Add(24*time.Hour), true, now, false)
	if ok {
		t.Fatalf("re-key MUST be refused against a live node with a valid certificate — authorizing it is a "+
			"takeover primitive, not a recovery path. Got authorized with reason %q", reason)
	}
	if !strings.Contains(reason, "still valid") {
		t.Errorf("the refusal must say WHY, so an operator knows the remedy is to revoke first; got %q", reason)
	}
	// The remedy must be named, not implied.
	if !strings.Contains(reason, "Revoke it first") {
		t.Errorf("the refusal must name the remedy (revoke first); got %q", reason)
	}
}

// TestRekeyNeverUnRevokes — THIS ASSERTION IS THE INVERSE OF THE ONE IT REPLACES, and that inversion is a
// security decision rather than a fix, so the reasoning lives here.
//
// The original red asserted that a REVOKED node AUTHORIZES re-key, on the reasoning that revocation is the
// strongest available evidence a node is gone. That is true, and it was the wrong question. The attack:
//
//  1. an attacker steals a gateway's state volume, which is its private key;
//  2. the operator notices and REVOKES that gateway — the product's answer to a stolen credential;
//  3. the attacker calls re-key, proving possession of the stolen key;
//  4. `revoked` authorizes it;
//  5. the attacker holds a fresh certificate for that node id — active, same site binding, same policy.
//
// Revocation defeated by the exact credential it was invoked against. The paper already forbade this in a
// condition on the same page; the evidence list contradicted it. The condition was right.
//
// A future reader who sees "revoked → refuse" without the chain above will eventually decide it is an
// inconvenience worth relaxing. That is why the chain is here and not only in the paper.
//
// EXPIRY IS AN ABSENCE OF ACTION; REVOCATION IS THE PRESENCE OF A DECISION. A cryptographic proof may overturn
// the first and must never overturn the second: the proof cannot distinguish the legitimate holder from whoever
// took the key, and revocation is precisely the response to that ambiguity.
func TestRekeyNeverUnRevokes(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	// Revoked, certificate still valid.
	if ok, reason := RekeyAuthorized("revoked", future, true, now, false); ok {
		t.Fatalf("a REVOKED node must NEVER authorize re-key: proof of possession cannot tell the real gateway "+
			"from whoever stole its key, so authorizing would let the stolen credential undo the revocation "+
			"invoked against it. Got authorized with %q", reason)
	}
	// Revoked AND expired — still refused. Expiry does not launder a revocation.
	if ok, reason := RekeyAuthorized("revoked", past, true, now, false); ok {
		t.Fatalf("revoked AND expired must still refuse — expiry must not launder away a human decision. Got %q", reason)
	}
	// The refusal must name the remedy, and it must be the HUMAN one.
	_, reason := RekeyAuthorized("revoked", past, true, now, false)
	if !strings.Contains(reason, "join token") {
		t.Errorf("the refusal must direct the operator to the human recovery path (a minted join token); got %q", reason)
	}
}

// TestExpiryIsTheONLYAuthorization — the positive half, and the completeness of the allowlist.
func TestExpiryIsTheONLYAuthorization(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	if ok, _ := RekeyAuthorized("active", past, true, now, false); !ok {
		t.Error("an EXPIRED certificate on an ACTIVE node must authorize re-key: the agent cannot authenticate " +
			"and cannot renew, which is the whole condition this epic exists to recover from — and no human " +
			"decided anything, so no decision is being overturned")
	}
	if ok, _ := RekeyAuthorized("active", future, true, now, false); ok {
		t.Error("valid certificate + active status must NOT authorize")
	}
}

// TestStalenessIsNotEvidenceOfGone — the inadmissible inference, asserted as a property.
//
// RekeyAuthorized takes no liveness argument AT ALL, which is the structural version of this rule: a caller cannot
// pass staleness in even by mistake. This test pins that the signature stays that way, because the tempting third
// condition is exactly "we haven't heard from it in days" — and a network partition would then authorize a
// takeover of a gateway that is running perfectly.
func TestStalenessIsNotEvidenceOfGone(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	// A node silent for a month, with a VALID certificate. Silence is not proof that a credential cannot work.
	if ok, reason := RekeyAuthorized("active", now.Add(720*time.Hour), true, now, false); ok {
		t.Fatalf("a long-silent node with a valid certificate must NOT authorize re-key: silence has many "+
			"causes and none of them is proof the credential stopped working. Got %q", reason)
	}
}

// TestUnknownExpiryIsNotGone — a row predating migration 0054 that 0055 declined to bound (it had never reported)
// carries no expiry. UNKNOWN is not gone: the CP knows nothing, so it must not authorize replacement.
func TestUnknownExpiryIsNotGone(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	ok, reason := RekeyAuthorized("active", time.Time{}, false, now, false)
	if ok {
		t.Fatalf("an unknown expiry must NOT authorize re-key — the control plane cannot establish the node is "+
			"gone, and 'I cannot tell' is not 'it is fine'. Got %q", reason)
	}
	if !strings.Contains(reason, "no record") || !strings.Contains(reason, "join token") {
		t.Errorf("the refusal must state that the CP cannot establish absence, and name the human remedy; got %q", reason)
	}
	// SECOND INVERTED ASSERTION, same reasoning as TestRekeyNeverUnRevokes. This previously asserted that a
	// revoked node with unknown expiry IS authorized, on the grounds that "revocation is independent evidence".
	// It is independent evidence that the node is GONE — and simultaneously evidence that a human wanted the
	// key-holder locked out, which is exactly what proof of possession cannot adjudicate.
	if ok, _ := RekeyAuthorized("revoked", time.Time{}, false, now, false); ok {
		t.Error("revoked + unknown expiry must refuse: neither fact authorizes a return, and the revocation is a " +
			"decision a cryptographic proof must not overturn")
	}
}

// TestRekeyGateTakesNoForceParameter is a SIGNATURE guard, and it is deliberate.
//
// The pressure to add a force flag arrives later, from a real operator stuck in a real incident. The answer is
// that a guard overridable by the party most motivated to override it is documentation. Encoding that as a
// compile-time property — the function simply has nowhere to put one — is stronger than a comment asking future
// authors not to.
func TestRekeyGateTakesNoForceParameter(t *testing.T) {
	// If a bool were added for "force", this assignment stops compiling and the author has to come back to the
	// paper. That is the point: the test's value is that it must be EDITED, not that it runs.
	//
	// IT WAS EDITED ONCE, deliberately, and the justification belongs here rather than in a commit message.
	// Review pass 1 #3 added a fifth parameter, now `certUndelivered`. THAT IS NOT A FORCE FLAG, and the
	// distinction is exact:
	//
	//   a FORCE flag is CALLER-ASSERTED INTENT — "do it anyway" — so the party most motivated to override the
	//   guard is the party who sets it, which is why it is documentation rather than a guard;
	//
	//   `certUndelivered` is a CALLER-INDEPENDENT FACT the control plane OBSERVED ABOUT ITSELF: whether the
	//   certificate it last issued has ever been used to authenticate. A caller cannot set it, cannot assert it,
	//   and cannot make it true — only the absence of the CP's own observation makes it true.
	//
	//   ITS FIRST VERSION WAS WEAKER AND WAS WRONG. `provesCurrentKey` keyed on the CALLER'S possession, which a
	//   live gateway's key-holder also has, so it authorized displacing a running node. The lesson is in the
	//   difference: "what the caller can prove" and "what we observed about our own issuance" look equally
	//   objective and are not.
	//
	// The test that keeps that honest is TestRedeliveryCarveOutCannotUnRevoke: whatever this parameter means, it
	// must never reach a revoked node.
	var gate func(string, time.Time, bool, time.Time, bool) (bool, string) = RekeyAuthorized
	if gate == nil {
		t.Fatal("unreachable")
	}
}

// TestRedeliveryREFUSESALiveNode — THE REGRESSION RED for the live-node takeover this carve-out's first version
// introduced (S13.1 D3, found by the author after Batch A).
//
// The first predicate was "the caller proves the key the CP currently records". A LIVE gateway's key-holder
// satisfies that, and RekeyNode replaces cert_serial — the column the agent channel authenticates against — so
// exercising it displaced the running gateway. The narrowed predicate is DELIVERY: a running gateway's
// certificate has authenticated, so it is marked delivered, so it can never be the subject of a redelivery.
//
// This red fails if anyone widens the predicate back toward the caller's possession.
func TestRedeliveryREFUSESALiveNode(t *testing.T) {
	now := time.Now()
	live := now.Add(47 * time.Hour) // a valid certificate — the node is running

	// DELIVERED = false is the ONLY thing that may authorize. A live node is delivered by definition.
	if ok, reason := RekeyAuthorized("active", live, true, now, false); ok {
		t.Fatalf("a live gateway must be refused: its certificate has authenticated, so nothing about it is "+
			"undelivered, and re-keying it would displace the running credential — got %q", reason)
	}
}

// TestRedeliveryCarveOutCannotUnRevoke — the carve-out's boundary, and the property that makes it safe to have.
//
// provesCurrentKey authorizes a REDELIVERY: the caller holds the key the control plane records now, so it can
// already authenticate as this node, and re-issuing over the same key grants nothing new. It must NEVER reach a
// revoked node — revocation is a human decision, and if a proof of possession could overturn it, D3 would be a
// comment rather than a gate.
func TestRedeliveryCarveOutCannotUnRevoke(t *testing.T) {
	now := time.Now()
	for _, notAfter := range []time.Time{now.Add(-48 * time.Hour), now.Add(48 * time.Hour)} {
		if ok, reason := RekeyAuthorized("revoked", notAfter, true, now, true); ok {
			t.Fatalf("a REVOKED node must be refused even when the caller proves the current key: %q", reason)
		}
	}
}

// TestRedeliveryAuthorizesTheLOSTRESPONSECase — the D3/D10 collision, as a unit.
//
// A lost re-key response leaves the control plane holding a FRESH certificate the agent never received. The node
// therefore reads as live by expiry, and before this carve-out the gate refused the recovery D10 exists for — for
// a full 48h certificate lifetime. What distinguishes it from an actually-live node is DELIVERY: this certificate
// has never authenticated.
func TestRedeliveryAuthorizesTheLOSTRESPONSECase(t *testing.T) {
	now := time.Now()
	fresh := now.Add(47 * time.Hour) // what a just-committed re-key leaves behind

	if ok, _ := RekeyAuthorized("active", fresh, true, now, false); ok {
		t.Fatal("a DELIVERED certificate on a live node must still be refused — that is the whole gate")
	}
	ok, reason := RekeyAuthorized("active", fresh, true, now, true)
	if !ok {
		t.Fatal("an UNDELIVERED certificate plus a CSR over the recorded key must authorize redelivery — that is " +
			"the lost-response case, and refusing it costs the gateway its identity for a full certificate lifetime")
	}
	if !strings.Contains(reason, "REDELIVERY") {
		t.Fatalf("the authorization reason must name redelivery, so an audit row says which rule allowed it; got %q", reason)
	}
}

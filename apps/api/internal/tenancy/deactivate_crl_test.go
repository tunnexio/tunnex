package tenancy

import (
	"os"
	"strings"
	"testing"
)

// TestDeactivationReachesTheCRLAndReactivationReversesIt — the gap the founder asked about.
//
// Deactivating a user drops their devices out of the WG peer set and the OVPN CCD roster, and the agent
// full-sweeps the stale CCD file, so `ccd-exclusive` refuses the client. That chain is real — and it is ONE
// MECHANISM, living in the AGENT, over a certificate that is still cryptographically valid.
//
// > **A REFUSAL THAT DEPENDS ENTIRELY ON A CONFIG FLAG ON A REMOTE BOX IS NOT DEFENCE IN DEPTH.** A gateway
// > whose `server.conf` lost `ccd-exclusive` would admit a deactivated user's OpenVPN client on cert alone.
//
// ⛔ AND THE SYMMETRIC HALF IS NOT OPTIONAL. Revoking on deactivation without restoring on reactivation is a
// ONE-WAY DOOR: the user returns `active` everywhere while their client stays on the CRL — control plane
// green, data plane refusing, operator told it succeeded. That is on record as review pass 1 #9 for the
// node-restore path, and this is the same shape.
func TestDeactivationReachesTheCRLAndReactivationReversesIt(t *testing.T) {
	b, err := os.ReadFile("membership.go")
	if err != nil {
		t.Fatalf("read membership.go: %v", err)
	}
	src := string(b)

	fn := func(name string) string {
		i := strings.Index(src, name)
		if i < 0 {
			t.Fatalf("%s not found — if it was renamed, carry these properties with it", name)
		}
		rest := src[i:]
		if end := strings.Index(rest[1:], "\nfunc "); end > 0 {
			return rest[:end]
		}
		return rest
	}

	// ⛔ THE REVOKE IS INSIDE THE DEACTIVATE TRANSACTION, for the reason the CLI-credential sweep is: a
	// revocation that can be lost between two statements is one an operator was told happened.
	deact := fn("func (s *MembershipService) deactivate(")
	if !strings.Contains(deact, "RevokeOVPNCertsForDeactivatedUser") {
		t.Fatal("deactivation does not revoke the user's OpenVPN certs — the refusal is then configurational " +
			"only, resting on ccd-exclusive on a remote gateway")
	}
	if !strings.Contains(deact, "s.crl.RebuildCRL") {
		t.Fatal("deactivation marks the certs revoked but never republishes the CRL — no gateway learns of it")
	}

	// ⛔ AND REACTIVATION REVERSES IT. Without this the verb is a one-way door.
	react := fn("func (s *MembershipService) ReactivateMember(")
	if !strings.Contains(react, "RestoreOVPNCertsForReactivatedUser") {
		t.Fatal("reactivation does not restore the certs — the user returns active with their OpenVPN client " +
			"still on the CRL, which is review pass 1 #9 reached from a different direction")
	}
	if !strings.Contains(react, "s.crl.RebuildCRL") {
		t.Fatal("reactivation clears revoked_at but never republishes the CRL — gateways keep refusing")
	}

	// ⚠ THE CAUSE MUST BE ITS OWN, NOT `cascade`. A cascade cert is revived by a GATEWAY restore; these must
	// come back when the USER does and by nothing else. Sharing the cause would let a gateway rebuild
	// silently un-revoke a deactivated user's credential.
	q, err := os.ReadFile("../../db/queries/ovpn.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(q)
	if !strings.Contains(sql, "revoked_cause = 'user_deactivated'") {
		t.Fatal("the deactivation revoke must use its own cause, so a gateway restore cannot revive it")
	}
	if !strings.Contains(sql, "c.revoked_cause = 'user_deactivated'") {
		t.Fatal("the restore must be scoped to cause='user_deactivated' — it must not revive a cert an " +
			"operator revoked deliberately, nor one a gateway revoke cascaded")
	}
}

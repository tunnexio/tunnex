package nodes

import (
	"testing"
	"time"
)

// TestCertExpiredOutranksEveryOtherKind — the load-bearing property of the WF-S11-6 fold.
//
// An agent whose certificate has expired cannot complete a TLS handshake, so it has not reported since the
// certificate lapsed. Every other kind's evidence IS that last report. So if any other kind can win here, the
// operator is shown a stale diagnosis with a remedy that cannot work: you cannot upgrade, restart, or reconcile
// your way past an expired certificate — only re-enrol.
//
// This is asserted against the FULL set of competing signals turned on simultaneously, not one at a time,
// because the ranking is what is being tested and a one-at-a-time check would pass on a table where
// cert-expired sat anywhere in the top half.
func TestCertExpiredOutranksEveryOtherKind(t *testing.T) {
	now := time.Now()
	everythingWrong := KindInput{
		CertExpired: true,

		// ...and every other alarm at once, including the ones that outrank each other.
		UnsupportedVersion:          true,
		SiteHubDown:                 true,
		SiteLinkDown:                true,
		SiteSubnetUnreachable:       true,
		HubForwardingNotReconciling: true,
		ConntrackFlushUnavailable:   true,
		K8sEndpointsUnavailable:     true,
		PolicyError:                 "apply failed",
		PolicyFailingSince:          now.Add(-time.Hour).Format(time.RFC3339),
		PushKnown:                   true,
		PushedHash:                  "aaaa",
		AppliedHash:                 "bbbb",
		DesyncSince:                 now.Add(-time.Hour),
		ReportAge:                   72 * time.Hour,
		Now:                         now,
	}

	if got := degradedKind(everythingWrong); got != KindCertExpiredCannotReconnect {
		t.Fatalf("cert-expired must outrank every other kind, got %q — an operator would be shown a diagnosis "+
			"derived from a report the agent could not have sent, with a remedy that cannot be applied", got)
	}
}

// TestCertExpiredIsNotInferredFromStaleness is the finding's other half, in reverse.
//
// The defect WF-S11-6 named was that a stale gateway and a bricked gateway rendered identically. The fix must
// not overcorrect into the mirror error: silence is NOT evidence of an expired certificate. A gateway that has
// been quiet for three days with a VALID certificate is unreachable-and-recoverable, and calling it bricked
// would send an operator to re-enrol a gateway that would have come back on its own.
func TestCertExpiredIsNotInferredFromStaleness(t *testing.T) {
	now := time.Now()
	silentButValid := KindInput{
		CertExpired: false, // the certificate is fine; we simply have not heard from it
		ReportAge:   72 * time.Hour,
		PushKnown:   true,
		PushedHash:  "aaaa",
		AppliedHash: "bbbb",
		DesyncSince: now.Add(-72 * time.Hour),
		Now:         now,
	}
	if got := degradedKind(silentButValid); got == KindCertExpiredCannotReconnect {
		t.Fatal("staleness must NOT be reported as an expired certificate: silence has many causes, and " +
			"re-enrolling a gateway that would have recovered on its own is a destructive remedy for a " +
			"self-healing condition")
	}
	if got := degradedKind(silentButValid); got != KindDesyncUnknown {
		t.Fatalf("a stale reporter with a stamped desync is desync_unknown, got %q", got)
	}
}

// TestCertExpiryRankingIsDeclaredInTheTransitionTable keeps the paper and the code in step: transitionTable is
// the documented evidence-in for each state and the source AllKinds() derives from, so a kind implemented in
// degradedKind but absent from the table would ship without a metric series or a documented remedy.
func TestCertExpiryRankingIsDeclaredInTheTransitionTable(t *testing.T) {
	if len(transitionTable) == 0 {
		t.Fatal("empty transition table")
	}
	if transitionTable[0].Kind != KindCertExpiredCannotReconnect {
		t.Fatalf("cert_expired_cannot_reconnect must be FIRST in transitionTable to match its priority in "+
			"degradedKind; found %q. Drift between the table's order and the projection's order makes the "+
			"documented ranking a fiction", transitionTable[0].Kind)
	}
	if transitionTable[0].EvidenceIn == "" {
		t.Fatal("a state with no declared evidence-in is a paper finding")
	}
}

// TestCertExpiredForNodeGatesOnStatusAndKnowledge — WF-S11-10, and a replacement for a red that could not fail.
//
// The first attempt asserted degradedKind(CertExpired: false) != the cert-expired kind, which is a tautology: it
// passed with the production fix removed. The decision being tested is not the projection, it is which node rows
// count as expired at all — so that decision was extracted from an inline expression into CertExpiredForNode and
// is exercised directly here.
//
// The revoked case is the one found on a live dashboard, where a revoked gateway rendered
// "revoked  certificate expired — re-enroll this gateway": two labels contradicting each other, one of them
// instructing the operator to undo a deliberate revocation.
func TestCertExpiredForNodeGatesOnStatusAndKnowledge(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	cases := []struct {
		name     string
		status   string
		notAfter time.Time
		known    bool
		want     bool
		why      string
	}{
		{"active + expired", "active", past, true, true,
			"the whole point: an active gateway whose cert lapsed cannot reconnect"},
		{"REVOKED + expired", "revoked", past, true, false,
			"refusing a revoked agent's renewal IS revocation working; prescribing re-enrolment would undo a " +
				"deliberate security action"},
		{"active + expiry UNKNOWN", "active", time.Time{}, false, false,
			"0054 added the column nullable so it could not retroactively brick every enrolled gateway"},
		{"active + still valid", "active", future, true, false,
			"a valid certificate is not an expired one"},
		{"revoked + expiry unknown", "revoked", time.Time{}, false, false,
			"neither condition holds"},
	}
	for _, c := range cases {
		if got := CertExpiredForNode(c.status, c.notAfter, c.known, now); got != c.want {
			t.Errorf("%s: got %v, want %v — %s", c.name, got, c.want, c.why)
		}
	}
}

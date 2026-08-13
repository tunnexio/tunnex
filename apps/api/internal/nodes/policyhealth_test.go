package nodes

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// degradedKind reds — X-3's render set. The kind is advisory over the authoritative bool;
// these pin that a desync NEVER false-alarms within T, a stuck one IS flagged past T, and a
// can't-determine (compile fault OR stale reports) is a DISTINCT honest state — never healthy,
// never a specific kind.
func TestDegradedKind(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	fresh := 5 * time.Second // report age < F
	base := KindInput{PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now}

	cases := []struct {
		name string
		in   KindInput
		want PolicyDegradedKind
	}{
		{"healthy — in sync, fresh", base, KindHealthy},
		// S8.7 Slice 2: policy in sync but the expired-grant flush is failing → conntrack_flush_unavailable
		// (lowest-priority degradation, surfaced only when otherwise healthy).
		{"conntrack_flush_unavailable — synced but flush failing", KindInput{PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now, ConntrackFlushUnavailable: true}, KindConntrackFlushUnavailable},
		// MASKED: a louder desync outranks it — flush-unavailable is the quietest signal, never the headline.
		{"masked — desync outranks flush-unavailable", KindInput{PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: fresh, Now: now, DesyncSince: now.Add(-90 * time.Second), ConntrackFlushUnavailable: true}, KindSilentDesync},
		// S10.3 k8s_endpoints_unavailable — both directions + ranking.
		{"k8s_endpoints_unavailable — synced but cluster DNS unreachable", KindInput{PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now, K8sEndpointsUnavailable: true}, KindK8sEndpointsUnavailable},
		{"k8s dns RECOVERS — synced, flag clear → healthy", KindInput{PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now, K8sEndpointsUnavailable: false}, KindHealthy},
		{"k8s dns outranks conntrack (louder exposed-Service surface)", KindInput{PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now, K8sEndpointsUnavailable: true, ConntrackFlushUnavailable: true}, KindK8sEndpointsUnavailable},
		{"masked — desync outranks k8s dns", KindInput{PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: fresh, Now: now, DesyncSince: now.Add(-90 * time.Second), K8sEndpointsUnavailable: true}, KindSilentDesync},
		{"apply_failing — error + failing_since", KindInput{PolicyError: "boom", PolicyFailingSince: "t0", ReportAge: fresh, Now: now}, KindApplyFailing},
		{"stuck_enforcing — error + NO failing_since", KindInput{PolicyError: "boom", ReportAge: fresh, Now: now}, KindStuckEnforcing},
		// [fold 3] TERM-2: failing_since set with NO error must be apply_failing, NEVER the benign
		// converging path (the bool catches failing_since alone; the kind must too).
		{"term-2 — failing_since, no error → apply_failing (not converging)", KindInput{PolicyFailingSince: "t0", PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: fresh, Now: now}, KindApplyFailing},
		{"desync_unknown — pushed hash unavailable", KindInput{PushKnown: false, AppliedHash: "h", ReportAge: fresh, Now: now}, KindDesyncUnknown},
		{"non-enforcing — pushed '' → healthy (no enforcement boundary)", KindInput{PushKnown: true, PushedHash: "", AppliedHash: "old", ReportAge: fresh, Now: now}, KindHealthy},

		// [X-3 false-alarm] a fresh push settling: mismatch, fresh, age < T → converging, NEVER silent_desync.
		{"converging — mismatch, fresh, age < T", KindInput{PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: fresh, Now: now, DesyncSince: now.Add(-10 * time.Second)}, KindConverging},
		// [X-3 stuck] mismatch persisting past T with fresh reports → silent_desync.
		{"silent_desync — mismatch, fresh, age > T", KindInput{PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: fresh, Now: now, DesyncSince: now.Add(-90 * time.Second)}, KindSilentDesync},
		// [exactly-T boundary] age == T → silent_desync (>=).
		{"boundary — age == T → silent_desync", KindInput{PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: fresh, Now: now, DesyncSince: now.Add(-DesyncSettleWindow)}, KindSilentDesync},
		// [just under T] → still converging.
		{"boundary − 1ns → converging", KindInput{PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: fresh, Now: now, DesyncSince: now.Add(-DesyncSettleWindow + time.Nanosecond)}, KindConverging},
		// not-yet-stamped race (zero onset) on a fresh mismatch → converging, not silent.
		{"zero onset → converging (just-onset race)", KindInput{PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: fresh, Now: now}, KindConverging},

		// [X-3 reports-stop] stale reports + mismatch → desync_unknown, NEVER silent_desync, NEVER healthy —
		// even with an OLD stamped onset (silence is not evidence of ongoing desync).
		{"reports-stop — stale + mismatch + old onset → desync_unknown", KindInput{PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: ReportFreshnessWindow, Now: now, DesyncSince: now.Add(-10 * time.Minute)}, KindDesyncUnknown},
		// [X-3 reconverge] applied catches up to pushed → healthy (convergence is a STATE predicate).
		{"reconverge — applied == pushed → healthy", KindInput{PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now}, KindHealthy},

		// [S8.1 D1] the agent refused a too-new artifact → unsupported_policy_version (deny-all,
		// version-incapable). Highest priority: it OUTRANKS the desync/apply paths because its remedy
		// is unique (upgrade the agent) — even when an apply error + a stuck desync are ALSO present.
		{"S8.1 — unsupported_policy_version (agent refused)", KindInput{UnsupportedVersion: true, PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now}, KindUnsupportedPolicyVersion},
		{"S8.1 — refused OUTRANKS apply-error + silent-desync", KindInput{UnsupportedVersion: true, PolicyError: "boom", PolicyFailingSince: "t0", PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: fresh, Now: now, DesyncSince: now.Add(-90 * time.Second)}, KindUnsupportedPolicyVersion},

		// [S8.2 Item 7/9] site-link reachability kinds — hub-down distinct from spoke link-down, ranked
		// below version-refused but above the policy apply/desync kinds (the site gateway's headline).
		{"S8.2 — site_hub_down", KindInput{SiteHubDown: true, PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now}, KindSiteHubDown},
		{"S8.2 — site_link_down (spoke)", KindInput{SiteLinkDown: true, PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now}, KindSiteLinkDown},
		{"S8.2 — hub-down OUTRANKS a spoke link-down", KindInput{SiteHubDown: true, SiteLinkDown: true, PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now}, KindSiteHubDown},
		{"S8.2 — hub-down OUTRANKS apply-error + silent-desync", KindInput{SiteHubDown: true, PolicyError: "boom", PolicyFailingSince: "t0", PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: fresh, Now: now, DesyncSince: now.Add(-90 * time.Second)}, KindSiteHubDown},
		{"S8.2 — version-refused still OUTRANKS hub-down", KindInput{UnsupportedVersion: true, SiteHubDown: true, PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now}, KindUnsupportedPolicyVersion},
		// S8.2c D3 — the reassuring-green trap: link handshake FRESH (SiteLinkDown=false) + hashes MATCH
		// (would be healthy) but the gateway advertises a subnet it isn't on → site_subnet_unreachable,
		// NEVER healthy. This is the exact bridge-mode shape the cross-cloud demo hit.
		{"S8.2c — site_subnet_unreachable fires though link fresh + in-sync (reassuring-green)", KindInput{SiteSubnetUnreachable: true, PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now}, KindSiteSubnetUnreachable},
		// A dead LINK is the louder failure → site_link_down OUTRANKS site_subnet_unreachable when both.
		{"S8.2c — site_link_down OUTRANKS site_subnet_unreachable", KindInput{SiteLinkDown: true, SiteSubnetUnreachable: true, PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: fresh, Now: now}, KindSiteLinkDown},
		// site_subnet_unreachable OUTRANKS the policy apply/desync kinds (a reachability fault is the headline).
		{"S8.2c — site_subnet_unreachable OUTRANKS silent_desync", KindInput{SiteSubnetUnreachable: true, PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: fresh, Now: now, DesyncSince: now.Add(-90 * time.Second)}, KindSiteSubnetUnreachable},

		// WF-C L2 (D-WFC2-1a) — the zombie hub: HubForwardingNotReconciling (wire fresh, agent dead) →
		// hub_forwarding_not_reconciling.
		{"WF-C L2 — hub_forwarding_not_reconciling", KindInput{HubForwardingNotReconciling: true, PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: ReportFreshnessWindow, Now: now}, KindHubForwardingNotReconciling},
		// OUTRANKS the apply/desync kinds: a dead agent's LAST report is frozen, so a stale apply_failing /
		// silent_desync must NOT mask "the agent is dead, restart it".
		{"WF-C L2 — zombie OUTRANKS a stale apply-error + desync", KindInput{HubForwardingNotReconciling: true, PolicyError: "boom", PolicyFailingSince: "t0", PushKnown: true, PushedHash: "new", AppliedHash: "old", ReportAge: ReportFreshnessWindow, Now: now, DesyncSince: now.Add(-90 * time.Second)}, KindHubForwardingNotReconciling},
		// BELOW the site-reachability kinds: a dead ORG TRANSIT (site_link_down) is the louder headline; a
		// standby zombie can co-occur with the active primary's link-down → the transit failure wins.
		{"WF-C L2 — site_link_down OUTRANKS a standby zombie", KindInput{SiteLinkDown: true, HubForwardingNotReconciling: true, PushKnown: true, PushedHash: "h", AppliedHash: "h", ReportAge: ReportFreshnessWindow, Now: now}, KindSiteLinkDown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := degradedKind(c.in); got != c.want {
				t.Fatalf("degradedKind = %q, want %q", got, c.want)
			}
		})
	}
}

// T = 2R, F = 2R — the report-cadence basis (not the push SLA). Pins the arithmetic so a
// silent edit can't quietly retune the debounce (the boundary red is only load-bearing if T holds).
func TestPolicyHealthWindowsAreTwiceReportInterval(t *testing.T) {
	if DesyncSettleWindow != 2*AssumedReportInterval || ReportFreshnessWindow != 2*AssumedReportInterval {
		t.Fatalf("T/F must be 2×R: T=%v F=%v R=%v", DesyncSettleWindow, ReportFreshnessWindow, AssumedReportInterval)
	}
	if AssumedReportInterval != 30*time.Second {
		t.Fatalf("R must mirror the agent default 30s, got %v", AssumedReportInterval)
	}
}

// TestSiteLinkVerdictWF_B — WF-B slice 2: the pure org-level site-link verdict from THE ONE liveness map.
// Pins the three ruled cases: the walk's exact state (demoted-dead while primary fresh → subordinate
// named line, healthy headline), the INVERSE (active-primary stale → headline down, the reassuring-green
// -at-precedence guard), and all-fresh → neither. Consumes deriveMemberLiveness's output (the two-truths
// red is structural: this function CANNOT see freshness except through that map).
func TestSiteLinkVerdictWF_B(t *testing.T) {
	primary, demotedMember := idAt(1), idAt(2)
	members := []uuid.UUID{primary, demotedMember}

	fresh := MemberLiveness{Observed: true, Fresh: true}
	stale := MemberLiveness{Observed: true, Fresh: false}
	staleDemoted := MemberLiveness{Observed: true, Fresh: false, Demoted: true}
	freshDemoted := MemberLiveness{Observed: true, Fresh: true, Demoted: true}

	// WALK STATE: primary fresh, the demoted member dead → SUBORDINATE (no headline, name the demoted peer).
	hd, sub := siteLinkVerdictFrom(members, primary, map[uuid.UUID]MemberLiveness{primary: fresh, demotedMember: staleDemoted})
	if hd || sub != demotedMember {
		t.Fatalf("walk state: want (headline=false, sub=demoted), got (headline=%v, sub=%v)", hd, sub)
	}

	// INVERSE: the ACTIVE PRIMARY is stale → HEADLINE down, NO subordinate (a real failure isn't softened).
	hd, sub = siteLinkVerdictFrom(members, primary, map[uuid.UUID]MemberLiveness{primary: stale, demotedMember: staleDemoted})
	if !hd || sub != uuid.Nil {
		t.Fatalf("inverse: want (headline=true, sub=nil), got (headline=%v, sub=%v)", hd, sub)
	}

	// ALL FRESH (incl. a fresh demoted member — a recovering standby): neither headline nor note.
	hd, sub = siteLinkVerdictFrom(members, primary, map[uuid.UUID]MemberLiveness{primary: fresh, demotedMember: freshDemoted})
	if hd || sub != uuid.Nil {
		t.Fatalf("all-fresh: want (false, nil), got (%v, %v)", hd, sub)
	}

	// SILENCE (WF-B review F1/F2): primary UNOBSERVED (no witness) WHILE a demoted member is stale → NEITHER.
	// No headline (silence ≠ death) AND no subordinate (silence can't assert transit is healthy → no
	// reassurance). FULL-tuple assertion (F2: a red that checks only half the return can't fail on the other).
	if hd, sub := siteLinkVerdictFrom(members, primary, map[uuid.UUID]MemberLiveness{demotedMember: staleDemoted}); hd || sub != uuid.Nil {
		t.Fatalf("silence + stale demoted → want (false, nil), got (headline=%v, sub=%v)", hd, sub)
	}
}

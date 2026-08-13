package nodes

import "time"

// PolicyDegradedKind is the ADVISORY differentiated-health enum (S7.4b). It refines the
// authoritative `policy_degraded` BOOL with which-kind display detail — it adds NO decision
// logic and is UI-read-only (nothing in enforcement / push targeting / compilation reads it;
// asserted by a structural guard, S1.1 edition-isolation shape). The bool stays the sole
// load-bearing signal (the S7.2 collapse must not silently un-collapse).
//
// `desync_unknown` is a FIRST-CLASS honest state — it means "we could not determine", NEVER
// "healthy" and NEVER a specific kind. Rendering a known hash mismatch as unknown, or an
// unknown as healthy, is the failure-must-be-legible law's mirror polarity.
type PolicyDegradedKind string

const (
	KindHealthy        PolicyDegradedKind = "healthy"
	KindApplyFailing   PolicyDegradedKind = "apply_failing"   // enforcing apply currently failing
	KindStuckEnforcing PolicyDegradedKind = "stuck_enforcing" // enforcing a disabled/off policy it can't swap out
	KindConverging     PolicyDegradedKind = "converging"      // pushed!=applied, fresh, age < T — a normal push settling
	KindSilentDesync   PolicyDegradedKind = "silent_desync"   // pushed!=applied, fresh, age >= T — stuck (the S7.2 nightmare)
	KindDesyncUnknown  PolicyDegradedKind = "desync_unknown"  // can't determine: pushed-hash unavailable, or stamped + reports stale
	// KindUnsupportedPolicyVersion (S8.1 D1): the agent REFUSED the compiled artifact — its
	// Version exceeds what the agent can apply — and went deny-all. UNIQUE remedy: upgrade the
	// agent (every other kind's remedy is CP-side). Highest priority: a refusing gateway isn't
	// stale or apply-failing, it's version-incapable — distinguish it so the operator upgrades.
	KindUnsupportedPolicyVersion PolicyDegradedKind = "unsupported_policy_version"
	// KindSiteHubDown / KindSiteLinkDown (S8.2, Item 7/9): a SITE gateway's site-link is down (stale/no
	// WG handshake), so site-to-site traffic blackholes though the policy may be perfectly synced — a
	// REACHABILITY failure, distinct from a policy desync (whose remedy is CP-side). HUB-down is separate
	// from a single spoke's link-down because the remedy differs entirely: hub-down kills EVERY spoke's
	// site traffic (fix the hub), a spoke link-down kills only that spoke (fix that spoke's tunnel/NAT).
	// Ranked directly below version-refused: for a site gateway, "my site link is dead" is the headline
	// infrastructure signal (the gateway can't do the one thing it exists for); hub outranks spoke.
	KindSiteHubDown  PolicyDegradedKind = "site_hub_down"
	KindSiteLinkDown PolicyDegradedKind = "site_link_down"
	// KindSiteSubnetUnreachable (S8.2c D3): a SITE gateway advertises a local subnet NO host address is
	// inside — it fronts a subnet it isn't actually on (bridge-trapped wg0, or a misconfigured
	// advertisement). The REASSURING-GREEN trap: wg0 is up and the handshake is fresh (so site_link_down
	// is FALSE), yet the LAN is unreachable and site traffic to it blackholes. Ranked directly below the
	// site-link kinds: a reachability/deploy fault whose remedy is operator-side (fix the gateway's host
	// networking — run host-mode / correct the advertised subnet), like the version-refused kind.
	KindSiteSubnetUnreachable PolicyDegradedKind = "site_subnet_unreachable"
	// KindConntrackFlushUnavailable (S8.7 Slice 2): the agent could NOT flush the conntrack entries of an
	// expired/revoked grant (CAP_NET_ADMIN absent in this deployment shape, or a netlink fault) — so
	// established flows under a since-removed grant may LINGER past the grant's death. The policy applies
	// correctly (this is NOT a desync); the degradation is enforcement HYGIENE — a revoked grant's open
	// flows aren't torn down. LOWEST priority: surfaced only when policy is otherwise synced + links up (a
	// desync/apply/link fault is the louder headline and masks it); remedy operator-side (restore
	// CAP_NET_ADMIN to the gateway). Never silent — it lives on the same health plane as every other
	// degradation, not just a log line.
	KindConntrackFlushUnavailable PolicyDegradedKind = "conntrack_flush_unavailable"
	// KindK8sEndpointsUnavailable (S10.3 WF-K5): a K8s gateway has NO successful endpoint view from the K8s
	// API (unreachable / RBAC-denied / watch not synced), so it can't learn any exposed Service's READY pods
	// and programs NO VIP DNAT (fail-closed) — those Services are unreachable while everything else works.
	// Reachability fault, remedy operator-side (gateway's API reachability + the read-only services/
	// endpointslices RBAC). (Renamed from the CoreDNS-era cluster-dns kind — WF-K5 moved target resolution
	// from CoreDNS to a read-only EndpointSlice+Service watch.)
	KindK8sEndpointsUnavailable PolicyDegradedKind = "k8s_endpoints_unavailable"
	// KindHubForwardingNotReconciling (WF-C Layer 2, D-WFC2-1a): a HUB-SET MEMBER whose spoke-observed
	// handshake is FRESH (its wg0 keeps forwarding) while its OWN agent is SILENT (last_seen stale — the
	// agent crashed/OOM'd but the interface it created in the host netns survives). A "zombie hub": the wire
	// is warm, the brain is dead. It CANNOT reconcile — a since-revoked device or tightened grant it never
	// received is still enforced as the frozen last artifact (stale-enforcement, the two-truths class). This
	// is NOT plain "offline" (that would deny it forwards) and NEVER healthy/green (that would deny it's
	// stale) — a THIRD honest state the product could previously not name. Detection is a pure CONJUNCTION of
	// two EXISTING signals — deriveMemberLiveness's wire-freshness ⋂ the node's last_seen staleness — so it
	// mints NO new freshness (the WF-B no-third-freshness discipline). Remedy is unique: restart the agent
	// (the wire is fine — do NOT touch the tunnel). Edition-independent (a crashed agent is core, not policy).
	KindHubForwardingNotReconciling PolicyDegradedKind = "hub_forwarding_not_reconciling"

	// KindCertExpiredCannotReconnect (S11 walk WF-S11-6): the agent's mTLS client certificate has EXPIRED, so
	// it cannot reach ANY agent endpoint — including /agent/renew, the only one that could issue a new
	// certificate. The gateway is BRICKED until a human re-enrolls it; no amount of waiting helps.
	//
	// THIS IS THE STATE THE PRODUCT COULD PREVIOUSLY NOT NAME, and its absence was the sharp half of the
	// finding: a gateway offline for two hours and a gateway offline for two days rendered IDENTICALLY (stale
	// reports, site links down), while demanding completely different actions — wait, versus re-enroll now.
	//
	// Derived from the CP's OWN SIGNING RECORD (nodes.cert_not_after, stamped at enroll/renew), not inferred
	// from silence: silence has many causes, an expiry we ourselves minted has one meaning. That also lets the
	// state be evaluated BEFORE the agent tries and fails — a gateway 40 hours into a 48-hour certificate is
	// eight hours from unrecoverable, which is worth saying while it is still actionable.
	//
	// Ranked HIGHEST, above even unsupported_policy_version: an agent that cannot complete a TLS handshake
	// cannot refuse an artifact, report an apply error, or desync. Every other kind's evidence is its last
	// report, which is by definition stale here — so any other kind would be describing the past and
	// prescribing the wrong remedy.
	KindCertExpiredCannotReconnect PolicyDegradedKind = "cert_expired_cannot_reconnect"
)

// T (desyncDebounce) + the report-freshness window F are derived from the agent REPORT
// interval R (TUNNEX_AGENT_REPORT_INTERVAL, default 30s), NOT the <5s push latency — the
// convergence signal is a REPORT, so a desync younger than a report cycle is expected, not
// stuck. T = 2R: one R for the agent to apply + report the new hash after a push, one R of
// margin for a jittered/dropped report. F = 2R: a node silent for two report cycles can't
// have its desync confirmed → desync_unknown. CP-side constants tied to the DEFAULT R; if an
// operator tunes the agent's report interval, revisit these (the CP can't read the agent's
// env — it logs assumed-R + derived-T at boot for discoverability, see logPolicyHealthTuning).
const (
	// AssumedReportInterval (R) mirrors the agent default; the CP can't read the agent env.
	AssumedReportInterval = 30 * time.Second
	// DesyncSettleWindow (T = 2R) — a term-3 desync younger than this is CONVERGING (a normal
	// push settling), not stuck. The exactly-T boundary is load-bearing (red).
	DesyncSettleWindow = 2 * AssumedReportInterval
	// ReportFreshnessWindow (F = 2R) — a node silent this long can't have its desync confirmed
	// → desync_unknown.
	ReportFreshnessWindow = 2 * AssumedReportInterval
)

// LogPolicyHealthTuning emits the assumed R + derived T at boot so an operator who tuned the
// agent report interval can DISCOVER the coupling (the doc caveat isn't findable at 3am).
func LogPolicyHealthTuning(log interface{ Info(string, ...any) }) {
	log.Info("policy_health_tuning",
		"assumed_report_interval", AssumedReportInterval.String(),
		"desync_settle_window_T", DesyncSettleWindow.String(),
		"report_freshness_window_F", ReportFreshnessWindow.String())
}

// KindInput is the render signature: kind = f(stamp × report-freshness × hash) — plus the
// agent-reported apply error/onset. Every field is CP-known at compute time; nothing here is
// UI state. `pushKnown` false = the compiled (pushed) hash was unavailable (compile fault) →
// the desync term can't be evaluated → can't-determine.
type KindInput struct {
	PolicyError        string        // agent-reported: last apply error ("" = none)
	PolicyFailingSince string        // agent-reported: enforcing-apply failure onset ("" = none)
	PushKnown          bool          // could the CP compute the pushed hash this cycle?
	PushedHash         string        // CP-computed desired hash (valid iff PushKnown)
	AppliedHash        string        // agent-reported hash in force
	DesyncSince        time.Time     // CP-stamped onset of term-3 (zero = not stamped)
	ReportAge          time.Duration // now − last_seen_at (report freshness)
	Now                time.Time
	UnsupportedVersion bool // agent-reported: it REFUSED a too-new artifact (S8.1 D1) → highest-priority kind
	SiteHubDown        bool // S8.2: a site gateway whose HUB site-link has no fresh WG handshake (all spokes' site traffic dead)
	SiteLinkDown       bool // S8.2: a site gateway with ≥1 spoke site-link with no fresh handshake (that spoke's traffic dead)
	// SiteSubnetUnreachable (S8.2c D3): the gateway advertises a local subnet no host address is inside —
	// the reassuring-green bridge-mode trap. INDEPENDENT of SiteLinkDown (fires when the link is FRESH).
	SiteSubnetUnreachable bool
	// ConntrackFlushUnavailable (S8.7 Slice 2): the agent's expired-grant conntrack flush is failing (no
	// CAP_NET_ADMIN / netlink fault). Lowest-priority degradation — surfaced only when policy is otherwise
	// healthy.
	ConntrackFlushUnavailable bool
	// K8sEndpointsUnavailable (S10.3 WF-K5): agent-reported — the gateway has no successful K8s endpoint view
	// (API unreachable / RBAC-denied / watch not synced), so exposed Services can't be DNAT-programmed
	// (fail-closed). Low-priority reachability degradation.
	K8sEndpointsUnavailable bool
	// HubForwardingNotReconciling (WF-C L2 D-WFC2-1a): the zombie-hub conjunction, computed by the CALLER
	// (wire-fresh via deriveMemberLiveness ⋂ agent last_seen stale) — passed in as ONE precomputed bool so
	// degradedKind stays pure and no freshness is recomputed here. Ranked above the apply/desync kinds: a
	// dead agent's LAST report is stale, so its apply-error/desync fields must not mask "the agent is dead".
	HubForwardingNotReconciling bool
	// CertExpired (S11 WF-S11-6): the CP's recorded cert_not_after for this node is in the past. Computed by
	// the CALLER from the node row so degradedKind stays pure and mints no clock of its own. NOT derived from
	// report staleness — that is the whole point: staleness is a symptom with many causes, an expired
	// certificate we issued ourselves is a diagnosis with one remedy.
	CertExpired bool
}

// CertExpiredForNode decides the WF-S11-6 input from a node row. Extracted as a pure function for one reason:
// as an inline expression at the call site it was UNTESTABLE, and the first red written for it asserted only
// that degradedKind(CertExpired: false) does not return the cert-expired kind — a tautology that passed with the
// fix removed (the tautological-guard law, S7.5.5, caught in the act).
//
// Two conditions, each load-bearing:
//
//   - ACTIVE only. Refusing a revoked agent's renewal IS the revocation mechanism, so a revoked node's expired
//     certificate is the system working as designed. Reporting it would prescribe "re-enroll this gateway" for a
//     gateway an operator deliberately retired — an instruction to undo an intentional security action (WF-S11-10,
//     observed on a live dashboard next to the word "revoked").
//   - KNOWN expiry only. An unrecorded expiry is UNKNOWN, never expired: migration 0054 added the column
//     nullable precisely so it could not retroactively brick every enrolled gateway.
func CertExpiredForNode(status string, notAfter time.Time, notAfterKnown bool, now time.Time) bool {
	return status == "active" && notAfterKnown && notAfter.Before(now)
}

// TransitionRule documents ONE state's authoritative evidence-in — mirrors the state × render
// × transition-evidence TABLE in docs/S7.4-decisions.md. Drift between this and degradedKind
// (or the paper) is caught at review; an evidence-less state is a paper finding.
type TransitionRule struct {
	Kind       PolicyDegradedKind
	EvidenceIn string
}

var transitionTable = []TransitionRule{
	{KindCertExpiredCannotReconnect, "CP-recorded cert_not_after is in the PAST (CertExpired) — the agent cannot complete a TLS handshake, so it cannot reach /agent/renew either; remedy = RE-ENROLL the gateway. Ranked FIRST because every other kind's evidence is the agent's last report, which is necessarily stale once it can no longer connect"},
	{KindUnsupportedPolicyVersion, "agent REFUSED a too-new artifact (UnsupportedVersion) — checked FIRST, remedy = upgrade the agent"},
	{KindSiteHubDown, "site gateway, HUB site-link no fresh handshake (SiteHubDown) — remedy = fix the hub; outranks a single spoke link-down"},
	{KindSiteLinkDown, "site gateway, a spoke site-link no fresh handshake (SiteLinkDown) — remedy = fix that spoke's tunnel/NAT"},
	{KindSiteSubnetUnreachable, "site gateway advertises a local subnet no host addr is inside (SiteSubnetUnreachable) — reassuring-green trap; remedy = fix the gateway's host networking"},
	{KindHubForwardingNotReconciling, "hub-set member, wire FRESH but agent last_seen STALE (HubForwardingNotReconciling) — zombie hub, remedy = restart the agent; ranked above apply/desync so a dead agent's stale report can't mask it"},
	{KindHealthy, "not degraded: no error, pushed==applied, reports fresh"},
	{KindApplyFailing, "policy_error set AND policy_failing_since set"},
	{KindStuckEnforcing, "policy_error set AND policy_failing_since EMPTY (pushed=='' && applied!='')"},
	{KindConverging, "term-3 (pushed!=applied), reports fresh, age < T"},
	{KindSilentDesync, "term-3 (pushed!=applied), reports fresh, age >= T"},
	{KindDesyncUnknown, "pushed-hash UNAVAILABLE, OR (stamped AND reports stale) — cannot determine"},
	{KindConntrackFlushUnavailable, "policy in sync but the expired-grant conntrack flush is failing (ConntrackFlushUnavailable) — lowest priority; remedy = restore CAP_NET_ADMIN"},
	{KindK8sEndpointsUnavailable, "K8s gateway has no endpoint view from the API (K8sEndpointsUnavailable) — exposed-Service DNAT unprogrammed, fail-closed; remedy = check the gateway's K8s API reachability + its read-only services/endpointslices RBAC"},
}

// AllKinds returns every health kind, derived from transitionTable — the SOURCE the metrics layer ranges
// over (S11 D3.1). Deriving beats a hand-maintained list: a 14th kind added to the const block without a
// metric path would otherwise be a series that silently never appears (the producer-without-consumer trap at
// the metrics tier). TestEveryHealthKindIsEnumerated parses the const block and fails the build if any kind
// is missing here, so omission is impossible rather than merely discouraged.
func AllKinds() []PolicyDegradedKind {
	out := make([]PolicyDegradedKind, 0, len(transitionTable))
	for _, r := range transitionTable {
		out = append(out, r.Kind)
	}
	return out
}

// degradedKind projects the advisory kind (pure — mirrors transitionTable). Order matters:
// a live apply error is self-evident from the agent's last report; the desync path needs a
// FRESH applied hash (a server-side compare is meaningless on a stale one).
func degradedKind(in KindInput) PolicyDegradedKind {
	// S11 WF-S11-6 — ABSOLUTE highest priority. The agent cannot complete a TLS handshake, so it cannot have
	// reported anything since its certificate lapsed: every field below is stale by construction. Reporting
	// any other kind here would describe a past state and prescribe a remedy that cannot be applied (you
	// cannot upgrade, restart or reconcile your way out of an expired certificate — only re-enroll).
	if in.CertExpired {
		return KindCertExpiredCannotReconnect
	}
	// S8.1 D1 — highest priority among reported states: the agent refused a too-new artifact and went deny-all. This is
	// a version-incapability, not a stale/failing apply; its remedy (upgrade the agent) is unique,
	// so it must not be masked by the desync/apply-error paths below.
	if in.UnsupportedVersion {
		return KindUnsupportedPolicyVersion
	}
	// S8.2 (Item 7/9) — a site gateway's site-link is down: site traffic is dead regardless of policy
	// state, and the remedy is infrastructure (fix the hub / that spoke), not CP-side. HUB-down first
	// (kills every spoke), then a single spoke link-down. Ranked above the policy apply/desync kinds:
	// for a site gateway this is the headline. (A gateway can be BOTH link-down and desync'd; the desync
	// stamp is retained and re-surfaces once the link recovers — the kind is a single summary.)
	if in.SiteHubDown {
		return KindSiteHubDown
	}
	if in.SiteLinkDown {
		return KindSiteLinkDown
	}
	// S8.2c D3 — the gateway advertises a local subnet it isn't on: site traffic to that LAN blackholes
	// even though the link handshake is fresh (the reassuring-green trap). Ranked below the link kinds
	// (a dead link is the louder failure) but above the policy apply/desync kinds — it's a reachability
	// fault, remedy operator-side (fix the gateway host networking), not a CP-side policy issue.
	if in.SiteSubnetUnreachable {
		return KindSiteSubnetUnreachable
	}
	// WF-C L2 (D-WFC2-1a) — the zombie hub: wire fresh, agent dead. Ranked ABOVE the apply/desync kinds
	// because the agent's last report (PolicyError/FailingSince/AppliedHash) is FROZEN at the crash — a
	// stale "apply_failing" must not mask "the agent is dead, restart it". Below the site-reachability kinds
	// (a dead org transit is the louder headline; a standby zombie can co-occur with the primary's link-down).
	if in.HubForwardingNotReconciling {
		return KindHubForwardingNotReconciling
	}
	// Agent-reported apply failure (from the last report — a reported fact, not a server compare).
	// [fold 3] mirror the bool's TERM-2: policy_failing_since alone (error empty) is a failing
	// enforcing apply — apply_failing, NEVER the benign desync path. Order: failing_since first.
	if in.PolicyFailingSince != "" {
		return KindApplyFailing // an enforcing apply is failing (onset stamped), with or without an error string
	}
	if in.PolicyError != "" {
		return KindStuckEnforcing // error + no failing_since = enforcing a disabled policy (S7.2 stuck branch)
	}
	// No error → desync territory (term-3). Can't compute pushed → can't determine.
	if !in.PushKnown {
		return KindDesyncUnknown
	}
	// pushed "" = non-enforcing (off/mesh) — no enforcement boundary, so never a desync
	// (mirrors the bool's term-3 `h != ""` guard). Equal hashes = in sync / reconverged.
	if in.PushedHash == "" || in.AppliedHash == in.PushedHash {
		// S8.7 Slice 2 — LOWEST priority: policy is in sync, but the expired-grant conntrack flush is
		// failing (revoked grants' flows may linger). Ranked here so any louder fault (version/apply/desync/
		// link) masks it; only an otherwise-healthy gateway surfaces conntrack_flush_unavailable.
		// S10.3 WF-K5 — a K8s gateway with no endpoint view from the API: exposed-Service DNAT can't be
		// programmed (fail-closed), so those Services are unreachable while everything else works. Ranked in the
		// otherwise-healthy block, above the conntrack hygiene label (a dead exposed-Service surface is more
		// user-visible than lingering revoked flows).
		if in.K8sEndpointsUnavailable {
			return KindK8sEndpointsUnavailable
		}
		if in.ConntrackFlushUnavailable {
			return KindConntrackFlushUnavailable
		}
		return KindHealthy
	}
	// pushed != applied. A stale report can't confirm ONGOING desync → desync_unknown (the
	// stamp is retained elsewhere; silence never clears it). NEVER healthy, NEVER silent_desync.
	if in.ReportAge >= ReportFreshnessWindow {
		return KindDesyncUnknown
	}
	// Fresh + mismatched: onset age decides converging vs stuck. A zero onset is a not-yet-
	// stamped race (this report's ingest stamps it) → just-onset = converging.
	if in.DesyncSince.IsZero() || in.Now.Sub(in.DesyncSince) < DesyncSettleWindow {
		return KindConverging
	}
	return KindSilentDesync // fresh, mismatched, age >= T
}

// RekeyAuthorized is the S13.1 D3 GATE, built before any re-key mechanism because a property that must never
// happen is easier to prove impossible than to retrofit.
//
// AUTHORIZED BY CERTIFICATE EXPIRY ONLY. Revocation REFUSES.
//
// THE ATTACK THAT AMENDED THIS GATE. D3 originally listed `revoked` as authorizing — it looked like the strongest
// evidence a node is gone. It is, and that was the wrong question. Trace it:
//
//  1. an attacker steals a gateway's state volume, which is its private key;
//  2. the operator notices and REVOKES that gateway — the product's answer to a stolen credential;
//  3. the attacker calls re-key, proving possession of the stolen key;
//  4. `revoked` authorizes it;
//  5. the attacker holds a fresh certificate for that node id — active, same site binding, same policy.
//
// Revocation defeated by the exact credential it was invoked against. The paper already forbade this in a
// condition on the same page ("re-key must not become an un-revoke; revocation is the product's security
// primitive") — the evidence list contradicted a condition in its own document. The condition was right and the
// list was wrong.
//
// THE DISTINCTION, which generalizes past this endpoint: EXPIRY IS AN ABSENCE OF ACTION; REVOCATION IS THE
// PRESENCE OF A DECISION. A cryptographic proof may overturn the first and must never overturn the second, because
// the proof cannot distinguish the legitimate holder from whoever took the key — and revocation is precisely the
// response to that ambiguity. A revoked gateway recovers through an operator-minted join token: a human act, which
// is the right gate for undoing a human decision.
//
// ALSO INADMISSIBLE:
//
//   - `last_seen_at` stale. Silence is not proof a credential cannot work — the inference the EPIC 11 walk taught
//     us to refuse. This function takes no liveness argument at all, so it cannot be passed in by mistake.
//   - Any operator- or client-supplied "force". A guard overridable by the party most motivated to override it is
//     documentation. There is no parameter for it and there must not be.
//
// THE RETURNED REASON IS FOR THE LOG, NEVER THE RESPONSE. D8's uniform-refusal rule: an attacker probing with a
// stolen key must not learn revoked-versus-not-found-versus-live. The remedy belongs in the operator-facing docs
// and the health surface, not in what the endpoint says back.
// certUndelivered is the REDELIVERY carve-out (S13.1 D3, RULED after review pass 1 #3 and the live-node takeover
// its first version introduced).
//
// THE COLLISION IT SOLVES. D10 exists so a LOST RESPONSE cannot brick a gateway: the control plane committed a
// certificate the agent never received. But committing it ALSO advanced cert_not_after, the column this gate
// reads, so the node looked LIVE and the gate refused the recovery D10 was built for — for a full 48h lifetime.
//
// THE FAILED FIRST ATTEMPT, ON THE RECORD. The carve-out was first written as "the caller proves the key the CP
// currently records". That authorized any holder of the private key INCLUDING while the gateway was running, and
// because RekeyNode replaces cert_serial — the column the agent channel authenticates against — exercising it
// DISPLACED the live gateway. It needed only the private key, never the certificate, so a key stolen without its
// certificate went from inert to immediately usable. A live-node takeover through the gate built to refuse live
// nodes.
//
// THE PREDICATE THAT IS ACTUALLY MEANT. Not "who is asking" but "was the thing we issued ever delivered". A
// running gateway's certificate HAS AUTHENTICATED — that is what running means — so it is marked delivered
// (MarkCertDelivered, on first use), and the live case cannot arise. Undelivered is a state only a lost response
// produces.
//
// It still cannot rotate to a different key (the caller must ask for a certificate over the recorded one), and it
// still cannot touch a REVOKED node — that check runs first, unconditionally, because revocation is a human
// decision no proof may overturn.
func RekeyAuthorized(status string, certNotAfter time.Time, certNotAfterKnown bool, now time.Time, certUndelivered bool) (bool, string) {
	if status == "revoked" {
		return false, "node is REVOKED — an operator deliberately retired it, and a proof of possession cannot " +
			"distinguish the real gateway from whoever holds its stolen key. Re-key must never un-revoke. " +
			"Recover it with an operator-minted join token"
	}
	if certUndelivered {
		return true, "the certificate this control plane last issued for this node has NEVER been used to " +
			"authenticate, and the caller asked for one over the same recorded key — a REDELIVERY of a grant that " +
			"was made but never arrived (D10 lost-response recovery). A running gateway's certificate has " +
			"authenticated by definition, so this state cannot describe a live node"
	}
	if !certNotAfterKnown {
		// UNKNOWN is not gone. A row with no recorded expiry predates migration 0054 and 0055 declined to bound
		// it (it had never reported), so the CP knows nothing about whether this node still works.
		return false, "this control plane has no record of when the node's certificate expires, so it cannot " +
			"establish that the node is gone. Recover it with an operator-minted join token"
	}
	if certNotAfter.Before(now) {
		return true, "the certificate this control plane issued expired at " +
			certNotAfter.UTC().Format(time.RFC3339) + " — the agent cannot authenticate and cannot renew"
	}
	return false, "the node's certificate is still valid until " + certNotAfter.UTC().Format(time.RFC3339) +
		" — a live gateway must never be re-keyed. Revoke it first if you intend to replace it"
}

// Package flowlog is the agent-side flow-observation pipeline for S7.5.1 (the VISIBILITY
// half of Zero Trust). It reads flow verdicts the kernel emits from the gateway forward
// chain (nft log, rule_id carried in the log prefix — no packet re-match), buffers them in
// a BOUNDED, NON-BLOCKING ring, and hands batches to the reporter.
//
// ENFORCEMENT ISOLATION (the hard guarantee): this package imports NOTHING from egress and
// is never on the forward-chain apply path. Observation is best-effort and async — if the
// reader dies, the buffer overflows, or the reporter fails, packets still accept/drop
// correctly (the kernel's `log` statement is non-terminal + best-effort: an nflog buffer
// full drops LOG MESSAGES, never packets). Observability may die; enforcement may not.
package flowlog

import "time"

// Verdict is the packet fate the kernel recorded for a flow's first packet (ct state new).
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
	// VerdictTerminated is a flow TORN DOWN by a policy change — the DORMANT seam (6/n): a
	// future agent-side conntrack flush on rule-revoke will emit an Event with this verdict
	// + the REVOKED grant's RuleID (the carried "conntrack-kill, same rule identity" binding).
	// Not produced by the nflog pump (that only sees allow/deny at flow-start); the kill code
	// constructs it directly and buffers it. The kill itself is a ledgered S7.2-class
	// enforcement follow-up (see docs/S7.5.1-decisions.md); this verdict is the ready contract.
	VerdictTerminated Verdict = "terminated"
)

// Reason is the bounded enforcement-owned explanation for a verdict. It is
// stamped from the kernel grant/default-deny prefix (or an explicit
// terminated/gap constructor), never reconstructed from a packet tuple.
type Reason string

const (
	ReasonMatchedGrant    Reason = "matched_grant"
	ReasonNoMatchingGrant Reason = "no_matching_grant"
	ReasonGrantRevoked    Reason = "grant_revoked"
	ReasonEventsDropped   Reason = "events_dropped"
)

// Attribution is the event-time metadata installed with the last successfully
// applied policy artifact. A nil ConfigRevision means the artifact did not
// record an agent runtime revision.
type Attribution struct {
	PolicyHash     string
	PolicyVersion  int
	SrcDeviceID    string
	SrcDeviceKind  string
	ConfigRevision *int64
}

// Event is ONE flow observation the agent ships to the control plane. The agent stamps
// RuleID (kernel-carried via the nft log prefix — attribution rides the grant the kernel
// matched, NOT a userspace re-derivation) and PolicyHash (the applied artifact hash at
// observation). F07 persists PolicyHash + PolicyVersion as event-time facts; the existing
// node-status desync path remains the live health signal. The
// agent ships IP-level facts. DEVICE identity (S7.5.4 v3) is now agent-STAMPED from the
// applied artifact's /32->device map (SrcDeviceID) — still NOT an src_ip->device DB guess;
// the CP joins device->user server-side. Resource enrichment stays CP-side at ingest.
type Event struct {
	OccurredAt        time.Time `json:"occurred_at"`
	Verdict           Verdict   `json:"verdict"`
	RuleID            string    `json:"rule_id,omitempty"` // "" = default-deny / no matching rule
	PolicyHash        string    `json:"policy_hash"`       // applied CanonicalHash at observation
	PolicyVersion     int       `json:"policy_version,omitempty"`
	SrcIP             string    `json:"src_ip"`
	SrcDeviceID       string    `json:"src_device_id,omitempty"` // v3: source device uuid from the artifact map ("" = unresolved src)
	SrcDeviceKind     string    `json:"src_device_kind,omitempty"`
	SrcConfigRevision *int64    `json:"src_config_revision,omitempty"`
	DstIP             string    `json:"dst_ip"`
	Protocol          string    `json:"protocol"`
	DstPort           int       `json:"dst_port,omitempty"`
	Reason            Reason    `json:"reason"`
}

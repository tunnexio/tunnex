// Package accesslog is the storage layer for S7.5.1 flow/access events — the
// VISIBILITY half of Zero Trust. Two stores share the Event contract: a bounded,
// queryable PG hot-window (the dashboard + keyset pull-API) and an append-only,
// rotating JSONL stream (the SIEM source-of-truth + retention record). The ingest +
// enrichment path (slice 4) produces Events; this package persists them.
package accesslog

import (
	"time"

	"github.com/google/uuid"
)

// Decision is the fate the gateway recorded for a flow.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	// DecisionDenyAggregate is a per-source deny COLLAPSE (D1): a port-scan is an
	// attacker-controlled flood, so N denies from one source in a window become one
	// event with DenyCount + WindowEnd — the signal survives, the volume does not.
	DecisionDenyAggregate Decision = "deny_aggregate"
	// DecisionTerminated is a flow KILLED by a policy change (the conntrack-kill binding):
	// its grant was revoked, so the established connection was torn down. Carries the SAME
	// RuleID the kill used.
	DecisionTerminated Decision = "terminated"
	// DecisionGap is a LEGIBLE hole marker: the CP writes it when an agent reports dropped
	// events (buffer overflow or kernel nflog overrun). DenyCount carries N ("N events
	// dropped here") so a hole in the audit trail is visible, never inferred.
	DecisionGap Decision = "gap"
)

// Retention + rotation defaults (D3/D4) — NAMED so a POC never silently fills the
// customer's disk. The PG hot-window is trimmed to whichever of age/row-cap hits first;
// the JSONL stream (the source-of-truth) rotates by size and is the retention record.
const (
	DefaultRetention = 30 * 24 * time.Hour // PG hot-window: max INGEST age kept
	DefaultPGRowCap  = 100_000             // PG hot-window: max rows per org
	// RetentionSweepInterval is how often the CP runs the hot-window sweep (wired in main).
	// Frequent enough to bound growth between runs, cheap enough to be idle.
	RetentionSweepInterval = 10 * time.Minute
)

// Event is ONE identity-level access event — a flow the gateway allowed or denied (or a
// flow a policy change terminated). It is the SHARED contract: the PG row and the JSONL
// line both marshal from this. Enriched identity fields are pointers (nil = unresolved or
// not applicable); Seq is the per-org monotonic tamper-evidence sequence assigned at
// ingest (slice 4), carried into BOTH stores so the same event cross-references.
type Event struct {
	ID uuid.UUID `json:"id"`
	// CreatedAt is the CP INGEST time — the keyset-pagination + retention clock (NOT the
	// agent-clock OccurredAt). Set at ingest so PG and the JSONL line agree.
	CreatedAt     time.Time  `json:"created_at"`
	Seq           int64      `json:"seq"`
	OrgID         uuid.UUID  `json:"org_id"`
	NodeID        *uuid.UUID `json:"node_id,omitempty"` // observing gateway
	OccurredAt    time.Time  `json:"occurred_at"`       // agent clock (flow observation)
	Decision      Decision   `json:"decision"`
	RuleID        *uuid.UUID `json:"rule_id,omitempty"` // the grant (nil = default-deny / no match)
	SrcDeviceID   *uuid.UUID `json:"src_device_id,omitempty"`
	SrcUserID     *uuid.UUID `json:"src_user_id,omitempty"`
	SrcIP         string     `json:"src_ip"`
	DstIP         string     `json:"dst_ip"`
	DstResourceID *uuid.UUID `json:"dst_resource_id,omitempty"`
	DstGroupID    *uuid.UUID `json:"dst_group_id,omitempty"`
	Protocol      string     `json:"protocol"`
	DstPort       int        `json:"dst_port,omitempty"`
	DenyCount     int        `json:"deny_count,omitempty"` // >1 only for deny_aggregate
	WindowEnd     *time.Time `json:"window_end,omitempty"` // deny_aggregate: end of the collapse window
}

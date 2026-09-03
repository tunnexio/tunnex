// Package accesslog is the PostgreSQL storage layer for S7.5.1 flow/access events —
// the VISIBILITY half of Zero Trust. The ingest and enrichment path produces Events;
// this package persists and prunes the queryable dashboard/API window. The proposed
// JSONL archive/export remains deferred and is not a durability claim of this store.
package accesslog

import (
	"time"

	"github.com/google/uuid"
)

// Decision is the fate the gateway recorded for a flow.
type Decision string

type DecisionReason string

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

const (
	ReasonMatchedGrant    DecisionReason = "matched_grant"
	ReasonNoMatchingGrant DecisionReason = "no_matching_grant"
	ReasonGrantRevoked    DecisionReason = "grant_revoked"
	ReasonEventsDropped   DecisionReason = "events_dropped"
)

// Retention defaults (D3) — NAMED so a POC never silently fills the customer's
// disk. The PG window is pruned toward whichever of age/row target hits first.
const (
	DefaultRetentionDays           int32 = 30
	MinRetentionDays               int32 = 1
	MaxRetentionDays               int32 = 3650
	DefaultCleanupIntervalMinutes  int32 = 60
	MinCleanupIntervalMinutes      int32 = 5
	MaxCleanupIntervalMinutes      int32 = 1440
	DefaultPGRowCap                int32 = 100_000 // fixed per-org asynchronous pruning target
	RetentionBatchSize             int32 = 1_000   // maximum rows in one delete transaction
	RetentionMaxBatches            int32 = 100     // maximum deletes in one claimed run
	DefaultRetention                     = time.Duration(DefaultRetentionDays) * 24 * time.Hour
	RetentionRunLease                    = 15 * time.Minute
	RetentionSchedulerPollInterval       = time.Minute
)

// Event is one identity-level access event — an eligible new packet the gateway
// allowed or denied (or a flow a policy change terminated). Enriched identity
// fields are pointers (nil = unresolved or not applicable); Seq is the
// per-organization monotonic sequence assigned at ingest.
type Event struct {
	ID uuid.UUID `json:"id"`
	// CreatedAt is the CP INGEST time — the keyset-pagination + retention clock (NOT the
	// agent-clock OccurredAt).
	CreatedAt         time.Time      `json:"created_at"`
	Seq               int64          `json:"seq"`
	OrgID             uuid.UUID      `json:"org_id"`
	NodeID            *uuid.UUID     `json:"node_id,omitempty"` // observing gateway
	OccurredAt        time.Time      `json:"occurred_at"`       // agent clock (flow observation)
	Decision          Decision       `json:"decision"`
	RuleID            *uuid.UUID     `json:"rule_id,omitempty"` // the grant (nil = default-deny / no match)
	PolicyHash        string         `json:"policy_hash,omitempty"`
	PolicyVersion     int            `json:"policy_version,omitempty"`
	SrcDeviceID       *uuid.UUID     `json:"src_device_id,omitempty"`
	SrcUserID         *uuid.UUID     `json:"src_user_id,omitempty"`
	SrcConfigRevision *int64         `json:"src_config_revision,omitempty"`
	SrcKind           string         `json:"src_kind,omitempty"`
	DecisionReason    DecisionReason `json:"decision_reason,omitempty"`
	SrcIP             string         `json:"src_ip"`
	DstIP             string         `json:"dst_ip"`
	DstResourceID     *uuid.UUID     `json:"dst_resource_id,omitempty"`
	DstGroupID        *uuid.UUID     `json:"dst_group_id,omitempty"`
	Protocol          string         `json:"protocol"`
	DstPort           int            `json:"dst_port,omitempty"`
	DenyCount         int            `json:"deny_count,omitempty"` // >1 only for deny_aggregate
	WindowEnd         *time.Time     `json:"window_end,omitempty"` // deny_aggregate: end of the collapse window
}

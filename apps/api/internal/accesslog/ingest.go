package accesslog

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// Wire verdict values (the agent's flowlog.Verdict, as a string on the ingest wire).
const (
	wireAllow      = "allow"
	wireDeny       = "deny"
	wireTerminated = "terminated" // 6/n seam: a flow torn down by a policy-rule revoke
)

// DenyAggregateThreshold bounds the port-scan log-DoS (D1): within ONE report batch (the
// window = the agent's drain/report interval), if a single src_ip produces MORE than this
// many denies, they collapse into ONE deny_aggregate event carrying the count — the signal
// (who scanned, how much) survives, the volume does not. Allows are NEVER aggregated
// (legitimate volume); a src at or under the threshold keeps its individual denies.
const DenyAggregateThreshold = 5

// WireEvent is the agent→CP flow-event shape (mirrors node flowlog.Event). Defined here so
// the api module never imports the node module. Verdict is "allow" | "deny".
type WireEvent struct {
	OccurredAt  time.Time `json:"occurred_at"`
	Verdict     string    `json:"verdict"`
	RuleID      string    `json:"rule_id,omitempty"`
	PolicyHash  string    `json:"policy_hash"`
	SrcIP       string    `json:"src_ip"`
	SrcDeviceID string    `json:"src_device_id,omitempty"` // v3: agent-stamped from the artifact ("" = unresolved)
	DstIP       string    `json:"dst_ip"`
	Protocol    string    `json:"protocol"`
	DstPort     int       `json:"dst_port,omitempty"`
}

// GrantResolver maps a kernel-stamped rule_id to the grant's destination, captured AT EVENT
// TIME so it survives a later rule delete. NO src_ip→device lookup anywhere (that would be a
// racy IP-map reconstruction; attribution rides authoritative agent-stamped identity). The
// v3 device identity (src_device_id) is stamped BY THE AGENT from the compiled artifact's
// /32→device map — the CP only joins device→user (an ID FK, DeviceResolver), never src_ip.
// ok=false = the rule was already deleted.
type GrantResolver interface {
	ResolveGrant(ctx context.Context, orgID, ruleID uuid.UUID) (dstResource, dstGroup *uuid.UUID, ok bool)
}

// DeviceResolver joins an agent-stamped src_device_id to its owning user (S7.5.4 v3). This
// is an ID→ID FK join, NEVER an src_ip→device guess. ok=false = the device is unknown/foreign
// to this org — the event drops BOTH device + user to unattributed (an unverifiable id is not
// persisted; [9] cross-tenant-seed guard).
type DeviceResolver interface {
	ResolveUser(ctx context.Context, orgID, deviceID uuid.UUID) (userID *uuid.UUID, ok bool)
}

// SQLDeviceResolver is the production DeviceResolver: src_device_id → owning user via the
// DB, org-scoped, NO deleted_at filter (a since-deleted device's historical flow still
// attributes its user). Mirrors SQLGrantResolver.
type SQLDeviceResolver struct{ Q *sqlc.Queries }

// ResolveUser implements DeviceResolver.
func (r SQLDeviceResolver) ResolveUser(ctx context.Context, orgID, deviceID uuid.UUID) (*uuid.UUID, bool) {
	uid, err := r.Q.GetDeviceUserForOrg(ctx, sqlc.GetDeviceUserForOrgParams{ID: deviceID, OrgID: orgID})
	if err != nil {
		return nil, false
	}
	return &uid, true
}

// SQLGrantResolver is the production GrantResolver: rule_id → the grant's destination via
// the DB, org-scoped. A deleted/unknown rule resolves to (nil,nil,false) — the event keeps
// its raw rule_id, the dst is simply not captured. This is the ONLY enrichment lookup; it
// takes a rule_id, never a src_ip.
type SQLGrantResolver struct{ Q *sqlc.Queries }

// ResolveGrant implements GrantResolver.
func (r SQLGrantResolver) ResolveGrant(ctx context.Context, orgID, ruleID uuid.UUID) (*uuid.UUID, *uuid.UUID, bool) {
	row, err := r.Q.GetPolicyRuleForOrg(ctx, sqlc.GetPolicyRuleForOrgParams{ID: ruleID, OrgID: orgID})
	if err != nil {
		return nil, nil, false
	}
	return uuidPtr(row.DstResourceID), uuidPtr(row.DstGroupID), true
}

// Ingester turns an agent report batch into persisted access events: enrich (grant-only),
// aggregate per-source denies, mark gaps, assign the per-org monotonic seq, and persist to the
// PG hot-window.
//
// NOTE (S7.5.1b deferral): the JSONL on-disk source-of-truth + byte-verbatim export were
// DEFERRED to S7.5.1b after the writer failed to converge over six review rounds (see
// docs/S7.5.1-decisions.md). v1 is PG-only; the per-org monotonic seq column REMAINS in PG as
// the follow-up's anchor + the gap detector.
//
// CONCURRENCY (review #1): the net/http agent channel calls IngestBatch from a per-request
// goroutine, so the SAME Ingester is hit concurrently. The per-org DB counter (BumpOrgFlowSeq)
// row-locks the org row, serializing same-org ingest so seq can never collide; a process-level
// `mu` additionally serializes the batch (defensive + keeps a single ordering point). seq is
// reserved from the per-org counter (organizations.flow_seq) INSIDE the per-batch tx, so a
// rolled-back batch releases its reserved range (no burn, no false gap), and the counter is
// never swept so seq is monotonic + sweep-proof.
type Ingester struct {
	mu      sync.Mutex // serializes IngestBatch (seq reservation + inserts) — defensive over the DB row lock
	pool    *pgxpool.Pool
	grants  GrantResolver
	devices DeviceResolver // v3: src_device_id → user join (may be nil = no device attribution)
	health  *Health
	now     func() time.Time
}

// NewIngester wires the pool (for the per-batch tx), the grant + device resolvers, and the
// health surface. now defaults to time.Now; health + devices may be nil.
func NewIngester(pool *pgxpool.Pool, grants GrantResolver, devices DeviceResolver, health *Health, now func() time.Time) *Ingester {
	if now == nil {
		now = time.Now
	}
	return &Ingester{pool: pool, grants: grants, devices: devices, health: health, now: now}
}

// IngestBatch persists one agent report: the observed events (enriched + aggregated) plus,
// if the agent dropped any, a single legible gap marker carrying the dropped count.
func (i *Ingester) IngestBatch(ctx context.Context, orgID, nodeID uuid.UUID, wire []WireEvent, dropped int64) error {
	events := i.aggregate(ctx, orgID, nodeID, wire)
	if dropped > 0 {
		// The gap marker sits in-stream where the loss occurred (an auditor sees it).
		events = append(events, Event{
			OrgID: orgID, NodeID: &nodeID, OccurredAt: i.now().UTC(),
			Decision: DecisionGap, DenyCount: int(dropped),
		})
	}
	if len(events) == 0 {
		return nil
	}
	// One ingest clock for the whole batch — the PG keyset created_at.
	ingestAt := i.now().UTC()
	for idx := range events {
		events[idx].CreatedAt = ingestAt
		// uuid v7 (time-ordered): within a batch all events share created_at, so the
		// (created_at DESC, id DESC) keyset falls to id — v7 keeps that in occurrence order
		// (review #5). uuid.NewV7 only errors on a crypto/rand failure; surface it.
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		events[idx].ID = id
	}

	// One critical section (seq reservation + PG inserts): serializes concurrent same-org ingest
	// so seq never collides (review #1). The per-org DB counter row-lock is the primary guard;
	// this process mutex is defensive + a single ordering point.
	i.mu.Lock()
	defer i.mu.Unlock()

	// PG: all inserts in ONE tx. seq is reserved from the per-org sweep-proof counter, whose
	// UPDATE row-locks the org row (serializes same-org even across instances). On failure
	// nothing commits and the counter bump rolls back → no burn → the agent's next report gaps.
	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	q := sqlc.New(tx)
	top, err := q.BumpOrgFlowSeq(ctx, sqlc.BumpOrgFlowSeqParams{N: int64(len(events)), OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // org soft-deleted / absent — nothing to ingest; drop the batch (not an error)
	}
	if err != nil {
		return err
	}
	base := top - int64(len(events)) // the reserved range is base+1 .. top
	params := make([]sqlc.InsertAccessEventBatchParams, len(events))
	for idx := range events {
		events[idx].Seq = base + int64(idx) + 1
		params[idx] = sqlc.InsertAccessEventBatchParams(InsertParams(events[idx]))
	}
	// Pipeline the whole batch's inserts in ONE round trip (fold-2 #6) so the process-global
	// ingest mutex is held for far less time. A (org_id, seq) collision is IMPOSSIBLE under the
	// counter, so any error here fails LOUD (never a silent drop).
	var insErr error
	br := q.InsertAccessEventBatch(ctx, params)
	br.Exec(func(_ int, err error) {
		if err != nil && insErr == nil {
			insErr = err
		}
	})
	if err := br.Close(); err != nil {
		return err
	}
	if insErr != nil {
		return insErr
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	// (S7.5.1b) the JSONL source-of-truth write happened HERE, after commit. Deferred — v1 is
	// PG-only. The per-line seq already committed above is the follow-up's anchor + gap detector.
	return nil
}

// grantCache memoizes rule_id → grant-dst resolution FOR ONE batch (fold-2 #5): a report
// where many flows share a grant resolved the same rule_id once per event (N+1). Keyed by
// rule_id; each distinct rule_id hits the DB at most once per batch.
type grantCache struct {
	r    GrantResolver
	seen map[uuid.UUID]grantHit
}

type grantHit struct {
	res, grp *uuid.UUID
	ok       bool
}

func (c *grantCache) resolve(ctx context.Context, orgID, ruleID uuid.UUID) (*uuid.UUID, *uuid.UUID, bool) {
	if h, ok := c.seen[ruleID]; ok {
		return h.res, h.grp, h.ok
	}
	res, grp, ok := c.r.ResolveGrant(ctx, orgID, ruleID)
	c.seen[ruleID] = grantHit{res, grp, ok}
	return res, grp, ok
}

// deviceCache memoizes device→user joins per batch — many flows share a src device, so this
// avoids an N+1 (mirrors grantCache). nil resolver => never joins (device stays unattributed).
type deviceCache struct {
	r    DeviceResolver
	seen map[uuid.UUID]deviceHit
}

type deviceHit struct {
	user *uuid.UUID
	ok   bool // the device id belongs to THIS org (an org-scoped resolve confirmed it)
}

// resolve returns the owning user AND whether the device id is a VERIFIED org device. An
// agent-stamped id that does not resolve to this org (ok=false) is treated as unverified —
// the caller drops it to unattributed (an unverifiable id is ABSENT, never persisted as if
// authoritative; the S7.5.3 no-guess law) rather than seeding the immutable log with a
// foreign/forged device id (the [9] cross-tenant-seed the story-end review flagged).
func (c *deviceCache) resolve(ctx context.Context, orgID, deviceID uuid.UUID) (*uuid.UUID, bool) {
	if c == nil || c.r == nil {
		return nil, false
	}
	if h, seen := c.seen[deviceID]; seen {
		return h.user, h.ok
	}
	u, ok := c.r.ResolveUser(ctx, orgID, deviceID)
	c.seen[deviceID] = deviceHit{user: u, ok: ok}
	return u, ok
}

// aggregate enriches each wire event (grant-only) and collapses per-source deny floods.
func (i *Ingester) aggregate(ctx context.Context, orgID, nodeID uuid.UUID, wire []WireEvent) []Event {
	out := make([]Event, 0, len(wire))
	gc := &grantCache{r: i.grants, seen: map[uuid.UUID]grantHit{}}    // one grant lookup per distinct rule_id per batch
	dc := &deviceCache{r: i.devices, seen: map[uuid.UUID]deviceHit{}} // one device→user lookup per distinct device per batch
	denyBySrc := map[string][]WireEvent{}
	for _, w := range wire {
		switch w.Verdict {
		case wireDeny:
			denyBySrc[w.SrcIP] = append(denyBySrc[w.SrcIP], w)
		case wireTerminated:
			// A flow torn down by a rule-revoke — enriched on the REVOKED grant's rule_id (the
			// carried binding), NEVER aggregated (each termination is a distinct event).
			out = append(out, i.enrich(ctx, gc, dc, orgID, nodeID, w, DecisionTerminated))
		default: // allow
			out = append(out, i.enrich(ctx, gc, dc, orgID, nodeID, w, DecisionAllow))
		}
	}
	// Deterministic order: aggregate/emit denies by src.
	srcs := make([]string, 0, len(denyBySrc))
	for s := range denyBySrc {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	for _, s := range srcs {
		ds := denyBySrc[s]
		if len(ds) > DenyAggregateThreshold {
			// Collapse: one deny_aggregate carrying the src (via enrich), the count, and the
			// full window BOUNDS — OccurredAt = first deny seen, WindowEnd = last — so a SIEM
			// has src + count + [start,end] without the individual lines.
			last := ds[len(ds)-1]
			agg := i.enrich(ctx, gc, dc, orgID, nodeID, last, DecisionDenyAggregate)
			agg.OccurredAt = ds[0].OccurredAt.UTC() // window START
			agg.DenyCount = len(ds)
			end := last.OccurredAt.UTC() // window END
			agg.WindowEnd = &end
			out = append(out, agg)
			continue
		}
		for _, w := range ds {
			out = append(out, i.enrich(ctx, gc, dc, orgID, nodeID, w, DecisionDeny))
		}
	}
	return out
}

// enrich builds an Event from a wire event. Attribution: rule_id → the grant's destination
// (resource/group), and — v3 — the AGENT-STAMPED src_device_id → its owning user (CP-side ID
// join). There is STILL NO src_ip→device lookup: device identity arrives stamped from the
// artifact, and the CP joins only device→user (an ID FK, never a racy IP-map). src_ip is kept
// as the raw observed fact.
func (i *Ingester) enrich(ctx context.Context, gc *grantCache, dc *deviceCache, orgID, nodeID uuid.UUID, w WireEvent, d Decision) Event {
	e := Event{
		OrgID: orgID, NodeID: &nodeID, OccurredAt: w.OccurredAt.UTC(), Decision: d,
		SrcIP: w.SrcIP, DstIP: w.DstIP, Protocol: w.Protocol, DstPort: w.DstPort,
	}
	if rid, err := uuid.Parse(w.RuleID); err == nil {
		e.RuleID = &rid
		if res, grp, ok := gc.resolve(ctx, orgID, rid); ok { // per-batch memoized (fold-2 #5)
			e.DstResourceID, e.DstGroupID = res, grp // grant dst captured at event time
		}
	}
	// v3: the agent stamped src_device_id from the applied artifact — capture it and join to
	// the owning user (per-batch memoized). Store it ONLY when the org-scoped resolve VERIFIES
	// it is this org's device ([9]): an unverified/foreign id (a buggy or compromised agent) is
	// dropped to unattributed — an unverifiable fact is ABSENT, never persisted into the
	// immutable log where a viewer could later surface a foreign device (cross-tenant seed).
	// The mismatch is LOGGED (a compromise/bug signal), not silently swallowed.
	if did, err := uuid.Parse(w.SrcDeviceID); err == nil {
		if user, ok := dc.resolve(ctx, orgID, did); ok {
			e.SrcDeviceID = &did
			e.SrcUserID = user
		} else {
			slog.Warn("flow_event_unverified_device_id",
				slog.String("org_id", orgID.String()), slog.String("node_id", nodeID.String()),
				slog.String("stamped_device_id", did.String()))
		}
	}
	return e
}

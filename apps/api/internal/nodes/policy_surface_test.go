package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// TestZombieHubConjunction_WFC_L2 (D-WFC2-1a + WF-C-L2-1 settle) — the zombie-hub kind fires only when this
// hub-set member's wire is FRESH (spokes still handshake it) AND its agent has been silent a settle-window
// (hubStaleWindow) LONGER than that last handshake. TRUE positive fires + persists; a CLEAN death (agent +
// wire die together → ages track) NEVER flashes the kind (WF-C-L2-1's flicker fix); both-fresh → healthy;
// stale wire → not the kind. DB-less via the `pre` SiteTopoBatch seam; open edition (edition-independent).
func TestZombieHubConjunction_WFC_L2(t *testing.T) {
	org, id, site := uuid.New(), uuid.New(), uuid.New()
	now := time.Now()
	open := &Service{policy: nil}
	// node with the agent last seen `agentAge` ago (or never, seenValid=false).
	node := func(agentAge time.Duration, seenValid bool) sqlc.Node {
		ls := pgtype.Timestamptz{Valid: seenValid}
		if seenValid {
			ls.Time = now.Add(-agentAge)
		}
		return sqlc.Node{ID: id, OrgID: org, SiteID: pgtype.UUID{Bytes: site, Valid: true},
			LastSeenAt: ls, Capabilities: capsJSON(map[string]any{})}
	}
	// batch with this member's liveness verdict (Age = last-handshake age). hasHub avoids site_hub_down.
	batch := func(ml MemberLiveness) SiteTopoBatch {
		return SiteTopoBatch{ok: true, hasHub: true, memberLive: map[uuid.UUID]MemberLiveness{id: ml}}
	}
	fresh := func(age time.Duration) MemberLiveness { return MemberLiveness{Observed: true, Fresh: true, Age: age} }
	kind := func(pre SiteTopoBatch, n sqlc.Node) (bool, PolicyDegradedKind) {
		h := open.PolicyHealthForNodes(context.Background(), org, []sqlc.Node{n}, pre)[id]
		return h.Degraded, h.Kind
	}

	// TRUE zombie: wire fresh (handshake 10s — spokes still hitting the live wg0) + agent long-dead (10m) →
	// silent WAY longer than the last handshake → forwarding-but-not-reconciling.
	if deg, k := kind(batch(fresh(10*time.Second)), node(10*time.Minute, true)); !deg || k != KindHubForwardingNotReconciling {
		t.Fatalf("true zombie (wire fresh, agent long-dead) must be the kind, got deg=%v k=%q", deg, k)
	}
	// never-seen agent + fresh wire → also a zombie (agent never checked in, but the wire forwards).
	if _, k := kind(batch(fresh(10*time.Second)), node(0, false)); k != KindHubForwardingNotReconciling {
		t.Fatalf("never-seen agent + fresh wire must be the zombie kind, got %q", k)
	}
	// CLEAN DEATH (WF-C-L2-1 true-negative): agent + wire die together → ages track (both ~150s), the gap is
	// within a report cycle → NEVER flashes the zombie kind before it settles to offline as the wire ages out.
	// (The OLD code — agentStale ∧ wireFresh with no settle — would have flickered here.)
	if _, k := kind(batch(fresh(150*time.Second)), node(150*time.Second, true)); k == KindHubForwardingNotReconciling {
		t.Fatalf("clean death (ages track within a window) must NOT flash the zombie kind, got %q", k)
	}
	// both-fresh → healthy (never green-lies over a zombie, never zombie-lies over a healthy hub).
	if deg, k := kind(batch(fresh(10*time.Second)), node(5*time.Second, true)); deg || k != KindHealthy {
		t.Fatalf("agent-fresh + wire-fresh must be healthy, got deg=%v k=%q", deg, k)
	}
	// stale wire (not fresh — nothing forwarding) → NOT the zombie kind, even with a long-dead agent.
	if _, k := kind(batch(MemberLiveness{Observed: true, Fresh: false, Age: 300 * time.Second}), node(10*time.Minute, true)); k == KindHubForwardingNotReconciling {
		t.Fatalf("stale wire must NOT be the zombie kind, got %q", k)
	}
	// F-Z1: a skewed agent clock (FUTURE handshake → negative Age) must NOT inflate the settle. Here agent
	// stale 85s + wire "10s in the future": without the zero-clamp that's 85−(−10)=95 >= 90 → spurious fire;
	// clamped to 0 it's 85 < 90 → no fire. Guards age-difference arithmetic on an agent-supplied timestamp.
	if _, k := kind(batch(MemberLiveness{Observed: true, Fresh: true, Age: -10 * time.Second}), node(85*time.Second, true)); k == KindHubForwardingNotReconciling {
		t.Fatalf("negative wire Age (clock skew) must NOT inflate the settle into a spurious zombie, got %q", k)
	}
}

type fakeProvider struct {
	pol *policyspec.Compiled
	err error
}

func (f fakeProvider) CompiledForNode(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (*policyspec.Compiled, error) {
	return f.pol, f.err
}

func (f fakeProvider) CompiledArtifactsForNodes(_ context.Context, _ uuid.UUID, ids []uuid.UUID, _ uuid.UUID) (map[uuid.UUID]*policyspec.Compiled, error) {
	if f.err != nil {
		return nil, f.err
	}
	// Route-less pushed artifact; the core pushedHash finalizes + hashes it (enforcing → hash, mesh → "").
	out := make(map[uuid.UUID]*policyspec.Compiled, len(ids))
	for _, id := range ids {
		out[id] = f.pol
	}
	return out, nil
}

func capsJSON(m map[string]any) []byte { b, _ := json.Marshal(m); return b }

// PolicyDegraded is the collapsed single health signal (S7.2 design change). It is a
// CONSERVATIVE disjunction of three terms; the field may only err toward OVER-reporting.
// Pure — no DB (fakeProvider).
func TestPolicyDegraded(t *testing.T) {
	enf := &policyspec.Compiled{Version: 1, Mode: "enforcing", Mesh: false,
		Allow: []policyspec.AllowEntry{{SrcIP: "10.99.0.2", DstCIDR: "10.0.5.0/24", Protocol: policyspec.ProtoAny}}}
	pushed := policyspec.CanonicalHash(*enf)
	org := uuid.New()
	node := func(caps map[string]any) sqlc.Node { return sqlc.Node{ID: uuid.New(), Capabilities: capsJSON(caps)} }
	deg := func(s *Service, n sqlc.Node) bool {
		return s.PolicyHealthForNodes(context.Background(), org, []sqlc.Node{n})[n.ID].Degraded
	}

	enfSvc := &Service{policy: fakeProvider{pol: enf}}
	// Healthy enforcing, in sync -> NOT degraded.
	if deg(enfSvc, node(map[string]any{"policy_hash": pushed})) {
		t.Fatal("healthy in-sync enforcing gateway must not be degraded")
	}
	// Term 3: enforcing, applied != pushed -> degraded (silent desync).
	if !deg(enfSvc, node(map[string]any{"policy_hash": "deadbeef0000"})) {
		t.Fatal("enforcing desync (applied != pushed) must be degraded")
	}
	// Term 2: failingSince set (any duration) -> degraded.
	if !deg(enfSvc, node(map[string]any{"policy_hash": pushed, "policy_failing_since": time.Now().UTC().Format(time.RFC3339)})) {
		t.Fatal("a failing enforcing apply (failingSince set) must be degraded")
	}
	// Term 1: applyErr set -> degraded even when otherwise in-sync.
	if !deg(enfSvc, node(map[string]any{"policy_hash": pushed, "policy_error": "nft: apply rejected"})) {
		t.Fatal("an apply error must be degraded")
	}

	// OFF org (provider returns "" pushed): a healthy off gateway is NOT degraded, whatever
	// its leftover applied hash — no enforcement boundary (kills #C's false alarm).
	offSvc := &Service{policy: fakeProvider{pol: nil}}
	if deg(offSvc, node(map[string]any{"policy_hash": "leftover_mesh_hash"})) {
		t.Fatal("healthy off-mode gateway must not be degraded")
	}

	// THE RED TEST (finding #1 — the gap state that survived passes 2, 3 AND 4): a
	// STUCK-ENFORCING gateway — off org, failed mesh apply so applyErr is set, failingSince
	// empty, and synced-would-be-true (off -> pushed "") — MUST be degraded via term 1. This
	// is the exact green-while-blackholing state the collapse exists to close.
	stuck := node(map[string]any{"policy_hash": "old_enforcing_hash", "policy_error": "nft: apply failed"})
	if !deg(offSvc, stuck) {
		t.Fatal("stuck-enforcing off gateway (applyErr set) MUST be degraded — the silent-blackhole class")
	}

	// A transient PROVIDER error (pushed unknown) must not manufacture a degraded signal on
	// an otherwise-clean node: term 3 is skipped, terms 1/2 are clean -> not degraded.
	errSvc := &Service{policy: fakeProvider{err: errors.New("db blip")}}
	if deg(errSvc, node(map[string]any{"policy_hash": "anything"})) {
		t.Fatal("a transient provider error alone must not degrade a clean gateway")
	}
	// ...but the agent-reported terms still apply through a provider error.
	if !deg(errSvc, node(map[string]any{"policy_error": "nft: apply failed"})) {
		t.Fatal("an agent-reported apply error must degrade even when the provider errored")
	}

	// Open build (no provider): nothing to compare, a clean node is not degraded.
	if (&Service{}).PolicyHealthForNodes(context.Background(), org, []sqlc.Node{node(map[string]any{"policy_hash": "x"})}) == nil {
		t.Fatal("open build must return a map, not nil")
	}
	if deg(&Service{}, node(map[string]any{"policy_hash": "x"})) {
		t.Fatal("open build clean node must not be degraded")
	}
}

// S8.1 D1 + Condition 1 — the operator-visible surface. A gateway that REFUSED a too-new
// artifact (reports policy_refused_version > 0) must surface, IN THE PolicyHealthForNodes
// OUTPUT the operator badge/API reads, both Degraded=true AND Kind=unsupported_policy_version —
// not stop at the node's self-report. Edition-independent: the version gate is on the agent, so
// even the open build (no policy engine) surfaces it. Priority: it outranks a co-present apply
// error (unique remedy — upgrade the agent). A node reporting no refusal (0/absent) is never it.
func TestUnsupportedPolicyVersionSurfaces(t *testing.T) {
	org := uuid.New()
	mk := func(caps map[string]any) sqlc.Node { return sqlc.Node{ID: uuid.New(), Capabilities: capsJSON(caps)} }
	health := func(s *Service, n sqlc.Node) PolicyHealth {
		return s.PolicyHealthForNodes(context.Background(), org, []sqlc.Node{n})[n.ID]
	}
	// Both editions: open (no provider) AND enterprise (a provider present).
	for _, svc := range []*Service{{}, {policy: fakeProvider{pol: nil}}} {
		h := health(svc, mk(map[string]any{"policy_refused_version": 4}))
		if !h.Degraded {
			t.Fatal("a refused (unsupported-version) gateway MUST be degraded (it is deny-all)")
		}
		if h.Kind != KindUnsupportedPolicyVersion {
			t.Fatalf("refused gateway must surface unsupported_policy_version in the health OUTPUT, got %q", h.Kind)
		}
	}
	// Priority: refused OUTRANKS a co-present apply error (its remedy differs — upgrade the agent).
	enfSvc := &Service{policy: fakeProvider{pol: &policyspec.Compiled{Version: 1, Mode: "enforcing"}}}
	if h := health(enfSvc, mk(map[string]any{"policy_refused_version": 5, "policy_error": "nft: apply failed"})); h.Kind != KindUnsupportedPolicyVersion {
		t.Fatalf("refused must OUTRANK apply_failing, got %q", h.Kind)
	}
	// No refusal reported (0/absent) → never unsupported_policy_version (backward-compat: old agents
	// report nothing; they must not be spuriously flagged).
	if h := health(&Service{}, mk(map[string]any{"policy_hash": "x"})); h.Kind == KindUnsupportedPolicyVersion {
		t.Fatal("a node not reporting a refusal must not surface unsupported_policy_version")
	}
}

// Finding #D guard: the DesiredState fail-closed/off fallbacks and the compiler stamp the
// policy artifact Version from TWO independent constants. They must stay equal, or a
// fallback artifact's canonical hash forks from the compiler's and false-alarms every
// enforcing gateway. This test fails CI loudly the moment a future bump breaks the tie.
func TestProtocolVersionConstantsAgree(t *testing.T) {
	if ProtocolVersion != policyspec.ProtocolVersion {
		t.Fatalf("nodes.ProtocolVersion (%d) != policyspec.ProtocolVersion (%d): the fail-closed "+
			"policy fallback would fork its hash from the compiler and false-alarm every enforcing "+
			"gateway. Reconcile them (or collapse to one constant).", ProtocolVersion, policyspec.ProtocolVersion)
	}
}

// Finding #3 + #2 (control-plane isolation, scoped): a policy-compile error must NOT fail
// the desired state — peers are still served (revocation converges within the <5s SLA,
// independent of the policy engine). The policy signal is SCOPED by the org's mode
// (finding #2): an ENFORCING org fails CLOSED (deny-all, never open mesh); a confirmed
// OFF org serves the mesh (a policy-subsystem blip must not blackhole an org that never
// opted into enforcement).
func TestDesiredStatePolicyErrorScopedByMode(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	cases := []struct {
		mode     string
		wantNil  bool // off => serve mesh via nil (agent decodes nil = blanket mesh)
		wantMode string
	}{
		{"off", true, ""},                 // nil policy = mesh; matches device-less steady state (#C)
		{"enforcing", false, "enforcing"}, // fail closed: explicit deny-all enforcing artifact
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Rollback(ctx) //nolint:errcheck
			q := sqlc.New(tx)

			org, user, node, dev := uuid.New(), uuid.New(), uuid.New(), uuid.New()
			if _, err := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug,zero_trust_mode) VALUES ($1,$2,$3,$4)", org, "O", "n-"+org.String(), tc.mode); err != nil {
				t.Fatalf("org: %v", err)
			}
			if _, err := tx.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", user, "u@t", "U"); err != nil {
				t.Fatalf("user: %v", err)
			}
			if _, err := tx.Exec(ctx, "INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, user); err != nil {
				t.Fatalf("membership: %v", err) // the peer query gates on current membership (offboarding parity)
			}
			if _, err := tx.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,$3,$4)", node, org, "gw", "serial-"+node.String()); err != nil {
				t.Fatalf("node: %v", err)
			}
			if _, err := tx.Exec(ctx,
				"INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1,$2,$3,$4,$5,$6,$7)",
				dev, org, user, node, "laptop", "hKAQzLYMvJffbeFJdJjqG0wlvxqbc4uIUsl7Bds4cZY=", "10.99.0.2"); err != nil {
				t.Fatalf("device: %v", err)
			}

			svc := &Service{q: q, policy: fakeProvider{err: errors.New("policy DB down")}}
			ds, err := svc.DesiredState(ctx, sqlc.Node{ID: node, OrgID: org, Name: "gw"})
			if err != nil {
				t.Fatalf("policy error must NOT fail the whole desired state: %v", err)
			}
			if len(ds.Peers) == 0 {
				t.Fatal("peers must still be served when the policy compile fails (revocation must converge)")
			}
			if tc.wantNil {
				// OFF: served as nil (= blanket mesh on the agent), matching the compiler's
				// device-less off output so PolicyDegradedForNodes never false-alarms (#C).
				if ds.Policy != nil {
					t.Fatalf("off-mode policy error must serve nil (mesh), not an explicit artifact; got %+v", ds.Policy)
				}
				return
			}
			// ENFORCING: explicit deny-all, stamped with the CONTENT-DERIVED version (S8.2 D1b) — a
			// deny-all has an empty Allow, so RequiredVersion == 4, byte-identical to the compiler's
			// device-less enforcing fallback for the same node (#D preserved: its hash matches
			// CompiledForNode's, no false desync). NOT the ProtocolVersion ceiling (now 5).
			if ds.Policy == nil || ds.Policy.Mesh || ds.Policy.Mode != tc.wantMode {
				t.Fatalf("enforcing error must fail closed (deny-all enforcing); got %+v", ds.Policy)
			}
			wantVer := policyspec.RequiredVersion(policyspec.Compiled{Mode: "enforcing"})
			if ds.Policy.Version != wantVer {
				t.Fatalf("fail-closed artifact must use the content-derived version (%d); got %d", wantVer, ds.Policy.Version)
			}
			if len(ds.Policy.Allow) != 0 {
				t.Fatalf("enforcing fail-closed must be deny-all (no allows); got %+v", ds.Policy.Allow)
			}
		})
	}
}

package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// THE MIXED-VERSION-FLEET SAFETY (S7.2 chunk-1 pin 2b), asserted not incidental:
// a DesiredState JSON with NO policy field — an open-build control plane, or an
// older control plane mid-upgrade — must decode to Policy == nil, which the whole
// enforcement path treats as LEGACY MESH. If a decode refactor ever flips this
// default (e.g. a non-pointer field defaulting to enforcing-empty = deny-all, or
// mesh-true-with-allows = open), an upgrade would silently change live traffic.
func TestAbsentPolicyDecodesToMesh(t *testing.T) {
	wire := `{"protocol_version":1,"node_id":"n1","interface_address":"10.99.0.1/24",
	          "mtu":1420,"listen_port":51820,"version":7,"peers":[]}`
	var ds DesiredState
	if err := json.Unmarshal([]byte(wire), &ds); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ds.Policy != nil {
		t.Fatalf("absent policy field must decode to nil (legacy mesh), got %+v", ds.Policy)
	}

	// An explicit null is the same contract.
	var ds2 DesiredState
	if err := json.Unmarshal([]byte(`{"version":1,"peers":[],"policy":null}`), &ds2); err != nil {
		t.Fatalf("decode null: %v", err)
	}
	if ds2.Policy != nil {
		t.Fatal("explicit null policy must also decode to nil (legacy mesh)")
	}

	// And a PRESENT policy round-trips intact (the positive control).
	var ds3 DesiredState
	present := `{"version":1,"peers":[],"policy":{"version":3,"node_id":"n1","mode":"enforcing","mesh":false,"allow":[]}}`
	if err := json.Unmarshal([]byte(present), &ds3); err != nil {
		t.Fatalf("decode present: %v", err)
	}
	if ds3.Policy == nil || ds3.Policy.Version != 3 || ds3.Policy.Mesh {
		t.Fatalf("present policy mis-decoded: %+v", ds3.Policy)
	}
}

// runOnce delivers the policy to the sink on EVERY fetch — including nil (which
// must be able to UNSET a previous policy: the enforcing->off recovery path) —
// and does so even when the WG backend converge fails (enforcement is orthogonal
// to interface config; a revocation push must not wait on an unrelated failure).
func TestRunOnceDeliversPolicyToSink(t *testing.T) {
	be := &fakeBackend{}
	cl := &fakeClient{}
	r := New(be, "priv", "pub", slog.New(slog.NewTextHandler(io.Discard, nil)))

	var got []*nodepolicy.Compiled
	r.OnPolicy(func(p *nodepolicy.Compiled) { got = append(got, p) })

	// 1: a policy arrives.
	cl.set(DesiredState{Version: 1, Policy: &nodepolicy.Compiled{Version: 5, Mode: nodepolicy.ModeEnforcing}})
	if _, err := r.runOnce(context.Background(), cl); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if len(got) != 1 || got[0] == nil || got[0].Version != 5 {
		t.Fatalf("policy not delivered: %+v", got)
	}

	// 2: absent policy delivers nil (unsets — legacy mesh).
	cl.set(DesiredState{Version: 2})
	if _, err := r.runOnce(context.Background(), cl); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if len(got) != 2 || got[1] != nil {
		t.Fatalf("nil policy must be delivered to unset: %+v", got)
	}

	// 3: a backend Configure failure must NOT block policy delivery.
	be.setConfigErr(errors.New("operation not permitted"))
	cl.set(DesiredState{Version: 3, Policy: &nodepolicy.Compiled{Version: 6, Mode: nodepolicy.ModeEnforcing}})
	if _, err := r.runOnce(context.Background(), cl); err == nil {
		t.Fatal("runOnce should surface the backend error")
	}
	if len(got) != 3 || got[2] == nil || got[2].Version != 6 {
		t.Fatalf("policy must be delivered even when the backend converge fails: %+v", got)
	}
}

// THE CONVERSE INDEPENDENCE DIRECTION: a policy/nftables apply FAILURE must not block
// or abort the WG peer converge — a revocation (peer removal) still lands on the
// interface while the egress leg is in persistent apply-failure. Structurally,
// OnPolicy has no error path into runOnce (the sink swallows downstream failure, as
// the real wiring does: SetPolicy + non-blocking kick; the nft apply errors in the
// egress goroutine and surfaces via AppliedStatus, never back into this loop). This
// test pins that CONTRACT so a refactor can't thread an error return through and
// freeze one data-plane leg on the other's failure.
func TestPolicyApplyFailureDoesNotBlockPeerConverge(t *testing.T) {
	be := &fakeBackend{}
	cl := &fakeClient{}
	r := New(be, "priv", "pub", slog.New(slog.NewTextHandler(io.Discard, nil)))

	// The sink simulates the real wiring with the egress leg PERSISTENTLY FAILING:
	// every delivery runs a downstream apply that errors; the sink swallows it
	// (exactly like SetPolicy+kick — failure surfaces via status, not a return).
	applyAttempts := 0
	r.OnPolicy(func(p *nodepolicy.Compiled) {
		applyAttempts++
		_ = errors.New("nft apply: rejected") // downstream failure, no path back
	})

	// Baseline: two peers converged.
	cl.set(DesiredState{Version: 1,
		Peers:  []Peer{{PublicKey: "A", AllowedIPs: []string{"10.99.0.10/32"}}, {PublicKey: "B", AllowedIPs: []string{"10.99.0.20/32"}}},
		Policy: &nodepolicy.Compiled{Version: 1, Mode: nodepolicy.ModeEnforcing}})
	if _, err := r.runOnce(context.Background(), cl); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if be.count() != 2 {
		t.Fatalf("baseline peers = %d, want 2", be.count())
	}

	// REVOCATION while the policy leg fails: B is removed from desired state.
	cl.set(DesiredState{Version: 2,
		Peers:  []Peer{{PublicKey: "A", AllowedIPs: []string{"10.99.0.10/32"}}},
		Policy: &nodepolicy.Compiled{Version: 2, Mode: nodepolicy.ModeEnforcing}})
	if _, err := r.runOnce(context.Background(), cl); err != nil {
		t.Fatalf("revocation converge must SUCCEED despite the failing policy leg: %v", err)
	}
	if be.count() != 1 {
		t.Fatalf("revocation did not land: peers = %d, want 1 (B removed)", be.count())
	}
	if applyAttempts != 2 {
		t.Fatalf("policy leg should have been attempted on both fetches, got %d", applyAttempts)
	}
}

// TestRunOnceReconnectWithdrawsFQDNGeneration is the S21 reconnect boundary:
// a control-plane outage leaves the last applied data plane alone, but the first
// successful full resync after reconnect delivers the replacement FQDN snapshot
// as one complete artifact. The agent never keeps a retired answer merely because
// it was disconnected while the resolver withdrew that generation.
func TestRunOnceReconnectWithdrawsFQDNGeneration(t *testing.T) {
	be := &fakeBackend{}
	cl := &fakeClient{watch: make(chan struct{})}
	r := New(be, "priv", "pub", slog.New(slog.NewTextHandler(io.Discard, nil)))

	var got []*nodepolicy.Compiled
	r.OnPolicy(func(p *nodepolicy.Compiled) { got = append(got, p) })

	active := &nodepolicy.Compiled{
		Version: nodepolicy.MaxSupportedVersion,
		Mode:    nodepolicy.ModeEnforcing,
		Allow: []nodepolicy.AllowEntry{
			{SrcIP: "10.99.0.10", DstCIDR: "203.0.113.10/32", Protocol: "tcp", PortLow: 443, PortHigh: 443},
			{SrcIP: "2001:db8:99::10", DstCIDR: "2001:db8:203::10/128", Protocol: "tcp", PortLow: 443, PortHigh: 443},
		},
		FQDNGenerations: []nodepolicy.FQDNGeneration{{
			ResourceID: "resource-api", Name: "api.example.com", Generation: "content-a",
			Answers: []string{"203.0.113.10/32", "2001:db8:203::10/128"},
		}},
	}
	cl.set(DesiredState{Version: 41, Peers: []Peer{p1}, Policy: active})
	if _, err := r.runOnce(context.Background(), cl); err != nil {
		t.Fatalf("initial full sync: %v", err)
	}
	if len(got) != 1 || len(got[0].FQDNGenerations) != 1 {
		t.Fatalf("initial active FQDN snapshot was not delivered: %+v", got)
	}

	// An outage must be fail-static: no synthetic nil/empty policy is delivered
	// that could rewrite the last-known artifact before the control plane returns.
	cl.setErr(errors.New("control plane unavailable"))
	if _, err := r.runOnce(context.Background(), cl); err == nil {
		t.Fatal("outage must surface")
	}
	if len(got) != 1 {
		t.Fatalf("outage must not overwrite the last policy snapshot, deliveries=%d", len(got))
	}

	// Reconnect is a full snapshot, not a delta. The resolver-withdrawn
	// generation and its concrete tuples are absent together.
	cl.setErr(nil)
	withdrawn := &nodepolicy.Compiled{Version: nodepolicy.MaxSupportedVersion, Mode: nodepolicy.ModeEnforcing}
	cl.set(DesiredState{Version: 42, Peers: []Peer{p1}, Policy: withdrawn})
	if _, err := r.runOnce(context.Background(), cl); err != nil {
		t.Fatalf("reconnect full sync: %v", err)
	}
	if len(got) != 2 || got[1] == nil || len(got[1].FQDNGenerations) != 0 || len(got[1].Allow) != 0 {
		t.Fatalf("reconnect must deliver the withdrawn FQDN snapshot atomically, got %+v", got)
	}
	if r.version.Load() != 42 {
		t.Fatalf("reconnect must advance watch version to full snapshot version, got %d", r.version.Load())
	}
}

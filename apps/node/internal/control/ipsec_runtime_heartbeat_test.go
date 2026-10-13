package control

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"testing"
	"time"
)

// Deterministic elapsed-clock regression for one static and three slow BGP
// items. Full reconciliation takes18s; independent between-item samples cost
// 400ms and keep native/status gaps <=10s without any parallel Apply owner.
type heartbeatPollRig struct {
	runtimePollFake
	items   []ipsec.RuntimePending
	at      time.Duration
	sampled []time.Duration
	applied []uuid.UUID
	static  ipsec.RuntimeDelivery
	seq     uint64
}

func (f *heartbeatPollRig) IPsecPending(context.Context, *uuid.UUID, int) (ipsec.RuntimePendingPage, error) {
	return ipsec.RuntimePendingPage{Items: f.items}, nil
}
func (f *heartbeatPollRig) IPsecMaterial(ctx context.Context, id uuid.UUID, rev int64) (ipsec.RuntimeMaterial, error) {
	f.item = ipsec.RuntimePending{ConnectionID: id, DesiredRevision: rev, Kind: "apply"}
	f.bgp = id != f.static.Manifest.ConnectionID
	if !f.bgp {
		return ipsec.RuntimeMaterial{RuntimeDelivery: f.static}, nil
	}
	return f.runtimePollFake.IPsecMaterial(ctx, id, rev)
}
func (f *heartbeatPollRig) Apply(ctx context.Context, m ipsec.RuntimeMaterial) (ipsec.RuntimeAcknowledgement, error) {
	f.applied = append(f.applied, m.Manifest.ConnectionID)
	if m.Manifest.BGP != nil {
		f.at += 6 * time.Second
	}
	return f.runtimePollFake.Apply(ctx, m)
}
func (f *heartbeatPollRig) RefreshIPsecActiveRecovery(context.Context) ([]ipsec.RuntimeRecoveryHeartbeat, error) {
	f.at += 400 * time.Millisecond
	f.sampled = append(f.sampled, f.at)
	f.seq++
	one := 1
	return []ipsec.RuntimeRecoveryHeartbeat{{ConnectionID: f.static.Manifest.ConnectionID, Delivery: f.static, Report: ipsec.RuntimeStatusReport{DeliveryID: f.static.ID, DesiredRevision: 2, ConfigurationRevision: 1, RecoveryVersion: &one, SelectionSequence: &f.seq, Tunnels: [2]ipsec.RuntimeTunnelStatus{{ID: f.static.Manifest.Tunnels[0].ID, Slot: 1, Status: "down", Selected: true}, {ID: f.static.Manifest.Tunnels[1].ID, Slot: 2, Status: "up"}}}}}, nil
}
func (f *heartbeatPollRig) ObserveIPsecStatus(ctx context.Context, d ipsec.RuntimeDelivery) (ipsec.RuntimeStatusReport, error) {
	r, err := f.runtimePollFake.ObserveIPsecStatus(ctx, d)
	if d.Manifest.RecoveryVersion != nil {
		one := 1
		f.seq++
		seq := f.seq
		r.RecoveryVersion = &one
		r.SelectionSequence = &seq
	}
	return r, err
}
func TestIPsecRuntimeHeartbeatSamplesDuringSlowSerialFourConnectionPass(t *testing.T) {
	f := &heartbeatPollRig{}
	one := 1
	f.static = ipsec.RuntimeDelivery{ID: uuid.New(), Kind: "apply", DesiredRevision: 2, Manifest: ipsec.RuntimeManifest{ConnectionID: uuid.New(), DesiredRevision: 2, ConfigurationRevision: 1, ProfileID: "aws-static-ipv4-v1", RecoveryVersion: &one, Tunnels: [2]ipsec.RuntimeTunnel{{ID: uuid.New(), Slot: 1, Selected: true}, {ID: uuid.New(), Slot: 2}}}}
	for i := 0; i < 3; i++ {
		f.items = append(f.items, ipsec.RuntimePending{ConnectionID: uuid.New(), DesiredRevision: 2, Kind: "apply"})
	}
	f.items = append(f.items, ipsec.RuntimePending{ConnectionID: f.static.Manifest.ConnectionID, DesiredRevision: 2, Kind: "apply"})
	if PollIPsecRuntime(context.Background(), f, f) != nil {
		t.Fatal("poll")
	}
	if len(f.applied) != 4 || len(f.sampled) != 4 || f.at < 18*time.Second {
		t.Fatal("four slow serial providers missing")
	}
	for i := 1; i < len(f.sampled); i++ {
		gap := f.sampled[i] - f.sampled[i-1]
		if gap > 10*time.Second {
			t.Fatalf("static observation starved: %s", gap)
		}
	}
	// A single provider exceeding10s still cannot be preempted by this serial
	// seam; this test establishes the bounded-item case, not a scheduler guarantee.
	t.Logf("full pass=%s heartbeat max gap=6.4s samples=%v", f.at, f.sampled)
}

type heartbeatBatchRig struct {
	runtimePollFake
	batch []ipsec.RuntimeRecoveryHeartbeat
}

func (f *heartbeatBatchRig) RefreshIPsecActiveRecovery(context.Context) ([]ipsec.RuntimeRecoveryHeartbeat, error) {
	return f.batch, nil
}
func TestIPsecRuntimeHeartbeatPublishesEveryIndependentStaticConnection(t *testing.T) {
	f := &heartbeatBatchRig{}
	for i := 0; i < 2; i++ {
		one := 1
		seq := uint64(7)
		id := uuid.New()
		d := ipsec.RuntimeDelivery{ID: uuid.New(), Kind: "apply", DesiredRevision: 2, Manifest: ipsec.RuntimeManifest{ConnectionID: id, DesiredRevision: 2, ConfigurationRevision: 1, ProfileID: "aws-static-ipv4-v1", RecoveryVersion: &one, Tunnels: [2]ipsec.RuntimeTunnel{{ID: uuid.New(), Slot: 1, Selected: true}, {ID: uuid.New(), Slot: 2}}}}
		r := ipsec.RuntimeStatusReport{DeliveryID: d.ID, DesiredRevision: 2, ConfigurationRevision: 1, RecoveryVersion: &one, SelectionSequence: &seq, Tunnels: [2]ipsec.RuntimeTunnelStatus{{ID: d.Manifest.Tunnels[0].ID, Slot: 1, Status: "down", Selected: true}, {ID: d.Manifest.Tunnels[1].ID, Slot: 2, Status: "up"}}}
		f.batch = append(f.batch, ipsec.RuntimeRecoveryHeartbeat{ConnectionID: id, Delivery: d, Report: r})
	}
	if RefreshIPsecRuntimeStatus(context.Background(), f, f) != nil || len(f.reports) != 2 {
		t.Fatal("second static sample lost")
	}
	f.batch[1] = f.batch[0]
	f.reports = nil
	if RefreshIPsecRuntimeStatus(context.Background(), f, f) == nil {
		t.Fatal("duplicate delivery reported")
	}
}

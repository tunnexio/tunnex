package control

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"testing"
	"time"
)

type recoveryRefreshPollFixture struct {
	runtimePollFake
	items     []ipsec.RuntimePending
	clock     time.Duration
	proofs    []time.Duration
	materials int
	events    []string
	itemCost  time.Duration
}

func (f *recoveryRefreshPollFixture) IPsecPending(context.Context, *uuid.UUID, int) (ipsec.RuntimePendingPage, error) {
	return ipsec.RuntimePendingPage{Items: f.items}, nil
}
func (f *recoveryRefreshPollFixture) IPsecMaterial(ctx context.Context, id uuid.UUID, rev int64) (ipsec.RuntimeMaterial, error) {
	f.materials++
	f.item = ipsec.RuntimePending{ConnectionID: id, DesiredRevision: rev, Kind: "apply"}
	return f.runtimePollFake.IPsecMaterial(ctx, id, rev)
}
func (f *recoveryRefreshPollFixture) Apply(ctx context.Context, m ipsec.RuntimeMaterial) (ipsec.RuntimeAcknowledgement, error) {
	f.events = append(f.events, "apply")
	f.clock += f.itemCost
	return f.runtimePollFake.Apply(ctx, m)
}
func (f *recoveryRefreshPollFixture) RefreshIPsecRecovery(ctx context.Context) error {
	d, ok := ctx.Deadline()
	if !ok || time.Until(d) > 5*time.Second {
		return ErrIPsecControl
	}
	f.events = append(f.events, "refresh")
	f.proofs = append(f.proofs, f.clock)
	f.clock += 100 * time.Millisecond
	return nil
}
func (f *recoveryRefreshPollFixture) Cleanup(context.Context, ipsec.RuntimeCleanup) (ipsec.RuntimeAcknowledgement, error) {
	f.events = append(f.events, "cleanup")
	return ipsec.RuntimeAcknowledgement{}, ErrIPsecControl
}
func (f *recoveryRefreshPollFixture) IPsecCleanup(_ context.Context, id uuid.UUID, rev int64) (ipsec.RuntimeCleanup, error) {
	return ipsec.RuntimeCleanup{RuntimeDelivery: ipsec.RuntimeDelivery{ID: uuid.New(), Kind: "cleanup", DesiredRevision: rev, Manifest: ipsec.RuntimeManifest{ConnectionID: id, DesiredRevision: rev - 1}}}, nil
}
func TestIPsecRecoveryRefreshSerialBetweenSlowItems(t *testing.T) {
	f := &recoveryRefreshPollFixture{itemCost: 6400 * time.Millisecond}
	for i := 0; i < 5; i++ {
		f.items = append(f.items, ipsec.RuntimePending{ConnectionID: uuid.New(), DesiredRevision: 2, Kind: "apply"})
	}
	for i := 0; i < 3; i++ {
		if err := PollIPsecRuntime(context.Background(), f, f); err != nil {
			t.Fatal(err)
		}
	}
	if f.materials != 15 || f.acks != 15 || len(f.reports) != 15 || len(f.proofs) != 15 {
		t.Fatal("fresh ordinary pipeline missing")
	}
	for i := 1; i < len(f.proofs); i++ {
		if gap := f.proofs[i] - f.proofs[i-1]; gap > 10*time.Second {
			t.Fatalf("slow ordinary item starved observation: %v", gap)
		}
	}
}
func TestIPsecRecoveryRefreshCleanupAttemptHasPriority(t *testing.T) {
	f := &recoveryRefreshPollFixture{}
	f.items = []ipsec.RuntimePending{{ConnectionID: uuid.New(), DesiredRevision: 2, Kind: "apply"}, {ConnectionID: uuid.New(), DesiredRevision: 2, Kind: "cleanup"}}
	_ = PollIPsecRuntime(context.Background(), f, f)
	if len(f.events) < 3 || f.events[0] != "cleanup" || f.events[1] != "refresh" {
		t.Fatal("refresh preempted cleanup", f.events)
	}
}
func TestIPsecRecoveryRefreshDoesNotHideSingleLongItemGap(t *testing.T) {
	f := &recoveryRefreshPollFixture{itemCost: 12 * time.Second}
	for i := 0; i < 2; i++ {
		f.items = append(f.items, ipsec.RuntimePending{ConnectionID: uuid.New(), DesiredRevision: 2, Kind: "apply"})
	}
	_ = PollIPsecRuntime(context.Background(), f, f)
	if len(f.proofs) != 2 || f.proofs[1]-f.proofs[0] <= 10*time.Second {
		t.Fatal("fixture concealed unsafe long item")
	}
}

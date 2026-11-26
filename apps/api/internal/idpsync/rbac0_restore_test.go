package idpsync

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// restoringDeprov is a Deprovisioner that also implements the RBAC-0 DirectoryRestorer seam.
type restoringDeprov struct {
	fakeDeprov
	restored []uuid.UUID
}

func (d *restoringDeprov) RestoreForSync(_ context.Context, _ uuid.UUID, userID uuid.UUID) (bool, error) {
	d.restored = append(d.restored, userID)
	return true, nil
}

// RBAC-0 D3: people can no longer reverse directory sync, so sync restores its own deprovisioning for every
// person the directory lists as ACTIVE — already in the group or newly added — and only behind the licence.
func TestRBAC0ReconcileRestoresActiveDirectoryMembers(t *testing.T) {
	s := baseStore()
	s.current[grp] = []uuid.UUID{uAli} // already synced earlier
	p := &fakeProvider{members: []DirectoryMember{
		{ExternalID: "x1", Email: "alice@acme.com", Status: StatusActive},
		{ExternalID: "x2", Email: "bob@acme.com", Status: StatusActive},
		{ExternalID: "x3", Email: "carol@acme.com", Status: StatusDisabled},
	}}
	d := &restoringDeprov{}
	run(t, p, s, &d.fakeDeprov) // a plain Deprovisioner: no restore seam, nothing restored
	if len(d.restored) != 0 {
		t.Fatalf("restored without the seam: %v", d.restored)
	}
	s = baseStore()
	s.current[grp] = []uuid.UUID{uAli}
	r := NewReconciler(p, s, d, func() time.Time { return time.Unix(1700000000, 0) })
	_ = r.ReconcileConfig(context.Background(), org, "microsoft")
	got := map[uuid.UUID]bool{}
	for _, u := range d.restored {
		got[u] = true
	}
	if !got[uAli] || !got[uBob] || got[uCar] || len(d.restored) != 2 {
		t.Fatalf("restored %v; want alice and bob (active), never carol (disabled)", d.restored)
	}
	// A lapsed licence stops grants — including restoration.
	d.restored = nil
	s = baseStore()
	r = NewReconciler(p, s, d, func() time.Time { return time.Unix(1700000000, 0) }).WithProvisioningGate(func() bool { return false })
	_ = r.ReconcileConfig(context.Background(), org, "microsoft")
	if len(d.restored) != 0 {
		t.Fatalf("restored on a lapsed licence: %v", d.restored)
	}
}

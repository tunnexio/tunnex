package sandboxes

import (
	"github.com/google/uuid"
	"testing"
)

func TestIdentityManagementAssociation(t *testing.T) {
	i := Identity{uuid.New(), uuid.New(), uuid.New()}
	if !i.CanManage(i.OrgID, i.CreatorID) {
		t.Fatal("creator must match")
	}
	if i.CanManage(uuid.New(), i.CreatorID) || i.CanManage(i.OrgID, uuid.New()) {
		t.Fatal("org and creator must both match")
	}
	for _, invalid := range []Identity{{}, {ID: i.ID, OrgID: i.OrgID}, {ID: i.ID, CreatorID: i.CreatorID}, {OrgID: i.OrgID, CreatorID: i.CreatorID}} {
		if invalid.Validate() == nil || invalid.CanManage(invalid.OrgID, invalid.CreatorID) {
			t.Fatal("zero identity accepted")
		}
	}
}

func TestLifecycle(t *testing.T) {
	path := []State{StateCreating, StateReady, StateStopping, StateStopped, StateStarting, StateReady, StateDeleting, StateDeleted}
	for n := 1; n < len(path); n++ {
		if err := Transition(path[n-1], path[n]); err != nil {
			t.Fatalf("%s -> %s: %v", path[n-1], path[n], err)
		}
	}
	for _, pair := range [][2]State{{StateStopped, StateReady}, {StateCreating, StateStopped}, {StateError, StateStarting}, {StateDeleted, StateStarting}, {StateDeleting, StateError}, {State("unknown"), State("unknown")}} {
		if Transition(pair[0], pair[1]) == nil {
			t.Fatalf("unsafe transition accepted: %v", pair)
		}
	}
	for _, s := range path {
		if Transition(s, s) != nil {
			t.Fatalf("retry refused: %s", s)
		}
	}
	if Transition(StateStarting, StateError) != nil || Transition(StateError, StateStopping) != nil || Transition(StateError, StateDeleting) != nil {
		t.Fatal("failure cleanup blocked")
	}
}

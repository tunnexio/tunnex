package hostposture

import (
	"context"
	"testing"
	"time"
)

type sequenceHeartbeatReader struct {
	heartbeats []Heartbeat
	index      int
}

func (s *sequenceHeartbeatReader) LoadHeartbeat() (Heartbeat, error) {
	index := s.index
	if index >= len(s.heartbeats) {
		index = len(s.heartbeats) - 1
	}
	s.index++
	return s.heartbeats[index], nil
}

func TestWaitForOwnerRequiresTwoAdvancingHeartbeatsFromSameManager(t *testing.T) {
	now := time.Unix(1000, 0)
	owner := testOwner()
	base := Heartbeat{
		SchemaVersion: 1, Contract: Contract, NodeName: "worker-a", ManagerUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		ManagerBootID: "11111111111111111111111111111111",
		State:         HeartbeatActive, Owners: []Owner{owner}, ObservedAt: now,
	}
	first, duplicate, second := base, base, base
	first.Sequence, duplicate.Sequence, second.Sequence = 7, 7, 8
	reader := &sequenceHeartbeatReader{heartbeats: []Heartbeat{first, duplicate, second}}
	sleeps := 0
	err := WaitForOwner(t.Context(), reader, "worker-a", owner.UID, func() time.Time { return now }, func(context.Context, time.Duration) error {
		sleeps++
		return nil
	})
	if err != nil || sleeps != 2 {
		t.Fatalf("wait err=%v sleeps=%d, want duplicate ignored then advancing proof", err, sleeps)
	}
}

func TestWaitForOwnerResetsSequenceEpochWhenManagerContainerRestartsInSamePod(t *testing.T) {
	now := time.Unix(1000, 0)
	owner := testOwner()
	base := Heartbeat{
		SchemaVersion: 1, Contract: Contract, NodeName: "worker-a", ManagerUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		ManagerBootID: "11111111111111111111111111111111", State: HeartbeatActive, Owners: []Owner{owner}, ObservedAt: now,
	}
	old, restarted, advanced := base, base, base
	old.Sequence = 88
	restarted.ManagerBootID, restarted.Sequence = "22222222222222222222222222222222", 1
	advanced.ManagerBootID, advanced.Sequence = restarted.ManagerBootID, 2
	reader := &sequenceHeartbeatReader{heartbeats: []Heartbeat{old, restarted, advanced}}
	sleeps := 0
	err := WaitForOwner(t.Context(), reader, "worker-a", owner.UID, func() time.Time { return now }, func(context.Context, time.Duration) error {
		sleeps++
		return nil
	})
	if err != nil || sleeps != 2 {
		t.Fatalf("same-Pod manager restart did not establish a new sequence epoch: err=%v sleeps=%d", err, sleeps)
	}
}

func TestCheckManagerHeartbeatRejectsStaleAndBlockedReadinessButKeepsBlockedLiveness(t *testing.T) {
	now := time.Unix(1000, 0)
	heartbeat := Heartbeat{SchemaVersion: 1, Contract: Contract, NodeName: "worker-a", ManagerUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ManagerBootID: "11111111111111111111111111111111", Sequence: 1, State: HeartbeatBlocked, ObservedAt: now}
	reader := &sequenceHeartbeatReader{heartbeats: []Heartbeat{heartbeat}}
	if err := CheckManagerHeartbeat(reader, "worker-a", false, now); err == nil {
		t.Fatal("blocked manager must not be ready")
	}
	reader.index = 0
	if err := CheckManagerHeartbeat(reader, "worker-a", true, now); err != nil {
		t.Fatalf("fresh blocked manager should remain live: %v", err)
	}
	reader.index = 0
	if err := CheckManagerHeartbeat(reader, "worker-a", true, now.Add(HeartbeatFreshness+time.Second)); err == nil {
		t.Fatal("stale heartbeat must not be live")
	}
}

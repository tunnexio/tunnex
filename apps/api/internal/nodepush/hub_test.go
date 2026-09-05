package nodepush

import (
	"testing"

	"github.com/google/uuid"
)

func TestSubscribeReceivesNotify(t *testing.T) {
	h := New()
	node := uuid.New()
	ch, unsub := h.Subscribe(node)
	defer unsub()

	h.Notify(node)
	select {
	case <-ch:
	default:
		t.Fatal("subscriber did not receive the notify")
	}
}

func TestNotifyIsCoalescedAndNonBlocking(t *testing.T) {
	h := New()
	node := uuid.New()
	ch, unsub := h.Subscribe(node)
	defer unsub()

	// Several notifies with no reader in between must not block; they coalesce
	// into the single buffered slot (the watcher resyncs fully on wake anyway).
	for i := 0; i < 5; i++ {
		h.Notify(node)
	}
	got := 0
	for {
		select {
		case <-ch:
			got++
			continue
		default:
		}
		break
	}
	if got != 1 {
		t.Fatalf("want 1 coalesced signal, got %d", got)
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	h := New()
	node := uuid.New()
	ch, unsub := h.Subscribe(node)
	unsub()
	h.Notify(node) // no subscribers now
	select {
	case <-ch:
		t.Fatal("received a notify after unsubscribe")
	default:
	}
}

func TestVersionAdvancesOnNotify(t *testing.T) {
	h := newWithInitialVersion(100)
	node := uuid.New()
	if h.Version(node) != 100 {
		t.Fatalf("initial version should be 100")
	}
	h.Notify(node)
	if h.Version(node) != 101 {
		t.Fatalf("version should be 101 after one notify, got %d", h.Version(node))
	}
	h.Notify(node)
	if h.Version(node) != 102 {
		t.Fatalf("version should advance on each notify, got %d", h.Version(node))
	}
	// A different node's version is independent.
	if h.Version(uuid.New()) != 100 {
		t.Fatalf("unrelated node version should be 100")
	}
}

func TestNewHubEpochDoesNotReusePreRestartVersions(t *testing.T) {
	node := uuid.New()
	before := newWithInitialVersion(100)
	before.Notify(node)
	after := newWithInitialVersion(200)
	if after.Version(node) <= before.Version(node) {
		t.Fatalf("new process epoch must advance the desired-state version: before=%d after=%d", before.Version(node), after.Version(node))
	}
}

func TestNotifyOnlyTargetsTheNode(t *testing.T) {
	h := New()
	a, b := uuid.New(), uuid.New()
	chA, unsubA := h.Subscribe(a)
	defer unsubA()
	chB, unsubB := h.Subscribe(b)
	defer unsubB()

	h.Notify(a)
	select {
	case <-chA:
	default:
		t.Fatal("node A subscriber missed its notify")
	}
	select {
	case <-chB:
		t.Fatal("node B subscriber got A's notify")
	default:
	}
}

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
	h := New()
	node := uuid.New()
	if h.Version(node) != 0 {
		t.Fatal("initial version should be 0")
	}
	h.Notify(node)
	if h.Version(node) != 1 {
		t.Fatalf("version should be 1 after one notify, got %d", h.Version(node))
	}
	h.Notify(node)
	if h.Version(node) != 2 {
		t.Fatalf("version should advance on each notify, got %d", h.Version(node))
	}
	// A different node's version is independent.
	if h.Version(uuid.New()) != 0 {
		t.Fatal("unrelated node version should be 0")
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

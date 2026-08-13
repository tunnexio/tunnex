// Package nodepush is the control-plane push hub: it lets the agent's long-poll
// watch return the instant a node's desired state changes (peer added/revoked,
// owner deactivated), so revocations apply within the S3.1 <5s bound rather than
// waiting for the interval reconcile. It is in-process (single API instance, as
// in the compose quickstart); a multi-instance deployment would back this with
// Redis pub/sub behind the same Subscribe/Notify shape.
package nodepush

import (
	"sync"

	"github.com/google/uuid"
)

// Hub fans node-change signals out to subscribed watchers. It also keeps a
// monotonic per-node version bumped on every Notify: a watcher passes the
// version it last saw, and if the hub's is newer the watcher is told to resync
// immediately. This closes the lost-wakeup gap — a change pushed while the agent
// is between long-polls (mid-fetch) is not dropped; the next watch sees the
// version advanced and returns at once instead of blocking to the interval.
type Hub struct {
	mu   sync.Mutex
	subs map[uuid.UUID]map[chan struct{}]struct{}
	ver  map[uuid.UUID]uint64
}

// New builds an empty hub.
func New() *Hub {
	return &Hub{
		subs: make(map[uuid.UUID]map[chan struct{}]struct{}),
		ver:  make(map[uuid.UUID]uint64),
	}
}

// Version returns the node's current change version (0 if never changed).
func (h *Hub) Version(nodeID uuid.UUID) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ver[nodeID]
}

// Subscribe registers interest in a node's changes. It returns a receive channel
// that gets a (coalesced) signal on each Notify, and an unsubscribe func the
// caller MUST invoke when done (e.g. on watch return).
func (h *Hub) Subscribe(nodeID uuid.UUID) (<-chan struct{}, func()) {
	// Buffered so Notify never blocks and a signal that arrives between selects
	// is not lost (a single pending token is enough — the watcher does a full
	// resync on wake, so coalescing multiple changes into one is correct).
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	if h.subs[nodeID] == nil {
		h.subs[nodeID] = make(map[chan struct{}]struct{})
	}
	h.subs[nodeID][ch] = struct{}{}
	h.mu.Unlock()

	return ch, func() {
		h.mu.Lock()
		if set := h.subs[nodeID]; set != nil {
			delete(set, ch)
			if len(set) == 0 {
				delete(h.subs, nodeID)
			}
		}
		h.mu.Unlock()
	}
}

// Notify signals every current subscriber of nodeID. Non-blocking: a subscriber
// whose buffer already holds a pending signal is skipped (it will resync anyway).
func (h *Hub) Notify(nodeID uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ver[nodeID]++ // bump under the lock, before signalling, so a watcher that
	// reads the version after subscribing never misses this change.
	for ch := range h.subs[nodeID] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// NotifyMany signals several nodes at once (e.g. a user's peers span nodes).
func (h *Hub) NotifyMany(nodeIDs []uuid.UUID) {
	for _, id := range nodeIDs {
		h.Notify(id)
	}
}

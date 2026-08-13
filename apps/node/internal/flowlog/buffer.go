package flowlog

import "sync"

// DefaultBufferCap bounds the in-memory flow-event ring — the EXPLICIT buffer bound
// (16384 events). On overflow the OLDEST event is dropped and a drop counter increments;
// Drain surfaces that count so a hole in the audit trail is LEGIBLE (the CP writes an
// explicit "N events dropped" gap marker into the stream on reconnect). The buffer NEVER
// blocks a producer — enforcement/observation must never wait on the reporter.
const DefaultBufferCap = 16384

// Buffer is a bounded, concurrency-safe, non-blocking ring of flow events. It is a true ring
// (fixed array + head index + count), so Add is O(1) even when full — drop-oldest advances
// the head instead of memmoving the whole array (review #8). This matters because the
// deny-log is the port-scan AMPLIFICATION point: the enqueue path runs hottest exactly when
// the buffer is full, so per-event work must be constant, not O(cap).
type Buffer struct {
	mu      sync.Mutex
	buf     []Event
	head    int // index of the OLDEST buffered event
	count   int // number currently buffered (0..len(buf))
	dropped int64
}

// NewBuffer returns a ring bounded to capacity (DefaultBufferCap if capacity<=0).
func NewBuffer(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = DefaultBufferCap
	}
	return &Buffer{buf: make([]Event, capacity)}
}

// Add appends an event; at capacity it drops the OLDEST and counts the drop. O(1), never
// blocks a producer.
func (b *Buffer) Add(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(b.buf)
	if b.count == n {
		// Full: overwrite the oldest slot with the new event and advance head. The new event
		// becomes the newest; the previous second-oldest becomes the oldest. Drop-oldest, O(1).
		b.buf[b.head] = e
		b.head = (b.head + 1) % n
		b.dropped++
		return
	}
	b.buf[(b.head+b.count)%n] = e
	b.count++
}

// Drain removes and returns the buffered events (oldest-first) plus the number DROPPED since
// the last drain (both reset). The caller ships the events and records the drop-count as a gap.
func (b *Buffer) Drain() (events []Event, dropped int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	dropped = b.dropped
	if b.count > 0 {
		n := len(b.buf)
		events = make([]Event, b.count)
		for i := 0; i < b.count; i++ {
			events[i] = b.buf[(b.head+i)%n]
		}
	}
	b.head, b.count, b.dropped = 0, 0, 0
	return events, dropped
}

// Len reports the current buffered count (for readiness/metrics; not load-bearing).
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count
}

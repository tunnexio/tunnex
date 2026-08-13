package flowlog

import (
	"testing"
	"time"
)

func TestPrefixRoundTrip(t *testing.T) {
	rid := "019f5a14-1c1b-7343-bfb9-76e94a54b574"
	// A rule: encode then parse recovers the id, not a deny.
	got, deny, ok := ParsePrefix(EncodePrefix(rid))
	if !ok || deny || got != rid {
		t.Fatalf("rule prefix round-trip: got=%q deny=%v ok=%v", got, deny, ok)
	}
	// A default-deny: encode("") -> deny sentinel, parses as deny with empty id.
	got, deny, ok = ParsePrefix(EncodePrefix(""))
	if !ok || !deny || got != "" {
		t.Fatalf("deny prefix round-trip: got=%q deny=%v ok=%v", got, deny, ok)
	}
	// A foreign log line (not ours) is skipped.
	if _, _, ok := ParsePrefix("SFW-DROP: IN=eth0"); ok {
		t.Fatal("a non-tnx prefix must not be claimed")
	}
	// The kernel appends packet fields after the space — parse tolerates a full token.
	if id, _, ok := ParsePrefix("tnx:" + rid); !ok || id != rid {
		t.Fatalf("bare token parse: id=%q ok=%v", id, ok)
	}
}

func TestBufferBoundDropOldestCounts(t *testing.T) {
	b := NewBuffer(4) // explicit small bound
	mk := func(ip string) Event {
		return Event{OccurredAt: time.Unix(0, 0), Verdict: VerdictDeny, SrcIP: ip, DstIP: "10.0.0.1", Protocol: "tcp"}
	}
	// Add 7 into a cap-4 ring: 3 oldest drop, newest 4 remain, dropped==3.
	for i := 0; i < 7; i++ {
		b.Add(mk(string(rune('a' + i))))
	}
	if b.Len() != 4 {
		t.Fatalf("len = %d, want 4 (bounded)", b.Len())
	}
	events, dropped := b.Drain()
	if len(events) != 4 || dropped != 3 {
		t.Fatalf("drain = %d events, %d dropped; want 4, 3", len(events), dropped)
	}
	// The survivors are the NEWEST 4 (d,e,f,g) — oldest dropped.
	if events[0].SrcIP != "d" || events[3].SrcIP != "g" {
		t.Fatalf("drop-oldest wrong: first=%q last=%q", events[0].SrcIP, events[3].SrcIP)
	}
	// Drain reset both event slice and the drop counter.
	events, dropped = b.Drain()
	if len(events) != 0 || dropped != 0 {
		t.Fatalf("post-drain not reset: %d events, %d dropped", len(events), dropped)
	}
}

// The buffer must NEVER block a producer (enforcement/observation can't wait on the
// reporter). Flooding far past capacity returns promptly and stays bounded.
func TestBufferNeverBlocks(t *testing.T) {
	b := NewBuffer(8)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1_000_000; i++ {
			b.Add(Event{SrcIP: "x"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Add blocked / too slow — the buffer must be non-blocking + bounded")
	}
	if b.Len() > 8 {
		t.Fatalf("buffer exceeded its bound: %d", b.Len())
	}
}

package fqdnrpc

import (
	"context"
	"testing"
	"time"
)

func TestLookupProofComponentsBoundedAndDefaultOff(t *testing.T) {
	RecordLookupPhase(context.Background(), "native_recovery", time.Second, true)
	ctx, a := WithLookupTiming(context.Background())
	RecordLookupPhase(ctx, "unknown_secret_phase", time.Second, true)
	if a.Snapshot().ProofComponents.Recovery.Count != 0 {
		t.Fatal("unknown recorded")
	}
	RecordLookupPhase(ctx, "native_recovery", 123*time.Millisecond, true)
	RecordLookupPhase(ctx, "native_recovery", 4*time.Millisecond, false)
	v := a.Snapshot().ProofComponents.Recovery
	if v.Count != 2 || v.Successful != 1 || v.Refused != 1 || v.SummedMillis != 127 || v.MaxMillis != 123 {
		t.Fatal("component outcome")
	}
	for i := 0; i < 2*lookupExchangeCeiling; i++ {
		RecordLookupPhase(ctx, "native_recovery", 0, true)
	}
	v2 := a.Snapshot()
	if !v2.StatsSaturated || v2.ProofComponents.Recovery.Count != 2*lookupExchangeCeiling {
		t.Fatal("bound")
	}
	RecordLookupPhase(ctx, "guard_commands", -time.Second, false)
	if !a.Snapshot().StatsSaturated || a.Snapshot().ProofComponents.GuardCommands.SummedMillis != 0 {
		t.Fatal("negative")
	}
}

package ipsec

import (
	"context"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"testing"
)

func TestDNSProofGuardComponentsUseActualReaderNone(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	f.c.config.DNSReadTiming = true
	ctx, a := fqdnrpc.WithLookupTiming(context.Background())
	if _, err := f.prove(ctx); err != nil {
		t.Fatal("fixture proof refused")
	}
	v := a.Snapshot().ProofComponents
	if v.GuardCommands.Count != 1 || v.GuardCommands.Successful != 1 || v.GuardCommands.Refused != 0 || v.GuardVerification.Count != 1 || v.GuardVerification.Successful != 1 {
		t.Fatalf("actual successful guard label not recorded: %+v", v)
	}
	if f.nativeProofs.Load() != 1 || f.guardReads.Load() != 1 || f.routeReads.Load() != 1 || f.sourceReads.Load() != 2 {
		t.Fatal("proof read count changed")
	}
	f.c.config.DNSReadTiming = false
	ctx, b := fqdnrpc.WithLookupTiming(context.Background())
	if _, err := f.prove(ctx); err != nil {
		t.Fatal(err)
	}
	if b.Snapshot().ProofComponents.GuardCommands.Count != 0 {
		t.Fatal("disabled timing recorded")
	}
}

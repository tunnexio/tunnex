package ipsec

import (
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"testing"
)

func TestRuntimeLookupTimingDefaultOffAndMandatoryRefusal(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		f := newDNSOwnerViewFixture(t, nil)
		f.c.config.DNSReadTiming = enabled
		f.config.Version++ // exact grant mismatch refuses before any socket/native read.
		ctx, a := fqdnrpc.WithLookupTiming(t.Context())
		_, err := f.c.exchangeResolverDNS(ctx, f.config, f.config.Endpoints[0], []byte("private-payload"))
		if err == nil || f.nativeProofs.Load() != 0 || f.guardReads.Load() != 0 || f.routeReads.Load() != 0 {
			t.Fatal("refusal/read behavior changed")
		}
		v := a.Snapshot()
		if enabled {
			if !v.TransportTimingObserved || v.AttemptedExchanges != 1 || v.CompletedExchanges != 0 || v.BeforeProof.Count != 1 || v.BeforeProof.Refused != 1 || v.AfterProof.Count != 0 || v.Socket.Count != 0 {
				t.Fatal("refused phases misstated", v)
			}
		} else if v.TransportTimingObserved || v.AttemptedExchanges != 0 || v.BeforeProof.Count != 0 {
			t.Fatal("default-off recorded transport timing")
		}
	}
}

func TestRuntimeLookupTimingSuccessfulProofAndSocketRefusal(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	f.c.config.DNSReadTiming = true
	ctx, a := fqdnrpc.WithLookupTiming(t.Context())
	// Invalid DNS framing is rejected by the existing socket input validator,
	// after the full before-proof. It does not open a socket or perform extra reads.
	_, err := f.c.exchangeResolverDNS(ctx, f.config, f.config.Endpoints[0], []byte("private"))
	v := a.Snapshot()
	if err == nil || v.BeforeProof.Count != 1 || v.BeforeProof.Successful != 1 || v.Socket.Count != 1 || v.Socket.Refused != 1 || v.AfterProof.Count != 0 || v.CompletedExchanges != 0 || f.nativeProofs.Load() != 1 || f.guardReads.Load() != 1 || f.routeReads.Load() != 1 || f.sourceReads.Load() != 2 {
		t.Fatal("successful/failed stages or exact proof reads misstated", v)
	}
}

package ipsec

import "context"

// Static native proof retains two complete independent snapshots. Within each,
// daemon inspection is independent of the XFRM-then-kernel branch. Drain both
// before any validation, environment observation, or second snapshot begins.
func runtimeReadStaticProofSnapshot(ctx context.Context, r runtimeStatusReaders) (d DaemonInventory, k KernelInventory, x XFRMInventory, de, ke, xe error) {
	if ctx.Err() != nil {
		return d, k, x, ctx.Err(), ctx.Err(), ctx.Err()
	}
	done := make(chan struct{})
	go func() { defer close(done); d, de = r.daemon(ctx) }()
	x, xe = r.xfrm(ctx)
	// Preserve original failure precedence and XFRM-before-kernel read ordering.
	// A failed first reader cannot supply positive native evidence.
	if xe == nil && ctx.Err() == nil {
		k, ke = r.kernel(ctx)
	} else {
		ke = ErrRuntimeController
	}
	<-done
	return
}

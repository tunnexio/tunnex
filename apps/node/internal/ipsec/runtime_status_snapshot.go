package ipsec

import "context"

// Only one complete observation is in flight: daemon on one branch, kernel
// then XFRM on the other. The caller validates all results after both drain,
// before starting its independent second snapshot. No native facts are reused.
func runtimeReadStatusSnapshot(ctx context.Context, r runtimeStatusReaders) (d DaemonInventory, k KernelInventory, x XFRMInventory, de, ke, xe error) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		d, de = r.daemon(ctx)
	}()
	k, ke = r.kernel(ctx)
	// A failed/canceled kernel observation does not skip the XFRM reader;
	// preserve the existing complete read set and deterministic error precedence.
	x, xe = r.xfrm(ctx)
	<-done
	return
}

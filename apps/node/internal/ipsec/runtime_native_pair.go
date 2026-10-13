package ipsec

import "context"

// These independent full readers share only this call's context. Both finish
// before inventory or environment validation; no result survives a leg.
func runtimeNativeDaemonKernel(ctx context.Context, r runtimeStatusReaders) (DaemonInventory, KernelInventory, error, error) {
	if ctx.Err() != nil || r.daemon == nil || r.kernel == nil {
		return DaemonInventory{}, KernelInventory{}, ErrRuntimeController, ErrRuntimeController
	}
	if !r.independent {
		d, de := r.daemon(ctx)
		if de != nil {
			return d, KernelInventory{}, de, nil
		}
		k, ke := r.kernel(ctx)
		return d, k, nil, ke
	}
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		daemon bool
		d      DaemonInventory
		k      KernelInventory
		err    error
	}
	completed := make(chan result, 2)
	go func() {
		d, err := r.daemon(readCtx)
		completed <- result{daemon: true, d: d, err: err}
	}()
	go func() {
		k, err := r.kernel(readCtx)
		completed <- result{k: k, err: err}
	}()
	var d DaemonInventory
	var k KernelInventory
	var de, ke error
	for n := 0; n < 2; n++ {
		out := <-completed
		if out.err != nil {
			cancel()
		}
		if out.daemon {
			d, de = out.d, out.err
		} else {
			k, ke = out.k, out.err
		}
	}
	if ctx.Err() != nil {
		return DaemonInventory{}, KernelInventory{}, ErrRuntimeController, ErrRuntimeController
	}
	return d, k, de, ke
}

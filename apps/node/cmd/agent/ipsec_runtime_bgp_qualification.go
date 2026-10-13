package main

import (
	"context"
	"github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

// Static qualification and BGP qualification have independent success lifetimes.
// Failed BGP preflight retains no receipt; the next ordinary poll must prove anew.
func qualifyIPsecRuntimeBGP(ctx context.Context, attached *bool, qualify func(context.Context) (*bgp.PreflightQualification, error), attach func(*bgp.PreflightQualification) error) (string, error) {
	if *attached {
		return "", nil
	}
	if ctx == nil {
		return "bgp_preflight", context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return "bgp_preflight", err
	}
	receipt, err := qualify(ctx)
	if err != nil {
		return "bgp_preflight", err
	}
	if err := ctx.Err(); err != nil {
		return "bgp_preflight", err
	}
	if err := attach(receipt); err != nil {
		return "bgp_attach", err
	}
	*attached = true
	return "bgp_attach", nil
}

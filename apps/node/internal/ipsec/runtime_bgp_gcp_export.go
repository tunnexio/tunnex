package ipsec

import (
	"context"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"net/netip"
	"reflect"
)

// The generic FRR local-prefix probe stays strict. GCP's routed /32 topology
// instead reuses the controller's complete independently observed environment,
// bound to the exact provider-shaped allocation and immutable export config.
func (c *RuntimeController) gcpBGPLocalExportProof(e RuntimeJournalEntry, cfg bgpengine.Config, env RuntimeEnvironment) (bgpengine.LocalExportProof, error) {
	if c == nil || c.config.Environment == nil || e.Allocation.ProfileID != GCPHABGPProfile || e.ContractVersion != 3 || !validJournalBGP(e) {
		return nil, ErrRuntimeController
	}
	inspector, ok := c.config.Environment.(interface {
		ObserveLocalExports(context.Context, KernelAllocation, [2]EngineTunnel) (RuntimeEnvironment, error)
	})
	if !ok {
		return nil, ErrRuntimeController
	}
	snapshot := cloneDNSOwnerActive(runtimeActive{Entry: e, Environment: env})
	expected, err := runtimeBGPProcessConfig(snapshot.Entry)
	if err != nil || !reflect.DeepEqual(expected, cfg) || snapshot.Environment.Namespace != snapshot.Entry.Allocation.Namespace {
		return nil, ErrRuntimeController
	}
	return func(ctx context.Context, prefixes []netip.Prefix) error {
		if ctx.Err() != nil || !reflect.DeepEqual(prefixes, expected.LocalPrefixes) {
			return ErrRuntimeController
		}
		observed, err := inspector.ObserveLocalExports(ctx, snapshot.Entry.Allocation, snapshot.Entry.Engines)
		if err != nil || ctx.Err() != nil || !reflect.DeepEqual(observed, snapshot.Environment) {
			return ErrRuntimeController
		}
		return nil
	}, nil
}

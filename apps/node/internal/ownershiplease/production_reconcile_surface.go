package ownershiplease

import (
	"context"
	"fmt"

	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

// productionReconcileSurface delegates WireGuard and route mutation back to
// the existing Reconciler. The WG readback decorator above this surface owns
// actual-state proof, so this base returns no cached desired echo.
type productionReconcileSurface struct {
	owner *reconcile.Reconciler
}

func NewProductionReconcileSurface(owner *reconcile.Reconciler) (DomainSurface, error) {
	if owner == nil {
		return nil, fmt.Errorf("%w: reconcile owner is not configured", ErrProductionAdapterUnavailable)
	}
	return &productionReconcileSurface{owner: owner}, nil
}

func (s *productionReconcileSurface) ApplyStage(ctx context.Context, stage Stage, desired reconcile.DesiredState) error {
	switch stage {
	case StageWireGuard:
		_, err := s.owner.ApplyWireGuardDesired(ctx, desired)
		return err
	case StageRoutes:
		return s.owner.ApplyRoutesDesired(ctx, desired)
	case StageDNS, StageDNAT, StageOVPN:
		return nil
	default:
		return fmt.Errorf("unknown ownership stage %q", stage)
	}
}

func (s *productionReconcileSurface) Readback(context.Context) (AppliedDomainState, error) {
	return AppliedDomainState{}, nil
}

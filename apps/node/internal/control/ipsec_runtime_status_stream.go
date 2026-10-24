package control

import (
	"context"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

// Optional streaming keeps real-controller observations and their publications
// inside independent owner budgets. Legacy appliers retain the batch interface.
type IPsecActiveRecoveryObservedRefresher interface {
	RefreshIPsecActiveRecoveryObserved(context.Context, func(context.Context, ipsec.RuntimeRecoveryHeartbeat) error) error
}

func refreshIPsecRuntimeStatusObserved(ctx context.Context, client IPsecRuntimeTransport, observer IPsecActiveRecoveryObservedRefresher) error {
	seen := map[uuid.UUID]bool{}
	failed := false
	publish := func(parent context.Context, v ipsec.RuntimeRecoveryHeartbeat) (resultErr error) {
		defer func() { failed = failed || resultErr != nil }()
		if ctx.Err() != nil || parent.Err() != nil || len(seen) >= 256 || seen[v.ConnectionID] || v.ConnectionID == uuid.Nil || v.Delivery.Kind != "apply" || v.Delivery.Manifest.ConnectionID != v.ConnectionID || !runtimeStatusMatchesDelivery(v.Delivery, v.Report) {
			return ErrIPsecControl
		}
		seen[v.ConnectionID] = true
		return client.IPsecReportStatus(parent, v.ConnectionID, v.Report)
	}
	if observer.RefreshIPsecActiveRecoveryObserved(ctx, publish) != nil || failed || ctx.Err() != nil {
		return ErrIPsecControl
	}
	return nil
}

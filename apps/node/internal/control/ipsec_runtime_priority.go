package control

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

type IPsecRuntimeActiveRenewer interface {
	RenewActiveIPsecRuntimeObserved(context.Context, func(context.Context, ipsec.RuntimeDelivery, ipsec.RuntimeStatusReport) error, func(context.Context, ipsec.RuntimeRecoveryHeartbeat) error) error
}

// RefreshIPsecRuntimePriority keeps finite renewal ahead of optional status and
// discovery/material IO. Existing cleanup/polling still runs afterward; no ACK
// or private material is obtained or retained by this step.
func RefreshIPsecRuntimePriority(ctx context.Context, client IPsecRuntimeTransport, controller IPsecRuntimeApplier) error {
	failed := false
	sequences := map[uuid.UUID]uint64{}
	observed := map[uuid.UUID]bool{}
	if renewer, ok := controller.(IPsecRuntimeActiveRenewer); ok {
		send := func(parent context.Context, d ipsec.RuntimeDelivery, out ipsec.RuntimeStatusReport) error {
			if ctx.Err() != nil || parent.Err() != nil || d.Kind != "apply" || d.Manifest.ConnectionID == uuid.Nil || !runtimeStatusMatchesDelivery(d, out) {
				return ErrIPsecControl
			}
			reportCtx, cancel := context.WithTimeout(parent, 5*time.Second)
			defer cancel()
			stopParentCancel := context.AfterFunc(ctx, cancel)
			defer stopParentCancel()
			// Status HTTP failures are advisory, as in normal maintained-page reporting.
			if client.IPsecReportStatus(reportCtx, d.Manifest.ConnectionID, out) != nil {
				failed = true
			}
			return nil
		}
		publish := func(parent context.Context, d ipsec.RuntimeDelivery, out ipsec.RuntimeStatusReport) error {
			if observed[d.ID] || len(observed) >= 256 || (sequences[d.ID] != 0 && (out.SelectionSequence == nil || *out.SelectionSequence <= sequences[d.ID])) {
				return ErrIPsecControl
			}
			observed[d.ID] = true
			if out.SelectionSequence != nil {
				sequences[d.ID] = *out.SelectionSequence
			}
			return send(parent, d, out)
		}
		recovery := func(parent context.Context, v ipsec.RuntimeRecoveryHeartbeat) error {
			if v.ConnectionID == uuid.Nil || v.ConnectionID != v.Delivery.Manifest.ConnectionID || v.Delivery.Manifest.BGP != nil || v.Report.RecoveryVersion == nil || *v.Report.RecoveryVersion != 1 || v.Report.SelectionSequence == nil || *v.Report.SelectionSequence == 0 || *v.Report.SelectionSequence > 9007199254740991 || *v.Report.SelectionSequence <= sequences[v.Delivery.ID] {
				return ErrIPsecControl
			}
			sequences[v.Delivery.ID] = *v.Report.SelectionSequence
			return send(parent, v.Delivery, v.Report)
		}
		if renewer.RenewActiveIPsecRuntimeObserved(ctx, publish, recovery) != nil {
			failed = true
		}
	}
	// Preserve the existing observation even after renewal refusal, and let the
	// caller continue its ordinary authoritative discovery/cleanup path.
	if RefreshIPsecRuntimeStatus(ctx, client, controller) != nil {
		failed = true
	}
	if failed {
		return ErrIPsecControl
	}
	return nil
}

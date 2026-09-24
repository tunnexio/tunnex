package control

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

type IPsecRuntimeTransport interface {
	IPsecPending(context.Context, *uuid.UUID, int) (ipsec.RuntimePendingPage, error)
	IPsecMaterial(context.Context, uuid.UUID, int64) (ipsec.RuntimeMaterial, error)
	IPsecCleanup(context.Context, uuid.UUID, int64) (ipsec.RuntimeCleanup, error)
	IPsecAcknowledge(context.Context, uuid.UUID, ipsec.RuntimeAcknowledgement) error
	IPsecReportStatus(context.Context, uuid.UUID, ipsec.RuntimeStatusReport) error
}
type IPsecRuntimeApplier interface {
	Apply(context.Context, ipsec.RuntimeMaterial) (ipsec.RuntimeAcknowledgement, error)
	Cleanup(context.Context, ipsec.RuntimeCleanup) (ipsec.RuntimeAcknowledgement, error)
	ObserveIPsecStatus(context.Context, ipsec.RuntimeDelivery) (ipsec.RuntimeStatusReport, error)
}

// PollIPsecRuntime is called serially by the runtime owner. Authority is fetched
// afresh on every pass; this function retains no material, grants, or lease.
func PollIPsecRuntime(ctx context.Context, client IPsecRuntimeTransport, controller IPsecRuntimeApplier) error {
	var cursor *uuid.UUID
	var failed bool
	seen := map[uuid.UUID]bool{}
	for pageNumber := 0; pageNumber < 16; pageNumber++ {
		page, e := client.IPsecPending(ctx, cursor, 100)
		if e != nil {
			return ErrIPsecControl
		}
		if len(page.Items) > 100 {
			return ErrIPsecControl
		}
		for _, item := range page.Items {
			if item.ConnectionID == uuid.Nil || item.DesiredRevision <= 0 || seen[item.ConnectionID] {
				return ErrIPsecControl
			}
			seen[item.ConnectionID] = true
		}
		// Cleanup on this page takes precedence over renewed activation.
		for _, kind := range []string{"cleanup", "apply"} {
			for _, item := range page.Items {
				if item.Kind != "cleanup" && item.Kind != "apply" {
					return ErrIPsecControl
				}
				if item.Kind != kind {
					continue
				}
				if e = pollIPsecItem(ctx, client, controller, item); e != nil {
					failed = true
				}
			}
		}
		if page.NextCursor == nil {
			if failed {
				return ErrIPsecControl
			}
			return nil
		}
		next := *page.NextCursor
		if next == uuid.Nil || cursor != nil && bytes.Compare(next[:], cursor[:]) <= 0 || len(page.Items) == 0 || next != page.Items[len(page.Items)-1].ConnectionID {
			return ErrIPsecControl
		}
		cursor = &next
	}
	return ErrIPsecControl
}
func pollIPsecItem(ctx context.Context, client IPsecRuntimeTransport, controller IPsecRuntimeApplier, item ipsec.RuntimePending) error {
	var ack ipsec.RuntimeAcknowledgement
	var delivery ipsec.RuntimeDelivery
	var err error
	var statusErr error
	switch item.Kind {
	case "apply":
		material, e := client.IPsecMaterial(ctx, item.ConnectionID, item.DesiredRevision)
		if e != nil {
			return ErrIPsecControl
		}
		defer func() {
			for i := range material.Secrets {
				material.Secrets[i].PSK = ""
			}
		}()
		delivery = material.RuntimeDelivery
		if !runtimeDeliveryMatches(delivery, item) {
			return ErrIPsecControl
		}
		ack, err = controller.Apply(ctx, material)
		report, observeErr := controller.ObserveIPsecStatus(ctx, delivery)
		if observeErr != nil {
			statusErr = ErrIPsecControl
		} else if client.IPsecReportStatus(ctx, item.ConnectionID, report) != nil {
			statusErr = ErrIPsecControl
		}
	case "cleanup":
		cleanup, e := client.IPsecCleanup(ctx, item.ConnectionID, item.DesiredRevision)
		if e != nil {
			return ErrIPsecControl
		}
		delivery = cleanup.RuntimeDelivery
		if !runtimeDeliveryMatches(delivery, item) {
			return ErrIPsecControl
		}
		ack, err = controller.Cleanup(ctx, cleanup)
	default:
		return ErrIPsecControl
	}
	if err != nil || ack.DeliveryID != delivery.ID || ack.DesiredRevision != item.DesiredRevision || ack.Kind != item.Kind {
		return ErrIPsecControl
	}
	if client.IPsecAcknowledge(ctx, item.ConnectionID, ack) != nil {
		return ErrIPsecControl
	}
	return statusErr
}
func runtimeDeliveryMatches(d ipsec.RuntimeDelivery, item ipsec.RuntimePending) bool {
	return d.ID != uuid.Nil && d.Kind == item.Kind && d.DesiredRevision == item.DesiredRevision && d.Manifest.ConnectionID == item.ConnectionID && ((item.Kind == "apply" && d.Manifest.DesiredRevision == item.DesiredRevision) || (item.Kind == "cleanup" && d.Manifest.DesiredRevision > 0 && d.Manifest.DesiredRevision < item.DesiredRevision))
}

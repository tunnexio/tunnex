package control

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"reflect"
	"time"
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

// IPsecRecoveryRefresher is optional inactive evidence work by the same owner.
// It never installs permits or substitutes for fresh ordinary material/Apply.
type IPsecRecoveryRefresher interface {
	RefreshIPsecRecovery(context.Context) error
}

// IPsecActiveRecoveryRefresher independently samples and reports current static
// transport between slow provider reconciliations; it cannot acknowledge Apply.
type IPsecActiveRecoveryRefresher interface {
	RefreshIPsecActiveRecovery(context.Context) ([]ipsec.RuntimeRecoveryHeartbeat, error)
}

func RefreshIPsecRuntimeStatus(ctx context.Context, client IPsecRuntimeTransport, controller IPsecRuntimeApplier) error {
	observer, ok := controller.(IPsecActiveRecoveryRefresher)
	if !ok {
		return nil
	}
	observationCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	reports, err := observer.RefreshIPsecActiveRecovery(observationCtx)
	if err != nil {
		return ErrIPsecControl
	}
	if len(reports) > 256 {
		return ErrIPsecControl
	}
	seen := map[uuid.UUID]bool{}
	for _, v := range reports {
		if seen[v.ConnectionID] {
			return ErrIPsecControl
		}
		seen[v.ConnectionID] = true
		if observationCtx.Err() != nil || v.ConnectionID == uuid.Nil || v.Delivery.Kind != "apply" || v.Delivery.Manifest.ConnectionID != v.ConnectionID || !runtimeStatusMatchesDelivery(v.Delivery, v.Report) {
			return ErrIPsecControl
		}
	}
	failed := false
	for _, v := range reports {
		if client.IPsecReportStatus(observationCtx, v.ConnectionID, v.Report) != nil {
			failed = true
		}
	}
	if failed {
		return ErrIPsecControl
	}
	return nil
}

// PollIPsecRuntime is called serially by the runtime owner. Authority is fetched
// afresh on every pass; this function retains no material, grants, or lease.
func PollIPsecRuntime(ctx context.Context, client IPsecRuntimeTransport, controller IPsecRuntimeApplier) error {
	_, err := PollIPsecRuntimeValidated(ctx, client, controller)
	return err
}

// IPsecRuntimeMaintainer handles only previously applied unchanged deliveries.
// Missing results retain the ordinary Apply path and its material validation.
type IPsecRuntimeMaintainer interface {
	MaintainIPsecRuntime(context.Context, []ipsec.RuntimeMaterial) ([]ipsec.RuntimeMaintenanceResult, error)
}

// IPsecRuntimeObservedMaintainer reports actual post-commit observations while
// gathering the page. Telemetry cannot substitute for a complete validated ACK.
type IPsecRuntimeObservedMaintainer interface {
	MaintainIPsecRuntimeObserved(context.Context, []ipsec.RuntimeMaterial, func(context.Context, ipsec.RuntimeDelivery, ipsec.RuntimeStatusReport) error) ([]ipsec.RuntimeMaintenanceResult, error)
}

// PollIPsecRuntimeValidated reports a complete nonempty application pass. The
// owner still validates on failed discovery/polling, empty, or cleanup-only work.
func PollIPsecRuntimeValidated(ctx context.Context, client IPsecRuntimeTransport, controller IPsecRuntimeApplier) (bool, error) {
	var cursor *uuid.UUID
	var failed bool
	var applied bool
	seen := map[uuid.UUID]bool{}
	for pageNumber := 0; pageNumber < 16; pageNumber++ {
		page, e := client.IPsecPending(ctx, cursor, 100)
		if e != nil {
			return false, ErrIPsecControl
		}
		if len(page.Items) > 100 {
			return false, ErrIPsecControl
		}
		for _, item := range page.Items {
			if item.ConnectionID == uuid.Nil || item.DesiredRevision <= 0 || seen[item.ConnectionID] {
				return false, ErrIPsecControl
			}
			seen[item.ConnectionID] = true
		}
		// Cleanup on this page takes precedence over renewed activation.
		for _, kind := range []string{"cleanup", "apply"} {
			if kind == "apply" {
				if maintainer, ok := controller.(IPsecRuntimeMaintainer); ok {
					count, err := pollIPsecMaintainedPage(ctx, client, controller, maintainer, page.Items)
					applied = applied || count > 0
					failed = failed || err != nil
					continue
				}
			}
			for _, item := range page.Items {
				if item.Kind != "cleanup" && item.Kind != "apply" {
					return false, ErrIPsecControl
				}
				if item.Kind != kind {
					continue
				}
				if kind == "apply" {
					applied = true
					if RefreshIPsecRuntimeStatus(ctx, client, controller) != nil {
						failed = true
					}
					if observer, ok := controller.(IPsecRecoveryRefresher); ok {
						observationCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
						if observer.RefreshIPsecRecovery(observationCtx) != nil {
							failed = true
						}
						cancel()
					}
				}
				if e = pollIPsecItem(ctx, client, controller, item); e != nil {
					failed = true
				}
			}
		}
		if page.NextCursor == nil {
			if failed || ctx.Err() != nil {
				return false, ErrIPsecControl
			}
			return applied, nil
		}
		next := *page.NextCursor
		if next == uuid.Nil || cursor != nil && bytes.Compare(next[:], cursor[:]) <= 0 || len(page.Items) == 0 || next != page.Items[len(page.Items)-1].ConnectionID {
			return false, ErrIPsecControl
		}
		cursor = &next
	}
	return false, ErrIPsecControl
}
func pollIPsecItem(ctx context.Context, client IPsecRuntimeTransport, controller IPsecRuntimeApplier, item ipsec.RuntimePending) error {
	var ack ipsec.RuntimeAcknowledgement
	var delivery ipsec.RuntimeDelivery
	var err error
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
		return pollIPsecApplyMaterial(ctx, client, controller, item, material)
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
	return nil
}
func runtimeDeliveryMatches(d ipsec.RuntimeDelivery, item ipsec.RuntimePending) bool {
	return d.ID != uuid.Nil && d.Kind == item.Kind && d.DesiredRevision == item.DesiredRevision && d.Manifest.ConnectionID == item.ConnectionID && ((item.Kind == "apply" && d.Manifest.DesiredRevision == item.DesiredRevision) || (item.Kind == "cleanup" && d.Manifest.DesiredRevision > 0 && d.Manifest.DesiredRevision < item.DesiredRevision))
}

func runtimeStatusMatchesDelivery(d ipsec.RuntimeDelivery, report ipsec.RuntimeStatusReport) bool {
	m := d.Manifest
	if !validIPsecStatusReport(report) || report.DeliveryID != d.ID || report.DesiredRevision != d.DesiredRevision || report.ConfigurationRevision != m.ConfigurationRevision {
		return false
	}
	count := 2
	if m.ProfileID == ipsec.GCPClassicStaticProfile {
		if m.TransportVersion == nil || *m.TransportVersion != 1 || m.TunnelCount == nil || *m.TunnelCount != 1 || m.Tunnels[1] != (ipsec.RuntimeTunnel{}) || report.TransportVersion == nil || *report.TransportVersion != 1 || report.TunnelCount == nil || *report.TunnelCount != 1 {
			return false
		}
		count = 1
	} else if m.TransportVersion != nil || m.TunnelCount != nil || report.TransportVersion != nil || report.TunnelCount != nil {
		return false
	}
	dynamic := m.ProfileID == "aws-bgp-ipv4-v1" || m.ProfileID == ipsec.GCPHABGPProfile
	bgpVersion := 1
	if m.ProfileID == ipsec.GCPHABGPProfile {
		bgpVersion = 2
	}
	if dynamic {
		if m.BGP == nil || m.BGPVersion == nil || *m.BGPVersion != bgpVersion || m.RecoveryVersion != nil {
			return false
		}
	} else if (m.ProfileID != "aws-static-ipv4-v1" && m.ProfileID != ipsec.GCPClassicStaticProfile) || m.BGP != nil || m.BGPVersion != nil || report.BGP != nil {
		return false
	}
	for i, t := range m.Tunnels[:count] {
		if report.Tunnels[i].ID != t.ID || t.Slot != i+1 || t.Selected != (!dynamic && i == 0) || report.Tunnels[i].Selected != t.Selected {
			return false
		}
	}
	if dynamic {
		if m.BGP.MaximumPrefixes < 1 || m.BGP.MaximumPrefixes > 64 || len(m.RemotePrefixes) > 64 {
			return false
		}
		approved := map[string]bool{}
		for _, prefix := range m.RemotePrefixes {
			approved[prefix] = true
		}
		if report.BGP != nil {
			for _, peer := range report.BGP.Peers {
				if peer.AcceptedPrefixes > m.BGP.MaximumPrefixes || peer.AcceptedPrefixes > len(approved) {
					return false
				}
			}
			for _, route := range report.BGP.Routes {
				if !approved[route.Prefix] {
					return false
				}
			}
		}
		return true
	}
	return (m.RecoveryVersion == nil && report.RecoveryVersion == nil) || (m.RecoveryVersion != nil && *m.RecoveryVersion == 1 && report.RecoveryVersion != nil && *report.RecoveryVersion == 1)
}

func pollIPsecApplyMaterial(ctx context.Context, client IPsecRuntimeTransport, controller IPsecRuntimeApplier, item ipsec.RuntimePending, material ipsec.RuntimeMaterial) error {
	delivery := material.RuntimeDelivery
	ack, err := controller.Apply(ctx, material)
	var statusErr error
	report, observeErr := controller.ObserveIPsecStatus(ctx, delivery)
	if observeErr != nil || !runtimeStatusMatchesDelivery(delivery, report) {
		statusErr = ErrIPsecControl
	} else if client.IPsecReportStatus(ctx, item.ConnectionID, report) != nil {
		statusErr = ErrIPsecControl
	}
	if err != nil || ack.DeliveryID != delivery.ID || ack.DesiredRevision != item.DesiredRevision || ack.Kind != item.Kind {
		return ErrIPsecControl
	}
	if client.IPsecAcknowledge(ctx, item.ConnectionID, ack) != nil {
		return ErrIPsecControl
	}
	return statusErr
}

// Cleanup has already run for this page. Fresh normal material is retained only
// through this pass, and every PSK is cleared even on cancellation or rejection.
func pollIPsecMaintainedPage(ctx context.Context, client IPsecRuntimeTransport, controller IPsecRuntimeApplier, maintainer IPsecRuntimeMaintainer, items []ipsec.RuntimePending) (int, error) {
	materials := []ipsec.RuntimeMaterial{}
	pending := []ipsec.RuntimePending{}
	byDelivery := map[uuid.UUID]int{}
	failed := false
	defer func() {
		for i := range materials {
			for j := range materials[i].Secrets {
				materials[i].Secrets[j].PSK = ""
			}
		}
	}()
	for _, item := range items {
		if item.Kind != "apply" {
			continue
		}
		material, err := client.IPsecMaterial(ctx, item.ConnectionID, item.DesiredRevision)
		if err != nil {
			failed = true
			continue
		}
		materials = append(materials, material)
		pending = append(pending, item)
		index := len(materials) - 1
		if !runtimeDeliveryMatches(material.RuntimeDelivery, item) {
			return 0, ErrIPsecControl
		}
		if _, duplicate := byDelivery[material.ID]; duplicate {
			return 0, ErrIPsecControl
		}
		byDelivery[material.ID] = index
	}
	if len(materials) == 0 {
		if failed {
			return 0, ErrIPsecControl
		}
		return 0, nil
	}
	observed := map[uuid.UUID]string{}
	published := map[uuid.UUID]bool{}
	observationRejected := false
	var results []ipsec.RuntimeMaintenanceResult
	var err error
	if observer, ok := maintainer.(IPsecRuntimeObservedMaintainer); ok {
		results, err = observer.MaintainIPsecRuntimeObserved(ctx, materials, func(observationCtx context.Context, delivery ipsec.RuntimeDelivery, report ipsec.RuntimeStatusReport) error {
			index, known := byDelivery[delivery.ID]
			if !known || ctx.Err() != nil || observationCtx.Err() != nil || !reflect.DeepEqual(delivery, materials[index].RuntimeDelivery) || !runtimeStatusMatchesDelivery(delivery, report) {
				observationRejected = true
				return ErrIPsecControl
			}
			if _, duplicate := observed[delivery.ID]; duplicate {
				observationRejected = true
				return ErrIPsecControl
			}
			raw, err := json.Marshal(report)
			if err != nil {
				observationRejected = true
				return ErrIPsecControl
			}
			observed[delivery.ID] = string(raw)
			reportCtx, cancel := context.WithTimeout(observationCtx, 5*time.Second)
			defer cancel()
			// Optional observers cannot detach report IO from the polling owner.
			stopParentCancel := context.AfterFunc(ctx, cancel)
			defer stopParentCancel()
			// A report RPC failure marks telemetry failed without revoking a
			// separately valid native commit solely because HTTP is unavailable.
			if client.IPsecReportStatus(reportCtx, delivery.Manifest.ConnectionID, report) != nil {
				failed = true
			} else {
				published[delivery.ID] = true
			}
			return nil
		})
	} else {
		results, err = maintainer.MaintainIPsecRuntime(ctx, materials)
	}
	if observationRejected {
		return 0, ErrIPsecControl
	}
	if err != nil {
		if len(results) != 0 {
			return 0, ErrIPsecControl
		}
		failed = true
	}
	if ctx.Err() != nil || len(results) > len(materials) {
		return 0, ErrIPsecControl
	}
	maintained := map[uuid.UUID]ipsec.RuntimeMaintenanceResult{}
	// Validate the entire result envelope before sending even the first ACK.
	for _, result := range results {
		ack := result.Acknowledgement
		index, ok := byDelivery[ack.DeliveryID]
		if !ok {
			return 0, ErrIPsecControl
		}
		if _, duplicate := maintained[ack.DeliveryID]; duplicate {
			return 0, ErrIPsecControl
		}
		m := materials[index]
		if ack.Kind != "apply" || ack.Result != "applied" || ack.DesiredRevision != pending[index].DesiredRevision || ack.OwnershipDigest != m.OwnershipDigest || !runtimeStatusMatchesDelivery(m.RuntimeDelivery, result.Report) {
			return 0, ErrIPsecControl
		}
		if before, ok := observed[ack.DeliveryID]; ok {
			raw, err := json.Marshal(result.Report)
			if err != nil || before != string(raw) {
				return 0, ErrIPsecControl
			}
		}
		maintained[ack.DeliveryID] = result
	}
	for i, material := range materials {
		item := pending[i]
		if result, ok := maintained[material.ID]; ok {
			if ctx.Err() != nil {
				return 0, ErrIPsecControl
			}
			if _, alreadySent := published[material.ID]; !alreadySent {
				if client.IPsecReportStatus(ctx, item.ConnectionID, result.Report) != nil {
					failed = true
				}
			}
			if client.IPsecAcknowledge(ctx, item.ConnectionID, result.Acknowledgement) != nil {
				failed = true
			}
			continue
		}
	}
	// Publish the completed maintained commit before an ordinary fallback can
	// replace or withdraw runtime state. Never report cached positive state after it.
	for i, material := range materials {
		if _, ok := maintained[material.ID]; ok {
			continue
		}
		item := pending[i]
		if RefreshIPsecRuntimeStatus(ctx, client, controller) != nil {
			failed = true
		}
		if observer, ok := controller.(IPsecRecoveryRefresher); ok {
			observationCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if observer.RefreshIPsecRecovery(observationCtx) != nil {
				failed = true
			}
			cancel()
		}
		if pollIPsecApplyMaterial(ctx, client, controller, item, material) != nil {
			failed = true
		}
	}
	if failed || ctx.Err() != nil {
		return len(materials), ErrIPsecControl
	}
	return len(materials), nil
}

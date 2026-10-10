package control

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
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
				if kind == "apply" {
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
		if observeErr != nil || !runtimeStatusMatchesDelivery(delivery, report) {
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

package ipsec

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Exercise the real expiry-only atomic commit and serialized callback envelope.
// The recovery envelope below is required by API validRecoveryStatus; unknown
// native status may be honest, but recovery1 must still carry a durable sequence.
func TestFQDNFollowupStaticPublishesCPRecoveryEnvelope(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "publication_refused"}[reject], func(t *testing.T) {
			x := newAssemblyRefreshRig(t)
			nativeReads := 0
			x.r.c.config.IPPath = "/usr/bin/true"
			x.r.c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
				nativeReads++
				return viciMessage{}, nil, ErrRuntimeController
			}}
			prepared := map[uuid.UUID]maintenanceItem{}
			for _, id := range x.ids {
				m, err := x.client.IPsecMaterial(context.Background(), id, x.prior[id].Delivery.DesiredRevision)
				if err != nil {
					t.Fatal(err)
				}
				item, err := x.r.c.prepareFQDNExpiryMaterial(context.Background(), x.prior[id], m)
				if err != nil {
					t.Fatal(err)
				}
				prepared[id] = item
			}
			_, sequenceBefore, err := x.r.c.journal.guardTemplates()
			if err != nil {
				t.Fatal(err)
			}
			published := map[uuid.UUID]uint64{}
			publish := func(_ context.Context, d RuntimeDelivery, original RuntimeStatusReport) error {
				wire, err := json.Marshal(original)
				if err != nil {
					t.Fatal(err)
				}
				var report RuntimeStatusReport
				if err = json.Unmarshal(wire, &report); err != nil {
					t.Fatal(err)
				}
				if report.DeliveryID != d.ID || report.DesiredRevision != d.DesiredRevision || report.ConfigurationRevision != d.Manifest.ConfigurationRevision {
					t.Fatal("followup report lost immutable delivery identity")
				}
				if d.Manifest.RecoveryVersion == nil || *d.Manifest.RecoveryVersion != 1 || report.RecoveryVersion == nil || *report.RecoveryVersion != 1 || report.SelectionSequence == nil || *report.SelectionSequence == 0 || *report.SelectionSequence > 9007199254740991 || report.ActiveSlot != nil && *report.ActiveSlot != 1 && *report.ActiveSlot != 2 {
					t.Fatal("CP would reject static followup recovery envelope", report.RecoveryVersion, report.SelectionSequence, report.ActiveSlot)
				}
				if report.BGP != nil || report.TransportVersion != nil || report.TunnelCount != nil {
					t.Fatal("AWS static followup gained a foreign transport envelope")
				}
				_, durable, err := x.r.c.journal.guardTemplates()
				if err != nil || *report.SelectionSequence != durable || durable <= sequenceBefore {
					t.Fatal("report did not use an actually persisted fresh sequence", err, durable, sequenceBefore)
				}
				for i, tunnel := range report.Tunnels {
					if tunnel.ID != d.Manifest.Tunnels[i].ID || tunnel.Slot != i+1 || tunnel.Selected != d.Manifest.Tunnels[i].Selected {
						t.Fatal("tunnel identity/selection changed")
					}
					if tunnel.Status != "unknown" || report.ActiveSlot != nil {
						t.Fatal("fixture native reader refused; positive state was fabricated")
					}
				}
				published[d.Manifest.ConnectionID] = durable
				if reject {
					return ErrRuntimeController
				}
				return nil
			}
			err = x.r.c.commitFQDNFollowup(context.Background(), maintenanceAuthority(x.r), func() bool { return true }, prepared, publish)
			if reject {
				if err == nil || len(published) != 1 || len(x.r.c.active) != 0 || len(x.r.c.fqdnNativeWindows) != 0 {
					t.Fatal("publication refusal retained authority", err, len(published), len(x.r.c.active))
				}
			} else {
				if err != nil || len(published) != 2 {
					t.Fatal("static expiry commit failed", err, len(published))
				}
				for _, id := range x.ids {
					a := x.r.c.active[id]
					if !reflect.DeepEqual(a.Entry, x.prior[id].Entry) || a.Identity.PolicyHash != prepared[id].PolicyHash || a.Authority == x.prior[id].Authority {
						t.Fatal("fresh followup changed transport or lacked independent authority")
					}
					if _, err := a.Authority.RemainingForApply(a.Identity, time.Millisecond); err != nil {
						t.Fatal(err)
					}
				}
			}
			if nativeReads != len(published) {
				t.Fatal("publication did not follow actual native attempts", nativeReads, len(published))
			}
			for authority, deadline := range x.deadlines {
				if authority.deadline != deadline || !reflect.DeepEqual(authority.fqdnDeadlines, x.fqdnDeadlines[authority]) {
					t.Fatal("old authority extended")
				}
			}
		})
	}
}

func TestFQDNFollowupBGPPreservesNonRecoveryEnvelope(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t)
	r.c.config.JournalDir = r.c.journal.dir
	fresh, err := r.c.prepareFQDNExpiryMaterial(context.Background(), r.c.active[r.target], client.material)
	if err != nil {
		t.Fatal(err)
	}
	published := 0
	publish := func(_ context.Context, d RuntimeDelivery, report RuntimeStatusReport) error {
		if d.Manifest.BGP == nil || report.RecoveryVersion != nil || report.SelectionSequence != nil || report.ActiveSlot != nil {
			t.Fatal("BGP followup gained recovery-only fields")
		}
		published++
		return nil
	}
	if err := r.c.commitFQDNFollowup(context.Background(), maintenanceAuthority(r), func() bool { return true }, map[uuid.UUID]maintenanceItem{r.target: fresh}, publish); err != nil || published != 1 {
		t.Fatal("existing BGP followup changed", err, published)
	}
}

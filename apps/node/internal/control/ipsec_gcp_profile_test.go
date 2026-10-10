package control

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"testing"
)

func TestGCPHAStatusRequiresExactProviderVersion(t *testing.T) {
	f := &runtimePollFake{item: ipsec.RuntimePending{ConnectionID: uuid.New(), DesiredRevision: 2, Kind: "apply"}, bgp: true}
	m, _ := f.IPsecMaterial(context.Background(), f.item.ConnectionID, 2)
	v := 2
	m.Manifest.ProfileID = ipsec.GCPHABGPProfile
	m.Manifest.BGPVersion = &v
	report, _ := f.ObserveIPsecStatus(context.Background(), m.RuntimeDelivery)
	if !runtimeStatusMatchesDelivery(m.RuntimeDelivery, report) {
		t.Fatal("honest unobserved GCP BGP status refused")
	}
	v = 1
	if runtimeStatusMatchesDelivery(m.RuntimeDelivery, report) {
		t.Fatal("AWS version accepted for GCP")
	}
	v = 2
	m.Manifest.ProfileID = ipsec.GCPClassicStaticProfile
	if runtimeStatusMatchesDelivery(m.RuntimeDelivery, report) {
		t.Fatal("unsupported classic accepted")
	}
	if (*Client)(nil).ipsecGCPHACapability() != 0 {
		t.Fatal("nil client capability")
	}
}

func TestGCPClassicStatusSingleSlotExactMetadata(t *testing.T) {
	v, count := 1, 1
	id := uuid.New()
	tunnel := uuid.New()
	d := ipsec.RuntimeDelivery{ID: id, DesiredRevision: 2, Kind: "apply", Manifest: ipsec.RuntimeManifest{ConnectionID: uuid.New(), DesiredRevision: 2, ConfigurationRevision: 1, ProfileID: ipsec.GCPClassicStaticProfile, TransportVersion: &v, TunnelCount: &count, Tunnels: [2]ipsec.RuntimeTunnel{{ID: tunnel, Slot: 1, Selected: true}}}}
	report := ipsec.RuntimeStatusReport{DeliveryID: id, DesiredRevision: 2, ConfigurationRevision: 1, TransportVersion: &v, TunnelCount: &count, Tunnels: [2]ipsec.RuntimeTunnelStatus{{ID: tunnel, Slot: 1, Status: "unknown", Selected: true}}}
	if !runtimeStatusMatchesDelivery(d, report) {
		t.Fatal("honest Classic status refused")
	}
	report.Tunnels[1].Status = "up"
	if runtimeStatusMatchesDelivery(d, report) {
		t.Fatal("fake inactive UP accepted")
	}
	report.Tunnels[1] = ipsec.RuntimeTunnelStatus{}
	report.TransportVersion = nil
	if runtimeStatusMatchesDelivery(d, report) {
		t.Fatal("missing version accepted")
	}
}

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

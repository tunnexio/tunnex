package control

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"testing"
)

func TestAzureStatusCardinalityAndVersionAreExact(t *testing.T) {
	for _, profile := range []string{ipsec.AzureActiveActiveBGPProfile, ipsec.AzureActiveActiveStaticProfile, ipsec.AzureActiveStandbyBGPProfile, ipsec.AzureActiveStandbyStaticProfile} {
		t.Run(profile, func(t *testing.T) {
			id := uuid.New()
			d := ipsec.RuntimeDelivery{ID: id, DesiredRevision: 2, Kind: "apply", Manifest: ipsec.RuntimeManifest{ConnectionID: uuid.New(), DesiredRevision: 2, ConfigurationRevision: 1, ProfileID: profile}}
			count := 2
			if ipsec.IsSingleTunnelProfile(profile) {
				v, n := 1, 1
				d.Manifest.TransportVersion = &v
				d.Manifest.TunnelCount = &n
				count = 1
			}
			bgp := ipsec.IsAzureBGPProfile(profile)
			if bgp {
				v := 3
				d.Manifest.BGPVersion = &v
				d.Manifest.BGP = &ipsec.BGPConfig{LocalASN: 65000, RemoteASN: 65515, RouterID: "10.10.0.1", MaximumPrefixes: 64}
			}
			for i := 0; i < count; i++ {
				d.Manifest.Tunnels[i] = ipsec.RuntimeTunnel{ID: uuid.New(), Slot: i + 1, Selected: !bgp && i == 0}
			}
			report, err := (*ipsec.RuntimeController)(nil).ObserveIPsecStatus(context.Background(), d)
			if err != nil || !runtimeStatusMatchesDelivery(d, report) {
				t.Fatal("honest unknown status refused", err)
			}
			if bgp {
				v := 2
				d.Manifest.BGPVersion = &v
				if runtimeStatusMatchesDelivery(d, report) {
					t.Fatal("GCP version accepted")
				}
				v = 3
				d.Manifest.BGPVersion = &v
			}
			if count == 1 {
				report.Tunnels[1] = ipsec.RuntimeTunnelStatus{ID: uuid.New(), Slot: 2, Status: "up"}
				if runtimeStatusMatchesDelivery(d, report) {
					t.Fatal("inactive tunnel reported")
				}
			}
		})
	}
	if (*Client)(nil).ipsecAzureCapability() != 0 {
		t.Fatal("nil capability")
	}
}

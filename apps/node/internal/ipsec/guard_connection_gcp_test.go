package ipsec

import (
	"github.com/google/uuid"
	"testing"
)

// Real profile contracts feed the production renderer/readback; native inputs
// are modeled. Healthy membership never borrows another profile's authority.
func TestGCPMixedConnectionGuardExpiryIsolation(t *testing.T) {
	classic := classicEntryFixture(t)
	m := gcpMaterialFixture()
	m.Manifest.ConnectionID = uuid.New()
	m.Manifest.RemotePrefixes = []string{"10.80.0.0/24"}
	runtimeReseal(&m)
	ha, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, classic.Allocation.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	links := []GuardInterface{{Name: classic.Allocation.Tunnels[0].Name, Index: 10}, {Name: ha.Allocation.Tunnels[0].Name, Index: 20}, {Name: ha.Allocation.Tunnels[1].Name, Index: 21}}
	for _, target := range []RuntimeJournalEntry{classic, ha} {
		other := ha
		if target.Allocation.ConnectionID == ha.Allocation.ConnectionID {
			other = classic
		}
		rendered, err := RenderGuard(GuardIntent{OwnerID: m.Manifest.NodeID, Namespace: classic.Allocation.Namespace, Revision: 1, Connections: []GuardConnection{gcpWithdrawalGuard(classic, 10), gcpWithdrawalGuard(ha, 20)}})
		if err != nil {
			t.Fatal(err)
		}
		for _, zero := range []bool{false, true} {
			raw := guardTableFixtureEdit(t, []byte(rendered.ExpectedJSON), func(o map[string]any) {
				set, ok := o["set"].(map[string]any)
				if !ok {
					return
				}
				name := set["name"]
				if name != guardLeaseName(other.Allocation.ConnectionID) && name != guardReplyLeaseName(other.Allocation.ConnectionID) && name != guardSALeaseName(other.Allocation.ConnectionID) {
					return
				}
				if !zero {
					delete(set, "elem")
					return
				}
				for _, item := range set["elem"].([]any) {
					item.(map[string]any)["elem"].(map[string]any)["expires"] = float64(0)
				}
			})
			if VerifyGuardReadbackWithInterfaces([]byte(rendered.ExpectedJSON), raw, links) == nil {
				t.Fatal("global positive proof accepted expiry")
			}
			if verifyGuardConnectionReadback([]byte(rendered.ExpectedJSON), raw, links, target.Allocation.ConnectionID) != nil {
				t.Fatal("healthy GCP profile coupled to other expiry")
			}
			if verifyGuardConnectionReadback([]byte(rendered.ExpectedJSON), raw, links, other.Allocation.ConnectionID) == nil {
				t.Fatal("expired GCP profile authorized")
			}
		}
	}
}

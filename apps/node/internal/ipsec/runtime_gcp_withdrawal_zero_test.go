package ipsec

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Material/profile contracts are real; namespace, links and nft observations are
// modeled component inputs, not native kernel or cloud acceptance.
func gcpWithdrawalGuard(e RuntimeJournalEntry, base int) GuardConnection {
	g := GuardConnection{ID: e.Allocation.ConnectionID, TunnelCount: uint8(e.Allocation.activeTunnelCount()), Local: e.Engines[0].LocalPrefixes, Remote: e.Engines[0].RemotePrefixes, LocalIngressIndices: []int{2}, PermitFor: 60 * time.Second}
	if g.TunnelCount == 2 {
		g.TunnelCount = 0
	}
	for i := 0; i < e.Allocation.activeTunnelCount(); i++ {
		g.Tunnels[i] = Ownership{Namespace: e.Allocation.Namespace, InterfaceName: e.Allocation.Tunnels[i].Name, InterfaceIndex: base + i, XFRMID: e.Allocation.Tunnels[i].XFRMID}
		g.ReplyIngressIndices = append(g.ReplyIngressIndices, base+i)
	}
	g.PermittedInterfaceIndices = []int{base}
	g.EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: base, ReqID: e.Engines[0].ReqID, Peer: e.Engines[0].RemoteAddress, UnderlayInterfaceIndex: 2}}
	g.Grants = []GuardGrant{{Source: g.Local[0], Destination: g.Remote[0], Protocol: GuardTCP, PortLow: 443, PortHigh: 443}}
	return g
}
func TestGCPMixedWithdrawalZeroExpiry(t *testing.T) {
	classic := classicEntryFixture(t)
	m := gcpMaterialFixture()
	m.Manifest.ConnectionID = uuid.New()
	m.Manifest.RemotePrefixes = []string{"10.80.0.0/24"}
	runtimeReseal(&m)
	ha, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, classic.Allocation.Namespace)
	if err != nil {
		t.Fatal("HA material invalid", err)
	}
	if classic.Allocation.activeTunnelCount() != 1 || ha.Allocation.activeTunnelCount() != 2 || !reflect.DeepEqual(classic.Engines[1], EngineTunnel{}) {
		t.Fatal("invalid profile cardinality")
	}
	for _, targetClassic := range []bool{false, true} {
		for _, positive := range []bool{false, true} {
			for _, inherited := range []bool{false, true} {
				t.Run(fmt.Sprintf("classic-target-%v/nonempty-%v/inherited-%v", targetClassic, positive, inherited), func(t *testing.T) {
					cg, hg := gcpWithdrawalGuard(classic, 10), gcpWithdrawalGuard(ha, 20)
					originalClassic := cg
					target, other := ha, classic
					if targetClassic {
						target, other = classic, ha
					}
					if !positive {
						empty := GuardConnection{ID: target.Allocation.ConnectionID, PrefixOnly: true, Local: target.Engines[0].LocalPrefixes, Remote: target.Engines[0].RemotePrefixes}
						if targetClassic {
							cg = empty
						} else {
							hg = empty
						}
					}
					intent := GuardIntent{OwnerID: m.Manifest.NodeID, Namespace: classic.Allocation.Namespace, Revision: 1, Connections: []GuardConnection{cg, hg}}
					rendered, err := RenderGuard(intent)
					if err != nil {
						t.Fatal("invalid mixed table", err)
					}
					bad := intent
					bad.Connections = []GuardConnection{originalClassic}
					bad.Connections[0].Tunnels[1] = gcpWithdrawalGuard(ha, 20).Tunnels[0]
					if _, err = RenderGuard(bad); err == nil {
						t.Fatal("Classic accepted inactive second ownership")
					}
					links := []GuardInterface{{Name: classic.Allocation.Tunnels[0].Name, Index: 10}, {Name: ha.Allocation.Tunnels[0].Name, Index: 20}, {Name: ha.Allocation.Tunnels[1].Name, Index: 21}}
					raw := zeroExpiryObserved(t, rendered.ExpectedJSON, inherited, nil)
					if err = VerifyGuardWithdrawal([]byte(rendered.ExpectedJSON), raw, links); err != nil {
						t.Fatal("known other-profile expiry blocks withdrawal", err)
					}
					if VerifyGuardReadbackWithInterfaces([]byte(rendered.ExpectedJSON), raw, links) == nil {
						t.Fatal("zero expiry supplied positive authorization")
					}
					j, err := OpenRuntimeJournal(journalDir(t), m.Manifest.NodeID)
					if err != nil {
						t.Fatal(err)
					}
					defer j.Close()
					if j.prepareGuard(rendered) != nil || j.finishGuard(rendered) != nil {
						t.Fatal("template persistence")
					}
					c := &RuntimeController{journal: j, guard: &RuntimeGuard{journal: j, reader: &GuardReader{namespace: func() (string, error) { return intent.Namespace, nil }, interfaces: func() ([]GuardInterface, error) { return links, nil }, run: func(context.Context, ...string) ([]byte, error) { return raw, nil }}}}
					denied, err := c.recoveryGuardDenials(context.Background(), []RuntimeJournalEntry{target, other})
					if err != nil || denied[target.Allocation.ConnectionID] == positive || denied[other.Allocation.ConnectionID] {
						t.Fatalf("membership lost: denied=%v err=%v", denied, err)
					}
				})
			}
		}
	}
}

//go:build linux

package ipsec

import (
	"bytes"
	"context"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Component qualification in an explicitly disposable namespace: actual owned
// XFRM allocation, managed charon staging, nft readback, native FRR observation,
// cleanup/recreate and foreign-link preservation. No Azure SA/cloud claim.
func TestAzureNativeOwnedComponents(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_NATIVE_LAB") != "1" || !IsAzureRuntimeProfile(os.Getenv("TUNNEX_AZURE_NATIVE_PROFILE")) {
		t.Skip("disposable owned namespace only")
	}
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyBGPProfile, AzureActiveStandbyStaticProfile} {
		if filter := os.Getenv("TUNNEX_AZURE_NATIVE_PROFILE"); filter != "" && filter != profile {
			continue
		}
		t.Run(profile, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			m := azureMaterialFixture(profile)
			ns, err := os.Readlink("/proc/self/ns/net")
			if err != nil {
				t.Fatal(err)
			}
			e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, ns)
			if err != nil {
				t.Fatal(err)
			}
			a, err := NewKernelApplier("/sbin/ip")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = a.run(ctx, "link", "add", "azure-foreign", "type", "dummy"); err != nil {
				t.Fatal(err)
			}
			defer a.run(ctx, "link", "del", "azure-foreign")
			own, err := a.Apply(ctx, e.Allocation, [2]Ownership{})
			if err != nil {
				t.Fatal("native allocation", err)
			}
			defer a.Remove(ctx, e.Allocation, own)
			count := e.Allocation.activeTunnelCount()
			if count == 1 && own[1] != (Ownership{}) {
				t.Fatal("inactive interface allocated")
			}
			again, err := a.Apply(ctx, e.Allocation, own)
			if err != nil || again != own {
				t.Fatal("reapply", err)
			}
			daemon, err := StartDaemonProcess(ctx)
			if err != nil {
				t.Fatal("managed IKE daemon", err)
			}
			defer daemon.Close()
			for i, engine := range e.Engines[:count] {
				if daemon.Client.stageTunnel(ctx, engine, []byte(m.Secrets[i].PSK)) != nil {
					t.Fatal("owned IKE stage")
				}
			}
			inv, err := daemon.Client.Inspect(ctx)
			if err != nil || len(inv.Connections) != count || len(inv.SharedKeys) != count || len(inv.SAs) != 0 {
				t.Fatal("stage cardinality/false health", err)
			}
			g := GuardConnection{ID: e.Allocation.ConnectionID, Local: e.Engines[0].LocalPrefixes, Remote: e.Engines[0].RemotePrefixes, Tunnels: own, LocalIngressIndices: []int{1}, PermitFor: 30 * time.Second}
			if count == 1 {
				g.TunnelCount = 1
			}
			for i := 0; i < count; i++ {
				g.PermittedInterfaceIndices = append(g.PermittedInterfaceIndices, own[i].InterfaceIndex)
				g.ReplyIngressIndices = append(g.ReplyIngressIndices, own[i].InterfaceIndex)
				g.TunnelMTUs = append(g.TunnelMTUs, GuardTunnelMTU{InterfaceIndex: own[i].InterfaceIndex, MTU: 1422})
				g.EncryptedEgress = append(g.EncryptedEgress, GuardEncryptedEgress{TunnelInterfaceIndex: own[i].InterfaceIndex, ReqID: e.Engines[i].ReqID, Peer: e.Engines[i].RemoteAddress, UnderlayInterfaceIndex: 1})
				if e.Allocation.BGP {
					g.BGPPeers = append(g.BGPPeers, GuardBGPPeer{Local: e.Allocation.Tunnels[i].InsideAddress.Addr(), Remote: e.Allocation.Tunnels[i].BGP.Peer, InterfaceIndex: own[i].InterfaceIndex})
				}
			}
			g.Grants = []GuardGrant{{Source: g.Local[0], Destination: g.Remote[0], Protocol: GuardTCP, PortLow: 443, PortHigh: 443}}
			reader, err := NewGuardReader("/usr/sbin/nft")
			if err != nil {
				t.Fatal(err)
			}
			applyGuard := func(g GuardConnection, revision int64) {
				manifest, err := RenderGuard(GuardIntent{Namespace: ns, OwnerID: m.Manifest.NodeID, Revision: revision, Connections: []GuardConnection{g}})
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-f", "-")
				cmd.Stdin = bytes.NewBufferString(manifest.NFTJSON)
				if err := cmd.Run(); err != nil {
					t.Fatal("nft application", err)
				}
				if reader.Check(ctx, manifest) != nil {
					t.Fatal("native independent guard readback")
				}
			}
			applyGuard(g, 1)
			if e.Allocation.BGP {
				if _, err := a.run(ctx, "link", "add", "azure-lan", "type", "veth", "peer", "name", "azure-lan-peer"); err != nil {
					t.Fatal(err)
				}
				defer a.run(ctx, "link", "del", "azure-lan")
				for _, args := range [][]string{{"link", "set", "azure-lan", "up"}, {"link", "set", "azure-lan-peer", "up"}, {"addr", "add", "10.10.0.1/24", "dev", "azure-lan"}} {
					if _, err := a.run(ctx, args...); err != nil {
						t.Fatal(err)
					}
				}
				cfg, err := runtimeBGPProcessConfig(e)
				if err != nil {
					t.Fatal(err)
				}
				process, err := bgpengine.StartProcess(ctx, "/run/azure-bgp", cfg)
				if err != nil {
					t.Fatal("managed native FRR", err)
				}
				status, err := process.Observe(ctx)
				if err != nil {
					process.Close()
					t.Fatal("actual FRR observation", err)
				}
				for i := 0; i < count; i++ {
					if status.Peers[i].Slot != i+1 || status.Peers[i].State == "established" || status.Peers[i].AcceptedPrefixes != 0 {
						t.Fatal("missing-peer falsely healthy")
					}
				}
				if count == 1 && status.Peers[1] != (bgpengine.PeerStatus{}) {
					t.Fatal("invented second peer")
				}
				if process.Close() != nil {
					t.Fatal("owned FRR cleanup")
				}
				restart, err := bgpengine.StartProcess(ctx, "/run/azure-bgp", cfg)
				if err != nil {
					t.Fatal("FRR genuine process restart", err)
				}
				restarted, err := restart.Observe(ctx)
				if err != nil {
					restart.Close()
					t.Fatal("FRR restart observation", err)
				}
				if count == 1 && restarted.Peers[1] != (bgpengine.PeerStatus{}) {
					t.Fatal("restart invented inactive peer")
				}
				if restart.Close() != nil {
					t.Fatal("restart cleanup")
				}

			}
			applyGuard(GuardConnection{ID: g.ID, PrefixOnly: true, Local: g.Local, Remote: g.Remote}, 2)
			for _, engine := range e.Engines[:count] {
				if daemon.Client.removeTunnel(ctx, engine) != nil {
					t.Fatal("owned IKE cleanup")
				}
			}
			inv, err = daemon.Client.Inspect(ctx)
			if err != nil || len(inv.SAs) != 0 || len(inv.Connections) != 0 || len(inv.SharedKeys) != 0 {
				t.Fatal("IKE cleanup readback", err)
			}
			if _, err = a.Remove(ctx, e.Allocation, own); err != nil {
				t.Fatal("owned cleanup", err)
			}
			if _, err = a.run(ctx, "link", "show", "dev", "azure-foreign"); err != nil {
				t.Fatal("foreign link removed")
			}
			own, err = a.Apply(ctx, e.Allocation, [2]Ownership{})
			if err != nil {
				t.Fatal("owned recreate", err)
			}
			if _, err = a.Remove(ctx, e.Allocation, own); err != nil {
				t.Fatal("recreated cleanup", err)
			}
		})
	}
}

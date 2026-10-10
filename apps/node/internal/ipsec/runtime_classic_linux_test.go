//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Opt-in only: caller must supply a disposable network namespace. This proves
// actual one-link XFRM allocation/reapply/cleanup and foreign-link preservation;
// it does not claim GCP SA or application traffic qualification.
func TestClassicKernelNativeSingleTunnelLifecycle(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_CLASSIC_KERNEL_LAB") != "1" {
		t.Skip("disposable native namespace only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	a, err := NewKernelApplier("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	e := classicEntryFixture(t)
	p := e.Allocation
	p.Namespace, err = os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.run(ctx, "link", "add", "classic-foreign", "type", "dummy"); err != nil {
		t.Fatal(err)
	}
	owned, err := a.Apply(ctx, p, [2]Ownership{})
	if err != nil {
		t.Fatal("single apply", err)
	}
	if owned[0].InterfaceIndex <= 0 || owned[1] != (Ownership{}) {
		t.Fatal("fake second owned tunnel")
	}
	again, err := a.Apply(ctx, p, owned)
	if err != nil || again != owned {
		t.Fatal("reapply drift", err)
	}

	// Exercise the same single-interface spoof/grant/MSS renderer against actual
	// nftables and strict independent readback before removing owned links.
	guard := GuardConnection{TunnelCount: 1, ID: p.ConnectionID, Local: e.Engines[0].LocalPrefixes, Remote: e.Engines[0].RemotePrefixes, Tunnels: owned, LocalIngressIndices: []int{1}, PermittedInterfaceIndices: []int{owned[0].InterfaceIndex}, ReplyIngressIndices: []int{owned[0].InterfaceIndex}, PermitFor: 30 * time.Second, TunnelMTUs: []GuardTunnelMTU{{InterfaceIndex: owned[0].InterfaceIndex, MTU: 1382}}, EncryptedEgress: []GuardEncryptedEgress{{TunnelInterfaceIndex: owned[0].InterfaceIndex, ReqID: e.Engines[0].ReqID, Peer: e.Engines[0].RemoteAddress, UnderlayInterfaceIndex: 1}}, Grants: []GuardGrant{{Source: e.Engines[0].LocalPrefixes[0], Destination: e.Engines[0].RemotePrefixes[0], Protocol: GuardTCP, PortLow: 443, PortHigh: 443}}}
	reader, err := NewGuardReader("/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	applyGuard := func(g GuardConnection, revision int64) {
		t.Helper()
		manifest, err := RenderGuard(GuardIntent{Namespace: p.Namespace, OwnerID: e.Engines[0].Binding.GatewayID, Revision: revision, Connections: []GuardConnection{g}})
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-f", "-")
		command.Stdin = bytes.NewBufferString(manifest.NFTJSON)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("native single guard: %v %s", err, output)
		}
		if err = reader.Check(ctx, manifest); err != nil {
			t.Fatal("native single guard readback", err)
		}
	}
	applyGuard(guard, 1)
	applyGuard(GuardConnection{ID: p.ConnectionID, PrefixOnly: true, Local: guard.Local, Remote: guard.Remote}, 2)

	absent, err := a.Remove(ctx, p, owned)
	if err != nil || absent.TunnelIDs[1] != ([16]byte{}) {
		t.Fatal("single cleanup", err)
	}
	if _, err = a.run(ctx, "link", "show", "dev", "classic-foreign"); err != nil {
		t.Fatal("foreign object removed")
	}
	recreated, err := a.Apply(ctx, p, [2]Ownership{})
	if err != nil || recreated[0].InterfaceIndex <= 0 || recreated[1] != (Ownership{}) {
		t.Fatal("recreate", err)
	}
	if _, err = a.Remove(ctx, p, recreated); err != nil {
		t.Fatal("recreate cleanup", err)
	}
}

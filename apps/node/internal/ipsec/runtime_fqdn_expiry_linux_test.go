//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"testing"
	"time"
)

// Native timed-set/readback component only, not encrypted packet or CP proof.
// Run only in the disconnected disposable two-XFRM guard harness, never a
// customer gateway namespace. It refuses every existing table before writes.
func TestGuardFQDNV2ExpiryNativeReadback(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_FQDN_EXPIRY_LAB") != "1" {
		t.Skip("disconnected owned guard component harness only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	run := func(input string, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "/usr/sbin/nft", args...)
		cmd.Stdin = bytes.NewBufferString(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal("owned nft component command refused", err)
		}
		return out
	}
	if bytes.Contains(run("", "-j", "list", "tables"), []byte(`"table"`)) {
		t.Fatal("foreign table present")
	}
	kernel, err := NewKernelReader("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := kernel.Read(ctx)
	if err != nil || len(inv.Links) != 2 {
		t.Fatal("expected two actual harness XFRM interfaces", err)
	}
	in := guardFixture()
	in.Namespace = inv.Namespace
	c := &in.Connections[0]
	for slot, k := range inv.Links {
		c.Tunnels[slot] = Ownership{Namespace: inv.Namespace, InterfaceName: k.Name, InterfaceIndex: k.Index, XFRMID: k.XFRMID}
	}
	c.LocalIngressIndices = []int{1}
	c.PermittedInterfaceIndices = []int{inv.Links[0].Index}
	c.ReplyIngressIndices = []int{inv.Links[0].Index}
	c.PermitFor = 20 * time.Second
	// The reqid set is a renderer/readback fixture, not an observed native SA.
	c.EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: inv.Links[0].Index, ReqID: 12345, Peer: netip.MustParseAddr("192.0.2.1"), UnderlayInterfaceIndex: 1}}
	_, g, _ := v2FQDNFixture(t)
	g.FQDN.SelectedGatewayID = in.OwnerID
	g.FQDN.ConnectionID = c.ID
	g.FQDNPermitFor = 3 * time.Second
	c.Grants = append(c.Grants, g)
	m, err := RenderGuard(in)
	if err != nil {
		t.Fatal(err)
	}
	run(m.NFTJSON, "-j", "-f", "-")
	t.Cleanup(func() { exec.Command("/usr/sbin/nft", "delete", "table", "inet", "tunnex_ipsec").Run() })
	inventory := func() []GuardInterface {
		t.Helper()
		actual, err := net.Interfaces()
		if err != nil {
			t.Fatal("actual interface census refused")
		}
		var result []GuardInterface
		loopback := false
		for _, link := range actual {
			if link.Name == "lo" && link.Index == 1 && link.Flags&net.FlagLoopback != 0 && link.Flags&net.FlagUp != 0 {
				loopback = true
			}
			result = append(result, GuardInterface{Name: link.Name, Index: link.Index})
		}
		if !loopback {
			t.Fatal("expected actual UP loopback index one")
		}
		for _, xfrm := range inv.Links {
			found := false
			for _, link := range result {
				found = found || link.Name == xfrm.Name && link.Index == xfrm.Index
			}
			if !found {
				t.Fatal("actual XFRM interface identity absent")
			}
		}
		sort.Slice(result, func(i, j int) bool { return result[i].Index < result[j].Index })
		return result
	}
	links := inventory()
	read := func() []byte {
		t.Helper()
		if !reflect.DeepEqual(links, inventory()) {
			t.Fatal("interface census changed before read")
		}
		actual := run("", "-j", "list", "table", "inet", "tunnex_ipsec")
		if !reflect.DeepEqual(links, inventory()) {
			t.Fatal("interface census changed after read")
		}
		return actual
	}
	actual := read()
	if VerifyGuardReadbackWithInterfaces([]byte(m.ExpectedJSON), actual, links) != nil {
		t.Fatal("native timed IPv4 member/readback mismatch")
	}
	time.Sleep(3200 * time.Millisecond)
	actual = read()
	if VerifyGuardReadbackWithInterfaces([]byte(m.ExpectedJSON), actual, links) == nil {
		t.Fatal("expired application member accepted as positive")
	}
	if VerifyGuardWithdrawal([]byte(m.ExpectedJSON), actual, links) != nil {
		t.Fatal("expired application member lost exact whole-table ownership")
	}
	if verifyGuardConnectionReadback([]byte(m.ExpectedJSON), actual, links, c.ID) != nil {
		t.Fatal("application expiry withdrew independent connection lease sets")
	}
	c.Grants = c.Grants[:len(c.Grants)-1]
	in.Revision++
	next, err := RenderGuard(in)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := replaceOwnedFQDNSets(next.NFTJSON, m.ExpectedJSON)
	if err != nil {
		t.Fatal(err)
	}
	run(tx, "-j", "-f", "-")
	actual = read()
	if VerifyGuardReadbackWithInterfaces([]byte(next.ExpectedJSON), actual, links) != nil {
		t.Fatal("expired-set turnover changed ordinary table")
	}
}

//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// Native timed-set/readback component only, not encrypted packet or CP proof.
// Run only in the disconnected disposable two-XFRM guard harness, never a
// customer gateway namespace. It refuses every existing table before writes.
func TestGuardFQDNV2ExpiryNativeReadback(t *testing.T) {
	testGuardFQDNExpiryNativeReadback(t, false)
}

func TestGuardDesktopStaticFQDNExpiryNativeReadback(t *testing.T) {
	testGuardFQDNExpiryNativeReadback(t, true)
}

func testGuardFQDNExpiryNativeReadback(t *testing.T, desktop bool) {
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
	wireMaterial, g, _ := v2FQDNFixture(t)
	if desktop {
		wireMaterial, g, _ = desktopStaticFQDNFixture(t)
		// Actual loopback is the disposable test ingress, never an enrolled peer.
		// This component qualifies renderer/expiry/readback; runtime peer proof is separate.
		g.DesktopIngressIndex = 1
	}
	g.FQDN.SelectedGatewayID = in.OwnerID
	g.FQDN.ConnectionID = c.ID
	c.Grants = append(c.Grants, g)
	// Exercise the real wire-descriptor -> issued finite permit -> guard digest
	// bridge. Directly setting FQDNPermitFor would hide lost desktop provenance.
	wire := wireMaterial.Policy.FQDNGrants[0]
	wire.SelectedGatewayID, wire.ConnectionID = in.OwnerID.String(), c.ID.String()
	key := runtimeFQDNGrantDigest(wire)
	authority := NewPermitLeaseAuthority()
	identity := permitIdentity()
	request, err := authority.BeginFQDN(identity, []string{key})
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 20000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: key, TTLMS: 5000}}}); err != nil {
		t.Fatal(err)
	}
	// One-second component commit budget keeps this disconnected test finite;
	// the production controller retains its unchanged five-second budget.
	in = limitFQDNGuardIntent(in, time.Now(), time.Second, func(_ uuid.UUID, g GuardGrant, budget time.Duration) (time.Duration, error) {
		return authority.RemainingFQDNForApply(identity, guardFQDNGrantDigest(g), budget)
	})
	c = &in.Connections[0]
	if len(c.Grants) == 0 || !c.Grants[len(c.Grants)-1].FQDNManaged {
		t.Fatal("issued desktop permit lost its native timed member")
	}
	g = c.Grants[len(c.Grants)-1]
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
	if desktop {
		oldSet := guardFQDNSetName(g)
		g.Destination = netip.MustParsePrefix("10.20.0.10/32")
		g.FQDN.Generation = strings.Repeat("b", 64)
		c.Grants[len(c.Grants)-1] = g
		in.Revision++
		replacement, err := RenderGuard(in)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := replaceOwnedFQDNSets(replacement.NFTJSON, m.ExpectedJSON)
		if err != nil {
			t.Fatal(err)
		}
		run(tx, "-j", "-f", "-")
		actual = read()
		if VerifyGuardReadbackWithInterfaces([]byte(replacement.ExpectedJSON), actual, links) != nil || bytes.Contains(actual, []byte(oldSet)) {
			t.Fatal("generation switch retained old answer authority")
		}
		m = replacement
	}
	time.Sleep(g.FQDNPermitFor + 200*time.Millisecond)
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

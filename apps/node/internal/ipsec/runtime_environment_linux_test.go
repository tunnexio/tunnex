//go:build linux

package ipsec

import (
	"context"
	conntrack "github.com/florianl/go-conntrack"
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestRuntimeEnvironmentConntrackExactScope(t *testing.T) {
	entry := journalFixture()
	local := entry.Engines[0].LocalPrefixes[0].Addr().Next()
	remote := entry.Engines[0].RemotePrefixes[0].Addr().Next()
	for _, tc := range []struct {
		src, dst string
		want     bool
	}{{local.String(), remote.String(), true}, {remote.String(), local.String(), true}, {"8.8.8.8", remote.String(), false}, {local.String(), "8.8.8.8", false}} {
		src, dst := net.ParseIP(tc.src), net.ParseIP(tc.dst)
		flow := conntrack.Con{Origin: &conntrack.IPTuple{Src: &src, Dst: &dst}}
		got, valid := runtimeConntrackMatch(flow, []RuntimeJournalEntry{entry})
		if !valid || got != tc.want {
			t.Fatal("conntrack scope mismatch")
		}
	}
	if _, valid := runtimeConntrackMatch(conntrack.Con{}, []RuntimeJournalEntry{entry}); valid {
		t.Fatal("malformed inventory accepted")
	}
}

// Explicitly gated read-only qualification inside a captured disposable lab.
func TestRuntimeEnvironmentNativeObservation(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_ENV_LAB") != "1" {
		t.Skip("owned native lab only")
	}
	ns, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	prefix, e := netip.ParsePrefix(os.Getenv("TUNNEX_IPSEC_ENV_LOCAL"))
	if e != nil {
		t.Fatal("missing synthetic LAN prefix")
	}
	peer, e := netip.ParseAddr(os.Getenv("TUNNEX_IPSEC_ENV_PEER"))
	if e != nil {
		t.Fatal("missing synthetic peer")
	}
	entry := journalFixture()
	entry.Allocation.Namespace = ns
	for i := range entry.Engines {
		entry.Engines[i].LocalPrefixes = []netip.Prefix{prefix}
		entry.Engines[i].RemoteAddress = peer
	}
	inspector, e := NewRuntimeEnvironmentInspector("/sbin/ip", "/usr/sbin/nft")
	if e != nil {
		t.Fatal(e)
	}
	observed, e := inspector.Observe(context.Background(), entry.Allocation, entry.Engines)
	if e != nil {
		t.Fatal(e)
	}
	if observed.Namespace != ns || len(observed.LocalIngressIndices) == 0 || observed.Underlays[0].InterfaceIndex <= 0 || !observed.Underlays[0].LocalAddress.Is4() {
		t.Fatal("native observation incomplete")
	}
}

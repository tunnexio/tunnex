//go:build linux

package ipsec

import (
	"context"
	"net/netip"
	"os"
	"testing"
)

// This test performs reads only. A separately guarded container harness owns
// fixture setup; never create interfaces/routes in the test runner's namespace.
func TestKernelReaderLinuxFixture(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_KERNEL_LAB") != "1" {
		t.Skip("requires isolated kernel-readback fixture")
	}
	r, err := NewKernelReader("/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := r.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Links) != 2 || len(inventory.Routes) != 2 {
		t.Fatalf("unexpected isolated inventory: %+v", inventory)
	}
	for i, name := range []string{"tnx-test-a", "tnx-test-b"} {
		found := false
		for _, link := range inventory.Links {
			if link.Name == name {
				if link.XFRMID != uint32(701+i) || !link.Up {
					t.Fatalf("incorrect link facts: %+v", link)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("missing expected test interface")
		}
	}
	for i, prefix := range []string{"198.18.10.0/24", "198.18.11.0/24"} {
		found := false
		for _, route := range inventory.Routes {
			if route.Destination == netip.MustParsePrefix(prefix) {
				if route.Table != uint32(220+i) || route.Protocol != 99 || route.Metric != 10 || route.Scope != 253 {
					t.Fatalf("incorrect route facts: %+v", route)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("missing expected test route")
		}
	}
	t.Logf("Read two XFRM links and two route tuples in %s; this is not traffic or ownership proof", inventory.Namespace)
}

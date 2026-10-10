//go:build linux

package ipsec

import (
	"context"
	"os"
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

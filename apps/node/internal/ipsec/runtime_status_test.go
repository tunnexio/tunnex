package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestRuntimeTunnelStatusIndependentEvidence(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	got := runtimeTunnelStatuses(e, d, k, x)
	if got != [2]string{"up", "up"} {
		t.Fatal("valid observed tunnels not up", got)
	}
	d.SAs = d.SAs[1:]
	got = runtimeTunnelStatuses(e, d, k, x)
	if got != [2]string{"down", "up"} {
		t.Fatal("one absent IKE affected other tunnel", got)
	}
	e, d, k, x = runtimeProofFixture()
	d.SAs[0].Children[0].Installed = false
	got = runtimeTunnelStatuses(e, d, k, x)
	if got != [2]string{"down", "up"} {
		t.Fatal("uninstalled CHILD fabricated up", got)
	}
	e, d, k, x = runtimeProofFixture()
	x.States[0].SPI++
	got = runtimeTunnelStatuses(e, d, k, x)
	if got != [2]string{"unknown", "up"} {
		t.Fatal("mismatched independent SPI accepted", got)
	}
	e, d, k, x = runtimeProofFixture()
	d.SAs = append(d.SAs, d.SAs[0])
	got = runtimeTunnelStatuses(e, d, k, x)
	if got[0] != "unknown" {
		t.Fatal("ambiguous rekey accepted", got)
	}
	e, d, k, x = runtimeProofFixture()
	k.Links[0].Up = false
	got = runtimeTunnelStatuses(e, d, k, x)
	if got != [2]string{"down", "up"} {
		t.Fatal("interface down ignored", got)
	}
}
func TestRuntimeTunnelStatusReadFailureIsUnknown(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	e.Phase = RuntimeApplied
	readers := runtimeStatusReaders{daemon: func(context.Context) (DaemonInventory, error) { return d, nil }, kernel: func(context.Context) (KernelInventory, error) { return k, nil }, xfrm: func(context.Context) (XFRMInventory, error) { return x, errors.New("synthetic private failure") }, alive: func() bool { return true }}
	if got := runtimeObservedStatuses(context.Background(), e, readers); got != [2]string{"unknown", "unknown"} {
		t.Fatal("Applied inferred up after failed read", got)
	}
}

func TestRuntimeTunnelStatusWrongOwnershipAndPartialInventory(t *testing.T) {
	cases := map[string]func(*DaemonInventory, *KernelInventory, *XFRMInventory){
		"foreign reqid":     func(_ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) { x.States[0].ReqID++ },
		"foreign interface": func(_ *DaemonInventory, k *KernelInventory, _ *XFRMInventory) { k.Links[0].Index += 100 },
		"expanded policy": func(_ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) {
			x.Policies[0].Source = netip.MustParsePrefix("0.0.0.0/0")
		},
		"wrong template spi": func(_ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) { x.Policies[0].TemplateSPI = 123456 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e, d, k, x := runtimeProofFixture()
			mutate(&d, &k, &x)
			if got := runtimeTunnelStatuses(e, d, k, x); got != [2]string{"unknown", "up"} {
				t.Fatal("foreign evidence accepted or unrelated tunnel changed", got)
			}
		})
	}
	e, d, k, x := runtimeProofFixture()
	calls := 0
	r := runtimeStatusReaders{daemon: func(context.Context) (DaemonInventory, error) { return d, nil }, kernel: func(context.Context) (KernelInventory, error) { return k, nil }, xfrm: func(context.Context) (XFRMInventory, error) {
		calls++
		if calls == 2 {
			return XFRMInventory{Namespace: x.Namespace}, nil
		}
		return x, nil
	}, alive: func() bool { return true }}
	if got := runtimeObservedStatuses(context.Background(), e, r); got != [2]string{"unknown", "unknown"} {
		t.Fatal("changing inventory reported definite status", got)
	}
}

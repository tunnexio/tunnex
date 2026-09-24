package ipsec

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"net/netip"
	"testing"
)

func kernelPlanFixture() KernelAllocation {
	p := KernelAllocation{Namespace: "net:[42]", Generation: uuid.New(), ConnectionID: uuid.New()}
	for i := range p.Tunnels {
		id := uuid.New()
		p.Tunnels[i] = KernelTunnelAllocation{TunnelID: id, Slot: uint8(i + 1), Name: KernelTunnelName(id), XFRMID: KernelTunnelID(id), InsideAddress: netip.MustParsePrefix([]string{"169.254.10.1/30", "169.254.10.5/30"}[i]), RemotePrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, Selected: i == 0}
		p.Tunnels[i].Alias = KernelTunnelAlias(p.Generation, id)
	}
	return p
}
func TestKernelAllocationRefusesAmbiguousOwnership(t *testing.T) {
	p := kernelPlanFixture()
	if !validKernelAllocation(p) {
		t.Fatal("valid plan refused")
	}
	cases := []func(*KernelAllocation){func(p *KernelAllocation) { p.Tunnels[1].XFRMID = p.Tunnels[0].XFRMID }, func(p *KernelAllocation) { p.Tunnels[0].Alias = "foreign" }, func(p *KernelAllocation) { p.Namespace = "host" }, func(p *KernelAllocation) { p.Tunnels[0].InsideAddress = netip.MustParsePrefix("10.0.0.1/24") }, func(p *KernelAllocation) {
		p.Tunnels[0].RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.20.1.0/16")}
	}, func(p *KernelAllocation) { p.Tunnels[1].Selected = true }}
	for i, fn := range cases {
		q := kernelPlanFixture()
		fn(&q)
		if validKernelAllocation(q) {
			t.Fatalf("case%d accepted", i)
		}
	}
}
func TestKernelApplyRefusesBeforeMutation(t *testing.T) {
	p := kernelPlanFixture()
	calls := 0
	a := &KernelApplier{namespace: func() (string, error) { return "net:[43]", nil }, run: func(context.Context, ...string) ([]byte, error) { calls++; return nil, errors.New("synthetic") }}
	if _, err := a.Apply(context.Background(), p, [2]Ownership{}); err == nil || calls != 0 {
		t.Fatal("namespace drift executed command")
	}
	p.Namespace = "net:[43]"
	p.Tunnels[0].Alias = "foreign"
	if _, err := a.Apply(context.Background(), p, [2]Ownership{}); err == nil || calls != 0 {
		t.Fatal("invalid plan executed command")
	}
}
func TestKernelApplyForeignNameRefusesWithoutMutation(t *testing.T) {
	p := kernelPlanFixture()
	mutations := 0
	a := &KernelApplier{namespace: func() (string, error) { return p.Namespace, nil }, run: func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) > 3 && args[0] == "-j" && args[2] == "link" {
			return []byte(`[{"ifindex":9,"ifname":"` + p.Tunnels[0].Name + `","flags":[],"ifalias":"foreign","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":"` + fmt.Sprintf("0x%x", p.Tunnels[0].XFRMID) + `"}}}]`), nil
		}
		if len(args) > 0 && args[0] == "-j" {
			return []byte(`[]`), nil
		}
		mutations++
		return nil, nil
	}}
	if _, err := a.Apply(context.Background(), p, [2]Ownership{}); err == nil {
		t.Fatal("foreign name accepted")
	}
	if mutations != 0 {
		t.Fatal("mutated before collision refusal")
	}
}

package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

type recoveryKernelFixture struct {
	p                  KernelAllocation
	owned              [2]Ownership
	routes             [2]map[string]bool
	missing            int
	deleted            [2]bool
	sa                 bool
	down               int
	badMetric, foreign bool
	mutations, failAt  int
}

func newRecoveryKernelFixture() *recoveryKernelFixture {
	f := &recoveryKernelFixture{p: kernelPlanFixture(), missing: -1, down: -1}
	for i := range f.p.Tunnels {
		f.p.Tunnels[i].RemotePrefixes = append(f.p.Tunnels[i].RemotePrefixes, netip.MustParsePrefix("10.30.0.0/16"))
		t := f.p.Tunnels[i]
		f.owned[i] = Ownership{Namespace: f.p.Namespace, InterfaceName: t.Name, InterfaceIndex: 10 + i, XFRMID: t.XFRMID}
		f.routes[i] = map[string]bool{}
	}
	for _, p := range f.p.Tunnels[0].RemotePrefixes {
		f.routes[0][p.String()] = true
	}
	return f
}
func (f *recoveryKernelFixture) applier() *KernelApplier {
	return &KernelApplier{namespace: func() (string, error) { return f.p.Namespace, nil }, run: f.run}
}
func (f *recoveryKernelFixture) run(_ context.Context, args ...string) ([]byte, error) {
	q := strings.Join(args, " ")
	var out []map[string]any
	if q == "xfrm state list nokeys" {
		if f.sa {
			return []byte(strings.Replace(xfrmStateFixture, "0x29", fmt.Sprintf("0x%x", f.p.Tunnels[0].XFRMID), 1)), nil
		}
		return nil, nil
	} else if q == "xfrm policy list nosock" {
		return nil, nil
	} else if strings.Contains(q, "link show") {
		for i, t := range f.p.Tunnels {
			if i == f.missing || f.deleted[i] {
				continue
			}
			flags := []string{"UP"}
			if f.down == i {
				flags = []string{}
			}
			out = append(out, map[string]any{"ifname": t.Name, "ifindex": 10 + i, "ifalias": t.Alias, "flags": flags, "linkinfo": map[string]any{"info_kind": "xfrm", "info_data": map[string]any{"if_id": fmt.Sprintf("0x%x", t.XFRMID)}}})
		}
	} else if strings.Contains(q, "addr show") {
		for i, t := range f.p.Tunnels {
			if i == f.missing || f.deleted[i] {
				continue
			}
			out = append(out, map[string]any{"ifname": t.Name, "ifindex": 10 + i, "addr_info": []map[string]any{{"family": "inet", "local": t.InsideAddress.Addr().String(), "prefixlen": 30}}})
		}
	} else if strings.Contains(q, "-4 route show") {
		for i, t := range f.p.Tunnels {
			for p := range f.routes[i] {
				metric := 50001 + i
				if f.badMetric {
					metric++
				}
				routeFlags := []string{}
				if f.down == i {
					routeFlags = []string{"linkdown"}
				}
				out = append(out, map[string]any{"flags": routeFlags, "dst": p, "dev": t.Name, "table": "254", "protocol": "242", "type": "1", "scope": "253", "metric": metric})
			}
		}
		if f.foreign {
			out = append(out, map[string]any{"dst": "10.20.0.0/16", "dev": "foreign"})
		}
	} else if strings.HasPrefix(q, "-j") {
		return []byte(`[]`), nil
	} else {
		f.mutations++
		if f.failAt == f.mutations {
			return nil, errors.New("injected")
		}
		if len(args) == 4 && args[0] == "link" && args[1] == "delete" && args[2] == "dev" {
			for i, t := range f.p.Tunnels {
				if t.Name == args[3] {
					f.deleted[i] = true
					return nil, nil
				}
			}
		}
		if len(args) == 12 && args[0] == "-4" && args[1] == "route" {
			for i, t := range f.p.Tunnels {
				if args[5] == t.Name {
					if args[2] == "del" {
						delete(f.routes[i], args[3])
					} else if args[2] == "add" {
						f.routes[i][args[3]] = true
					}
					return nil, nil
				}
			}
		}
		return nil, fmt.Errorf("unexpected mutation %s", q)
	}
	if out == nil {
		return []byte(`[]`), nil
	}
	return json.Marshal(out)
}
func TestKernelRecoverySelectionAndPartialRetry(t *testing.T) {
	for _, failAt := range []int{0, 1, 2, 3, 4} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			f := newRecoveryKernelFixture()
			f.failAt = failAt
			a := f.applier()
			err := a.ReconcileSelection(context.Background(), f.p, f.owned, 2)
			if failAt > 0 && err == nil {
				t.Fatal("injected error ignored")
			}
			f.failAt = 0
			if err = a.ReconcileSelection(context.Background(), f.p, f.owned, 2); err != nil {
				t.Fatal(err)
			}
			if len(f.routes[0]) != 0 || len(f.routes[1]) != 2 {
				t.Fatal("partial route selection")
			}
			before := f.mutations
			if err = a.ReconcileSelection(context.Background(), f.p, f.owned, 2); err != nil || before != f.mutations {
				t.Fatal("nonidempotent")
			}
		})
	}
}
func TestKernelRecoveryRejectsUnsafeInventory(t *testing.T) {
	for _, kind := range []string{"missing", "metric", "foreign", "ownership", "target"} {
		t.Run(kind, func(t *testing.T) {
			f := newRecoveryKernelFixture()
			target := uint8(2)
			switch kind {
			case "missing":
				f.missing = 1
			case "metric":
				f.badMetric = true
			case "foreign":
				f.foreign = true
			case "ownership":
				f.owned[0].InterfaceIndex++
			case "target":
				target = 3
			}
			if err := f.applier().ReconcileSelection(context.Background(), f.p, f.owned, target); err == nil || f.mutations != 0 {
				t.Fatal("unsafe inventory mutated")
			}
		})
	}
}

func TestKernelRecoveryRemoveEitherSlotAndSARefusal(t *testing.T) {
	for _, sa := range []bool{false, true} {
		t.Run(fmt.Sprint(sa), func(t *testing.T) {
			f := newRecoveryKernelFixture()
			f.sa = sa
			f.routes[1]["10.20.0.0/16"] = true
			a := f.applier()
			err := a.RemoveRecovery(context.Background(), f.p, f.owned)
			if sa {
				if err == nil || f.mutations != 0 {
					t.Fatal("SA present allowed cleanup")
				}
				return
			}
			if err != nil || !f.deleted[0] || !f.deleted[1] || len(f.routes[0])+len(f.routes[1]) != 0 {
				t.Fatal("cleanup incomplete", err)
			}
			if err = a.RemoveRecovery(context.Background(), f.p, f.owned); err != nil {
				t.Fatal("repeat cleanup refused", err)
			}
		})
	}
}
func TestKernelRecoveryAllowsDownSourceRefusesDownTarget(t *testing.T) {
	for _, down := range []int{0, 1} {
		f := newRecoveryKernelFixture()
		f.down = down
		err := f.applier().ReconcileSelection(context.Background(), f.p, f.owned, 2)
		if down == 0 && err != nil {
			t.Fatal("down source prevented switch", err)
		}
		if down == 1 && (err == nil || f.mutations != 0) {
			t.Fatal("down target accepted")
		}
	}
}

package ipsec

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
)

func TestAWSUnderlayPaddingCeiling(t *testing.T) {
	for _, x := range []struct{ outer, inner uint32 }{{1500, 1422}, {1300, 1230}, {1299, 1214}, {1298, 1214}, {1301, 1230}, {9001, 1422}, {148, 78}} {
		got, ok := awsIPv4InnerMTU(x.outer)
		if !ok || got != x.inner {
			t.Fatalf("outer%d =>%d/%v want%d", x.outer, got, ok, x.inner)
		}
		outerBytes := uint32(68) + ((got+2+15)/16)*16
		if outerBytes > x.outer {
			t.Fatal("AES padding exceeds physical ceiling")
		}
	}
	for _, v := range []uint32{0, 67, 68, 147, 65536} {
		if _, ok := awsIPv4InnerMTU(v); ok {
			t.Fatalf("invalid%d accepted", v)
		}
	}
}
func TestRuntimeOuterMTUStrictReadback(t *testing.T) {
	for _, x := range []struct {
		raw  string
		want uint32
		ok   bool
	}{{`{}`, 1500, true}, {`{"metrics":[{"mtu":1300}]}`, 1300, true}, {`{"cache":[{"expires":120,"mtu":1200}]}`, 1200, true}, {`{"metrics":[{"mtu":9001}]}`, 1500, true}, {`{"metrics":{"mtu":1300}}`, 0, false}, {`{"metrics":[{"mtu":"1300"}]}`, 0, false}, {`{"cache":[{"mtu":1300,"mystery":1}]}`, 0, false}, {`{"metrics":[{},{}]}`, 0, false}, {`{"mtu":0}`, 0, false}, {`{"cache":null}`, 0, false}} {
		var row map[string]json.RawMessage
		_ = json.Unmarshal([]byte(x.raw), &row)
		got, ok := runtimeOuterMTU(1500, row)
		if got != x.want || ok != x.ok {
			t.Fatalf("%s=>%d/%v", x.raw, got, ok)
		}
	}
}
func TestKernelUnderlayMTULowersOnlyExactOwned(t *testing.T) {
	for _, scenario := range []string{"lower", "smaller", "foreign", "failure", "readback", "denial", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRecoveryKernelFixture()
			a := f.applier()
			oldRun := a.run
			mutations := 0
			if scenario == "smaller" {
				f.mtu[0] = 1100
			}
			previous := f.owned
			if scenario == "foreign" {
				previous[0].InterfaceIndex++
			}
			a.run = func(ctx context.Context, args ...string) ([]byte, error) {
				if len(args) == 6 && args[0] == "link" && args[1] == "set" && args[4] == "mtu" {
					mutations++
					if scenario == "failure" {
						return nil, ErrKernelApply
					}
					for i, tun := range f.p.Tunnels {
						if tun.Name == args[3] && scenario != "readback" {
							value, _ := strconv.ParseUint(args[5], 10, 64)
							f.mtu[i] = value
						}
					}
					if scenario == "replacement" && mutations == 1 {
						f.owned[1].InterfaceIndex++
					}
					return nil, nil
				}
				return oldRun(ctx, args...)
			}
			verify := func(context.Context) error {
				if scenario == "denial" {
					return ErrRuntimeController
				}
				return nil
			}
			outer := [2]uint32{1300, 1500}
			if scenario == "replacement" {
				outer[1] = 1300
			}
			err := a.LowerTunnelMTUs(context.Background(), f.p, previous, outer, nil, verify)
			if scenario == "foreign" || scenario == "failure" || scenario == "readback" || scenario == "denial" || scenario == "replacement" {
				if err == nil {
					t.Fatal("refusal missing")
				}
				if (scenario == "foreign" || scenario == "denial") && mutations != 0 {
					t.Fatal("foreign mutated")
				}
				if scenario == "replacement" && mutations != 1 {
					t.Fatal("replacement second interface mutated")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(1230)
			if scenario == "smaller" {
				want = 1100
			}
			if f.mtu[0] != want || f.mtu[1] != 1422 {
				t.Fatal("wrong owned lowering")
			}
			if err = a.LowerTunnelMTUs(context.Background(), f.p, previous, [2]uint32{1500, 1500}, nil, func(context.Context) error { return nil }); err != nil || f.mtu[0] != want {
				t.Fatal("restoration raised existing smaller MTU")
			}
		})
	}
}

//go:build linux

package k8snetprep

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// See observed_calico_test.go: the Calico rules here are modelled on Calico's
// documented masquerade rule, not captured from a live node.

type calicoTestKernel struct {
	*awsTestKernel
	sets     map[string]string
	setErr   error
	onIPSet  func()
	setReads []string
}

func (f *calicoTestKernel) ipset(_ context.Context, args ...string) (string, error) {
	f.commands = append(f.commands, "ipset "+strings.Join(args, " "))
	if len(args) != 2 || args[0] != "save" {
		return "", errors.New("unexpected ipset command")
	}
	f.setReads = append(f.setReads, args[1])
	if f.onIPSet != nil {
		f.onIPSet()
	}
	if f.setErr != nil {
		return "", f.setErr
	}
	out, ok := f.sets[args[1]]
	if !ok {
		return "", errors.New("exit status 1: The set with the given name does not exist")
	}
	return out, nil
}

func newCalicoTestKernel(t *testing.T, nft map[string][]string, save string) (*calicoTestKernel, *Reconciler) {
	t.Helper()
	f := &calicoTestKernel{
		awsTestKernel: &awsTestKernel{save: save, version: "iptables-nft-save v1.8.10 (nf_tables)", next: 100},
		sets: map[string]string{
			calicoMasq: "create " + calicoMasq + " hash:net family inet hashsize 1024 maxelem 1048576 bucketsize 12 initval 0x1\nadd " + calicoMasq + " 192.168.0.0/16\n",
		},
	}
	f.doc.NFTables = []map[string]json.RawMessage{}
	handle := uint64(0)
	// Listing order is chain order, as nft prints one table.
	for _, name := range []string{"POSTROUTING", "KUBE-POSTROUTING", "cali-POSTROUTING", "cali-nat-outgoing"} {
		handle++
		chain := nftChainView{Family: "ip", Table: "nat", Name: name, Handle: handle}
		if name == "POSTROUTING" {
			chain.Type, chain.Hook, chain.Priority, chain.Policy = "nat", "postrouting", 100, "accept"
		}
		f.doc.NFTables = append(f.doc.NFTables, rawEntry("chain", chain))
	}
	for _, name := range []string{"POSTROUTING", "KUBE-POSTROUTING", "cali-POSTROUTING", "cali-nat-outgoing"} {
		for _, line := range nft[name] {
			var expr []map[string]any
			if err := json.Unmarshal([]byte(line), &expr); err != nil {
				t.Fatal(err)
			}
			f.addRule(nftRuleView{Family: "ip", Table: "nat", Chain: name, Expr: expr}, false)
		}
	}
	r := awsTestReconciler(t, f.awsTestKernel, ScopeIPMasqAndAWS)
	r.runIPSet = f.ipset
	return f, r
}

func TestCalicoNodeIsReadyAsObservedAndNamesItsPool(t *testing.T) {
	f, r := newCalicoTestKernel(t, calicoNFT(), calicoSave(calicoOutgoing(calicoMasqOK)))
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	if err != nil {
		t.Fatalf("Calico node was refused: %+v %v", status, err)
	}
	adapter := status.Adapters[0]
	want := ReasonObservedNoTunnelSourceNAT + "; masquerade sources are limited by sets outside it: " + calicoMasq
	if adapter.Name != ObservedAdapterName || adapter.State != StateReady || adapter.Reason != want {
		t.Fatalf("adapter = %+v", adapter)
	}
	if len(f.mutations) != 0 {
		t.Fatalf("observed proof mutated: %v", f.mutations)
	}
	// Only the set that carries the proof is read, and every reading of the
	// saved text and the set lies between two nft listings.
	for _, name := range f.setReads {
		if name != calicoMasq {
			t.Fatalf("read set %s", name)
		}
	}
	if len(f.setReads) == 0 {
		t.Fatal("no set was read")
	}
	listing := "nft -j -a list ruleset"
	if f.commands[0] != listing || f.commands[len(f.commands)-1] != listing {
		t.Fatalf("observation is not bracketed by listings: %v", f.commands)
	}
	for i, command := range f.commands {
		if strings.HasPrefix(command, "ipset ") && (f.commands[i-1] == listing || !strings.Contains(strings.Join(f.commands[i:], "\n"), listing)) {
			t.Fatalf("set read outside a bracketed observation: %v", f.commands)
		}
	}
}

func TestCalicoNodeRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		save   string
		tunnel string
		mutate func(*calicoTestKernel)
		want   string
	}{
		"pool overlaps the device range": {tunnel: "192.168.44.0/24", want: "set " + calicoMasq + ", which overlaps the tunnel range 192.168.44.0/24"},
		"negated source match": {
			save: calicoSave(calicoOutgoing("-m set ! --match-set " + calicoMasq + " src -m set ! --match-set " + calicoAll + " dst")),
			want: "can rewrite the source",
		},
		"destination-only match": {
			save: calicoSave(calicoOutgoing("-m set --match-set " + calicoMasq + " dst -m set ! --match-set " + calicoAll + " dst")),
			want: "can rewrite the source",
		},
		"unknown set type": {
			mutate: func(f *calicoTestKernel) {
				f.sets[calicoMasq] = "create " + calicoMasq + " hash:net,port family inet\nadd " + calicoMasq + " 192.168.0.0/16,tcp:80\n"
			},
			want: "type hash:net,port, which is not understood",
		},
		// Review finding 2. A hash:ip set with a netmask lists one address per
		// network it matches: the member 100.64.0.0 of a `netmask 10` set is
		// every address of 100.64.0.0/10, which contains the tunnel range.
		"source set that matches whole networks": {
			mutate: func(f *calicoTestKernel) {
				f.sets[calicoMasq] = "create " + calicoMasq + " hash:ip family inet hashsize 1024 maxelem 65536 netmask 10 bucketsize 12 initval 0x1\nadd " + calicoMasq + " 100.64.0.0\n"
			},
			want: "set " + calicoMasq + " has netmask 10: its members match whole networks",
		},
		"source set with a bitmask": {
			mutate: func(f *calicoTestKernel) {
				f.sets[calicoMasq] = "create " + calicoMasq + " hash:ip family inet hashsize 1024 maxelem 65536 bitmask 255.192.0.0 bucketsize 12 initval 0x1\nadd " + calicoMasq + " 100.64.0.0\n"
			},
			want: "set " + calicoMasq + " has a bitmask",
		},
		"source set with an option that is not known": {
			mutate: func(f *calicoTestKernel) {
				f.sets[calicoMasq] = "create " + calicoMasq + " hash:net family inet hashsize 1024 maxelem 65536 wildcard\nadd " + calicoMasq + " 192.168.0.0/16\n"
			},
			want: "header option that is not understood",
		},
		"IPv6 pool": {
			mutate: func(f *calicoTestKernel) {
				f.sets[calicoMasq] = "create " + calicoMasq + " hash:net family inet6\nadd " + calicoMasq + " fd00::/64\n"
			},
			want: "is not IPv4",
		},
		"missing set": {
			mutate: func(f *calicoTestKernel) { delete(f.sets, calicoMasq) },
			want:   "read set " + calicoMasq,
		},
		"ipset cannot run": {
			mutate: func(f *calicoTestKernel) {
				f.setErr = errors.New("exec: \"ipset\": executable file not found in $PATH")
			},
			want: "read set " + calicoMasq,
		},
		"set listing for another set": {
			mutate: func(f *calicoTestKernel) { f.sets[calicoMasq] = "create other hash:net family inet\n" },
			want:   "not for " + calicoMasq,
		},
		"oversized set listing": {
			mutate: func(f *calicoTestKernel) {
				f.sets[calicoMasq] += strings.Repeat("add "+calicoMasq+" 192.168.0.0/16\n", maxSetSaveBytes/32)
			},
			want: "exceeds bound",
		},
		"saved text does not pair": {
			save: calicoSave(calicoOutgoing(calicoMasqOK), "-j RETURN"),
			want: "cannot be read",
		},
		"saved text is cut short": {
			save: strings.Replace(calicoSave(calicoOutgoing(calicoMasqOK)), "COMMIT\n", "", 1),
			want: "incomplete compat NAT inspection",
		},
		"saved text carries a warning": {
			save: "# Warning: iptables-legacy tables present, use iptables-legacy-save to see them\n" + calicoSave(calicoOutgoing(calicoMasqOK)),
			want: "unrecognized compat inspection warning",
		},
		"legacy iptables backend": {
			mutate: func(f *calicoTestKernel) { f.version = "iptables-nft-save v1.8.10 (legacy)" },
			want:   "unavailable or incompatible",
		},
		// The chain is rewritten after the first listing: the two listings differ.
		"rules change during observation": {
			mutate: func(f *calicoTestKernel) {
				f.onIPSet = func() {
					f.onIPSet = nil
					f.addRule(nftRuleView{Family: "ip", Table: "nat", Chain: "cali-nat-outgoing", Expr: []map[string]any{{"return": nil}}}, true)
				}
			},
			want: "CNI rules changed across semantic observation",
		},
	} {
		t.Run(name, func(t *testing.T) {
			save, tunnel := tc.save, tc.tunnel
			if save == "" {
				save = calicoSave(calicoOutgoing(calicoMasqOK))
			}
			if tunnel == "" {
				tunnel = "100.96.0.0/24"
			}
			f, r := newCalicoTestKernel(t, calicoNFT(), save)
			if tc.mutate != nil {
				tc.mutate(f)
			}
			status, err := r.Reconcile(t.Context(), tunnel)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("status %+v, error %v", status, err)
			}
			for _, adapter := range status.Adapters {
				if adapter.State == StateReady {
					t.Fatalf("refused node reports a ready adapter: %+v", status)
				}
			}
			if len(f.mutations) != 0 {
				t.Fatalf("refusal mutated: %v", f.mutations)
			}
		})
	}
}

// A node whose rules need no set proof is observed exactly as before: no saved
// text and no set is read, and the reason is the unchanged constant.
func TestExistingFlannelFixtureReadsNoSavedTextOrSet(t *testing.T) {
	listing, err := os.ReadFile("testdata/k3s-flannel-nat.json")
	if err != nil {
		t.Fatal(err)
	}
	f, r := newCalicoTestKernel(t, nil, "")
	if err := json.Unmarshal(listing, &f.doc); err != nil {
		t.Fatal(err)
	}
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	if err != nil || status.Adapters[0].Name != ObservedAdapterName || status.Adapters[0].Reason != ReasonObservedNoTunnelSourceNAT {
		t.Fatalf("k3s Flannel node: %+v %v", status, err)
	}
	for _, command := range f.commands {
		if !strings.HasPrefix(command, "nft ") {
			t.Fatalf("unneeded inspection %q", command)
		}
	}
}

func TestRealIPSetRunnerAllowsOnlySaveOfAValidName(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"save"},
		{"list", calicoMasq},
		{"save", calicoMasq, "extra"},
		{"save", "-file"},
		{"save", "-"},
		{"destroy", calicoMasq},
		{"save", ""},
		{"save", "a b"},
		{"save", "a;b"},
		{"save", "a/b"},
		{"save", strings.Repeat("x", 32)},
		{"restore"},
	} {
		if _, err := realIPSetRunner(t.Context(), args...); err == nil || err.Error() != "unsupported ipset inspection" {
			t.Errorf("%v: %v", args, err)
		}
	}
}

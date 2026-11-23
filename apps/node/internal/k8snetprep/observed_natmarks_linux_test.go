//go:build linux

package k8snetprep

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Review finding 4 on the whole reconcile; observed_natmarks_test.go has the
// walk itself.

// natMarkKernel is a kube-proxy node whose ip nat POSTROUTING holds one rule
// before kube-proxy's chain: nft shows it as rule, the saved text as saved.
func natMarkKernel(t *testing.T, rule, saved string) (*calicoTestKernel, *Reconciler) {
	t.Helper()
	save := "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n:KUBE-POSTROUTING - [0:0]\n:cali-POSTROUTING - [0:0]\n:cali-nat-outgoing - [0:0]\n"
	if saved != "" {
		save += "-A POSTROUTING " + saved + "\n"
	}
	save += "-A POSTROUTING -m comment --comment \"kubernetes postrouting rules\" -j KUBE-POSTROUTING\n" +
		"-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN\n" +
		"-A KUBE-POSTROUTING -j MARK --set-xmark 0x4000/0x0\n" +
		"-A KUBE-POSTROUTING -m comment --comment \"kubernetes service traffic requiring SNAT\" -j MASQUERADE --random-fully\n" +
		"COMMIT\n"
	return newCalicoTestKernel(t, natMarkChains(rule), save)
}

func wantRefusedNoMutation(t *testing.T, f *calicoTestKernel, status ReconcileStatus, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("status %+v, error %v, want %q", status, err, want)
	}
	if status.Host.State != StateBlocked || status.Host.Reason != bounded(err.Error(), maxReasonBytes) {
		t.Fatalf("status does not carry the reason: %+v", status)
	}
	for _, adapter := range status.Adapters {
		if adapter.State == StateReady {
			t.Fatalf("refused node reports a ready adapter: %+v", status)
		}
	}
	if len(f.mutations) != 0 {
		t.Fatalf("refusal mutated: %v", f.mutations)
	}
}

// A rule ahead of kube-proxy's chain sets kube-proxy's masquerade mark on
// everything. kube-proxy's `-m mark ! --mark 0x4000/0x4000 -j RETURN` then no
// longer returns, and its MASQUERADE rewrites traffic bound for the tunnel.
// The node was ready before the fix: the MARK target read as "does nothing".
func TestNodeIsRefusedWhenANATRuleSetsAKubernetesMark(t *testing.T) {
	mark := `[` + xtMark + `]`
	t.Run("iptables MARK target", func(t *testing.T) {
		f, r := natMarkKernel(t, mark, "-j MARK --set-xmark 0x4000/0x4000")
		status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
		wantRefusedNoMutation(t, f, status, err, "NAT chain POSTROUTING can set a Kubernetes mark that selects a masquerade")
		// The value came from the saved text, read after the listing.
		if f.commands[0] != "nft -j -a list ruleset" || f.commands[len(f.commands)-1] != "iptables-nft-save -t nat" {
			t.Fatalf("commands: %v", f.commands)
		}
	})
	t.Run("iptables MARK target that leaves the marks alone", func(t *testing.T) {
		f, r := natMarkKernel(t, mark, "-j MARK --set-xmark 0x100/0x100")
		status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
		if err != nil || status.Adapters[0].Name != ObservedAdapterName || status.Adapters[0].State != StateReady || status.Adapters[0].Reason != ReasonObservedNoTunnelSourceNAT {
			t.Fatalf("%+v %v", status, err)
		}
		if len(f.mutations) != 0 || len(f.setReads) != 0 {
			t.Fatalf("mutations %v, sets read %v", f.mutations, f.setReads)
		}
	})
	t.Run("saved text cannot be read", func(t *testing.T) {
		f, r := natMarkKernel(t, mark, "-j MARK --set-xmark 0x100/0x100")
		f.save = strings.Replace(f.save, "COMMIT\n", "", 1)
		status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
		wantRefusedNoMutation(t, f, status, err, "NAT chain POSTROUTING sets a mark whose value was not read: read saved NAT rules: ")
	})
	t.Run("saved text has no such rule", func(t *testing.T) {
		f, r := natMarkKernel(t, mark, "")
		status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
		wantRefusedNoMutation(t, f, status, err, "NAT chain POSTROUTING has 2 rules but 1 saved rules")
	})
	t.Run("native mark statement", func(t *testing.T) {
		f, r := natMarkKernel(t, `[`+nativeMark(`{"|":[`+oldMark+`,16384]}`)+`]`, "")
		status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
		wantRefusedNoMutation(t, f, status, err, "NAT chain POSTROUTING can set a Kubernetes mark that selects a masquerade")
		for _, command := range f.commands {
			if !strings.HasPrefix(command, "nft ") {
				t.Fatalf("a native statement needs no saved text, ran %q", command)
			}
		}
	})
	t.Run("native source address rewrite", func(t *testing.T) {
		f, r := natMarkKernel(t, `[{"mangle":{"key":{"payload":{"protocol":"ip","field":"saddr"}},"value":"10.0.0.1"}}]`, "")
		status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
		wantRefusedNoMutation(t, f, status, err, "NAT chain POSTROUTING rewrites a packet field with a statement that is not understood")
	})
	t.Run("native mark statement that leaves the marks alone", func(t *testing.T) {
		_, r := natMarkKernel(t, `[`+nativeMark(`{"|":[`+oldMark+`,256]}`)+`]`, "")
		if status, err := r.Reconcile(t.Context(), "100.96.0.0/24"); err != nil {
			t.Fatalf("%+v %v", status, err)
		}
	})
}

// The gateway in Kubernetes takes saved text from the manager's receipt only.
// The manager carries NAT chains for their set matches, so a MARK target in
// another chain has no saved rule at hand and the node is refused; in a
// carried chain its value is read like any other.
func TestGatewayOnHostFactsRefusesANATMarkItCannotRead(t *testing.T) {
	mark := nftRuleView{Family: "ip", Table: "nat", Chain: "POSTROUTING", Expr: []map[string]any{{"xt": map[string]any{"type": "target", "name": "MARK"}}}}

	t.Run("chain the manager does not carry", func(t *testing.T) {
		f, r := gatewayOnLiveCalico(t, constantFacts(liveCalicoHostFacts(t)))
		f.addRule(mark, true)
		status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
		wantRefusedNoMutation(t, f, status, err, "NAT chain POSTROUTING sets a mark whose value was not read: its saved rules are not at hand")
		for _, command := range f.commands {
			if strings.HasPrefix(command, "DENIED") {
				t.Fatalf("gateway ran a command it cannot run: %v", f.commands)
			}
		}
	})
	t.Run("manager read no NAT text", func(t *testing.T) {
		facts := liveCalicoHostFacts(t)
		facts.NAT, facts.Sets = SavedTableFacts{State: FactsNotNeeded, Reason: "the kernel has no ipset, so no NAT rule can match one"}, nil
		f, r := natMarkKernel(t, `[`+xtMark+`]`, "-j MARK --set-xmark 0x100/0x100")
		r.runIPTables = func(context.Context, ...string) (string, error) {
			return "", errors.New("the gateway must not read saved text itself")
		}
		facts.Mangle = SavedTableFacts{State: FactsRead}
		r.UseHostFacts(constantFacts(facts))
		status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
		wantRefusedNoMutation(t, f, status, err, "NAT chain POSTROUTING sets a mark whose value was not read: host-posture manager did not read saved nat rules: the kernel has no ipset")
	})
	for name, tc := range map[string]struct{ value, want string }{
		"carried chain, mark that selects a masquerade": {"0x4000/0x4000", "NAT chain cali-nat-outgoing can set a Kubernetes mark that selects a masquerade"},
		"carried chain, mark that leaves them alone":    {"0x0/0x100", ""},
	} {
		t.Run(name, func(t *testing.T) {
			inChain := mark
			inChain.Chain = "cali-nat-outgoing"
			// The manager reads the node with the extra rule ...
			node, reader := liveCalicoFactsReader(t)
			node.addRule(inChain, true)
			node.save = strings.Replace(node.save, "-A cali-nat-outgoing ", "-A cali-nat-outgoing -j MARK --set-xmark "+tc.value+"\n-A cali-nat-outgoing ", 1)
			facts := reader.Read(t.Context())
			if facts.NAT.State != FactsRead || len(facts.NAT.Chains) != 1 || len(facts.NAT.Chains[0].Rules) != 2 {
				t.Fatalf("manager facts: %+v", facts.NAT)
			}
			// ... and the gateway lists the same node.
			f, r := gatewayOnLiveCalico(t, constantFacts(facts))
			f.addRule(inChain, true)
			status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
			if tc.want == "" {
				if err != nil || status.Adapters[0].State != StateReady {
					t.Fatalf("%+v %v", status, err)
				}
				return
			}
			wantRefusedNoMutation(t, f, status, err, tc.want)
		})
	}
}

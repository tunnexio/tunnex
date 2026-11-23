//go:build linux

package k8snetprep

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Unlike observed_calico_test.go, everything read here was CAPTURED FROM A REAL
// NODE: Calico v3.31.2 (manifests/calico.yaml, unchanged) on a one-node kind
// v0.31.0 cluster, Kubernetes v1.35.0, kernel 6.8. Calico ran its default
// iptables dataplane on the nft backend, with the default pool 192.168.0.0/16
// (IPIP Always, natOutgoing). The files were read in the node's network
// namespace with the tools of the gateway image (Alpine 3.24.2: nft 1.1.6,
// iptables-nft-save 1.8.13, ipset 7.24) and are stored byte for byte; see
// testdata/README.md.

const liveCalico = "testdata/calico-v3.31.2-kind."

func liveCalicoFile(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(liveCalico + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func liveCalicoSnapshot(t *testing.T) *cniSnapshot {
	t.Helper()
	s, err := parseCNISnapshot(liveCalicoFile(t, "nft.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func liveCalicoFacts(t *testing.T) *natSetFacts {
	t.Helper()
	save := liveCalicoFile(t, "iptables-nft-save.txt")
	if _, err := parseNFTSaveNAT(save); err != nil {
		t.Fatalf("captured save is not one complete nat table: %v", err)
	}
	saved, err := parseSavedRules(save)
	if err != nil {
		t.Fatal(err)
	}
	members, err := parseIPSetSave(calicoMasq, liveCalicoFile(t, "ipset-"+calicoMasq+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(members, []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}) {
		t.Fatalf("captured pool set = %v", members)
	}
	return &natSetFacts{saved: saved, members: map[string][]netip.Prefix{calicoMasq: members}}
}

// (a) A tunnel range disjoint from the pool is accepted, and the proof names
// the set that carried it.
func TestLiveCalicoNodeIsAcceptedOutsideItsPool(t *testing.T) {
	chains, rules := liveCalicoSnapshot(t).observedNATInput()
	facts := liveCalicoFacts(t)

	// Every chain of the real nat table pairs with its saved text, not only
	// the one the proof reads: same rule count, set matches and targets.
	for chain := range chains {
		if err := pairSavedChain(chain, rules[chain], facts.saved[chain]); err != nil {
			t.Errorf("real chain does not pair: %v", err)
		}
	}
	want := []savedRule{{
		Sets:   []setMatch{{Name: calicoMasq, Dirs: []string{"src"}}, {Name: calicoAll, Dirs: []string{"dst"}, Negated: true}},
		Target: "MASQUERADE", Args: []string{"--random-fully"},
	}}
	if got := facts.saved["cali-nat-outgoing"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("real masquerade rule read as %+v", got)
	}

	if err := proveNoTunnelSourceNAT(chains, rules, "POSTROUTING", calicoTunnel, observedHandledChains); !errors.Is(err, errSetFactsNeeded) {
		t.Fatalf("without set facts: %v", err)
	}
	needed, err := setsNeededForProof(chains, rules, "POSTROUTING", calicoTunnel, "wg0", observedHandledChains, facts.saved)
	if err != nil || !reflect.DeepEqual(needed, []string{calicoMasq}) {
		t.Fatalf("sets needed = %v, %v", needed, err)
	}
	proof, err := proveNoTunnelSourceNATWithSets(chains, rules, "POSTROUTING", calicoTunnel, "wg0", observedHandledChains, facts)
	if err != nil || !reflect.DeepEqual(proof, []string{calicoMasq}) {
		t.Fatalf("real Calico node was refused: %v %v", proof, err)
	}
	if reason := observedReadyReason(proof); !strings.HasSuffix(reason, "limited by sets outside it: "+calicoMasq) {
		t.Fatalf("reason = %q", reason)
	}
}

// (b) A tunnel range that overlaps the pool is refused, and the refusal names
// the set.
func TestLiveCalicoNodeIsRefusedInsideItsPool(t *testing.T) {
	chains, rules := liveCalicoSnapshot(t).observedNATInput()
	facts := liveCalicoFacts(t)
	for _, tunnel := range []string{"192.168.7.0/24", "192.168.0.0/16", "192.0.0.0/8", "192.168.255.255/32"} {
		proof, err := proveNoTunnelSourceNATWithSets(chains, rules, "POSTROUTING", netip.MustParsePrefix(tunnel), "wg0", observedHandledChains, facts)
		if err == nil || len(proof) != 0 || !strings.Contains(err.Error(), "masquerades sources in set "+calicoMasq+", which overlaps the tunnel range") {
			t.Errorf("%s: %v %v", tunnel, proof, err)
		}
	}
}

// The real node has a second masquerade the model did not know: Calico's
// `-o tunl0 -m addrtype ! --src-type LOCAL --limit-iface-out -m addrtype
// --src-type LOCAL -j MASQUERADE`. No set limits it; only its exact output
// interface excuses it. Without the tunnel interface, or when the tunnel
// interface is that very interface, the node stays refused.
func TestLiveCalicoIPIPMasqueradeIsExcusedOnlyByItsOutputInterface(t *testing.T) {
	chains, rules := liveCalicoSnapshot(t).observedNATInput()
	facts := liveCalicoFacts(t)
	for _, egress := range []string{"", "tunl0"} {
		_, err := proveNoTunnelSourceNATWithSets(chains, rules, "POSTROUTING", calicoTunnel, egress, observedHandledChains, facts)
		if err == nil || !strings.Contains(err.Error(), "NAT chain cali-POSTROUTING can rewrite the source") {
			t.Errorf("egress %q: %v", egress, err)
		}
	}
}

// The real node hooks ip mangle POSTROUTING and sets a mark there
// (`MARK --set-xmark 0x0/0x1b0000`). It is accepted because that value leaves
// the Kubernetes marks alone, and refused when the same rule would set one.
func TestLiveCalicoMangleHookCannotSetAKubernetesMark(t *testing.T) {
	s := liveCalicoSnapshot(t)
	if err := s.validateHookCoverage("wg0", ""); !errors.Is(err, errMarkFactsNeeded) {
		t.Fatalf("mangle hook with its mark unread: %v", err)
	}
	mangle := liveCalicoFile(t, "iptables-nft-save-mangle.txt")
	if _, err := parseNFTSaveTable(mangle, "mangle"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mangle, "-j MARK --set-xmark 0x0/0x1b0000") {
		t.Fatal("captured mangle text lost Calico's mark rule")
	}
	saved, err := parseSavedRules(mangle)
	if err != nil {
		t.Fatal(err)
	}
	s.mangleSaved = saved
	if err := s.validateHookCoverage("wg0", ""); err != nil {
		t.Fatalf("real mangle hook was refused: %v", err)
	}
	for _, mark := range []string{"0x4000/0x4000", "0x0/0x1b4000", "0x2000/0x0", "0x8000/0xffffffff"} {
		saved, err := parseSavedRules(strings.Replace(mangle, "0x0/0x1b0000", mark, 1))
		if err != nil {
			t.Fatal(err)
		}
		s.mangleSaved = saved
		if err := s.validateHookCoverage("wg0", ""); err == nil || !strings.Contains(err.Error(), "can set a Kubernetes mark") {
			t.Errorf("mark %s: %v", mark, err)
		}
	}
	// The nat text is not the mangle table.
	if _, err := parseNFTSaveTable(liveCalicoFile(t, "iptables-nft-save.txt"), "mangle"); err == nil {
		t.Error("nat text accepted as the mangle table")
	}
}

func liveCalicoKernel(t *testing.T) (*calicoTestKernel, *Reconciler) {
	t.Helper()
	f := &calicoTestKernel{
		awsTestKernel: &awsTestKernel{
			save:       liveCalicoFile(t, "iptables-nft-save.txt"),
			saveMangle: liveCalicoFile(t, "iptables-nft-save-mangle.txt"),
			version:    "iptables-nft-save v1.8.13 (nf_tables)",
			next:       1 << 20,
		},
		sets: map[string]string{calicoMasq: liveCalicoFile(t, "ipset-"+calicoMasq+".txt")},
	}
	if err := json.Unmarshal([]byte(liveCalicoFile(t, "nft.json")), &f.doc); err != nil {
		t.Fatal(err)
	}
	r := awsTestReconciler(t, f.awsTestKernel, ScopeIPMasqAndAWS)
	r.runIPSet = f.ipset
	return f, r
}

// The whole reconcile, fed the real captures through the same runners' seams:
// ready as observed, naming the pool set, with nothing written.
func TestLiveCalicoNodeReconcilesReadyAndNamesItsPool(t *testing.T) {
	f, r := liveCalicoKernel(t)
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	if err != nil {
		t.Fatalf("real Calico node was refused: %+v %v", status, err)
	}
	want := ReasonObservedNoTunnelSourceNAT + "; masquerade sources are limited by sets outside it: " + calicoMasq
	if adapter := status.Adapters[0]; adapter.Name != ObservedAdapterName || adapter.State != StateReady || adapter.Reason != want {
		t.Fatalf("adapter = %+v", adapter)
	}
	if len(f.mutations) != 0 {
		t.Fatalf("observed proof mutated: %v", f.mutations)
	}
	if len(f.setReads) == 0 {
		t.Fatal("no set was read")
	}
	for _, name := range f.setReads {
		if name != calicoMasq {
			t.Fatalf("read set %s", name)
		}
	}
	listing := "nft -j -a list ruleset"
	if f.commands[0] != listing || f.commands[len(f.commands)-1] != listing {
		t.Fatalf("observation is not bracketed by listings: %v", f.commands)
	}
	joined := strings.Join(f.commands, "\n")
	if !strings.Contains(joined, "iptables-nft-save -t mangle") || !strings.Contains(joined, "iptables-nft-save -t nat") {
		t.Fatalf("saved text was not read: %v", f.commands)
	}
}

// Review finding 3, on the whole reconcile. The captured node masquerades on
// its overlay interface (`-o tunl0 ... -j MASQUERADE`), and only that exact
// output interface excuses the rule. The gateway is told every tunnel
// interface the agent owns, at every observation. While that interface is not
// one of them the node is ready; once the agent owns it (here by giving the
// second tunnel interface the overlay's name) the same rule is refused, on
// the direct path and on the receipt path alike, and nothing is written.
func TestLiveCalicoNodeIsRefusedWhenAMasqueradeIsBoundToASecondTunnelInterface(t *testing.T) {
	for name, build := range map[string]func(*testing.T) (*calicoTestKernel, *Reconciler){
		"direct reads": liveCalicoKernel,
		"host facts": func(t *testing.T) (*calicoTestKernel, *Reconciler) {
			return gatewayOnLiveCalico(t, constantFacts(liveCalicoHostFacts(t)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, r := build(t)
			owned := []string{"wg0", "tunnex-ovpn"}
			asked := 0
			r.UseTunnelInterfaces(func() []string { asked++; return owned })
			status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
			if err != nil || status.Adapters[0].Name != ObservedAdapterName || status.Adapters[0].State != StateReady {
				t.Fatalf("an unrelated second tunnel interface refused the node: %+v %v", status, err)
			}
			if asked < 2 {
				t.Fatalf("the tunnel interfaces were read %d times; every observation must read them", asked)
			}

			// The OpenVPN server starts on the interface the masquerade names.
			owned = []string{"wg0", "tunl0"}
			status, err = r.Reconcile(t.Context(), "100.96.0.0/24")
			if err == nil || !strings.Contains(err.Error(), "NAT chain cali-POSTROUTING can rewrite the source of traffic to the tunnel range 100.96.0.0/24") {
				t.Fatalf("masquerade bound to a tunnel interface: %+v %v", status, err)
			}
			for _, adapter := range status.Adapters {
				if adapter.State == StateReady {
					t.Fatalf("refused node reports a ready adapter: %+v", status)
				}
			}
			if status.Host.State != StateBlocked || len(f.mutations) != 0 {
				t.Fatalf("status %+v, mutations %v", status, f.mutations)
			}

			// And stops again: the node is ready on the next pass.
			owned = []string{"wg0"}
			if status, err = r.Reconcile(t.Context(), "100.96.0.0/24"); err != nil {
				t.Fatalf("after the second tunnel interface went away: %+v %v", status, err)
			}

			// A list the proof cannot use refuses before anything is read.
			f.commands = nil
			owned = []string{"wg0", "tunnex-*"}
			if status, err = r.Reconcile(t.Context(), "100.96.0.0/24"); err == nil || !strings.Contains(err.Error(), "invalid tunnel interface name") || len(f.commands) != 0 {
				t.Fatalf("wildcard tunnel interface: %+v %v, ran %v", status, err, f.commands)
			}
		})
	}
}

func TestLiveCalicoNodeReconcileRefusals(t *testing.T) {
	t.Run("tunnel range inside the pool", func(t *testing.T) {
		f, r := liveCalicoKernel(t)
		status, err := r.Reconcile(t.Context(), "192.168.7.0/24")
		if err == nil || !strings.Contains(err.Error(), "overlaps the tunnel range") {
			t.Fatalf("%+v %v", status, err)
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
	// What the gateway container reads today, captured on the same node with
	// only NET_ADMIN and NET_BIND_SERVICE: iptables-nft-save exits 1 with
	// "Can't open socket to ipset." and stops in the middle of the masquerade
	// rule. The command's failure already refuses the node; if only the text
	// were looked at, it is refused as well.
	t.Run("saved text cut short without NET_RAW", func(t *testing.T) {
		cut := liveCalicoFile(t, "iptables-nft-save.no-net-raw.txt")
		if !strings.Contains(cut, "Can't open socket to ipset.") || strings.Contains(cut, "COMMIT") {
			t.Fatal("capture is not the truncated one")
		}
		if _, err := parseNFTSaveNAT(cut); err == nil {
			t.Fatal("truncated save accepted as complete")
		}
		f, r := liveCalicoKernel(t)
		f.save = cut
		if status, err := r.Reconcile(t.Context(), "100.96.0.0/24"); err == nil {
			t.Fatalf("truncated save accepted: %+v", status)
		}
	})
	t.Run("mangle text unavailable", func(t *testing.T) {
		f, r := liveCalicoKernel(t)
		f.saveMangle = ""
		if status, err := r.Reconcile(t.Context(), "100.96.0.0/24"); err == nil {
			t.Fatalf("unread mangle marks accepted: %+v", status)
		}
	})
	t.Run("mangle rule sets the kube-proxy mark", func(t *testing.T) {
		f, r := liveCalicoKernel(t)
		f.saveMangle = strings.Replace(f.saveMangle, "0x0/0x1b0000", "0x4000/0x4000", 1)
		if status, err := r.Reconcile(t.Context(), "100.96.0.0/24"); err == nil || !strings.Contains(err.Error(), "Kubernetes mark") {
			t.Fatalf("%+v %v", status, err)
		}
	})
}

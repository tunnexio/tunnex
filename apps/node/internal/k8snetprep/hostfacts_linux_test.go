//go:build linux

package k8snetprep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// K8N-1, Decision 9. The node here is the captured Calico v3.31.2 one (see
// observed_calico_live_linux_test.go). Two parties read it: the manager, which
// may run every command, and the gateway, whose iptables-nft-save and ipset
// fail as they do without NET_RAW and which must never need them.

// factsNFT answers the manager's `list chain` from the same document the
// gateway lists as a whole.
func (f *calicoTestKernel) factsNFT(ctx context.Context, args ...string) (string, error) {
	var out struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	out.NFTables = []map[string]json.RawMessage{}
	f.commands = append(f.commands, "nft "+strings.Join(args, " "))
	if strings.Join(args, " ") == "-j -a list tables" {
		for _, entry := range f.doc.NFTables {
			if _, ok := entry["table"]; ok {
				out.NFTables = append(out.NFTables, entry)
			}
		}
		encoded, _ := json.Marshal(out)
		return string(encoded), nil
	}
	if len(args) != 7 || strings.Join(args[:5], " ") != "-j -a list chain ip" {
		return "", errors.New("the facts reader ran an nft command that is not a table or chain listing")
	}
	for _, entry := range f.doc.NFTables {
		var chain nftChainView
		if raw, ok := entry["chain"]; ok && json.Unmarshal(raw, &chain) == nil && chain.Family == "ip" && chain.Table == args[5] && chain.Name == args[6] {
			out.NFTables = append(out.NFTables, entry)
		}
		var rule nftRuleView
		if raw, ok := entry["rule"]; ok && json.Unmarshal(raw, &rule) == nil && rule.Family == "ip" && rule.Table == args[5] && rule.Chain == args[6] {
			out.NFTables = append(out.NFTables, entry)
		}
	}
	if len(out.NFTables) == 0 {
		return "", fakeNftExitError{message: "Error: No such file or directory"}
	}
	encoded, _ := json.Marshal(out)
	return string(encoded), nil
}

// setTableHandle rewrites one ip table's handle in the listing; zero removes
// the table entry.
func (f *calicoTestKernel) setTableHandle(t *testing.T, name string, handle uint64) {
	t.Helper()
	for i, entry := range f.doc.NFTables {
		var table struct {
			Family string `json:"family"`
			Name   string `json:"name"`
			Handle uint64 `json:"handle"`
		}
		if raw, ok := entry["table"]; ok && json.Unmarshal(raw, &table) == nil && table.Family == "ip" && table.Name == name {
			if handle == 0 {
				f.doc.NFTables = append(f.doc.NFTables[:i], f.doc.NFTables[i+1:]...)
				return
			}
			table.Handle = handle
			f.doc.NFTables[i] = rawEntry("table", table)
			return
		}
	}
	t.Fatalf("no ip %s table in the listing", name)
}

func (f *calicoTestKernel) factsIPSet(ctx context.Context, args ...string) (string, error) {
	if len(args) == 2 && args[0] == "list" && args[1] == "-n" {
		f.commands = append(f.commands, "ipset list -n")
		names := ""
		for name := range f.sets {
			names += name + "\n"
		}
		return names, f.setErr
	}
	return f.ipset(ctx, args...)
}

func liveCalicoFactsReader(t *testing.T) (*calicoTestKernel, *HostFactsReader) {
	t.Helper()
	f, _ := liveCalicoKernel(t)
	reader := NewHostFactsReader(f.factsNFT, f.iptables, f.factsIPSet)
	reader.sysModule = t.TempDir()
	reader.procNet = legacyProcNet(t)
	if err := os.Mkdir(filepath.Join(reader.sysModule, "ip_set"), 0o755); err != nil {
		t.Fatal(err)
	}
	return f, reader
}

// gatewayOnLiveCalico is a reconciler whose own iptables-nft-save and ipset
// behave as in the gateway container on this node: they fail. It takes its
// facts from source and counts what it ran.
func gatewayOnLiveCalico(t *testing.T, source HostFactsSource) (*calicoTestKernel, *Reconciler) {
	t.Helper()
	f, r := liveCalicoKernel(t)
	denied := func(_ context.Context, args ...string) (string, error) {
		f.commands = append(f.commands, "DENIED "+strings.Join(args, " "))
		return "", errors.New("exit status 1: Can't open socket to ipset.")
	}
	r.runIPTables, r.runIPSet = denied, denied
	r.UseHostFacts(func(ctx context.Context) (HostNetFacts, error) {
		f.commands = append(f.commands, "take host facts")
		return source(ctx)
	})
	return f, r
}

func constantFacts(facts HostNetFacts) HostFactsSource {
	return func(context.Context) (HostNetFacts, error) { return facts, nil }
}

func liveCalicoHostFacts(t *testing.T) HostNetFacts {
	t.Helper()
	_, reader := liveCalicoFactsReader(t)
	facts := reader.Read(t.Context())
	if facts.NAT.State != FactsRead || facts.Mangle.State != FactsRead {
		t.Fatalf("captured node was not read: %+v", facts)
	}
	return facts
}

func TestHostFactsReaderCarriesOnlyWhatAProofCanNeed(t *testing.T) {
	f, reader := liveCalicoFactsReader(t)
	facts := reader.Read(t.Context())
	if err := facts.Validate(); err != nil {
		t.Fatal(err)
	}
	if facts.NAT.State != FactsRead || len(facts.NAT.Chains) != 1 || facts.NAT.Chains[0].Name != "cali-nat-outgoing" {
		t.Fatalf("nat facts = %+v", facts.NAT)
	}
	wantRule := `-A cali-nat-outgoing -m comment --comment "cali:flqWnvo8yq4ULQLa" -m set --match-set cali40masq-ipam-pools src -m set ! --match-set cali40all-ipam-pools dst -j MASQUERADE --random-fully`
	if !reflect.DeepEqual(facts.NAT.Chains[0].Rules, []string{wantRule}) {
		t.Fatalf("nat rule text = %q", facts.NAT.Chains[0].Rules)
	}
	if facts.Mangle.State != FactsRead || len(facts.Mangle.Chains) != 1 || facts.Mangle.Chains[0].Name != "cali-POSTROUTING" || len(facts.Mangle.Chains[0].Rules) != 5 {
		t.Fatalf("mangle facts = %+v", facts.Mangle)
	}
	// Exactly the source set of the masquerade rule; never the negated
	// destination set, never a set of the mangle table.
	if len(facts.Sets) != 1 || facts.Sets[0].Name != calicoMasq || facts.Sets[0].State != FactsRead ||
		facts.Sets[0].Saved != liveCalicoFile(t, "ipset-"+calicoMasq+".txt") {
		t.Fatalf("sets = %+v", facts.Sets)
	}
	if !reflect.DeepEqual(f.setReads, []string{calicoMasq}) {
		t.Fatalf("sets read = %v", f.setReads)
	}
	// The listing digest is the one the gateway computes from the whole ruleset.
	s := liveCalicoSnapshot(t)
	for table, chains := range map[string][]SavedChainFacts{"nat": facts.NAT.Chains, "mangle": facts.Mangle.Chains} {
		for _, chain := range chains {
			if digest, ok := s.chainListingDigest(table, chain.Name); !ok || digest != chain.Listing {
				t.Errorf("%s %s: manager digest %s, gateway digest %s", table, chain.Name, chain.Listing, digest)
			}
		}
	}
	// The manager never lists the whole ruleset, and each save lies between
	// two listings of the chains it carries.
	joined := strings.Join(f.commands, "\n")
	if strings.Contains(joined, "list ruleset") {
		t.Fatalf("reader listed the whole ruleset: %v", f.commands)
	}
	for _, table := range []string{"nat", "mangle"} {
		save := lastIndex(f.commands, "iptables-nft-save -t "+table)
		listing := "nft -j -a list chain ip " + table + " "
		before, after := false, false
		for i, command := range f.commands {
			if strings.HasPrefix(command, listing) {
				before, after = before || i < save, after || i > save
			}
		}
		if save < 0 || !before || !after {
			t.Errorf("%s save is not between two chain listings: %v", table, f.commands)
		}
	}
	if set, listing := lastIndex(f.commands, "ipset save "+calicoMasq), lastIndex(f.commands, "nft -j -a list chain ip nat cali-nat-outgoing"); set > listing {
		t.Fatalf("set read after the closing listing: %v", f.commands)
	}
	if len(f.mutations) != 0 {
		t.Fatalf("reader mutated: %v", f.mutations)
	}

	// The next pass remembers the chains: one save per table, no second try.
	f.commands = nil
	if again := reader.Read(t.Context()); !reflect.DeepEqual(again, facts) {
		t.Fatalf("second read differs:\n%+v\n%+v", again, facts)
	}
	for _, table := range []string{"nat", "mangle"} {
		if n := count(f.commands, "iptables-nft-save -t "+table); n != 1 {
			t.Errorf("%s saved %d times on a steady pass: %v", table, n, f.commands)
		}
	}
}

func lastIndex(commands []string, want string) int {
	for i := len(commands) - 1; i >= 0; i-- {
		if commands[i] == want {
			return i
		}
	}
	return -1
}

func count(commands []string, want string) int {
	n := 0
	for _, command := range commands {
		if command == want {
			n++
		}
	}
	return n
}

func TestHostFactsReaderReadsNoNATTextWithoutKernelSets(t *testing.T) {
	t.Run("ip_set is not loaded", func(t *testing.T) {
		f, reader := liveCalicoFactsReader(t)
		reader.sysModule = t.TempDir()
		facts := reader.Read(t.Context())
		if facts.NAT.State != FactsNotNeeded || facts.Mangle.State != FactsRead || len(facts.Sets) != 0 {
			t.Fatalf("facts = %+v", facts)
		}
		for _, command := range f.commands {
			if strings.HasPrefix(command, "ipset") || command == "iptables-nft-save -t nat" {
				t.Fatalf("ran %q on a kernel without ip_set", command)
			}
		}
	})
	t.Run("no set exists", func(t *testing.T) {
		f, reader := liveCalicoFactsReader(t)
		f.sets = map[string]string{}
		facts := reader.Read(t.Context())
		if facts.NAT.State != FactsNotNeeded || !strings.Contains(facts.NAT.Reason, "no ipset") {
			t.Fatalf("nat facts = %+v", facts.NAT)
		}
		if count(f.commands, "iptables-nft-save -t nat") != 0 {
			t.Fatalf("NAT text saved without any set: %v", f.commands)
		}
	})
}

func TestHostFactsReaderStatesWhatItCouldNotRead(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate     func(*calicoTestKernel, *HostFactsReader)
		nat        string
		mangle     string
		wantNAT    string
		wantMangle string
		check      func(*testing.T, HostNetFacts)
	}{
		"saved text cut short, as without NET_RAW": {
			mutate: func(f *calicoTestKernel, _ *HostFactsReader) {
				f.save = liveCalicoFile(t, "iptables-nft-save.no-net-raw.txt")
			},
			nat:     FactsUnreadable,
			wantNAT: "read saved nat rules",
			mangle:  FactsRead,
		},
		"save command fails": {
			mutate:  func(f *calicoTestKernel, _ *HostFactsReader) { f.inspectErr = errors.New("exit status 1") },
			nat:     FactsUnreadable,
			wantNAT: "read saved nat rules: exit status 1",
			mangle:  FactsRead,
		},
		"saved text carries a warning": {
			mutate: func(f *calicoTestKernel, _ *HostFactsReader) {
				f.saveMangle = "# Warning: iptables-legacy tables present, use iptables-legacy-save to see them\n" + f.saveMangle
			},
			nat:        FactsRead,
			mangle:     FactsUnreadable,
			wantMangle: "unrecognized compat inspection warning",
		},
		"legacy iptables backend": {
			mutate:     func(f *calicoTestKernel, _ *HostFactsReader) { f.version = "iptables-nft-save v1.8.13 (legacy)" },
			nat:        FactsUnreadable,
			wantNAT:    "unavailable or incompatible",
			mangle:     FactsUnreadable,
			wantMangle: "unavailable or incompatible",
		},
		"set listing fails": {
			mutate: func(f *calicoTestKernel, _ *HostFactsReader) { delete(f.sets, calicoMasq); f.sets["other"] = "x" },
			nat:    FactsRead,
			mangle: FactsRead,
			check: func(t *testing.T, facts HostNetFacts) {
				if len(facts.Sets) != 1 || facts.Sets[0].State != FactsUnreadable || !strings.Contains(facts.Sets[0].Reason, "does not exist") || facts.Sets[0].Saved != "" {
					t.Fatalf("sets = %+v", facts.Sets)
				}
			},
		},
		"ipset cannot list names": {
			mutate:  func(f *calicoTestKernel, _ *HostFactsReader) { f.setErr = errors.New("exit status 1: Kernel error") },
			nat:     FactsUnreadable,
			wantNAT: "look for kernel sets",
			mangle:  FactsRead,
		},
		// A rule of a carried chain is replaced while its text is read.
		"chain changes while it is read": {
			mutate: func(f *calicoTestKernel, _ *HostFactsReader) {
				f.onIPSet = func() {
					f.onIPSet = nil
					f.addRule(nftRuleView{Family: "ip", Table: "nat", Chain: "cali-nat-outgoing", Expr: []map[string]any{{"return": nil}}}, true)
				}
			},
			nat:     FactsUnreadable,
			wantNAT: "nat rules changed while they were read",
			mangle:  FactsRead,
		},
		// The table is deleted and created again while its text is read.
		"table created again while it is read": {
			mutate: func(f *calicoTestKernel, _ *HostFactsReader) {
				f.onIPSet = func() { f.onIPSet = nil; f.setTableHandle(t, "nat", 99) }
			},
			nat:     FactsUnreadable,
			wantNAT: "nat rules changed while they were read",
			mangle:  FactsRead,
		},
		"a carried chain cannot be listed": {
			mutate: func(f *calicoTestKernel, r *HostFactsReader) {
				tables := r.runNFT
				r.runNFT = func(ctx context.Context, args ...string) (string, error) {
					if strings.Join(args, " ") == "-j -a list tables" {
						return tables(ctx, args...)
					}
					return "", errors.New("exit status 1")
				}
			},
			nat:        FactsUnreadable,
			wantNAT:    "nat rules",
			mangle:     FactsUnreadable,
			wantMangle: "mangle rules",
		},
		"more sets than one proof may read": {
			mutate: func(f *calicoTestKernel, _ *HostFactsReader) {
				lines := ""
				for i := 0; i <= maxProofSets; i++ {
					lines += "-A cali-fip-snat -m set --match-set extra" + string(rune('a'+i)) + " src -j MASQUERADE\n"
				}
				f.save = strings.Replace(f.save, "COMMIT\n", lines+"COMMIT\n", 1)
			},
			nat:     FactsUnreadable,
			wantNAT: "more than 16 source sets",
			mangle:  FactsRead,
		},
		"chain name nft could not be asked for": {
			mutate: func(f *calicoTestKernel, _ *HostFactsReader) {
				f.saveMangle = strings.Replace(f.saveMangle, ":cali-POSTROUTING - [0:0]\n", ":cali-POSTROUTING - [0:0]\n:9;drop - [0:0]\n", 1)
				f.saveMangle = strings.Replace(f.saveMangle, "COMMIT\n", "-A 9;drop -j MARK --set-xmark 0x0/0x1\nCOMMIT\n", 1)
			},
			nat:        FactsRead,
			mangle:     FactsUnreadable,
			wantMangle: "name that is not understood",
		},
		"facts larger than the receipt may hold": {
			mutate: func(f *calicoTestKernel, _ *HostFactsReader) {
				f.sets[calicoMasq] += strings.Repeat("add "+calicoMasq+" 10.0.0.0/8\n", MaxHostNetFactsBytes/32)
			},
			nat:        FactsUnreadable,
			wantNAT:    "exceed bound",
			mangle:     FactsUnreadable,
			wantMangle: "exceed bound",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, reader := liveCalicoFactsReader(t)
			tc.mutate(f, reader)
			facts := reader.Read(t.Context())
			if err := facts.Validate(); err != nil {
				t.Fatalf("reader returned malformed facts: %v", err)
			}
			if facts.NAT.State != tc.nat || !strings.Contains(facts.NAT.Reason, tc.wantNAT) {
				t.Errorf("nat = %s %q", facts.NAT.State, facts.NAT.Reason)
			}
			if facts.Mangle.State != tc.mangle || !strings.Contains(facts.Mangle.Reason, tc.wantMangle) {
				t.Errorf("mangle = %s %q", facts.Mangle.State, facts.Mangle.Reason)
			}
			if tc.check != nil {
				tc.check(t, facts)
			}
			if len(f.mutations) != 0 {
				t.Fatalf("reader mutated: %v", f.mutations)
			}
			// What the manager could not read, the gateway refuses, with the reason.
			_, r := gatewayOnLiveCalico(t, constantFacts(facts))
			status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
			if err == nil {
				t.Fatalf("gateway became ready on unread facts: %+v", status)
			}
		})
	}
}

// A chain that was carried and then disappears is found again without an
// operator: the reader starts over inside the same pass.
func TestHostFactsReaderFollowsAChangedChainSet(t *testing.T) {
	f, reader := liveCalicoFactsReader(t)
	first := reader.Read(t.Context())
	if first.NAT.State != FactsRead {
		t.Fatal(first.NAT)
	}
	reader.remembered["nat"] = []string{"cali-gone"}
	second := reader.Read(t.Context())
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("after a vanished chain: %+v", second.NAT)
	}
	if n := count(f.commands, "iptables-nft-save -t nat"); n < 2 {
		t.Fatalf("NAT text was not read again: %v", f.commands)
	}
}

func TestGatewayBecomesReadyOnHostFactsWithoutRunningWhatItCannot(t *testing.T) {
	facts := liveCalicoHostFacts(t)
	f, r := gatewayOnLiveCalico(t, constantFacts(facts))
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	if err != nil {
		t.Fatalf("gateway was refused: %+v %v", status, err)
	}
	want := ReasonObservedNoTunnelSourceNAT + "; masquerade sources are limited by sets outside it: " + calicoMasq
	if adapter := status.Adapters[0]; adapter.Name != ObservedAdapterName || adapter.State != StateReady || adapter.Reason != want {
		t.Fatalf("adapter = %+v", adapter)
	}
	// Every observation is: listing, the facts once, listing. Nothing else ran.
	listing := "nft -j -a list ruleset"
	wantCommands := []string{listing, "take host facts", listing, listing, "take host facts", listing}
	if !reflect.DeepEqual(f.commands, wantCommands) {
		t.Fatalf("gateway ran %v", f.commands)
	}
	if len(f.mutations) != 0 || len(f.setReads) != 0 {
		t.Fatalf("gateway mutated or read a set: %v %v", f.mutations, f.setReads)
	}

	// The same facts refuse a tunnel range inside the pool.
	_, r = gatewayOnLiveCalico(t, constantFacts(facts))
	status, err = r.Reconcile(t.Context(), "192.168.7.0/24")
	if err == nil || !strings.Contains(err.Error(), "masquerades sources in set "+calicoMasq+", which overlaps the tunnel range 192.168.7.0/24") {
		t.Fatalf("%+v %v", status, err)
	}
}

// The facts path decides exactly what the direct path decides on the same node.
func TestHostFactsCarryWhatTheDirectReadSaw(t *testing.T) {
	facts := liveCalicoHostFacts(t)
	s := liveCalicoSnapshot(t)
	direct := liveCalicoFacts(t)
	saved, err := s.savedRulesFromFacts("nat", facts.NAT)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(saved, map[string][]savedRule{"cali-nat-outgoing": direct.saved["cali-nat-outgoing"]}) {
		t.Fatalf("carried nat rules = %+v", saved)
	}
	directMangle, err := parseSavedRules(liveCalicoFile(t, "iptables-nft-save-mangle.txt"))
	if err != nil {
		t.Fatal(err)
	}
	mangle, err := s.savedRulesFromFacts("mangle", facts.Mangle)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(mangle, map[string][]savedRule{"cali-POSTROUTING": directMangle["cali-POSTROUTING"]}) {
		t.Fatalf("carried mangle rules = %+v", mangle)
	}
	_, r := liveCalicoKernel(t)
	got, err := r.natSetFactsFromHostFacts(s, &facts, "100.96.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.members, direct.members) {
		t.Fatalf("members = %v, direct read %v", got.members, direct.members)
	}
}

func TestGatewayRefusesHostFactsThatDoNotHold(t *testing.T) {
	replaceRule := func(table *SavedTableFacts, old, new string) {
		for i := range table.Chains {
			for k := range table.Chains[i].Rules {
				table.Chains[i].Rules[k] = strings.Replace(table.Chains[i].Rules[k], old, new, 1)
			}
		}
	}
	for name, tc := range map[string]struct {
		source  func(HostNetFacts) HostFactsSource
		mutate  func(*HostNetFacts)
		gateway func(*calicoTestKernel)
		want    string
	}{
		"no receipt": {
			source: func(HostNetFacts) HostFactsSource {
				return func(context.Context) (HostNetFacts, error) {
					return HostNetFacts{}, errors.New("host facts receipt is missing")
				}
			},
			want: "host-posture facts: host facts receipt is missing",
		},
		"stale receipt": {
			source: func(HostNetFacts) HostFactsSource {
				return func(context.Context) (HostNetFacts, error) {
					return HostNetFacts{}, errors.New("host facts receipt is stale or from the future")
				}
			},
			want: "host-posture facts: host facts receipt is stale",
		},
		"manager read no NAT text": {
			mutate: func(f *HostNetFacts) {
				f.NAT, f.Sets = SavedTableFacts{State: FactsNotNeeded, Reason: "the kernel has no ipset"}, nil
			},
			want: "did not read saved nat rules: the kernel has no ipset",
		},
		"manager could not read the mangle text": {
			mutate: func(f *HostNetFacts) {
				f.Mangle = SavedTableFacts{State: FactsUnreadable, Reason: "read saved mangle rules: exit status 1"}
			},
			want: "did not read saved mangle rules: read saved mangle rules: exit status 1",
		},
		"NAT chain not carried": {
			mutate: func(f *HostNetFacts) { f.NAT.Chains, f.Sets = nil, nil },
			want:   "do not carry nat chain cali-nat-outgoing",
		},
		"mangle chain not carried": {
			mutate: func(f *HostNetFacts) { f.Mangle.Chains = nil },
			want:   "do not carry mangle chain cali-POSTROUTING",
		},
		"chain of another listing": {
			mutate: func(f *HostNetFacts) { f.NAT.Chains[0].Listing = strings.Repeat("0", 64) },
			want:   "nat chain cali-nat-outgoing changed after the host-posture manager read it",
		},
		"chain the gateway does not have": {
			mutate: func(f *HostNetFacts) {
				f.Mangle.Chains = append(f.Mangle.Chains, SavedChainFacts{Name: "cali-ZZ", Listing: strings.Repeat("0", 64), Rules: []string{"-A cali-ZZ -j MARK --set-xmark 0x0/0x1"}})
			},
			want: "mangle chain cali-ZZ changed after the host-posture manager read it",
		},
		// The rule was replaced after the manager's read: same words, new handle.
		"rule replaced since the manager read it": {
			gateway: func(f *calicoTestKernel) {
				for i, entry := range f.doc.NFTables {
					var rule nftRuleView
					if raw, ok := entry["rule"]; ok && json.Unmarshal(raw, &rule) == nil && rule.Table == "nat" && rule.Chain == "cali-nat-outgoing" {
						rule.Handle += 1000
						f.doc.NFTables[i] = rawEntry("rule", rule)
					}
				}
			},
			want: "nat chain cali-nat-outgoing changed after the host-posture manager read it",
		},
		// The table was deleted and created again: its chains and rules count
		// from one again and can look exactly as before. Its handle cannot.
		"table created again since the manager read it": {
			gateway: func(f *calicoTestKernel) { f.setTableHandle(t, "nat", 99) },
			want:    "nat chain cali-nat-outgoing changed after the host-posture manager read it",
		},
		"listing that does not state its tables": {
			gateway: func(f *calicoTestKernel) { f.setTableHandle(t, "mangle", 0) },
			want:    "mangle chain cali-POSTROUTING changed after the host-posture manager read it",
		},
		"set not carried": {
			mutate: func(f *HostNetFacts) { f.Sets = nil },
			want:   "do not carry set " + calicoMasq,
		},
		"set the manager could not read": {
			mutate: func(f *HostNetFacts) {
				f.Sets[0] = SavedSetFacts{Name: calicoMasq, State: FactsUnreadable, Reason: "exit status 1: The set with the given name does not exist"}
			},
			want: "read set " + calicoMasq + ": exit status 1",
		},
		"set listing of another set": {
			mutate: func(f *HostNetFacts) { f.Sets[0].Saved = "create other hash:net family inet\nadd other 10.0.0.0/8\n" },
			want:   "not for " + calicoMasq,
		},
		"set of another type": {
			mutate: func(f *HostNetFacts) {
				f.Sets[0].Saved = "create " + calicoMasq + " hash:net,port family inet\nadd " + calicoMasq + " 192.168.0.0/16,tcp:80\n"
			},
			want: "type hash:net,port, which is not understood",
		},
		// Review finding 2, through the receipt: the member is one address
		// outside the tunnel range, and the set matches the /10 around it.
		"set that matches whole networks": {
			mutate: func(f *HostNetFacts) {
				f.Sets[0].Saved = "create " + calicoMasq + " hash:ip family inet hashsize 1024 maxelem 65536 netmask 10 bucketsize 12 initval 0x1\nadd " + calicoMasq + " 100.64.0.0\n"
			},
			want: "set " + calicoMasq + " has netmask 10: its members match whole networks",
		},
		"set with a bitmask": {
			mutate: func(f *HostNetFacts) {
				f.Sets[0].Saved = "create " + calicoMasq + " hash:ip family inet bitmask 255.192.0.0\nadd " + calicoMasq + " 100.64.0.0\n"
			},
			want: "set " + calicoMasq + " has a bitmask",
		},
		"pool overlaps the tunnel range": {
			mutate: func(f *HostNetFacts) { f.Sets[0].Saved += "add " + calicoMasq + " 100.64.0.0/10\n" },
			want:   "which overlaps the tunnel range 100.96.0.0/24",
		},
		"rule text says the match is on the destination": {
			mutate: func(f *HostNetFacts) { replaceRule(&f.NAT, calicoMasq+" src", calicoMasq+" dst") },
			want:   "can rewrite the source",
		},
		"rule text says the match is negated": {
			mutate: func(f *HostNetFacts) {
				replaceRule(&f.NAT, "-m set --match-set "+calicoMasq, "-m set ! --match-set "+calicoMasq)
			},
			want: "can rewrite the source",
		},
		"rule text names a set that is not carried": {
			mutate: func(f *HostNetFacts) { replaceRule(&f.NAT, calicoMasq+" src", "cali40other src") },
			want:   "do not carry set cali40other",
		},
		"rule text lost a rule": {
			mutate: func(f *HostNetFacts) { f.Mangle.Chains[0].Rules = f.Mangle.Chains[0].Rules[1:] },
			want:   "cannot be read",
		},
		"rule text gained a rule": {
			mutate: func(f *HostNetFacts) {
				f.NAT.Chains[0].Rules = append(f.NAT.Chains[0].Rules, "-A cali-nat-outgoing -j RETURN")
			},
			want: "cannot be read",
		},
		"rule text ends in another target": {
			mutate: func(f *HostNetFacts) { replaceRule(&f.NAT, "-j MASQUERADE --random-fully", "-j RETURN") },
			want:   "does not pair",
		},
		"mark that selects a masquerade": {
			mutate: func(f *HostNetFacts) { replaceRule(&f.Mangle, "0x0/0x1b0000", "0x4000/0x4000") },
			want:   "can set a Kubernetes mark",
		},
		"line of another chain": {
			mutate: func(f *HostNetFacts) {
				f.NAT.Chains[0].Rules[0] = strings.Replace(f.NAT.Chains[0].Rules[0], "-A cali-nat-outgoing ", "-A POSTROUTING ", 1)
			},
			want: "carry a line that is not one of its rules",
		},
		"two lines in one": {
			mutate: func(f *HostNetFacts) { f.NAT.Chains[0].Rules[0] += "\n-A cali-nat-outgoing -j RETURN" },
			want:   "carry a line that is not one of its rules",
		},
		"oversized rule": {
			mutate: func(f *HostNetFacts) { f.NAT.Chains[0].Rules[0] += strings.Repeat(" x", maxSavedRuleBytes) },
			want:   "carry a line that is not one of its rules",
		},
		"oversized facts": {
			mutate: func(f *HostNetFacts) {
				f.Sets[0].Saved += strings.Repeat("add "+calicoMasq+" 10.9.0.0/16\n", maxSetSaveBytes/40)
				f.Sets = append(f.Sets, SavedSetFacts{Name: "zz", State: FactsRead, Saved: strings.Repeat("x", maxSetSaveBytes)})
			},
			want: "host facts exceed bound",
		},
		"unknown state": {
			mutate: func(f *HostNetFacts) { f.Mangle.State = "assumed" },
			want:   "unknown state",
		},
		"sets without NAT text": {
			mutate: func(f *HostNetFacts) { f.NAT = SavedTableFacts{State: FactsNotNeeded, Reason: "none"} },
			want:   "sets without saved nat rules",
		},
		"digest that is not one": {
			mutate: func(f *HostNetFacts) { f.NAT.Chains[0].Listing = "sha256:abc" },
			want:   "lack a listing digest",
		},
	} {
		t.Run(name, func(t *testing.T) {
			facts := liveCalicoHostFacts(t)
			if tc.mutate != nil {
				tc.mutate(&facts)
			}
			source := constantFacts(facts)
			if tc.source != nil {
				source = tc.source(facts)
			}
			f, r := gatewayOnLiveCalico(t, source)
			if tc.gateway != nil {
				tc.gateway(f)
			}
			status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("status %+v, error %v", status, err)
			}
			for _, adapter := range status.Adapters {
				if adapter.State == StateReady {
					t.Fatalf("refused node reports a ready adapter: %+v", status)
				}
			}
			if status.Host.State != StateBlocked || status.Host.Reason != bounded(err.Error(), maxReasonBytes) {
				t.Fatalf("status does not carry the reason: %+v", status)
			}
			for _, command := range f.commands {
				if strings.HasPrefix(command, "DENIED") {
					t.Fatalf("gateway ran a command it cannot run: %v", f.commands)
				}
			}
			if len(f.mutations) != 0 {
				t.Fatalf("refusal mutated: %v", f.mutations)
			}
		})
	}
}

// Decision 4 still holds on the gateway: the facts are taken between two
// listings, and a rule that changes between them refuses the observation.
func TestGatewayStillRefusesRulesThatChangeAroundTheFacts(t *testing.T) {
	facts := liveCalicoHostFacts(t)
	var f *calicoTestKernel
	f, r := gatewayOnLiveCalico(t, func(context.Context) (HostNetFacts, error) {
		f.addRule(nftRuleView{Family: "ip", Table: "nat", Chain: "cali-fip-snat", Expr: []map[string]any{{"return": nil}}}, false)
		return facts, nil
	})
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	if err == nil || !strings.Contains(err.Error(), "CNI rules changed across semantic observation") {
		t.Fatalf("%+v %v", status, err)
	}
}

// Without a facts source nothing changed: the reconciler reads by itself, as
// the manager's own reconciler and every non-Kubernetes caller do.
func TestReconcilerWithoutHostFactsStillReadsDirectly(t *testing.T) {
	f, r := liveCalicoKernel(t)
	if r.hostFacts != nil {
		t.Fatal("a facts source is set by default")
	}
	if _, err := r.Reconcile(t.Context(), "100.96.0.0/24"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.commands, "\n")
	if !strings.Contains(joined, "iptables-nft-save -t nat") || !strings.Contains(joined, "iptables-nft-save -t mangle") || !strings.Contains(joined, "ipset save "+calicoMasq) {
		t.Fatalf("direct reads did not run: %v", f.commands)
	}
}

// A node whose rules need no fact still takes the receipt, for what it says
// of the node (legacy tables, K8N review finding 5): Flannel is ready on a
// receipt that carries no rule text and no set, and reads no set. Before the
// review such a node never asked and was ready with no receipt at all; that
// case is now refused (TestGatewayTakesTheReceiptOnEveryObservation).
func TestGatewayNeedsOnlyTheReceiptOnANodeThatNeedsNoRuleFacts(t *testing.T) {
	listing, err := os.ReadFile("testdata/k3s-flannel-nat.json")
	if err != nil {
		t.Fatal(err)
	}
	f, r := newCalicoTestKernel(t, nil, "")
	if err := json.Unmarshal(listing, &f.doc); err != nil {
		t.Fatal(err)
	}
	asked := false
	r.UseHostFacts(func(context.Context) (HostNetFacts, error) {
		asked = true
		return HostNetFacts{
			NAT:            SavedTableFacts{State: FactsNotNeeded, Reason: "the kernel has no ipset, so no NAT rule can match one"},
			Mangle:         SavedTableFacts{State: FactsUnreadable, Reason: "not needed by this node"},
			LegacyIPTables: LegacyTablesFacts{State: FactsRead},
		}, nil
	})
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	if err != nil || !asked || status.Adapters[0].Name != ObservedAdapterName || status.Adapters[0].State != StateReady {
		t.Fatalf("asked=%v status=%+v err=%v", asked, status, err)
	}
	if len(f.setReads) != 0 {
		t.Fatalf("read sets: %v", f.setReads)
	}
}

func TestClosedFactsRunnersRefuseEverythingElse(t *testing.T) {
	for _, args := range [][]string{
		{"-j", "-a", "list", "ruleset"},
		{"-j", "-a", "list", "tables", "ip"},
		{"list", "tables"},
		{"-j", "-a", "list", "chain", "ip", "filter", "INPUT"},
		{"-j", "-a", "list", "chain", "ip6", "nat", "POSTROUTING"},
		{"-j", "-a", "list", "chain", "ip", "nat", "x;flush ruleset"},
		{"-j", "-a", "list", "chain", "ip", "nat", "-f"},
		{"flush", "ruleset"},
		{"-j", "-a", "list", "chain", "ip", "nat", "POSTROUTING", "extra"},
	} {
		if _, err := realFactsNFTRunner(t.Context(), args...); err == nil || err.Error() != "unsupported nft inspection" {
			t.Errorf("nft %v: %v", args, err)
		}
	}
	for _, args := range [][]string{{"list"}, {"list", "-n", "x"}, {"flush"}, {"destroy", "x"}, {"save"}, {"save", "-x"}, {"add", "x", "1.1.1.1"}} {
		if _, err := realFactsIPSetRunner(t.Context(), args...); err == nil || err.Error() != "unsupported ipset inspection" {
			t.Errorf("ipset %v: %v", args, err)
		}
	}
}

// Review finding 7. The members are read between two listings of the kernel's
// set names. A set created, renamed or removed meanwhile makes the reader start
// the table over; if that keeps happening the NAT facts are unreadable, which
// the gateway refuses. Before the fix the members were published as read.
func TestHostFactsReaderRereadsSetNamesAfterTheMembers(t *testing.T) {
	// Every member read renames a set: the names never settle.
	f, reader := liveCalicoFactsReader(t)
	renames := 0
	var churn func()
	churn = func() {
		renames++
		old := fmt.Sprintf("renamed-%d", renames-1)
		if renames == 1 {
			old = "spare"
		}
		f.sets[fmt.Sprintf("renamed-%d", renames)] = f.sets[old]
		delete(f.sets, old)
		f.onIPSet = churn
	}
	f.sets["spare"] = "create spare hash:net family inet\n"
	f.onIPSet = churn
	facts := reader.Read(t.Context())
	if facts.NAT.State != FactsUnreadable || facts.NAT.Reason != "kernel sets were created, renamed or removed while they were read" || len(facts.Sets) != 0 {
		t.Fatalf("nat = %+v, sets = %+v", facts.NAT, facts.Sets)
	}
	// The first attempt of a new reader finds the chains to carry; every
	// later one reads the members and starts over.
	if renames != maxFactReadAttempts-1 {
		t.Fatalf("read the members %d times, want %d", renames, maxFactReadAttempts-1)
	}
	_, r := gatewayOnLiveCalico(t, constantFacts(facts))
	if status, err := r.Reconcile(t.Context(), "100.96.0.0/24"); err == nil || !strings.Contains(err.Error(), "kernel sets were created, renamed or removed") {
		t.Fatalf("gateway on churning sets: %+v %v", status, err)
	}

	// The scenario of the finding: while the members are read, the set is
	// renamed away and a set with the old name and other members takes its
	// place. The read starts over and publishes the members the name has once
	// the names settle. (On a real node the kernel refuses to rename a set a
	// rule holds; see readSets.)
	f, reader = liveCalicoFactsReader(t)
	original := f.sets[calicoMasq]
	f.onIPSet = func() {
		f.onIPSet = nil
		f.sets["cali40masq-old"] = original
		f.sets[calicoMasq] = "create " + calicoMasq + " hash:net family inet\nadd " + calicoMasq + " 172.16.0.0/12\n"
	}
	facts = reader.Read(t.Context())
	if facts.NAT.State != FactsRead || len(facts.Sets) != 1 || !strings.Contains(facts.Sets[0].Saved, "172.16.0.0/12") {
		t.Fatalf("nat = %+v, sets = %+v", facts.NAT, facts.Sets)
	}
	if !reflect.DeepEqual(f.setReads, []string{calicoMasq, calicoMasq}) {
		t.Fatalf("sets read = %v", f.setReads)
	}

	// The names cannot be listed again: unreadable, never published.
	f, reader = liveCalicoFactsReader(t)
	f.onIPSet = func() { f.onIPSet = nil; f.setErr = errors.New("exit status 1: Kernel error") }
	if facts := reader.Read(t.Context()); facts.NAT.State != FactsUnreadable || !strings.Contains(facts.NAT.Reason, "list kernel sets") || len(facts.Sets) != 0 {
		t.Fatalf("nat = %+v, sets = %+v", facts.NAT, facts.Sets)
	}
}

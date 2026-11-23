package hostposture

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

// K8N-2: the `cilium` section of the host-facts receipt. It is under the same
// identity, freshness and digest as the rest of the receipt, and a node
// without Cilium publishes the receipt exactly as before.

const testCiliumDump = `[{"key":["0x18","0x00","0x00","0x00","0x64","0x60","0x00","0x00"],"value":["0x00"]}]`

func testCiliumFacts() *k8snetprep.CiliumFacts {
	return &k8snetprep.CiliumFacts{
		Status: k8snetprep.CiliumTextFact{State: k8snetprep.FactsRead,
			Text: `{"masquerading":{"enabled":true,"enabledProtocols":{"ipv4":true},"ip-masq-agent":true,"mode":"BPF","snat-exclusion-cidr":"10.244.0.0/16","snat-exclusion-cidr-v4":"10.244.0.0/16"}}`},
		PinnedMaps: k8snetprep.CiliumPinFacts{State: k8snetprep.FactsRead, Total: 47},
		IPMasqMap:  k8snetprep.CiliumTextFact{State: k8snetprep.FactsRead, Text: testCiliumDump},
	}
}

func saveTestCiliumReceipt(t *testing.T, store *Store, heartbeat Heartbeat, observedAt time.Time) HostFacts {
	t.Helper()
	receipt, err := SealHostFactsWithCilium(heartbeat, observedAt, testNetFacts(), testCiliumFacts())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveHeartbeat(heartbeat); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveHostFacts(receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestCiliumSectionIsTakenOnlyWithItsLiveHeartbeat(t *testing.T) {
	now := time.Unix(5000, 0).UTC()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	saveTestCiliumReceipt(t, store, cniTestHeartbeat(now, 9), now.Add(-time.Second))
	gateway, err := OpenStore(store.dir)
	if err != nil {
		t.Fatal(err)
	}
	section, err := gateway.CiliumFacts("worker-a", now)
	if err != nil || !reflect.DeepEqual(section, testCiliumFacts()) {
		t.Fatalf("section = %+v, %v", section, err)
	}
	// The rest of the receipt is taken as before.
	if facts, err := gateway.HostNetFacts("worker-a", now); err != nil || facts.Sets[0].Name != "cali40masq-ipam-pools" {
		t.Fatalf("netfilter facts = %+v, %v", facts, err)
	}

	for name, tc := range map[string]struct {
		node      string
		now       time.Time
		heartbeat func(*Heartbeat)
		receipt   func(*HostFacts)
		want      string
	}{
		"another node asks":       {node: "worker-b", want: "heartbeat identity is invalid"},
		"receipt of another node": {receipt: func(r *HostFacts) { r.NodeName = "worker-b" }, want: "from another node"},
		"receipt of another manager": {
			receipt: func(r *HostFacts) { r.ManagerUID = "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee" },
			want:    "another host-posture manager process",
		},
		"manager restarted since the receipt": {
			heartbeat: func(h *Heartbeat) { h.ManagerBootID = "22222222222222222222222222222222"; h.Sequence = 1 },
			want:      "another host-posture manager process",
		},
		"receipt of an earlier pass": {heartbeat: func(h *Heartbeat) { h.Sequence = 10 }, want: "does not belong to the live heartbeat"},
		"facts read too long ago": {
			receipt: func(r *HostFacts) { r.ObservedAt = now.Add(-HostFactsFreshness - time.Second) },
			want:    "stale or from the future",
		},
		"facts from the future": {receipt: func(r *HostFacts) { r.ObservedAt = now.Add(3 * time.Second) }, want: "stale or from the future"},
		"heartbeat gone stale":  {now: now.Add(HeartbeatFreshness + time.Second), want: "heartbeat is stale"},
		"heartbeat blocked": {
			heartbeat: func(h *Heartbeat) { h.State = HeartbeatBlocked },
			want:      "require an active host-posture heartbeat",
		},
		// Re-sealed with a matching digest, so the section's own rules refuse.
		"section with an unknown state": {
			receipt: func(r *HostFacts) { r.Cilium.Status.State = "partial" },
			want:    "host facts for Cilium status have an unknown state",
		},
		"section over its bound": {
			receipt: func(r *HostFacts) {
				r.Cilium.IPMasqMap.Text = strings.Repeat("x", k8snetprep.MaxCiliumMapFactBytes+1)
			},
			want: "host facts for Cilium ip-masq-agent map exceed bound",
		},
		"egress map of another name": {
			receipt: func(r *HostFacts) { r.Cilium.PinnedMaps.EgressGateway = []string{"cilium_egresscall_policy"} },
			want:    "host facts for Cilium pinned maps name an invalid",
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			heartbeat := cniTestHeartbeat(now, 9)
			receipt := saveTestCiliumReceipt(t, store, heartbeat, now.Add(-time.Second))
			if tc.heartbeat != nil {
				tc.heartbeat(&heartbeat)
				if err := store.SaveHeartbeat(heartbeat); err != nil {
					t.Fatal(err)
				}
			}
			if tc.receipt != nil {
				tc.receipt(&receipt)
				digest, err := hostFactsDigest(receipt)
				if err != nil {
					t.Fatal(err)
				}
				receipt.Digest = digest
				if err := store.SaveHostFacts(receipt); err != nil {
					t.Fatal(err)
				}
			}
			node, at := "worker-a", now
			if tc.node != "" {
				node = tc.node
			}
			if !tc.now.IsZero() {
				at = tc.now
			}
			if section, err := store.CiliumFacts(node, at); err == nil || section != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("section = %+v, error = %v, want %q", section, err, tc.want)
			}
		})
	}
}

// The digest covers the section: a file whose Cilium facts were edited, cut or
// removed after sealing is refused as damaged, for both kinds of facts.
func TestCiliumSectionEditedAfterSealingIsRefused(t *testing.T) {
	now := time.Unix(5000, 0).UTC()
	for name, edit := range map[string]func([]byte) []byte{
		"a range added to the map": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`\"0x18\"`), []byte(`\"0x08\"`), 1)
		},
		"mode rewritten": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`\"mode\":\"BPF\"`), []byte(`\"mode\":\"iptables\"`), 1)
		},
		"ip-masq-agent flag removed": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`\"ip-masq-agent\":true,`), nil, 1)
		},
		"section removed": func(raw []byte) []byte {
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			delete(doc, "cilium")
			out, _ := json.Marshal(doc)
			return out
		},
		"map fact swapped for not needed": func(raw []byte) []byte {
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			section := testCiliumFacts()
			section.IPMasqMap = k8snetprep.CiliumTextFact{State: k8snetprep.FactsNotNeeded, Reason: "the agent reports that its ip-masq-agent is off"}
			doc["cilium"], _ = json.Marshal(section)
			out, _ := json.Marshal(doc)
			return out
		},
	} {
		store, err := NewStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		saveTestCiliumReceipt(t, store, cniTestHeartbeat(now, 9), now.Add(-time.Second))
		raw, err := os.ReadFile(store.HostFactsPath())
		if err != nil {
			t.Fatal(err)
		}
		edited := edit(raw)
		if bytes.Equal(edited, raw) {
			t.Fatalf("%s: the edit changed nothing", name)
		}
		if err := os.WriteFile(store.HostFactsPath(), edited, 0o644); err != nil {
			t.Fatal(err)
		}
		if section, err := store.CiliumFacts("worker-a", now); err == nil || section != nil || !strings.Contains(err.Error(), "digest does not match") {
			t.Errorf("%s: section = %+v, error = %v", name, section, err)
		}
		if _, err := store.HostNetFacts("worker-a", now); err == nil || !strings.Contains(err.Error(), "digest does not match") {
			t.Errorf("%s: netfilter facts taken from a damaged receipt: %v", name, err)
		}
	}

	// A member this code does not know is refused when the file is read.
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	saveTestCiliumReceipt(t, store, cniTestHeartbeat(now, 9), now.Add(-time.Second))
	raw, _ := os.ReadFile(store.HostFactsPath())
	if err := os.WriteFile(store.HostFactsPath(), bytes.Replace(raw, []byte(`"pinned_maps":{`), []byte(`"pinned_maps":{"verdict":"ready",`), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CiliumFacts("worker-a", now); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown member accepted: %v", err)
	}
}

// A receipt without the section is the receipt of a node without Cilium, byte
// for byte what it was before K8N-2; the gateway is told there is no section.
func TestReceiptWithoutCiliumSectionIsUnchanged(t *testing.T) {
	now := time.Unix(5000, 0).UTC()
	heartbeat := cniTestHeartbeat(now, 9)
	plain, err := SealHostFacts(heartbeat, now, testNetFacts())
	if err != nil {
		t.Fatal(err)
	}
	same, err := SealHostFactsWithCilium(heartbeat, now, testNetFacts(), nil)
	if err != nil || !reflect.DeepEqual(plain, same) {
		t.Fatalf("%+v %v", same, err)
	}
	encoded, _ := json.Marshal(plain)
	if bytes.Contains(encoded, []byte("cilium")) {
		t.Fatalf("receipt of a node without Cilium names it: %s", encoded)
	}
	withSection, err := SealHostFactsWithCilium(heartbeat, now, testNetFacts(), testCiliumFacts())
	if err != nil || withSection.Digest == plain.Digest {
		t.Fatalf("the digest does not cover the section: %v", err)
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	saveTestHostFacts(t, store, heartbeat, now)
	if section, err := store.CiliumFacts("worker-a", now); err != nil || section != nil {
		t.Fatalf("section = %+v, %v", section, err)
	}
	// No receipt at all is an error, not "no section".
	empty, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := empty.SaveHeartbeat(heartbeat); err != nil {
		t.Fatal(err)
	}
	if section, err := empty.CiliumFacts("worker-a", now); err == nil || section != nil || !strings.Contains(err.Error(), "host facts receipt is missing") {
		t.Fatalf("section = %+v, %v", section, err)
	}
}

func TestSealNeverCutsACiliumSectionThatDoesNotFit(t *testing.T) {
	now := time.Unix(5000, 0).UTC()
	heartbeat := cniTestHeartbeat(now, 3)

	// A malformed section is stated as unreadable, never published as it is.
	bad := testCiliumFacts()
	bad.IPMasqMap.Text = strings.Repeat("x", k8snetprep.MaxCiliumMapFactBytes+1)
	receipt, err := SealHostFactsWithCilium(heartbeat, now, testNetFacts(), bad)
	if err != nil || receipt.Cilium.Status.State != k8snetprep.FactsUnreadable || !strings.Contains(receipt.Cilium.Status.Reason, "exceed bound") || receipt.Cilium.IPMasqMap.Text != "" {
		t.Fatalf("%+v %v", receipt.Cilium, err)
	}
	if receipt.Netfilter.NAT.State != k8snetprep.FactsRead {
		t.Fatalf("a bad Cilium section took the netfilter facts with it: %+v", receipt.Netfilter)
	}

	// Both kinds of facts at their bounds, escaped, do not fit the file: both
	// are replaced by the statement, and the receipt still validates.
	facts := testNetFacts()
	facts.Sets[0].Saved = strings.Repeat("\x01", k8snetprep.MaxHostNetFactsBytes-1024)
	receipt, err = SealHostFactsWithCilium(heartbeat, now, facts, testCiliumFacts())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Netfilter.NAT.State != k8snetprep.FactsUnreadable || receipt.Cilium.Status.State != k8snetprep.FactsUnreadable || !strings.Contains(receipt.Cilium.IPMasqMap.Reason, "host facts exceed") {
		t.Fatalf("oversized receipt sealed as %+v / %+v", receipt.Netfilter, receipt.Cilium)
	}
	if err := validateHostFacts(receipt, heartbeat, "worker-a", now); err != nil {
		t.Fatal(err)
	}

	// The largest valid section fits beside small netfilter facts.
	entry := `{"key":["0x18","0x00","0x00","0x00","0x64","0x60","0x00","0x00"],"value":["0x00"]}`
	full := testCiliumFacts()
	full.IPMasqMap.Text = "[" + strings.Repeat(entry+",", (k8snetprep.MaxCiliumMapFactBytes-len(entry)-2)/(len(entry)+1)) + entry + "]"
	receipt, err = SealHostFactsWithCilium(heartbeat, now, testNetFacts(), full)
	if err != nil || receipt.Cilium.IPMasqMap.State != k8snetprep.FactsRead || receipt.Netfilter.NAT.State != k8snetprep.FactsRead {
		t.Fatalf("%+v %v", receipt.Cilium.IPMasqMap.State, err)
	}
}

type fakeCiliumReader struct {
	facts *k8snetprep.CiliumFacts
	reads int
	check func()
}

func (f *fakeCiliumReader) Read(context.Context) *k8snetprep.CiliumFacts {
	f.reads++
	if f.check != nil {
		f.check()
	}
	return f.facts
}

func TestManagerPublishesTheCiliumSectionWithEveryActiveHeartbeat(t *testing.T) {
	source := &fakeOwnerSource{owners: []Owner{testOwner()}}
	store := &fakePostureStore{}
	manager := newTestManager(t, source, store, &fakeKernel{})
	manager.SetHostFactsReader(&fakeFactsReader{facts: testNetFacts()})
	cilium := &fakeCiliumReader{facts: testCiliumFacts()}
	cilium.check = func() {
		if store.lockHeld {
			t.Error("Cilium facts were read while holding the CNI operation lock")
		}
	}
	manager.SetCiliumFactsReader(cilium)

	for pass := 1; pass <= 2; pass++ {
		if err := manager.ReconcileOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
		if cilium.reads != pass || len(store.facts) != pass {
			t.Fatalf("pass %d: reads=%d receipts=%d", pass, cilium.reads, len(store.facts))
		}
		receipt := store.facts[pass-1]
		if err := validateHostFacts(receipt, store.heartbeat, "worker-a", time.Unix(1234, 0)); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if !reflect.DeepEqual(receipt.Cilium, testCiliumFacts()) || receipt.Sequence != store.heartbeat.Sequence {
			t.Fatalf("pass %d: receipt %+v", pass, receipt)
		}
	}
	// The section follows the node: once the reader sees no Cilium, the next
	// receipt has none, and the earlier one belongs to an earlier pass.
	cilium.facts = nil
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if last := store.facts[len(store.facts)-1]; last.Cilium != nil || last.Netfilter.NAT.State != k8snetprep.FactsRead {
		t.Fatalf("receipt = %+v", last)
	}
	if err := validateHostFacts(store.facts[1], store.heartbeat, "worker-a", time.Unix(1234, 0)); err == nil {
		t.Fatal("the section of an earlier pass was accepted for the live heartbeat")
	}
}

func TestManagerReadsNoCiliumFactsWhereNoGatewayRuns(t *testing.T) {
	cilium := &fakeCiliumReader{facts: testCiliumFacts()}
	store := &fakePostureStore{}
	manager := newTestManager(t, &fakeOwnerSource{}, store, &fakeKernel{})
	manager.SetHostFactsReader(&fakeFactsReader{facts: testNetFacts()})
	manager.SetCiliumFactsReader(cilium)
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if cilium.reads != 0 || len(store.facts) != 0 {
		t.Fatalf("idle node: reads=%d receipts=%d", cilium.reads, len(store.facts))
	}
}

package hostposture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

// K8N-1, Decision 9: the receipt that carries the manager's reads to a gateway.

func testNetFacts() k8snetprep.HostNetFacts {
	return k8snetprep.HostNetFacts{
		NAT: k8snetprep.SavedTableFacts{State: k8snetprep.FactsRead, Chains: []k8snetprep.SavedChainFacts{{
			Name: "cali-nat-outgoing", Listing: strings.Repeat("ab", 32),
			Rules: []string{`-A cali-nat-outgoing -m set --match-set cali40masq-ipam-pools src -j MASQUERADE --random-fully`},
		}}},
		Mangle: k8snetprep.SavedTableFacts{State: k8snetprep.FactsRead},
		Sets: []k8snetprep.SavedSetFacts{{Name: "cali40masq-ipam-pools", State: k8snetprep.FactsRead,
			Saved: "create cali40masq-ipam-pools hash:net family inet\nadd cali40masq-ipam-pools 192.168.0.0/16\n"}},
		LegacyIPTables: k8snetprep.LegacyTablesFacts{State: k8snetprep.FactsRead},
	}
}

func saveTestHostFacts(t *testing.T, store *Store, heartbeat Heartbeat, observedAt time.Time) HostFacts {
	t.Helper()
	receipt, err := SealHostFacts(heartbeat, observedAt, testNetFacts())
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

func TestHostFactsAreTakenOnlyWithTheirLiveHeartbeat(t *testing.T) {
	now := time.Unix(5000, 0).UTC()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	saveTestHostFacts(t, store, cniTestHeartbeat(now, 9), now.Add(-time.Second))

	// The gateway's view of the same directory is read-only and cannot publish.
	gateway, err := OpenStore(store.dir)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := gateway.HostNetFacts("worker-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if want := testNetFacts(); facts.NAT.Chains[0].Rules[0] != want.NAT.Chains[0].Rules[0] || facts.Sets[0].Saved != want.Sets[0].Saved {
		t.Fatalf("facts = %+v", facts)
	}
	if err := gateway.SaveHostFacts(HostFacts{}); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only store published host facts: %v", err)
	}
	if info, err := os.Stat(store.HostFactsPath()); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("receipt mode = %v %v", info, err)
	}

	for name, tc := range map[string]struct {
		node      string
		now       time.Time
		heartbeat func(*Heartbeat)
		receipt   func(*HostFacts)
		want      string
	}{
		"another node asks": {node: "worker-b", want: "heartbeat identity is invalid"},
		"receipt of another node": {
			receipt: func(r *HostFacts) { r.NodeName = "worker-b" },
			want:    "from another node",
		},
		"receipt of another manager": {
			receipt: func(r *HostFacts) { r.ManagerUID = "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee" },
			want:    "another host-posture manager process",
		},
		"receipt of an earlier manager process": {
			receipt: func(r *HostFacts) { r.ManagerBootID = "22222222222222222222222222222222" },
			want:    "another host-posture manager process",
		},
		"manager restarted since the receipt": {
			heartbeat: func(h *Heartbeat) { h.ManagerBootID = "22222222222222222222222222222222"; h.Sequence = 1 },
			want:      "another host-posture manager process",
		},
		"receipt of an earlier pass": {
			heartbeat: func(h *Heartbeat) { h.Sequence = 10 },
			want:      "does not belong to the live heartbeat",
		},
		"receipt of a later pass": {
			receipt: func(r *HostFacts) { r.Sequence = 10 },
			want:    "does not belong to the live heartbeat",
		},
		"facts read too long ago": {
			receipt: func(r *HostFacts) { r.ObservedAt = now.Add(-HostFactsFreshness - time.Second) },
			want:    "stale or from the future",
		},
		"facts from the future": {
			receipt: func(r *HostFacts) { r.ObservedAt = now.Add(3 * time.Second) },
			want:    "stale or from the future",
		},
		"facts with no time": {
			receipt: func(r *HostFacts) { r.ObservedAt = time.Time{} },
			want:    "stale or from the future",
		},
		"heartbeat gone stale": {now: now.Add(HeartbeatFreshness + time.Second), want: "heartbeat is stale"},
		"heartbeat blocked": {
			heartbeat: func(h *Heartbeat) { h.State = HeartbeatBlocked },
			want:      "require an active host-posture heartbeat",
		},
		"heartbeat idle": {
			heartbeat: func(h *Heartbeat) { h.State, h.Owners = HeartbeatIdle, nil },
			want:      "require an active host-posture heartbeat",
		},
		"unknown schema": {
			receipt: func(r *HostFacts) { r.SchemaVersion = 2 },
			want:    "unknown schema or contract",
		},
		"another contract": {
			receipt: func(r *HostFacts) { r.Contract = CNIAuthorityContract },
			want:    "unknown schema or contract",
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			heartbeat := cniTestHeartbeat(now, 9)
			receipt := saveTestHostFacts(t, store, heartbeat, now.Add(-time.Second))
			if tc.heartbeat != nil {
				tc.heartbeat(&heartbeat)
				if err := store.SaveHeartbeat(heartbeat); err != nil {
					t.Fatal(err)
				}
			}
			if tc.receipt != nil {
				// Re-sealed: the refusal must come from the binding itself, not
				// from a digest that no longer matches.
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
			if _, err := store.HostNetFacts(node, at); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestHostFactsFileThatIsMissingDamagedOrTooLargeIsRefused(t *testing.T) {
	now := time.Unix(5000, 0).UTC()
	rewrite := func(edit func([]byte) []byte) func(*testing.T, *Store) {
		return func(t *testing.T, store *Store) {
			body, err := os.ReadFile(store.HostFactsPath())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(store.HostFactsPath(), edit(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, tc := range map[string]struct {
		damage func(*testing.T, *Store)
		want   string
	}{
		"missing": {
			damage: func(t *testing.T, store *Store) {
				if err := os.Remove(store.HostFactsPath()); err != nil {
					t.Fatal(err)
				}
			},
			want: "host facts receipt is missing",
		},
		"empty": {damage: rewrite(func([]byte) []byte { return nil }), want: "read host facts receipt"},
		"truncated": {
			damage: rewrite(func(body []byte) []byte { return body[:len(body)/2] }),
			want:   "read host facts receipt",
		},
		"truncated before the last brace": {
			damage: rewrite(func(body []byte) []byte { return bytes.TrimRight(body, "}\n") }),
			want:   "read host facts receipt",
		},
		"second value appended": {
			damage: rewrite(func(body []byte) []byte { return append(body, body...) }),
			want:   "trailing JSON value",
		},
		"unknown field": {
			damage: rewrite(func(body []byte) []byte {
				return bytes.Replace(body, []byte(`{"schema_version"`), []byte(`{"verdict":"ready","schema_version"`), 1)
			}),
			want: "unknown field",
		},
		// One word of a rule is changed and the digest is left as it was.
		"rule text edited": {
			damage: rewrite(func(body []byte) []byte {
				return bytes.Replace(body, []byte("cali40masq-ipam-pools src"), []byte("cali40masq-ipam-pools dst"), 1)
			}),
			want: "damaged: its digest does not match",
		},
		"set member edited": {
			damage: rewrite(func(body []byte) []byte {
				return bytes.Replace(body, []byte("192.168.0.0/16"), []byte("192.168.0.0/24"), 1)
			}),
			want: "damaged: its digest does not match",
		},
		"sequence edited": {
			damage: rewrite(func(body []byte) []byte {
				return bytes.Replace(body, []byte(`"sequence":9`), []byte(`"sequence":8`), 1)
			}),
			want: "does not belong to the live heartbeat",
		},
		"time edited": {
			damage: rewrite(func(body []byte) []byte {
				return bytes.Replace(body, []byte(`"observed_at":"1970-01-01T01:23:19Z"`), []byte(`"observed_at":"1970-01-01T01:23:20Z"`), 1)
			}),
			want: "damaged: its digest does not match",
		},
		"digest removed": {
			damage: rewrite(func(body []byte) []byte {
				var receipt HostFacts
				if err := json.Unmarshal(body, &receipt); err != nil {
					panic(err)
				}
				receipt.Digest = ""
				out, _ := json.Marshal(receipt)
				return out
			}),
			want: "damaged: its digest does not match",
		},
		"larger than the bound": {
			damage: rewrite(func(body []byte) []byte { return append(body, bytes.Repeat([]byte(" "), maxHostFacts)...) }),
			want:   "not a bounded regular file",
		},
		"symlink": {
			damage: func(t *testing.T, store *Store) {
				real := store.HostFactsPath() + ".real"
				if err := os.Rename(store.HostFactsPath(), real); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(real, store.HostFactsPath()); err != nil {
					t.Fatal(err)
				}
			},
			want: "not a bounded regular file",
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			saveTestHostFacts(t, store, cniTestHeartbeat(now, 9), now.Add(-time.Second))
			if _, err := store.HostNetFacts("worker-a", now); err != nil {
				t.Fatalf("undamaged receipt refused: %v", err)
			}
			tc.damage(t, store)
			if _, err := store.HostNetFacts("worker-a", now); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSealHostFactsNeverCutsWhatDoesNotFit(t *testing.T) {
	now := time.Unix(5000, 0).UTC()
	heartbeat := cniTestHeartbeat(now, 3)

	// Text that is within the facts bound but, escaped, would not fit the file.
	facts := testNetFacts()
	facts.Sets[0].Saved = strings.Repeat("\x01", k8snetprep.MaxHostNetFactsBytes-1024)
	if err := facts.Validate(); err != nil {
		t.Fatal(err)
	}
	receipt, err := SealHostFacts(heartbeat, now, facts)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Netfilter.NAT.State != k8snetprep.FactsUnreadable || !strings.Contains(receipt.Netfilter.NAT.Reason, "host facts exceed") || len(receipt.Netfilter.Sets) != 0 {
		t.Fatalf("oversized facts sealed as %+v", receipt.Netfilter)
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveHeartbeat(heartbeat); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveHostFacts(receipt); err != nil {
		t.Fatal(err)
	}
	if got, err := store.HostNetFacts("worker-a", now); err != nil || got.Mangle.State != k8snetprep.FactsUnreadable {
		t.Fatalf("%+v %v", got, err)
	}

	// Malformed facts are stated as unreadable, never published as they are.
	bad := testNetFacts()
	bad.NAT.Chains[0].Rules[0] = "-A POSTROUTING -j ACCEPT"
	receipt, err = SealHostFacts(heartbeat, now, bad)
	if err != nil || receipt.Netfilter.NAT.State != k8snetprep.FactsUnreadable || !strings.Contains(receipt.Netfilter.NAT.Reason, "not one of its rules") {
		t.Fatalf("%+v %v", receipt.Netfilter, err)
	}

	// The store refuses to write a receipt beyond its bound.
	huge := HostFacts{Digest: strings.Repeat("x", maxHostFacts)}
	if err := store.SaveHostFacts(huge); err == nil || !strings.Contains(err.Error(), "exceeds bounded size") {
		t.Fatalf("oversized receipt written: %v", err)
	}
}

// The receipt holds rule text and set members under fixed keys, and nothing else.
func TestHostFactsReceiptHasAClosedShape(t *testing.T) {
	now := time.Unix(5000, 0).UTC()
	receipt, err := SealHostFacts(cniTestHeartbeat(now, 3), now, testNetFacts())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &top); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema_version", "contract", "node_name", "manager_uid", "manager_boot_id", "sequence", "observed_at", "netfilter", "digest"} {
		if _, ok := top[key]; !ok {
			t.Errorf("receipt lacks %s", key)
		}
		delete(top, key)
	}
	if len(top) != 0 {
		t.Fatalf("receipt carries more than its contract: %v", top)
	}
	// No owner, no pod identity of a gateway, no tunnel range: the manager
	// does not know the range and the facts are the same for every gateway.
	for _, word := range []string{testOwner().UID, testOwner().Name, testOwner().Namespace, "owners", "tunnel"} {
		if bytes.Contains(encoded, []byte(word)) {
			t.Errorf("receipt contains %q", word)
		}
	}
}

type fakeFactsReader struct {
	facts k8snetprep.HostNetFacts
	reads int
	check func()
}

func (f *fakeFactsReader) Read(context.Context) k8snetprep.HostNetFacts {
	f.reads++
	if f.check != nil {
		f.check()
	}
	return f.facts
}

func TestManagerPublishesHostFactsWithEveryActiveHeartbeat(t *testing.T) {
	source := &fakeOwnerSource{owners: []Owner{testOwner()}}
	store := &fakePostureStore{}
	manager := newTestManager(t, source, store, &fakeKernel{})
	reader := &fakeFactsReader{facts: testNetFacts()}
	// The read only observes: like the API read it must not hold the lock.
	reader.check = func() {
		if store.lockHeld {
			t.Error("host facts were read while holding the CNI operation lock")
		}
	}
	manager.SetHostFactsReader(reader)

	for pass := 1; pass <= 2; pass++ {
		if err := manager.ReconcileOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
		if reader.reads != pass || len(store.facts) != pass {
			t.Fatalf("pass %d: reads=%d receipts=%d", pass, reader.reads, len(store.facts))
		}
		receipt := store.facts[pass-1]
		if err := validateHostFacts(receipt, store.heartbeat, "worker-a", time.Unix(1234, 0)); err != nil {
			t.Fatalf("pass %d: published receipt does not match its heartbeat: %v", pass, err)
		}
		if receipt.Sequence != store.heartbeat.Sequence || receipt.Sequence != store.authority.Sequence || !receipt.ObservedAt.Equal(time.Unix(1234, 0)) {
			t.Fatalf("pass %d: receipt %+v heartbeat %+v", pass, receipt, store.heartbeat)
		}
	}
	// The receipt of the first pass is not the receipt of the second heartbeat.
	if err := validateHostFacts(store.facts[0], store.heartbeat, "worker-a", time.Unix(1234, 0)); err == nil {
		t.Fatal("receipt of an earlier pass accepted for the live heartbeat")
	}
}

func TestManagerReadsNoHostFactsWhereNoGatewayRuns(t *testing.T) {
	reader := &fakeFactsReader{facts: testNetFacts()}
	store := &fakePostureStore{}
	manager := newTestManager(t, &fakeOwnerSource{}, store, &fakeKernel{})
	manager.SetHostFactsReader(reader)
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if reader.reads != 0 || len(store.facts) != 0 || store.heartbeat.State != HeartbeatIdle {
		t.Fatalf("idle node: reads=%d receipts=%d heartbeat=%s", reader.reads, len(store.facts), store.heartbeat.State)
	}

	// Without a reader nothing is published and nothing else changes.
	store = &fakePostureStore{}
	manager = newTestManager(t, &fakeOwnerSource{owners: []Owner{testOwner()}}, store, &fakeKernel{})
	if err := manager.ReconcileOnce(t.Context()); err != nil || len(store.facts) != 0 || store.authority.State != CNIAuthorityGranted {
		t.Fatalf("no reader: %v receipts=%d authority=%s", err, len(store.facts), store.authority.State)
	}
}

func TestManagerPublishesNoHostFactsWhenBlockedAndReportsAFailedWrite(t *testing.T) {
	reader := &fakeFactsReader{facts: testNetFacts()}
	store := &fakePostureStore{}
	kernel := &fakeKernel{enforceErr: errors.New("injected enforce failure")}
	manager := newTestManager(t, &fakeOwnerSource{owners: []Owner{testOwner()}}, store, kernel)
	manager.SetHostFactsReader(reader)
	if err := manager.ReconcileOnce(t.Context()); err == nil {
		t.Fatal("blocked pass succeeded")
	}
	if store.heartbeat.State != HeartbeatBlocked || len(store.facts) != 0 {
		t.Fatalf("blocked pass published host facts: %s %d", store.heartbeat.State, len(store.facts))
	}

	kernel.enforceErr = nil
	store.factsErr = errors.New("injected write failure")
	if err := manager.ReconcileOnce(t.Context()); err == nil || !strings.Contains(err.Error(), "publish host facts: injected write failure") {
		t.Fatalf("failed receipt write not reported: %v", err)
	}
}

// While the API is failing inside its grace the heartbeat stays active, and so
// do the facts: they are read again and published with that heartbeat.
func TestManagerKeepsPublishingHostFactsThroughAnAPIFault(t *testing.T) {
	reader := &fakeFactsReader{facts: testNetFacts()}
	source := &fakeOwnerSource{owners: []Owner{testOwner()}}
	store := &fakePostureStore{}
	manager := newTestManager(t, source, store, &fakeKernel{})
	manager.SetHostFactsReader(reader)
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	source.err = errors.New("injected API failure")
	if err := manager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.heartbeat.State != HeartbeatActive || len(store.facts) != 2 || store.facts[1].Sequence != store.heartbeat.Sequence {
		t.Fatalf("heartbeat=%s receipts=%d", store.heartbeat.State, len(store.facts))
	}
}

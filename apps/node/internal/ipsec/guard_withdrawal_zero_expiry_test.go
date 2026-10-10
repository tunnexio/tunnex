package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func zeroExpiryGuardIntent() GuardIntent {
	g := guardFixture()
	c := &g.Connections[0]
	c.PermitFor = 60 * time.Second
	c.ReplyIngressIndices = []int{10, 11}
	c.EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: 10, ReqID: 123, Peer: netip.MustParseAddr("192.0.2.20"), UnderlayInterfaceIndex: 2}}
	return g
}

func zeroExpiryObserved(t *testing.T, expected string, inherited bool, change func(map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewBufferString(expected))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, item := range doc["nftables"].([]any) {
		set, ok := item.(map[string]any)["set"].(map[string]any)
		if !ok {
			continue
		}
		elems, _ := set["elem"].([]any)
		for _, raw := range elems {
			count++
			e := raw.(map[string]any)["elem"].(map[string]any)
			e["expires"] = json.Number("0")
			if inherited {
				delete(e, "timeout")
			}
		}
		if change != nil {
			change(set)
		}
	}
	if count == 0 {
		t.Fatal("fixture contains no timed members")
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGuardWithdrawalZeroExpiryKnownOnly(t *testing.T) {
	m, err := RenderGuard(zeroExpiryGuardIntent())
	if err != nil {
		t.Fatal(err)
	}
	links := []GuardInterface{{Name: "tnxi-a", Index: 10}, {Name: "tnxi-b", Index: 11}, {Name: "outer", Index: 2}}
	for _, inherited := range []bool{false, true} {
		observed := zeroExpiryObserved(t, m.ExpectedJSON, inherited, nil)
		if err = VerifyGuardWithdrawal([]byte(m.ExpectedJSON), observed, links); err != nil {
			t.Fatalf("exact known zero-expiry members block withdrawal, inherited=%v: %v", inherited, err)
		}
		if VerifyGuardReadback([]byte(m.ExpectedJSON), observed) == nil || VerifyGuardReadbackWithInterfaces([]byte(m.ExpectedJSON), observed, links) == nil {
			t.Fatal("zero expiry became a positive readback")
		}
		r := &GuardReader{namespace: func() (string, error) { return m.Namespace, nil }, interfaces: func() ([]GuardInterface, error) { return links, nil }, run: func(context.Context, ...string) ([]byte, error) { return observed, nil }}
		if r.Check(context.Background(), m) == nil {
			t.Fatal("GuardReader.Check minted authority from zero expiry")
		}
		if VerifyGuardWithdrawal(observed, observed, links) == nil {
			t.Fatal("observed zero expiry accepted as a trusted rendered template")
		}
	}
	for _, scenario := range []string{"foreign-value", "zero-value", "duplicate", "timeout-change", "set-timeout", "negative", "overlong", "fractional", "string-expiry", "extra-field", "flags", "foreign-name", "no-inherited-expiry"} {
		t.Run(scenario, func(t *testing.T) {
			observed := zeroExpiryObserved(t, m.ExpectedJSON, scenario == "no-inherited-expiry", func(s map[string]any) {
				elems, _ := s["elem"].([]any)
				if len(elems) == 0 {
					return
				}
				e := elems[0].(map[string]any)["elem"].(map[string]any)
				switch scenario {
				case "foreign-value":
					e["val"] = json.Number("999")
				case "zero-value":
					e["val"] = json.Number("0")
				case "duplicate":
					s["elem"] = append(elems, elems[0])
				case "timeout-change":
					e["timeout"] = json.Number("59")
				case "set-timeout":
					s["timeout"] = json.Number("59")
				case "negative":
					e["expires"] = json.Number("-1")
				case "overlong":
					e["expires"] = json.Number("61")
				case "fractional":
					e["expires"] = json.Number("0.5")
				case "string-expiry":
					e["expires"] = "0"
				case "extra-field":
					e["foreign"] = true
				case "flags":
					s["flags"] = []any{}
				case "foreign-name":
					s["name"] = "foreign"
				case "no-inherited-expiry":
					delete(e, "expires")
				}
			})
			if VerifyGuardWithdrawal([]byte(m.ExpectedJSON), observed, links) == nil {
				t.Fatal("unsafe member or descriptor accepted")
			}
		})
	}
	observed := zeroExpiryObserved(t, m.ExpectedJSON, true, nil)
	for scenario, changed := range map[string][]byte{
		"owner":        bytes.ReplaceAll(observed, []byte("tunnex-ipsec:"), []byte("foreign-owner:")),
		"rule":         bytes.ReplaceAll(observed, []byte(`"drop":null`), []byte(`"accept":null`)),
		"priority":     bytes.ReplaceAll(observed, []byte(`"prio":-10`), []byte(`"prio":10`)),
		"extra-object": []byte(strings.TrimSuffix(string(observed), "]}") + `,{"rule":{"family":"inet","table":"tunnex_ipsec","chain":"output_guard","expr":[{"accept":null}]}}]}`),
	} {
		t.Run(scenario, func(t *testing.T) {
			if bytes.Equal(observed, changed) || VerifyGuardWithdrawal([]byte(m.ExpectedJSON), changed, links) == nil {
				t.Fatal("zero expiry hid foreign ownership or rule drift")
			}
		})
	}
}

func TestRuntimeGuardReplacementZeroExpiryPriorOnly(t *testing.T) {
	for _, expireNewReadback := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh-successor", true: "expired-successor"}[expireNewReadback], func(t *testing.T) {
			g := zeroExpiryGuardIntent()
			prior, err := RenderGuard(g)
			if err != nil {
				t.Fatal(err)
			}
			j, err := OpenRuntimeJournal(journalDir(t), g.OwnerID)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			if j.prepareGuard(prior) != nil || j.finishGuard(prior) != nil {
				t.Fatal("prior template")
			}
			g.Revision++
			next, err := RenderGuard(g)
			if err != nil {
				t.Fatal(err)
			}
			current := zeroExpiryObserved(t, prior.ExpectedJSON, true, nil)
			writes := 0
			r := &GuardReader{namespace: func() (string, error) { return g.Namespace, nil }, interfaces: func() ([]GuardInterface, error) { return nil, nil }, run: func(_ context.Context, args ...string) ([]byte, error) {
				if reflect.DeepEqual(args, []string{"-j", "list", "tables"}) {
					return []byte(`{"nftables":[{"table":{"family":"inet","name":"tunnex_ipsec"}}]}`), nil
				}
				return current, nil
			}}
			a := &RuntimeGuard{journal: j, reader: r, apply: func(context.Context, []byte) error {
				writes++
				current = []byte(next.ExpectedJSON)
				if expireNewReadback {
					current = zeroExpiryObserved(t, next.ExpectedJSON, true, nil)
				}
				return nil
			}}
			_, err = a.Replace(context.Background(), g)
			if writes != 1 || (err != nil) != expireNewReadback {
				t.Fatalf("prior withdrawal or successor receipt conflated: writes=%d err=%v", writes, err)
			}
			templates, _, err := j.guardTemplates()
			if err != nil || len(templates) != 1+map[bool]int{false: 0, true: 1}[expireNewReadback] {
				t.Fatal("successor journal commit mismatch", err, len(templates))
			}
		})
	}
}

func zeroExpiryRecoveryTable(t *testing.T, r *recoveryTestRig, targetPositive bool) (RuntimeJournalEntry, uuid.UUID, []byte) {
	t.Helper()
	entries, _ := r.c.journal.Entries()
	target := entries[0]
	g := zeroExpiryGuardIntent()
	g.OwnerID, g.Namespace = r.c.config.GatewayID, target.Allocation.Namespace
	other := uuid.New()
	positive := g.Connections[0]
	positive.ID = other
	positive.Local = target.Engines[0].LocalPrefixes
	positive.Remote = []netip.Prefix{netip.MustParsePrefix("10.111.0.0/24")}
	positive.Grants[0].Source = positive.Local[0]
	positive.Grants[0].Destination = positive.Remote[0]
	positive.Tunnels[0].InterfaceName, positive.Tunnels[1].InterfaceName = "other-a", "other-b"
	positive.Tunnels[0].InterfaceIndex, positive.Tunnels[1].InterfaceIndex = 20, 21
	positive.Tunnels[0].XFRMID, positive.Tunnels[1].XFRMID = 30, 31
	positive.PermittedInterfaceIndices = []int{20}
	positive.ReplyIngressIndices = []int{20, 21}
	positive.EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: 20, ReqID: 123, Peer: netip.MustParseAddr("192.0.2.20"), UnderlayInterfaceIndex: 2}}
	selected := GuardConnection{ID: target.Allocation.ConnectionID, PrefixOnly: true, Local: target.Engines[0].LocalPrefixes, Remote: target.Engines[0].RemotePrefixes}
	if targetPositive {
		selected = zeroExpiryGuardIntent().Connections[0]
		selected.ID, selected.Local, selected.Remote = target.Allocation.ConnectionID, target.Engines[0].LocalPrefixes, target.Engines[0].RemotePrefixes
		selected.Tunnels = target.Observed
		selected.Grants[0].Source, selected.Grants[0].Destination = selected.Local[0], selected.Remote[0]
		selected.EncryptedEgress[0].ReqID = 456
	}
	g.Connections = []GuardConnection{selected, positive}
	m, err := RenderGuard(g)
	if err != nil {
		t.Fatal(err)
	}
	if r.c.journal.prepareGuard(m) != nil || r.c.journal.finishGuard(m) != nil {
		t.Fatal("guard")
	}
	raw := zeroExpiryObserved(t, m.ExpectedJSON, true, nil)
	r.c.guard = &RuntimeGuard{journal: r.c.journal, reader: &GuardReader{namespace: r.c.namespace, interfaces: func() ([]GuardInterface, error) {
		return []GuardInterface{{Name: "tnxi-a", Index: 10}, {Name: "tnxi-b", Index: 11}, {Name: "other-a", Index: 20}, {Name: "other-b", Index: 21}}, nil
	}, run: func(context.Context, ...string) ([]byte, error) { return raw, nil }}}
	return target, other, raw
}

func TestRecoveryGuardZeroExpiryDoesNotMeanDenied(t *testing.T) {
	for _, targetPositive := range []bool{false, true} {
		r := newRecoveryTestRig(t)
		target, other, _ := zeroExpiryRecoveryTable(t, r, targetPositive)
		before, err := os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
		if err != nil {
			t.Fatal(err)
		}
		denied, err := r.c.recoveryGuardDenials(context.Background(), []RuntimeJournalEntry{target, {Allocation: KernelAllocation{Namespace: target.Allocation.Namespace, ConnectionID: other}}})
		if err != nil || denied[target.Allocation.ConnectionID] == targetPositive || denied[other] {
			t.Fatalf("zero expiry starved other provider or became target absence: positive=%v denied=%v err=%v", targetPositive, denied, err)
		}
		after, err := os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
		if err != nil || !bytes.Equal(before, after) || r.switches != 0 || len(r.events) != 0 {
			t.Fatal("read-only denial minted authority, changed route or journal")
		}
	}
}

func TestRecoveryRefreshZeroExpiryOtherProviderKeepsEvidence(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	target, _, _ := zeroExpiryRecoveryTable(t, r, false)
	before, err := os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	active := r.c.active[target.Allocation.ConnectionID]
	writes, switches := len(r.events), r.switches
	lease := &refreshLeaseFixture{}
	r.c.client = lease
	r.status = [2]string{"down", "up"}
	for _, at := range []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second} {
		r.now = at
		if err := r.c.RefreshIPsecRecovery(context.Background()); err != nil {
			t.Fatal("unrelated exact expired member erased target recovery evidence", err)
		}
	}
	h := r.c.recoveryHistory[target.Allocation.ConnectionID]
	if h == nil || h.consecutive != 3 || h.lastNow-h.firstDown != 10*time.Second || len(lease.requests) != 3 {
		t.Fatal("bounded fresh observations missing", h, len(lease.requests))
	}
	after, err := os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
	current := r.c.active[target.Allocation.ConnectionID]
	if err != nil || !bytes.Equal(before, after) || current.Authority != active.Authority || current.Identity != active.Identity || writes != len(r.events) || switches != r.switches {
		t.Fatal("inactive sampling granted authority or changed native/journal/route")
	}
}

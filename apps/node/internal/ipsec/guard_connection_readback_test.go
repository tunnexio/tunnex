package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func guardTableFixtureEdit(t *testing.T, raw []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var table map[string]any
	if json.Unmarshal(raw, &table) != nil {
		t.Fatal("typed table fixture")
	}
	for _, object := range table["nftables"].([]any) {
		edit(object.(map[string]any))
	}
	out, err := json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestConnectionGuardReadDoesNotCoupleUnrelatedExpiry(t *testing.T) {
	for _, zero := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "zero"}[zero], func(t *testing.T) {
			c, _, _, _ := heartbeatBudgetRig(t)
			entries, _ := c.journal.Entries()
			bad, good := entries[0], entries[1]
			templates, _, _ := c.journal.guardTemplates()
			m := GuardManifest{Namespace: templates[0].Namespace, ExpectedJSON: templates[0].ExpectedJSON}
			names := map[string]bool{guardLeaseName(bad.Allocation.ConnectionID): true, guardReplyLeaseName(bad.Allocation.ConnectionID): true, guardSALeaseName(bad.Allocation.ConnectionID): true}
			raw := guardTableFixtureEdit(t, []byte(m.ExpectedJSON), func(object map[string]any) {
				if set, ok := object["set"].(map[string]any); ok && names[set["name"].(string)] {
					if zero {
						for _, elem := range set["elem"].([]any) {
							elem.(map[string]any)["elem"].(map[string]any)["expires"] = float64(0)
						}
					} else {
						delete(set, "elem")
					}
				}
			})
			reads := 0
			c.guard.reader.run = func(_ context.Context, args ...string) ([]byte, error) {
				reads++
				if !reflect.DeepEqual(args, []string{"-j", "list", "table", "inet", "tunnex_ipsec"}) {
					t.Fatal(args)
				}
				return raw, nil
			}
			if c.guard.reader.Check(context.Background(), m) == nil {
				t.Fatal("global install/readback must still reject incomplete positive template")
			}
			if !c.recoveryGuardPermits(context.Background(), good) {
				t.Fatal("healthy target refused because unrelated owner expired")
			}
			if c.recoveryGuardPermits(context.Background(), bad) {
				t.Fatal("expired target promoted")
			}
			objects, ok := normalizedGuardObjects([]byte(m.ExpectedJSON))
			if !ok {
				t.Fatal("invalid expected guard fixture")
			}
			view := &runtimeDNSOwnerView{expected: guardExpectedSnapshot{raw: m.ExpectedJSON, objects: objects}, guard: m, observer: runtimeDNSObserver{guardReader: c.guard.reader}}
			index, req := good.Observed[0].InterfaceIndex, good.Engines[0].ReqID
			before := reads
			if !view.resolverGuardPermits(context.Background(), good, index, req) || reads != before+1 {
				t.Fatal("DNS target must use one same bracketed table snapshot")
			}
			if view.resolverGuardPermits(context.Background(), bad, bad.Observed[0].InterfaceIndex, bad.Engines[0].ReqID) {
				t.Fatal("DNS expired target promoted")
			}
		})
	}
}

func TestConnectionGuardReadPreservesOwnerAndPositiveTargetBoundaries(t *testing.T) {
	cases := []string{"own_zero", "own_absent", "own_reply_missing", "wrong_target", "widened_unrelated", "wrong_timeout", "missing_timeout", "zero_timeout", "foreign_rule", "wrong_owner", "namespace", "interfaces", "canceled", "read_error", "oversize", "unknown_id", "bad_expected"}
	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			c, _, _, _ := heartbeatBudgetRig(t)
			entries, _ := c.journal.Entries()
			good, bad := entries[1], entries[0]
			templates, _, _ := c.journal.guardTemplates()
			m := GuardManifest{Namespace: templates[0].Namespace, ExpectedJSON: templates[0].ExpectedJSON}
			raw := []byte(m.ExpectedJSON)
			id := good.Allocation.ConnectionID
			ctx := context.Background()
			names := map[string]bool{guardLeaseName(id): true, guardReplyLeaseName(id): true, guardSALeaseName(id): true}
			if kind == "own_zero" || kind == "own_absent" || kind == "own_reply_missing" || kind == "wrong_target" || kind == "widened_unrelated" || kind == "wrong_timeout" || kind == "missing_timeout" || kind == "zero_timeout" || kind == "foreign_rule" || kind == "wrong_owner" {
				raw = guardTableFixtureEdit(t, raw, func(object map[string]any) {
					if set, ok := object["set"].(map[string]any); ok {
						name := set["name"].(string)
						if names[name] {
							switch kind {
							case "own_zero":
								for _, elem := range set["elem"].([]any) {
									elem.(map[string]any)["elem"].(map[string]any)["expires"] = float64(0)
								}
							case "own_absent":
								delete(set, "elem")
							case "own_reply_missing":
								if name == guardReplyLeaseName(id) {
									set["elem"] = set["elem"].([]any)[:1]
								}
							case "wrong_target":
								if name == guardLeaseName(id) {
									set["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)["val"] = float64(999)
								}
							}
						}
						if name == guardLeaseName(bad.Allocation.ConnectionID) {
							switch kind {
							case "widened_unrelated":
								set["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)["val"] = float64(999)
							case "wrong_timeout":
								set["timeout"] = float64(61)
							case "missing_timeout":
								delete(set, "timeout")
							case "zero_timeout":
								set["timeout"] = float64(0)
							}
						}
					}
					if kind == "wrong_owner" {
						if chain, ok := object["chain"].(map[string]any); ok && chain["name"] == "owner" {
							chain["comment"] = "foreign"
						}
					}
					if kind == "foreign_rule" {
						if rule, ok := object["rule"].(map[string]any); ok {
							rule["expr"] = []any{map[string]any{"accept": nil}}
						}
					}
				})
			}
			if kind == "missing_timeout" || kind == "zero_timeout" {
				var fixture map[string]any
				_ = json.Unmarshal(raw, &fixture)
				found := false
				for _, object := range fixture["nftables"].([]any) {
					if set, ok := object.(map[string]any)["set"].(map[string]any); ok && set["name"] == guardLeaseName(bad.Allocation.ConnectionID) {
						value, present := set["timeout"]
						found = true
						if kind == "missing_timeout" && present || kind == "zero_timeout" && (!present || value != float64(0)) {
							t.Fatal("negative fixture did not alter the actual set timeout")
						}
					}
				}
				if !found {
					t.Fatal("missing negative fixture target")
				}
			}

			c.guard.reader.run = func(context.Context, ...string) ([]byte, error) { return raw, nil }
			switch kind {
			case "namespace":
				n := 0
				c.guard.reader.namespace = func() (string, error) {
					n++
					if n == 1 {
						return m.Namespace, nil
					}
					return "net:[456]", nil
				}
			case "interfaces":
				n := 0
				c.guard.reader.interfaces = func() ([]GuardInterface, error) { n++; return []GuardInterface{{Name: "owned", Index: 10 + n}}, nil }
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "read_error":
				c.guard.reader.run = func(context.Context, ...string) ([]byte, error) { return nil, errors.New("private") }
			case "oversize":
				c.guard.reader.run = func(context.Context, ...string) ([]byte, error) { return make([]byte, kernelOutputLimit+1), nil }
			case "unknown_id":
				id = uuid.New()
			case "bad_expected":
				m.ExpectedJSON = `{"nftables":[]}`
			}
			if c.guard.reader.checkConnection(ctx, m, id) == nil {
				t.Fatal("unsafe target permit accepted")
			}
		})
	}
}

func TestHeartbeatUnknownGlobalFailureStillWithdrawsAll(t *testing.T) {
	for _, kind := range []string{"native_unknown", "foreign_guard", "namespace", "qualification", "withdraw_error"} {
		t.Run(kind, func(t *testing.T) {
			c, _, _, denials := heartbeatBudgetRig(t)
			entries, _ := c.journal.Entries()
			bad := entries[0]
			c.recoveryHistory[bad.Allocation.ConnectionID].lastNow = 0
			c.recoveryHistory[entries[1].Allocation.ConnectionID].lastNow = 1
			switch kind {
			case "native_unknown":
				c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"unknown", "up"} }
			case "foreign_guard":
				c.guard.reader.run = func(context.Context, ...string) ([]byte, error) { return []byte(`{"nftables":[]}`), nil }
			case "namespace":
				c.namespace = func() (string, error) { return "net:[456]", nil }
			case "qualification":
				observe := c.recoveryObserve
				c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
					statuses := observe(ctx, e)
					c.qualification.alive = func() bool { return false }
					return statuses
				}
			case "withdraw_error":
				a := c.active[bad.Allocation.ConnectionID]
				a.Authority.elapsed = func() time.Duration { return 61 * time.Second }
				c.guard.apply = func(context.Context, []byte) error { return ErrGuardRead }
			}
			if reports, err := c.RefreshIPsecActiveRecovery(context.Background()); err == nil || len(reports) != 0 || *denials != 1 {
				t.Fatalf("global failure was not refused: %s %v denials=%d", kind, err, *denials)
			}
		})
	}
}

//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"reflect"
	"testing"
)

// Actual generic Apply then maintenance; modeled native I/O, not cloud proof.
func TestClassicOrdinaryApplyPublishesMaintenanceIdentity(t *testing.T) {
	for _, mode := range []string{"unchanged", "changed-delivery", "invalid-material", "expired-authority", "foreign-native"} {
		for _, restored := range []bool{false, true} {
			t.Run(mode+"/"+map[bool]string{false: "initial", true: "restored"}[restored], func(t *testing.T) {
				testClassicApplyBoot(t, restored, false, func(c *RuntimeController, m RuntimeMaterial, daemonMutations *int) {
					id := m.Manifest.ConnectionID
					before := c.active[id]
					entries, err := c.journal.Entries()
					if err != nil || len(entries) != 1 {
						t.Fatal("journal", err)
					}
					if !reflect.DeepEqual(before.Delivery, m.RuntimeDelivery) || !reflect.DeepEqual(before.Entry, entries[0]) {
						t.Fatalf("ordinary Apply did not publish committed maintenance identity: delivery=%t entry=%t activePhase=%s savedPhase=%s", reflect.DeepEqual(before.Delivery, m.RuntimeDelivery), reflect.DeepEqual(before.Entry, entries[0]), before.Entry.Phase, entries[0].Phase)
					}
					var native []byte
					c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
						g, e := RenderGuard(in)
						if e != nil {
							return g, e
						}
						if e = c.journal.prepareGuard(g); e != nil {
							return g, e
						}
						if e = c.journal.finishGuard(g); e != nil {
							return g, e
						}
						var document map[string]any
						json.Unmarshal([]byte(g.ExpectedJSON), &document)
						for _, v := range document["nftables"].([]any) {
							s, ok := v.(map[string]any)["set"].(map[string]any)
							if !ok {
								continue
							}
							for _, x := range classicMaintenanceElements(s["elem"]) {
								z := x.(map[string]any)["elem"].(map[string]any)
								z["expires"] = z["timeout"]
							}
						}
						native, _ = json.Marshal(document)
						return g, nil
					}
					links := []GuardInterface{{Name: "ens4", Index: 2}, {Name: entries[0].Observed[0].InterfaceName, Index: 10}}
					c.guard = &RuntimeGuard{journal: c.journal, reader: &GuardReader{namespace: c.namespace, interfaces: func() ([]GuardInterface, error) { return links, nil }, run: func(context.Context, ...string) ([]byte, error) { return native, nil }}}
					if e := c.installActive(context.Background(), entries); e != nil {
						t.Fatal("initial native guard", e)
					}
					mutations := *daemonMutations
					results, e := c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{m}, NewPermitLeaseAuthority, func() bool { return true })
					if e != nil || len(results) != 1 {
						t.Fatal("unchanged Classic maintenance fell back", e, len(results))
					}
					current := c.active[id]
					if *daemonMutations != mutations || !reflect.DeepEqual(current.Entry, before.Entry) || !reflect.DeepEqual(current.Delivery, before.Delivery) || current.Authority == before.Authority || current.Entry.Observed[1] != (Ownership{}) {
						t.Fatal("maintenance recreated transport or lost exact one-slot identity")
					}
					if mode != "unchanged" {
						bad := m
						switch mode {
						case "changed-delivery":
							bad.ID = uuid.New()
							runtimeReseal(&bad)
						case "invalid-material":
							bad.Secrets[1] = RuntimeSecret{PSK: "inactive forbidden"}
						case "expired-authority":
							current.Authority.deadline = 0
							c.active[id] = current
						case "foreign-native":
							var v map[string]any
							json.Unmarshal(native, &v)
							v["nftables"] = append(v["nftables"].([]any), map[string]any{"chain": map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": "unknown"}})
							native, _ = json.Marshal(v)
						}
						got, _ := c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{bad}, NewPermitLeaseAuthority, func() bool { return true })
						if len(got) != 0 || *daemonMutations != mutations {
							t.Fatal("invalid unchanged admission renewed or mutated transport", mode)
						}
					}

				})
			})
		}

	}
}

func classicMaintenanceElements(v any) []any { a, _ := v.([]any); return a }

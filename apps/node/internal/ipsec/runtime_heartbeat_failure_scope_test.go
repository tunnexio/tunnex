package ipsec

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// Two independently bound current providers share the real rendered table and
// journal. Only B loses old native membership or its original CP lease. A's
// native members, authority object/deadline, entry and recovery epoch stay exact.
func TestHeartbeatFailedProviderDoesNotWithdrawHealthyProvider(t *testing.T) {
	for _, kind := range []string{"native_absent_bad_first", "native_absent_healthy_first", "native_zero_healthy_first", "original_expired_bad_first"} {
		t.Run(kind, func(t *testing.T) {
			c, _, _, _ := heartbeatBudgetRig(t)
			entries, err := c.journal.Entries()
			if err != nil || len(entries) != 2 {
				t.Fatal("two-provider journal", err)
			}
			bad, good := entries[0], entries[1]
			a := c.active[good.Allocation.ConnectionID]
			beforeA := a
			remainingBefore, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second)
			if err != nil {
				t.Fatal("healthy original lease", err)
			}
			templates, _, err := c.journal.guardTemplates()
			if err != nil || len(templates) != 1 {
				t.Fatal("current exact template", err)
			}
			// The old kernel members have only17s left although their original
			// timeout was50s and the CP authority still has nearly60s. Keeping
			// the CP authority alone must not permit a replacement to renew them.
			raw := guardTableFixtureEdit(t, []byte(templates[0].ExpectedJSON), func(object map[string]any) {
				if set, ok := object["set"].(map[string]any); ok {
					if elements, ok := set["elem"].([]any); ok {
						for _, element := range elements {
							element.(map[string]any)["elem"].(map[string]any)["expires"] = float64(17)
						}
					}
				}
			})
			c.guard.reader.run = func(context.Context, ...string) ([]byte, error) { return append([]byte(nil), raw...), nil }
			goodNames := map[string]bool{guardLeaseName(good.Allocation.ConnectionID): true, guardReplyLeaseName(good.Allocation.ConnectionID): true, guardSALeaseName(good.Allocation.ConnectionID): true}
			badNames := map[string]bool{guardLeaseName(bad.Allocation.ConnectionID): true, guardReplyLeaseName(bad.Allocation.ConnectionID): true, guardSALeaseName(bad.Allocation.ConnectionID): true}
			members := func(raw []byte, names map[string]bool) map[string]any {
				var table map[string]any
				if json.Unmarshal(raw, &table) != nil {
					t.Fatal("typed native fixture")
				}
				out := map[string]any{}
				for _, object := range table["nftables"].([]any) {
					if set, ok := object.(map[string]any)["set"].(map[string]any); ok && names[set["name"].(string)] {
						out[set["name"].(string)] = set["elem"]
					}
				}
				return out
			}
			healthyMembersBefore := members(raw, goodNames)
			if len(healthyMembersBefore) != 3 {
				t.Fatal("all healthy sets")
			}
			if kind != "original_expired_bad_first" {
				var table map[string]any
				if json.Unmarshal(raw, &table) != nil {
					t.Fatal("native JSON")
				}
				for _, object := range table["nftables"].([]any) {
					if set, ok := object.(map[string]any)["set"].(map[string]any); ok && badNames[set["name"].(string)] {
						if kind == "native_zero_healthy_first" {
							for _, item := range set["elem"].([]any) {
								item.(map[string]any)["elem"].(map[string]any)["expires"] = float64(0)
							}
						} else {
							delete(set, "elem")
						}
					}
				}
				raw, err = json.Marshal(table)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				b := c.active[bad.Allocation.ConnectionID]
				b.Authority.elapsed = func() time.Duration { return 61 * time.Second }
			}
			if !reflect.DeepEqual(members(raw, goodNames), healthyMembersBefore) {
				t.Fatal("healthy native member fixture changed")
			}
			beforeDenied, err := c.recoveryGuardDenials(context.Background(), entries)
			if err != nil || beforeDenied[good.Allocation.ConnectionID] {
				t.Fatal("whole owned table and healthy current members", err, beforeDenied)
			}
			if kind == "native_absent_bad_first" || kind == "native_absent_healthy_first" {
				if !beforeDenied[bad.Allocation.ConnectionID] {
					t.Fatal("expired old B native sets not actually empty")
				}
			}
			if kind == "native_zero_healthy_first" && beforeDenied[bad.Allocation.ConnectionID] {
				t.Fatal("zero-expiry member must remain nonempty")
			}
			if c.proveCurrent(context.Background(), good, a.Environment) != nil {
				t.Fatal("healthy independent proof")
			}
			c.recoveryHistory[bad.Allocation.ConnectionID].lastNow = 0
			c.recoveryHistory[good.Allocation.ConnectionID].lastNow = time.Second
			if kind == "native_absent_healthy_first" || kind == "native_zero_healthy_first" {
				c.recoveryHistory[bad.Allocation.ConnectionID].lastNow = time.Second
				c.recoveryHistory[good.Allocation.ConnectionID].lastNow = 0
			}
			beforeHistory := *c.recoveryHistory[good.Allocation.ConnectionID]
			beforeTemplates, beforeSequence, _ := c.journal.guardTemplates()
			c.guard.apply = func(_ context.Context, transaction []byte) error {
				var doc map[string]any
				if json.Unmarshal(transaction, &doc) != nil {
					t.Fatal("withdraw transaction")
				}
				cmds := doc["nftables"].([]any)
				if len(cmds) != 3 {
					t.Fatal("target withdrawal count")
				}
				names := map[string]bool{}
				for _, cmd := range cmds {
					object := cmd.(map[string]any)
					if len(object) != 1 {
						t.Fatal("extra mutation")
					}
					fields := object["flush"].(map[string]any)["set"].(map[string]any)
					name := fields["name"].(string)
					if fields["family"] != "inet" || fields["table"] != "tunnex_ipsec" || len(fields) != 3 || !badNames[name] || names[name] {
						t.Fatal("wrong withdrawal scope")
					}
					names[name] = true
				}
				var table map[string]any
				_ = json.Unmarshal(raw, &table)
				for _, object := range table["nftables"].([]any) {
					if set, ok := object.(map[string]any)["set"].(map[string]any); ok && names[set["name"].(string)] {
						delete(set, "elem")
					}
				}
				raw, _ = json.Marshal(table)
				return nil
			}
			// The replacement seam exercises real renderer and two-template journal
			// transition; it simulates the atomic kernel's exact resulting table.
			c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				m, err := RenderGuard(in)
				if err != nil {
					return m, err
				}
				if err = c.journal.prepareGuard(m); err != nil {
					return m, err
				}
				raw = []byte(m.ExpectedJSON)
				if err = c.journal.finishGuard(m); err != nil {
					return m, err
				}
				return m, nil
			}
			reports, err := c.RefreshIPsecActiveRecovery(context.Background())
			if err == nil || len(reports) != 0 {
				t.Fatal("failed provider must remain refused", err, len(reports))
			}
			after, readErr := c.recoveryGuardDenials(context.Background(), entries)
			if readErr != nil {
				t.Fatal("exact post-refusal table", readErr)
			}
			leaseRemaining, leaseErr := a.Authority.RemainingForApply(a.Identity, 5*time.Second)
			if leaseErr != nil || leaseRemaining > remainingBefore {
				t.Fatal("healthy original deadline expired or extended", leaseErr)
			}
			if after[good.Allocation.ConnectionID] {
				t.Fatalf("healthy provider globally denied after unrelated %s; original authority and exact native proof remain valid", kind)
			}
			live, ok := c.active[good.Allocation.ConnectionID]
			if !ok || live.Authority != beforeA.Authority || !reflect.DeepEqual(live.Entry, beforeA.Entry) {
				t.Fatal("unrelated original authority changed")
			}
			if c.recoveryHistory[good.Allocation.ConnectionID] == nil || c.recoveryHistory[good.Allocation.ConnectionID].epoch != beforeHistory.epoch || c.recoveryHistory[good.Allocation.ConnectionID].current != beforeHistory.current {
				t.Fatal("healthy history invalidated")
			}
			if !reflect.DeepEqual(members(raw, goodNames), healthyMembersBefore) {
				t.Fatal("healthy native deadlines/members changed by failed-provider heartbeat")
			}
			afterTemplates, afterSequence, _ := c.journal.guardTemplates()
			if !reflect.DeepEqual(afterTemplates, beforeTemplates) || afterSequence != beforeSequence {
				t.Fatal("target withdrawal changed journal/template")
			}
			if !after[bad.Allocation.ConnectionID] || c.active[bad.Allocation.ConnectionID].Authority != nil || c.recoveryHistory[bad.Allocation.ConnectionID] != nil {
				t.Fatal("failed own provider retained authority")
			}
		})
	}
}

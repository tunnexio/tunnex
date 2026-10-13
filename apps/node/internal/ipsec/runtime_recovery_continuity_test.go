package ipsec

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStaticRecoveryContinuityRetainsOnlyExactOldAuthority(t *testing.T) {
	for _, scenario := range []string{"unchanged", "pending", "inactive", "policy", "environment", "grant", "prepared_missing", "prepared_changed", "delivery", "native", "expired", "late_native", "revoked_native", "canceled_native", "daemon_native", "foreign_guard", "namespace"} {
		t.Run(scenario, func(t *testing.T) {
			r := newRenewalCycleRig(t)
			c := r.c
			e := r.entries[3]
			a := c.active[r.target]
			env, hash, grants := a.Environment, a.Identity.PolicyHash, a.Grants
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "pending":
				next := *e.Recovery
				next.Stage = "pending"
				next.PendingFrom = 1
				next.PendingTo = 2
				next.SelectedSlot = 0
				e.Recovery = &next
			case "inactive":
				delete(c.active, r.target)
			case "policy":
				hash = strings.Repeat("c", 64)
			case "environment":
				env.Underlays[0].InterfaceIndex++
			case "grant":
				grants = []GuardGrant{{}}
			case "prepared_missing":
				delete(c.recoveryPrepared, e.DeliveryID)
			case "prepared_changed":
				v := c.recoveryPrepared[e.DeliveryID]
				v.Underlays[0].InterfaceIndex++
				c.recoveryPrepared[e.DeliveryID] = v
			case "delivery":
				a.Delivery.OwnershipDigest = strings.Repeat("c", 64)
				c.active[r.target] = a
			case "native":
				c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return ErrRuntimeController }
			case "expired":
				*r.now = 61 * time.Second
			case "late_native":
				c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
					*r.now = 56 * time.Second
					return nil
				}
			case "revoked_native":
				c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
					a.Authority.Invalidate()
					return nil
				}
			case "canceled_native":
				c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { cancel(); return nil }
			case "daemon_native":
				c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
					c.config.DaemonAlive = func() bool { return false }
					return nil
				}
			case "foreign_guard":
				c.guard.reader.run = func(context.Context, ...string) ([]byte, error) {
					return []byte(strings.ReplaceAll(string(r.native()), "tunnex_ipsec", "foreign_ipsec")), nil
				}
			case "namespace":
				c.guard.reader.namespace = func() (string, error) { return "net:[4026532999]", nil }
			}
			beforeDeadline, beforeLeaseCount := a.Authority.deadline, r.leases
			before, seq, err := c.journal.guardTemplates()
			if err != nil {
				t.Fatal(err)
			}
			continued := c.recoveryUnchangedActive(ctx, e, env, hash, grants)
			if continued != (scenario == "unchanged") {
				t.Fatalf("continuity=%t scenario=%s", continued, scenario)
			}
			after, nextSeq, err := c.journal.guardTemplates()
			if err != nil {
				t.Fatal(err)
			}
			if seq != nextSeq || len(before) != len(after) || before[0].ExpectedJSON != after[0].ExpectedJSON || r.leases != beforeLeaseCount {
				t.Fatal("read-only proof changed native template/nonce authority")
			}
			if scenario == "unchanged" && (c.active[r.target].Authority != a.Authority || a.Authority.deadline != beforeDeadline) {
				t.Fatal("continuity extended or replaced old lease")
			}
		})
	}
}

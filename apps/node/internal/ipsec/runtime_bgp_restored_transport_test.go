package ipsec

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestBGPTrustedRestoredAppliedTransportPreparation(t *testing.T) {
	for _, fault := range []string{"none", "checkpointed survivor", "checkpointed now absent", "partial survivor", "foreign route", "foreign SA", "no trusted reset", "expired authority", "denial failure"} {
		t.Run(fault, func(t *testing.T) {
			c, f, _, denied := bgpControllerFixture(t, false)
			entries, _ := c.journal.Entries()
			old := entries[0]
			e := restoredFixture(old)
			if !validRestoration(e) {
				t.Fatal("invalid restored fixture")
			}
			entries = []RuntimeJournalEntry{e}
			f.p = e.Allocation
			f.deleted = [2]bool{true, true}
			f.routes = [2]map[string]bool{{}, {}}
			active := c.active[old.Allocation.ConnectionID]
			identity := active.Identity
			authority := active.Authority
			c.namespace = func() (string, error) { return e.Allocation.Namespace, nil }
			c.qualification = testRuntimeQualification(e.Allocation.Namespace)
			switch fault {
			case "checkpointed survivor", "checkpointed now absent":
				f.deleted = [2]bool{false, false}
				for i, a := range e.Allocation.Tunnels {
					e.Observed[i] = Ownership{Namespace: e.Allocation.Namespace, InterfaceName: a.Name, InterfaceIndex: 10 + i, XFRMID: a.XFRMID}
					f.routes[i][netip.PrefixFrom(a.BGP.Peer, 32).String()] = true
				}
				entries[0] = e
				if fault == "checkpointed now absent" {
					f.deleted = [2]bool{true, true}
					f.routes = [2]map[string]bool{{}, {}}
				}
			case "partial survivor":
				f.deleted[0] = false
				f.routes[0][netip.PrefixFrom(e.Allocation.Tunnels[0].BGP.Peer, 32).String()] = true
			case "foreign route":
				c.kernel.run = func(ctx context.Context, args ...string) ([]byte, error) {
					if strings.Contains(strings.Join(args, " "), "-4 route show") {
						return []byte(fmt.Sprintf(`[{"dst":%q,"dev":"foreign","table":"254","protocol":"242","type":"1","scope":"253","metric":50001,"flags":[]}]`, netip.PrefixFrom(e.Allocation.Tunnels[0].BGP.Peer, 32).String())), nil
					}
					return f.run(ctx, args...)
				}
			case "foreign SA":
				f.sa = true
			case "no trusted reset":
				e.Restoration = nil
				entries[0] = e
			case "expired authority":
				authority.Invalidate()
			case "denial failure":
				c.replace = func(context.Context, GuardIntent) (GuardManifest, error) { return GuardManifest{}, ErrGuardReadback }
			}
			before := e
			mutations := f.mutations
			recreate, missing, err := c.bgpRestoredTransportAbsent(context.Background(), e, entries, authority, identity, active.Environment)
			if fault == "none" || fault == "checkpointed survivor" || fault == "checkpointed now absent" {
				if err != nil || !recreate || !*denied || missing != (fault != "checkpointed survivor") {
					t.Fatal("trusted Applied reset did not authorize reconstruction after proof", err)
				}
			} else if err == nil || recreate {
				t.Fatal("unsafe reset admitted")
			}
			if f.mutations != mutations || !reflect.DeepEqual(e, before) || e.Phase != RuntimeApplied {
				t.Fatal("absence preparation mutated intent or kernel")
			}
		})
	}
}

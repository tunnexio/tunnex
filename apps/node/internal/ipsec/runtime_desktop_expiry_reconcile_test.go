package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Production desktop proof/expiry, combined guard and BGP
// reconciliation; only OS reads, native transport and FRR are deterministic fixtures.
func TestStaticDesktopExpiryDuringBGPSiblingGuard(t *testing.T) {
	for _, crossing := range []bool{false, true} {
		t.Run(map[bool]string{false: "live_expiry_control", true: "expires_during_static_observation"}[crossing], func(t *testing.T) {
			r, _ := fqdnExpiryTurnoverRig(t, true)
			old := cloneMaintenanceActive(r.c.active[r.target])
			expires := time.Now().UTC().Add(8 * time.Second)
			old.FQDNLeaseDescriptors[0].ExpiresAt = expires
			for i := range old.Grants {
				if old.Grants[i].FQDNManaged {
					old.Grants[i].FQDN.ExpiresAt = expires
					old.Grants[i].DesktopExpiresAt = expires
				}
			}
			authority := maintenanceAuthority(r)()
			key := runtimeFQDNGrantDigest(old.FQDNLeaseDescriptors[0])
			q, err := authority.BeginFQDN(old.Identity, []string{key})
			if err != nil {
				t.Fatal(err)
			}
			if err = authority.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: key, TTLMS: 8000}}}); err != nil {
				t.Fatal(err)
			}
			old.Authority = authority
			r.c.active[r.target] = old
			r.c.config.IPPath, r.c.config.NFTPath = "ip", "nft"
			proofs, expiredProofs := 0, 0
			r.c.desktopObserve = func(ctx context.Context, grants []GuardGrant) ([]GuardGrant, error) {
				proofs++
				peers := map[string]string{}
				rows := append([]any(nil), pendingNATFixture()[:2]...)
				tupleSeen := map[string]bool{}
				for _, g := range grants {
					if g.DesktopDeviceID == uuid.Nil {
						continue
					}
					peers[g.Source.String()] = g.DesktopPublicKey
					tuple := g.Source.String() + ":" + g.Destination.String()
					if !tupleSeen[tuple] {
						rows = append(rows, pendingNATExemption(g.Source.String(), g.Destination.String()))
						tupleSeen[tuple] = true
					}
					if g.FQDNManaged && !g.FQDN.ExpiresAt.After(time.Now()) {
						expiredProofs++
					}
				}
				rows = append(rows, pendingNATFixture()[2])
				var wg string
				for source, key := range peers {
					wg += "wg0\t" + key + "\t" + source + "\n"
				}
				read := func(path string, args ...string) ([]byte, error) {
					switch command := path + " " + strings.Join(args, " "); {
					case command == "wg show all allowed-ips":
						return []byte(wg), nil
					case command == "nft -j list table ip tunnex":
						return pendingNATJSON(rows), nil
					case command == "ip -j -d link show dev wg0":
						return []byte(`[{"ifname":"wg0","ifindex":7777,"linkinfo":{"info_kind":"wireguard"},"flags":["UP"]}]`), nil
					case strings.HasPrefix(command, "ip -j -4 route get "):
						return []byte(fmt.Sprintf(`[{"dst":%q,"dev":"wg0"}]`, args[len(args)-1])), nil
					default:
						t.Fatalf("unexpected read %s", command)
						return nil, ErrRuntimeController
					}
				}
				return r.c.observeDesktopGrantsWithRead(ctx, grants, "wg", read)
			}
			if err := r.c.installActive(context.Background(), r.entries); err != nil {
				t.Fatal("initial exact live desktop proof", err)
			}
			// This short answer is conservatively omitted by the existing commit
			// budget. Its retained descriptor must not later withdraw independent
			// ordinary permissions or regain any native answer membership.
			before := map[uuid.UUID]runtimeActive{}
			beforeDenied := map[uuid.UUID]bool{}
			deadlines := map[uuid.UUID]time.Duration{}
			processes := map[uuid.UUID]runtimeBGPSession{}
			for id, a := range r.c.active {
				before[id] = cloneMaintenanceActive(a)
				beforeDenied[id] = r.applicationDenied[id]
				deadlines[id] = a.Authority.deadline
				if a.Entry.ContractVersion == 3 {
					processes[a.Entry.DeliveryID] = r.c.bgpProcesses[a.Entry.DeliveryID]
				}
			}
			var bgpID uuid.UUID
			for _, entry := range r.entries {
				if entry.ContractVersion == 3 {
					bgpID = entry.Allocation.ConnectionID
					break
				}
			}
			bgp := r.c.active[bgpID]
			process := r.c.bgpProcesses[bgp.Entry.DeliveryID].(*bgpSessionFixture)
			kernel := newRecoveryKernelFixture()
			kernel.p, kernel.owned = bgp.Entry.Allocation, bgp.Entry.Observed
			for i, tunnel := range kernel.p.Tunnels {
				kernel.routes[i] = map[string]bool{netip.PrefixFrom(tunnel.BGP.Peer, 32).String(): true}
			}
			for _, route := range bgp.Entry.BGPRoutes.Owned {
				kernel.routes[route.Slot-1][route.Prefix.String()] = true
			}
			staticKernel := r.c.kernel
			r.c.kernel = kernel.applier()
			r.c.kernel.run = func(ctx context.Context, args ...string) ([]byte, error) {
				if len(args) > 0 && args[0] == "-j" {
					combined := []json.RawMessage{}
					for _, read := range []func(context.Context, ...string) ([]byte, error){staticKernel.run, kernel.run} {
						raw, e := read(ctx, args...)
						if e != nil {
							return nil, e
						}
						var rows []json.RawMessage
						if e = json.Unmarshal(raw, &rows); e != nil {
							return nil, e
						}
						combined = append(combined, rows...)
					}
					return json.Marshal(combined)
				}
				return kernel.run(ctx, args...)
			}
			process.routes = nil // a valid empty learned RIB must withdraw this owner's route only.
			var refused []RuntimeDiagnostic
			r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
				if d.Refused {
					refused = append(refused, d)
					t.Logf("%s %s %s", d.Operation, d.Stage, d.ConnectionID)
				}
			}
			observed := false
			baseObserve := r.c.recoveryObserve
			r.c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
				if crossing && e.Allocation.ConnectionID == r.target && !observed {
					observed = true
					if !expires.After(time.Now()) {
						t.Fatal("expiry must be live at first desktop proof")
					}
					timer := time.NewTimer(time.Until(expires) + 10*time.Millisecond)
					select {
					case <-timer.C:
					case <-ctx.Done():
						timer.Stop()
						t.Fatal("fixture exceeded bounded native observation", ctx.Err())
					}
				}
				return baseObserve(ctx, e)
			}
			if crossing {
				time.Sleep(time.Until(expires.Add(-2 * time.Second)))
			}
			err = r.c.reconcileActiveBGP(context.Background(), r.entries)
			t.Logf("crossing=%t err=%v proofs=%d post_expiry_ownership_proofs=%d active=%d static_denied=%t changed_bgp_denied=%t", crossing, err, proofs, expiredProofs, len(r.c.active), r.applicationDenied[r.target], r.applicationDenied[bgpID])
			if crossing && (!observed || expiredProofs == 0) {
				t.Fatal("did not exercise real absolute-expiry boundary")
			}
			if err != nil {
				t.Fatal("static DNS expiry globally refused unrelated BGP guard", err)
			}
			if !reflect.DeepEqual(r.c.active[r.target].Grants, old.Grants) || !reflect.DeepEqual(r.c.active[r.target].FQDNLeaseDescriptors, old.FQDNLeaseDescriptors) {
				t.Fatal("ownership proof changed retained grant or absolute deadline")
			}
			if crossing {
				for _, g := range old.Grants {
					if g.FQDNManaged && r.installed[guardFQDNSetName(g)] > *r.now {
						t.Fatal("expired FQDN membership revived")
					}
				}
			}
			for id, previous := range before {
				if previous.Authority.deadline != deadlines[id] {
					t.Fatal("original finite authority extended", id)
				}
				if id == bgpID {
					continue
				}
				a, ok := r.c.active[id]
				if !ok || a.Authority != previous.Authority || a.Identity != previous.Identity || a.Authority.deadline != previous.Authority.deadline || !reflect.DeepEqual(a.Entry, previous.Entry) || r.applicationDenied[id] != beforeDenied[id] {
					t.Fatal("static expiry damaged independently live sibling", id)
				}
			}
			for delivery, previous := range processes {
				if r.c.bgpProcesses[delivery] != previous || !previous.Alive() {
					t.Fatal("static DNS expiry stopped an independently owned BGP process")
				}
			}
		})
	}
}

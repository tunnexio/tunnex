package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func staticTransportEntry(t *testing.T, modern bool) RuntimeJournalEntry {
	t.Helper()
	m := desktopAWSStaticMaterial(t, false)
	m.Policy.DesktopGrants = nil
	if !modern {
		m.Manifest.DesktopStaticVersion = nil
	}
	runtimeReseal(&m)
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range e.Allocation.Tunnels {
		e.Observed[i] = Ownership{Namespace: e.Allocation.Namespace, InterfaceName: a.Name, InterfaceIndex: 10 + i, XFRMID: a.XFRMID}
	}
	return e
}

func TestDesktopStaticTransportStagesWideSelectorsOnlyWithExplicitContract(t *testing.T) {
	for _, modern := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "desktop"}[modern], func(t *testing.T) {
			e := staticTransportEntry(t, modern)
			for _, cfg := range e.Engines {
				var loaded viciMessage
				daemon := &DaemonClient{request: func(_ context.Context, cmd, event string, m viciMessage) (viciMessage, []viciMessage, error) {
					switch cmd {
					case "get-conns":
						return viciMessage{"conns": viciList()}, nil, nil
					case "get-shared":
						return viciMessage{"keys": viciList()}, nil, nil
					case "load-conn":
						loaded = m
					case "initiate":
						t.Fatal("transport staged before finite permits")
					}
					return viciMessage{"success": viciText("yes")}, nil, nil
				}}
				if err := daemon.stageTunnel(context.Background(), cfg, []byte("Synthetic.PSK_123")); err != nil {
					t.Fatal(err)
				}
				child := loaded[engineName(cfg)].section["children"].section[engineName(cfg)].section
				local, remote := cfg.LocalPrefixes, cfg.RemotePrefixes
				if modern {
					local = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
					remote = local
				}
				if !reflect.DeepEqual(child["local_ts"], enginePrefixes(local)) || !reflect.DeepEqual(child["remote_ts"], enginePrefixes(remote)) || string(child["start_action"].scalar) != "none" {
					t.Fatal("wrong staged transport selectors")
				}
				if cfg.LocalPrefixes[0].Bits() == 0 || cfg.RemotePrefixes[0].Bits() == 0 {
					t.Fatal("application range widened with transport")
				}
			}
		})
	}
}

func TestDesktopStaticTransportNativeProofRejectsLegacyAndForeignSelectors(t *testing.T) {
	for _, modern := range []bool{false, true} {
		for _, drift := range []string{"none", "opposite_child", "opposite_xfrm", "wrong_reqid"} {
			t.Run(map[bool]string{false: "legacy", true: "desktop"}[modern]+"/"+drift, func(t *testing.T) {
				e := staticTransportEntry(t, modern)
				d, k, x := sharedStaticInventories(e, 0)
				switch drift {
				case "opposite_child":
					d.SAs[0].Children[0].LocalPrefixes = e.Engines[0].LocalPrefixes
					if !modern {
						d.SAs[0].Children[0].LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
					}
				case "opposite_xfrm":
					x.Policies[0].Destination = e.Engines[0].LocalPrefixes[0]
					if !modern {
						x.Policies[0].Destination = netip.MustParsePrefix("0.0.0.0/0")
					}
				case "wrong_reqid":
					d.SAs[0].Children[0].ReqID++
				}
				err := runtimeInventoryMatches(e, d, k, x)
				if (err == nil) != (drift == "none") {
					t.Fatalf("native selector proof: %v", err)
				}
			})
		}
	}
}

func TestDesktopStaticTransportCleanupUsesPersistedSelectorOwner(t *testing.T) {
	for _, modern := range []bool{false, true} {
		for _, wrong := range []bool{false, true} {
			t.Run(map[bool]string{false: "legacy", true: "desktop"}[modern]+map[bool]string{false: "/owned", true: "/wrong"}[wrong], func(t *testing.T) {
				cfg := staticTransportEntry(t, modern).Engines[0]
				event := sameNamespaceOwnedSAEvent(cfg)
				if wrong {
					ch := event[engineName(cfg)].section["child-sas"].section["child-1"].section
					p := cfg.LocalPrefixes
					if !modern {
						p = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
					}
					ch["local-ts"] = enginePrefixes(p)
				}
				mutations := 0
				base := daemonInventoryStub([]viciMessage{event}, viciMessage{}, &mutations)
				request := base.request
				base.request = func(ctx context.Context, cmd, ev string, m viciMessage) (viciMessage, []viciMessage, error) {
					if cmd == "list-sas" && mutations > 0 {
						return viciMessage{}, nil, nil
					}
					return request(ctx, cmd, ev, m)
				}
				err := base.removeTunnel(context.Background(), cfg)
				if wrong {
					if err == nil || mutations != 0 {
						t.Fatal("cleanup touched wrong selector owner")
					}
				} else if err != nil || mutations != 1 {
					t.Fatal("exact persisted selector cleanup failed", err, mutations)
				}
			})
		}
	}
}

func TestDesktopStaticTransportJournalUpgradeAndLegacyImmutability(t *testing.T) {
	legacy := staticTransportEntry(t, false)
	j, err := OpenRuntimeJournal(journalDir(t), legacy.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Save([]RuntimeJournalEntry{legacy}); err != nil {
		t.Fatal(err)
	}
	before, err := j.cleanupSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(legacy)
	if before.Version != 2 || strings.Contains(string(raw), "DesktopStaticVersion") {
		t.Fatal("legacy bytes/version changed")
	}
	changed := legacy
	for i := range changed.Engines {
		changed.Engines[i].DesktopStaticVersion = 1
	}
	if j.Save([]RuntimeJournalEntry{changed}) == nil {
		t.Fatal("live legacy selectors rewritten in place")
	}
	modern := staticTransportEntry(t, true)
	// A separate new delivery may advance the journal; the old owner remains exact.
	for i := range modern.Engines {
		modern.Engines[i].Binding.GatewayID = legacy.Engines[0].Binding.GatewayID
	}
	if err = j.Save([]RuntimeJournalEntry{legacy, modern}); err != nil {
		t.Fatal(err)
	}
	after, err := j.cleanupSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != 15 || !reflect.DeepEqual(after.Entries[0], legacy) {
		t.Fatal("new contract not durably distinguished")
	}
	downgraded := cloneJournal(after)
	downgraded.Version = 14
	if validJournalPayload(downgraded) || validJournalSuccessor(after, downgraded) {
		t.Fatal("old reader permitted for new transport")
	}
	for _, mutate := range []func(*RuntimeJournalEntry){
		func(e *RuntimeJournalEntry) { e.Engines[1].DesktopStaticVersion = 0 },
		func(e *RuntimeJournalEntry) { e.Engines[0].DesktopStaticVersion = 2 },
		func(e *RuntimeJournalEntry) { e.ContractVersion = 0; e.Recovery = nil },
		func(e *RuntimeJournalEntry) { e.Engines[0].BGP = true },
	} {
		bad := cloneJournal(after)
		mutate(&bad.Entries[1])
		if validJournalPayload(bad) {
			t.Fatal("inconsistent static transport journal accepted")
		}
	}
	dir := j.dir
	j.Close()
	reopened, err := OpenRuntimeJournal(dir, legacy.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, err := reopened.cleanupSnapshot()
	if err != nil || !reflect.DeepEqual(after, recovered) {
		t.Fatal("restart lost selector ownership", err)
	}
}

func TestDesktopStaticTransportMarkerCannotCrossProvidersOrRecoveryContract(t *testing.T) {
	for name, mutate := range map[string]func(*RuntimeMaterial){
		"bgp":             func(m *RuntimeMaterial) { m.Manifest.ProfileID = "aws-bgp-ipv4-v1" },
		"gcp":             func(m *RuntimeMaterial) { m.Manifest.ProfileID = GCPClassicStaticProfile },
		"azure":           func(m *RuntimeMaterial) { m.Manifest.ProfileID = "azure-vgw-static-ipv4-v1" },
		"recovery_absent": func(m *RuntimeMaterial) { m.Manifest.RecoveryVersion = nil },
		"future_version":  func(m *RuntimeMaterial) { two := 2; m.Manifest.DesktopStaticVersion = &two },
		"single_tunnel":   func(m *RuntimeMaterial) { one := 1; m.Manifest.TunnelCount = &one },
	} {
		t.Run(name, func(t *testing.T) {
			m := desktopAWSStaticMaterial(t, false)
			m.Policy.DesktopGrants = nil
			mutate(&m)
			runtimeReseal(&m)
			if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
				t.Fatal("invalid contract widened transport even without desktop grants")
			}
		})
	}
	for name, mutate := range map[string]func(*EngineTunnel){"bgp": func(e *EngineTunnel) { e.BGP = true }, "provider": func(e *EngineTunnel) { e.ProfileID = GCPClassicStaticProfile }, "version": func(e *EngineTunnel) { e.DesktopStaticVersion = 2 }} {
		t.Run("engine/"+name, func(t *testing.T) {
			cfg := staticTransportEntry(t, true).Engines[0]
			mutate(&cfg)
			if validEngineTunnel(cfg) {
				t.Fatal("invalid engine transport marker")
			}
		})
	}
}

// The original live defect had valid DNS, routes and guards, but a LAN-only SA.
// Exercise actual selector proof before the shared renewal can publish permits.
func TestDesktopStaticTransportNarrowNativeCannotRenewPermission(t *testing.T) {
	for _, fqdn := range []bool{false, true} {
		t.Run(map[bool]string{false: "CIDR", true: "managed_CNAME"}[fqdn], func(t *testing.T) {
			var r *renewalCycleRig
			if fqdn {
				r, _ = fqdnExpiryTurnoverRig(t, true)
			} else {
				var id uuid.UUID
				r, id = desktopStaticRenewalRig(t)
				r.target = id
			}
			before := r.c.active[r.target]
			old := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				if e.Allocation.ConnectionID != r.target {
					return old(ctx, e, env)
				}
				d, k, x := sharedStaticInventories(e, 0)
				d.SAs[0].Children[0].LocalPrefixes = e.Engines[0].LocalPrefixes
				return runtimeInventoryMatches(e, d, k, x)
			}
			_ = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
			if _, ok := r.c.active[r.target]; ok || !r.applicationDenied[r.target] {
				t.Fatal("LAN-only native SA acquired renewed desktop authority")
			}
			if before.Authority.deadline <= 0 {
				t.Fatal("fixture never had finite authority")
			}
		})
	}
}

func TestDesktopStaticTransportLegacyLANPreservesBGPSibling(t *testing.T) {
	r, id, _, _ := desktopBGPRenewalRig(t, true)
	r.target = id
	bgpBefore := r.c.active[r.target]
	if bgpBefore.Entry.ContractVersion != 3 {
		t.Fatal("fixture missing BGP sibling")
	}
	var legacyID uuid.UUID
	materials := maintenanceMaterials(r)
	for i := range materials {
		m := &materials[i]
		if m.Manifest.ProfileID != "aws-static-ipv4-v1" {
			continue
		}
		if m.Manifest.DesktopStaticVersion != nil {
			t.Fatal("fixture is not legacy narrow transport")
		}
		legacyID = m.Manifest.ConnectionID
		// The matching API capability/delivery gate withholds desktop grants,
		// preserving this legacy delivery and its original LAN permissions.
		if len(m.Policy.DesktopGrants) != 0 || len(m.Policy.FQDNGrants) != 0 {
			t.Fatal("legacy producer shape contains desktop authority")
		}
	}
	if legacyID == uuid.Nil {
		t.Fatal("fixture missing legacy owner")
	}
	results, maintenanceErr := r.c.maintainIPsecRuntime(context.Background(), materials, maintenanceAuthority(r), func() bool { return true })
	after, ok := r.c.active[r.target]
	if !ok || after.Authority == bgpBefore.Authority || r.applicationDenied[r.target] || !reflect.DeepEqual(after.Entry, bgpBefore.Entry) {
		t.Fatalf("valid legacy LAN material starved independent BGP owner: present=%v renewed=%v denied=%v entrySame=%v results=%v err=%v", ok, after.Authority != bgpBefore.Authority, r.applicationDenied[r.target], reflect.DeepEqual(after.Entry, bgpBefore.Entry), results, maintenanceErr)
	}
	legacy, ok := r.c.active[legacyID]
	if !ok || runtimeDesktopEntrySupported(legacy.Entry) {
		t.Fatal("legacy LAN transport changed or acquired desktop support")
	}
	for _, g := range legacy.Grants {
		if g.DesktopDeviceID != uuid.Nil {
			t.Fatal("legacy owner acquired desktop grant")
		}
	}
	for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
		if r.installed[name] <= *r.now {
			t.Fatal("independent BGP native permit expired")
		}
	}
}

func TestDesktopStaticTransportRestorationRetainsSelectorContract(t *testing.T) {
	for _, quiesced := range []bool{false, true} {
		t.Run(map[bool]string{false: "applied", true: "quiesced"}[quiesced], func(t *testing.T) {
			e := staticTransportEntry(t, true)
			owner := e.Engines[0].Binding.GatewayID
			dir := journalDir(t)
			j, err := OpenRuntimeJournal(dir, owner)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			e = saveAppliedRestorationFixture(t, j, e)
			e.Restoration = &RuntimeRestoration{BootID: uuid.NewString()}
			if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
				t.Fatal(err)
			}
			if quiesced {
				e.Phase = RuntimeQuiesced
				if err = j.Save([]RuntimeJournalEntry{e}); err == nil {
					t.Fatal("static transport adopted BGP-only quiesced checkpoint")
				}
				return
			}
			n := restoredFixture(e)
			if err = j.Save([]RuntimeJournalEntry{n}); err != nil {
				t.Fatal("marked restoration reservation", err)
			}
			j.Close()
			j, err = OpenRuntimeJournal(dir, owner)
			if err != nil {
				t.Fatal("restoration reopen", err)
			}
			defer j.Close()
			got, err := j.Entries()
			if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], n) {
				t.Fatal("marked restoration history lost", err)
			}
			if j.payload.Version != 15 || retiredJournalVersion(got[0].Restoration.Retired[0].Entry) != 15 {
				t.Fatal("history presented new selectors as legacy")
			}
			n2 := restoredFixture(n)
			if err = j.Save([]RuntimeJournalEntry{n2}); err != nil {
				t.Fatal("second marked restoration", err)
			}
			bad := cloneJournal(j.payload)
			bad.Entries[0].Restoration.Retired[0].Entry.Engines[0].DesktopStaticVersion = 0
			if validJournalPayload(bad) {
				t.Fatal("restoration silently changed retired selector ownership")
			}
			if j.Save([]RuntimeJournalEntry{n}) == nil {
				t.Fatal("restoration rollback accepted")
			}
		})
	}
}

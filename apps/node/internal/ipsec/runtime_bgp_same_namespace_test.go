package ipsec

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"reflect"
	"strconv"
	"testing"
)

func TestGCPAppliedSameNamespaceMissingDaemonTransport(t *testing.T) {
	for _, fault := range []string{"none", "initial boot", "foreign config", "partial config", "missing links", "environment drift", "cancelled", "expired lease", "wrong namespace", "loaded target", "foreign key", "one loaded slot", "AWS unchanged", "other bytes", "other SPI", "other rekey", "other unknown SA"} {
		t.Run(fault, func(t *testing.T) {
			m := gcpMaterialFixture()
			if fault == "AWS unchanged" {
				m = bgpMaterialFixture()
			}
			initial, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
			if err != nil {
				t.Fatal(err)
			}
			c, f, _, denied := bgpControllerEntryFixture(t, false, initial)
			entries, _ := c.journal.Entries()
			e := entries[0]
			e.Phase = RuntimeApplied
			e.Restoration = nil
			e.BGPRoutes = nil
			for i, a := range e.Allocation.Tunnels {
				e.Observed[i] = Ownership{Namespace: e.Allocation.Namespace, InterfaceName: a.Name, InterfaceIndex: 10 + i, XFRMID: a.XFRMID}
			}
			f.p = e.Allocation
			f.mtu = [2]uint64{uint64(runtimeProfileMTU(e.Allocation.ProfileID)), uint64(runtimeProfileMTU(e.Allocation.ProfileID))}
			active := c.active[e.Allocation.ConnectionID]
			c.config.Environment = &gcpExportEnvironment{entry: e, env: active.Environment}
			mutations := 0
			c.config.Daemon = daemonInventoryStub(nil, viciMessage{}, &mutations)
			c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"down", "down"} }
			ctx := context.Background()
			preparedEntries := []RuntimeJournalEntry{e}
			switch fault {
			case "other bytes", "other SPI", "other rekey", "other unknown SA":
				otherMaterial := classicMaterialFixture()
				otherMaterial.ID = uuid.New()
				otherMaterial.Manifest.ConnectionID = uuid.New()
				id := uuid.New()
				otherMaterial.Manifest.Tunnels[0].ID = id
				otherMaterial.Manifest.Tunnels[0].LinkName = KernelTunnelName(id)
				otherMaterial.Manifest.Tunnels[0].XFRMID = KernelTunnelID(id)
				otherMaterial.Manifest.Tunnels[0].ReqID = KernelTunnelID(id)
				otherMaterial.Secrets[0].TunnelID = id
				otherMaterial.Manifest.RemotePrefixes = []string{"10.81.0.0/24"}
				runtimeReseal(&otherMaterial)
				other, _, err := runtimeMaterialEntry(otherMaterial, otherMaterial.Manifest.OrgID, otherMaterial.Manifest.NodeID, e.Allocation.Namespace)
				if err != nil {
					t.Fatal(err)
				}
				other.Phase = RuntimeApplied
				preparedEntries = append(preparedEntries, other)
				request := c.config.Daemon.request
				reads := 0
				c.config.Daemon.request = func(ctx context.Context, command, event string, message viciMessage) (viciMessage, []viciMessage, error) {
					name := engineName(other.Engines[0])
					if command == "get-conns" {
						return viciMessage{"conns": viciList(name)}, nil, nil
					}
					if command == "get-shared" {
						return viciMessage{"keys": viciList(name)}, nil, nil
					}
					if command == "list-sas" {
						reads++
						sa := sameNamespaceOwnedSAEvent(other.Engines[0])
						child := sa[name].section["child-sas"].section["child-1"].section
						child["bytes-in"] = viciText(strconv.Itoa(reads))
						child["bytes-out"] = viciText(strconv.Itoa(reads * 2))
						if reads > 1 {
							switch fault {
							case "other SPI":
								child["spi-in"] = viciText("12345679")
							case "other rekey":
								child["state"] = viciText("REKEYING")
							case "other unknown SA":
								sa["foreign-sa"] = sa[name]
								delete(sa, name)
							}
						}
						return viciMessage{}, []viciMessage{sa}, nil
					}
					return request(ctx, command, event, message)
				}
			case "initial boot":
				boot, err := resetBootID()
				if err != nil {
					t.Skip("native boot provenance unavailable")
				}
				e.Restoration = &RuntimeRestoration{BootID: boot}
			case "foreign config", "partial config", "loaded target", "foreign key", "one loaded slot":
				request := c.config.Daemon.request
				c.config.Daemon.request = func(ctx context.Context, command, event string, message viciMessage) (viciMessage, []viciMessage, error) {
					if fault == "loaded target" && (command == "get-conns" || command == "get-shared") {
						key := "conns"
						if command == "get-shared" {
							key = "keys"
						}
						return viciMessage{key: viciList(engineName(e.Engines[0]), engineName(e.Engines[1]))}, nil, nil
					}
					if fault == "foreign key" && command == "get-shared" {
						return viciMessage{"keys": viciList("foreign-key")}, nil, nil
					}
					if fault == "one loaded slot" && (command == "get-conns" || command == "get-shared") {
						key := "conns"
						if command == "get-shared" {
							key = "keys"
						}
						return viciMessage{key: viciList(engineName(e.Engines[0]))}, nil, nil
					}
					if command == "get-conns" && (fault == "foreign config" || fault == "partial config") {
						name := "foreign-connection"
						if fault == "partial config" {
							name = engineName(e.Engines[0])
						}
						return viciMessage{"conns": viciList(name)}, nil, nil
					}
					return request(ctx, command, event, message)
				}
			case "missing links":
				f.deleted = [2]bool{true, true}
				f.routes = [2]map[string]bool{{}, {}}
			case "environment drift":
				c.config.Environment.(*gcpExportEnvironment).changed = true
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "expired lease":
				active.Authority.Invalidate()
			case "wrong namespace":
				c.namespace = func() (string, error) { return "net:[999]", nil }
			}
			recreate, missing, err := c.bgpRestoredTransportAbsent(ctx, e, preparedEntries, active.Authority, active.Identity, active.Environment)
			if fault == "AWS unchanged" || fault == "loaded target" {
				if err != nil || recreate || missing || *denied || mutations != 0 {
					t.Fatal("existing transport path changed", fault, err)
				}
				return
			}
			if fault != "none" && fault != "initial boot" && fault != "other bytes" {
				if err == nil || recreate {
					t.Fatal("unsafe restart admitted", fault)
				}
				return
			}
			if err != nil || !recreate || missing || !*denied {
				t.Fatalf("fresh daemon with retained Applied links not staged: recreate=%v missing=%v denied=%v err=%v", recreate, missing, *denied, err)
			}
			if mutations != 0 {
				t.Fatal("preparation mutated daemon")
			}
			if fault == "other bytes" {
				return
			}
			persistedBefore, _ := c.journal.Entries()
			owned, err := c.kernel.Apply(ctx, e.Allocation, e.Observed)
			if err != nil || owned != e.Observed {
				t.Fatal("retained native ownership was replaced", err)
			}
			for i, engine := range e.Engines {
				if err := c.config.Daemon.removeTunnel(ctx, engine); err != nil {
					t.Fatal(err)
				}
				if err := c.config.Daemon.stageTunnel(ctx, engine, []byte(m.Secrets[i].PSK)); err != nil {
					t.Fatal("normal stage refused", err)
				}
			}
			if mutations != 4 {
				t.Fatal("two normal load-shared/load-conn pairs missing", mutations)
			}
			persistedAfter, _ := c.journal.Entries()
			if !reflect.DeepEqual(persistedBefore, persistedAfter) {
				t.Fatal("preparation manufactured restoration or changed journal")
			}

		})
	}
}

func sameNamespaceOwnedSAEvent(engine EngineTunnel) viciMessage {
	base := daemonSAFixture()["owned"].section
	name := engineName(engine)
	base["local-host"] = viciText(engine.LocalAddress.String())
	base["remote-host"] = viciText(engine.RemoteAddress.String())
	child := base["child-sas"].section["child-1"].section
	child["name"] = viciText(name)
	child["reqid"] = viciText(strconv.FormatUint(uint64(engine.ReqID), 10))
	child["if-id-in"] = viciText(fmt.Sprintf("%08x", engine.XFRMID))
	child["if-id-out"] = child["if-id-in"]
	child["local-ts"] = enginePrefixes(engineTransportPrefixes(engine, true))
	child["remote-ts"] = enginePrefixes(engineTransportPrefixes(engine, false))
	return viciMessage{name: viciSection(base)}
}

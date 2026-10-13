package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func azureCleanupEntryFixture(t *testing.T) RuntimeJournalEntry {
	t.Helper()
	m := azureMaterialFixture(AzureActiveActiveBGPProfile)
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	e.Phase = RuntimeCleanupPending
	e.CleanupID = uuid.New()
	e.CleanupDesiredRevision = m.DesiredRevision + 1
	e.CoveredDeliveryRevision = m.DesiredRevision
	return e
}
func azureCleanupDaemonFixture(t *testing.T, e RuntimeJournalEntry, change func(viciMessage)) (*DaemonClient, *int) {
	t.Helper()
	tunnel := e.Engines[0]
	events := []viciMessage{}
	for _, id := range []string{"1", "2"} {
		ike := daemonSAFixture()["owned"].section
		ike["uniqueid"] = viciText(id)
		ike["local-host"] = viciText(tunnel.LocalAddress.String())
		ike["remote-host"] = viciText(tunnel.RemoteAddress.String())
		child := ike["child-sas"].section["child-1"].section
		child["name"] = viciText(engineName(tunnel))
		child["reqid"] = viciText(fmt.Sprint(tunnel.ReqID))
		child["if-id-in"] = viciText(fmt.Sprintf("%08x", tunnel.XFRMID))
		child["if-id-out"] = child["if-id-in"]
		if id == "1" {
			child["local-ts"] = viciList(e.Allocation.Tunnels[0].InsideAddress.String())
			child["remote-ts"] = enginePrefixes(tunnel.RemotePrefixes)
			if change != nil {
				change(child)
			}
		} else {
			child["uniqueid"] = viciText("4")
			child["spi-in"] = viciText("12345679")
			child["spi-out"] = viciText("87654322")
			child["local-ts"] = viciList("0.0.0.0/0")
			child["remote-ts"] = viciList("0.0.0.0/0")
		}
		events = append(events, viciMessage{engineName(tunnel): viciSection(ike)})
	}
	mutations := new(int)
	c := daemonInventoryStub(events, viciMessage{}, mutations)
	base := c.request
	terminated := 0
	c.request = func(ctx context.Context, cmd, event string, m viciMessage) (viciMessage, []viciMessage, error) {
		if cmd == "list-sas" && terminated == 2 {
			return viciMessage{}, nil, nil
		}
		if cmd == "terminate" {
			if _, ok := viciString(m, "ike-id"); !ok {
				t.Fatal("nonexact termination")
			}
			terminated++
		}
		return base(ctx, cmd, event, m)
	}
	return c, mutations
}
func TestAzureNarrowCleanupCausalAndStrictPositivePreserved(t *testing.T) {
	e := azureCleanupEntryFixture(t)
	c, mutations := azureCleanupDaemonFixture(t, e, nil)
	if c.removeTunnel(t.Context(), e.Engines[0]) == nil || *mutations != 0 {
		t.Fatal("ordinary wrapper widened")
	}
	d, err := c.Inspect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = ownedRuntimeChildren(e.Engines[0], d); err == nil {
		t.Fatal("positive duplicate ownership widened")
	}
	if err = c.removeAzureCleanupTunnel(t.Context(), e, 0, e.Allocation.Namespace); err != nil || *mutations != 2 {
		t.Fatal("exact negative-only cleanup failed", err, *mutations)
	}
}
func TestAzureNarrowCleanupRejectsForeignSelectorsAndBindings(t *testing.T) {
	for _, scenario := range []string{"foreign_local", "foreign_remote", "wrong_inside", "noncanonical", "default_mix", "duplicate", "empty", "wrong_name", "wrong_ifid", "wrong_reqid", "wrong_namespace", "wrong_phase", "wrong_profile", "wrong_allocation", "zero_reqid"} {
		t.Run(scenario, func(t *testing.T) {
			e := azureCleanupEntryFixture(t)
			namespace := e.Allocation.Namespace
			c, mutations := azureCleanupDaemonFixture(t, e, func(child viciMessage) {
				switch scenario {
				case "foreign_local":
					child["local-ts"] = viciList("203.0.113.0/24")
				case "foreign_remote":
					child["remote-ts"] = viciList("203.0.113.0/24")
				case "wrong_inside":
					child["local-ts"] = viciList("169.254.10.2/32")
				case "noncanonical":
					child["local-ts"] = viciList("10.10.0.1/24")
				case "default_mix":
					child["local-ts"] = viciList("0.0.0.0/0", e.Allocation.Tunnels[0].InsideAddress.String())
				case "duplicate":
					child["local-ts"] = viciList(e.Allocation.Tunnels[0].InsideAddress.String(), e.Allocation.Tunnels[0].InsideAddress.String())
				case "empty":
					child["local-ts"] = viciList()
				case "wrong_name":
					child["name"] = viciText("foreign")
				case "wrong_ifid":
					child["if-id-out"] = viciText("ffffffff")
				case "wrong_reqid":
					child["reqid"] = viciText("999")
				}
			})
			switch scenario {
			case "wrong_namespace":
				namespace = "net:[42]"
			case "wrong_phase":
				e.Phase = RuntimeApplied
			case "wrong_profile":
				e.Allocation.ProfileID = GCPHABGPProfile
			case "wrong_allocation":
				e.Allocation.Tunnels[0].TunnelID = uuid.New()
			case "zero_reqid":
				e.Engines[0].ReqID = 0
			}
			if c.removeAzureCleanupTunnel(t.Context(), e, 0, namespace) == nil || *mutations != 0 {
				t.Fatal("unsafe cleanup mutated", *mutations)
			}
		})
	}
}

func TestAzureNarrowCleanupThroughNormalControllerDenial(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprint(foreign), func(t *testing.T) {
			m := azureMaterialFixture(AzureActiveActiveBGPProfile)
			grants := dnsMaterialFixture().Policy.DNSResolverGrants
			grants[0].ConnectionID = m.Manifest.ConnectionID
			grants[0].ConfigurationRevision = m.Manifest.ConfigurationRevision
			m.Policy.DNSResolverGrants = grants
			runtimeReseal(&m)
			f := newDNSOwnerViewMaterialFixture(t, m, nil)
			c := f.c
			e, _, buildErr := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			if err := c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
				t.Fatal("reserve owned cleanup fixture", err)
			}
			e.Phase = RuntimeCleanupPending
			e.CleanupID = uuid.New()
			e.CleanupDesiredRevision = m.DesiredRevision + 1
			e.CoveredDeliveryRevision = m.DesiredRevision
			if err := c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
				t.Fatal("journal entry", err, validJournalPayload(runtimeJournalPayload{Version: 10, OwnerID: m.Manifest.NodeID, Entries: []RuntimeJournalEntry{e}}))
			}
			c.namespace = func() (string, error) { return e.Allocation.Namespace, nil }
			denied := false
			c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				for _, connection := range in.Connections {
					if len(connection.Grants) != 0 {
						t.Fatal("cleanup published permit")
					}
				}
				denied = true
				return RenderGuard(in)
			}
			daemon, mutations := azureCleanupDaemonFixture(t, e, func(child viciMessage) {
				if foreign {
					child["local-ts"] = viciList("203.0.113.0/24")
				}
			})
			base := daemon.request
			daemon.request = func(ctx context.Context, cmd, event string, msg viciMessage) (viciMessage, []viciMessage, error) {
				if cmd == "terminate" && !denied {
					t.Fatal("native mutation before denial")
				}
				return base(ctx, cmd, event, msg)
			}
			c.config.Daemon = daemon
			c.kernel = &KernelApplier{namespace: c.namespace, run: func(ctx context.Context, args ...string) ([]byte, error) {
				if strings.Contains(strings.Join(args, " "), "xfrm") {
					return nil, nil
				}
				return []byte("[]"), nil
			}}
			c.config.Environment = &mtuEnvironmentFixture{}
			cleanup := RuntimeCleanup{RuntimeDelivery: m.RuntimeDelivery, RetainGuard: true, Lineage: []RuntimeDelivery{m.RuntimeDelivery}}
			cleanup.ID = e.CleanupID
			cleanup.Kind = "cleanup"
			cleanup.DesiredRevision = m.DesiredRevision + 1
			cleanup.CoversDeliveryRevision = m.DesiredRevision
			raw, _ := json.Marshal(cleanup.Lineage)
			cleanup.OwnershipDigest = stringDigest(raw)
			ack, err := c.Cleanup(t.Context(), cleanup)
			if foreign {
				if err == nil || *mutations != 0 || !denied {
					t.Fatal("foreign cleanup mutated")
				}
				return
			}
			if err != nil || *mutations != 2 || !denied || !ack.GuardRetained {
				t.Fatal("normal cleanup refused", err, *mutations, ack)
			}
		})
	}
}

func TestAzureCleanupSelectorCanonicalBound(t *testing.T) {
	approved := []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}
	if !azureCleanupSelectors([]netip.Prefix{netip.MustParsePrefix("10.10.0.0/25")}, approved) {
		t.Fatal("approved narrower selector refused")
	}
}

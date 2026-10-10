package ipsec

// Test-only read-only proof projection. No controller, Process adoption or authority.
import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

type azureMaxProofBinding struct {
	HistoricalBoot        *azureProofHistoricalPins `json:"historical_boot,omitempty"`
	Mode                  string                    `json:"mode"`
	OrgID                 uuid.UUID                 `json:"org_id"`
	SiteID                uuid.UUID                 `json:"site_id"`
	GatewayID             uuid.UUID                 `json:"gateway_id"`
	ConnectionID          uuid.UUID                 `json:"connection_id"`
	DesiredRevision       int64                     `json:"desired_revision"`
	ConfigurationRevision int64                     `json:"configuration_revision"`
	MaximumPrefixes       int                       `json:"maximum_prefixes"`
	NamespaceDevice       uint64                    `json:"namespace_device"`
	NamespaceInode        uint64                    `json:"namespace_inode"`
	NodeExecutableSHA256  string                    `json:"node_executable_sha256"`
}

func azureProofParentMatches(parent, node int) bool { return node > 0 && parent == node }

func azureProofSocketMatches(actual, expected bgpengine.FileIdentity) bool {
	return expected.Device > 0 && expected.Inode > 0 && actual == expected && actual.Mode == uint32(os.ModeSocket|0600)
}

func TestAzureMaxProofParentAndSocketIdentityRefusals(t *testing.T) {
	if !azureProofParentMatches(1, 1) || azureProofParentMatches(2, 1) || azureProofParentMatches(0, 0) {
		t.Fatal("managed parent predicate")
	}
	want := bgpengine.FileIdentity{Device: 1, Inode: 2, Mode: uint32(os.ModeSocket | 0600)}
	if !azureProofSocketMatches(want, want) {
		t.Fatal("matching socket refused")
	}
	for _, actual := range []bgpengine.FileIdentity{
		{Device: 2, Inode: 2, Mode: want.Mode}, {Device: 1, Inode: 3, Mode: want.Mode},
		{Device: 1, Inode: 2, Mode: uint32(os.ModeSocket | 0660)}, {Device: 1, Inode: 2, Mode: 0600},
	} {
		if azureProofSocketMatches(actual, want) {
			t.Fatal("changed socket accepted")
		}
	}
	if azureProofSocketMatches(bgpengine.FileIdentity{}, bgpengine.FileIdentity{}) {
		t.Fatal("missing attestation accepted")
	}
}

func azureMaxProofEntry(p runtimeJournalPayload, b azureMaxProofBinding, ns string) (RuntimeJournalEntry, error) {
	return azureMaxProofEntryHistory(p, b, ns, nil)
}

func azureMaxProofEntryHistory(p runtimeJournalPayload, b azureMaxProofBinding, ns string, historical map[uuid.UUID]bool) (RuntimeJournalEntry, error) {
	bad := func() (RuntimeJournalEntry, error) { return RuntimeJournalEntry{}, fmt.Errorf("journal_scope_refused") }
	if !validJournalPayload(p) || p.OwnerID != b.GatewayID || b.OrgID == uuid.Nil || b.SiteID == uuid.Nil || b.ConnectionID == uuid.Nil || b.DesiredRevision < 1 || b.ConfigurationRevision < 1 || (b.Mode != "baseline" && b.Mode != "absence") || len(p.Entries) == 0 || len(p.Guards) != 1 || p.Guards[0].Namespace != ns {
		return bad()
	}
	var selected RuntimeJournalEntry
	active := 0
	latest := int64(0)
	for _, e := range p.Entries {
		// Site mapping is directly recorded, not filled from a normal API response.
		if e.SiteID != b.SiteID || (e.Allocation.Namespace != ns && !historical[e.DeliveryID]) || e.Engines[0].Binding.OrgID != b.OrgID || e.Engines[0].Binding.GatewayID != b.GatewayID {
			return bad()
		}
		if e.Phase != RuntimeRetainedRefusal {
			active++
			if b.Mode == "absence" || e.Phase != RuntimeApplied {
				return bad()
			}
			selected = e
		}
		if e.Phase == RuntimeRetainedRefusal {
			if e.BGPRoutes != nil && (e.BGPRoutes.Stage != "completed" || !e.BGPRoutes.Withdrawal || len(e.BGPRoutes.Owned) != 0 || len(e.BGPRoutes.Target) != 0) {
				return bad()
			}
			duties := append([]bgpengine.ProcessIdentity(nil), e.BGPProcessRetired...)
			if e.BGPProcess != nil {
				duties = append(duties, *e.BGPProcess)
			}
			for _, d := range duties {
				if d.Stage != "cleaned" {
					return bad()
				}
			}
			if b.Mode == "absence" && e.Allocation.ConnectionID == b.ConnectionID && e.Engines[0].Binding.ConfigurationRevision == b.ConfigurationRevision && e.Engines[0].Binding.DesiredRevision > latest {
				selected = e
				latest = e.Engines[0].Binding.DesiredRevision
			}
		}
	}
	if b.Mode == "baseline" && active != 1 || b.Mode == "absence" && (active != 0 || latest == 0) {
		return bad()
	}
	if selected.Allocation.ConnectionID != b.ConnectionID || selected.SiteID != b.SiteID || selected.ContractVersion != 3 || selected.Allocation.ProfileID != AzureActiveActiveBGPProfile || selected.Allocation.activeTunnelCount() != 2 || selected.AbsenceOnly {
		return bad()
	}
	cfg, err := runtimeBGPProcessConfig(selected)
	if err != nil || cfg.MaximumPrefixes != b.MaximumPrefixes || cfg.LocalPrefixes == nil || !sameEnginePrefixes(cfg.LocalPrefixes, []netip.Prefix{netip.MustParsePrefix("10.233.10.0/24")}) {
		return bad()
	}
	expected := []netip.Prefix{netip.MustParsePrefix("10.231.0.0/16")}
	if b.MaximumPrefixes == 1 {
		expected = append(expected, netip.MustParsePrefix("10.235.77.0/24"))
	} else if b.MaximumPrefixes != 8 {
		return bad()
	}
	if !sameEnginePrefixes(cfg.RemotePrefixes, expected) {
		return bad()
	}
	actualRevision := selected.Engines[0].Binding.DesiredRevision
	if b.Mode == "absence" {
		actualRevision = selected.CleanupDesiredRevision
	}
	if actualRevision != b.DesiredRevision || selected.Engines[0].Binding.ConfigurationRevision != b.ConfigurationRevision {
		return bad()
	}
	return selected, nil
}

func azureMaxProofBaseline(e RuntimeJournalEntry, d DaemonInventory, k KernelInventory, x XFRMInventory, status bgpengine.Status, routes []bgpengine.LearnedRoute) error {
	if k.Namespace != e.Allocation.Namespace || x.Namespace != e.Allocation.Namespace || len(d.SAs) != 2 || len(d.Connections) != 2 || len(d.SharedKeys) != 2 || len(x.States) != 4 || len(x.Policies) != 6 || e.BGPRoutes == nil || e.BGPRoutes.Stage != "completed" || e.BGPRoutes.Withdrawal || !reflect.DeepEqual(e.BGPRoutes.Owned, e.BGPRoutes.Target) || len(e.BGPRoutes.Owned) != 1 || len(routes) != 1 || routes[0].Prefix != netip.MustParsePrefix("10.231.0.0/16") {
		return fmt.Errorf("baseline_inventory_refused")
	}
	slots := azureNativeSlotDiagnostic(e, d, k, x)
	if len(slots) != 2 {
		return fmt.Errorf("baseline_slots_refused")
	}
	for i, s := range slots {
		if s.Status != "up" || s.Category != "native_observation" || s.IKEMatches != 1 || s.ChildStates["INSTALLED"] != 1 || len(s.ChildStates) != 1 || s.SADMatches != 2 || !reflect.DeepEqual(s.SPDDirections, map[string]int{"in": 1, "out": 1, "fwd": 1}) || !s.StoredConnection || !s.StoredSharedKey || status.Peers[i].Slot != i+1 || status.Peers[i].State != "established" || status.Peers[i].AcceptedPrefixes != 1 {
			return fmt.Errorf("baseline_slot_or_peer_refused")
		}
	}
	r := e.BGPRoutes.Owned[0]
	if r.Prefix != routes[0].Prefix || int(r.Slot) != routes[0].Slot || r.InterfaceIndex != e.Observed[r.Slot-1].InterfaceIndex || r.Table != 254 || r.Protocol != 242 || r.Metric != 50000+uint32(r.Slot) {
		return fmt.Errorf("baseline_route_binding_refused")
	}
	expected := map[RouteTuple]bool{{Destination: r.Prefix, Table: r.Table, Protocol: uint8(r.Protocol), Metric: r.Metric, OutputInterface: r.InterfaceIndex}: true}
	for i, t := range e.Allocation.Tunnels {
		expected[RouteTuple{Destination: netip.PrefixFrom(t.BGP.Peer, 32), Table: 254, Protocol: 242, Metric: 50001 + uint32(i), OutputInterface: e.Observed[i].InterfaceIndex}] = true
	}
	for _, route := range k.Routes {
		if route.Destination == netip.MustParsePrefix("10.235.77.0/24") {
			return fmt.Errorf("candidate_route_present")
		}
		if route.Protocol != 242 {
			continue
		}
		if !expected[route.RouteTuple] || route.Kind != 1 {
			return fmt.Errorf("unexpected_owned_route")
		}
		delete(expected, route.RouteTuple)
	}
	if len(expected) != 0 {
		return fmt.Errorf("owned_route_missing")
	}
	return nil
}

func azureMaxProofAbsence(p runtimeJournalPayload, d DaemonInventory, k KernelInventory, x XFRMInventory) error {
	return azureMaxProofAbsenceHistory(p, d, k, x, nil)
}
func azureMaxProofAbsenceHistory(p runtimeJournalPayload, d DaemonInventory, k KernelInventory, x XFRMInventory, historical map[uuid.UUID]bool) error {
	if len(d.SAs) != 0 || len(d.Connections) != 0 || len(d.SharedKeys) != 0 || len(x.States) != 0 || len(x.Policies) != 0 {
		return fmt.Errorf("native_objects_remain")
	}
	for _, e := range p.Entries {
		if e.Phase != RuntimeRetainedRefusal || k.Namespace != x.Namespace || (k.Namespace != e.Allocation.Namespace && !historical[e.DeliveryID]) {
			return fmt.Errorf("retained_scope_refused")
		}
		for _, t := range e.Allocation.Tunnels[:e.Allocation.activeTunnelCount()] {
			for _, link := range k.Links {
				if link.Name == t.Name || link.XFRMID != 0 && link.XFRMID == t.XFRMID {
					return fmt.Errorf("owned_interface_remains")
				}
			}
		}
	}
	for _, r := range k.Routes {
		if r.Protocol == 242 {
			return fmt.Errorf("owned_route_remains")
		}
	}
	return nil
}

func azureMaxProofProjection(p runtimeJournalPayload, e RuntimeJournalEntry, b azureMaxProofBinding, observed time.Time, journalHash string, d DaemonInventory, k KernelInventory, x XFRMInventory, status bgpengine.Status, routes []bgpengine.LearnedRoute) map[string]any {
	desired := e.Engines[0].Binding.DesiredRevision
	result := map[string]any{"version": 1, "observed_at": observed.UTC().Format(time.RFC3339Nano), "org_id": e.Engines[0].Binding.OrgID.String(), "site_id": e.SiteID.String(), "gateway_id": p.OwnerID.String(), "connection_id": e.Allocation.ConnectionID.String(), "configuration_revision": e.Engines[0].Binding.ConfigurationRevision, "journal_sha256": journalHash, "journal_entries": len(p.Entries), "scope": "Independent bracketed native observation only; no authority, synthetic acknowledgement or packet readiness"}
	if b.Mode == "absence" {
		desired = e.CleanupDesiredRevision
		result["kind"] = "owned_native_cleanup_absence"
		result["azure_connection_id"] = "/subscriptions/34e2f259-b462-40bf-8f4a-06a3930d99e6/resourceGroups/tunnex-azure-s2s-20261010/providers/Microsoft.Network/connections/tunnex-connection"
		result["guard_retained"] = true
		result["namespace_device"] = b.NamespaceDevice
		result["namespace_inode"] = b.NamespaceInode
		result["owned_ike"] = len(d.SAs)
		children := 0
		for _, sa := range d.SAs {
			children += len(sa.Children)
		}
		result["owned_children"] = children
		result["owned_sad"] = len(x.States)
		result["owned_spd"] = len(x.Policies)
		links := 0
		for _, link := range k.Links {
			for _, entry := range p.Entries {
				for _, tunnel := range entry.Allocation.Tunnels[:entry.Allocation.activeTunnelCount()] {
					if link.Name == tunnel.Name || link.XFRMID != 0 && link.XFRMID == tunnel.XFRMID {
						links++
					}
				}
			}
		}
		count := 0
		for _, route := range k.Routes {
			if route.Protocol == 242 {
				count++
			}
		}
		result["owned_interfaces"] = links
		result["owned_routes"] = count
	} else {
		result["kind"] = "owned_max_prefix_baseline"
		result["namespace"] = map[string]uint64{"device": b.NamespaceDevice, "inode": b.NamespaceInode}
		native := map[string]int{"sad": len(x.States), "spd_in": 0, "spd_out": 0, "spd_fwd": 0}
		for _, policy := range x.Policies {
			native["spd_"+policy.Direction]++
		}
		result["native"] = native
		tunnels := []map[string]any{}
		for _, slot := range azureNativeSlotDiagnostic(e, d, k, x) {
			tunnels = append(tunnels, map[string]any{"slot": slot.Slot, "state": slot.Status, "owned_ike": slot.IKEMatches, "owned_installed_children": slot.ChildStates["INSTALLED"]})
		}
		result["tunnels"] = tunnels
		peers := []map[string]any{}
		for _, peer := range status.Peers {
			peers = append(peers, map[string]any{"slot": peer.Slot, "state": peer.State, "accepted_prefixes": peer.AcceptedPrefixes})
		}
		prefixes := []string{}
		for _, route := range routes {
			prefixes = append(prefixes, route.Prefix.String())
		}
		result["bgp"] = map[string]any{"peers": peers, "routes": prefixes}
	}
	result["desired_revision"] = desired
	return result
}

func azureMaxProofFixture(t *testing.T) (runtimeJournalPayload, RuntimeJournalEntry, azureMaxProofBinding, DaemonInventory, KernelInventory, XFRMInventory, bgpengine.Status, []bgpengine.LearnedRoute) {
	t.Helper()
	m := azureMaterialFixture(AzureActiveActiveBGPProfile)
	m.DesiredRevision = 40
	m.Manifest.DesiredRevision = 40
	m.Manifest.ConfigurationRevision = 7
	m.Manifest.LocalPrefixes = []string{"10.233.10.0/24"}
	m.Manifest.RemotePrefixes = []string{"10.231.0.0/16", "10.235.77.0/24"}
	m.Manifest.BGP.MaximumPrefixes = 1
	runtimeReseal(&m)
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	e.Phase = RuntimeApplied
	d := DaemonInventory{}
	k := KernelInventory{Namespace: e.Allocation.Namespace}
	x := XFRMInventory{Namespace: e.Allocation.Namespace}
	wide := netip.MustParsePrefix("0.0.0.0/0")
	for i, tunnel := range e.Engines {
		e.Observed[i] = Ownership{Namespace: k.Namespace, InterfaceName: e.Allocation.Tunnels[i].Name, InterfaceIndex: 10 + i, XFRMID: tunnel.XFRMID}
		k.Links = append(k.Links, KernelLink{Name: e.Observed[i].InterfaceName, Index: 10 + i, XFRMID: tunnel.XFRMID, Up: true})
		d.Connections = append(d.Connections, engineName(tunnel))
		d.SharedKeys = append(d.SharedKeys, engineName(tunnel))
		child := DaemonChild{Name: engineName(tunnel), State: "INSTALLED", UniqueID: uint64(i + 1), ReqID: tunnel.ReqID, IfIDIn: tunnel.XFRMID, IfIDOut: tunnel.XFRMID, SPIIn: uint32(100 + i), SPIOut: uint32(200 + i), Installed: true, LocalPrefixes: []netip.Prefix{wide}, RemotePrefixes: []netip.Prefix{wide}}
		d.SAs = append(d.SAs, DaemonIKE{Name: engineName(tunnel), UniqueID: uint64(i + 1), Established: true, LocalAddress: tunnel.LocalAddress, RemoteAddress: tunnel.RemoteAddress, Children: []DaemonChild{child}})
		x.States = append(x.States, XFRMState{Source: tunnel.LocalAddress, Destination: tunnel.RemoteAddress, SPI: child.SPIOut, ReqID: tunnel.ReqID, IfID: tunnel.XFRMID}, XFRMState{Source: tunnel.RemoteAddress, Destination: tunnel.LocalAddress, SPI: child.SPIIn, ReqID: tunnel.ReqID, IfID: tunnel.XFRMID})
		for _, dir := range []string{"in", "out", "fwd"} {
			p := XFRMPolicy{Source: wide, Destination: wide, Direction: dir, ReqID: tunnel.ReqID, IfID: tunnel.XFRMID, TemplateSource: tunnel.RemoteAddress, TemplateDestination: tunnel.LocalAddress}
			if dir == "out" {
				p.TemplateSource, p.TemplateDestination = tunnel.LocalAddress, tunnel.RemoteAddress
			}
			x.Policies = append(x.Policies, p)
		}
		k.Routes = append(k.Routes, KernelRoute{Kind: 1, RouteTuple: RouteTuple{Destination: netip.PrefixFrom(e.Allocation.Tunnels[i].BGP.Peer, 32), Table: 254, Protocol: 242, Metric: 50001 + uint32(i), OutputInterface: 10 + i}})
	}
	route := RuntimeBGPRouteTuple{Prefix: netip.MustParsePrefix("10.231.0.0/16"), Slot: 1, InterfaceIndex: 10, Table: 254, Protocol: 242, Metric: 50001}
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Owned: []RuntimeBGPRouteTuple{route}, Target: []RuntimeBGPRouteTuple{route}}
	k.Routes = append(k.Routes, KernelRoute{Kind: 1, RouteTuple: RouteTuple{Destination: route.Prefix, Table: 254, Protocol: 242, Metric: 50001, OutputInterface: 10}})
	intent := guardFixture()
	intent.OwnerID = m.Manifest.NodeID
	intent.Namespace = k.Namespace
	intent.Revision = 40
	guard, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	p := runtimeJournalPayload{Version: 10, OwnerID: m.Manifest.NodeID, Sequence: 40, Guards: []runtimeGuardTemplate{{Namespace: k.Namespace, Revision: 40, Digest: guard.Digest, ExpectedJSON: guard.ExpectedJSON}}}
	for i := 0; i < 19; i++ {
		old := e
		old.DeliveryID = uuid.New()
		old.Phase = RuntimeRetainedRefusal
		for j := range old.Engines {
			old.Engines[j].Binding.DesiredRevision = int64(i + 1)
		}
		old.CleanupID = uuid.New()
		old.CleanupDesiredRevision = 39
		old.CoveredDeliveryRevision = 38
		old.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Withdrawal: true, Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
		p.Entries = append(p.Entries, old)
	}
	p.Entries = append(p.Entries, e)
	b := azureMaxProofBinding{Mode: "baseline", OrgID: m.Manifest.OrgID, SiteID: e.SiteID, GatewayID: m.Manifest.NodeID, ConnectionID: m.Manifest.ConnectionID, DesiredRevision: 40, ConfigurationRevision: 7, MaximumPrefixes: 1, NamespaceDevice: 4, NamespaceInode: 4026531992, NodeExecutableSHA256: strings.Repeat("a", 64)}
	status := bgpengine.Status{Peers: [2]bgpengine.PeerStatus{{Slot: 1, State: "established", AcceptedPrefixes: 1}, {Slot: 2, State: "established", AcceptedPrefixes: 1}}}
	routes := []bgpengine.LearnedRoute{{Prefix: route.Prefix, Slot: 1}}
	if !validJournalPayload(p) {
		t.Fatal("constructed whole journal invalid")
	}
	return p, e, b, d, k, x, status, routes
}
func TestAzureMaxProofWholeJournalNineteenRetainedAndBaseline(t *testing.T) {
	p, e, b, d, k, x, status, routes := azureMaxProofFixture(t)
	selected, err := azureMaxProofEntry(p, b, k.Namespace)
	if err != nil || selected.DeliveryID != e.DeliveryID {
		t.Fatal("valid retained scope refused")
	}
	if err = azureMaxProofBaseline(selected, d, k, x, status, routes); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(azureMaxProofProjection(p, selected, b, time.Unix(1, 123456789), strings.Repeat("b", 64), d, k, x, status, routes))
	for _, secret := range []string{engineName(e.Engines[0]), e.Engines[0].LocalAddress.String(), e.Engines[0].RemoteAddress.String(), "Synthetic_PSK_123"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("raw native material leaked")
		}
	}
	if !bytes.Contains(raw, []byte(`"spd_in":2`)) || !bytes.Contains(raw, []byte(`"journal_entries":20`)) {
		t.Fatal("actual counts omitted")
	}
}
func TestAzureMaxProofAllRetainedAbsenceUsesJournalCleanupRevision(t *testing.T) {
	p, e, b, _, k, _, _, _ := azureMaxProofFixture(t)
	e.Phase = RuntimeRetainedRefusal
	e.CleanupID = uuid.New()
	e.CleanupDesiredRevision = 41
	e.CoveredDeliveryRevision = 40
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 2, Stage: "completed", Withdrawal: true, Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
	p.Entries[len(p.Entries)-1] = e
	b.Mode = "absence"
	b.DesiredRevision = 41
	selected, err := azureMaxProofEntry(p, b, k.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	emptyKernel := KernelInventory{Namespace: k.Namespace}
	emptyXfrm := XFRMInventory{Namespace: k.Namespace}
	if azureMaxProofAbsence(p, DaemonInventory{}, emptyKernel, emptyXfrm) != nil {
		t.Fatal("empty inventory refused")
	}
	got := azureMaxProofProjection(p, selected, b, time.Now(), strings.Repeat("b", 64), DaemonInventory{}, emptyKernel, emptyXfrm, bgpengine.Status{}, nil)
	if got["desired_revision"] != int64(41) || got["owned_spd"] != 0 {
		t.Fatal("cleanup revision or actual absence projection wrong")
	}
	b.DesiredRevision = 42
	if _, err = azureMaxProofEntry(p, b, k.Namespace); err == nil {
		t.Fatal("unobserved API revision substituted for journal revision")
	}
	emptyKernel.Links = append(emptyKernel.Links, KernelLink{Name: p.Entries[0].Allocation.Tunnels[0].Name})
	if azureMaxProofAbsence(p, DaemonInventory{}, emptyKernel, emptyXfrm) == nil {
		t.Fatal("oldest retained interface ignored")
	}
}
func TestAzureMaxProofUnknownAndPartialSnapshotsRefuse(t *testing.T) {
	for _, name := range []string{"duplicate_ike", "missing_spd", "wrong_spi", "peer_limit", "candidate_route", "missing_route", "unrelated_key"} {
		t.Run(name, func(t *testing.T) {
			_, e, _, d, k, x, status, routes := azureMaxProofFixture(t)
			switch name {
			case "duplicate_ike":
				d.SAs = append(d.SAs, d.SAs[0])
			case "missing_spd":
				x.Policies = x.Policies[1:]
			case "wrong_spi":
				x.States[0].SPI++
			case "peer_limit":
				status.Peers[0].State = "idle"
			case "candidate_route":
				k.Routes = append(k.Routes, KernelRoute{RouteTuple: RouteTuple{Destination: netip.MustParsePrefix("10.235.77.0/24")}})
			case "missing_route":
				k.Routes = k.Routes[:2]
			case "unrelated_key":
				d.SharedKeys[0] = "foreign"
			}
			if azureMaxProofBaseline(e, d, k, x, status, routes) == nil {
				t.Fatal("partial native proof accepted")
			}
		})
	}
	for _, name := range []string{"site", "org", "namespace", "pending_retired_routes", "active_revision", "config_revision", "extra_active"} {
		t.Run(name, func(t *testing.T) {
			p, e, b, _, k, _, _, _ := azureMaxProofFixture(t)
			switch name {
			case "site":
				b.SiteID = uuid.New()
			case "org":
				b.OrgID = uuid.New()
			case "namespace":
				p.Entries[0].Allocation.Namespace = "net:[999]"
			case "pending_retired_routes":
				p.Entries[0].BGPRoutes.Stage = "pending"
			case "active_revision":
				b.DesiredRevision++
			case "config_revision":
				b.ConfigurationRevision++
			case "extra_active":
				e.DeliveryID = uuid.New()
				p.Entries = append(p.Entries, e)
			}
			if _, err := azureMaxProofEntry(p, b, k.Namespace); err == nil {
				t.Fatal("invalid whole journal scope accepted")
			}
		})
	}
}
func TestAzureMaxProofRequiresWholeJournalChecksum(t *testing.T) {
	p, _, _, _, _, _, _, _ := azureMaxProofFixture(t)
	envelope := runtimeJournalEnvelope{Payload: p, Checksum: journalChecksum(p)}
	raw, _ := json.Marshal(envelope)
	if _, err := decodeRuntimeJournalSnapshot(raw); err != nil {
		t.Fatal(err)
	}
	envelope.Payload.Entries[0].SiteID = uuid.New()
	raw, _ = json.Marshal(envelope)
	if _, err := decodeRuntimeJournalSnapshot(raw); err == nil {
		t.Fatal("modified retained duty accepted under stale checksum")
	}
}

// FRR VTY frames terminate with three NUL bytes and a command return code.
// Read through the same connection whose SO_PEERCRED and pathname were checked.
func azureProofVTYWire(conn net.Conn, command string, limit int) ([]byte, error) {
	if command != "show bgp ipv4 unicast summary json" && command != "show bgp ipv4 unicast json" {
		return nil, fmt.Errorf("vty_command_refused")
	}
	request := []byte(command + "\x00")
	for len(request) > 0 {
		n, err := conn.Write(request)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("vty_write_refused")
		}
		request = request[n:]
	}
	out := []byte{}
	chunk := make([]byte, 4096)
	for {
		n, err := conn.Read(chunk)
		if n > 0 {
			out = append(out, chunk[:n]...)
		}
		if len(out) > limit+4 {
			return nil, fmt.Errorf("vty_bound_refused")
		}
		if i := bytes.Index(out, []byte{0, 0, 0}); i >= 0 {
			if len(out) < i+4 && err == nil {
				continue
			}
			if len(out) != i+4 || out[i+3] != 0 || i > limit || bytes.IndexByte(out[:i], 0) >= 0 {
				return nil, fmt.Errorf("vty_frame_refused")
			}
			return out[:i], nil
		}
		if err != nil {
			return nil, fmt.Errorf("vty_read_refused")
		}
	}
}

func TestAzureMaxProofVTYBoundWireRefusesMalformedAndBoundedReplies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		chunks [][]byte
		limit  int
		ok     bool
	}{
		{"split_terminator", [][]byte{[]byte(`{"routes":{}}`), {0}, {0, 0}, {0}}, 64, true},
		{"nonzero_return", [][]byte{{'{', '}', 0, 0, 0, 1}}, 64, false},
		{"truncated_return", [][]byte{{'{', '}', 0, 0, 0}}, 64, false},
		{"trailing_bytes", [][]byte{{'{', '}', 0, 0, 0, 0, 1}}, 64, false},
		{"oversized", [][]byte{[]byte(`{"routes":{}}`), {0, 0, 0, 0}}, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			client.SetDeadline(time.Now().Add(time.Second))
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				request := make([]byte, 128)
				_, _ = server.Read(request)
				for _, chunk := range tc.chunks {
					if _, err := server.Write(chunk); err != nil {
						return
					}
				}
			}()
			out, err := azureProofVTYWire(client, "show bgp ipv4 unicast json", tc.limit)
			if (err == nil) != tc.ok {
				t.Fatalf("expected success=%v", tc.ok)
			}
			if tc.ok && string(out) != `{"routes":{}}` {
				t.Fatal("reply mismatch")
			}
			client.Close()
			<-done
		})
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if _, err := azureProofVTYWire(client, "configure terminal", 64); err == nil {
		t.Fatal("mutation command accepted")
	}
}

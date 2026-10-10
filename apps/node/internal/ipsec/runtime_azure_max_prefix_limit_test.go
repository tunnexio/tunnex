package ipsec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

type azureProofLimitPeer struct {
	Slot     int    `json:"slot"`
	State    string `json:"observed_state"`
	Reason   string `json:"reason"`
	Accepted int    `json:"accepted_prefixes"`
}

func azureProofLimitSummary(raw []byte, cfg bgpengine.Config) ([2]azureProofLimitPeer, error) {
	var out [2]azureProofLimitPeer
	bad := func() ([2]azureProofLimitPeer, error) { return out, fmt.Errorf("exact_pfxct_frame_refused") }
	if len(raw) > 65536 || cfg.MaximumPrefixes != 1 {
		return bad()
	}
	top, ok := runtimeJSONObject(raw)
	if !ok {
		return bad()
	}
	section := raw
	if value, ok := top["ipv4Unicast"]; ok {
		section = value
	}
	var doc struct {
		Peers map[string]struct {
			State  string `json:"state"`
			Reason string `json:"peerState"`
			Count  *int   `json:"pfxRcd"`
		} `json:"peers"`
	}
	if json.Unmarshal(section, &doc) != nil || len(doc.Peers) != 2 {
		return bad()
	}
	// Retain the fixed observed reason that the production status parser safely
	// normalizes to Idle. Generic Idle is deliberately not causal evidence.
	if _, err := bgpengine.ParseSummary(raw, cfg); err != nil {
		return bad()
	}
	for i, peer := range cfg.Peers {
		value, ok := doc.Peers[peer.Remote.String()]
		if !ok || peer.Slot != i+1 || value.State != "Idle (PfxCt)" || value.Reason != "PfxCt" || value.Count == nil || *value.Count != 0 {
			return bad()
		}
		out[i] = azureProofLimitPeer{Slot: peer.Slot, State: value.State, Reason: value.Reason, Accepted: *value.Count}
	}
	return out, nil
}

func azureMaxProofPostLimit(e RuntimeJournalEntry, d DaemonInventory, k KernelInventory, x XFRMInventory, status bgpengine.Status, routes []bgpengine.LearnedRoute, peers [2]azureProofLimitPeer) error {
	bad := func() error { return fmt.Errorf("post_limit_native_binding_refused") }
	if e.BGP == nil || e.BGP.MaximumPrefixes != 1 || e.BGPRoutes == nil || e.BGPRoutes.Stage != "completed" || len(e.BGPRoutes.Owned) != 0 || len(e.BGPRoutes.Target) != 0 || len(routes) != 0 || k.Namespace != e.Allocation.Namespace || x.Namespace != e.Allocation.Namespace || len(d.SAs) != 2 || len(d.Connections) != 2 || len(d.SharedKeys) != 2 || len(x.States) != 4 || len(x.Policies) != 6 {
		return bad()
	}
	slots := azureNativeSlotDiagnostic(e, d, k, x)
	if len(slots) != 2 {
		return bad()
	}
	for i, s := range slots {
		if s.Status != "up" || s.Category != "native_observation" || s.IKEMatches != 1 || s.ChildStates["INSTALLED"] != 1 || len(s.ChildStates) != 1 || s.SADMatches != 2 || !reflect.DeepEqual(s.SPDDirections, map[string]int{"in": 1, "out": 1, "fwd": 1}) || !s.StoredConnection || !s.StoredSharedKey || status.Peers[i].Slot != i+1 || status.Peers[i].State != "idle" || status.Peers[i].AcceptedPrefixes != 0 || peers[i] != (azureProofLimitPeer{Slot: i + 1, State: "Idle (PfxCt)", Reason: "PfxCt", Accepted: 0}) {
			return bad()
		}
	}
	wanted := map[RouteTuple]bool{}
	for i, t := range e.Allocation.Tunnels {
		wanted[RouteTuple{Destination: netip.PrefixFrom(t.BGP.Peer, 32), Table: 254, Protocol: 242, Metric: 50001 + uint32(i), OutputInterface: e.Observed[i].InterfaceIndex}] = true
	}
	for _, r := range k.Routes {
		if r.Destination == netip.MustParsePrefix("10.231.0.0/16") || r.Destination == netip.MustParsePrefix("10.235.77.0/24") {
			return bad()
		}
		if r.Protocol != 242 {
			continue
		}
		if !wanted[r.RouteTuple] || r.Kind != 1 {
			return bad()
		}
		delete(wanted, r.RouteTuple)
	}
	if len(wanted) != 0 {
		return bad()
	}
	return nil
}

// Full native guard readback is checked by the caller. Independently require
// no forwarding accept rule; transport-only host BGP rules remain permitted.
func azureProofNoForwardGrants(raw []byte, links []GuardInterface) error {
	mapping := map[string]int{}
	for _, link := range links {
		if link.Name == "" || link.Index <= 0 || mapping[link.Name] != 0 {
			return ErrGuardReadback
		}
		mapping[link.Name] = link.Index
	}
	objects, ok := normalizedGuardWithdrawalObjectsWithInterfaces(raw, mapping)
	if !ok {
		return ErrGuardReadback
	}
	for _, object := range objects {
		if rule, ok := object.(map[string]any)["rule"].(map[string]any); ok && rule["chain"] == "forward_guard" {
			expressions, ok := rule["expr"].([]any)
			if !ok {
				return ErrGuardReadback
			}
			for _, expression := range expressions {
				if value, ok := expression.(map[string]any); ok {
					if _, accept := value["accept"]; accept {
						return ErrGuardReadback
					}
				}
			}
		}
	}
	return nil
}

func TestAzureMaxProofPostLimitExactReasonAndWithdrawal(t *testing.T) {
	p, e, b, d, k, x, _, _ := azureMaxProofFixture(t)
	cfg, err := runtimeBGPProcessConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	frame := func(state, reason string, count int, foreign bool) []byte {
		peers := map[string]any{}
		for _, peer := range cfg.Peers {
			peers[peer.Remote.String()] = map[string]any{"state": state, "peerState": reason, "pfxRcd": count}
		}
		if foreign {
			peers["169.254.99.2"] = peers[cfg.Peers[0].Remote.String()]
			delete(peers, cfg.Peers[0].Remote.String())
		}
		raw, _ := json.Marshal(map[string]any{"ipv4Unicast": map[string]any{"peers": peers}})
		return raw
	}
	peers, err := azureProofLimitSummary(frame("Idle (PfxCt)", "PfxCt", 0, false), cfg)
	if err != nil {
		t.Fatal(err)
	}
	status := bgpengine.Status{Peers: [2]bgpengine.PeerStatus{{Slot: 1, State: "idle"}, {Slot: 2, State: "idle"}}}
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 2, Stage: "completed", Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
	p.Entries[len(p.Entries)-1] = e
	b.Mode = "post-limit"
	if _, err := azureMaxProofEntry(p, b, k.Namespace); err != nil {
		t.Fatal("post-limit journal refused")
	}
	filtered := []KernelRoute{}
	for _, r := range k.Routes {
		if r.Destination != netip.MustParsePrefix("10.231.0.0/16") {
			filtered = append(filtered, r)
		}
	}
	k.Routes = filtered
	if azureMaxProofPostLimit(e, d, k, x, status, nil, peers) != nil {
		t.Fatal("exact limit with independent withdrawal refused")
	}
	for _, tc := range []struct {
		state, reason string
		count         int
		foreign       bool
	}{{"Idle", "", 0, false}, {"Idle (Admin)", "PfxCt", 0, false}, {"Idle (PfxCt)", "", 0, false}, {"Idle (PfxCt)", "PfxCt", 1, false}, {"Established", "PfxCt", 0, false}, {"Idle (PfxCt)", "PfxCt", 0, true}} {
		if _, err := azureProofLimitSummary(frame(tc.state, tc.reason, tc.count, tc.foreign), cfg); err == nil {
			t.Fatal("noncausal or foreign frame accepted")
		}
	}
	if _, err := azureProofLimitSummary([]byte(`{"peers":`), cfg); err == nil {
		t.Fatal("malformed frame accepted")
	}
	duplicate := bytes.Replace(frame("Idle (PfxCt)", "PfxCt", 0, false), []byte(`"pfxRcd":0`), []byte(`"pfxRcd":0,"pfxRcd":0`), 1)
	if _, err := azureProofLimitSummary(duplicate, cfg); err == nil {
		t.Fatal("duplicate-key frame accepted")
	}
	withRoute := k
	withRoute.Routes = append(append([]KernelRoute{}, k.Routes...), KernelRoute{RouteTuple: RouteTuple{Destination: netip.MustParsePrefix("10.231.0.0/16"), Protocol: 242}, Kind: 1})
	if azureMaxProofPostLimit(e, d, withRoute, x, status, nil, peers) == nil {
		t.Fatal("unwithdrawn route accepted")
	}
	if azureMaxProofPostLimit(e, d, k, x, status, []bgpengine.LearnedRoute{{Prefix: netip.MustParsePrefix("10.235.77.0/24"), Slot: 1}}, peers) == nil {
		t.Fatal("unwithdrawn RIB accepted")
	}
	badDaemon := d
	badDaemon.SAs = append(append([]DaemonIKE{}, d.SAs...), d.SAs[0])
	if azureMaxProofPostLimit(e, badDaemon, k, x, status, nil, peers) == nil {
		t.Fatal("foreign or duplicate SA accepted")
	}
	b.DesiredRevision++
	if _, err := azureMaxProofEntry(p, b, k.Namespace); err == nil {
		t.Fatal("superseded binding accepted")
	}
}

func TestAzureMaxProofPostLimitNativeGuardRejectsForwardGrant(t *testing.T) {
	intent := guardFixture()
	links := []GuardInterface{{Name: "tnxi-a", Index: 10}, {Name: "tnxi-b", Index: 11}}
	granted, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	if azureProofNoForwardGrants([]byte(granted.ExpectedJSON), links) == nil {
		t.Fatal("forward grant accepted as withdrawn")
	}
	intent.Connections[0].Grants = nil
	denied, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	if azureProofNoForwardGrants([]byte(denied.ExpectedJSON), links) != nil {
		t.Fatal("actual grant-free guard shape refused")
	}
	if azureProofNoForwardGrants([]byte(`{"nftables":`), links) == nil {
		t.Fatal("malformed native guard accepted")
	}
}

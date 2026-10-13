package bgp

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
)

type PeerStatus struct {
	Slot              int
	State             string
	AcceptedPrefixes  int
	InstalledPrefixes int
	RejectedPrefixes  *int
}
type Status struct{ Peers [2]PeerStatus }

func ParseSummary(raw []byte, c Config) (Status, error) {
	var out Status
	if !c.valid() || len(raw) > 65536 {
		return out, ErrPackage
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return out, ErrPackage
	}
	section := raw
	if v, ok := top["ipv4Unicast"]; ok {
		section = v
	}
	var doc struct {
		Peers map[string]struct {
			State  string `json:"state"`
			Reason string `json:"peerState"`
			Count  *int   `json:"pfxRcd"`
		}
	}
	if json.Unmarshal(section, &doc) != nil || len(doc.Peers) != 2 {
		return out, ErrPackage
	}
	for i, p := range c.Peers {
		peer, ok := doc.Peers[p.Remote.String()]
		if !ok || peer.Count == nil || *peer.Count < 0 || *peer.Count > c.MaximumPrefixes {
			return out, ErrPackage
		}
		state := strings.ToLower(peer.State)
		if peer.State == "Idle (PfxCt)" {
			if peer.Reason != "PfxCt" || *peer.Count != 0 {
				return out, ErrPackage
			}
			state = "idle"
		} else if peer.Reason == "PfxCt" {
			return out, ErrPackage
		}
		switch state {
		case "idle", "connect", "active", "opensent", "openconfirm", "established":
		default:
			return out, ErrPackage
		}
		if state != "established" && *peer.Count != 0 {
			return out, ErrPackage
		}
		out.Peers[i] = PeerStatus{Slot: p.Slot, State: state, AcceptedPrefixes: *peer.Count}
	}
	return out, nil
}

// LearnedRoute is observation only; bgpd no-rib never installs it.
type LearnedRoute struct {
	Prefix netip.Prefix
	Slot   int
}

type boundedResponse struct{ bytes.Buffer }

func (b *boundedResponse) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, ErrPackage
	}
	return b.Buffer.Write(p)
}

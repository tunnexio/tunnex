package bgp

import (
	"encoding/json"
	"net/netip"
	"sort"
)

// ParseRoutes accepts only the filtered IPv4 RIB and FRR's unique selected path.
// It does not choose a slot, infer an unobserved route or trust kernel state.
func ParseRoutes(raw []byte, c Config, status Status) ([]LearnedRoute, error) {
	if !c.valid() || len(raw) > 1024*1024 {
		return nil, ErrPackage
	}
	var doc struct {
		Routes map[string][]struct {
			Stale    *bool  `json:"stale"`
			Valid    *bool  `json:"valid"`
			Best     *bool  `json:"bestpath"`
			Network  string `json:"network"`
			Peer     string `json:"peerId"`
			Nexthops []struct {
				IP   string `json:"ip"`
				AFI  string `json:"afi"`
				Used bool   `json:"used"`
			} `json:"nexthops"`
		} `json:"routes"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Routes == nil || len(doc.Routes) > len(c.LocalPrefixes)+len(c.RemotePrefixes) {
		return nil, ErrPackage
	}
	approved := map[netip.Prefix]bool{}
	local := map[netip.Prefix]bool{}
	for _, p := range c.RemotePrefixes {
		approved[p] = true
	}
	for _, p := range c.LocalPrefixes {
		local[p] = true
	}
	counts := [2]int{}
	selected := []LearnedRoute{}
	for text, paths := range doc.Routes {
		prefix, e := netip.ParsePrefix(text)
		if e != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != text || len(paths) == 0 || len(paths) > 2 {
			return nil, ErrPackage
		}
		if !approved[prefix] && !local[prefix] {
			return nil, ErrPackage
		}
		seen := [2]bool{}
		best := 0
		for _, path := range paths {
			if path.Valid == nil || path.Network != text {
				return nil, ErrPackage
			}
			if local[prefix] {
				if path.Peer != "(unspec)" || len(paths) != 1 {
					return nil, ErrPackage
				}
				continue
			}
			slot := -1
			for i, peer := range c.Peers[:c.activePeerCount()] {
				if path.Peer == peer.Remote.String() {
					slot = i
				}
			}
			if slot < 0 || seen[slot] {
				return nil, ErrPackage
			}
			seen[slot] = true
			if status.Peers[slot].State != "established" {
				continue
			}
			counts[slot]++
			if path.Stale != nil && *path.Stale {
				continue
			}
			if !*path.Valid {
				if path.Best != nil && *path.Best {
					return nil, ErrPackage
				}
				continue
			}
			if status.Peers[slot].State != "established" || len(path.Nexthops) != 1 || path.Nexthops[0].IP != c.Peers[slot].Remote.String() || path.Nexthops[0].AFI != "ipv4" || !path.Nexthops[0].Used {
				return nil, ErrPackage
			}
			if path.Best != nil && *path.Best {
				best++
				selected = append(selected, LearnedRoute{Prefix: prefix, Slot: c.Peers[slot].Slot})
			}
		}
		if approved[prefix] && best > 1 {
			return nil, ErrPackage
		}
	}
	for i := range counts {
		if counts[i] != status.Peers[i].AcceptedPrefixes || counts[i] > c.MaximumPrefixes {
			return nil, ErrPackage
		}
	}
	if len(selected) > len(c.RemotePrefixes) {
		return nil, ErrPackage
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Prefix.String() < selected[j].Prefix.String() })
	return selected, nil
}

// RIB responses include two full path attribute objects per approved prefix.
type boundedRIBResponse struct{ boundedResponse }

func (b *boundedRIBResponse) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1024*1024 {
		return 0, ErrPackage
	}
	return b.Buffer.Write(p)
}

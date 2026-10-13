//go:build linux

package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"time"
)

// ProbePeerReachability qualifies explicit single-hop XFRM /32 transport before
// disabling FRR's connected-prefix check. TTL remains the eBGP default of one.
func ProbePeerReachability(ctx context.Context, peers [2]Peer) error {
	read := func(args ...string) ([]byte, error) {
		bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(bounded, "/sbin/ip", args...)
		var out boundedResponse
		cmd.Stdout = &out
		if cmd.Run() != nil {
			return nil, ErrPackage
		}
		return out.Bytes(), nil
	}
	raw, e := read("-j", "-d", "link", "show")
	if e != nil {
		return e
	}
	links, ok := objects(raw)
	if !ok {
		return ErrPackage
	}
	raw, e = read("-j", "-4", "addr", "show")
	if e != nil {
		return e
	}
	addresses, ok := objects(raw)
	if !ok {
		return ErrPackage
	}
	raw, e = read("-j", "-d", "-N", "-4", "route", "show", "table", "main")
	if e != nil {
		return e
	}
	routes, ok := objects(raw)
	if !ok {
		return ErrPackage
	}
	for i, peer := range peers {
		if i == 1 && peer == (Peer{}) {
			continue
		}
		if peer.LinkName == "" || peer.XFRMID == 0 || (peer.AddressBits != 0 && peer.AddressBits != 32) {
			return ErrPackage
		}
		linkOK := false
		for _, l := range links {
			name, valid := fieldString(l, "ifname", true)
			if !valid {
				return ErrPackage
			}
			if name != peer.LinkName {
				continue
			}
			flags, valid := fieldFlags(l)
			if !valid {
				return ErrPackage
			}
			up := false
			for _, f := range flags {
				up = up || f == "UP"
			}
			var info struct {
				Kind string `json:"info_kind"`
				Data struct {
					ID string `json:"if_id"`
				} `json:"info_data"`
			}
			if json.Unmarshal(l["linkinfo"], &info) != nil {
				return ErrPackage
			}
			id, e := strconv.ParseUint(info.Data.ID, 0, 32)
			linkOK = up && info.Kind == "xfrm" && e == nil && uint32(id) == peer.XFRMID
		}
		if !linkOK {
			return ErrPackage
		}
		addressOK := false
		for _, a := range addresses {
			name, _ := fieldString(a, "ifname", true)
			if name != peer.LinkName {
				continue
			}
			var infos []struct {
				Local string
				Bits  int `json:"prefixlen"`
			}
			if json.Unmarshal(a["addr_info"], &infos) != nil {
				return ErrPackage
			}
			for _, i := range infos {
				addressOK = addressOK || (i.Local == peer.Local.String() && i.Bits == map[bool]int{true: 32, false: 30}[peer.AddressBits == 32])
			}
		}
		if !addressOK {
			return ErrPackage
		}
		expected := netip.PrefixFrom(peer.Remote, 32)
		count := 0
		for _, r := range routes {
			var dst, dev string
			json.Unmarshal(r["dst"], &dst)
			json.Unmarshal(r["dev"], &dev)
			destination, err := netip.ParsePrefix(dst)
			if addr, e := netip.ParseAddr(dst); e == nil && addr.Is4() && addr.String() == dst {
				destination = netip.PrefixFrom(addr, 32)
				err = nil
			}
			if err != nil || destination != expected {
				continue
			}
			var proto, metric, kind, scope int
			if dev != peer.LinkName || peerRouteNumber(r, "protocol", &proto, -1) != nil || proto != 242 || peerRouteNumber(r, "metric", &metric, -1) != nil || metric != 50000+peer.Slot || peerRouteNumber(r, "type", &kind, 1) != nil || kind != 1 || peerRouteNumber(r, "scope", &scope, -1) != nil || scope != 253 {
				return fmt.Errorf("%w: peer route ownership", ErrPackage)
			}
			for _, key := range []string{"gateway", "multipath", "nexthops", "nhid", "encap", "encap_type"} {
				if r[key] != nil {
					return ErrPackage
				}
			}
			flags, valid := fieldFlags(r)
			if !valid || len(flags) != 0 {
				return ErrPackage
			}
			count++
		}
		if count != 1 {
			return ErrPackage
		}
	}
	return nil
}

func peerRouteNumber(row map[string]json.RawMessage, key string, value *int, missing int) error {
	raw, ok := row[key]
	if !ok {
		if missing < 0 {
			return ErrPackage
		}
		*value = missing
		return nil
	}
	if json.Unmarshal(raw, value) == nil {
		return nil
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return ErrPackage
	}
	n, e := strconv.Atoi(text)
	if e != nil || strconv.Itoa(n) != text {
		return ErrPackage
	}
	*value = n
	return nil
}

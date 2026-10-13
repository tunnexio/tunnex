package bgp

import (
	"encoding/json"
	"net/netip"
)

type reachabilityRead func(...string) ([]byte, error)

func objects(raw []byte) ([]map[string]json.RawMessage, bool) {
	var rows []map[string]json.RawMessage
	err := json.Unmarshal(raw, &rows)
	return rows, err == nil && rows != nil
}
func fieldString(row map[string]json.RawMessage, key string, required bool) (string, bool) {
	raw, exists := row[key]
	if !exists {
		return "", !required
	}
	if string(raw) == "null" {
		return "", false
	}
	var s string
	err := json.Unmarshal(raw, &s)
	return s, err == nil
}
func fieldFlags(row map[string]json.RawMessage) ([]string, bool) {
	raw, present := row["flags"]
	if !present {
		return nil, true
	}
	var flags []string
	err := json.Unmarshal(raw, &flags)
	return flags, err == nil && flags != nil
}
func routeTuple(row map[string]json.RawMessage) (string, string, string, bool) {
	dst, a := fieldString(row, "dst", false)
	dev, b := fieldString(row, "dev", true)
	gateway, c := fieldString(row, "gateway", false)
	kind, d := fieldString(row, "type", false)
	flags, e := fieldFlags(row)
	if !a || !b || !c || !d || !e || len(flags) != 0 || (kind != "" && kind != "unicast") {
		return "", "", "", false
	}
	for _, key := range []string{"multipath", "nexthops", "nhid", "encap", "encap_type"} {
		if _, present := row[key]; present {
			return "", "", "", false
		}
	}
	return dst, dev, gateway, true
}
func probeLocalReachability(prefixes []netip.Prefix, read reachabilityRead) error {
	linksRaw, e := read("-j", "-d", "link", "show")
	if e != nil {
		return ErrPackage
	}
	linkRows, ok := objects(linksRaw)
	if !ok {
		return ErrPackage
	}
	physical := map[string]bool{}
	for _, row := range linkRows {
		name, a := fieldString(row, "ifname", true)
		typ, b := fieldString(row, "link_type", true)
		flags, c := fieldFlags(row)
		if !a || !b || !c {
			return ErrPackage
		}
		kind := ""
		if raw, present := row["linkinfo"]; present {
			var info map[string]json.RawMessage
			if json.Unmarshal(raw, &info) != nil || info == nil {
				return ErrPackage
			}
			var valid bool
			kind, valid = fieldString(info, "info_kind", true)
			if !valid {
				return ErrPackage
			}
		}
		up := false
		for _, flag := range flags {
			up = up || flag == "UP"
		}
		if up && typ == "ether" && (kind == "" || kind == "veth") {
			physical[name] = true
		}
	}
	addrRaw, e := read("-j", "-4", "addr", "show")
	if e != nil {
		return ErrPackage
	}
	addrRows, ok := objects(addrRaw)
	if !ok {
		return ErrPackage
	}
	addresses := map[string][]netip.Prefix{}
	for _, row := range addrRows {
		name, valid := fieldString(row, "ifname", true)
		if !valid {
			return ErrPackage
		}
		var infos []map[string]json.RawMessage
		if json.Unmarshal(row["addr_info"], &infos) != nil || infos == nil {
			return ErrPackage
		}
		for _, info := range infos {
			local, valid := fieldString(info, "local", true)
			var bits int
			if !valid || json.Unmarshal(info["prefixlen"], &bits) != nil || bits < 1 || bits > 32 {
				return ErrPackage
			}
			ip, e := netip.ParseAddr(local)
			if e != nil || !ip.Is4() || ip.String() != local {
				return ErrPackage
			}
			addresses[name] = append(addresses[name], netip.PrefixFrom(ip, bits))
		}
	}
	routesRaw, e := read("-j", "-4", "route", "show", "table", "main")
	if e != nil {
		return ErrPackage
	}
	routes, ok := objects(routesRaw)
	if !ok {
		return ErrPackage
	}
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() == 0 {
			return ErrPackage
		}
		found := false
		for _, row := range routes {
			dst, dev, gateway, valid := routeTuple(row)
			if !valid {
				return ErrPackage
			}
			if dst != prefix.String() || !physical[dev] {
				continue
			}
			// Tunnex/FRR dynamic protocols cannot prove a local export path.
			if raw, present := row["protocol"]; present {
				var proto string
				if json.Unmarshal(raw, &proto) == nil {
					if proto != "kernel" && proto != "static" && proto != "boot" {
						continue
					}
				} else {
					var n int
					if json.Unmarshal(raw, &n) != nil {
						return ErrPackage
					}
					if n != 2 && n != 3 && n != 4 {
						continue
					}
				}
			}
			addressOK := false
			for _, address := range addresses[dev] {
				if gateway == "" {
					addressOK = addressOK || address.Masked() == prefix
				} else {
					gw, e := netip.ParseAddr(gateway)
					addressOK = addressOK || (e == nil && gw.Is4() && address.Contains(gw) && address.Addr() != gw)
				}
			}
			if !addressOK {
				continue
			}
			selected, e := read("-j", "-4", "route", "get", prefix.Addr().String())
			if e != nil {
				return ErrPackage
			}
			selectedRows, ok := objects(selected)
			if !ok || len(selectedRows) != 1 {
				return ErrPackage
			}
			_, chosenDev, chosenGateway, valid := routeTuple(selectedRows[0])
			if !valid {
				return ErrPackage
			}
			if chosenDev == dev && chosenGateway == gateway {
				found = true
			}
		}
		if !found {
			return ErrPackage
		}
	}
	return nil
}

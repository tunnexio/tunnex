package ipsec

import (
	"encoding/json"
	"net/netip"
)

// desktopNATExemptionPending recognizes only the complete egress-owned NAT
// recipe while an exact requested exemption is absent. It is a scheduling hint,
// never proof of exemption or permission to forward a desktop packet.
func desktopNATExemptionPending(raw []byte, source, destination netip.Prefix, iface string) bool {
	if !source.IsValid() || !source.Addr().Is4() || source.Bits() != 32 || !source.Addr().IsGlobalUnicast() ||
		!destination.IsValid() || !destination.Addr().Is4() || destination != destination.Masked() || destination.Bits() == 0 ||
		!destination.Addr().IsGlobalUnicast() || source.Overlaps(destination) || !validToken(iface) || len(iface) > 15 {
		return false
	}
	rows, ok := runtimeCensusRows(raw)
	if !ok {
		return false
	}
	tables, chains := 0, 0
	var rules []map[string]json.RawMessage
	for _, row := range rows {
		if len(row) != 1 {
			return false
		}
		for kind, value := range row {
			obj, ok := kernelObject(value)
			if !ok {
				return false
			}
			if kind == "metainfo" {
				continue
			}
			family, _ := kernelString(obj, "family")
			if family != "ip" {
				return false
			}
			if kind == "table" {
				name, _ := kernelString(obj, "name")
				if name != "tunnex" || !desktopPendingNATFields(obj, "family", "name", "handle") {
					return false
				}
				tables++
				continue
			}
			table, _ := kernelString(obj, "table")
			if table != "tunnex" {
				return false
			}
			switch kind {
			case "chain":
				name, _ := kernelString(obj, "name")
				if name != "postrouting" {
					if hook, _ := kernelString(obj, "hook"); hook == "postrouting" {
						return false
					}
					continue
				}
				chainType, _ := kernelString(obj, "type")
				hook, _ := kernelString(obj, "hook")
				policy, _ := kernelString(obj, "policy")
				priority, ok := kernelNumber(obj["prio"], 32)
				if !ok || chainType != "nat" || hook != "postrouting" || priority != 99 || policy != "accept" ||
					!desktopPendingNATFields(obj, "family", "table", "name", "handle", "type", "hook", "prio", "policy") {
					return false
				}
				chains++
			case "rule":
				chain, ok := kernelString(obj, "chain")
				if !ok || chain == "" {
					return false
				}
				if chain == "postrouting" {
					if !desktopPendingNATFields(obj, "family", "table", "chain", "handle", "expr", "comment") {
						return false
					}
					rules = append(rules, obj)
				}
			case "set", "element":
				// The postrouting recipe below accepts no set references.
			default:
				return false
			}
		}
	}
	if tables != 1 || chains != 1 || len(rules) == 0 {
		return false
	}
	terminal := rules[len(rules)-1]
	if _, present := terminal["comment"]; present {
		return false
	}
	expr, ok := kernelObjects(terminal["expr"])
	if !ok || len(expr) != 3 || len(expr[2]) != 1 || string(expr[2]["masquerade"]) != "null" {
		return false
	}
	pool, ok := desktopPendingNATAddress(expr[0], "saddr")
	if !ok || !pool.Contains(source.Addr()) || pool.Overlaps(destination) || !desktopPendingNATInterface(expr[1], iface) {
		return false
	}
	seen := map[DesktopNATExemption]bool{}
	for _, rule := range rules[:len(rules)-1] {
		comment, _ := kernelString(rule, "comment")
		expr, ok := kernelObjects(rule["expr"])
		if comment != "tunnex_ipsec_desktop_no_snat" || !ok || len(expr) != 4 || len(expr[3]) != 1 || string(expr[3]["return"]) != "null" {
			return false
		}
		src, sok := desktopPendingNATAddress(expr[0], "saddr")
		dst, dok := desktopPendingNATAddress(expr[1], "daddr")
		counter, cok := kernelObject(expr[2]["counter"])
		_, packetsOK := kernelNumber(counter["packets"], 64)
		_, bytesOK := kernelNumber(counter["bytes"], 64)
		tuple := DesktopNATExemption{Source: src, Destination: dst}
		if !sok || !dok || src.Bits() != 32 || !pool.Contains(src.Addr()) || src.Overlaps(dst) ||
			len(expr[2]) != 1 || !cok || len(counter) != 2 || !packetsOK || !bytesOK || seen[tuple] ||
			(src == source && dst.Overlaps(destination)) {
			return false
		}
		for prior := range seen {
			if prior.Source == src && prior.Destination.Overlaps(dst) {
				return false
			}
		}
		seen[tuple] = true
	}
	return true
}

func desktopPendingNATFields(obj map[string]json.RawMessage, allowed ...string) bool {
	for key := range obj {
		known := false
		for _, name := range allowed {
			known = known || key == name
		}
		if !known {
			return false
		}
	}
	if handle, present := obj["handle"]; present {
		if value, ok := kernelNumber(handle, 64); !ok || value == 0 {
			return false
		}
	}
	return true
}

func desktopPendingNATAddress(expr map[string]json.RawMessage, field string) (netip.Prefix, bool) {
	match, ok := kernelObject(expr["match"])
	op, _ := kernelString(match, "op")
	left, _ := kernelObject(match["left"])
	payload, _ := kernelObject(left["payload"])
	protocol, _ := kernelString(payload, "protocol")
	actualField, _ := kernelString(payload, "field")
	if len(expr) != 1 || !ok || len(match) != 3 || op != "==" || len(left) != 1 || len(payload) != 2 || protocol != "ip" || actualField != field {
		return netip.Prefix{}, false
	}
	var result netip.Prefix
	if right, ok := kernelObject(match["right"]); ok {
		prefix, pok := kernelObject(right["prefix"])
		address, _ := kernelString(prefix, "addr")
		bits, bok := kernelNumber(prefix["len"], 8)
		addr, err := netip.ParseAddr(address)
		if len(right) != 1 || !pok || len(prefix) != 2 || !bok || bits == 0 || bits > 32 || err != nil || !addr.Is4() {
			return netip.Prefix{}, false
		}
		result = netip.PrefixFrom(addr, int(bits))
	} else {
		var host string
		if json.Unmarshal(match["right"], &host) != nil {
			return netip.Prefix{}, false
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is4() {
			return netip.Prefix{}, false
		}
		result = netip.PrefixFrom(addr, 32)
	}
	return result, result == result.Masked() && result.Addr().IsGlobalUnicast()
}

func desktopPendingNATInterface(expr map[string]json.RawMessage, iface string) bool {
	match, ok := kernelObject(expr["match"])
	op, _ := kernelString(match, "op")
	left, _ := kernelObject(match["left"])
	meta, _ := kernelObject(left["meta"])
	key, _ := kernelString(meta, "key")
	value, vok := kernelString(match, "right")
	return len(expr) == 1 && ok && len(match) == 3 && op == "!=" && len(left) == 1 && len(meta) == 1 && key == "oifname" && vok && value == iface
}

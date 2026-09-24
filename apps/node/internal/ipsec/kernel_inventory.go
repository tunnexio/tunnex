package ipsec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrKernelInventoryInvalid = errors.New("invalid kernel inventory")

const kernelDumpLimit = 1 << 20
const kernelEntryLimit = 4096

type KernelInventory struct {
	Namespace string
	Links     []KernelLink
	Routes    []KernelRoute
}
type KernelLink struct {
	Name   string
	Index  int
	XFRMID uint32
	Up     bool
}
type KernelRoute struct {
	Kind uint8 // Numeric RTN type; address routes never stand in for unicast payload routes.
	RouteTuple
	Scope           uint8
	PreferredSource netip.Addr
}

// ParseKernelInventory parses detailed numeric iproute2 JSON observations only.
// It never supplies expected ownership, inventory consistency or runtime readiness.
// The two input dumps need not describe the same instant.
func ParseKernelInventory(namespace string, linkJSON, routeJSON []byte) (KernelInventory, error) {
	invalid := func() (KernelInventory, error) { return KernelInventory{}, ErrKernelInventoryInvalid }
	if !validKernelNamespace(namespace) {
		return invalid()
	}
	links, ok := kernelObjects(linkJSON)
	if !ok {
		return invalid()
	}
	routes, ok := kernelObjects(routeJSON)
	if !ok {
		return invalid()
	}
	result := KernelInventory{Namespace: namespace, Links: []KernelLink{}, Routes: []KernelRoute{}}
	byName := map[string]KernelLink{}
	indices := map[int]bool{}
	xfrmNames := map[string]bool{}
	ids := map[uint32]bool{}
	for _, obj := range links {
		name, ok := kernelString(obj, "ifname")
		if !ok || !validToken(name) || len(name) > 15 || name == "." || name == ".." || strings.ContainsAny(name, "/:") {
			return invalid()
		}
		index, ok := kernelNumber(obj["ifindex"], 31)
		if !ok || index == 0 || indices[int(index)] {
			return invalid()
		}
		if _, duplicate := byName[name]; duplicate {
			return invalid()
		}
		flags, ok := kernelFlags(obj["flags"])
		if !ok {
			return invalid()
		}
		link := KernelLink{Name: name, Index: int(index)}
		for _, flag := range flags {
			if flag == "UP" {
				link.Up = true
			}
		}
		indices[link.Index] = true
		byName[name] = link
		raw, exists := obj["linkinfo"]
		if !exists {
			continue
		}
		info, ok := kernelObject(raw)
		if !ok {
			return invalid()
		}
		kind, ok := kernelString(info, "info_kind")
		if !ok {
			return invalid()
		}
		if kind != "xfrm" {
			continue
		}
		data, ok := kernelObject(info["info_data"])
		if !ok {
			return invalid()
		}
		if external, exists := data["external"]; exists {
			var value bool
			if json.Unmarshal(external, &value) != nil || string(external) == "null" || value {
				return invalid()
			}
		}
		id, ok := kernelString(data, "if_id")
		if !ok || !strings.HasPrefix(id, "0x") || len(id) < 3 {
			return invalid()
		}
		numeric, err := strconv.ParseUint(id[2:], 16, 32)
		if err != nil || ids[uint32(numeric)] {
			return invalid()
		}
		link.XFRMID = uint32(numeric)
		ids[link.XFRMID] = true
		byName[name] = link
		xfrmNames[name] = true
		result.Links = append(result.Links, link)
	}
	allowed := map[string]bool{"type": true, "dst": true, "dev": true, "table": true, "protocol": true, "scope": true, "metric": true, "gateway": true, "prefsrc": true, "flags": true}
	seenRoutes := map[RouteTuple]bool{}
	for _, obj := range routes {
		// Indirection may refer to an XFRM device even when a direct device is present.
		for _, key := range []string{"nhid", "multipath", "nexthops", "encap", "encap_type"} {
			if _, exists := obj[key]; exists {
				return invalid()
			}
		}
		dev, ok := kernelString(obj, "dev")
		if !ok {
			return invalid()
		}
		link, known := byName[dev]
		if !known {
			return invalid()
		}
		if !xfrmNames[dev] {
			continue
		}
		for key := range obj {
			if !allowed[key] {
				return invalid()
			}
		}
		// -N makes RTN_UNICAST a decimal JSON string, not the display name.
		kind, ok := kernelDecimal(obj, "type", 8)
		if !ok || (kind != 1 && kind != 2 && kind != 3) {
			return invalid()
		}
		table, ok := kernelDecimal(obj, "table", 32)
		if !ok || table == 0 {
			return invalid()
		}
		protocol, ok := kernelDecimal(obj, "protocol", 8)
		if !ok {
			return invalid()
		}
		scope, ok := kernelDecimal(obj, "scope", 8)
		if !ok {
			return invalid()
		}
		dst, ok := kernelString(obj, "dst")
		if !ok {
			return invalid()
		}
		prefix, ok := kernelDestination(dst)
		if !ok {
			return invalid()
		}
		route := KernelRoute{Kind: uint8(kind), RouteTuple: RouteTuple{Destination: prefix, Table: uint32(table), Protocol: uint8(protocol), OutputInterface: link.Index}, Scope: uint8(scope)}
		if value, exists := obj["metric"]; exists {
			metric, ok := kernelNumber(value, 32)
			if !ok {
				return invalid()
			}
			route.Metric = uint32(metric)
		}
		if _, exists := obj["flags"]; exists {
			flags, ok := kernelFlags(obj["flags"])
			if !ok || len(flags) != 0 {
				return invalid()
			}
		}
		if _, exists := obj["gateway"]; exists {
			addr, ok := kernelIPv4(obj, "gateway")
			if !ok {
				return invalid()
			}
			route.Gateway = addr
		}
		if _, exists := obj["prefsrc"]; exists {
			addr, ok := kernelIPv4(obj, "prefsrc")
			if !ok {
				return invalid()
			}
			route.PreferredSource = addr
		}
		if kind != 1 {
			// The only non-unicast profile is the kernel's IPv4 /30 address
			// bookkeeping. It is retained as typed observation, never ignored or
			// treated as a configured remote route. Assignment matching is separate.
			if table != 255 || protocol != 2 || route.Metric != 0 || route.Gateway.IsValid() || prefix.Bits() != 32 || !route.PreferredSource.Is4() || !netip.MustParsePrefix("169.254.0.0/16").Contains(route.PreferredSource) {
				return invalid()
			}
			if _, present := obj["metric"]; present {
				return invalid()
			}
			if _, present := obj["gateway"]; present {
				return invalid()
			}
			source := route.PreferredSource.As4()
			if source[3]&3 == 0 || source[3]&3 == 3 {
				return invalid()
			}
			expected := route.PreferredSource
			if kind == 2 {
				if scope != 254 {
					return invalid()
				}
			} else {
				if scope != 253 {
					return invalid()
				}
				source[3] |= 3
				expected = netip.AddrFrom4(source)
			}
			if prefix.Addr() != expected {
				return invalid()
			}
		}
		if seenRoutes[route.RouteTuple] {
			return invalid()
		}
		seenRoutes[route.RouteTuple] = true
		result.Routes = append(result.Routes, route)
	}
	return result, nil
}
func validKernelNamespace(value string) bool {
	if !strings.HasPrefix(value, "net:[") || !strings.HasSuffix(value, "]") {
		return false
	}
	number := value[5 : len(value)-1]
	v, err := strconv.ParseUint(number, 10, 64)
	return err == nil && v > 0 && strconv.FormatUint(v, 10) == number
}
func kernelObjects(data []byte) ([]map[string]json.RawMessage, bool) {
	if len(data) > kernelDumpLimit || !utf8.Valid(data) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if !kernelJSONValue(decoder, 0) {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	var values []json.RawMessage
	if json.Unmarshal(data, &values) != nil || values == nil || len(values) > kernelEntryLimit {
		return nil, false
	}
	objects := make([]map[string]json.RawMessage, 0, len(values))
	for _, value := range values {
		object, ok := kernelObject(value)
		if !ok {
			return nil, false
		}
		objects = append(objects, object)
	}
	return objects, true
}

// Walk tokens before decoding objects so encoding/json cannot silently replace a
// duplicate key; decoder keys are unescaped, so escaped aliases collide too.
func kernelJSONValue(decoder *json.Decoder, depth int) bool {
	if depth > 64 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return true
	}
	switch delimiter {
	case '{':
		keys := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				return false
			}
			keys[name] = true
			if !kernelJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !kernelJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}
func kernelObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var obj map[string]json.RawMessage
	err := json.Unmarshal(raw, &obj)
	return obj, err == nil && obj != nil
}
func kernelString(obj map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := obj[key]
	if !ok {
		return "", false
	}
	var value string
	err := json.Unmarshal(raw, &value)
	return value, err == nil && string(raw) != "null"
}
func kernelNumber(raw json.RawMessage, bits int) (uint64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	value, err := strconv.ParseUint(string(raw), 10, bits)
	return value, err == nil
}
func kernelDecimal(obj map[string]json.RawMessage, key string, bits int) (uint64, bool) {
	value, ok := kernelString(obj, key)
	if !ok {
		return 0, false
	}
	number, err := strconv.ParseUint(value, 10, bits)
	return number, err == nil && strconv.FormatUint(number, 10) == value
}
func kernelFlags(raw json.RawMessage) ([]string, bool) {
	var values []string
	if json.Unmarshal(raw, &values) != nil || values == nil {
		return nil, false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !validToken(value) || seen[value] {
			return nil, false
		}
		seen[value] = true
	}
	return values, true
}
func kernelDestination(value string) (netip.Prefix, bool) {
	if value == "default" {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), true
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return netip.PrefixFrom(addr, 32), addr.Is4() && addr.String() == value
	}
	prefix, err := netip.ParsePrefix(value)
	return prefix, err == nil && prefix.Addr().Is4() && prefix == prefix.Masked() && prefix.String() == value
}
func kernelIPv4(obj map[string]json.RawMessage, key string) (netip.Addr, bool) {
	value, ok := kernelString(obj, key)
	if !ok {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(value)
	return addr, err == nil && addr.Is4() && addr.String() == value && !addr.IsUnspecified() && !addr.IsMulticast() && addr != netip.MustParseAddr("255.255.255.255")
}

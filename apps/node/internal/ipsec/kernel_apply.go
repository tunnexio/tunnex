package ipsec

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

var ErrKernelApply = errors.New("IPsec owned kernel operation refused")

// KernelAllocation is nonsecret journal data, persisted before the first mutation.
// Names and IDs are proposals, never proof of ownership. Collisions refuse.
type KernelAllocation struct {
	Namespace                string
	Generation, ConnectionID uuid.UUID
	Tunnels                  [2]KernelTunnelAllocation
}
type KernelTunnelAllocation struct {
	TunnelID       uuid.UUID
	Slot           uint8
	Name, Alias    string
	XFRMID         uint32
	InsideAddress  netip.Prefix
	RemotePrefixes []netip.Prefix
	Selected       bool
}
type KernelAbsence struct {
	Namespace  string
	Generation uuid.UUID
	TunnelIDs  [2]uuid.UUID
}

func KernelTunnelName(id uuid.UUID) string {
	h := sha256.Sum256(id[:])
	return "tx" + hex.EncodeToString(h[:6])
}
func KernelTunnelID(id uuid.UUID) uint32 {
	h := sha256.Sum256(id[:])
	return binary.BigEndian.Uint32(h[:4]) | 0x80000000
}
func KernelTunnelAlias(generation, tunnel uuid.UUID) string {
	return "tunnex-ipsec:" + generation.String() + ":" + tunnel.String()
}

func validKernelAllocation(p KernelAllocation) bool {
	if !validKernelNamespace(p.Namespace) || p.Generation == uuid.Nil || p.ConnectionID == uuid.Nil {
		return false
	}
	for i, t := range p.Tunnels {
		if t.TunnelID == uuid.Nil || t.Slot != uint8(i+1) || t.Name != KernelTunnelName(t.TunnelID) || t.XFRMID != KernelTunnelID(t.TunnelID) || t.Alias != KernelTunnelAlias(p.Generation, t.TunnelID) || t.Selected != (i == 0) {
			return false
		}
		if !t.InsideAddress.IsValid() || !t.InsideAddress.Addr().Is4() || t.InsideAddress.Bits() != 30 || !netip.MustParsePrefix("169.254.0.0/16").Contains(t.InsideAddress.Addr()) {
			return false
		}
		b := t.InsideAddress.Addr().As4()
		if b[3]&3 == 0 || b[3]&3 == 3 {
			return false
		}
		if len(t.RemotePrefixes) == 0 || len(t.RemotePrefixes) > 128 {
			return false
		}
		seen := map[netip.Prefix]bool{}
		for _, r := range t.RemotePrefixes {
			if !r.IsValid() || !r.Addr().Is4() || r != r.Masked() || r.Bits() == 0 || seen[r] || r.Overlaps(netip.MustParsePrefix("169.254.0.0/16")) {
				return false
			}
			seen[r] = true
		}
	}
	a, b := p.Tunnels[0], p.Tunnels[1]
	if a.TunnelID == b.TunnelID || a.Name == b.Name || a.XFRMID == b.XFRMID || a.InsideAddress.Masked() == b.InsideAddress.Masked() || len(a.RemotePrefixes) != len(b.RemotePrefixes) {
		return false
	}
	for i := range a.RemotePrefixes {
		if a.RemotePrefixes[i] != b.RemotePrefixes[i] {
			return false
		}
	}
	return true
}

type KernelApplier struct {
	run       func(context.Context, ...string) ([]byte, error)
	namespace func() (string, error)
}

func NewKernelApplier(ipPath string) (*KernelApplier, error) {
	if !filepath.IsAbs(ipPath) {
		return nil, ErrKernelApply
	}
	return &KernelApplier{run: func(ctx context.Context, args ...string) ([]byte, error) {
		return runKernelCommand(ctx, ipPath, args...)
	}, namespace: func() (string, error) { return os.Readlink("/proc/self/ns/net") }}, nil
}
func (a *KernelApplier) check(ctx context.Context, p KernelAllocation) error {
	if a == nil || a.run == nil || a.namespace == nil || ctx.Err() != nil || !validKernelAllocation(p) {
		return ErrKernelApply
	}
	ns, err := a.namespace()
	if err != nil || ns != p.Namespace {
		return ErrKernelApply
	}
	return nil
}

type ownedKernelSnapshot struct {
	ownership [2]Ownership
	up        [2]bool
	address   [2]bool
	routes    [2]map[netip.Prefix]bool
}

// snapshot refuses foreign name/ID collisions and unexpected objects on an owned
// link. It does not serialize another privileged writer; the controller must hold
// exclusive local journal/runtime ownership for the operation's entire lifetime.
func (a *KernelApplier) snapshot(ctx context.Context, p KernelAllocation) (ownedKernelSnapshot, error) {
	out := ownedKernelSnapshot{}
	fail := func() (ownedKernelSnapshot, error) { return ownedKernelSnapshot{}, ErrKernelApply }
	if a.check(ctx, p) != nil {
		return fail()
	}
	raw, err := a.run(ctx, "-j", "-d", "link", "show")
	if err != nil {
		return fail()
	}
	links, ok := kernelObjects(raw)
	if !ok {
		return fail()
	}
	allNames := map[string]int{}
	allIndices := map[int]bool{}
	for _, obj := range links {
		name, ok := kernelString(obj, "ifname")
		if !ok {
			return fail()
		}
		index, ok := kernelNumber(obj["ifindex"], 31)
		if !ok || index == 0 || allIndices[int(index)] || allNames[name] != 0 {
			return fail()
		}
		allNames[name] = int(index)
		allIndices[int(index)] = true
		var xfrm uint32
		if v, present := obj["linkinfo"]; present {
			info, ok := kernelObject(v)
			if !ok {
				return fail()
			}
			kind, ok := kernelString(info, "info_kind")
			if !ok {
				return fail()
			}
			if kind == "xfrm" {
				data, ok := kernelObject(info["info_data"])
				if !ok {
					return fail()
				}
				value, ok := kernelString(data, "if_id")
				if !ok || !strings.HasPrefix(value, "0x") {
					return fail()
				}
				id, err := strconv.ParseUint(value[2:], 16, 32)
				if err != nil {
					return fail()
				}
				xfrm = uint32(id)
				if _, external := data["external"]; external {
					return fail()
				}
			}
		}
		for i, t := range p.Tunnels {
			if name != t.Name && xfrm != t.XFRMID {
				continue
			}
			alias, ok := kernelString(obj, "ifalias")
			if !ok || name != t.Name || xfrm != t.XFRMID || alias != t.Alias || out.ownership[i].InterfaceIndex != 0 {
				return fail()
			}
			flags, ok := kernelFlags(obj["flags"])
			if !ok {
				return fail()
			}
			for _, f := range flags {
				if f == "UP" {
					out.up[i] = true
				}
			}
			out.ownership[i] = Ownership{Namespace: p.Namespace, InterfaceName: name, InterfaceIndex: int(index), XFRMID: xfrm}
		}
	}
	raw, err = a.run(ctx, "-j", "addr", "show")
	if err != nil {
		return fail()
	}
	addresses, ok := kernelObjects(raw)
	if !ok {
		return fail()
	}
	for _, obj := range addresses {
		name, ok := kernelString(obj, "ifname")
		if !ok {
			return fail()
		}
		for i, t := range p.Tunnels {
			if name != t.Name {
				continue
			}
			idx, ok := kernelNumber(obj["ifindex"], 31)
			if !ok || int(idx) != out.ownership[i].InterfaceIndex {
				return fail()
			}
			var infos []map[string]json.RawMessage
			if json.Unmarshal(obj["addr_info"], &infos) != nil {
				return fail()
			}
			for _, info := range infos {
				family, _ := kernelString(info, "family")
				local, _ := kernelString(info, "local")
				bits, ok := kernelNumber(info["prefixlen"], 8)
				if !ok || family != "inet" || local != t.InsideAddress.Addr().String() || int(bits) != t.InsideAddress.Bits() || out.address[i] {
					return fail()
				}
				out.address[i] = true
			}
		}
	}
	raw, err = a.run(ctx, "-j", "-d", "-N", "-4", "route", "show", "table", "all")
	if err != nil {
		return fail()
	}
	routes, ok := kernelObjects(raw)
	if !ok {
		return fail()
	}
	for i := range out.routes {
		out.routes[i] = map[netip.Prefix]bool{}
	}
	for _, obj := range routes {
		dst, ok := kernelString(obj, "dst")
		if !ok {
			return fail()
		}
		prefix, ok := kernelDestination(dst)
		if !ok {
			return fail()
		}
		dev, _ := kernelString(obj, "dev")
		// Reject indirect forwarding: its device cannot be proven from this dump.
		for _, k := range []string{"nhid", "multipath", "nexthops", "encap", "encap_type"} {
			if _, present := obj[k]; present {
				return fail()
			}
		}
		owned := -1
		for i, t := range p.Tunnels {
			if dev == t.Name {
				owned = i
			}
		}
		if owned < 0 {
			for _, remote := range p.Tunnels[0].RemotePrefixes {
				if prefix.Overlaps(remote) && prefix.Bits() >= remote.Bits() {
					return fail()
				}
			}
			continue
		}
		t := p.Tunnels[owned]
		table, ok := kernelDecimal(obj, "table", 32)
		if !ok {
			return fail()
		}
		protocol, ok := kernelDecimal(obj, "protocol", 8)
		if !ok {
			return fail()
		}
		kind, ok := kernelDecimal(obj, "type", 8)
		if !ok {
			return fail()
		}
		// Only exact kernel-generated address routes or our exact selected route.
		broadcast := t.InsideAddress.Masked().Addr().As4()
		broadcast[3] |= 3
		expectedScope := uint64(254)
		ownAddressRoute := kind == 2 && prefix == netip.PrefixFrom(t.InsideAddress.Addr(), 32)
		if kind == 3 && prefix == netip.PrefixFrom(netip.AddrFrom4(broadcast), 32) {
			ownAddressRoute = true
			expectedScope = 253
		}
		if protocol == 2 && table == 255 && ownAddressRoute {
			scope, ok := kernelDecimal(obj, "scope", 8)
			source, sourceOK := kernelString(obj, "prefsrc")
			if !ok || scope != expectedScope || !sourceOK || source != t.InsideAddress.Addr().String() {
				return fail()
			}
			for k := range obj {
				switch k {
				case "dst", "dev", "table", "protocol", "type", "scope", "prefsrc", "flags":
				default:
					return fail()
				}
			}
			continue
		}
		allowed := map[string]bool{"dst": true, "dev": true, "table": true, "protocol": true, "type": true, "metric": true, "scope": true, "flags": true}
		for k := range obj {
			if !allowed[k] {
				return fail()
			}
		}
		metric, ok := kernelNumber(obj["metric"], 32)
		if !ok || table != 254 || protocol != 242 || kind != 1 || metric != uint64(50000+int(t.Slot)) || !t.Selected {
			return fail()
		}
		scope, ok := kernelDecimal(obj, "scope", 8)
		if !ok || scope != 253 {
			return fail()
		}
		if f, present := obj["flags"]; present {
			flags, ok := kernelFlags(f)
			if !ok || len(flags) != 0 {
				return fail()
			}
		}
		expected := false
		for _, r := range t.RemotePrefixes {
			if r == prefix {
				expected = true
			}
		}
		if !expected || out.routes[owned][prefix] {
			return fail()
		}
		out.routes[owned][prefix] = true
	}
	raw, err = a.run(ctx, "-j", "-d", "-N", "-6", "route", "show", "table", "all")
	if err != nil {
		return fail()
	}
	v6, ok := kernelObjects(raw)
	if !ok {
		return fail()
	}
	for _, obj := range v6 {
		for _, key := range []string{"nhid", "multipath", "nexthops"} {
			if _, found := obj[key]; found {
				return fail()
			}
		}
		dev, _ := kernelString(obj, "dev")
		for _, tunnel := range p.Tunnels {
			if dev == tunnel.Name {
				// An IPv4-only interface still has this kernel multicast route.
				// No unicast IPv6 route or manually attributed route is adopted.
				dst, _ := kernelString(obj, "dst")
				table, tok := kernelDecimal(obj, "table", 32)
				proto, pok := kernelDecimal(obj, "protocol", 8)
				kind, kok := kernelDecimal(obj, "type", 8)
				if dst != "ff00::/8" || !tok || table != 255 || !pok || proto != 2 || !kok || kind != 5 {
					return fail()
				}
			}
		}
	}
	if a.check(ctx, p) != nil {
		return fail()
	}
	return out, nil
}
func (a *KernelApplier) mutate(ctx context.Context, p KernelAllocation, args ...string) error {
	if a.check(ctx, p) != nil {
		return ErrKernelApply
	}
	if _, err := a.run(ctx, args...); err != nil || a.check(ctx, p) != nil {
		return ErrKernelApply
	}
	return nil
}

// Apply is called only after prefix refusal has been installed and verified and
// this allocation durably journaled. It never installs an allow rule or an SA.
// Partial failure preserves the journal/guard for a subsequent exact cleanup.
func (a *KernelApplier) Apply(ctx context.Context, p KernelAllocation, previous [2]Ownership) ([2]Ownership, error) {
	fail := func() ([2]Ownership, error) { return [2]Ownership{}, ErrKernelApply }
	if a.check(ctx, p) != nil {
		return fail()
	}
	ctx, cancel := context.WithTimeout(ctx, 6*kernelReadTimeout)
	defer cancel()
	s, err := a.snapshot(ctx, p)
	if err != nil {
		return fail()
	}
	for i, t := range p.Tunnels {
		got := s.ownership[i]
		if previous[i].InterfaceIndex != 0 && previous[i] != got {
			return fail()
		}
		if got.InterfaceIndex == 0 {
			if a.mutate(ctx, p, "link", "add", "name", t.Name, "alias", t.Alias, "type", "xfrm", "if_id", strconv.FormatUint(uint64(t.XFRMID), 10)) != nil {
				return fail()
			}
			// The qualified kernel's XFRM newlink ignores IFLA_IFALIAS at
			// creation. Stamp only following this successful exclusive create.
			// A crash in this gap remains an unresolved journal obligation;
			// startup must never adopt an unlabeled interface by name alone.
			if a.mutate(ctx, p, "link", "set", "dev", t.Name, "alias", t.Alias, "addrgenmode", "none") != nil {
				return fail()
			}
		}
		s, err = a.snapshot(ctx, p)
		if err != nil || s.ownership[i].InterfaceIndex == 0 {
			return fail()
		}
		if !s.address[i] {
			if a.mutate(ctx, p, "-4", "addr", "add", t.InsideAddress.String(), "dev", t.Name, "noprefixroute") != nil {
				return fail()
			}
		}
		if !s.up[i] {
			if a.mutate(ctx, p, "link", "set", "dev", t.Name, "up") != nil {
				return fail()
			}
		}
		for _, prefix := range t.RemotePrefixes {
			if !t.Selected || s.routes[i][prefix] {
				continue
			}
			if a.mutate(ctx, p, "-4", "route", "add", prefix.String(), "dev", t.Name, "table", "254", "proto", "242", "metric", fmt.Sprint(50000+int(t.Slot))) != nil {
				return fail()
			}
		}
	}
	s, err = a.snapshot(ctx, p)
	if err != nil {
		return fail()
	}
	for i, t := range p.Tunnels {
		if !s.address[i] || !s.up[i] || s.ownership[i].InterfaceIndex == 0 || (t.Selected && len(s.routes[i]) != len(t.RemotePrefixes)) {
			return fail()
		}
	}
	return s.ownership, nil
}

// Remove requires SAs/policies already absent and a verified permanent refusal
// guard. It deletes individual exact routes/links; no flush or replacement.
func (a *KernelApplier) Remove(ctx context.Context, p KernelAllocation, previous [2]Ownership) (KernelAbsence, error) {
	fail := func() (KernelAbsence, error) { return KernelAbsence{}, ErrKernelApply }
	if a.check(ctx, p) != nil {
		return fail()
	}
	ctx, cancel := context.WithTimeout(ctx, 6*kernelReadTimeout)
	defer cancel()
	s, err := a.snapshot(ctx, p)
	if err != nil {
		return fail()
	}
	r := &XFRMReader{run: a.run, namespace: a.namespace}
	x, err := r.Read(ctx)
	if err != nil {
		return fail()
	}
	for _, t := range p.Tunnels {
		for _, v := range x.States {
			if v.IfID == t.XFRMID {
				return fail()
			}
		}
		for _, v := range x.Policies {
			if v.IfID == t.XFRMID {
				return fail()
			}
		}
	}
	for i, t := range p.Tunnels {
		if s.ownership[i].InterfaceIndex == 0 {
			continue
		}
		if previous[i].InterfaceIndex != 0 && previous[i] != s.ownership[i] {
			return fail()
		}
		for prefix := range s.routes[i] {
			if a.mutate(ctx, p, "-4", "route", "del", prefix.String(), "dev", t.Name, "table", "254", "proto", "242", "metric", fmt.Sprint(50000+int(t.Slot))) != nil {
				return fail()
			}
		}
		// Fresh collision/foreign-object check immediately before removing a link.
		fresh, err := a.snapshot(ctx, p)
		if err != nil || fresh.ownership[i] != s.ownership[i] {
			return fail()
		}
		if a.mutate(ctx, p, "link", "delete", "dev", t.Name) != nil {
			return fail()
		}
	}
	s, err = a.snapshot(ctx, p)
	if err != nil {
		return fail()
	}
	for _, o := range s.ownership {
		if o.InterfaceIndex != 0 {
			return fail()
		}
	}
	x, err = r.Read(ctx)
	if err != nil {
		return fail()
	}
	for _, t := range p.Tunnels {
		for _, v := range x.States {
			if v.IfID == t.XFRMID {
				return fail()
			}
		}
		for _, v := range x.Policies {
			if v.IfID == t.XFRMID {
				return fail()
			}
		}
	}
	return KernelAbsence{Namespace: p.Namespace, Generation: p.Generation, TunnelIDs: [2]uuid.UUID{p.Tunnels[0].TunnelID, p.Tunnels[1].TunnelID}}, nil
}

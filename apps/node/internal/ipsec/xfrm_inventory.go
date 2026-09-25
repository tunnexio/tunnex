package ipsec

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var ErrXFRMInventoryInvalid = errors.New("invalid no-key XFRM inventory")

type XFRMState struct {
	Direction           string // Optional on older kernels; explicit values are in or out.
	Source, Destination netip.Addr
	SPI, ReqID, IfID    uint32
	ReplayWindow        uint8
	Encapsulation       XFRMEncapsulation
}

// XFRMEncapsulation preserves NAT-T readback for independent snapshot comparison.
// The zero value denotes native ESP without UDP encapsulation.
type XFRMEncapsulation struct {
	SourcePort, DestinationPort uint16
	OriginalAddress             netip.Addr
}
type XFRMPolicy struct {
	TemplateSPI                         uint32 // Zero means the kernel template does not constrain SPI.
	Source, Destination                 netip.Prefix
	Direction                           string
	Priority, ReqID, IfID               uint32
	TemplateSource, TemplateDestination netip.Addr
}
type XFRMInventory struct {
	Namespace string
	States    []XFRMState
	Policies  []XFRMPolicy
}

// ParseXFRMInventory accepts the closed IPv4 ESP tunnel profile printed by
// `ip xfrm state list nokeys` and `ip xfrm policy list nosock`, without -s/-o/-j.
// iproute2's XFRM printer is text, even when JSON is requested. Algorithm lines
// MUST contain the nokeys sentinel. Raw input is never returned in an error.
// This is a partial observation, not ownership, atomic consistency, freshness,
// encryption key length, SA establishment or permission to activate traffic.
// Unknown fields (including marks, offload and optional templates) refuse.
func ParseXFRMInventory(namespace string, states, policies []byte) (XFRMInventory, error) {
	invalid := func() (XFRMInventory, error) { return XFRMInventory{}, ErrXFRMInventoryInvalid }
	if !validKernelNamespace(namespace) {
		return invalid()
	}
	sb, ok := xfrmBlocks(states)
	if !ok {
		return invalid()
	}
	pb, ok := xfrmBlocks(policies)
	if !ok {
		return invalid()
	}
	out := XFRMInventory{Namespace: namespace, States: []XFRMState{}, Policies: []XFRMPolicy{}}
	// Kernel state identity is destination/protocol/SPI; source/reqid cannot
	// disguise a duplicate. All accepted states use ESP.
	seenStates := map[string]bool{}
	seenPolicies := map[XFRMPolicy]bool{}
	for _, b := range sb {
		s, ok := xfrmState(b)
		if !ok {
			return invalid()
		}
		key := s.Destination.String() + ":" + strconv.FormatUint(uint64(s.SPI), 10)
		if seenStates[key] {
			return invalid()
		}
		seenStates[key] = true
		out.States = append(out.States, s)
	}
	for _, b := range pb {
		p, ok := xfrmPolicy(b)
		key := p
		key.TemplateSource, key.TemplateDestination = netip.Addr{}, netip.Addr{}
		key.TemplateSPI, key.ReqID = 0, 0
		if !ok || seenPolicies[key] {
			return invalid()
		}
		seenPolicies[key] = true
		out.Policies = append(out.Policies, p)
	}
	return out, nil
}

func xfrmBlocks(raw []byte) ([][]string, bool) {
	if len(raw) > kernelDumpLimit {
		return nil, false
	}
	for _, c := range raw {
		if c != '\n' && c != '\t' && (c < 32 || c > 126) {
			return nil, false
		}
	}
	var blocks [][]string
	for _, line := range strings.Split(string(raw), "\n") {
		if len(line) > 4096 {
			return nil, false
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "src ") {
			if len(blocks) >= kernelEntryLimit {
				return nil, false
			}
			blocks = append(blocks, []string{line})
		} else {
			if len(blocks) == 0 || len(blocks[len(blocks)-1]) >= 16 {
				return nil, false
			}
			blocks[len(blocks)-1] = append(blocks[len(blocks)-1], line)
		}
	}
	return blocks, true
}
func xfrmUint(s string, base, bits int) (uint32, bool) {
	if s == "" || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
		return 0, false
	}
	if base == 16 {
		if !strings.HasPrefix(s, "0x") {
			return 0, false
		}
		s = s[2:]
	}
	n, e := strconv.ParseUint(s, base, bits)
	return uint32(n), e == nil
}
func xfrmAddr(s string) (netip.Addr, bool) {
	a, e := netip.ParseAddr(s)
	return a, e == nil && a.Is4() && !a.IsUnspecified() && !a.IsMulticast() && a.String() == s
}
func xfrmPrefix(s string) (netip.Prefix, bool) {
	p, e := netip.ParsePrefix(s)
	return p, e == nil && p.Addr().Is4() && p == p.Masked() && p.String() == s
}
func xfrmEndpoints(line string) (netip.Addr, netip.Addr, bool) {
	f := strings.Fields(line)
	if len(f) != 4 || f[0] != "src" || f[2] != "dst" {
		return netip.Addr{}, netip.Addr{}, false
	}
	a, ok := xfrmAddr(f[1])
	b, ok2 := xfrmAddr(f[3])
	return a, b, ok && ok2 && a != b
}
func xfrmState(b []string) (XFRMState, bool) {
	var s XFRMState
	if len(b) < 7 || len(b) > 10 {
		return s, false
	}
	// Newer kernels expose SA direction after if_id. Preserve it for runtime
	// association; legacy absence is accepted, but no other position/value is.
	last := strings.Fields(b[len(b)-1])
	if len(last) > 0 && last[0] == "dir" {
		if len(last) != 2 || (last[1] != "in" && last[1] != "out") {
			return s, false
		}
		s.Direction = last[1]
		b = b[:len(b)-1]
	}
	if len(b) < 7 || len(b) > 9 {
		return s, false
	}
	var ok bool
	s.Source, s.Destination, ok = xfrmEndpoints(b[0])
	if !ok {
		return s, false
	}
	f := strings.Fields(b[1])
	if len(f) != 8 || f[0] != "proto" || f[1] != "esp" || f[2] != "spi" || f[4] != "reqid" || f[6] != "mode" || f[7] != "tunnel" {
		return s, false
	}
	s.SPI, ok = xfrmUint(f[3], 16, 32)
	if !ok || s.SPI == 0 {
		return s, false
	}
	s.ReqID, ok = xfrmUint(f[5], 10, 32)
	if !ok || s.ReqID == 0 {
		return s, false
	}
	f = strings.Fields(b[2])
	if len(f) != 2 && len(f) != 4 {
		return s, false
	}
	if f[0] != "replay-window" || (len(f) == 4 && (f[2] != "flag" || f[3] != "af-unspec")) {
		return s, false
	}
	window, ok := xfrmUint(f[1], 10, 8)
	if !ok {
		return s, false
	}
	s.ReplayWindow = uint8(window)
	if b[3] != "auth-trunc hmac(sha256) <<Keys hidden>> 128" || b[4] != "enc cbc(aes) <<Keys hidden>>" {
		return s, false
	}
	// Native printers may include NAT-T and last-use metadata before the replay
	// context. Neither field grants authority. Keep the encapsulation tuple in
	// the inventory so a changed UDP mapping invalidates a double read.
	antiReplayLine := 5
	seenLastUsed, seenEncap := false, false
	for antiReplayLine < len(b)-2 {
		line := b[antiReplayLine]
		switch {
		case strings.HasPrefix(line, "encap "):
			if seenEncap {
				return s, false
			}
			seenEncap = true
			f := strings.Fields(line)
			if len(f) != 9 || f[0] != "encap" || f[1] != "type" || f[2] != "espinudp" || f[3] != "sport" || f[5] != "dport" || f[7] != "addr" {
				return s, false
			}
			sport, sok := xfrmUint(f[4], 10, 16)
			dport, dok := xfrmUint(f[6], 10, 16)
			// ESP-in-UDP's original address is unused for this fixed IPv4 ESP
			// tunnel profile; nonzero NAT-OA remains unsupported.
			if !sok || !dok || sport == 0 || dport == 0 || f[8] != "0.0.0.0" {
				return s, false
			}
			s.Encapsulation = XFRMEncapsulation{SourcePort: uint16(sport), DestinationPort: uint16(dport), OriginalAddress: netip.IPv4Unspecified()}
		case strings.HasPrefix(line, "lastused "):
			if seenLastUsed {
				return s, false
			}
			seenLastUsed = true
			const layout = "2006-01-02 15:04:05"
			stamp := strings.TrimPrefix(line, "lastused ")
			parsed, err := time.Parse(layout, stamp)
			if err != nil || parsed.Format(layout) != stamp {
				return s, false
			}
		default:
			return s, false
		}
		antiReplayLine++
	}
	f = strings.Fields(b[antiReplayLine])
	if len(f) != 8 || f[0] != "anti-replay" || f[1] != "context:" || f[2] != "seq" || f[4] != "oseq" || f[6] != "bitmap" || !strings.HasSuffix(f[3], ",") || !strings.HasSuffix(f[5], ",") {
		return s, false
	}
	for _, v := range []string{strings.TrimSuffix(f[3], ","), strings.TrimSuffix(f[5], ","), f[7]} {
		if _, ok = xfrmUint(v, 16, 32); !ok {
			return s, false
		}
	}
	f = strings.Fields(b[antiReplayLine+1])
	if len(f) != 2 || f[0] != "if_id" {
		return s, false
	}
	s.IfID, ok = xfrmUint(f[1], 16, 32)
	return s, ok && s.IfID != 0
}
func xfrmPolicy(b []string) (XFRMPolicy, bool) {
	var p XFRMPolicy
	if len(b) != 5 {
		return p, false
	}
	f := strings.Fields(b[0])
	if len(f) != 4 || f[0] != "src" || f[2] != "dst" {
		return p, false
	}
	var ok bool
	p.Source, ok = xfrmPrefix(f[1])
	if !ok {
		return p, false
	}
	p.Destination, ok = xfrmPrefix(f[3])
	if !ok {
		return p, false
	}
	f = strings.Fields(b[1])
	if (len(f) != 4 && len(f) != 6) || f[0] != "dir" || (f[1] != "out" && f[1] != "in" && f[1] != "fwd") || f[2] != "priority" || (len(f) == 6 && (f[4] != "ptype" || f[5] != "main")) {
		return p, false
	}
	p.Direction = f[1]
	p.Priority, ok = xfrmUint(f[3], 10, 32)
	if !ok {
		return p, false
	}
	if !strings.HasPrefix(b[2], "tmpl ") {
		return p, false
	}
	p.TemplateSource, p.TemplateDestination, ok = xfrmEndpoints(strings.TrimPrefix(b[2], "tmpl "))
	if !ok {
		return p, false
	}
	f = strings.Fields(b[3])
	if len(f) == 8 && f[0] == "proto" && f[1] == "esp" && f[2] == "spi" {
		p.TemplateSPI, ok = xfrmUint(f[3], 16, 32)
		if !ok || p.TemplateSPI == 0 {
			return p, false
		}
		f = append(append([]string(nil), f[:2]...), f[4:]...)
	}
	if len(f) != 6 || f[0] != "proto" || f[1] != "esp" || f[2] != "reqid" || f[4] != "mode" || f[5] != "tunnel" {
		return p, false
	}
	p.ReqID, ok = xfrmUint(f[3], 10, 32)
	if !ok || p.ReqID == 0 {
		return p, false
	}
	f = strings.Fields(b[4])
	if len(f) != 2 || f[0] != "if_id" {
		return p, false
	}
	p.IfID, ok = xfrmUint(f[1], 16, 32)
	return p, ok && p.IfID != 0
}

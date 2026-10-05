package sandboxscope

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

const MaxScopeEntries = 64

var ErrInvalidScope = errors.New("invalid or unsupported sandbox scope")
var ErrScopeExceeded = errors.New("sandbox scope exceeds current entitlement or template")

// Scope is a static IPv4 packet tuple. Zero ports mean all ports; protocol any
// requires zero ports. Dynamic destination identities need a separate contract.
type Scope struct {
	CIDR     string `json:"cidr"`
	Protocol string `json:"protocol"`
	PortLow  uint16 `json:"port_low"`
	PortHigh uint16 `json:"port_high"`
}

func (s Scope) Validate() error {
	p, err := netip.ParsePrefix(s.CIDR)
	if err != nil || !p.Addr().Is4() || p != p.Masked() || p.String() != s.CIDR {
		return ErrInvalidScope
	}
	if s.Protocol != "any" && s.Protocol != "tcp" && s.Protocol != "udp" {
		return ErrInvalidScope
	}
	if (s.PortLow == 0) != (s.PortHigh == 0) || s.PortLow > s.PortHigh || (s.Protocol == "any" && s.PortLow != 0) {
		return ErrInvalidScope
	}
	return nil
}

func NormalizeScope(entries []Scope) ([]Scope, error) {
	if len(entries) > MaxScopeEntries {
		return nil, ErrInvalidScope
	}
	unique := map[Scope]bool{}
	for _, s := range entries {
		if err := s.Validate(); err != nil {
			return nil, err
		}
		unique[s] = true
	}
	out := make([]Scope, 0, len(unique))
	for s := range unique {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return scopeKey(out[i]) < scopeKey(out[j]) })
	return out, nil
}
func scopeKey(s Scope) string {
	return fmt.Sprintf("%s/%s/%05d/%05d", s.CIDR, s.Protocol, s.PortLow, s.PortHigh)
}

func portBounds(s Scope) (uint16, uint16) {
	if s.PortLow == 0 {
		return 1, 65535
	}
	return s.PortLow, s.PortHigh
}

// Intersect returns the narrower overlap; invalid tuples never contribute.
func Intersect(a, b Scope) (Scope, bool) {
	if a.Validate() != nil || b.Validate() != nil {
		return Scope{}, false
	}
	ap, _ := netip.ParsePrefix(a.CIDR)
	bp, _ := netip.ParsePrefix(b.CIDR)
	if !ap.Overlaps(bp) {
		return Scope{}, false
	}
	out := a
	if bp.Bits() > ap.Bits() {
		out.CIDR = b.CIDR
	}
	if a.Protocol == "any" {
		out.Protocol = b.Protocol
	} else if b.Protocol != "any" && a.Protocol != b.Protocol {
		return Scope{}, false
	}
	al, ah := portBounds(a)
	bl, bh := portBounds(b)
	low, high := max(al, bl), min(ah, bh)
	if low > high {
		return Scope{}, false
	}
	if low == 1 && high == 65535 {
		out.PortLow = 0
		out.PortHigh = 0
	} else {
		out.PortLow = low
		out.PortHigh = high
	}
	return out, true
}
func covers(cap, request Scope) bool {
	intersection, ok := Intersect(cap, request)
	if !ok {
		return false
	}
	// 1..65535 and 0/0 are equivalent full-port spellings.
	rl, rh := portBounds(request)
	il, ih := portBounds(intersection)
	return intersection.CIDR == request.CIDR && intersection.Protocol == request.Protocol && rl == il && rh == ih
}

// AdmitScope conservatively requires each requested tuple be wholly covered by
// one tuple in each envelope. It refuses union coverage rather than widening.
func AdmitScope(requested, entitlement, template []Scope) error {
	for _, entries := range [][]Scope{requested, entitlement, template} {
		if _, err := NormalizeScope(entries); err != nil {
			return err
		}
	}
	for _, r := range requested {
		for _, envelope := range [][]Scope{entitlement, template} {
			found := false
			for _, cap := range envelope {
				if covers(cap, r) {
					found = true
					break
				}
			}
			if !found {
				return ErrScopeExceeded
			}
		}
	}
	return nil
}

// EffectiveScope recomputes current access. Invalid/oversized inputs withdraw
// all access. Intersection output is bounded too, avoiding Cartesian blowup.
func EffectiveScope(requested, entitlement, template []Scope) []Scope {
	for _, entries := range [][]Scope{requested, entitlement, template} {
		if _, err := NormalizeScope(entries); err != nil {
			return nil
		}
	}
	unique := map[Scope]bool{}
	for _, r := range requested {
		for _, e := range entitlement {
			re, ok := Intersect(r, e)
			if !ok {
				continue
			}
			for _, cap := range template {
				if clipped, ok := Intersect(re, cap); ok {
					unique[clipped] = true
					if len(unique) > MaxScopeEntries {
						return nil
					}
				}
			}
		}
	}
	out := make([]Scope, 0, len(unique))
	for s := range unique {
		out = append(out, s)
	}
	normalized, err := NormalizeScope(out)
	if err != nil {
		return nil
	}
	return normalized
}

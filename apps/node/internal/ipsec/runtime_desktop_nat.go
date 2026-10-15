package ipsec

import (
	"github.com/google/uuid"
	"net/netip"
	"sort"
	"sync"
)

// DesktopNATExemption preserves the enrolled source on one explicit cloud
// destination. It grants no forwarding authority; the IPsec guard owns that.
type DesktopNATExemption struct{ Source, Destination netip.Prefix }

// DesktopNATSource joins the IPsec and ordinary egress reconcilers without a
// lock-order callback. The egress reconciler renders Snapshot; IPsec verifies
// exact kernel readback before permitting any desktop packets.
type DesktopNATSource struct {
	mu          sync.Mutex
	connections map[uuid.UUID][]DesktopNATExemption
}

func (s *DesktopNATSource) Set(id uuid.UUID, values []DesktopNATExemption) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.connections == nil {
		s.connections = map[uuid.UUID][]DesktopNATExemption{}
	}
	if len(values) == 0 {
		delete(s.connections, id)
		return
	}
	s.connections[id] = append([]DesktopNATExemption(nil), values...)
}
func (s *DesktopNATSource) Snapshot() []DesktopNATExemption {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[DesktopNATExemption]bool{}
	for _, list := range s.connections {
		for _, item := range list {
			if item.Source.IsValid() && item.Source.Addr().Is4() && item.Source.Bits() == 32 && item.Destination.IsValid() && item.Destination.Addr().Is4() && item.Destination == item.Destination.Masked() && item.Destination.Bits() > 0 {
				seen[item] = true
			}
		}
	}
	out := make([]DesktopNATExemption, 0, len(seen))
	for item := range seen {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source.String() < out[j].Source.String()
		}
		return out[i].Destination.String() < out[j].Destination.String()
	})
	return out
}

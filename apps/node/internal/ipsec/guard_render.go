package ipsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

type GuardProtocol string

const (
	GuardAny GuardProtocol = "any"
	GuardTCP GuardProtocol = "tcp"
	GuardUDP GuardProtocol = "udp"
)

// GuardGrant is explicit shared-policy authority. Configuration and SA selectors
// never create a grant. FQDN-managed provenance is not supported by this renderer.
type GuardGrant struct {
	Source, Destination netip.Prefix
	Protocol            GuardProtocol
	PortLow, PortHigh   uint16
	HostOrigin          bool
	FQDNManaged         bool
}

// GuardEncryptedEgress is observed installed-SA and underlay identity, not
// configuration authority. The caller must independently qualify these facts.
type GuardEncryptedEgress struct {
	TunnelInterfaceIndex   int
	ReqID                  uint32
	Peer                   netip.Addr
	UnderlayInterfaceIndex int
}
type GuardConnection struct {
	// PrefixOnly installs permanent refusal before any live interface ownership
	// is known (startup/retained cleanup). It cannot carry permits or grants.
	PrefixOnly      bool
	EncryptedEgress []GuardEncryptedEgress
	ID              uuid.UUID
	Local, Remote   []netip.Prefix
	Tunnels         [2]Ownership
	// Callers may populate these only after independent ownership/evidence checks.
	// PermitFor is remaining in-memory authority after request/install budgets.
	// It must never be persisted or reused on a later installation attempt.
	PermitFor                 time.Duration
	PermittedInterfaceIndices []int
	// ReplyIngressIndices is separately observed healthy ingress authority, never outbound selection.
	// It admits replies and explicitly granted remote-origin connections.
	ReplyIngressIndices []int
	LocalIngressIndices []int
	Grants              []GuardGrant
}
type GuardIntent struct {
	Namespace   string
	OwnerID     uuid.UUID
	Revision    int64
	Connections []GuardConnection
}

// GuardManifest is rendered intent, NOT an applied/readback receipt.
type GuardManifest struct {
	Namespace    string
	OwnerID      uuid.UUID
	Revision     int64
	Digest       string
	NFT          string
	NFTJSON      string
	ExpectedJSON string
}

var ErrGuardIntent = errors.New("invalid IPsec guard intent")

// RenderGuard creates an atomic replacement for one exclusively owned table.
// The applying owner must verify namespace, table ownership and full readback.
// This function performs no command, activation or persistent state change.
func RenderGuard(intent GuardIntent) (GuardManifest, error) {
	canonical, ok := canonicalGuard(intent)
	if !ok {
		return GuardManifest{}, ErrGuardIntent
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return GuardManifest{}, ErrGuardIntent
	}
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	var forward, output, input, post, postnat guardChain
	var setText, setPreamble strings.Builder
	// NAT can rewrite a protected address before the filter hooks run. Check
	// both original and current tuples before ANY connection can permit it.
	// A second refusal-only hook observes conventional SNAT after priority 90.
	// Qualification must still reject later modifying hooks; this is not a hook census.
	for _, c := range canonical.Connections {
		for _, prefix := range c.Remote {
			for _, original := range []bool{true, false} {
				for _, field := range []string{"saddr", "daddr"} {
					for _, status := range []string{"dnat", "snat"} {
						rule := guardNATDrop(prefix, field, status, original)
						forward.add(rule)
						input.add(rule)
						output.add(rule)
						post.add(rule)
						postnat.add(rule)
					}
				}
			}
		}
	}
	for _, c := range canonical.Connections {
		setText.WriteString(guardLeaseSetText(c))
		// nft flush-table retains sets. Keep an empty declaration during refusal
		// so withdrawals flush previous reply authority and readback stays exact.
		setText.WriteString(guardReplyLeaseSetText(c))
		fmt.Fprintf(&setPreamble, "add set inet tunnex_ipsec %s { type iface_index; flags timeout; timeout 60s; }\nflush set inet tunnex_ipsec %s\n", guardReplyLeaseName(c.ID), guardReplyLeaseName(c.ID))
		setText.WriteString(guardSALeaseText(c))
		fmt.Fprintf(&setPreamble, "add set inet tunnex_ipsec %s { typeof ipsec out reqid; flags timeout; timeout 60s; }\nflush set inet tunnex_ipsec %s\n", guardSALeaseName(c.ID), guardSALeaseName(c.ID))
		fmt.Fprintf(&setPreamble, "add set inet tunnex_ipsec %s { type iface_index; flags timeout; timeout 60s; }\nflush set inet tunnex_ipsec %s\n", guardLeaseName(c.ID), guardLeaseName(c.ID))
		// Reject spoofed remote identities before considering any grant.
		for _, p := range c.Remote {
			if c.PrefixOnly {
				continue
			}
			indices := []int{c.Tunnels[0].InterfaceIndex, c.Tunnels[1].InterfaceIndex}
			line := guardRule{text: fmt.Sprintf("    ip saddr %s meta iif != %s counter drop\n", p, indexSet(indices)), expr: []any{guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(p)), guardMatch("!=", guardMeta("iif"), map[string]any{"set": indices}), guardCounter(), guardVerdict("drop")}}
			forward.add(line)
			input.add(line)
		}
		for _, g := range c.Grants {
			outbound := withinPrefixes(g.Source, c.Local)
			if outbound && len(c.PermittedInterfaceIndices) > 0 {
				for _, tunnel := range c.ReplyIngressIndices {
					if g.HostOrigin {
						input.add(guardAllow(g, tunnel, 0, true, guardReplyLeaseName(c.ID), "iif"))
					} else {
						for _, local := range c.LocalIngressIndices {
							forward.add(guardAllow(g, tunnel, local, true, guardReplyLeaseName(c.ID), "iif"))
						}
					}
				}
			}
			// A remote peer can initiate on either independently qualified SA.
			// Ingress health is separate from our selected outbound route. Explicit
			// grants and the same expiring authority still gate every packet.
			if !outbound && len(c.ReplyIngressIndices) > 0 {
				if len(c.PermittedInterfaceIndices) > 0 {
					for _, local := range c.LocalIngressIndices {
						for _, tunnel := range c.ReplyIngressIndices {
							forward.add(guardAllow(g, tunnel, local, false, guardReplyLeaseName(c.ID), "iif"))
						}
						for _, tunnel := range c.PermittedInterfaceIndices {
							forward.add(guardAllow(g, local, tunnel, true, guardLeaseName(c.ID), "oif"))
						}
					}
				}
				continue
			}
			for _, tunnel := range c.PermittedInterfaceIndices {
				if g.HostOrigin {
					output.add(guardAllow(g, 0, tunnel, false, guardLeaseName(c.ID), "oif"))
					if len(c.ReplyIngressIndices) == 0 {
						input.add(guardAllow(g, tunnel, 0, true, guardLeaseName(c.ID), "iif"))
					}
					continue
				}
				for _, local := range c.LocalIngressIndices {
					ingress, egress := local, tunnel
					if !outbound {
						ingress, egress = tunnel, local
					}
					leaseKey, replyLeaseKey := "oif", "iif"
					if !outbound {
						leaseKey, replyLeaseKey = "iif", "oif"
					}
					forward.add(guardAllow(g, ingress, egress, false, guardLeaseName(c.ID), leaseKey))
					if !outbound || len(c.ReplyIngressIndices) == 0 {
						forward.add(guardAllow(g, egress, ingress, true, guardLeaseName(c.ID), replyLeaseKey))
					}
				}
			}
		}
		// These unconditional fallbacks cover both new and established traffic.
		for _, p := range c.Remote {
			dropDst := guardPrefixDrop("daddr", p)
			dropSrc := guardPrefixDrop("saddr", p)
			forward.add(dropDst)
			forward.add(dropSrc)
			output.add(dropDst)
			output.add(dropSrc)
			input.add(dropSrc)
			for _, index := range c.PermittedInterfaceIndices {
				post.add(guardRule{text: fmt.Sprintf("    ip daddr %s meta oif %d meta oif @%s counter accept\n", p, index, guardLeaseName(c.ID)), expr: []any{guardMatch("==", guardPayload("ip", "daddr"), guardPrefixJSON(p)), guardMatch("==", guardMeta("oif"), index), guardMatch("==", guardMeta("oif"), "@"+guardLeaseName(c.ID)), guardCounter(), guardVerdict("accept")}})
			}
			for _, encrypted := range c.EncryptedEgress {
				post.add(guardEncryptedAllow(p, encrypted, guardSALeaseName(c.ID)))
			}
			post.add(dropDst)
		}
		for _, tunnel := range c.Tunnels {
			if c.PrefixOnly {
				continue
			}
			forward.add(guardInterfaceDrop("iif", tunnel.InterfaceIndex))
			forward.add(guardInterfaceDrop("oif", tunnel.InterfaceIndex))
			input.add(guardInterfaceDrop("iif", tunnel.InterfaceIndex))
			output.add(guardInterfaceDrop("oif", tunnel.InterfaceIndex))
		}
		if forward.Len()+output.Len()+input.Len()+post.Len()+postnat.Len() > 1<<20 {
			return GuardManifest{}, ErrGuardIntent
		}
	}
	nft := fmt.Sprintf("add table inet tunnex_ipsec\nflush table inet tunnex_ipsec\nadd chain inet tunnex_ipsec owner\ndelete chain inet tunnex_ipsec owner\n%stable inet tunnex_ipsec {\n%s  chain owner {\n    comment \"tunnex-ipsec:%s:%d:%s\"\n  }\n  chain forward_guard {\n    type filter hook forward priority -10; policy accept;\n%s  }\n  chain output_guard {\n    type filter hook output priority -10; policy accept;\n%s  }\n  chain input_guard {\n    type filter hook input priority -10; policy accept;\n%s  }\n  chain postrouting_guard {\n    type filter hook postrouting priority 90; policy accept;\n%s  }\n  chain postnat_guard {\n    type filter hook postrouting priority 300; policy accept;\n%s  }\n}\n", setPreamble.String(), setText.String(), canonical.OwnerID, canonical.Revision, digest, forward.String(), output.String(), input.String(), post.String(), postnat.String())
	if len(nft) > 1<<20 {
		return GuardManifest{}, ErrGuardIntent
	}
	transaction, expectedJSON, err := guardDocuments(canonical, digest, []guardChain{forward, output, input, post, postnat})
	if err != nil || len(transaction) > 4<<20 || len(expectedJSON) > 4<<20 {
		return GuardManifest{}, ErrGuardIntent
	}
	return GuardManifest{Namespace: canonical.Namespace, OwnerID: canonical.OwnerID, Revision: canonical.Revision, Digest: digest, NFT: nft, NFTJSON: transaction, ExpectedJSON: expectedJSON}, nil
}
func guardAllow(g GuardGrant, ingress, egress int, reply bool, leaseName, leaseKey string) guardRule {
	var expr []any
	var b strings.Builder
	b.WriteString("    ")
	if ingress > 0 {
		fmt.Fprintf(&b, "meta iif %d ", ingress)
		expr = append(expr, guardMatch("==", guardMeta("iif"), ingress))
	}
	if egress > 0 {
		fmt.Fprintf(&b, "meta oif %d ", egress)
		expr = append(expr, guardMatch("==", guardMeta("oif"), egress))
	}
	src, dst := g.Source, g.Destination
	if reply {
		src, dst = dst, src
	}
	fmt.Fprintf(&b, "ip saddr %s ip daddr %s ", src, dst)
	expr = append(expr, guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(src)), guardMatch("==", guardPayload("ip", "daddr"), guardPrefixJSON(dst)))
	if g.Protocol != GuardAny {
		field := "dport"
		if reply {
			field = "sport"
		}
		ports := fmt.Sprint(g.PortLow)
		if g.PortHigh != g.PortLow {
			ports = fmt.Sprintf("%d-%d", g.PortLow, g.PortHigh)
		}
		fmt.Fprintf(&b, "%s %s %s ", g.Protocol, field, ports)
		var portJSON any = g.PortLow
		if g.PortHigh != g.PortLow {
			portJSON = map[string]any{"range": []uint16{g.PortLow, g.PortHigh}}
		}
		// Typed transport payload carries the protocol dependency; nft removes a redundant meta l4proto match.
		expr = append(expr, guardMatch("==", guardPayload(string(g.Protocol), field), portJSON))
	}
	if reply {
		b.WriteString("ct direction reply ct state established ")
		expr = append(expr, guardMatch("==", guardCT("direction"), "reply"), guardMatch("in", guardCT("state"), "established"))
	} else {
		b.WriteString("ct direction original ")
		expr = append(expr, guardMatch("==", guardCT("direction"), "original"))
	}
	fmt.Fprintf(&b, "meta %s @%s counter accept\n", leaseKey, leaseName)
	expr = append(expr, guardMatch("==", guardMeta(leaseKey), "@"+leaseName))
	return guardRule{text: b.String(), expr: append(expr, guardCounter(), guardVerdict("accept"))}
}
func indexSet(indices []int) string {
	sort.Ints(indices)
	if len(indices) == 1 {
		return fmt.Sprint(indices[0])
	}
	parts := make([]string, len(indices))
	for i, n := range indices {
		parts[i] = fmt.Sprint(n)
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}
func canonicalGuard(in GuardIntent) (GuardIntent, bool) {
	if !validKernelNamespace(in.Namespace) || in.OwnerID == uuid.Nil || in.Revision <= 0 || len(in.Connections) == 0 || len(in.Connections) > 64 {
		return GuardIntent{}, false
	}
	out := in
	out.Connections = append([]GuardConnection(nil), in.Connections...)
	connIDs := map[uuid.UUID]bool{}
	indices := map[int]bool{}
	names := map[string]bool{}
	xfrms := map[uint32]bool{}
	reqids := map[uint32]bool{}
	var allRemote, allLocal []netip.Prefix
	for i, c := range out.Connections {
		if c.ID == uuid.Nil || connIDs[c.ID] || len(c.Grants) > 128 || c.PermitFor < 0 || c.PermitFor > 60*time.Second {
			return GuardIntent{}, false
		}
		connIDs[c.ID] = true
		var ok bool
		c.Local, ok = guardPrefixes(c.Local)
		if !ok {
			return GuardIntent{}, false
		}
		c.Remote, ok = guardPrefixes(c.Remote)
		if !ok {
			return GuardIntent{}, false
		}
		allLocal = append(allLocal, c.Local...)
		allRemote = append(allRemote, c.Remote...)
		own := map[int]bool{}
		if c.PrefixOnly && (c.Tunnels != [2]Ownership{} || c.PermitFor != 0 || len(c.PermittedInterfaceIndices) != 0 || len(c.ReplyIngressIndices) != 0 || len(c.EncryptedEgress) != 0 || len(c.LocalIngressIndices) != 0 || len(c.Grants) != 0) {
			return GuardIntent{}, false
		}
		for _, t := range c.Tunnels {
			if c.PrefixOnly {
				continue
			}
			if t.Namespace != in.Namespace || !validToken(t.InterfaceName) || len(t.InterfaceName) > 15 || t.InterfaceName == "." || t.InterfaceName == ".." || strings.ContainsAny(t.InterfaceName, "/:") || t.InterfaceIndex <= 0 || int64(t.InterfaceIndex) > 2147483647 || t.XFRMID == 0 || indices[t.InterfaceIndex] || names[t.InterfaceName] || xfrms[t.XFRMID] {
				return GuardIntent{}, false
			}
			indices[t.InterfaceIndex] = true
			names[t.InterfaceName] = true
			xfrms[t.XFRMID] = true
			own[t.InterfaceIndex] = true
		}
		if c.Tunnels[0].InterfaceIndex > c.Tunnels[1].InterfaceIndex {
			c.Tunnels[0], c.Tunnels[1] = c.Tunnels[1], c.Tunnels[0]
		}
		c.PermittedInterfaceIndices, ok = guardIndices(c.PermittedInterfaceIndices, 2)
		if !ok {
			return GuardIntent{}, false
		}
		for _, index := range c.PermittedInterfaceIndices {
			if !own[index] {
				return GuardIntent{}, false
			}
		}
		c.ReplyIngressIndices, ok = guardIndices(c.ReplyIngressIndices, 2)
		if !ok {
			return GuardIntent{}, false
		}
		for _, index := range c.ReplyIngressIndices {
			if !own[index] {
				return GuardIntent{}, false
			}
		}
		if len(c.EncryptedEgress) > 2 {
			return GuardIntent{}, false
		}
		c.EncryptedEgress = append([]GuardEncryptedEgress(nil), c.EncryptedEgress...)
		seenTunnels := map[int]bool{}
		for _, e := range c.EncryptedEgress {
			permitted := false
			for _, index := range c.PermittedInterfaceIndices {
				if index == e.TunnelInterfaceIndex {
					permitted = true
				}
			}
			if !permitted || seenTunnels[e.TunnelInterfaceIndex] || e.ReqID == 0 || reqids[e.ReqID] || !e.Peer.Is4() || e.Peer.IsUnspecified() || e.Peer.IsMulticast() || e.UnderlayInterfaceIndex <= 0 || int64(e.UnderlayInterfaceIndex) > 2147483647 {
				return GuardIntent{}, false
			}
			seenTunnels[e.TunnelInterfaceIndex] = true
			reqids[e.ReqID] = true
		}
		sort.Slice(c.EncryptedEgress, func(a, b int) bool { return c.EncryptedEgress[a].ReqID < c.EncryptedEgress[b].ReqID })
		c.PermitFor = (c.PermitFor / time.Second) * time.Second
		if c.PermitFor == 0 {
			c.PermittedInterfaceIndices = nil
			c.ReplyIngressIndices = nil
			c.EncryptedEgress = nil
		}
		c.LocalIngressIndices, ok = guardIndices(c.LocalIngressIndices, 16)
		if !ok {
			return GuardIntent{}, false
		}
		c.Grants = append([]GuardGrant(nil), c.Grants...)
		seen := map[GuardGrant]bool{}
		for _, g := range c.Grants {
			outbound := withinPrefixes(g.Source, c.Local) && withinPrefixes(g.Destination, c.Remote)
			inbound := withinPrefixes(g.Source, c.Remote) && withinPrefixes(g.Destination, c.Local)
			if g.FQDNManaged || seen[g] || !validGuardPrefix(g.Source) || !validGuardPrefix(g.Destination) || (!outbound && !inbound) || (g.HostOrigin && !outbound) || (!g.HostOrigin && len(c.LocalIngressIndices) == 0) {
				return GuardIntent{}, false
			}
			switch g.Protocol {
			case GuardAny:
				if g.PortLow != 0 || g.PortHigh != 0 {
					return GuardIntent{}, false
				}
			case GuardTCP, GuardUDP:
				if g.PortLow == 0 || g.PortHigh < g.PortLow {
					return GuardIntent{}, false
				}
			default:
				return GuardIntent{}, false
			}
			seen[g] = true
		}
		sort.Slice(c.Grants, func(a, b int) bool {
			aa, _ := json.Marshal(c.Grants[a])
			bb, _ := json.Marshal(c.Grants[b])
			return string(aa) < string(bb)
		})
		out.Connections[i] = c
	}
	for _, c := range out.Connections {
		for _, e := range c.EncryptedEgress {
			for _, prefix := range append(append([]netip.Prefix(nil), allLocal...), allRemote...) {
				if prefix.Contains(e.Peer) {
					return GuardIntent{}, false
				}
			}
			if indices[e.UnderlayInterfaceIndex] {
				return GuardIntent{}, false
			}
		}
		for _, index := range c.LocalIngressIndices {
			if indices[index] {
				return GuardIntent{}, false
			}
		}
	}
	for i, p := range allRemote {
		for _, q := range allLocal {
			if p.Overlaps(q) {
				return GuardIntent{}, false
			}
		}
		for j := 0; j < i; j++ {
			if p.Overlaps(allRemote[j]) {
				return GuardIntent{}, false
			}
		}
	}
	sort.Slice(out.Connections, func(i, j int) bool { return out.Connections[i].ID.String() < out.Connections[j].ID.String() })
	return out, true
}
func validGuardPrefix(p netip.Prefix) bool { return p.IsValid() && p.Addr().Is4() && p == p.Masked() }
func guardPrefixes(in []netip.Prefix) ([]netip.Prefix, bool) {
	if len(in) == 0 || len(in) > 64 {
		return nil, false
	}
	out := append([]netip.Prefix(nil), in...)
	for i, p := range out {
		if !validGuardPrefix(p) {
			return nil, false
		}
		for j := 0; j < i; j++ {
			if p.Overlaps(out[j]) {
				return nil, false
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, true
}
func withinPrefixes(p netip.Prefix, set []netip.Prefix) bool {
	if !validGuardPrefix(p) {
		return false
	}
	for _, outer := range set {
		if outer.Contains(p.Addr()) && outer.Bits() <= p.Bits() {
			return true
		}
	}
	return false
}
func guardIndices(in []int, limit int) ([]int, bool) {
	if len(in) > limit {
		return nil, false
	}
	out := append([]int(nil), in...)
	sort.Ints(out)
	for i, n := range out {
		if n <= 0 || int64(n) > 2147483647 || i > 0 && out[i-1] == n {
			return nil, false
		}
	}
	return out, true
}

// Rules retain their typed expression AST alongside text; no command text is parsed
// back into authority, and expected readback is not inferred from a marker.
type guardRule struct {
	text string
	expr []any
}
type guardChain struct {
	strings.Builder
	rules []guardRule
}

func (c *guardChain) add(r guardRule) { c.WriteString(r.text); c.rules = append(c.rules, r) }
func guardMeta(key string) any        { return map[string]any{"meta": map[string]any{"key": key}} }
func guardCT(key string) any          { return map[string]any{"ct": map[string]any{"key": key}} }
func guardPayload(protocol, field string) any {
	return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
}
func guardPrefixJSON(p netip.Prefix) any {
	return map[string]any{"prefix": map[string]any{"addr": p.Addr().String(), "len": p.Bits()}}
}
func guardMatch(op string, left, right any) any {
	return map[string]any{"match": map[string]any{"op": op, "left": left, "right": right}}
}
func guardCounter() any         { return map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}} }
func guardVerdict(v string) any { return map[string]any{v: nil} }
func guardPrefixDrop(field string, p netip.Prefix) guardRule {
	return guardRule{text: fmt.Sprintf("    ip %s %s counter drop\n", field, p), expr: []any{guardMatch("==", guardPayload("ip", field), guardPrefixJSON(p)), guardCounter(), guardVerdict("drop")}}
}
func guardInterfaceDrop(field string, index int) guardRule {
	return guardRule{text: fmt.Sprintf("    meta %s %d counter drop\n", field, index), expr: []any{guardMatch("==", guardMeta(field), index), guardCounter(), guardVerdict("drop")}}
}
func guardDocuments(intent GuardIntent, digest string, chains []guardChain) (string, string, error) {
	table := map[string]any{"family": "inet", "name": "tunnex_ipsec"}
	expected := []any{map[string]any{"table": table}}
	// Native nft add-chain leaves an existing chain comment unchanged. After
	// flushing owned rules, ensure the non-hook, unreferenced marker exists and
	// recreate it inside this same atomic transaction. Caller must establish
	// exclusive table ownership before submitting any replacement transaction.
	marker := map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": "owner"}
	transaction := []any{map[string]any{"add": map[string]any{"table": table}}, map[string]any{"flush": map[string]any{"table": table}}, map[string]any{"add": map[string]any{"chain": marker}}, map[string]any{"delete": map[string]any{"chain": marker}}}
	add := func(kind string, value any) {
		expected = append(expected, map[string]any{kind: value})
		transaction = append(transaction, map[string]any{"add": map[string]any{kind: value}})
	}
	for _, connection := range intent.Connections {
		saDescriptor := map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": guardSALeaseName(connection.ID), "type": map[string]any{"typeof": map[string]any{"ipsec": map[string]any{"dir": "out", "key": "reqid", "spnum": 0}}}, "flags": []string{"timeout"}, "timeout": 60}
		saReadback := map[string]any{}
		for key, value := range saDescriptor {
			saReadback[key] = value
		}
		var saElements []any
		for _, e := range connection.EncryptedEgress {
			saElements = append(saElements, map[string]any{"elem": map[string]any{"val": e.ReqID, "timeout": int64(connection.PermitFor / time.Second)}})
		}
		if len(saElements) > 0 {
			saReadback["elem"] = saElements
		}
		expected = append(expected, map[string]any{"set": saReadback})
		transaction = append(transaction, map[string]any{"add": map[string]any{"set": saDescriptor}}, map[string]any{"flush": map[string]any{"set": map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": guardSALeaseName(connection.ID)}}})
		if len(saElements) > 0 {
			transaction = append(transaction, map[string]any{"add": map[string]any{"element": map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": guardSALeaseName(connection.ID), "elem": saElements}}})
		}
		descriptor := map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": guardLeaseName(connection.ID), "type": "iface_index", "flags": []string{"timeout"}, "timeout": 60}
		readback := map[string]any{}
		for key, value := range descriptor {
			readback[key] = value
		}
		var elements []any
		for _, index := range connection.PermittedInterfaceIndices {
			elements = append(elements, map[string]any{"elem": map[string]any{"val": index, "timeout": int64(connection.PermitFor / time.Second)}})
		}
		if len(elements) > 0 {
			readback["elem"] = elements
		}
		expected = append(expected, map[string]any{"set": readback})
		transaction = append(transaction, map[string]any{"add": map[string]any{"set": descriptor}}, map[string]any{"flush": map[string]any{"set": map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": guardLeaseName(connection.ID)}}})
		if len(elements) > 0 {
			transaction = append(transaction, map[string]any{"add": map[string]any{"element": map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": guardLeaseName(connection.ID), "elem": elements}}})
		}
		{
			descriptor := map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": guardReplyLeaseName(connection.ID), "type": "iface_index", "flags": []string{"timeout"}, "timeout": 60}
			readback := map[string]any{}
			for key, value := range descriptor {
				readback[key] = value
			}
			var elements []any
			for _, index := range connection.ReplyIngressIndices {
				elements = append(elements, map[string]any{"elem": map[string]any{"val": index, "timeout": int64(connection.PermitFor / time.Second)}})
			}
			if len(elements) > 0 {
				readback["elem"] = elements
			}
			expected = append(expected, map[string]any{"set": readback})
			transaction = append(transaction, map[string]any{"add": map[string]any{"set": descriptor}}, map[string]any{"flush": map[string]any{"set": map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": guardReplyLeaseName(connection.ID)}}})
			if len(elements) > 0 {
				transaction = append(transaction, map[string]any{"add": map[string]any{"element": map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": guardReplyLeaseName(connection.ID), "elem": elements}}})
			}
		}
	}
	add("chain", map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": "owner", "comment": fmt.Sprintf("tunnex-ipsec:%s:%d:%s", intent.OwnerID, intent.Revision, digest)})
	hooks := []string{"forward", "output", "input", "postrouting", "postrouting"}
	for i, chain := range chains {
		hook := hooks[i]
		priority := -10
		if hook == "postrouting" {
			priority = 90
		}
		name := hook + "_guard"
		if i == 4 {
			name = "postnat_guard"
			priority = 300
		}
		add("chain", map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": name, "type": "filter", "hook": hook, "prio": priority, "policy": "accept"})
		for _, rule := range chain.rules {
			add("rule", map[string]any{"family": "inet", "table": "tunnex_ipsec", "chain": name, "expr": rule.expr})
		}
	}
	tx, err := json.Marshal(map[string]any{"nftables": transaction})
	if err != nil {
		return "", "", err
	}
	ex, err := json.Marshal(map[string]any{"nftables": expected})
	return string(tx), string(ex), err
}

func guardLeaseName(id uuid.UUID) string { return "lease_" + strings.ReplaceAll(id.String(), "-", "") }
func guardLeaseSetText(c GuardConnection) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  set %s {\n    type iface_index; flags timeout; timeout 60s;\n", guardLeaseName(c.ID))
	if len(c.PermittedInterfaceIndices) > 0 {
		parts := make([]string, len(c.PermittedInterfaceIndices))
		for i, index := range c.PermittedInterfaceIndices {
			parts[i] = fmt.Sprintf("%d timeout %ds", index, int64(c.PermitFor/time.Second))
		}
		fmt.Fprintf(&b, "    elements = { %s }\n", strings.Join(parts, ", "))
	}
	b.WriteString("  }\n")
	return b.String()
}

// guardNATDrop retains protection when translation rewrites a protected tuple
// away, or translates another tuple into an otherwise explicitly granted range.
func guardNATDrop(prefix netip.Prefix, field, status string, original bool) guardRule {
	selector := guardPayload("ip", field)
	textSelector := "ip " + field
	if original {
		selector = map[string]any{"ct": map[string]any{"key": "ip " + field, "dir": "original"}}
		textSelector = "ct original ip " + field
	}
	return guardRule{
		text: fmt.Sprintf("    %s %s ct status %s counter drop\n", textSelector, prefix, status),
		expr: []any{guardMatch("==", selector, guardPrefixJSON(prefix)), guardMatch("in", guardCT("status"), status), guardCounter(), guardVerdict("drop")},
	}
}

func guardSALeaseName(id uuid.UUID) string {
	return "sa_lease_" + strings.ReplaceAll(id.String(), "-", "")
}
func guardSALeaseText(c GuardConnection) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  set %s {\n    typeof ipsec out reqid; flags timeout; timeout 60s;\n", guardSALeaseName(c.ID))
	if len(c.EncryptedEgress) > 0 {
		parts := make([]string, len(c.EncryptedEgress))
		for i, e := range c.EncryptedEgress {
			parts[i] = fmt.Sprintf("%d timeout %ds", e.ReqID, int64(c.PermitFor/time.Second))
		}
		fmt.Fprintf(&b, "    elements = { %s }\n", strings.Join(parts, ", "))
	}
	b.WriteString("  }\n")
	return b.String()
}
func guardEncryptedAllow(prefix netip.Prefix, e GuardEncryptedEgress, set string) guardRule {
	reqid := map[string]any{"ipsec": map[string]any{"dir": "out", "key": "reqid", "spnum": 0}}
	peer := map[string]any{"ipsec": map[string]any{"dir": "out", "key": "daddr", "family": "ip", "spnum": 0}}
	return guardRule{text: fmt.Sprintf("    ip daddr %s meta oif %d ipsec out reqid %d ipsec out ip daddr %s ipsec out reqid @%s counter accept\n", prefix, e.UnderlayInterfaceIndex, e.ReqID, e.Peer, set), expr: []any{guardMatch("==", guardPayload("ip", "daddr"), guardPrefixJSON(prefix)), guardMatch("==", guardMeta("oif"), e.UnderlayInterfaceIndex), guardMatch("==", reqid, e.ReqID), guardMatch("==", peer, e.Peer.String()), guardMatch("==", reqid, "@"+set), guardCounter(), guardVerdict("accept")}}
}

func guardReplyLeaseName(id uuid.UUID) string { return "reply_" + guardLeaseName(id) }
func guardReplyLeaseSetText(c GuardConnection) string {
	c.PermittedInterfaceIndices = c.ReplyIngressIndices
	return strings.ReplaceAll(guardLeaseSetText(c), guardLeaseName(c.ID), guardReplyLeaseName(c.ID))
}

package egress

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/tunnexio/tunnex/apps/node/internal/flowlog"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// policyDenyComment marks an explicit deny from the compiled artifact (v16, AI-SEC-2).
const policyDenyComment = "tunnex_policy_deny"

// renderDenies renders the artifact's explicit denies for the ip and ip6 tables. The lines go ahead of the
// blanket mesh accepts and ahead of the compiled allows, so they hold in both modes and whatever an allow
// says.
//
// Each entry becomes two drops in its one address family:
//
//   - on the destination the device DIALED (`ct original`), the tuple the allows and the conntrack flush
//     key on, so a destination that is DNATed on the way is still closed;
//   - on the destination the packet is GOING to, so another address that is DNATed to the denied server is
//     closed as well.
//
// Off a DNAT path the two are the same packet set.
//
// ok=false means an entry could not be rendered exactly. An allow that cannot be rendered is skipped and
// the default drop closes it; a deny that is skipped leaves the path it names OPEN. So nothing is rendered
// and the caller must deny everything. Every field is re-emitted through netip or as an integer: this is
// root ruleset text and never carries a control-plane string.
func renderDenies(denies []nodepolicy.DenyEntry, flowLogGroup int) (v4, v6 string, ok bool) {
	var b4, b6 strings.Builder
	for _, e := range denies {
		lines, isV6, ok := renderDeny(e, flowLogGroup)
		if !ok {
			return "", "", false
		}
		if isV6 {
			b6.WriteString(lines)
		} else {
			b4.WriteString(lines)
		}
	}
	return b4.String(), b6.String(), true
}

func renderDeny(e nodepolicy.DenyEntry, flowLogGroup int) (lines string, v6, ok bool) {
	src, ok := denySource(e.SrcIP)
	if !ok {
		return "", false, false
	}
	dst, err := netip.ParsePrefix(e.DstCIDR)
	if err != nil || dst.Addr().Is4In6() || dst.Addr().Is6() != src.Addr().Is6() {
		return "", false, false
	}
	v6 = src.Addr().Is6()
	family := "ip"
	if v6 {
		family = "ip6"
	}
	srcText := src.Masked().String()
	if src.IsSingleIP() {
		srcText = src.Addr().String()
	}
	dialed, arriving := "", ""
	switch e.Protocol {
	case "any":
		if e.PortLow != 0 || e.PortHigh != 0 {
			return "", false, false
		}
	case "tcp", "udp":
		switch {
		case e.PortLow == 0 && e.PortHigh == 0:
			dialed = " meta l4proto " + e.Protocol
			arriving = dialed
		case e.PortLow >= 1 && e.PortHigh >= e.PortLow && e.PortHigh <= 65535:
			ports := fmt.Sprintf("%d", e.PortLow)
			if e.PortHigh > e.PortLow {
				ports = fmt.Sprintf("%d-%d", e.PortLow, e.PortHigh)
			}
			dialed = fmt.Sprintf(" meta l4proto %s ct original proto-dst %s", e.Protocol, ports)
			arriving = fmt.Sprintf(" %s dport %s", e.Protocol, ports)
		default:
			return "", false, false
		}
	default:
		return "", false, false
	}
	verdict := denyLogClause(flowLogGroup) + " counter drop comment \"" + policyDenyComment + "\"\n"
	dstText := dst.Masked().String()
	lines = fmt.Sprintf("    %[1]s saddr %[2]s ct original %[1]s daddr %[3]s%[4]s%[5]s", family, srcText, dstText, dialed, verdict) +
		fmt.Sprintf("    %[1]s saddr %[2]s %[1]s daddr %[3]s%[4]s%[5]s", family, srcText, dstText, arriving, verdict)
	return lines, v6, true
}

// denySource accepts a bare device address or a CIDR, as the allows do.
func denySource(raw string) (netip.Prefix, bool) {
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Addr().Is4In6() {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(raw)
	if err != nil || a.Is4In6() || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// denyLogClause is the non-terminal flow-log statement of a deny line: the deny sentinel, as the default
// drop logs. Empty when flow logging is off.
func denyLogClause(group int) string {
	if group <= 0 {
		return ""
	}
	return fmt.Sprintf(" log prefix %q group %d", flowlog.EncodePrefix(""), group)
}

// addedDenies returns the denies in current whose match tuple was not in old: the ones whose
// already-established flows must be cut, because `ct state established accept` runs ahead of every deny.
func addedDenies(old, current []nodepolicy.DenyEntry) []nodepolicy.DenyEntry {
	had := make(map[string]bool, len(old))
	for _, e := range old {
		had[denyKey(e)] = true
	}
	var out []nodepolicy.DenyEntry
	for _, e := range current {
		if !had[denyKey(e)] {
			out = append(out, e)
		}
	}
	return out
}

// denyKey is the match tuple of a deny. Reason and SrcDeviceID are metadata and not part of it.
func denyKey(e nodepolicy.DenyEntry) string {
	return fmt.Sprintf("%s|%s|%s|%d|%d", e.SrcIP, e.DstCIDR, e.Protocol, e.PortLow, e.PortHigh)
}

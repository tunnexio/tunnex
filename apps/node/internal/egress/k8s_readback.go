package egress

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const k8sVIPCommentPrefix = "tunnex_k8s_vip:"

var (
	k8sVIPReceiptRE   = regexp.MustCompile(` comment "` + k8sVIPCommentPrefix + `([0-9a-f]{64})"`)
	k8sSingleDNATRE   = regexp.MustCompile(`^ip daddr (\S+) (tcp|udp) dport ([0-9]+) dnat to (\S+):([0-9]+)$`)
	k8sBalancedDNATRE = regexp.MustCompile(`^ip daddr (\S+) (tcp|udp) dport ([0-9]+) dnat to jhash ip saddr \. ip daddr mod ([0-9]+) map \{ (.+) \}$`)
	k8sMapTargetRE    = regexp.MustCompile(`^([0-9]+) : (\S+) \. ([0-9]+)$`)
)

// K8sDNATReceipt is a kernel-verifiable proof that nft accepted one exact
// rendered VIP->ready-endpoint rule. Digest binds the complete rule before its
// comment, including protocol, service port, target IPs, target ports, and load
// balancing expression.
type K8sDNATReceipt struct {
	VIP    string
	Digest string
}

func dnatReceipt(vip, rule string) K8sDNATReceipt {
	sum := sha256.Sum256([]byte(rule))
	return K8sDNATReceipt{VIP: vip, Digest: hex.EncodeToString(sum[:])}
}

func attachDNATReceipt(vip, rule string) string {
	receipt := dnatReceipt(vip, rule)
	return fmt.Sprintf(`%s comment "%s%s"`, rule, k8sVIPCommentPrefix, receipt.Digest)
}

func parseK8sDNATReceipts(listing string) ([]string, error) {
	seen := map[string]struct{}{}
	for _, raw := range strings.Split(listing, "\n") {
		line := strings.TrimSpace(raw)
		match := k8sVIPReceiptRE.FindStringSubmatchIndex(line)
		if match == nil {
			continue
		}
		rule := strings.TrimSpace(line[:match[0]])
		digest := line[match[2]:match[3]]
		trailer := strings.TrimSpace(line[match[1]:])
		if trailer != "" && !strings.HasPrefix(trailer, "# handle ") {
			return nil, fmt.Errorf("unexpected Kubernetes DNAT rule trailer %q", trailer)
		}
		if err := validateK8sDNATRule(rule); err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(rule))
		actualDigest := hex.EncodeToString(sum[:])
		if actualDigest != digest {
			return nil, fmt.Errorf("Kubernetes DNAT receipt digest mismatch: comment=%s actual=%s", digest, actualDigest)
		}
		if _, duplicate := seen[digest]; duplicate {
			return nil, fmt.Errorf("duplicate Kubernetes DNAT receipt %s", digest)
		}
		seen[digest] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for digest := range seen {
		out = append(out, digest)
	}
	sort.Strings(out)
	return out, nil
}

// validateK8sDNATRule accepts only the two rule shapes emitted by dnatRule.
// The comment is merely a locator: readback proves the live rule's protocol,
// ports, VIP and every DNAT target before accepting its recomputed digest.
func validateK8sDNATRule(rule string) error {
	if match := k8sSingleDNATRE.FindStringSubmatch(rule); match != nil {
		if err := validateIPv4AndPort(match[1], match[3]); err != nil {
			return fmt.Errorf("invalid Kubernetes DNAT match: %w", err)
		}
		if err := validateIPv4AndPort(match[4], match[5]); err != nil {
			return fmt.Errorf("invalid Kubernetes DNAT target: %w", err)
		}
		return nil
	}
	match := k8sBalancedDNATRE.FindStringSubmatch(rule)
	if match == nil {
		return fmt.Errorf("unrecognized Kubernetes DNAT rule semantics %q", rule)
	}
	if err := validateIPv4AndPort(match[1], match[3]); err != nil {
		return fmt.Errorf("invalid Kubernetes DNAT match: %w", err)
	}
	count, err := strconv.Atoi(match[4])
	if err != nil || count < 2 {
		return fmt.Errorf("invalid Kubernetes DNAT target count %q", match[4])
	}
	parts := strings.Split(match[5], ", ")
	if len(parts) != count {
		return fmt.Errorf("Kubernetes DNAT map has %d targets, want %d", len(parts), count)
	}
	for index, part := range parts {
		target := k8sMapTargetRE.FindStringSubmatch(part)
		if target == nil || target[1] != strconv.Itoa(index) {
			return fmt.Errorf("invalid Kubernetes DNAT map entry %q", part)
		}
		if err := validateIPv4AndPort(target[2], target[3]); err != nil {
			return fmt.Errorf("invalid Kubernetes DNAT map target: %w", err)
		}
	}
	return nil
}

func validateIPv4AndPort(rawIP, rawPort string) error {
	addr, err := netip.ParseAddr(rawIP)
	if err != nil || !addr.Is4() || addr.String() != rawIP {
		return fmt.Errorf("invalid canonical IPv4 address %q", rawIP)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != rawPort {
		return fmt.Errorf("invalid canonical port %q", rawPort)
	}
	return nil
}

// parseInterfaceIPv4s parses `ip -o -4 addr show dev <iface>`. It returns only
// successfully enumerated canonical addresses; malformed lines fail the whole
// readback instead of turning uncertainty into absence.
func parseInterfaceIPv4s(output string) ([]string, error) {
	seen := map[string]struct{}{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		inet := -1
		for i, field := range fields {
			if field == "inet" {
				inet = i
				break
			}
		}
		if inet < 0 || inet+1 >= len(fields) {
			return nil, fmt.Errorf("malformed IPv4 address listing line %q", line)
		}
		prefix, err := netip.ParsePrefix(fields[inet+1])
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("malformed IPv4 address listing prefix %q", fields[inet+1])
		}
		seen[prefix.Addr().String()] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for addr := range seen {
		out = append(out, addr)
	}
	sort.Strings(out)
	return out, nil
}

func observedCandidates(observed, candidates []string) ([]string, error) {
	seenObserved := map[string]struct{}{}
	for _, raw := range observed {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is4() || addr.String() != raw {
			return nil, fmt.Errorf("invalid observed IPv4 address %q", raw)
		}
		seenObserved[raw] = struct{}{}
	}
	want := map[string]struct{}{}
	for _, raw := range candidates {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is4() || addr.String() != raw {
			return nil, fmt.Errorf("invalid candidate IPv4 address %q", raw)
		}
		want[raw] = struct{}{}
	}
	out := make([]string, 0, len(want))
	for raw := range want {
		if _, exists := seenObserved[raw]; exists {
			out = append(out, raw)
		}
	}
	sort.Strings(out)
	return out, nil
}

// parseOwnedDNSVIPs enumerates both the durable label used by current agents
// and the legacy shape current agents previously wrote: a secondary IPv4 /32
// on the dedicated Tunnex WireGuard interface. Primary/non-/32 addresses and
// every address on other interfaces remain foreign.
func parseOwnedDNSVIPs(output, iface string, candidates []string) ([]string, error) {
	want := map[string]struct{}{}
	for _, raw := range candidates {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is4() || addr.String() != raw {
			return nil, fmt.Errorf("invalid candidate IPv4 address %q", raw)
		}
		want[raw] = struct{}{}
	}
	marker := iface + ":tnxk8s"
	owned := map[string]struct{}{}
	for _, raw := range strings.Split(strings.TrimSpace(output), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		inet := -1
		for i, field := range fields {
			if field == "inet" {
				inet = i
				break
			}
		}
		if inet < 0 || inet+1 >= len(fields) {
			return nil, fmt.Errorf("malformed IPv4 address listing line %q", raw)
		}
		prefix, err := netip.ParsePrefix(fields[inet+1])
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("malformed IPv4 address listing prefix %q", fields[inet+1])
		}
		address := prefix.Addr().String()
		secondary, labelled := false, false
		for _, field := range fields[inet+2:] {
			secondary = secondary || field == "secondary"
			labelled = labelled || field == marker
		}
		_, explicit := want[address]
		if labelled || explicit || (prefix.Bits() == 32 && secondary) {
			owned[address] = struct{}{}
		}
	}
	out := make([]string, 0, len(owned))
	for address := range owned {
		out = append(out, address)
	}
	sort.Strings(out)
	return out, nil
}

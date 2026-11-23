package k8snetprep

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// K8N-2: Cilium can masquerade in eBPF, where there is no NAT rule for the
// observed walk to read. What the node can show instead is (1) what the agent
// itself reports about masquerading, from GET /v1/healthz on its local
// socket, and (2) the live content of its ip-masq-agent map. This file holds
// only the pure reading and deciding. Nothing here writes, and nothing here
// talks to the agent or the kernel; see docs/K8N-2-cilium.md for the wiring.

// CiliumAdapterName is the adapter reported when a Cilium agent runs on the
// node and its own masquerading was proved unable to rewrite traffic bound
// for the tunnel range.
const CiliumAdapterName = "cilium_masquerade"

const (
	// ReasonCiliumMasqueradeOff is carried when the agent reports that it
	// does not masquerade IPv4 at all.
	ReasonCiliumMasqueradeOff = "Cilium does not masquerade IPv4 traffic"
	// ReasonCiliumIPTablesMasquerade is carried when the agent masquerades
	// with iptables rules. Those rules are then the NAT rule walk's to prove;
	// this reason alone never makes a node ready.
	ReasonCiliumIPTablesMasquerade = "Cilium masquerades with iptables rules; the NAT rule walk decides"
)

const (
	maxCiliumStatusBytes  = 4 << 20
	maxCiliumMapDumpBytes = 4 << 20
	// The ip-masq-agent map holds at most this many entries (Cilium's
	// MaxEntriesIPv4), so a longer listing is not that map.
	maxCiliumNonMasqueradeCIDRs = 16384
	// struct { u32 prefixlen; u8 addr[4] } and struct { u8 pad }.
	ciliumIPMasqKeyBytes   = 8
	ciliumIPMasqValueBytes = 1
)

type ciliumMasqMode string

const (
	ciliumMasqOff      ciliumMasqMode = "off"
	ciliumMasqIPTables ciliumMasqMode = "iptables"
	ciliumMasqBPF      ciliumMasqMode = "bpf"
)

// ciliumMasquerade is what a Cilium agent reports about IPv4 masquerading.
// The zero value is not a valid report and proves nothing.
type ciliumMasquerade struct {
	Mode ciliumMasqMode
	// Exclusion is the destination range the agent never masquerades to
	// (ipv4-native-routing-cidr when set, otherwise the node's pod range).
	// It is valid whenever Mode is not off.
	Exclusion netip.Prefix
	// IPMasqAgent says the eBPF ip-masq-agent is compiled into the datapath,
	// so the ip-masq-agent map is consulted. Only possible in eBPF mode.
	IPMasqAgent bool
}

// ciliumMasqueradingModel is the `masquerading` object of the agent's status
// (api/v1 model Masquerading). Every field is optional on the wire because the
// agent omits false and empty values.
type ciliumMasqueradingModel struct {
	Enabled   *bool `json:"enabled"`
	Protocols *struct {
		IPv4 *bool `json:"ipv4"`
		IPv6 *bool `json:"ipv6"`
	} `json:"enabledProtocols"`
	Mode        *string `json:"mode"`
	IPMasqAgent *bool   `json:"ip-masq-agent"`
	Legacy      *string `json:"snat-exclusion-cidr"`
	V4          *string `json:"snat-exclusion-cidr-v4"`
	V6          *string `json:"snat-exclusion-cidr-v6"`
}

// parseCiliumStatus reads the agent's status document and returns what it says
// about IPv4 masquerading. Other sections of the status are ignored; inside the
// masquerading section every field must be one this code knows, and the fields
// must agree with each other. A missing, stale, inconsistent or newer-shaped
// section is an error, never "masquerading is off".
func parseCiliumStatus(raw []byte) (ciliumMasquerade, error) {
	if len(raw) > maxCiliumStatusBytes {
		return ciliumMasquerade{}, errors.New("Cilium status exceeds bound")
	}
	var top map[string]json.RawMessage
	if err := ciliumDecodeJSON(raw, &top, false); err != nil || top == nil {
		return ciliumMasquerade{}, errors.New("Cilium status is not a JSON object")
	}
	if staleRaw, ok := top["stale"]; ok {
		var stale map[string]json.RawMessage
		if err := ciliumDecodeJSON(staleRaw, &stale, false); err != nil {
			return ciliumMasquerade{}, errors.New("Cilium status has a stale list that is not understood")
		}
		if _, isStale := stale["masquerading"]; isStale {
			return ciliumMasquerade{}, errors.New("Cilium masquerading status is stale")
		}
	}
	body, ok := top["masquerading"]
	if !ok {
		return ciliumMasquerade{}, errors.New("Cilium status has no masquerading section")
	}
	var model ciliumMasqueradingModel
	if err := ciliumDecodeJSON(body, &model, true); err != nil {
		return ciliumMasquerade{}, errors.New("Cilium masquerading status is not understood")
	}
	if model.Protocols == nil {
		return ciliumMasquerade{}, errors.New("Cilium masquerading status has no per-protocol state")
	}
	enabled, agent := ciliumBool(model.Enabled), ciliumBool(model.IPMasqAgent)
	ipv4, ipv6 := ciliumBool(model.Protocols.IPv4), ciliumBool(model.Protocols.IPv6)
	mode := ""
	if model.Mode != nil {
		mode = *model.Mode
	}
	inconsistent := errors.New("Cilium masquerading status is inconsistent")
	if !enabled {
		// A disabled agent reports nothing else. Anything more is a shape this
		// code has not seen, not a second way of saying "off".
		if ipv4 || ipv6 || agent || mode != "" || model.Legacy != nil || model.V4 != nil || model.V6 != nil {
			return ciliumMasquerade{}, inconsistent
		}
		return ciliumMasquerade{Mode: ciliumMasqOff}, nil
	}
	if !ipv4 && !ipv6 {
		return ciliumMasquerade{}, inconsistent
	}
	out := ciliumMasquerade{IPMasqAgent: agent}
	switch mode {
	case "BPF":
		out.Mode = ciliumMasqBPF
	case "iptables":
		out.Mode = ciliumMasqIPTables
	default:
		return ciliumMasquerade{}, errors.New("Cilium masquerading mode is not understood")
	}
	if agent && out.Mode != ciliumMasqBPF {
		return ciliumMasquerade{}, inconsistent
	}
	if !ipv4 {
		// Masquerading is on for IPv6 only. The tunnel range is IPv4.
		return ciliumMasquerade{Mode: ciliumMasqOff}, nil
	}
	if model.V4 == nil {
		return ciliumMasquerade{}, errors.New("Cilium masquerading status has no IPv4 exclusion range")
	}
	exclusion, err := netip.ParsePrefix(*model.V4)
	if err != nil || !exclusion.Addr().Is4() {
		return ciliumMasquerade{}, errors.New("Cilium IPv4 exclusion range is not understood")
	}
	if model.Legacy != nil && *model.Legacy != *model.V4 {
		return ciliumMasquerade{}, inconsistent
	}
	out.Exclusion = exclusion.Masked()
	return out, nil
}

func ciliumBool(value *bool) bool { return value != nil && *value }

// ciliumDecodeJSON decodes exactly one JSON value and rejects trailing data.
func ciliumDecodeJSON(raw []byte, into any, strict bool) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(into); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// parseBPFToolMapDump reads `bpftool --json map dump pinned PATH` and returns
// each entry's raw key. bpftool prints a key and a value as arrays of "0xNN"
// strings, and adds a "formatted" member when the map carries type
// information; the raw bytes are what is read here. An entry of another shape
// or size, a lookup error in place of a value, or more than maxEntries entries
// is an error. An empty array is a valid, empty map.
func parseBPFToolMapDump(raw []byte, keyBytes, valueBytes, maxEntries int) ([][]byte, error) {
	if len(raw) > maxCiliumMapDumpBytes {
		return nil, errors.New("BPF map dump exceeds bound")
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, errors.New("BPF map dump is not a JSON array")
	}
	var entries []map[string]json.RawMessage
	if err := ciliumDecodeJSON(raw, &entries, false); err != nil {
		return nil, errors.New("BPF map dump is not understood")
	}
	if len(entries) > maxEntries {
		return nil, errors.New("BPF map dump has too many entries")
	}
	keys := make([][]byte, 0, len(entries))
	for _, entry := range entries {
		if entry == nil {
			return nil, errors.New("BPF map dump has an entry that is not understood")
		}
		for name := range entry {
			if name != "key" && name != "value" && name != "formatted" {
				return nil, errors.New("BPF map dump has an entry that is not understood")
			}
		}
		key, err := ciliumHexBytes(entry["key"], keyBytes)
		if err != nil {
			return nil, errors.New("BPF map dump has a key that is not understood")
		}
		if _, err := ciliumHexBytes(entry["value"], valueBytes); err != nil {
			return nil, errors.New("BPF map dump has a value that is not understood")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func ciliumHexBytes(raw json.RawMessage, want int) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("missing")
	}
	var parts []string
	if err := ciliumDecodeJSON(raw, &parts, false); err != nil || len(parts) != want {
		return nil, errors.New("wrong shape")
	}
	out := make([]byte, want)
	for i, part := range parts {
		if len(part) != 4 || !strings.HasPrefix(part, "0x") {
			return nil, errors.New("not a byte")
		}
		value, err := strconv.ParseUint(part[2:], 16, 8)
		if err != nil {
			return nil, errors.New("not a byte")
		}
		out[i] = byte(value)
	}
	return out, nil
}

// decodeCiliumIPMasqKeys turns the raw keys of Cilium's cilium_ipmasq_v4 map
// (an LPM trie keyed by a 32-bit prefix length in host byte order, then the
// IPv4 address) into the ranges Cilium does not masquerade to. Host byte order
// is little-endian on every architecture the gateway image is built for; a key
// from a big-endian host reads as a prefix length above 32 and is refused.
func decodeCiliumIPMasqKeys(keys [][]byte) ([]netip.Prefix, error) {
	if len(keys) > maxCiliumNonMasqueradeCIDRs {
		return nil, errors.New("Cilium ip-masq-agent map has too many entries")
	}
	out := make([]netip.Prefix, 0, len(keys))
	for _, key := range keys {
		if len(key) != ciliumIPMasqKeyBytes {
			return nil, errors.New("Cilium ip-masq-agent map has a key of the wrong size")
		}
		bits := binary.LittleEndian.Uint32(key[:4])
		if bits > 32 {
			return nil, errors.New("Cilium ip-masq-agent map has a prefix length that is not understood")
		}
		addr := netip.AddrFrom4([4]byte{key[4], key[5], key[6], key[7]})
		// An LPM trie compares only the first `bits` bits of the key.
		out = append(out, netip.PrefixFrom(addr, int(bits)).Masked())
	}
	return out, nil
}

// parseCiliumIPMasqDump reads a bpftool JSON dump of cilium_ipmasq_v4.
func parseCiliumIPMasqDump(raw []byte) ([]netip.Prefix, error) {
	keys, err := parseBPFToolMapDump(raw, ciliumIPMasqKeyBytes, ciliumIPMasqValueBytes, maxCiliumNonMasqueradeCIDRs)
	if err != nil {
		return nil, err
	}
	return decodeCiliumIPMasqKeys(keys)
}

// ciliumPresent reports whether the node shows any trace of a Cilium agent:
// one of its network devices, one of its NAT chains, or one of its pinned
// maps. When it does, the NAT rule walk alone proves nothing about eBPF and
// the Cilium proof below is required as well. The inputs are names only.
func ciliumPresent(links, natChains, pinnedMaps []string) bool {
	for _, name := range links {
		if strings.HasPrefix(name, "cilium_") {
			return true
		}
	}
	for _, name := range natChains {
		if strings.HasPrefix(name, "CILIUM_") {
			return true
		}
	}
	for _, name := range pinnedMaps {
		if strings.HasPrefix(name, "cilium_") {
			return true
		}
	}
	return false
}

// ciliumEgressGatewayPinned reports whether an IPv4 egress-gateway policy map
// is pinned. Cilium creates it only when the egress gateway is enabled.
func ciliumEgressGatewayPinned(pinnedMaps []string) bool {
	for _, name := range pinnedMaps {
		if strings.HasPrefix(name, "cilium_egress_gw_policy_v4") {
			return true
		}
	}
	return false
}

// ciliumObservation is everything read from one Cilium node for one proof.
type ciliumObservation struct {
	Masquerade ciliumMasquerade
	// NonMasquerade is the live content of the ip-masq-agent map, and
	// NonMasqueradeRead says it was read. An unread map is not an empty one.
	NonMasquerade     []netip.Prefix
	NonMasqueradeRead bool
	// EgressGateway says an egress-gateway policy map exists on the node.
	EgressGateway bool
}

// proveCiliumNoTunnelMasquerade returns a reason only when Cilium's own
// masquerading cannot rewrite the source of a packet bound for tunnel:
//
//   - the agent does not masquerade IPv4; or
//   - it masquerades with iptables rules (the caller's NAT rule walk must then
//     pass on its own; this function does not replace it); or
//   - it masquerades in eBPF and tunnel lies wholly inside a destination range
//     the agent reports it never masquerades to: its native-routing range, or,
//     with the ip-masq-agent enabled, one entry of the live map.
//
// In eBPF mode an egress-gateway policy is applied before either exclusion, so
// a node with the egress gateway enabled is refused. A range covered only by
// several entries together is refused too: one entry must contain it.
func proveCiliumNoTunnelMasquerade(obs ciliumObservation, tunnel netip.Prefix) (string, error) {
	if !tunnel.IsValid() || !tunnel.Addr().Is4() {
		return "", errors.New("invalid IPv4 tunnel range")
	}
	tunnel = tunnel.Masked()
	masq := obs.Masquerade
	switch masq.Mode {
	case ciliumMasqOff:
		if masq.IPMasqAgent || masq.Exclusion.IsValid() {
			return "", errors.New("Cilium masquerading report is inconsistent")
		}
		return ReasonCiliumMasqueradeOff, nil
	case ciliumMasqIPTables:
		if masq.IPMasqAgent {
			return "", errors.New("Cilium masquerading report is inconsistent")
		}
		return ReasonCiliumIPTablesMasquerade, nil
	case ciliumMasqBPF:
	default:
		return "", errors.New("Cilium masquerading mode is not understood")
	}
	if !masq.Exclusion.IsValid() || !masq.Exclusion.Addr().Is4() {
		return "", errors.New("Cilium IPv4 exclusion range is not understood")
	}
	if obs.EgressGateway {
		return "", errCiliumEgressGateway
	}
	exclusion := masq.Exclusion.Masked()
	if ciliumPrefixCovers(exclusion, tunnel) {
		return bounded(fmt.Sprintf("tunnel range is inside Cilium's native-routing range %s", exclusion), maxReasonBytes), nil
	}
	if !masq.IPMasqAgent {
		return "", &ciliumTunnelNotExcludedError{Tunnel: tunnel, Exclusion: exclusion}
	}
	if !obs.NonMasqueradeRead {
		return "", errors.New("Cilium ip-masq-agent is enabled but its map was not read")
	}
	if len(obs.NonMasquerade) > maxCiliumNonMasqueradeCIDRs {
		return "", errors.New("Cilium ip-masq-agent map has too many entries")
	}
	var widest netip.Prefix
	for _, member := range obs.NonMasquerade {
		if !member.IsValid() || !member.Addr().Is4() {
			return "", errors.New("Cilium ip-masq-agent map has an entry that is not understood")
		}
		member = member.Masked()
		if ciliumPrefixCovers(member, tunnel) && (!widest.IsValid() || member.Bits() < widest.Bits()) {
			widest = member
		}
	}
	if !widest.IsValid() {
		return "", &ciliumTunnelNotExcludedError{Tunnel: tunnel, Exclusion: exclusion, IPMasqAgent: true}
	}
	return bounded(fmt.Sprintf("tunnel range is inside Cilium ip-masq-agent range %s", widest), maxReasonBytes), nil
}

// errCiliumEgressGateway refuses a node whose agent runs the egress gateway.
var errCiliumEgressGateway = errors.New("Cilium egress gateway is enabled; its policies are applied before any masquerade exclusion and are not read")

// ciliumTunnelNotExcludedError is the one refusal the customer can lift: the
// agent masquerades in eBPF and the tunnel range is in no range it excludes.
// Everything else the proof refuses is something this code could not read or
// does not understand.
type ciliumTunnelNotExcludedError struct {
	Tunnel    netip.Prefix
	Exclusion netip.Prefix
	// IPMasqAgent says the ip-masq-agent is on, so one more entry in its list
	// is enough; otherwise the feature has to be enabled first.
	IPMasqAgent bool
}

func (e *ciliumTunnelNotExcludedError) Error() string {
	if e.IPMasqAgent {
		return fmt.Sprintf("Cilium eBPF masquerade can rewrite traffic to the tunnel range %s: no ip-masq-agent nonMasqueradeCIDRs entry contains it", e.Tunnel)
	}
	return fmt.Sprintf("Cilium eBPF masquerade can rewrite traffic to the tunnel range %s: it is outside the native-routing range %s and ip-masq-agent is off", e.Tunnel, e.Exclusion)
}

// ciliumPrefixCovers reports whether every address of inner is inside outer. Both
// must already be in masked form.
func ciliumPrefixCovers(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

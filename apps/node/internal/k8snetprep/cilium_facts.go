package k8snetprep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// K8N-2, the reader's side of the proof. The gateway container has no path to
// Cilium's agent socket or to its pinned maps, and is given none. The
// privileged host-posture manager reads them and publishes what it read as the
// `cilium` section of its host-facts receipt (K8N-1, Decision 9): facts, never
// a verdict. The gateway, which knows the tunnel range, decides with the
// parsers and the proof of cilium.go.

const (
	// MaxCiliumStatusFactBytes bounds the carried part of the agent's status.
	MaxCiliumStatusFactBytes = 8 << 10
	// MaxCiliumMapFactBytes bounds the carried dump of the ip-masq-agent map.
	// One entry prints as about 84 bytes, so this is about 390 ranges. A longer
	// list is published as unreadable, never cut.
	MaxCiliumMapFactBytes = 32 << 10

	maxCiliumEgressPins = 8
	// ciliumEgressGatewayPinPrefix is the exact prefix of the egress-gateway
	// policy maps. A shorter one would match cilium_egresscall_policy, which
	// every node pins.
	ciliumEgressGatewayPinPrefix = "cilium_egress_gw_policy_v4"
)

var ciliumPinNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// CiliumFacts is what the manager read on a node that shows Cilium.
type CiliumFacts struct {
	// Status is the agent's own account of its masquerading: the
	// `masquerading` member of GET /v1/healthz on its local socket and, when
	// the agent sent one, the `stale` member, as one JSON object.
	Status CiliumTextFact `json:"status"`
	// PinnedMaps is what was found under /sys/fs/bpf/tc/globals.
	PinnedMaps CiliumPinFacts `json:"pinned_maps"`
	// IPMasqMap is what `bpftool --json map dump pinned
	// /sys/fs/bpf/tc/globals/cilium_ipmasq_v4` printed. It is read only when
	// the status says the ip-masq-agent is on, and is not_needed otherwise.
	IPMasqMap CiliumTextFact `json:"ip_masq_map"`
}

// CiliumTextFact is one text that was read, or why it was not.
type CiliumTextFact struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	Text   string `json:"text,omitempty"`
}

// CiliumPinFacts carries how many maps are pinned and the names of those that
// are egress-gateway policy maps.
type CiliumPinFacts struct {
	State         string   `json:"state"`
	Reason        string   `json:"reason,omitempty"`
	Total         int      `json:"total,omitempty"`
	EgressGateway []string `json:"egress_gateway,omitempty"`
}

// CiliumFactsSource returns the Cilium section of the current host-facts
// receipt, nil when the receipt has none, or the reason there is no receipt to
// take it from.
type CiliumFactsSource func(context.Context) (*CiliumFacts, error)

// UnreadableCiliumFacts is the section of a read that failed as a whole.
func UnreadableCiliumFacts(reason string) *CiliumFacts {
	reason = bounded(reason, maxReasonBytes)
	if reason == "" {
		reason = "no reason given"
	}
	return &CiliumFacts{
		Status:     CiliumTextFact{State: FactsUnreadable, Reason: reason},
		PinnedMaps: CiliumPinFacts{State: FactsUnreadable, Reason: reason},
		IPMasqMap:  CiliumTextFact{State: FactsUnreadable, Reason: reason},
	}
}

// Validate refuses a section that is malformed or exceeds a bound. It says
// nothing about what the section proves.
func (f CiliumFacts) Validate() error {
	if err := f.Status.validate("Cilium status", MaxCiliumStatusFactBytes, false); err != nil {
		return err
	}
	if err := f.IPMasqMap.validate("Cilium ip-masq-agent map", MaxCiliumMapFactBytes, true); err != nil {
		return err
	}
	pins := f.PinnedMaps
	if len(pins.Reason) > maxReasonBytes {
		return errors.New("host facts for Cilium pinned maps carry an oversized reason")
	}
	switch pins.State {
	case FactsRead:
		if pins.Reason != "" || pins.Total < len(pins.EgressGateway) || len(pins.EgressGateway) > maxCiliumEgressPins {
			return errors.New("host facts for Cilium pinned maps are inconsistent")
		}
	case FactsUnreadable:
		if pins.Reason == "" || pins.Total != 0 || len(pins.EgressGateway) != 0 {
			return errors.New("host facts for Cilium pinned maps are inconsistent")
		}
	default:
		return errors.New("host facts for Cilium pinned maps have an unknown state")
	}
	for i, name := range pins.EgressGateway {
		if !ciliumPinNameRE.MatchString(name) || !strings.HasPrefix(name, ciliumEgressGatewayPinPrefix) || (i > 0 && pins.EgressGateway[i-1] >= name) {
			return errors.New("host facts for Cilium pinned maps name an invalid, repeated or unordered map")
		}
	}
	return nil
}

func (f CiliumTextFact) validate(what string, limit int, mayBeNotNeeded bool) error {
	if len(f.Reason) > maxReasonBytes || len(f.Text) > limit {
		return fmt.Errorf("host facts for %s exceed bound", what)
	}
	switch {
	case f.State == FactsRead:
		if f.Reason != "" || f.Text == "" {
			return fmt.Errorf("host facts for %s are inconsistent", what)
		}
	case f.State == FactsUnreadable, f.State == FactsNotNeeded && mayBeNotNeeded:
		if f.Reason == "" || f.Text != "" {
			return fmt.Errorf("host facts for %s are inconsistent", what)
		}
	default:
		return fmt.Errorf("host facts for %s have an unknown state", what)
	}
	return nil
}

// Summary is a bounded, change-only description for the manager's log.
func (f CiliumFacts) Summary() string {
	part := func(name, state, reason string) string {
		if reason != "" {
			return fmt.Sprintf("%s=%s (%s)", name, state, bounded(reason, 60))
		}
		return name + "=" + state
	}
	return bounded(strings.Join([]string{
		part("status", f.Status.State, f.Status.Reason),
		part("pinned_maps", f.PinnedMaps.State, f.PinnedMaps.Reason) + fmt.Sprintf(" egress_gateway=%d", len(f.PinnedMaps.EgressGateway)),
		part("ip_masq_map", f.IPMasqMap.State, f.IPMasqMap.Reason),
	}, "; "), maxReasonBytes)
}

// ReasonCiliumNotVerified starts the refusal of a node that shows Cilium when
// what the proof needs could not be read or was not understood. The detail
// that follows says which.
const ReasonCiliumNotVerified = "Cilium masquerade on this node is not verified"

// ReasonCiliumTunnelMasqueraded starts the refusal the customer can lift: the
// tunnel range is in no range Cilium's eBPF masquerade excludes. The
// instruction follows it.
const ReasonCiliumTunnelMasqueraded = "Cilium eBPF masquerade would rewrite traffic to the tunnel range"

var (
	errCiliumNotVerified       = errors.New(ReasonCiliumNotVerified)
	errCiliumTunnelMasqueraded = errors.New(ReasonCiliumTunnelMasqueraded)
)

func ciliumNotVerified(detail string) error {
	return fmt.Errorf("%w: %s", errCiliumNotVerified, bounded(detail, maxReasonBytes))
}

// ReasonCiliumReportedRangeNotProof starts the other refusal the customer can
// lift: the ip-masq-agent is on and the tunnel range is inside the
// native-routing range the agent reports, but in no entry of its list. With
// the ip-masq-agent on that reported range is applied only when it was set
// explicitly, which the report does not say, so the range has to be listed.
const ReasonCiliumReportedRangeNotProof = "Cilium's ip-masq-agent is on: its reported native-routing range"

// ciliumLiftableRefusal is a refusal the customer can lift with one change in
// Cilium whose text does not begin with ReasonCiliumTunnelMasqueraded. It is
// of the same kind for errors.Is.
type ciliumLiftableRefusal string

func (e ciliumLiftableRefusal) Error() string      { return string(e) }
func (ciliumLiftableRefusal) Is(target error) bool { return target == errCiliumTunnelMasqueraded }

// ciliumInstruction is what the customer changes in Cilium so that the tunnel
// range is excluded (docs/K8N-2-cilium.md, "What the customer does").
func ciliumInstruction(e *ciliumTunnelNotExcludedError) string {
	if e.IPMasqAgent {
		return fmt.Sprintf("Add %s to nonMasqueradeCIDRs in the ip-masq-agent ConfigMap (namespace kube-system, key config); no restart is needed, allow about a minute", e.Tunnel)
	}
	return fmt.Sprintf("Enable Cilium's ip-masq-agent (Helm ipMasqAgent.enabled=true) with %s in nonMasqueradeCIDRs, then restart the Cilium agents", e.Tunnel)
}

// ciliumNotExcludedReason is the whole customer-facing refusal for a tunnel
// range that no exclusion Tunnex can read contains. Every form fits the
// reason bound for any two IPv4 ranges.
func ciliumNotExcludedReason(e *ciliumTunnelNotExcludedError) error {
	if e.IPMasqAgent && e.InsideReported {
		return ciliumLiftableRefusal(fmt.Sprintf("%s %s does not prove %s is not masqueraded. Add %s to nonMasqueradeCIDRs in the ip-masq-agent ConfigMap (kube-system, key config)",
			ReasonCiliumReportedRangeNotProof, e.Exclusion, e.Tunnel, e.Tunnel))
	}
	return fmt.Errorf("%w %s. %s", errCiliumTunnelMasqueraded, e.Tunnel, ciliumInstruction(e))
}

// decideCiliumMasquerade is the gateway's decision on a node that shows
// Cilium. It returns the reason only when Cilium's own masquerading cannot
// rewrite traffic bound for tunnel, as proveCiliumNoTunnelMasquerade defines
// it. In iptables mode the returned reason says the NAT rule walk decides; the
// caller must have run that walk. Every other outcome is an error whose text
// is the bounded reason the customer sees.
func decideCiliumMasquerade(facts *CiliumFacts, tunnel netip.Prefix) (string, error) {
	if facts == nil {
		return "", ciliumNotVerified("the host-posture manager published no Cilium facts")
	}
	if err := facts.Validate(); err != nil {
		return "", ciliumNotVerified(err.Error())
	}
	if facts.Status.State != FactsRead {
		return "", ciliumNotVerified("the host-posture manager could not read the Cilium agent status: " + facts.Status.Reason)
	}
	masq, err := parseCiliumStatus([]byte(facts.Status.Text))
	if err != nil {
		return "", ciliumNotVerified(err.Error())
	}
	// The manager dumps the map exactly when the status says the ip-masq-agent
	// is on. Anything else is a receipt this code does not understand.
	if !masq.IPMasqAgent && facts.IPMasqMap.State != FactsNotNeeded {
		return "", ciliumNotVerified("the ip-masq-agent map fact contradicts the agent status")
	}
	if masq.IPMasqAgent && facts.IPMasqMap.State == FactsNotNeeded {
		return "", ciliumNotVerified("the ip-masq-agent map fact contradicts the agent status")
	}
	obs := ciliumObservation{Masquerade: masq}
	if masq.Mode == ciliumMasqBPF {
		if facts.PinnedMaps.State != FactsRead {
			return "", ciliumNotVerified("the host-posture manager could not list Cilium's pinned maps: " + facts.PinnedMaps.Reason)
		}
		obs.EgressGateway = ciliumEgressGatewayPinned(facts.PinnedMaps.EgressGateway)
		if masq.IPMasqAgent {
			if facts.IPMasqMap.State != FactsRead {
				return "", ciliumNotVerified("the host-posture manager could not read the ip-masq-agent map: " + facts.IPMasqMap.Reason)
			}
			members, err := parseCiliumIPMasqDump([]byte(facts.IPMasqMap.Text))
			if err != nil {
				return "", ciliumNotVerified(err.Error())
			}
			obs.NonMasquerade, obs.NonMasqueradeRead = members, true
		}
	}
	reason, err := proveCiliumNoTunnelMasquerade(obs, tunnel)
	var notExcluded *ciliumTunnelNotExcludedError
	switch {
	case err == nil:
		return reason, nil
	case errors.As(err, &notExcluded):
		return "", ciliumNotExcludedReason(notExcluded)
	case errors.Is(err, errCiliumEgressGateway):
		return "", err
	default:
		return "", ciliumNotVerified(err.Error())
	}
}

// reduceCiliumStatus keeps of the agent's status only what the proof reads:
// the `masquerading` member and, when present, the `stale` member. The result
// is one JSON object that parseCiliumStatus reads like the full status. The
// status has dozens of members and grows; none of the others is carried.
func reduceCiliumStatus(raw []byte) (string, error) {
	if len(raw) > maxCiliumStatusBytes {
		return "", errors.New("Cilium status exceeds bound")
	}
	var top map[string]json.RawMessage
	if err := ciliumDecodeJSON(raw, &top, false); err != nil || top == nil {
		return "", errors.New("Cilium status is not a JSON object")
	}
	names := make([]string, 0, 2)
	for _, name := range []string{"masquerading", "stale"} {
		if _, ok := top[name]; ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var out strings.Builder
	out.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			out.WriteByte(',')
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, top[name]); err != nil {
			return "", errors.New("Cilium status is not understood")
		}
		fmt.Fprintf(&out, "%q:%s", name, compact.Bytes())
	}
	out.WriteByte('}')
	if out.Len() > MaxCiliumStatusFactBytes {
		return "", fmt.Errorf("Cilium masquerading status exceeds %d bytes", MaxCiliumStatusFactBytes)
	}
	return out.String(), nil
}

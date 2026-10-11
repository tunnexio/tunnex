package ipsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"reflect"
	"strings"
	"time"
)

// Absolute generation/rule authority is never extended by a connection renewal.
// This only removes application grants; ordinary and dedicated DNS retain their
// independent native, lease, and tuple requirements.
func liveFQDNGrants(in []GuardGrant, now time.Time) []GuardGrant {
	out := make([]GuardGrant, 0, len(in))
	for _, g := range in {
		if g.FQDN.Version == 2 && !g.FQDN.ExpiresAt.After(now) {
			continue
		}
		out = append(out, g)
	}
	return out
}

// Call after all independent proofs, immediately before the original bounded
// atomic commit. Subtract its entire remaining upper budget conservatively.
func limitFQDNGuardIntent(in GuardIntent, now time.Time, commitBudget time.Duration, remaining func(uuid.UUID, GuardGrant, time.Duration) (time.Duration, error)) GuardIntent {
	out := in
	out.Connections = append([]GuardConnection(nil), in.Connections...)
	for i, c := range out.Connections {
		c.Grants = liveFQDNGrants(c.Grants, now)
		kept := c.Grants[:0]
		for _, g := range c.Grants {
			if g.FQDN.Version == 2 {
				if remaining == nil {
					continue
				}
				d, err := remaining(c.ID, g, commitBudget)
				if err != nil {
					continue
				}
				if d > c.PermitFor {
					d = c.PermitFor
				}
				if d > 60*time.Second {
					d = 60 * time.Second
				}
				d = d / time.Second * time.Second
				// Early cutoff is intentional: even the rounded emitted membership must
				// outlive the full original commit/readback budget. This can omit
				// grants with ten seconds or less remaining; it never extends them.
				if commitBudget <= 0 || d <= commitBudget {
					continue
				}
				g.FQDNPermitFor = d
			}
			kept = append(kept, g)
		}
		c.Grants = kept
		out.Connections[i] = c
	}
	return out
}

func guardFQDNSetName(g GuardGrant) string {
	g.FQDNPermitFor = 0
	b, _ := json.Marshal(g)
	h := sha256.Sum256(b)
	return "fqdn_" + hex.EncodeToString(h[:])
}
func guardFQDNSetText(g GuardGrant) string {
	return fmt.Sprintf("  set %s {\n    type ipv4_addr; flags timeout; timeout 60s;\n    elements = { %s timeout %ds }\n  }\n", guardFQDNSetName(g), g.Destination.Addr(), int64(g.FQDNPermitFor/time.Second))
}

func validFQDNSetName(name string) bool {
	return strings.HasPrefix(name, "fqdn_") && validDigest(strings.TrimPrefix(name, "fqdn_"))
}

// Values already passed the exact typed normalizer. A different native set type
// remains a refusal; this does not interpret arbitrary strings as interface IDs.
func guardSetMemberKey(v any) string {
	if n, ok := v.(json.Number); ok {
		return "number:" + n.String()
	}
	if s, ok := v.(string); ok {
		return "address:" + s
	}
	return "invalid"
}

// Only an independently matched previous whole-table template may supply these
// names. Clear old references and delete precisely its FQDN sets in the same
// atomic transaction before creating the new generation's sets.
func replaceOwnedFQDNSets(transaction, prior string) (string, error) {
	objects, ok := normalizedGuardObjects([]byte(prior))
	if !ok {
		return "", ErrGuardReadback
	}
	var names []string
	for _, o := range objects {
		if set, ok := o.(map[string]any)["set"].(map[string]any); ok {
			name, _ := set["name"].(string)
			if validFQDNSetName(name) {
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return transaction, nil
	}
	var envelope struct {
		Commands []json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(transaction), &envelope) != nil || len(envelope.Commands) < 2 {
		return "", ErrGuardReadback
	}
	for i, operation := range []string{"add", "flush"} {
		var command any
		want := map[string]any{operation: map[string]any{"table": map[string]any{"family": "inet", "name": "tunnex_ipsec"}}}
		if json.Unmarshal(envelope.Commands[i], &command) != nil || !reflect.DeepEqual(command, want) {
			return "", ErrGuardReadback
		}
	}
	commands := append([]json.RawMessage(nil), envelope.Commands[:2]...)
	for _, name := range names {
		b, _ := json.Marshal(map[string]any{"delete": map[string]any{"set": map[string]any{"family": "inet", "table": "tunnex_ipsec", "name": name}}})
		commands = append(commands, b)
	}
	commands = append(commands, envelope.Commands[2:]...)
	b, err := json.Marshal(map[string]any{"nftables": commands})
	return string(b), err
}

func runtimeFQDNGrantDigest(g RuntimeFQDNGrant) string {
	raw, _ := json.Marshal(g)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func runtimeFQDNLeaseKeys(p RuntimePolicy) []string {
	if p.FQDNPolicyVersion != 2 {
		return nil
	}
	keys := make([]string, 0, len(p.FQDNGrants))
	for _, g := range p.FQDNGrants {
		keys = append(keys, runtimeFQDNGrantDigest(g))
	}
	return keys
}
func guardFQDNGrantDigest(g GuardGrant) string {
	b := g.FQDN
	f := RuntimeFQDNGrant{ExpiresAt: b.ExpiresAt, ResolverSourceAddress: b.ResolverSourceAddress, RuntimeGrant: RuntimeGrant{Source: g.Source.String(), Destination: g.Destination.String(), Protocol: string(g.Protocol), PortLow: g.PortLow, PortHigh: g.PortHigh, RuleID: b.RuleID.String()}, FQDNManaged: g.FQDNManaged, ResourceID: b.ResourceID.String(), Name: b.Name, Generation: b.Generation, ResolverConfigID: b.ResolverConfigID.String(), ResolverConfigVersion: b.ResolverConfigVersion, SelectedSiteID: b.SelectedSiteID.String(), SelectedGatewayID: b.SelectedGatewayID.String(), ResolverProfileID: b.ResolverProfileID.String(), ResolverMatchSuffix: b.ResolverMatchSuffix, ConnectionID: b.ConnectionID.String(), ConfigurationRevision: b.ConfigurationRevision}
	return runtimeFQDNGrantDigest(f)
}

func runtimeFQDNLeaseDescriptors(p RuntimePolicy) []RuntimeFQDNGrant {
	if p.FQDNPolicyVersion != 2 {
		return nil
	}
	return append([]RuntimeFQDNGrant(nil), p.FQDNGrants...)
}

package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

// Model the CP's exact-current-descriptor lease check, not native acceptance.
// A has no retained runtime after restart; B renews normally while the CP
// publishes a new immutable FQDN generation for A, with the same destination.
type fallbackFreshnessPollFake struct {
	*maintenancePollFake
	turnoverAt      string
	reads           map[uuid.UUID]int
	staleApply      int
	turnovers       int
	refetch         func(ipsec.RuntimeMaterial) (ipsec.RuntimeMaterial, error)
	cancelAtRefresh context.CancelFunc
}

func newFallbackFreshnessPollFake(t *testing.T, turnoverAt string) *fallbackFreshnessPollFake {
	t.Helper()
	f := &fallbackFreshnessPollFake{maintenancePollFake: newMaintenancePollFake(t), turnoverAt: turnoverAt, reads: map[uuid.UUID]int{}}
	id := f.items[0].ConnectionID
	m := f.materials[id]
	v := 1
	m.Manifest.ProfileID = "aws-bgp-ipv4-v1"
	m.Manifest.BGPVersion = &v
	m.Manifest.BGP = &ipsec.BGPConfig{MaximumPrefixes: 64}
	m.Manifest.RemotePrefixes = []string{"10.182.0.0/16"}
	for i := range m.Manifest.Tunnels {
		m.Manifest.Tunnels[i].Selected = false
	}
	m.Policy = ipsec.RuntimePolicy{FQDNPolicyVersion: 2, FQDNGrants: []ipsec.RuntimeFQDNGrant{{
		RuntimeGrant: ipsec.RuntimeGrant{Source: "10.99.0.2/32", Destination: "10.182.10.20/32", Protocol: "tcp", PortLow: 443, PortHigh: 443, RuleID: uuid.NewString()},
		ExpiresAt:    time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), Generation: strings.Repeat("a", 64), FQDNManaged: true,
		Name: "app.internal.test", DeviceID: uuid.NewString(), ResolverKind: "static_cname",
	}}}
	m.Policy.Hash = fallbackPolicyFingerprint(m.Policy)
	f.materials[id] = m
	return f
}

func fallbackPolicyFingerprint(p ipsec.RuntimePolicy) string {
	p.Hash = ""
	raw, _ := json.Marshal(p)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func (f *fallbackFreshnessPollFake) advanceGeneration() {
	id := f.items[0].ConnectionID
	m := f.materials[id]
	m.Policy.FQDNGrants = append([]ipsec.RuntimeFQDNGrant(nil), m.Policy.FQDNGrants...)
	m.Policy.FQDNGrants[0].Generation = strings.Repeat("b", 64)
	m.Policy.FQDNGrants[0].ExpiresAt = m.Policy.FQDNGrants[0].ExpiresAt.Add(time.Minute)
	m.Policy.Hash = fallbackPolicyFingerprint(m.Policy)
	f.materials[id] = m
	f.turnovers++
	f.events = append(f.events, "generation")
}

func (f *fallbackFreshnessPollFake) IPsecMaterial(ctx context.Context, id uuid.UUID, revision int64) (ipsec.RuntimeMaterial, error) {
	f.reads[id]++
	if id == f.items[0].ConnectionID && f.reads[id] > 1 {
		f.events = append(f.events, "fresh-original")
		if ctx.Err() != nil {
			return ipsec.RuntimeMaterial{}, ctx.Err()
		}
		if f.refetch != nil {
			return f.refetch(f.materials[id])
		}
	}
	return f.maintenancePollFake.IPsecMaterial(ctx, id, revision)
}

func (f *fallbackFreshnessPollFake) MaintainIPsecRuntime(ctx context.Context, material []ipsec.RuntimeMaterial) ([]ipsec.RuntimeMaintenanceResult, error) {
	results, err := f.maintenancePollFake.MaintainIPsecRuntime(ctx, material)
	if err != nil {
		return nil, err
	}
	if f.turnoverAt == "maintenance" {
		f.advanceGeneration()
	}
	return results[1:], nil // Only B is already applied and maintained.
}

func (f *fallbackFreshnessPollFake) RefreshIPsecRecovery(context.Context) error {
	f.events = append(f.events, "recovery-refresh")
	if f.turnoverAt == "recovery" {
		f.advanceGeneration()
	}
	if f.cancelAtRefresh != nil {
		f.cancelAtRefresh()
	}
	return nil
}

func TestIPsecMaintenanceFallbackRefetchFailureCannotApplyCachedMaterial(t *testing.T) {
	for _, name := range []string{"fetch_failure", "connection", "revision", "kind", "nil_delivery", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f := newFallbackFreshnessPollFake(t, "maintenance")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.refetch = func(m ipsec.RuntimeMaterial) (ipsec.RuntimeMaterial, error) {
				switch name {
				case "fetch_failure":
					return ipsec.RuntimeMaterial{}, errors.New("synthetic fresh material unavailable")
				case "connection":
					m.Manifest.ConnectionID = uuid.New()
				case "revision":
					m.DesiredRevision++
				case "kind":
					m.Kind = "cleanup"
				case "nil_delivery":
					m.ID = uuid.Nil
				}
				return m, nil
			}
			if name == "canceled" {
				f.cancelAtRefresh = cancel
			}
			valid, err := PollIPsecRuntimeValidated(ctx, f, f)
			if !errors.Is(err, ErrIPsecControl) || valid || f.reads[f.items[0].ConnectionID] != 2 || f.applyCount != 0 || f.staleApply != 0 || f.acks != 1 || len(f.reports) != 1 {
				t.Fatalf("rejected refetch fell back to old authority: valid=%v err=%v reads=%d apply=%d stale=%d ack=%d reports=%d", valid, err, f.reads[f.items[0].ConnectionID], f.applyCount, f.staleApply, f.acks, len(f.reports))
			}
			assertMaintenanceSecretsCleared(t, f.maintenancePollFake)
		})
	}
}

func (f *fallbackFreshnessPollFake) Apply(ctx context.Context, material ipsec.RuntimeMaterial) (ipsec.RuntimeAcknowledgement, error) {
	current := f.materials[material.Manifest.ConnectionID]
	if material.Policy.Hash != current.Policy.Hash || !reflect.DeepEqual(material.Policy.FQDNGrants, current.Policy.FQDNGrants) {
		f.staleApply++
		return ipsec.RuntimeAcknowledgement{}, errors.New("synthetic current FQDN lease conflict")
	}
	return f.maintenancePollFake.Apply(ctx, material)
}

func TestIPsecMaintenanceFallbackRefetchesAfterFQDNTurnover(t *testing.T) {
	for _, phase := range []string{"maintenance", "recovery"} {
		t.Run(phase, func(t *testing.T) {
			f := newFallbackFreshnessPollFake(t, phase)
			valid, err := PollIPsecRuntimeValidated(context.Background(), f, f)
			if err != nil || !valid || f.turnovers != 1 || f.staleApply != 0 || f.applyCount != 1 || f.acks != 2 || f.reads[f.items[0].ConnectionID] != 2 || f.reads[f.items[1].ConnectionID] != 1 {
				t.Fatalf("missing owner replayed pre-maintenance FQDN material: valid=%v err=%v turns=%d staleApply=%d apply=%d ack=%d reads=%v", valid, err, f.turnovers, f.staleApply, f.applyCount, f.acks, f.reads)
			}
			positions := map[string]int{}
			for i, event := range f.events {
				if _, ok := positions[event]; !ok {
					positions[event] = i
				}
			}
			if positions["ack"] >= positions["fresh-original"] || positions["recovery-refresh"] >= positions["fresh-original"] || positions["generation"] >= positions["fresh-original"] || positions["fresh-original"] >= positions["apply"] {
				t.Fatal("fresh fetch did not follow maintained publication and recovery observation")
			}
			assertMaintenanceSecretsCleared(t, f.maintenancePollFake)
		})
	}
}

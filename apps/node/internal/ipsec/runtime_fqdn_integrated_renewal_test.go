package ipsec

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// This exercises the shared maintenance/priority path using the existing
// synthetic five-provider rig. It is not native or control-plane acceptance.
func TestIntegratedFQDNDescriptorsSurviveMaintenanceAndPriority(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	a := r.c.active[r.target]
	var original []RuntimeFQDNGrant
	for i := range r.materials {
		m := &r.materials[i]
		if m.Manifest.ConnectionID != r.target {
			continue
		}
		fixture, _, _ := v2FQDNFixture(t)
		f := fixture.Policy.FQDNGrants[0]
		f.Source = a.Entry.Engines[0].LocalPrefixes[0].String()
		f.Destination = netip.PrefixFrom(a.Entry.Engines[0].RemotePrefixes[0].Addr().Next(), 32).String()
		f.ResolverSourceAddress = a.Entry.Engines[0].LocalPrefixes[0].Addr().Next().String()
		f.SelectedSiteID, f.SelectedGatewayID = m.Manifest.SiteID.String(), m.Manifest.NodeID.String()
		f.ConnectionID, f.ConfigurationRevision = r.target.String(), m.Manifest.ConfigurationRevision
		f.ExpiresAt = time.Now().UTC().Add(-time.Second)
		m.Policy.FQDNPolicyVersion = 2
		m.Policy.FQDNGrants = []RuntimeFQDNGrant{f}
		_, grants, err := runtimeMaterialEntry(*m, r.c.config.OrgID, r.c.config.GatewayID, a.Environment.Namespace)
		if err != nil || !reflect.DeepEqual(grants, a.Grants) {
			t.Fatal("expired descriptor changed ordinary guard authority", err)
		}
		original = runtimeFQDNLeaseDescriptors(m.Policy)
	}
	if len(original) != 1 {
		t.Fatal("missing target material")
	}
	calls := 0
	client := r.c.client
	r.c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
		out, err := client.RenewIPsecLease(ctx, id, q)
		if id == r.target {
			if !reflect.DeepEqual(q.FQDNGrants, original) {
				t.Fatal("lease lost immutable expired descriptor")
			}
			calls++
			out.FQDNPermits = []RuntimeFQDNPermit{{GrantDigest: runtimeFQDNGrantDigest(original[0]), TTLMS: 0}}
		}
		return out, err
	})
	// Normal material seeds the retained descriptors even though no FQDN grant
	// is eligible for the native guard. Subsequent priority renewal has no material.
	r.phase = "maintenance"
	results, err := r.c.maintainIPsecRuntime(context.Background(), maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true })
	if err != nil || len(results) != len(r.materials) {
		t.Fatal("normal maintained renewal", len(results), err)
	}
	beforePriority := calls
	if err = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err != nil {
		t.Fatal("priority retained renewal", err)
	}
	current := r.c.active[r.target]
	if calls <= beforePriority || !reflect.DeepEqual(current.FQDNLeaseDescriptors, original) {
		t.Fatal("priority omitted original descriptor")
	}
	if _, err = current.Authority.RemainingForApply(current.Identity, time.Millisecond); err != nil {
		t.Fatal("expired FQDN withdrew ordinary authority", err)
	}
	if _, err = current.Authority.RemainingFQDNForApply(current.Identity, runtimeFQDNGrantDigest(original[0]), time.Millisecond); err == nil {
		t.Fatal("expired descriptor regained permission")
	}
	// Both the retained active record and published DNS snapshot own their copy.
	view := cloneDNSOwnerActive(current)
	for i := range r.materials {
		if r.materials[i].Manifest.ConnectionID == r.target {
			r.materials[i].Policy.FQDNGrants[0].Name = "mutated.example.test"
		}
	}
	current.FQDNLeaseDescriptors[0].Name = "another.example.test"
	if !reflect.DeepEqual(view.FQDNLeaseDescriptors, original) {
		t.Fatal("mutable material or active slice changed captured descriptor")
	}
}

func TestIntegratedRecoveryLeaseCarriesOriginalFQDNDescriptors(t *testing.T) {
	m, _, _ := v2FQDNFixture(t)
	expired := m.Policy.FQDNGrants[0]
	expired.ExpiresAt = time.Now().UTC().Add(-time.Second)
	m.Policy.FQDNGrants = append([]RuntimeFQDNGrant{expired}, m.Policy.FQDNGrants...)
	entry, grants, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil || len(grants) != 1 {
		t.Fatal("expired descriptor not filtered independently", err)
	}
	original := runtimeFQDNLeaseDescriptors(m.Policy)
	identity := PermitLeaseIdentity{DeliveryID: entry.DeliveryID, Binding: entry.Engines[0].Binding, PolicyHash: m.Policy.Hash}
	calls := 0
	c := &RuntimeController{active: map[uuid.UUID]runtimeActive{entry.Allocation.ConnectionID: {Identity: identity, FQDNLeaseDescriptors: runtimeFQDNLeaseDescriptors(m.Policy)}}}
	c.client = maintenanceLeaseFunc(func(_ context.Context, _ uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
		calls++
		if !reflect.DeepEqual(q.FQDNGrants, original) {
			t.Fatal("recovery lease reconstructed a filtered descriptor subset")
		}
		return RuntimeLease{RuntimeLeaseRequest: q, TTLMS: 60000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: runtimeFQDNGrantDigest(original[0]), TTLMS: 0}, {GrantDigest: runtimeFQDNGrantDigest(original[1]), TTLMS: 30000}}}, nil
	})
	for _, material := range []bool{true, false} {
		var authority *PermitLeaseAuthority
		var got PermitLeaseIdentity
		if material {
			authority, got, err = c.recoveryLease(context.Background(), entry, m.Policy.Hash, m.Policy)
		} else {
			authority, got, err = c.recoveryLease(context.Background(), entry, m.Policy.Hash)
		}
		if err != nil || got != identity {
			t.Fatal("recovery lease refused original descriptors", material, err)
		}
		if _, err = authority.RemainingForApply(got, time.Millisecond); err != nil {
			t.Fatal("ordinary authority lost", err)
		}
		if _, err = authority.RemainingFQDNForApply(got, runtimeFQDNGrantDigest(original[0]), time.Millisecond); err == nil {
			t.Fatal("expired descriptor acquired permission")
		}
		if _, err = authority.RemainingFQDNForApply(got, runtimeFQDNGrantDigest(original[1]), time.Millisecond); err != nil {
			t.Fatal("live descriptor lost permission", err)
		}
	}
	if calls != 2 {
		t.Fatal("recovery did not obtain both fresh leases")
	}
}

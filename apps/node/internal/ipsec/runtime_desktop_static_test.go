package ipsec

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func desktopAWSStaticMaterial(t *testing.T, fqdn bool) RuntimeMaterial {
	t.Helper()
	m := runtimeMaterialFixture()
	if fqdn {
		m, _, _ = desktopStaticFQDNFixture(t)
	}
	version := 1
	m.Manifest.ProfileID = "aws-static-ipv4-v1"
	m.Manifest.BGP, m.Manifest.BGPVersion = nil, nil
	m.Manifest.RecoveryVersion = &version
	m.Manifest.DesktopStaticVersion = &version
	m.Manifest.Tunnels[0].Selected = true
	m.Manifest.Tunnels[1].Selected = false
	if !fqdn {
		m.Policy.DesktopGrants = []RuntimeDesktopGrant{desktopGrantFixture()}
	}
	runtimeReseal(&m)
	return m
}

func TestDesktopAWSStaticMaterialUsesAuthenticatedContract(t *testing.T) {
	for _, fqdn := range []bool{false, true} {
		name := "CIDR"
		if fqdn {
			name = "managed_CNAME"
		}
		t.Run(name, func(t *testing.T) {
			m := desktopAWSStaticMaterial(t, fqdn)
			entry, grants, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
			if err != nil || len(grants) != 1 || grants[0].DesktopDeviceID == uuid.Nil || entry.ContractVersion != 2 || entry.Allocation.BGP || selectedRuntimeSlot(entry) != 1 {
				t.Fatal("static desktop contract refused or lost authenticated identity", err)
			}
			for label, mutate := range map[string]func(*RuntimeMaterial){
				"legacy_narrow_transport": func(m *RuntimeMaterial) { m.Manifest.DesktopStaticVersion = nil },
				"unsupported_transport":   func(m *RuntimeMaterial) { v := 2; m.Manifest.DesktopStaticVersion = &v },
				"legacy_fixed_slot":       func(m *RuntimeMaterial) { m.Manifest.RecoveryVersion = nil },
				"foreign_provider":        func(m *RuntimeMaterial) { m.Manifest.ProfileID = "gcp-classic-static-ipv4-v1" },
				"bgp_mix":                 func(m *RuntimeMaterial) { m.Manifest.BGP = &BGPConfig{} },
				"broad_source": func(m *RuntimeMaterial) {
					if fqdn {
						m.Policy.FQDNGrants[0].Source = "10.99.0.0/24"
					} else {
						m.Policy.DesktopGrants[0].Source = "10.99.0.0/24"
					}
				},
				"foreign_key": func(m *RuntimeMaterial) {
					if fqdn {
						m.Policy.FQDNGrants[0].PublicKey = "foreign"
					} else {
						m.Policy.DesktopGrants[0].PublicKey = "foreign"
					}
				},
				"foreign_destination": func(m *RuntimeMaterial) {
					if fqdn {
						m.Policy.FQDNGrants[0].Destination = "8.8.8.8/32"
					} else {
						m.Policy.DesktopGrants[0].Destination = "8.8.8.8/32"
					}
				},
				"expired": func(m *RuntimeMaterial) {
					end := time.Now().Add(-time.Second)
					if fqdn {
						m.Policy.FQDNGrants[0].ExpiresAt = end
					} else {
						m.Policy.DesktopGrants[0].ExpiresAt = &end
					}
				},
			} {
				t.Run(label, func(t *testing.T) {
					bad := desktopAWSStaticMaterial(t, fqdn)
					mutate(&bad)
					runtimeReseal(&bad)
					_, got, err := runtimeMaterialEntry(bad, bad.Manifest.OrgID, bad.Manifest.NodeID, "net:[4026531992]")
					if fqdn && label == "expired" {
						if err != nil || len(got) != 0 {
							t.Fatal("expired membership should be selectively withdrawn", err)
						}
					} else if err == nil {
						t.Fatal("invalid static desktop material accepted")
					}
				})
			}
		})
	}
}

// Reuse the mixed-owner renewal rig: journal, finite permits and guard are real;
// native WireGuard and tunnel observations use the existing deterministic seams.
func desktopStaticRenewalRig(t *testing.T) (*renewalCycleRig, uuid.UUID) {
	t.Helper()
	r := newRenewalCycleRigInput(t, true, desktopStaticTransportFixture)
	var id uuid.UUID
	for i := range r.materials {
		m := &r.materials[i]
		if m.Manifest.ProfileID != "aws-static-ipv4-v1" {
			continue
		}
		id = m.Manifest.ConnectionID
		d := desktopGrantFixture()
		d.Destination = netip.PrefixFrom(netip.MustParsePrefix(m.Manifest.RemotePrefixes[0]).Addr().Next(), 32).String()
		m.Policy.DesktopGrants = []RuntimeDesktopGrant{d}
		a := r.c.active[id]
		_, grants, err := runtimeMaterialEntry(*m, r.c.config.OrgID, r.c.config.GatewayID, a.Environment.Namespace)
		if err != nil {
			t.Fatal(err)
		}
		for j := range grants {
			if grants[j].DesktopDeviceID != uuid.Nil {
				grants[j].DesktopIngressIndex = 7777
			}
		}
		a.Grants = grants
		r.c.active[id] = a
		break
	}
	if id == uuid.Nil {
		t.Fatal("missing AWS static fixture")
	}
	a := r.c.active[id]
	kernel := newRecoveryKernelFixture()
	kernel.p, kernel.owned = a.Entry.Allocation, a.Entry.Observed
	kernel.routes = [2]map[string]bool{{}, {}}
	for _, prefix := range a.Entry.Allocation.Tunnels[0].RemotePrefixes {
		kernel.routes[0][prefix.String()] = true
	}
	r.c.kernel = kernel.applier()
	r.c.desktopObserve = func(_ context.Context, in []GuardGrant) ([]GuardGrant, error) {
		out := append([]GuardGrant(nil), in...)
		for i := range out {
			if out[i].DesktopDeviceID != uuid.Nil {
				out[i].DesktopIngressIndex = 7777
			}
		}
		return out, nil
	}
	interfaces := r.c.guard.reader.interfaces
	r.c.guard.reader.interfaces = func() ([]GuardInterface, error) {
		out, err := interfaces()
		return append(out, GuardInterface{Name: "wg0", Index: 7777}), err
	}
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal("initial static desktop guard", err)
	}
	r.phase = "maintenance"
	return r, id
}

func TestDesktopAWSStaticRenewalPreservesSelectedOwner(t *testing.T) {
	r, id := desktopStaticRenewalRig(t)
	old := r.c.active[id]
	deadline := old.Authority.deadline
	if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err != nil {
		t.Fatal(err)
	}
	after, ok := r.c.active[id]
	if !ok || after.Authority == old.Authority || old.Authority.deadline != deadline || !reflect.DeepEqual(old.Entry, after.Entry) || !reflect.DeepEqual(old.Grants, after.Grants) || r.applicationDenied[id] {
		t.Fatal("static renewal lost exact selected owner or finite authority")
	}
	if len(r.c.bgpDesktopExports[old.Entry.DeliveryID]) != 0 {
		t.Fatal("static desktop created BGP export")
	}
}

func TestDesktopAWSStaticRenewalClosesLostAuthority(t *testing.T) {
	for _, reason := range []string{"expired_lease", "revoked_peer", "wrong_ingress", "cp_revocation"} {
		t.Run(reason, func(t *testing.T) {
			r, id := desktopStaticRenewalRig(t)
			old := r.c.active[id]
			deadline := old.Authority.deadline
			switch reason {
			case "expired_lease":
				*r.now = deadline + time.Second
			case "revoked_peer":
				r.c.desktopObserve = func(context.Context, []GuardGrant) ([]GuardGrant, error) { return nil, ErrRuntimeController }
			case "wrong_ingress":
				r.c.desktopObserve = func(_ context.Context, in []GuardGrant) ([]GuardGrant, error) {
					out := append([]GuardGrant(nil), in...)
					for i := range out {
						if out[i].DesktopDeviceID != uuid.Nil {
							out[i].DesktopIngressIndex++
						}
					}
					return out, nil
				}
			case "cp_revocation":
				base := r.c.client
				r.c.client = maintenanceLeaseFunc(func(ctx context.Context, connection uuid.UUID, req RuntimeLeaseRequest) (RuntimeLease, error) {
					if connection == id {
						return RuntimeLease{}, ErrRuntimeController
					}
					return base.RenewIPsecLease(ctx, connection, req)
				})
			}
			_ = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
			if _, ok := r.c.active[id]; ok || !r.applicationDenied[id] || old.Authority.deadline != deadline {
				t.Fatal("lost static authority retained forwarding or extended original lease")
			}
		})
	}
}

func TestDesktopAWSStaticRecoveryMovesOnlyAfterDenialAndFreshProof(t *testing.T) {
	r := newRecoveryTestRigTransport(t, true)
	r.m.Policy.DesktopGrants = []RuntimeDesktopGrant{desktopGrantFixture()}
	_, grants, err := runtimeMaterialEntry(r.m, r.m.Manifest.OrgID, r.m.Manifest.NodeID, r.env.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	for i := range grants {
		grants[i].DesktopIngressIndex = 7777
	}
	r.c.desktopObserve = func(_ context.Context, in []GuardGrant) ([]GuardGrant, error) {
		return append([]GuardGrant(nil), in...), nil
	}
	permits := 0
	base := r.c.replace
	r.c.replace = func(ctx context.Context, intent GuardIntent) (GuardManifest, error) {
		for _, c := range intent.Connections {
			if c.PrefixOnly {
				continue
			}
			permits++
			if len(c.Grants) != 1 || c.Grants[0].DesktopIngressIndex != 7777 || c.Grants[0].DesktopDeviceID == uuid.Nil || len(c.PermittedInterfaceIndices) != 1 || c.PermittedInterfaceIndices[0] != 11 {
				t.Fatal("static failover lost WireGuard identity or selected the old tunnel")
			}
		}
		return base(ctx, intent)
	}
	apply := func() error {
		entries, e := r.c.journal.Entries()
		if e != nil {
			return e
		}
		_, e = r.c.applyRecovery(context.Background(), r.m, entries, 0, r.env, grants)
		return e
	}
	for _, now := range []time.Duration{0, 5 * time.Second} {
		r.now = now
		if apply() == nil {
			t.Fatal("hold-down granted desktop access")
		}
	}
	r.now = 10 * time.Second
	if err := apply(); err != nil {
		t.Fatal("static desktop recovery", err)
	}
	if permits == 0 || r.switches != 1 {
		t.Fatal("desktop permission not restored on exact recovered slot")
	}
	r.now = 15 * time.Second
	r.status = [2]string{"up", "up"}
	if err := apply(); err != nil || r.switches != 1 {
		t.Fatal("healthy alternate failed or unexpectedly failed back", err)
	}
	r.c.desktopObserve = func(context.Context, []GuardGrant) ([]GuardGrant, error) { return nil, ErrRuntimeController }
	if apply() == nil || len(r.c.active) != 0 {
		t.Fatal("lost WireGuard identity survived recovery reuse")
	}
}

// Construct the explicit transport contract before the journal is written. This
// is a fresh delivery, never an in-place upgrade of legacy native ownership.
func desktopStaticTransportFixture(t *testing.T, c *RuntimeController, entries []RuntimeJournalEntry, materials []RuntimeMaterial) ([]RuntimeJournalEntry, []RuntimeMaterial) {
	t.Helper()
	for i := range materials {
		m := &materials[i]
		if m.Manifest.ProfileID != "aws-static-ipv4-v1" {
			continue
		}
		one := 1
		m.Manifest.DesktopStaticVersion = &one
		runtimeReseal(m)
		entries[i].OwnershipDigest = m.OwnershipDigest
		for j := range entries[i].Engines {
			entries[i].Engines[j].DesktopStaticVersion = 1
		}
		a := c.active[m.Manifest.ConnectionID]
		a.Entry, a.Delivery = entries[i], m.RuntimeDelivery
		c.active[m.Manifest.ConnectionID] = a
	}
	return entries, materials
}

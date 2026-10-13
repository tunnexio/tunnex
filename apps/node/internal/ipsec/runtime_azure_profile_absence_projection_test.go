package ipsec

import (
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"testing"
	"time"
)

func azureProfileAbsenceProjection(p runtimeJournalPayload, e RuntimeJournalEntry, b azureMaxProofBinding, clock time.Time, hash string, d DaemonInventory, k KernelInventory, x XFRMInventory, status bgpengine.Status, routes []bgpengine.LearnedRoute) map[string]any {
	absence := azureMaxProofProjection(p, e, b, clock, hash, d, k, x, status, routes)
	out := map[string]any{}
	for _, key := range []string{"guard_retained", "owned_ike", "owned_children", "owned_sad", "owned_spd", "owned_interfaces", "owned_routes", "azure_connection_id"} {
		out[key] = absence[key]
	}
	// Guard presence is from the validated payload; live verification remains mandatory.
	out["guard_retained"] = len(p.Guards) == 1
	return out
}

func TestAzureProfileAbsenceProjectionPreservesActualNonzeroInventory(t *testing.T) {
	p, e, b, d, k, x, status, routes := azureMaxProofFixture(t)
	b.Mode = "absence"
	got := azureProfileAbsenceProjection(p, e, b, time.Now(), "fixture", d, k, x, status, routes)
	children := 0
	for _, sa := range d.SAs {
		children += len(sa.Children)
	}
	if got["owned_ike"] != len(d.SAs) || got["owned_children"] != children || got["owned_sad"] != len(x.States) || got["owned_spd"] != len(x.Policies) {
		t.Fatal("actual native counters replaced")
	}
	if got["owned_interfaces"].(int) == 0 || got["owned_routes"].(int) == 0 {
		t.Fatal("observed kernel obligations omitted")
	}
}
func TestAzureProfileAbsenceProjectionEmptyInventory(t *testing.T) {
	p, e, b, _, k, _, _, _ := azureMaxProofFixture(t)
	b.Mode = "absence"
	got := azureProfileAbsenceProjection(p, e, b, time.Now(), "fixture", DaemonInventory{}, KernelInventory{Namespace: k.Namespace}, XFRMInventory{Namespace: k.Namespace}, bgpengine.Status{}, nil)
	for _, key := range []string{"owned_ike", "owned_children", "owned_sad", "owned_spd", "owned_interfaces", "owned_routes"} {
		if got[key] != 0 {
			t.Fatal("nonzero empty frame")
		}
	}
}

func TestAzureProfileAbsenceProjectionMissingGuardNotInferred(t *testing.T) {
	p, e, b, d, k, x, status, routes := azureMaxProofFixture(t)
	b.Mode = "absence"
	p.Guards = nil
	got := azureProfileAbsenceProjection(p, e, b, time.Now(), "fixture", d, k, x, status, routes)
	if got["guard_retained"] != false {
		t.Fatal("missing guard inferred")
	}
}

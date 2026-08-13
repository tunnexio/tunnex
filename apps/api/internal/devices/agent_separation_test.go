package devices

import (
	"os"
	"strings"
	"testing"
)

// TestPostureRefusesAgents — S15.3.
//
// ⛔ THE OWNER GATE DOES NOT STOP THIS, AND THAT IS WHY A SEPARATE GUARD EXISTS. An agent's `user_id` is the
// ADMIN WHO CREATED IT, so the admin satisfies "only the device owner may report its health" and can post
// posture facts about a machine they have never seen. Measured end to end on a live rig:
//
//	report {"disk_encrypted": false} -> {"blocked": true}
//	devices.health_blocked = true -> `NOT d.health_blocked` in ListActiveWireGuardPeersForNode
//	-> the agent's peer LEFT wg0 (peer count 1 -> 0) -> every granted request dead
//
// > **A HUMAN-ENDPOINT CONTROL REACHED AN AGENT'S DATA PLANE THROUGH A GATE WRITTEN FOR HUMANS.** The gate
// > was not bypassed — it was SATISFIED, by an owner who is not the machine.
//
// The refusal is at the WRITE, not at a downstream filter: a stale `health_blocked = true` left on an agent
// row would keep killing its tunnel forever, and no read-side filter would clear it.
func TestPostureRefusesAgents(t *testing.T) {
	b, err := os.ReadFile("health.go")
	if err != nil {
		t.Fatalf("read health.go: %v", err)
	}
	src := string(b)

	// ⛔ AND IT MUST BE INSIDE ReportDeviceHealth. A check elsewhere in the file would satisfy a naive
	// "contains" test while leaving the reporting path ungated — the same failure shape as
	// TestEnrolmentPathActuallyCallsTheGate, which is why that test's method is reused here.
	i := strings.Index(src, "func (s *Service) ReportHealth(")
	if i < 0 {
		t.Fatal("ReportHealth not found — if it was renamed, move this guard with it")
	}
	fn := src[i:]
	if end := strings.Index(fn[1:], "\nfunc "); end > 0 {
		fn = fn[:end]
	}
	if !strings.Contains(fn, `dev.Kind == "agent"`) {
		t.Fatal("ReportHealth does not refuse agents — an admin can post posture for an agent they " +
			"own, and a blocking evaluation removes that agent's peer from wg0. Proven on a live rig.")
	}
	if !strings.Contains(fn, "posture_not_applicable") {
		t.Fatal("the agent refusal must carry its own error code — folding it into forbidden/not_found " +
			"would tell an operator their permissions are wrong when the truth is that the check does not apply")
	}

	// ⚠ THE ORDER MATTERS. If the owner check ran first, an agent owned by a DIFFERENT admin would be
	// refused as `forbidden` — a permission answer to a question that is not about permission.
	if strings.Index(fn, `dev.Kind == "agent"`) > strings.Index(fn, "only the device owner may report") {
		t.Fatal("the agent refusal must precede the owner check: posture does not apply to an agent " +
			"regardless of who owns it, and answering `forbidden` would misdescribe why")
	}
}

// TestHumanDeviceSurfacesExcludeAgents — the other half of the separation.
//
// ⛔ THE PREDICATE MUST BE `kind`, NEVER `platform`. Agent rows exist with a NULL platform (measured on the
// review rig: one such row), so a platform-based filter silently misses them and the row reappears in the
// middle of an operator's laptop roster with no owner and no posture.
//
// ⚠ AND ONLY THE HUMAN SURFACES. An agent IS a WireGuard peer: the peer set, the pool allocation, the
// revocation sweep and the liveness upsert all read `devices` and MUST keep seeing it. Excluding agents from
// those would not separate the entity — it would delete the tunnel.
func TestHumanDeviceSurfacesExcludeAgents(t *testing.T) {
	b, err := os.ReadFile("../../db/queries/devices.sql")
	if err != nil {
		t.Fatalf("read devices.sql: %v", err)
	}
	src := string(b)

	human := []string{
		"ListDevicesByOrg :many",
		"ListDevicesByUser :many",
		"ListPendingDevicesByOrg :many",
		"CountActiveDevicesForOrg :one",
	}
	for _, name := range human {
		i := strings.Index(src, "-- name: "+name)
		if i < 0 {
			t.Fatalf("%s not found — if renamed, carry its agent exclusion with it", name)
		}
		q := src[i:]
		if end := strings.Index(q[1:], "\n-- name: "); end > 0 {
			q = q[:end]
		}
		if !strings.Contains(q, "kind <> 'agent'") {
			t.Fatalf("%s is an OPERATOR-FACING device surface and does not exclude agents — an AI agent "+
				"would appear in a laptop roster it has no business in", name)
		}
	}

	// ⛔ THE SECOND HALF, WITHOUT WHICH THE FIRST IS A LIABILITY. If the exclusion spread to the data-plane
	// queries, every agent would silently lose its peer slot — a far worse outcome than appearing on the
	// wrong screen, and one an "agents are excluded" test would happily report as success.
	dataPlane := []string{
		"ListActiveWireGuardPeersForNode :many",
		"UpsertDeviceStatus :batchexec",
		"ListActiveDeviceAllocations :many",
	}
	for _, name := range dataPlane {
		i := strings.Index(src, "-- name: "+name)
		if i < 0 {
			continue // shape changes are caught by the compiler; this test is about the predicate
		}
		q := src[i:]
		if end := strings.Index(q[1:], "\n-- name: "); end > 0 {
			q = q[:end]
		}
		if strings.Contains(q, "kind <> 'agent'") {
			t.Fatalf("%s is a DATA-PLANE query and must NOT exclude agents — an agent is a WireGuard peer, "+
				"and filtering it here removes its tunnel rather than separating the entity", name)
		}
	}
}

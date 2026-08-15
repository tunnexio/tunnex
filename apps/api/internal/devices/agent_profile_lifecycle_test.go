package devices

import (
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func TestAgentLifecycleTransition(t *testing.T) {
	allowed := [][2]string{{"active", "suspended"}, {"suspended", "active"}}
	for _, pair := range allowed {
		if !AgentLifecycleTransition(pair[0], pair[1]) {
			t.Errorf("expected %s -> %s", pair[0], pair[1])
		}
	}
	invalid := [][2]string{{"pending", "active"}, {"pending", "suspended"}, {"active", "revoked"}, {"revoked", "active"}, {"revoked", "suspended"}, {"unknown", "active"}}
	for _, pair := range invalid {
		if AgentLifecycleTransition(pair[0], pair[1]) {
			t.Errorf("expected refusal for %s -> %s", pair[0], pair[1])
		}
	}
}

func TestSuspendedAgentIsAbsentFromPeersAndAtomicProfileFailure(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	var profileTable bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('agent_profiles') IS NOT NULL`).Scan(&profileTable); err != nil {
		t.Fatal(err)
	}
	if !profileTable {
		t.Skip("migration 0088 is not applied")
	}
	if _, err := tx.Exec(ctx, `SAVEPOINT f01_suspended_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO devices (org_id, user_id, node_id, name, platform, public_key, assigned_ip, status, transport, kind)
VALUES ($1,$2,$3,'human','linux','BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=','10.99.0.11','suspended','wireguard','human')`, org, user, node); err == nil {
		t.Fatal("database allowed a human device to become suspended")
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT f01_suspended_guard`); err != nil {
		t.Fatal(err)
	}
	deviceID := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO devices (id, org_id, user_id, node_id, name, platform, public_key, assigned_ip, status, transport, kind)
VALUES ($1,$2,$3,$4,'agent','agent','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','10.99.0.10','active','wireguard','agent')`, deviceID, org, user, node); err != nil {
		t.Fatal(err)
	}
	if err := svc.q.EnsureAgentProfile(ctx, deviceID); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.q.ListActiveWireGuardPeersForNode(ctx, node); err != nil || len(got) != 1 {
		t.Fatalf("active agent peer missing: len=%d err=%v", len(got), err)
	}
	bad := "pending"
	_, err := svc.UpdateAgentProfileWithLifecycle(ctx, user, org, deviceID, "changed", "runtime", []byte(`{"team":"sec"}`), &bad)
	if code(err) != "invalid_agent_transition" {
		t.Fatalf("invalid lifecycle update code=%q err=%v", code(err), err)
	}
	profile, err := svc.q.GetAgentProfileForOrg(ctx, sqlc.GetAgentProfileForOrgParams{DeviceID: deviceID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Environment != "" || profile.Runtime != "" || string(profile.Labels) != "{}" {
		t.Fatalf("failed lifecycle request partially committed metadata: %+v", profile)
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET status='suspended' WHERE id=$1`, deviceID); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.q.ListActiveWireGuardPeersForNode(ctx, node); err != nil || len(got) != 0 {
		t.Fatalf("suspended agent still in peers: len=%d err=%v", len(got), err)
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET status='active' WHERE id=$1`, deviceID); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.q.ListActiveWireGuardPeersForNode(ctx, node); err != nil || len(got) != 1 {
		t.Fatalf("resumed agent did not return to peers: len=%d err=%v", len(got), err)
	}
}

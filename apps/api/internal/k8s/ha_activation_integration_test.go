package k8s

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestHASettingsAbsentFalseIsDurableNoOp(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	orgID, _, actorID := seedOrgSiteActor(t, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, orgID, actorID); err != nil {
		t.Fatal(err)
	}

	got, err := NewService(pool).SetHASettings(ctx, orgID, actorID, "already off", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled || got.Revision != 0 || got.ActualState != "disabled" {
		t.Fatalf("absent OFF must remain the revision-zero default, got %+v", got)
	}

	var settingsRows, auditRows int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM k8s_ha_settings WHERE org_id=$1),
		(SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.ha_setting_changed')`, orgID).Scan(&settingsRows, &auditRows); err != nil {
		t.Fatal(err)
	}
	if settingsRows != 0 || auditRows != 0 {
		t.Fatalf("absent OFF wrote settings=%d audits=%d; want 0/0", settingsRows, auditRows)
	}
}

func TestHARequestAuditsRecordExactOldAndNewState(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	orgID, siteID, actorID := seedOrgSiteActor(t, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, orgID, actorID); err != nil {
		t.Fatal(err)
	}
	clusterID, poolID, activeID, standbyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, nodeID := range []uuid.UUID{activeID, standbyID} {
		exec(`INSERT INTO nodes(id,org_id,site_id,name,cert_serial,agent_version,status)
			VALUES($1,$2,$3,$4,$5,'test','active')`, nodeID, orgID, siteID, "ha-"+nodeID.String()[:8], "ha-"+nodeID.String())
	}
	exec(`INSERT INTO k8s_clusters(id,org_id,site_id,name,vip_range,service_cidr,dns_zone,dns_vip)
		VALUES($1,$2,$3,'ha-audit','100.90.0.0/24','10.96.0.0/12','ha.test','100.90.0.2')`, clusterID, orgID, siteID)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_connector_pools(id,org_id,site_id,cluster_id,preferred_node_id,active_node_id,generation)
		VALUES($1,$2,$3,$4,$5,$5,1)`, poolID, orgID, siteID, clusterID, activeID); err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range []uuid.UUID{activeID, standbyID} {
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_connector_pool_members(pool_id,org_id,site_id,node_id) VALUES($1,$2,$3,$4)`, poolID, orgID, siteID, nodeID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE k8s_clusters SET connector_pool_id=$1 WHERE id=$2`, poolID, clusterID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO k8s_connector_pool_health_states(org_id,site_id,cluster_id,pool_id,membership_epoch,observed_active_node_id,observed_generation)
		VALUES($1,$2,$3,$4,0,$5,1)`, orgID, siteID, clusterID, poolID, activeID)

	service := NewService(pool)
	if _, err := service.SetHASettings(ctx, orgID, actorID, "enable audit proof", true, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetConnectorPoolHAMode(ctx, orgID, poolID, actorID, "pool audit proof", "fenced_ha", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHASettings(ctx, orgID, actorID, "disable audit proof", false, 1); err != nil {
		t.Fatal(err)
	}

	var exactSettings, exactPoolRequest, exactOptOut int
	if err := pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE action='k8s.ha_setting_changed'
		 AND metadata->>'old_enabled'='false' AND metadata->>'new_enabled'='true'
		 AND metadata->>'old_revision'='0' AND metadata->>'new_revision'='1'),
		count(*) FILTER (WHERE action='k8s.connector_pool_ha_mode_requested'
		 AND metadata->>'old_requested_mode'='legacy' AND metadata->>'new_requested_mode'='fenced_ha'
		 AND metadata->>'old_actual_mode'='legacy' AND metadata->>'new_actual_mode'='bootstrap_pending'
		 AND metadata->>'old_transition_revision'='0' AND metadata->>'new_transition_revision'='1'),
		count(*) FILTER (WHERE action='k8s.connector_pool_ha_mode_requested'
		 AND metadata->>'old_requested_mode'='fenced_ha' AND metadata->>'new_requested_mode'='legacy'
		 AND metadata->>'old_actual_mode'='bootstrap_pending' AND metadata->>'new_actual_mode'='drain_pending'
		 AND metadata->>'old_transition_revision'='1' AND metadata->>'new_transition_revision'='2')
		FROM audit_logs WHERE org_id=$1`, orgID).Scan(&exactSettings, &exactPoolRequest, &exactOptOut); err != nil {
		t.Fatal(err)
	}
	if exactSettings != 1 || exactPoolRequest != 1 || exactOptOut != 1 {
		t.Fatalf("exact audit counts settings=%d pool_request=%d opt_out=%d", exactSettings, exactPoolRequest, exactOptOut)
	}
}

func TestHAOptOutLeavesSettledLegacyPoolUntouched(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	orgID, siteID, actorID := seedOrgSiteActor(t, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, orgID, actorID); err != nil {
		t.Fatal(err)
	}
	nodeID, clusterID, poolID := uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO nodes(id,org_id,site_id,name,cert_serial,agent_version,status)
		VALUES($1,$2,$3,$4,$5,'test','active')`, nodeID, orgID, siteID,
		"settled-"+nodeID.String()[:8], "settled-"+nodeID.String())
	exec(`INSERT INTO k8s_clusters(id,org_id,site_id,name,vip_range,service_cidr,dns_zone,dns_vip)
		VALUES($1,$2,$3,'settled-legacy','100.91.0.0/24','10.96.0.0/12','legacy.test','100.91.0.2')`, clusterID, orgID, siteID)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_connector_pools(id,org_id,site_id,cluster_id,preferred_node_id,active_node_id,generation)
		VALUES($1,$2,$3,$4,$5,$5,1)`, poolID, orgID, siteID, clusterID, nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_connector_pool_members(pool_id,org_id,site_id,node_id)
		VALUES($1,$2,$3,$4)`, poolID, orgID, siteID, nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE k8s_clusters SET connector_pool_id=$1 WHERE id=$2`, poolID, clusterID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO k8s_connector_pool_ha_transitions
		(pool_id,org_id,site_id,cluster_id,requested_mode,actual_mode,active_node_id,promotion_generation,
		 transition_revision,reason_code,actor_user_id,cause,achieved_at)
		VALUES($1,$2,$3,$4,'legacy','legacy',$5,1,7,'legacy',$6,'settled fixture',now())`,
		poolID, orgID, siteID, clusterID, nodeID, actorID)

	service := NewService(pool)
	if _, err := service.SetHASettings(ctx, orgID, actorID, "enable before opt out", true, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHASettings(ctx, orgID, actorID, "disable without churn", false, 1); err != nil {
		t.Fatal(err)
	}

	var requested, actual, reason, cause string
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT requested_mode,actual_mode,transition_revision,reason_code,cause
		FROM k8s_connector_pool_ha_transitions WHERE pool_id=$1`, poolID).
		Scan(&requested, &actual, &revision, &reason, &cause); err != nil {
		t.Fatal(err)
	}
	if requested != "legacy" || actual != "legacy" || revision != 7 || reason != "legacy" || cause != "settled fixture" {
		t.Fatalf("settled legacy pool was rewritten: requested=%s actual=%s revision=%d reason=%s cause=%q",
			requested, actual, revision, reason, cause)
	}
	var poolAudits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs
		WHERE org_id=$1 AND target_type='k8s_connector_pool' AND target_id=$2
		  AND action='k8s.connector_pool_ha_mode_requested'`, orgID, poolID.String()).Scan(&poolAudits); err != nil {
		t.Fatal(err)
	}
	if poolAudits != 0 {
		t.Fatalf("settled legacy pool emitted %d opt-out audits; want 0", poolAudits)
	}
}

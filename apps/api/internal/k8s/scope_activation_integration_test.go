package k8s

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

func TestClusterScopeSettingDefaultOffRevisionAndSafeDisable(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	service := NewService(pool)
	orgID, _, actorID := seedOrgSiteActor(t, pool)
	actor := &authctx.Principal{
		UserID: actorID, EmailVerified: true, AuthMethod: authctx.AuthSSO,
	}

	setting, err := service.GetClusterScopeSetting(ctx, orgID, true)
	if err != nil {
		t.Fatal(err)
	}
	if setting.Enabled || setting.Effective || setting.Revision != 0 || setting.UpdatedAt != nil {
		t.Fatalf("missing setting must be default OFF at revision zero: %+v", setting)
	}

	_, err = service.SetClusterScopeSetting(ctx, orgID, actor, true, true, 0, "integration")
	assertScopeAPIError(t, err, http.StatusForbidden, "human_actor_required")
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, orgID, actorID); err != nil {
		t.Fatal(err)
	}

	// Writing OFF over the absent/default-OFF state is a true no-op: no row,
	// revision, or audit event is manufactured.
	setting, err = service.SetClusterScopeSetting(ctx, orgID, actor, true, false, 0, "integration")
	if err != nil {
		t.Fatal(err)
	}
	if setting.Enabled || setting.Revision != 0 || setting.UpdatedAt != nil {
		t.Fatalf("default-OFF no-op changed state: %+v", setting)
	}

	_, err = service.SetClusterScopeSetting(ctx, orgID, actor, false, true, 0, "integration")
	assertScopeAPIError(t, err, http.StatusForbidden, "edition_required")

	setting, err = service.SetClusterScopeSetting(ctx, orgID, actor, true, true, 0, "integration")
	if err != nil {
		t.Fatal(err)
	}
	if !setting.Enabled || !setting.Effective || setting.Revision != 1 || setting.UpdatedAt == nil {
		t.Fatalf("enabled setting = %+v", setting)
	}

	// Lost-response retry with the preceding expected revision is idempotent.
	retry, err := service.SetClusterScopeSetting(ctx, orgID, actor, true, true, 0, "integration")
	if err != nil {
		t.Fatal(err)
	}
	if retry.Revision != 1 || !retry.Enabled {
		t.Fatalf("enable retry = %+v", retry)
	}

	_, err = service.SetClusterScopeSetting(ctx, orgID, actor, true, false, 0, "integration")
	assertScopeAPIError(t, err, http.StatusConflict, "k8s_cluster_scope_revision_conflict")

	// Safe withdrawal stays available after entitlement loss.
	setting, err = service.SetClusterScopeSetting(ctx, orgID, actor, false, false, 1, "integration")
	if err != nil {
		t.Fatal(err)
	}
	if setting.Enabled || setting.Effective || setting.Revision != 2 {
		t.Fatalf("disabled setting = %+v", setting)
	}

	var rows, audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_cluster_scope_settings WHERE org_id=$1`, orgID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.cluster_scope_setting_changed'`, orgID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || audits != 2 {
		t.Fatalf("settings rows/audits = %d/%d, want 1/2", rows, audits)
	}
}

func TestDeregisterClusterRefusesTypedScopeCleanupBeforeAnyCascade(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	service := NewService(pool)
	orgID, siteID, actorID := seedOrgSiteActor(t, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, orgID, actorID); err != nil {
		t.Fatal(err)
	}
	cluster, err := service.RegisterCluster(ctx, orgID, siteID, "cleanup", pfx("100.70.0.0/24"), pfx("10.96.0.0/12"), "k8s.example.test", uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ruleID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO policy_rules(id,org_id,src_kind,src_cidr,dst_kind,dst_k8s_cluster_id) VALUES($1,$2,'cidr','10.20.0.0/24',$3,$4)`, ruleID, orgID, "k8s_cluster_scope", cluster.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_cluster_scope_grants(rule_id,org_id,cluster_id,created_by_user_id,initial_candidate_count,active,revision) VALUES($1,$2,$3,$4,0,true,1)`, ruleID, orgID, cluster.ID, actorID); err != nil {
		t.Fatal(err)
	}

	err = service.DeregisterCluster(ctx, actorID, "", "integration", orgID, cluster.ID)
	assertScopeAPIError(t, err, http.StatusConflict, "cluster_scope_cleanup_required")
	var clusters, scopes int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_clusters WHERE org_id=$1 AND id=$2`, orgID, cluster.ID).Scan(&clusters); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_cluster_scope_grants WHERE org_id=$1 AND cluster_id=$2`, orgID, cluster.ID).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if clusters != 1 || scopes != 1 {
		t.Fatalf("typed refusal mutated cluster/scope rows: %d/%d", clusters, scopes)
	}
	actor := &authctx.Principal{UserID: actorID, EmailVerified: true, AuthMethod: authctx.AuthSSO}
	if err := service.DeleteClusterScope(ctx, orgID, ruleID, actor, 1, "integration cleanup"); err != nil {
		t.Fatalf("explicit scope cleanup: %v", err)
	}
	var pending, approved, rejected int
	if err := pool.QueryRow(ctx, `SELECT
		(metadata->>'pending_deleted')::int,
		(metadata->>'approved_deleted')::int,
		(metadata->>'rejected_deleted')::int
		FROM audit_logs WHERE org_id=$1 AND action='k8s.cluster_scope_deleted' AND target_id=$2`, orgID, ruleID.String()).
		Scan(&pending, &approved, &rejected); err != nil {
		t.Fatal(err)
	}
	if pending != 0 || approved != 0 || rejected != 0 {
		t.Fatalf("scope delete audit counts = pending:%d approved:%d rejected:%d", pending, approved, rejected)
	}
	if err := service.DeregisterCluster(ctx, actorID, "", "integration", orgID, cluster.ID); err != nil {
		t.Fatalf("deregister after explicit scope cleanup: %v", err)
	}
}

package k8s

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type connectorPoolFixture struct {
	service                *Service
	orgID, siteID, actorID uuid.UUID
	clusterID              uuid.UUID
	activeID, standbyID    uuid.UUID
}

func seedConnectorPoolFixture(t *testing.T) connectorPoolFixture {
	t.Helper()
	pool := testPool(t)
	ctx := context.Background()
	orgID, siteID, actorID := seedOrgSiteActor(t, pool)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID) })

	activeID, standbyID, clusterID := uuid.New(), uuid.New(), uuid.New()
	for name, id := range map[string]uuid.UUID{"active": activeID, "standby": standbyID} {
		key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		if name == "standby" {
			key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
		}
		_, err := pool.Exec(ctx, `
INSERT INTO nodes (id, org_id, name, cert_serial, site_id, status, wg_public_key, endpoint)
VALUES ($1,$2,$3,$4,$5,'active',$6,$7)`,
			id, orgID, name+"-"+id.String()[:8], "pool-"+name+"-"+id.String()[:8], siteID,
			key, "198.51.100.1:51820")
		if err != nil {
			t.Fatalf("seed %s connector: %v", name, err)
		}
	}
	_, err := pool.Exec(ctx, `
INSERT INTO k8s_clusters (id, org_id, site_id, connector_node_id, name, vip_range)
VALUES ($1,$2,$3,$4,$5,'100.122.0.0/24')`, clusterID, orgID, siteID, activeID, "pool-"+clusterID.String()[:8])
	if err != nil {
		t.Fatalf("seed legacy cluster: %v", err)
	}
	return connectorPoolFixture{
		service: NewService(pool), orgID: orgID, siteID: siteID, actorID: actorID,
		clusterID: clusterID, activeID: activeID, standbyID: standbyID,
	}
}

func configureFixturePool(t *testing.T, f connectorPoolFixture) ConnectorPoolConfiguration {
	t.Helper()
	configured, err := f.service.ConfigureConnectorPool(context.Background(), f.orgID, f.siteID, ConfigureConnectorPoolRequest{
		ClusterID: f.clusterID,
		Members: []ConnectorPoolMemberConfiguration{
			{NodeID: f.activeID, AdminPriority: 10},
			{NodeID: f.standbyID, AdminPriority: 1},
		},
	}, f.actorID, "", "operator approved connector HA configuration")
	if err != nil {
		t.Fatalf("configure connector pool: %v", err)
	}
	return configured
}

func TestConnectorPoolConfigurationPostgres(t *testing.T) {
	f := seedConnectorPoolFixture(t)
	ctx := context.Background()
	configured := configureFixturePool(t, f)
	if configured.ActiveNodeID != f.activeID || configured.PreferredNodeID != f.activeID || configured.Generation != 1 {
		t.Fatalf("legacy ownership changed during pool bind: %+v", configured)
	}
	if !configured.MembershipEpochKnown || configured.MembershipEpoch != 0 || len(configured.Members) != 2 {
		t.Fatalf("initial pool membership state is not exact: %+v", configured)
	}

	var legacyPresent, poolPresent bool
	if err := f.service.pool.QueryRow(ctx, `
SELECT connector_node_id IS NOT NULL, connector_pool_id IS NOT NULL
FROM k8s_clusters WHERE id=$1`, f.clusterID).Scan(&legacyPresent, &poolPresent); err != nil {
		t.Fatal(err)
	}
	if legacyPresent || !poolPresent {
		t.Fatalf("cluster connector modes are ambiguous: legacy=%v pool=%v", legacyPresent, poolPresent)
	}

	read, err := f.service.GetConnectorPoolConfiguration(ctx, f.orgID, f.siteID, f.clusterID)
	if err != nil || read.PoolID != configured.PoolID || read.ActiveNodeID != configured.ActiveNodeID || len(read.Members) != 2 {
		t.Fatalf("pool read=%+v err=%v, configured=%+v", read, err, configured)
	}

	err = f.service.SetClusterConnector(ctx, f.orgID, f.clusterID, f.standbyID, f.actorID, "", "")
	var typed *apierr.Error
	if !errors.As(err, &typed) || typed.Code != "connector_pool_configured" {
		t.Fatalf("legacy setter err=%v, want connector_pool_configured", err)
	}

	var auditCount int
	var auditCause *string
	if err := f.service.pool.QueryRow(ctx, `
SELECT count(*), max(metadata->>'cause')
FROM audit_logs WHERE org_id=$1 AND action=$2`, f.orgID, connectorPoolConfigurationAuditAction).Scan(&auditCount, &auditCause); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("configuration audit count=%d, want 1", auditCount)
	}
	if auditCause == nil || *auditCause != "operator approved connector HA configuration" {
		t.Fatalf("human configuration cause=%v, want preserved cause", auditCause)
	}
}

func TestConnectorPoolMembershipEpochRejectsStaleConfiguration(t *testing.T) {
	f := seedConnectorPoolFixture(t)
	configured := configureFixturePool(t, f)
	epoch := configured.MembershipEpoch
	changed, err := f.service.ConfigureConnectorPool(context.Background(), f.orgID, f.siteID, ConfigureConnectorPoolRequest{
		ClusterID: f.clusterID,
		Members: []ConnectorPoolMemberConfiguration{
			{NodeID: f.activeID, AdminPriority: 10},
			{NodeID: f.standbyID, AdminPriority: 20},
		},
		ExpectedMembershipEpoch: &epoch,
	}, f.actorID, "", "priority update")
	if err != nil {
		t.Fatalf("change priority: %v", err)
	}
	if !changed.MembershipEpochKnown || changed.MembershipEpoch != epoch+1 {
		t.Fatalf("priority change epoch=%+v, want %d", changed, epoch+1)
	}
	if changed.ActiveNodeID != configured.ActiveNodeID || changed.Generation != configured.Generation {
		t.Fatalf("membership configuration changed ownership: before=%+v after=%+v", configured, changed)
	}

	_, err = f.service.ConfigureConnectorPool(context.Background(), f.orgID, f.siteID, ConfigureConnectorPoolRequest{
		ClusterID: f.clusterID,
		Members: []ConnectorPoolMemberConfiguration{
			{NodeID: f.activeID, AdminPriority: 10},
			{NodeID: f.standbyID, AdminPriority: 30},
		},
		ExpectedMembershipEpoch: &epoch,
	}, f.actorID, "", "stale priority update")
	var typed *apierr.Error
	if !errors.As(err, &typed) || typed.Code != "connector_pool_membership_epoch_conflict" {
		t.Fatalf("stale membership err=%v, want connector_pool_membership_epoch_conflict", err)
	}
}

func TestConnectorPoolMembershipEpochGuardsAddAndRemove(t *testing.T) {
	f := seedConnectorPoolFixture(t)
	configured := configureFixturePool(t, f)
	thirdID := uuid.New()
	if _, err := f.service.pool.Exec(context.Background(), `
INSERT INTO nodes (id, org_id, name, cert_serial, site_id, status, wg_public_key, endpoint)
VALUES ($1,$2,'third',$3,$4,'active','CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=','198.51.100.3:51820')`, thirdID, f.orgID, "pool-third-"+thirdID.String()[:8], f.siteID); err != nil {
		t.Fatalf("seed third connector: %v", err)
	}

	epoch0 := configured.MembershipEpoch
	added, err := f.service.ConfigureConnectorPool(context.Background(), f.orgID, f.siteID, ConfigureConnectorPoolRequest{
		ClusterID: f.clusterID,
		Members: []ConnectorPoolMemberConfiguration{
			{NodeID: f.activeID, AdminPriority: 10},
			{NodeID: f.standbyID, AdminPriority: 1},
			{NodeID: thirdID, AdminPriority: 0},
		},
		ExpectedMembershipEpoch: &epoch0,
	}, f.actorID, "", "add third connector")
	if err != nil || !added.MembershipEpochKnown || added.MembershipEpoch != epoch0+1 || len(added.Members) != 3 {
		t.Fatalf("add member result=%+v err=%v, want epoch %d and three members", added, err, epoch0+1)
	}

	epoch1 := added.MembershipEpoch
	removed, err := f.service.ConfigureConnectorPool(context.Background(), f.orgID, f.siteID, ConfigureConnectorPoolRequest{
		ClusterID: f.clusterID,
		Members: []ConnectorPoolMemberConfiguration{
			{NodeID: f.activeID, AdminPriority: 10},
			{NodeID: f.standbyID, AdminPriority: 1},
		},
		ExpectedMembershipEpoch: &epoch1,
	}, f.actorID, "", "remove third connector")
	if err != nil || removed.MembershipEpoch != epoch1+1 || len(removed.Members) != 2 {
		t.Fatalf("remove member result=%+v err=%v, want epoch %d and two members", removed, err, epoch1+1)
	}
	if removed.ActiveNodeID != configured.ActiveNodeID || removed.Generation != configured.Generation {
		t.Fatalf("add/remove changed ownership: before=%+v after=%+v", configured, removed)
	}

	_, err = f.service.ConfigureConnectorPool(context.Background(), f.orgID, f.siteID, ConfigureConnectorPoolRequest{
		ClusterID: f.clusterID,
		Members: []ConnectorPoolMemberConfiguration{
			{NodeID: f.activeID, AdminPriority: 10},
			{NodeID: f.standbyID, AdminPriority: 1},
			{NodeID: thirdID, AdminPriority: 0},
		},
		ExpectedMembershipEpoch: &epoch1,
	}, f.actorID, "", "stale add replay")
	var typed *apierr.Error
	if !errors.As(err, &typed) || typed.Code != "connector_pool_membership_epoch_conflict" {
		t.Fatalf("stale add replay err=%v, want connector_pool_membership_epoch_conflict", err)
	}
}

func TestPoolValidationDoesNotTightenLegacyConnectorContract(t *testing.T) {
	siteID := uuid.New()
	legacyShape := sqlc.Node{
		Status:      "active",
		SiteID:      pgtype.UUID{Bytes: siteID, Valid: true},
		WgPublicKey: "legacy-non-empty-key",
		Endpoint:    "   ",
	}
	if err := validateConnectorNode(legacyShape, siteID); err != nil {
		t.Fatalf("released legacy non-empty predicate changed: %v", err)
	}
	if err := validateConnectorPoolMemberNode(legacyShape, siteID); err == nil {
		t.Fatal("new pool member must require a valid WireGuard key and trimmed non-empty endpoint")
	}
}

func TestConnectorPoolConfigurationRollsBackAfterPostMutationFailure(t *testing.T) {
	f := seedConnectorPoolFixture(t)
	configured := configureFixturePool(t, f)
	epoch := configured.MembershipEpoch
	f.service.connectorPoolConfigurationAfterMutationHook = func() error { return errors.New("injected post-mutation failure") }

	_, err := f.service.ConfigureConnectorPool(context.Background(), f.orgID, f.siteID, ConfigureConnectorPoolRequest{
		ClusterID: f.clusterID,
		Members: []ConnectorPoolMemberConfiguration{
			{NodeID: f.activeID, AdminPriority: 10},
			{NodeID: f.standbyID, AdminPriority: 20},
		},
		ExpectedMembershipEpoch: &epoch,
	}, f.actorID, "", "must roll back")
	if err == nil || err.Error() != "injected post-mutation failure" {
		t.Fatalf("configuration error=%v, want injected rollback failure", err)
	}

	f.service.connectorPoolConfigurationAfterMutationHook = nil
	read, err := f.service.GetConnectorPoolConfiguration(context.Background(), f.orgID, f.siteID, f.clusterID)
	if err != nil {
		t.Fatalf("read after rollback: %v", err)
	}
	if read.MembershipEpoch != epoch || read.Members[1].AdminPriority != configured.Members[1].AdminPriority {
		t.Fatalf("post-mutation failure committed state: before=%+v after=%+v", configured, read)
	}
	var auditCount int
	if err := f.service.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action=$2`, f.orgID, connectorPoolConfigurationAuditAction).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("rolled-back configuration left audit count=%d, want original 1", auditCount)
	}
}

func TestPoolActiveConnectorEligibilityFailsClosedForEveryConsumerProjection(t *testing.T) {
	f := seedConnectorPoolFixture(t)
	configureFixturePool(t, f)
	ctx := context.Background()
	if _, err := f.service.pool.Exec(ctx, `UPDATE k8s_clusters SET dns_zone='cluster.test', dns_vip='100.122.0.2' WHERE id=$1`, f.clusterID); err != nil {
		t.Fatalf("seed cluster DNS: %v", err)
	}
	if _, err := f.service.pool.Exec(ctx, `
INSERT INTO k8s_services (org_id, cluster_id, name, namespace, protocol, port_low, port_high, vip)
VALUES ($2,$1,'api','default','tcp',443,443,'100.122.0.3')`, f.clusterID, f.orgID); err != nil {
		t.Fatalf("seed exposed service: %v", err)
	}

	assertProjection := func(t *testing.T, wantEligible bool) {
		t.Helper()
		rows, err := f.service.q.ListActiveK8sServicesForOrg(ctx, f.orgID)
		if err != nil || len(rows) != 1 {
			t.Fatalf("active service projection rows=%d err=%v", len(rows), err)
		}
		if rows[0].PoolConnectorEligible != wantEligible {
			t.Fatalf("pool active eligibility=%v, want %v", rows[0].PoolConnectorEligible, wantEligible)
		}
		zones, err := f.service.q.ListK8sServedZonesForOrg(ctx, f.orgID)
		if err != nil {
			t.Fatalf("served zones: %v", err)
		}
		wantZones := 0
		if wantEligible {
			wantZones = 1
		}
		if len(zones) != wantZones {
			t.Fatalf("served zones=%d, want %d", len(zones), wantZones)
		}
	}

	assertProjection(t, true)
	for name, invalidate := range map[string]string{
		"revoked status": `UPDATE nodes SET status='revoked' WHERE id=$1`,
		"revoked marker": `UPDATE nodes SET revoked_at=now() WHERE id=$1`,
		"malformed key":  `UPDATE nodes SET wg_public_key='malformed' WHERE id=$1`,
		"empty endpoint": `UPDATE nodes SET endpoint='   ' WHERE id=$1`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.service.pool.Exec(ctx, `UPDATE nodes SET status='active', revoked_at=NULL, wg_public_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', endpoint='198.51.100.1:51820' WHERE id=$1`, f.activeID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.pool.Exec(ctx, invalidate, f.activeID); err != nil {
				t.Fatal(err)
			}
			assertProjection(t, false)
		})
	}
}

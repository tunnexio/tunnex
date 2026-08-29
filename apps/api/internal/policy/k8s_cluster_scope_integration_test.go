package policy_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
)

// TestK8sClusterScopeLoweringFailClosed proves the S20.4 enforcement seam,
// not merely the pure approval model: a licensed, opted-in, active, approved
// exact child lowers to the existing k8s_service compiler input, while every
// independently authoritative OFF/currentness state removes it.
func TestK8sClusterScopeLoweringFailClosed(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}

	siteID, connectorID, clusterID := uuid.New(), uuid.New(), uuid.New()
	replayID, ledgerID, reportID := uuid.New(), uuid.New(), uuid.New()
	childID, pendingChildID, rejectedChildID, ruleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	exec(`UPDATE organizations SET zero_trust_mode='enforcing' WHERE id=$1`, f.org)
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'scope-site')`, siteID, f.org)
	exec(`INSERT INTO nodes(id,org_id,site_id,name,cert_serial,status,wg_public_key,endpoint)
		VALUES($1,$2,$3,'scope-connector',$4,'active','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','172.31.20.10:51820')`, connectorID, f.org, siteID, "scope-"+connectorID.String())
	exec(`INSERT INTO k8s_clusters(id,org_id,site_id,name,vip_range,connector_node_id)
		VALUES($1,$2,$3,'scope-cluster','100.70.0.0/16',$4)`, clusterID, f.org, siteID, connectorID)
	exec(`INSERT INTO k8s_service_uid_observation_replay_states
		(id,org_id,site_id,cluster_id,connector_node_id,scope_identity,sequence,digest)
		VALUES($1,$2,$3,$4,$5,'scope',1,$6)`, replayID, f.org, siteID, clusterID, connectorID, digest)
	exec(`INSERT INTO k8s_service_uid_observation_ledgers
		(id,org_id,site_id,cluster_id,scope_identity) VALUES($1,$2,$3,$4,'scope')`, ledgerID, f.org, siteID, clusterID)
	exec(`INSERT INTO k8s_service_uid_observation_current
		(ledger_id,org_id,namespace,service,uid,state,replay_sequence)
		VALUES($1,$2,'payments','ledger','uid-v1','live',1)`, ledgerID, f.org)
	exec(`INSERT INTO k8s_service_uid_observation_current_attributions
		(ledger_id,org_id,namespace,service,replay_state_id,replay_sequence)
		VALUES($1,$2,'payments','ledger',$3,1)`, ledgerID, f.org, replayID)
	exec(`INSERT INTO k8s_services
		(id,org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip)
		VALUES($1,$2,$3,'ledger','payments','tcp',8443,8443,'100.70.0.10')`, childID, f.org, clusterID)
	exec(`INSERT INTO k8s_services
		(id,org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip)
		VALUES($1,$2,$3,'ledger','payments','tcp',9443,9443,'100.70.0.10')`, pendingChildID, f.org, clusterID)
	exec(`INSERT INTO k8s_services
		(id,org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip)
		VALUES($1,$2,$3,'ledger','payments','udp',5353,5353,'100.70.0.10')`, rejectedChildID, f.org, clusterID)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `INSERT INTO k8s_service_inventory_reports
		(id,org_id,site_id,cluster_id,connector_node_id,replay_state_id,replay_sequence,promotion_generation,digest,service_count,observed_at,fresh_until)
		VALUES($1,$2,$3,$4,$5,$6,1,0,$7,1,now(),now()+interval '10 minutes')`, reportID, f.org, siteID, clusterID, connectorID, replayID, digest); err != nil {
		t.Fatal(err)
	}
	var inventoryRef uuid.UUID
	if err = tx.QueryRow(ctx, `INSERT INTO k8s_service_inventory_items
		(report_id,org_id,cluster_id,namespace,service,service_uid,port_count)
		VALUES($1,$2,$3,'payments','ledger','uid-v1',3) RETURNING inventory_ref`, reportID, f.org, clusterID).Scan(&inventoryRef); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO k8s_service_inventory_ports
		(report_id,inventory_ref,protocol,service_port,target_port)
		VALUES($1,$2,'tcp',8443,8443)`, reportID, inventoryRef); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO k8s_service_inventory_ports
		(report_id,inventory_ref,protocol,service_port,target_port)
		VALUES($1,$2,'tcp',9443,9443),($1,$2,'udp',5353,5353)`, reportID, inventoryRef); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	exec(`INSERT INTO k8s_cluster_scope_settings(org_id,enabled,actor_user_id,cause)
		VALUES($1,true,$2,'compiler integration')`, f.org, f.user)
	exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_user_id,dst_kind,dst_k8s_cluster_id)
		VALUES($1,$2,'user',$3,'k8s_cluster_scope',$4)`, ruleID, f.org, f.user, clusterID)
	exec(`INSERT INTO k8s_cluster_scope_grants
		(rule_id,org_id,cluster_id,created_by_user_id,initial_candidate_count,active)
		VALUES($1,$2,$3,$4,0,true)`, ruleID, f.org, clusterID, f.user)
	exec(`INSERT INTO k8s_cluster_scope_memberships
		(rule_id,org_id,cluster_id,service_child_id,namespace,service_uid,protocol,port_low,port_high,status,decided_by_user_id,decided_at,origin)
		VALUES($1,$2,$3,$4,'payments','uid-v1','tcp',8443,8443,'approved',$5,now(),'later')`, ruleID, f.org, clusterID, childID, f.user)
	exec(`INSERT INTO k8s_cluster_scope_memberships
		(rule_id,org_id,cluster_id,service_child_id,namespace,service_uid,protocol,port_low,port_high,status,origin)
		VALUES($1,$2,$3,$4,'payments','uid-v1','tcp',9443,9443,'pending','later')`, ruleID, f.org, clusterID, pendingChildID)
	exec(`INSERT INTO k8s_cluster_scope_memberships
		(rule_id,org_id,cluster_id,service_child_id,namespace,service_uid,protocol,port_low,port_high,status,decided_by_user_id,decided_at,origin)
		VALUES($1,$2,$3,$4,'payments','uid-v1','udp',5353,5353,'rejected',$5,now(),'later')`, ruleID, f.org, clusterID, rejectedChildID, f.user)

	assertAllowed := func(t *testing.T, entitled, want bool) {
		t.Helper()
		snapshot, err := policy.BuildSnapshotWithQueriesAndK8sClusterScopes(ctx, sqlc.New(pool), f.org, entitled)
		if err != nil {
			t.Fatal(err)
		}
		compiled := policy.Compile(snapshot)
		sourceAllows := allowsFor(compiled, f.node)
		got := hasAllow(sourceAllows, "10.99.0.10", "100.70.0.10/32") &&
			hasAllow(allowsFor(compiled, connectorID), "10.99.0.10", "100.70.0.10/32")
		if got != want {
			t.Fatalf("scope allow=%v want=%v; rules=%+v compiled=%+v", got, want, snapshot.Rules, compiled)
		}
		if want {
			serviceEntries := 0
			for _, entry := range sourceAllows {
				if entry.DstCIDR == "100.70.0.10/32" && (entry.RuleID != ruleID.String() || entry.Protocol != "tcp" || entry.PortLow != 8443 || entry.PortHigh != 8443) {
					t.Fatalf("lowering changed exact static-Service semantics: %+v", entry)
				}
				if entry.DstCIDR == "100.70.0.10/32" {
					serviceEntries++
				}
			}
			if serviceEntries != 1 {
				t.Fatalf("pending/rejected sibling ports widened the approved child: %+v", sourceAllows)
			}
		}
	}

	assertAllowed(t, true, true)
	assertAllowed(t, false, false)

	t.Run("organization opt-in off", func(t *testing.T) {
		exec(`UPDATE k8s_cluster_scope_settings SET enabled=false,cause='withdraw' WHERE org_id=$1`, f.org)
		assertAllowed(t, true, false)
		exec(`UPDATE k8s_cluster_scope_settings SET enabled=true,cause='restore' WHERE org_id=$1`, f.org)
	})
	t.Run("scope inactive", func(t *testing.T) {
		exec(`UPDATE k8s_cluster_scope_grants SET active=false WHERE rule_id=$1`, ruleID)
		assertAllowed(t, true, false)
		exec(`UPDATE k8s_cluster_scope_grants SET active=true WHERE rule_id=$1`, ruleID)
	})
	t.Run("rule disabled", func(t *testing.T) {
		exec(`UPDATE policy_rules SET disabled=true WHERE id=$1`, ruleID)
		assertAllowed(t, true, false)
		exec(`UPDATE policy_rules SET disabled=false WHERE id=$1`, ruleID)
	})
	t.Run("current UID attribution lost", func(t *testing.T) {
		exec(`DELETE FROM k8s_service_uid_observation_current_attributions
			WHERE ledger_id=$1 AND namespace='payments' AND service='ledger'`, ledgerID)
		assertAllowed(t, true, false)
		exec(`INSERT INTO k8s_service_uid_observation_current_attributions
			(ledger_id,org_id,namespace,service,replay_state_id,replay_sequence)
			VALUES($1,$2,'payments','ledger',$3,1)`, ledgerID, f.org, replayID)
	})
	t.Run("connector no longer active", func(t *testing.T) {
		exec(`UPDATE nodes SET status='revoked' WHERE id=$1`, connectorID)
		assertAllowed(t, true, false)
		exec(`UPDATE nodes SET status='active' WHERE id=$1`, connectorID)
	})

	// Sanity: the final restoration is live. This also catches subtests that
	// accidentally left a fail-closed condition behind.
	assertAllowed(t, true, true)
}

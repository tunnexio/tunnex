package db_test

import (
	"os"
	"strings"
	"testing"
)

// TestK8sClusterScopeMigrationContract keeps the additive 0086 patch honest
// while it is prepared in P3 before P2's consolidated 0079–0085 chain lands
// here.  The canonical replay owns the real PostgreSQL up/down/up execution;
// this source contract prevents a hand-merge from losing its identity,
// cardinality, or no-wildcard boundary.
func TestK8sClusterScopeMigrationContract(t *testing.T) {
	const migration = "migrations/0086_k8s_cluster_scope_approvals.up.sql"
	b, err := os.ReadFile(migration)
	if err != nil {
		t.Fatalf("read %s: %v", migration, err)
	}
	sql := string(b)
	for _, want := range []string{
		"follows the consolidated P1/P2 0079–0085 chain",
		"0080 supplies exact-port",
		"0084 supplies the authoritative Kubernetes Service UID ledger",
		"dst_kind IN ('resource', 'group', 'site', 'k8s_service', 'k8s_cluster_scope')",
		"CREATE TABLE k8s_cluster_scope_grants",
		"CREATE TABLE k8s_cluster_scope_memberships",
		"PRIMARY KEY (rule_id, service_child_id)",
		"service_uid",
		"protocol IN ('tcp', 'udp')",
		"port_high = port_low",
		"status IN ('pending', 'approved', 'rejected')",
		"k8s_cluster_scope_limit_reached",
		"k8s_cluster_scope_membership_limit_reached",
		"k8s_cluster_scope_pending_fanout_limit_reached",
		"k8s_cluster_scope_grant_require_rule",
		"k8s_cluster_scope_actor_require_org_membership",
		"k8s_cluster_scope_membership_require_live_identity",
		"k8s_service_uid_observation_current",
		"decision is immutable",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("%s must retain %q", migration, want)
		}
	}
	for _, forbidden := range []string{"namespace scope", "pod_cidr", "vpc_cidr", "kubernetes_api"} {
		if strings.Contains(strings.ToLower(sql), forbidden) {
			t.Fatalf("%s must not introduce %q", migration, forbidden)
		}
	}
}

// TestK8sClusterScopeOriginMigrationContract keeps 0087 immediately after the
// reviewed 0086 scope schema and makes legacy origin absence explicit rather
// than allowing a later replay to backfill or infer it.
func TestK8sClusterScopeOriginMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0087_k8s_cluster_scope_membership_origin.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0087_k8s_cluster_scope_membership_origin.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Existing 0086 rows deliberately remain NULL",
		"ADD COLUMN origin text CHECK (origin IN ('initial', 'later'))",
		"origin is required for new rows",
		"initial k8s cluster scope membership must be approved",
		"origin is immutable",
	} {
		if !strings.Contains(string(up), want) {
			t.Fatalf("0087 up migration must retain %q", want)
		}
	}
	for _, want := range []string{
		"origin IS NOT NULL",
		"cannot rollback 0087 with persisted cluster-scope membership origin data",
		"DROP COLUMN origin",
	} {
		if !strings.Contains(string(down), want) {
			t.Fatalf("0087 down migration must retain %q", want)
		}
	}
}

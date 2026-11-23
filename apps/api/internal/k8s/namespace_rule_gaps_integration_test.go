package k8s

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// K8N-4: the two fail-closed outcomes of a pass that had no test of their own.
//
//   - withdrawal_blocked for a Service that is GONE from the cluster (the exclusion case is covered in
//     namespace_rule_slices_integration_test.go): the exposure a rule made cannot be withdrawn while an
//     agent access request or an agent policy template version points at it.
//   - scope_review_limit: one Service whose ports would create more than 500 pending scope reviews makes
//     the pass expose none of the namespace's missing Services.
//
// Reports are seeded rows; nothing here needs a cluster.

// pendingAgentRequest makes a pending agent access request point at the exposure and returns its id.
func (f *nsRuleFixture) pendingAgentRequest(serviceID uuid.UUID) uuid.UUID {
	f.t.Helper()
	agent, request := uuid.New(), uuid.New()
	f.exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'agent',$5,'10.99.0.2','active','agent')`,
		agent, f.org, f.actor.UserID, f.node, "ns-agent-"+agent.String())
	f.exec(`INSERT INTO agent_access_requests (id,org_id,device_id,dst_kind,dst_k8s_service_id,reason,requested_duration_seconds,requested_by_user_id)
		VALUES ($1,$2,$3,'k8s_service',$4,'deploy',3600,$5)`, request, f.org, agent, serviceID, f.actor.UserID)
	return request
}

// withdrawals counts the audit entries of a completed withdrawal of one Service by the rule.
func (f *nsRuleFixture) withdrawals(name string) int {
	f.t.Helper()
	return f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.service_unexposed' AND actor_system=$2
		AND metadata->>'name'=$3 AND metadata->>'reason'=$4`, f.org, namespaceRuleActorSystem, name, namespaceRuleWithdrawNotReported)
}

func (f *nsRuleFixture) missingSince(serviceID uuid.UUID) *time.Time {
	f.t.Helper()
	var since *time.Time
	if err := f.pool.QueryRow(context.Background(), `SELECT missing_since FROM k8s_namespace_rule_exposures WHERE service_id=$1`, serviceID).Scan(&since); err != nil {
		f.t.Fatalf("the exposure lost its rule: %v", err)
	}
	return since
}

// A Service the rule exposed disappears from the cluster while a pending agent access request points at
// its exposure. After the wait the withdrawal is refused: the rule says so and names the Service, the
// exposure and its "missing since" mark stay, every later pass tries again, and the pass after the
// request is closed withdraws it.
func TestNamespaceRuleVanishedServicePinnedByAnAgentAccessRequestIsBlockedRetriedThenWithdrawn(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	f.report(0, nsSvc{"shop", "web", []int32{80}}, nsSvc{"shop", "api", []int32{8080}})
	if _, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor); err != nil {
		t.Fatal(err)
	}
	web := f.serviceID("web", 80)
	request := f.pendingAgentRequest(web)

	// shop/web is gone from the next report. Inside the wait it is only marked.
	start := time.Now().UTC()
	onlyAPI := nsSvc{"shop", "api", []int32{8080}}
	f.report(0, onlyAPI)
	f.reconcileAt(start)
	f.reconcileAt(start.Add(NamespaceRuleWithdrawWait - time.Minute))
	if rule := f.rule("shop"); rule.Status != NamespaceRuleOK || f.liveKeys() != "shop/api:8080=rule shop/web:80=rule" || f.missingSince(web) == nil {
		t.Fatalf("inside the wait: status=%q live=%q missing_since=%v", rule.Status, f.liveKeys(), f.missingSince(web))
	}

	// Past the wait the withdrawal is due and refused. Twice: a later pass tries again and says the same.
	for pass, at := range []time.Time{start.Add(NamespaceRuleWithdrawWait + time.Second), start.Add(NamespaceRuleWithdrawWait + time.Minute)} {
		f.report(0, onlyAPI)
		f.reconcileAt(at)
		rule := f.rule("shop")
		if rule.Status != NamespaceRuleWithdrawalBlocked {
			t.Fatalf("pass %d: status = %q (%q), want %q", pass, rule.Status, rule.StatusMessage, NamespaceRuleWithdrawalBlocked)
		}
		for _, want := range []string{"shop/web is gone from the cluster but its exposure cannot be withdrawn", "1 pending or approved agent access requests reference this Service"} {
			if !strings.Contains(rule.StatusMessage, want) {
				t.Fatalf("pass %d: the status must say %q, got %q", pass, want, rule.StatusMessage)
			}
		}
		if got := f.liveKeys(); got != "shop/api:8080=rule shop/web:80=rule" {
			t.Fatalf("pass %d: a refused withdrawal changed the exposures: %q", pass, got)
		}
		// Still the rule's, still marked with the first time it was missing: the next pass is due at once.
		if since := f.missingSince(web); since == nil || since.Sub(start).Abs() > time.Second {
			t.Fatalf("pass %d: missing_since = %v, want the first miss at %v", pass, since, start)
		}
		if rule.ExposedPorts != 2 || rule.WaitingServices != 0 || f.withdrawals("web") != 0 {
			t.Fatalf("pass %d: ports=%d waiting=%d audited withdrawals=%d", pass, rule.ExposedPorts, rule.WaitingServices, f.withdrawals("web"))
		}
	}

	// The request is closed. The same pass that was refused now withdraws the exposure.
	f.exec(`UPDATE agent_access_requests SET state='cancelled', cancelled_by_user_id=$2, cancelled_at=now() WHERE id=$1`, request, f.actor.UserID)
	f.report(0, onlyAPI)
	f.reconcileAt(start.Add(NamespaceRuleWithdrawWait + 2*time.Minute))
	rule := f.rule("shop")
	if rule.Status != NamespaceRuleOK || rule.StatusMessage != "" || rule.ExposedPorts != 1 {
		t.Fatalf("after the pin is gone: %+v", rule)
	}
	if got := f.liveKeys(); got != "shop/api:8080=rule" {
		t.Fatalf("after the pin is gone: %q", got)
	}
	if n := f.withdrawals("web"); n != 1 {
		t.Fatalf("audited withdrawals of web = %d, want exactly 1", n)
	}
	if n := f.count(`SELECT count(*) FROM k8s_services WHERE id=$1 AND deleted_at IS NOT NULL`, web); n != 1 {
		t.Fatalf("the exposure row must be kept, soft-deleted: %d", n)
	}
}

// The other pin: an agent policy template version. It blocks only the exposure it points at; another
// vanished Service of the same rule is withdrawn on the same pass, and the status still reports the block.
func TestNamespaceRuleVanishedServicePinnedByAnAgentTemplateBlocksOnlyThatExposure(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	f.report(0, nsSvc{"shop", "web", []int32{80}}, nsSvc{"shop", "api", []int32{8080}}, nsSvc{"shop", "cart", []int32{9000}})
	if _, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor); err != nil {
		t.Fatal(err)
	}
	web := f.serviceID("web", 80)
	f.blockWithdrawal(web)

	// web and api are both gone; only web is pinned.
	start := time.Now().UTC()
	onlyCart := nsSvc{"shop", "cart", []int32{9000}}
	f.report(0, onlyCart)
	f.reconcileAt(start)
	f.report(0, onlyCart)
	f.reconcileAt(start.Add(NamespaceRuleWithdrawWait + time.Second))
	rule := f.rule("shop")
	if rule.Status != NamespaceRuleWithdrawalBlocked ||
		!strings.Contains(rule.StatusMessage, "shop/web is gone from the cluster but its exposure cannot be withdrawn") ||
		!strings.Contains(rule.StatusMessage, "1 immutable agent policy template versions reference this Service") {
		t.Fatalf("blocked by a template: %q %q", rule.Status, rule.StatusMessage)
	}
	if got := f.liveKeys(); got != "shop/cart:9000=rule shop/web:80=rule" {
		t.Fatalf("only the pinned exposure may stay: %q", got)
	}
	if f.withdrawals("api") != 1 || f.withdrawals("web") != 0 {
		t.Fatalf("audited withdrawals api=%d web=%d, want 1 and 0", f.withdrawals("api"), f.withdrawals("web"))
	}

	// A later pass has nothing else to do and still reports the block: the status is not a one-off.
	f.report(0, onlyCart)
	f.reconcileAt(start.Add(NamespaceRuleWithdrawWait + time.Minute))
	if rule := f.rule("shop"); rule.Status != NamespaceRuleWithdrawalBlocked || f.liveKeys() != "shop/cart:9000=rule shop/web:80=rule" || f.missingSince(web) == nil {
		t.Fatalf("second pass: status=%q live=%q", rule.Status, f.liveKeys())
	}
	// If the Service comes back the block is moot: the mark is cleared and the rule is applied again.
	f.report(0, onlyCart, nsSvc{"shop", "web", []int32{80}})
	f.reconcileAt(start.Add(NamespaceRuleWithdrawWait + 2*time.Minute))
	if rule := f.rule("shop"); rule.Status != NamespaceRuleOK || f.missingSince(web) != nil || f.serviceID("web", 80) != web {
		t.Fatalf("after the Service returned: status=%q (%q) missing_since=%v", rule.Status, rule.StatusMessage, f.missingSince(web))
	}
}

// Sixteen active cluster scopes and a Service with 32 ports would create 512 pending scope reviews, more
// than the limit of 500. The pass exposes NONE of the namespace's missing Services, also not the small
// one it reached first, writes no review and no audit entry, and records why. Once the Service fits, the
// next pass exposes everything.
func TestNamespaceRuleScopeReviewLimitExposesNothingAndSaysWhy(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	const scopes = 16
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, f.org, f.actor.UserID)
	f.report(0, nsSvc{"billing", "ledger", []int32{5432}})
	if _, err := f.svc.SetClusterScopeSetting(ctx, f.org, f.actor, true, true, 0, "test"); err != nil {
		t.Fatal(err)
	}
	for i := range scopes {
		if _, err := f.svc.CreateClusterScope(ctx, CreateClusterScopeInput{OrgID: f.org, ClusterID: f.cluster,
			Source: ClusterScopeSource{Kind: "cidr", CIDR: fmt.Sprintf("10.200.%d.0/24", i)}, Actor: f.actor, EntitlementUnlocked: true, Cause: "test"}); err != nil {
			t.Fatalf("scope %d: %v", i, err)
		}
	}
	if n := f.count(`SELECT count(*) FROM k8s_cluster_scope_grants WHERE org_id=$1 AND cluster_id=$2 AND active`, f.org, f.cluster); n != scopes {
		t.Fatalf("active scopes = %d, want %d", n, scopes)
	}
	ports := func(n int) []int32 {
		out := make([]int32, n)
		for i := range out {
			out[i] = int32(8000 + i)
		}
		return out
	}
	if scopes*32 <= clusterScopePendingFanoutLimit || scopes*31 > clusterScopePendingFanoutLimit {
		t.Fatalf("fixture: %d scopes must exceed the limit of %d with 32 ports and fit with 31", scopes, clusterScopePendingFanoutLimit)
	}
	reviews := func() int {
		return f.count(`SELECT count(*) FROM k8s_cluster_scope_memberships m JOIN k8s_services s ON s.id=m.service_child_id WHERE m.org_id=$1 AND s.namespace='shop'`, f.org)
	}
	exposureAudits := func() int {
		return f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND actor_system=$2 AND target_type='k8s_service'`, f.org, namespaceRuleActorSystem)
	}

	// "api" sorts first and fits on its own (16 reviews); "wide" does not (512).
	billing := nsSvc{"billing", "ledger", []int32{5432}}
	f.report(0, billing, nsSvc{"shop", "api", []int32{8080}}, nsSvc{"shop", "wide", ports(32)})
	rule, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, NamespaceRuleInput{Namespace: "shop"}, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	for pass := range 2 {
		if rule.Status != NamespaceRuleScopeReviewLimit || rule.WaitingServices != 2 || rule.ExposedServices != 0 || rule.ExposedPorts != 0 {
			t.Fatalf("pass %d: rule = %+v", pass, rule)
		}
		for _, want := range []string{"shop/wide could not be exposed", "more than 500 pending scope reviews", "none of the 2 waiting Services in shop was exposed"} {
			if !strings.Contains(rule.StatusMessage, want) {
				t.Fatalf("pass %d: the status must say %q, got %q", pass, want, rule.StatusMessage)
			}
		}
		if live := f.live(); len(live) != 0 {
			t.Fatalf("pass %d: exposed despite the limit: %v", pass, live)
		}
		if n := f.count(`SELECT count(*) FROM k8s_services WHERE cluster_id=$1`, f.cluster); n != 0 {
			t.Fatalf("pass %d: %d exposure rows were written and kept", pass, n)
		}
		if reviews() != 0 || exposureAudits() != 0 {
			t.Fatalf("pass %d: scope reviews=%d audit entries=%d, want none", pass, reviews(), exposureAudits())
		}
		// The gateway's next report: the same pass, the same answer.
		f.report(0, billing, nsSvc{"shop", "api", []int32{8080}}, nsSvc{"shop", "wide", ports(32)})
		if err := f.svc.ReconcileNamespaceRulesForOrg(ctx, f.org); err != nil {
			t.Fatal(err)
		}
		rule = f.rule("shop")
	}

	// One port fewer and the whole namespace fits (16 + 496 reviews, each Service under the limit).
	f.report(0, billing, nsSvc{"shop", "api", []int32{8080}}, nsSvc{"shop", "wide", ports(31)})
	if err := f.svc.ReconcileNamespaceRulesForOrg(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	rule = f.rule("shop")
	if rule.Status != NamespaceRuleOK || rule.StatusMessage != "" || rule.WaitingServices != 0 || rule.ExposedServices != 2 || rule.ExposedPorts != 32 {
		t.Fatalf("once it fits: %+v", rule)
	}
	if n := f.count(`SELECT count(*) FROM k8s_cluster_scope_memberships m JOIN k8s_services s ON s.id=m.service_child_id
		WHERE m.org_id=$1 AND s.namespace='shop' AND m.status='pending'`, f.org); n != scopes*32 {
		t.Fatalf("pending scope reviews = %d, want one per exposed port per scope (%d)", n, scopes*32)
	}
}

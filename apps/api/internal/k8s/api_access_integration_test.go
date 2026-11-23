package k8s

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

// K8N-3 stage 1 database proof. Nothing here needs a cluster: the gateway's reports are seeded rows.

func (f *nsRuleFixture) apiAudits(action string) int {
	f.t.Helper()
	return f.count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action=$2 AND target_id=$3`, f.org, action, f.cluster.String())
}

func (f *nsRuleFixture) legacyAPIServerExposure() uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	f.exec(`INSERT INTO k8s_services(id,org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip) VALUES($1,$2,$3,'kubernetes','default','tcp',443,443,'100.66.0.200')`, id, f.org, f.cluster)
	return id
}

func TestAPIAccessIsOffByDefaultAndEnablingAllocatesOneAuditedAddress(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	f.exec(`UPDATE k8s_clusters SET dns_vip='100.66.0.2', dns_zone='k8s.acme.com' WHERE id=$1`, f.cluster)

	state, err := f.svc.GetAPIAccess(ctx, f.org, f.cluster)
	if err != nil {
		t.Fatal(err)
	}
	if state.Enabled || state.VIP != "" || state.EndpointID != uuid.Nil || state.RuleCount != 0 || state.Port != 443 ||
		state.FQDN != "kubernetes.default.svc.prod.k8s.acme.com" {
		t.Fatalf("API access must be off by default and already know its name: %+v", state)
	}

	// A Service already holds the first free address; the API must get another one, never the DNS address.
	if _, err := f.svc.ExposeService(ctx, f.org, f.cluster, "web", "shop", "tcp", p32(80), p32(80), uuid.Nil, f.actor.UserID, "", ""); err != nil {
		t.Fatal(err)
	}
	state, err = f.svc.SetAPIAccess(ctx, f.org, f.cluster, true, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Enabled || state.EndpointID == uuid.Nil || state.EnabledAt == nil {
		t.Fatalf("enabled state = %+v", state)
	}
	vip := netip.MustParseAddr(state.VIP)
	if !netip.MustParsePrefix("100.66.0.0/24").Contains(vip) || state.VIP == "100.66.0.2" {
		t.Fatalf("the API address must come from the cluster's range and never be the DNS address: %s", state.VIP)
	}
	if n := f.count(`SELECT count(*) FROM k8s_services WHERE cluster_id=$1 AND deleted_at IS NULL AND host(vip)=$2`, f.cluster, state.VIP); n != 0 {
		t.Fatalf("the API address %s is also a Service's", state.VIP)
	}
	// The API is NOT a k8s_services row: that is what keeps it out of scopes and agent access.
	if n := f.count(`SELECT count(*) FROM k8s_services WHERE cluster_id=$1 AND namespace='default' AND name='kubernetes'`, f.cluster); n != 0 {
		t.Fatalf("API access created %d exposed-Service rows", n)
	}
	if n := f.apiAudits("k8s.api_access_enabled"); n != 1 {
		t.Fatalf("enable audit entries = %d, want 1", n)
	}
	var actor uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT actor_user_id FROM audit_logs WHERE org_id=$1 AND action='k8s.api_access_enabled'`, f.org).Scan(&actor); err != nil || actor != f.actor.UserID {
		t.Fatalf("the enable entry must name the person: %v %v", actor, err)
	}
	// Enabling grants nothing: no rule exists until someone writes one.
	if n := f.count(`SELECT count(*) FROM policy_rules WHERE org_id=$1`, f.org); n != 0 {
		t.Fatalf("enabling API access created %d rules", n)
	}

	// Asking for the state it is already in changes nothing and writes nothing.
	again, err := f.svc.SetAPIAccess(ctx, f.org, f.cluster, true, f.actor)
	if err != nil || again.VIP != state.VIP || f.apiAudits("k8s.api_access_enabled") != 1 {
		t.Fatalf("re-enabling must be a no-op: %+v err=%v audits=%d", again, err, f.apiAudits("k8s.api_access_enabled"))
	}

	// A Service exposed afterwards is never handed the API's address.
	next, err := f.svc.ExposeService(ctx, f.org, f.cluster, "api", "shop", "tcp", p32(8080), p32(8080), uuid.Nil, f.actor.UserID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if next.Vip.String() == state.VIP || next.Vip.String() == "100.66.0.2" {
		t.Fatalf("a Service was handed a reserved address: %s", next.Vip)
	}
	// And the database refuses it even if the allocator were wrong.
	if _, err := f.pool.Exec(ctx, `INSERT INTO k8s_services(org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip) VALUES($1,$2,'rogue','shop','tcp',9,9,$3::inet)`, f.org, f.cluster, state.VIP); err == nil {
		t.Fatal("a Service row at the API's address must be refused by the database")
	}

	// A rule exists; turning API access off keeps it and gives the address back.
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, f.org, f.actor.UserID)
	f.exec(`INSERT INTO policy_rules(org_id,src_kind,src_user_id,dst_kind,dst_k8s_api_endpoint_id) VALUES($1,'user',$2,'k8s_api',$3)`, f.org, f.actor.UserID, state.EndpointID)
	off, err := f.svc.SetAPIAccess(ctx, f.org, f.cluster, false, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	if off.Enabled || off.VIP != "" || off.RuleCount != 1 || off.EndpointID != state.EndpointID || off.EnabledAt != nil {
		t.Fatalf("off state = %+v", off)
	}
	if n := f.apiAudits("k8s.api_access_disabled"); n != 1 {
		t.Fatalf("disable audit entries = %d, want 1", n)
	}
	if n := f.count(`SELECT count(*) FROM policy_rules WHERE org_id=$1 AND dst_kind='k8s_api'`, f.org); n != 1 {
		t.Fatalf("turning API access off must keep its rules, have %d", n)
	}
	if _, err := f.svc.SetAPIAccess(ctx, f.org, f.cluster, false, f.actor); err != nil || f.apiAudits("k8s.api_access_disabled") != 1 {
		t.Fatalf("re-disabling must be a no-op: err=%v", err)
	}
	// On again: the same endpoint, so the kept rule takes effect again.
	on, err := f.svc.SetAPIAccess(ctx, f.org, f.cluster, true, f.actor)
	if err != nil || !on.Enabled || on.EndpointID != state.EndpointID || on.RuleCount != 1 {
		t.Fatalf("re-enable = %+v err=%v", on, err)
	}
}

func TestAPIAccessNeedsAVerifiedHumanAndTheRightOrganization(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()

	machine := &authctx.Principal{MachineID: uuid.New(), OwnerUserID: f.actor.UserID, EmailVerified: true}
	if !machine.IsMachine() {
		t.Fatal("fixture: the machine principal must read as a machine")
	}
	_, err := f.svc.SetAPIAccess(ctx, f.org, f.cluster, true, machine)
	assertScopeAPIError(t, err, http.StatusForbidden, "human_actor_required")
	_, err = f.svc.SetAPIAccess(ctx, f.org, f.cluster, true, nil)
	assertScopeAPIError(t, err, http.StatusForbidden, "human_actor_required")
	_, err = f.svc.SetAPIAccess(ctx, f.org, f.cluster, true, &authctx.Principal{UserID: f.actor.UserID, AuthMethod: authctx.AuthSSO})
	assertScopeAPIError(t, err, http.StatusForbidden, "email_not_verified")

	// Another organization's cluster does not exist for this one, to read or to change.
	other := newNSRuleFixture(t, "100.67.0.0/24")
	_, err = f.svc.SetAPIAccess(ctx, f.org, other.cluster, true, f.actor)
	assertScopeAPIError(t, err, http.StatusNotFound, "cluster_not_found")
	_, err = f.svc.GetAPIAccess(ctx, f.org, other.cluster)
	assertScopeAPIError(t, err, http.StatusNotFound, "cluster_not_found")
	if n := f.count(`SELECT count(*) FROM k8s_api_endpoints`); n != 0 && f.count(`SELECT count(*) FROM k8s_api_endpoints WHERE cluster_id=ANY($1::uuid[])`, []uuid.UUID{f.cluster, other.cluster}) != 0 {
		t.Fatal("a refused request must not create an endpoint")
	}
}

func TestAPIServerIsRefusedAsAnOrdinaryExposureEverywhere(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, f.org, f.actor.UserID)
	f.report(0, nsSvc{"default", "kubernetes", []int32{443}}, nsSvc{"default", "web", []int32{80}}, nsSvc{"shop", "kubernetes", []int32{443}})

	// 1. The exposure verb (dashboard API, CLI, operator).
	_, err := f.svc.ExposeService(ctx, f.org, f.cluster, "kubernetes", "default", "tcp", p32(443), p32(443), uuid.Nil, f.actor.UserID, "", "")
	assertScopeAPIError(t, err, http.StatusBadRequest, "k8s_api_server_not_a_service")
	// A Service that only shares the name, in another namespace, is an ordinary Service.
	if _, err := f.svc.ExposeService(ctx, f.org, f.cluster, "kubernetes", "shop", "tcp", p32(443), p32(443), uuid.Nil, f.actor.UserID, "", ""); err != nil {
		t.Fatalf("shop/kubernetes is an ordinary Service: %v", err)
	}

	// 2. The inventory the Expose dialog lists leaves it out.
	page, err := f.svc.ListClusterScopeInventory(ctx, f.org, f.cluster, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, item := range page.Items {
		listed[item.Namespace+"/"+item.Service] = true
	}
	if listed["default/kubernetes"] || !listed["default/web"] || !listed["shop/kubernetes"] {
		t.Fatalf("inventory candidates = %v; default/kubernetes must be absent and nothing else", listed)
	}

	// 3. A reference to it obtained another way is refused by the inventory exposure path.
	var ref, portRef uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT i.inventory_ref,p.port_ref FROM k8s_service_inventory_items i JOIN k8s_service_inventory_ports p ON p.report_id=i.report_id AND p.inventory_ref=i.inventory_ref
		WHERE i.cluster_id=$1 AND i.namespace='default' AND i.service='kubernetes' ORDER BY i.created_at DESC LIMIT 1`, f.cluster).Scan(&ref, &portRef); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.ExposeInventoryService(ctx, ExposeInventoryServiceInput{OrgID: f.org, ClusterID: f.cluster, InventoryRef: ref, PortRefs: []uuid.UUID{portRef}, Actor: f.actor, Cause: "test"})
	assertScopeAPIError(t, err, http.StatusBadRequest, "k8s_api_server_not_a_service")

	// 4. A namespace rule for default exposes the namespace's other Services and never the API server.
	rule, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, "default", f.actor)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Status != NamespaceRuleOK || rule.ExposedServices != 1 || rule.WaitingServices != 0 {
		t.Fatalf("the rule must be fully applied with one Service, got %+v", rule)
	}
	if got := f.liveKeys(); got != "default/web:80=rule shop/kubernetes:443=manual" {
		t.Fatalf("live exposures = %q; default/kubernetes must never be exposed", got)
	}
	f.report(0, nsSvc{"default", "kubernetes", []int32{443}}, nsSvc{"default", "web", []int32{80}})
	f.reconcileAt(time.Now().UTC().Add(time.Hour))
	if n := f.count(`SELECT count(*) FROM k8s_services WHERE cluster_id=$1 AND namespace='default' AND name='kubernetes'`, f.cluster); n != 0 {
		t.Fatalf("a later pass exposed the API server (%d rows)", n)
	}
}

// Founder ruling 2026-11-23: an exposure of default/kubernetes that already exists is left in place and
// not converted. It keeps its row, its address, its rule, its namespace-rule ownership and its place in
// the lists; only NEW ones are refused.
func TestAnExistingAPIServerExposureSurvives(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, f.org, f.actor.UserID)
	legacy := f.legacyAPIServerExposure()
	grant := uuid.New()
	f.exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_user_id,dst_kind,dst_k8s_service_id) VALUES($1,$2,'user',$3,'k8s_service',$4)`, grant, f.org, f.actor.UserID, legacy)

	// A namespace rule that owns it (as a rule made before the refusal would) keeps it through passes,
	// however long the wait has run, because the Service is still reported.
	f.report(0, nsSvc{"default", "kubernetes", []int32{443}})
	rule, err := f.svc.CreateNamespaceRule(ctx, f.org, f.cluster, "default", f.actor)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO k8s_namespace_rule_exposures(service_id,org_id,rule_id) VALUES($1,$2,$3)`, legacy, f.org, rule.ID)
	now := time.Now().UTC()
	f.report(0, nsSvc{"default", "kubernetes", []int32{443}})
	f.reconcileAt(now)
	f.report(0, nsSvc{"default", "kubernetes", []int32{443}})
	f.reconcileAt(now.Add(3 * NamespaceRuleWithdrawWait))

	var vip string
	var deleted bool
	if err := f.pool.QueryRow(ctx, `SELECT host(vip), deleted_at IS NOT NULL FROM k8s_services WHERE id=$1`, legacy).Scan(&vip, &deleted); err != nil {
		t.Fatal(err)
	}
	if deleted || vip != "100.66.0.200" {
		t.Fatalf("the existing exposure was touched: deleted=%v vip=%s", deleted, vip)
	}
	if n := f.count(`SELECT count(*) FROM policy_rules WHERE id=$1 AND dst_k8s_service_id=$2 AND NOT disabled`, grant, legacy); n != 1 {
		t.Fatal("the rule that points at the existing exposure was touched")
	}
	if n := f.count(`SELECT count(*) FROM k8s_namespace_rule_exposures WHERE service_id=$1 AND missing_since IS NULL`, legacy); n != 1 {
		t.Fatal("the namespace rule's ownership of the existing exposure was touched")
	}
	views, err := f.svc.ListServicesForCluster(ctx, f.org, f.cluster)
	if err != nil || len(views) != 1 || views[0].Svc.ID != legacy || views[0].FQDN != "kubernetes.default.svc.prod."+views[0].Zone {
		t.Fatalf("the existing exposure must still be listed: %+v err=%v", views, err)
	}
	live, err := f.svc.LiveServiceIDs(ctx, f.org)
	if err != nil || !live[legacy] {
		t.Fatalf("the existing exposure must still be live for its rule: %v err=%v", live, err)
	}

	// It is not converted either: API access reports it and refuses to turn on beside it.
	state, err := f.svc.GetAPIAccess(ctx, f.org, f.cluster)
	if err != nil || !state.OrdinaryExposure || state.Enabled {
		t.Fatalf("state = %+v err=%v", state, err)
	}
	_, err = f.svc.SetAPIAccess(ctx, f.org, f.cluster, true, f.actor)
	assertScopeAPIError(t, err, http.StatusConflict, "k8s_api_ordinary_exposure_exists")
	if n := f.count(`SELECT count(*) FROM k8s_api_endpoints WHERE cluster_id=$1`, f.cluster); n != 0 {
		t.Fatal("a refused enable must not leave an endpoint")
	}

	// The administrator can still remove it by removing the rule that owns it, and then turn API access on.
	if err := f.svc.DeleteNamespaceRule(ctx, f.org, f.cluster, rule.ID, true, f.actor); err != nil {
		t.Fatal(err)
	}
	if state, err = f.svc.SetAPIAccess(ctx, f.org, f.cluster, true, f.actor); err != nil || !state.Enabled {
		t.Fatalf("after the ordinary exposure is gone API access turns on: %+v err=%v", state, err)
	}
}

func TestANewClusterScopeNeverOffersTheAPIServer(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, f.org, f.actor.UserID)
	legacy := f.legacyAPIServerExposure()
	f.report(0, nsSvc{"default", "kubernetes", []int32{443}}, nsSvc{"shop", "web", []int32{80}})
	if _, err := f.svc.ExposeService(ctx, f.org, f.cluster, "web", "shop", "tcp", p32(80), p32(80), uuid.Nil, f.actor.UserID, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetClusterScopeSetting(ctx, f.org, f.actor, true, true, 0, "test"); err != nil {
		t.Fatal(err)
	}
	scope, err := f.svc.CreateClusterScope(ctx, CreateClusterScopeInput{OrgID: f.org, ClusterID: f.cluster,
		Source: ClusterScopeSource{Kind: "user", ID: f.actor.UserID}, Actor: f.actor, EntitlementUnlocked: true, Cause: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM k8s_cluster_scope_initial_candidates WHERE rule_id=$1`, scope.RuleID); n != 1 {
		t.Fatalf("scope candidates = %d, want only shop/web", n)
	}
	if n := f.count(`SELECT count(*) FROM k8s_cluster_scope_initial_candidates WHERE rule_id=$1 AND service_child_id=$2`, scope.RuleID, legacy); n != 0 {
		t.Fatal("the API server is a scope candidate")
	}
	// Naming it explicitly as an initial member is refused: it is not among the scope's candidates.
	if _, err := f.svc.CreateClusterScope(ctx, CreateClusterScopeInput{OrgID: f.org, ClusterID: f.cluster,
		Source: ClusterScopeSource{Kind: "group", ID: uuid.New()}, InitialChildIDs: []uuid.UUID{legacy}, Actor: f.actor, EntitlementUnlocked: true, Cause: "test"}); err == nil {
		t.Fatal("a scope must not be creatable with the API server as a member")
	}
	if n := f.count(`SELECT count(*) FROM k8s_cluster_scope_memberships WHERE org_id=$1 AND service_child_id=$2`, f.org, legacy); n != 0 {
		t.Fatal("the API server became a scope member")
	}
}

func TestAPIAccessRefusesAConnectorPoolAndAFullRange(t *testing.T) {
	// /30 has one usable address after the network and gateway addresses: the first exposure takes it.
	f := newNSRuleFixture(t, "100.66.0.0/30")
	ctx := context.Background()
	if _, err := f.svc.ExposeService(ctx, f.org, f.cluster, "web", "shop", "tcp", p32(80), p32(80), uuid.Nil, f.actor.UserID, "", ""); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.SetAPIAccess(ctx, f.org, f.cluster, true, f.actor)
	assertScopeAPIError(t, err, http.StatusConflict, "vip_range_exhausted")
	if n := f.count(`SELECT count(*) FROM k8s_api_endpoints WHERE cluster_id=$1`, f.cluster) + f.apiAudits("k8s.api_access_enabled"); n != 0 {
		t.Fatal("a refused enable must leave no endpoint and no audit entry")
	}

	// A cluster served by a connector pool: refused, and the mirror — a pool cannot be configured while
	// API access is on.
	pooled := seedConnectorPoolFixture(t)
	human := &authctx.Principal{UserID: pooled.actorID, EmailVerified: true, AuthMethod: authctx.AuthSSO}
	if state, err := pooled.service.SetAPIAccess(ctx, pooled.orgID, pooled.clusterID, true, human); err != nil || !state.Enabled {
		t.Fatalf("a single-gateway cluster turns API access on: %+v err=%v", state, err)
	}
	_, err = pooled.service.ConfigureConnectorPool(ctx, pooled.orgID, pooled.siteID, ConfigureConnectorPoolRequest{
		ClusterID: pooled.clusterID,
		Members:   []ConnectorPoolMemberConfiguration{{NodeID: pooled.activeID, AdminPriority: 10}, {NodeID: pooled.standbyID, AdminPriority: 1}},
	}, pooled.actorID, "", "operator approved connector HA configuration")
	assertScopeAPIError(t, err, http.StatusConflict, "k8s_api_access_enabled")
	if _, err := pooled.service.SetAPIAccess(ctx, pooled.orgID, pooled.clusterID, false, human); err != nil {
		t.Fatal(err)
	}
	configureFixturePool(t, pooled)
	_, err = pooled.service.SetAPIAccess(ctx, pooled.orgID, pooled.clusterID, true, human)
	assertScopeAPIError(t, err, http.StatusConflict, "k8s_api_connector_pool_unsupported")
}

func TestResolveAPIDestination(t *testing.T) {
	f := newNSRuleFixture(t, "100.66.0.0/24")
	ctx := context.Background()
	f.exec(`UPDATE k8s_clusters SET dns_zone='k8s.acme.com' WHERE id=$1`, f.cluster)

	// By name while off: recognised, so "Test access" can say it is off rather than "unknown host".
	got, ok, err := f.svc.ResolveAPIDestination(ctx, f.org, "Kubernetes.default.svc.prod.k8s.acme.com.")
	if err != nil || !ok || got.Enabled || got.VIP != "" || got.ClusterID != f.cluster || got.ClusterName != "prod" || got.ConnectorNodeID != f.node {
		t.Fatalf("by name while off = %+v ok=%v err=%v", got, ok, err)
	}
	state, err := f.svc.SetAPIAccess(ctx, f.org, f.cluster, true, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"kubernetes.default.svc.prod.k8s.acme.com", state.VIP} {
		got, ok, err = f.svc.ResolveAPIDestination(ctx, f.org, destination)
		if err != nil || !ok || !got.Enabled || got.VIP != state.VIP {
			t.Fatalf("%q while on = %+v ok=%v err=%v", destination, got, ok, err)
		}
	}
	for _, destination := range []string{"web.shop.svc.prod.k8s.acme.com", "kubernetes.default.svc.other.k8s.acme.com", "100.66.0.250", "10.0.0.1", ""} {
		if _, ok, err := f.svc.ResolveAPIDestination(ctx, f.org, destination); err != nil || ok {
			t.Fatalf("%q must not be recognised as a cluster API (ok=%v err=%v)", destination, ok, err)
		}
	}
	// Another organization never sees this cluster's API, by name or by address.
	other := newNSRuleFixture(t, "100.67.0.0/24")
	for _, destination := range []string{"kubernetes.default.svc.prod.k8s.acme.com", state.VIP} {
		if got, ok, err := other.svc.ResolveAPIDestination(ctx, other.org, destination); err != nil || (ok && got.ClusterID == f.cluster) {
			t.Fatalf("cross-organization resolution of %q: %+v ok=%v err=%v", destination, got, ok, err)
		}
	}
}

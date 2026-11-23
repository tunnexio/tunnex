package controllers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	tunnexv1 "github.com/tunnexio/tunnex/apps/operator/api/v1alpha1"
	cpapi "github.com/tunnexio/tunnex/apps/operator/internal/cp"
)

// K8L-8: Ready must mean "what this resource declares is live", and a resource must only ever remove what
// it created.

func readyCluster() *tunnexv1.TunnexCluster {
	return &tunnexv1.TunnexCluster{
		ObjectMeta: managedMeta("ns", "prod-cluster"),
		Status:     tunnexv1.TunnexClusterStatus{ClusterID: "clu-1"},
	}
}

func exposure(name string, port int32, serviceID string) *tunnexv1.TunnexExposedService {
	meta := managedMeta("ns", name)
	meta.UID = types.UID("uid-" + name)
	return &tunnexv1.TunnexExposedService{
		ObjectMeta: meta,
		Spec:       tunnexv1.TunnexExposedServiceSpec{Cluster: "prod-cluster", Namespace: "prod", Service: "api", Protocol: "tcp", Port: port},
		Status:     tunnexv1.TunnexExposedServiceStatus{ServiceID: serviceID},
	}
}

func row(id string, port int, managed bool) map[string]any {
	return map[string]any{"id": id, "cluster_id": "clu-1", "namespace": "prod", "name": "api", "protocol": "tcp",
		"port_low": port, "port_high": port, "vip": "100.64.0.9", "fqdn": "api.prod.svc.prod.k8s.acme.com", "managed_by_operator": managed}
}

func getExposure(t *testing.T, r *TunnexExposedServiceReconciler, name string) tunnexv1.TunnexExposedService {
	t.Helper()
	var got tunnexv1.TunnexExposedService
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: name}, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// Port 80 is already exposed by another resource. A resource for port 443 of the SAME Service must make its
// own exposure, not adopt port 80's row and call itself Ready.
func TestSecondPortOfAServiceIsExposedNotAdopted(t *testing.T) {
	var posted map[string]any
	cp := testCP(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/k8s/services"):
			json.NewEncoder(w).Encode([]map[string]any{row("svc-80", 80, true)})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/services"):
			json.NewDecoder(r.Body).Decode(&posted)
			json.NewEncoder(w).Encode(row("svc-443", 443, true))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	r := &TunnexExposedServiceReconciler{Client: fakeK8s(t, readyCluster(), exposure("api-http", 80, "svc-80"), exposure("api-https", 443, "")), CP: cp}
	res, err := r.Reconcile(context.Background(), req("ns", "api-https"))
	if err != nil {
		t.Fatal(err)
	}
	if posted == nil || posted["port_low"] != float64(443) {
		t.Fatalf("port 443 was not exposed: %v", posted)
	}
	got := getExposure(t, r, "api-https")
	if got.Status.ServiceID != "svc-443" {
		t.Fatalf("adopted the wrong exposure: %q", got.Status.ServiceID)
	}
	if c := readyCond(t, got.Status.Conditions); c == nil || c.Status != metav1.ConditionTrue || res.RequeueAfter != resyncReady {
		t.Fatalf("want Ready and a periodic re-check, got %+v res=%+v", c, res)
	}
}

// Editing the port of a live exposure cannot be applied. It must not read as Ready, and must not expose or
// unexpose anything.

func TestExposureSpecEditIsNotReportedAsReady(t *testing.T) {
	cp := testCP(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/k8s/services/svc-80"):
			json.NewEncoder(w).Encode(row("svc-80", 80, true))
		default:
			t.Errorf("a spec edit must not change anything in the control plane: %s %s", r.Method, r.URL.Path)
		}
	})
	edited := exposure("api", 8080, "svc-80") // was exposed on 80, spec now says 8080
	r := &TunnexExposedServiceReconciler{Client: fakeK8s(t, readyCluster(), edited), CP: cp}
	if _, err := r.Reconcile(context.Background(), req("ns", "api")); err != nil {
		t.Fatal(err)
	}
	c := readyCond(t, getExposure(t, r, "api").Status.Conditions)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != reasonSpecChange || !strings.Contains(c.Message, "prod/api TCP 80") {
		t.Fatalf("want Ready=False/%s naming what is live, got %+v", reasonSpecChange, c)
	}
}

// K8N-3: default/kubernetes is the cluster's API server. A resource declaring it is not Ready and says
// why; the control plane is never asked to expose it.
func TestAPIServerExposureIsRefusedWithTheReason(t *testing.T) {
	cp := testCP(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/k8s/services"):
			json.NewEncoder(w).Encode([]map[string]any{})
		default:
			t.Errorf("the API server must never be sent to the control plane as an exposure: %s %s", r.Method, r.URL.Path)
		}
	})
	cr := exposure("kube-api", 443, "")
	cr.Spec.Namespace, cr.Spec.Service = "default", "kubernetes"
	r := &TunnexExposedServiceReconciler{Client: fakeK8s(t, readyCluster(), cr), CP: cp}
	res, err := r.Reconcile(context.Background(), req("ns", "kube-api"))
	if err != nil {
		t.Fatal(err)
	}
	got := getExposure(t, r, "kube-api")
	c := readyCond(t, got.Status.Conditions)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != reasonAPIServer || !strings.Contains(c.Message, "API access") {
		t.Fatalf("want Ready=False/%s pointing at API access, got %+v", reasonAPIServer, c)
	}
	if got.Status.ServiceID != "" || got.Status.VIP != "" || res.RequeueAfter != clientErrRequeue {
		t.Fatalf("nothing may be recorded as exposed: id=%q vip=%q res=%+v", got.Status.ServiceID, got.Status.VIP, res)
	}
	// A Service that merely shares the name in another namespace is an ordinary Service.
	if isAPIServerService("prod", "kubernetes") || isAPIServerService("default", "api") || !isAPIServerService("default", "kubernetes") {
		t.Fatal("only default/kubernetes is the API server")
	}
}

// A resource that already owns an exposure of default/kubernetes, made before the refusal existed, is
// left as it is: still Ready, nothing removed, nothing re-created.
func TestExistingAPIServerExposureIsLeftInPlace(t *testing.T) {
	existing := map[string]any{"id": "svc-kube", "cluster_id": "clu-1", "namespace": "default", "name": "kubernetes", "protocol": "tcp",
		"port_low": 443, "port_high": 443, "vip": "100.64.0.7", "fqdn": "kubernetes.default.svc.prod.k8s.acme.com", "managed_by_operator": true}
	cp := testCP(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/k8s/services/svc-kube"):
			json.NewEncoder(w).Encode(existing)
		default:
			t.Errorf("an existing exposure must not be changed: %s %s", r.Method, r.URL.Path)
		}
	})
	cr := exposure("kube-api", 443, "svc-kube")
	cr.Spec.Namespace, cr.Spec.Service = "default", "kubernetes"
	r := &TunnexExposedServiceReconciler{Client: fakeK8s(t, readyCluster(), cr), CP: cp}
	if _, err := r.Reconcile(context.Background(), req("ns", "kube-api")); err != nil {
		t.Fatal(err)
	}
	got := getExposure(t, r, "kube-api")
	if c := readyCond(t, got.Status.Conditions); c == nil || c.Status != metav1.ConditionTrue || got.Status.ServiceID != "svc-kube" {
		t.Fatalf("an exposure that already exists stays Ready and owned, got %+v id=%q", c, got.Status.ServiceID)
	}
}

// A port exposed from the dashboard is not adopted, so deleting the resource can never unexpose it.
func TestDashboardExposureIsNeitherAdoptedNorRemoved(t *testing.T) {
	cp := testCP(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/k8s/services"):
			json.NewEncoder(w).Encode([]map[string]any{row("svc-ui", 80, false)})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	cr := exposure("api", 80, "")
	r := &TunnexExposedServiceReconciler{Client: fakeK8s(t, readyCluster(), cr), CP: cp}
	if _, err := r.Reconcile(context.Background(), req("ns", "api")); err != nil {
		t.Fatal(err)
	}
	got := getExposure(t, r, "api")
	if c := readyCond(t, got.Status.Conditions); c == nil || c.Status != metav1.ConditionFalse || c.Reason != reasonUnmanaged || got.Status.ServiceID != "" {
		t.Fatalf("want Ready=False/%s and no adopted id, got %+v id=%q", reasonUnmanaged, c, got.Status.ServiceID)
	}
	// Deleting it now touches nothing in the control plane (the handler above fails on any DELETE).
	if err := r.Delete(context.Background(), &got); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req("ns", "api")); err != nil {
		t.Fatal(err)
	}
}

// Two resources for the same Service port: the second is told so instead of sharing (and later deleting)
// the first one's exposure.
func TestDuplicateExposureDeclarationIsRefused(t *testing.T) {
	cp := testCP(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/k8s/services"):
			json.NewEncoder(w).Encode([]map[string]any{row("svc-80", 80, true)})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	r := &TunnexExposedServiceReconciler{Client: fakeK8s(t, readyCluster(), exposure("first", 80, "svc-80"), exposure("second", 80, "")), CP: cp}
	if _, err := r.Reconcile(context.Background(), req("ns", "second")); err != nil {
		t.Fatal(err)
	}
	c := readyCond(t, getExposure(t, r, "second").Status.Conditions)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != reasonDuplicate || !strings.Contains(c.Message, "ns/first") {
		t.Fatalf("want Ready=False/%s naming ns/first, got %+v", reasonDuplicate, c)
	}
}

func clusterCR(status string) *tunnexv1.TunnexCluster {
	return &tunnexv1.TunnexCluster{
		ObjectMeta: managedMeta("ns", "c"),
		Spec:       tunnexv1.TunnexClusterSpec{Site: "edge", Connector: "edge-gw", Name: "prod", VIPRange: "100.64.0.0/16", ServiceCIDR: "10.96.0.0/12", DNSZone: "k8s.acme.com"},
		Status:     tunnexv1.TunnexClusterStatus{ClusterID: status},
	}
}

func clusterRow(connector any, managed bool) map[string]any {
	return map[string]any{"id": "clu-1", "name": "prod", "site_id": "site-1", "vip_range": "100.64.0.0/16", "service_cidr": "10.96.0.0/12",
		"dns_zone": "k8s.acme.com", "dns_vip": "100.64.0.1", "connector_node_id": connector, "managed_by_operator": managed}
}

func clusterCP(t *testing.T, list []map[string]any, byID map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/sites"):
			json.NewEncoder(w).Encode([]map[string]string{{"id": "site-1", "name": "edge"}})
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/k8s/clusters/clu-1") && byID != nil:
			json.NewEncoder(w).Encode(byID)
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/k8s/clusters") && list != nil:
			json.NewEncoder(w).Encode(list)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}
}

func clusterReady(t *testing.T, r *TunnexClusterReconciler) (*metav1.Condition, tunnexv1.TunnexCluster) {
	t.Helper()
	var got tunnexv1.TunnexCluster
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: "c"}, &got); err != nil {
		t.Fatal(err)
	}
	return readyCond(t, got.Status.Conditions), got
}

// A cluster registered in the dashboard under the same name is not adopted: deleting the resource would
// otherwise deregister it together with its Services and grants.
func TestDashboardClusterIsNotAdopted(t *testing.T) {
	r := &TunnexClusterReconciler{Client: fakeK8s(t, clusterCR("")), CP: testCP(t, clusterCP(t, []map[string]any{clusterRow("node-1", false)}, nil))}
	if _, err := r.Reconcile(context.Background(), req("ns", "c")); err != nil {
		t.Fatal(err)
	}
	c, got := clusterReady(t, r)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != reasonUnmanaged || got.Status.ClusterID != "" {
		t.Fatalf("want Ready=False/%s and no adopted id, got %+v id=%q", reasonUnmanaged, c, got.Status.ClusterID)
	}
}

// spec.connector is the one cluster field the control plane can change. Editing it must actually change the
// serving gateway, with the resource named as the cause.
func TestClusterConnectorEditIsApplied(t *testing.T) {
	r := &TunnexClusterReconciler{Client: fakeK8s(t, clusterCR("clu-1")), CP: testCP(t, clusterCP(t, nil, clusterRow("node-old", true)))}
	res, err := r.Reconcile(context.Background(), req("ns", "c"))
	if err != nil {
		t.Fatal(err)
	}
	puts, _ := connectorPuts.Load(t.Name())
	if calls, _ := puts.([]string); len(calls) != 1 || calls[0] != "node-1 cause=tunnexcluster:ns/c" {
		t.Fatalf("connector was not changed to the gateway the spec names: %v", puts)
	}
	if c, _ := clusterReady(t, r); c == nil || c.Status != metav1.ConditionTrue || res.RequeueAfter != resyncReady {
		t.Fatalf("want Ready and a periodic re-check, got %+v res=%+v", c, res)
	}
}

func TestClusterConnectorIsLeftAloneWhenItMatches(t *testing.T) {
	r := &TunnexClusterReconciler{Client: fakeK8s(t, clusterCR("clu-1")), CP: testCP(t, clusterCP(t, nil, clusterRow("node-1", true)))}
	if _, err := r.Reconcile(context.Background(), req("ns", "c")); err != nil {
		t.Fatal(err)
	}
	if puts, called := connectorPuts.Load(t.Name()); called {
		t.Fatalf("connector was rewritten although it already matched: %v", puts)
	}
}

// The address range (like the name, Service network, DNS zone and site) cannot move after registration.
func TestClusterImmutableFieldEditIsNotReportedAsReady(t *testing.T) {
	cr := clusterCR("clu-1")
	cr.Spec.VIPRange = "100.70.0.0/16"
	r := &TunnexClusterReconciler{Client: fakeK8s(t, cr), CP: testCP(t, clusterCP(t, nil, clusterRow("node-1", true)))}
	if _, err := r.Reconcile(context.Background(), req("ns", "c")); err != nil {
		t.Fatal(err)
	}
	c, _ := clusterReady(t, r)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != reasonSpecChange || !strings.Contains(c.Message, "spec.vipRange") || !strings.Contains(c.Message, "100.64.0.0/16") {
		t.Fatalf("want Ready=False/%s naming spec.vipRange and the live range, got %+v", reasonSpecChange, c)
	}
	// The same range written with host bits set is not an edit.
	same := clusterCR("clu-1")
	same.Spec.VIPRange = "100.64.0.1/16"
	live := &cpapi.Cluster{ID: "clu-1", Name: "prod", SiteID: "site-1", VipRange: "100.64.0.0/16", ServiceCidr: "10.96.0.0/12", DnsZone: "k8s.acme.com"}
	if field, _ := clusterSpecMismatch(same, live, "site-1"); field != "" {
		t.Fatalf("equivalent range read as an edit of %s", field)
	}
}

func grantCR(ruleID string) (*tunnexv1.TunnexExposedService, *tunnexv1.TunnexGrant) {
	svc := &tunnexv1.TunnexExposedService{ObjectMeta: managedMeta("ns", "api"), Status: tunnexv1.TunnexExposedServiceStatus{ServiceID: "svc-new"}}
	grant := &tunnexv1.TunnexGrant{
		ObjectMeta: managedMeta("ns", "g"),
		Spec:       tunnexv1.TunnexGrantSpec{SubjectKind: "user", Subject: "dev@acme.com", Service: "api"},
		Status:     tunnexv1.TunnexGrantStatus{RuleID: ruleID},
	}
	return svc, grant
}

func ruleRow(id, serviceID, userID string, enabled bool) map[string]any {
	return map[string]any{"id": id, "src_kind": "user", "src_user_id": userID, "dst_kind": "k8s_service", "dst_k8s_service_id": serviceID,
		"managed_by_operator": true, "enabled": enabled}
}

// grantCP serves the member lookup and a fixed rule list, and records creates and deletes.
func grantCP(t *testing.T, rules []map[string]any, created *[]map[string]any, deleted *[]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/members"):
			json.NewEncoder(w).Encode([]map[string]string{{"user_id": "user-1", "email": "dev@acme.com"}})
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/policies"):
			json.NewEncoder(w).Encode(rules)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/policies"):
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			*created = append(*created, body)
			json.NewEncoder(w).Encode(map[string]any{"id": "rule-new"})
		case r.Method == "DELETE" && strings.Contains(r.URL.Path, "/policies/"):
			*deleted = append(*deleted, r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}
}

func reconcileGrant(t *testing.T, ruleID string, rules []map[string]any, mutate func(*tunnexv1.TunnexGrant)) (tunnexv1.TunnexGrant, []map[string]any, []string, time.Duration) {
	t.Helper()
	var created []map[string]any
	var deleted []string
	svc, grant := grantCR(ruleID)
	if mutate != nil {
		mutate(grant)
	}
	r := &TunnexGrantReconciler{Client: fakeK8s(t, svc, grant), CP: testCP(t, grantCP(t, rules, &created, &deleted)), Recorder: record.NewFakeRecorder(8)}
	res, err := r.Reconcile(context.Background(), req("ns", "g"))
	if err != nil {
		t.Fatal(err)
	}
	var got tunnexv1.TunnexGrant
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: "g"}, &got); err != nil {
		t.Fatal(err)
	}
	return got, created, deleted, res.RequeueAfter
}

// A healthy grant stays Ready and is looked at again on a timer, because nothing tells the operator when a
// rule changes in the dashboard.
func TestGrantIsRecheckedPeriodically(t *testing.T) {
	got, created, deleted, after := reconcileGrant(t, "rule-1", []map[string]any{ruleRow("rule-1", "svc-new", "user-1", true)}, nil)
	if c := readyCond(t, got.Status.Conditions); c == nil || c.Status != metav1.ConditionTrue || after != resyncReady || len(created)+len(deleted) != 0 {
		t.Fatalf("want Ready, re-check in %s, and no writes; got %+v after=%s created=%v deleted=%v", resyncReady, c, after, created, deleted)
	}
}

// The rule was deleted in the dashboard: access is gone, so the grant is placed again from the resource.
func TestGrantRemovedOutOfBandIsRecreated(t *testing.T) {
	got, created, _, _ := reconcileGrant(t, "rule-gone", []map[string]any{}, nil)
	if len(created) != 1 || created[0]["dst_k8s_service_id"] != "svc-new" || got.Status.RuleID != "rule-new" {
		t.Fatalf("a removed rule was not recreated: created=%v ruleId=%q", created, got.Status.RuleID)
	}
}

// The Service was recreated and has a new id. The old rule points at nothing; it is replaced.
func TestGrantForARecreatedServiceIsReplaced(t *testing.T) {
	got, created, deleted, _ := reconcileGrant(t, "rule-1", []map[string]any{ruleRow("rule-1", "svc-old", "user-1", true)}, nil)
	if len(deleted) != 1 || deleted[0] != "rule-1" || len(created) != 1 || created[0]["dst_k8s_service_id"] != "svc-new" || got.Status.RuleID != "rule-new" {
		t.Fatalf("stale rule not replaced: deleted=%v created=%v ruleId=%q", deleted, created, got.Status.RuleID)
	}
}

func TestGrantSwitchedOffIsNotReady(t *testing.T) {
	got, created, deleted, _ := reconcileGrant(t, "rule-1", []map[string]any{ruleRow("rule-1", "svc-new", "user-1", false)}, nil)
	c := readyCond(t, got.Status.Conditions)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "rule_disabled" || len(created)+len(deleted) != 0 {
		t.Fatalf("want Ready=False/rule_disabled and no writes, got %+v created=%v deleted=%v", c, created, deleted)
	}
}

func TestExpiredGrantIsNotReady(t *testing.T) {
	past := metav1.NewTime(time.Now().Add(-time.Hour))
	got, created, _, _ := reconcileGrant(t, "rule-1", []map[string]any{ruleRow("rule-1", "svc-new", "user-1", true)}, func(g *tunnexv1.TunnexGrant) { g.Spec.ExpiresAt = &past })
	c := readyCond(t, got.Status.Conditions)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "Expired" || len(created) != 0 {
		t.Fatalf("want Ready=False/Expired, got %+v created=%v", c, created)
	}
}

// Changing who a grant is for cannot be applied to the existing rule; it must not read as Ready.
func TestGrantSubjectEditIsNotReportedAsReady(t *testing.T) {
	got, created, deleted, _ := reconcileGrant(t, "rule-1", []map[string]any{ruleRow("rule-1", "svc-new", "user-other", true)}, nil)
	c := readyCond(t, got.Status.Conditions)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != reasonSpecChange || len(created)+len(deleted) != 0 {
		t.Fatalf("want Ready=False/%s and no writes, got %+v created=%v deleted=%v", reasonSpecChange, c, created, deleted)
	}
}

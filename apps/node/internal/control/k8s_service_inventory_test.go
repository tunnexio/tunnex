package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestK8sServiceInventoryDigestGoldenAndOrderIndependent(t *testing.T) {
	observedAt := time.Date(2026, 8, 28, 4, 5, 6, 7000000, time.UTC)
	services := []K8sServiceInventoryService{
		{Namespace: "prod", Service: "dns", UID: "uid-dns", Ports: []K8sServiceInventoryPort{{Protocol: "udp", Port: 53, Name: "dns-udp"}, {Protocol: "tcp", Port: 53, Name: "dns-tcp"}}},
		{Namespace: "apps", Service: "api", UID: "uid-api", Ports: []K8sServiceInventoryPort{{Protocol: "tcp", Port: 443, Name: "https"}}},
	}
	want := "33462a4cabb3727f591d07b293cd914b93f0c5e8cea7d2be3f5a446340c2e4c0"
	if got := K8sServiceInventoryDigest(42, observedAt, services); got != want {
		t.Fatalf("digest=%s", got)
	}
	reversed := []K8sServiceInventoryService{services[1], services[0]}
	if got := K8sServiceInventoryDigest(42, observedAt, reversed); got != want {
		t.Fatalf("reordered digest=%s", got)
	}
	report := K8sServiceInventoryReport{Version: 1, Sequence: 42, ObservedAt: observedAt, Digest: want, Services: reversed}
	if err := ValidateK8sServiceInventoryReport(report); err != nil {
		t.Fatal(err)
	}
}

func TestK8sServiceInventoryValidationRefusesDuplicateAndOverflow(t *testing.T) {
	now := time.Now().UTC()
	service := K8sServiceInventoryService{Namespace: "prod", Service: "api", UID: "uid", Ports: []K8sServiceInventoryPort{{Protocol: "tcp", Port: 443}, {Protocol: "tcp", Port: 443}}}
	report := K8sServiceInventoryReport{Version: 1, Sequence: 1, ObservedAt: now, Services: []K8sServiceInventoryService{service}}
	report.Digest = K8sServiceInventoryDigest(report.Sequence, report.ObservedAt, report.Services)
	if ValidateK8sServiceInventoryReport(report) == nil {
		t.Fatal("duplicate protocol/port accepted")
	}
	service.Ports = make([]K8sServiceInventoryPort, maxK8sServiceInventoryPorts+1)
	for i := range service.Ports {
		service.Ports[i] = K8sServiceInventoryPort{Protocol: "tcp", Port: i + 1}
	}
	report.Services = []K8sServiceInventoryService{service}
	report.Digest = K8sServiceInventoryDigest(report.Sequence, report.ObservedAt, report.Services)
	if ValidateK8sServiceInventoryReport(report) == nil {
		t.Fatal("port overflow accepted")
	}
}

func labelledInventory() (time.Time, []K8sServiceInventoryService) {
	return time.Date(2026, 8, 28, 4, 5, 6, 7000000, time.UTC), []K8sServiceInventoryService{
		{Namespace: "prod", Service: "dns", UID: "uid-dns", Ports: []K8sServiceInventoryPort{{Protocol: "udp", Port: 53, Name: "dns-udp"}},
			Labels: map[string]string{"k8s-app": "kube-dns", "app.kubernetes.io/name": "coredns"}, LabelsTruncated: true},
		{Namespace: "apps", Service: "api", UID: "uid-api", Ports: []K8sServiceInventoryPort{{Protocol: "tcp", Port: 443, Name: "https"}}},
	}
}

const labelledInventoryDigest = "0b840796da2076018a7454cbe66815c7cdb8b908d2fba8da5e8b23555dd85723"

func TestK8sServiceInventoryV2DigestGoldenCoversLabels(t *testing.T) {
	observedAt, services := labelledInventory()
	if got := K8sServiceInventoryDigestV2(42, observedAt, services); got != labelledInventoryDigest {
		t.Fatalf("digest=%s", got)
	}
	report := K8sServiceInventoryReport{Version: K8sServiceInventoryVersionLabels, Sequence: 42, ObservedAt: observedAt, Digest: labelledInventoryDigest, Services: []K8sServiceInventoryService{services[1], services[0]}}
	if err := ValidateK8sServiceInventoryReport(report); err != nil {
		t.Fatal(err)
	}
	// Every label fact is under the digest: a changed value, a dropped label and the truncated flag.
	for name, change := range map[string]func(*K8sServiceInventoryService){
		"value":     func(s *K8sServiceInventoryService) { s.Labels["k8s-app"] = "other" },
		"dropped":   func(s *K8sServiceInventoryService) { delete(s.Labels, "k8s-app") },
		"truncated": func(s *K8sServiceInventoryService) { s.LabelsTruncated = false },
	} {
		_, changed := labelledInventory()
		change(&changed[0])
		if K8sServiceInventoryDigestV2(42, observedAt, changed) == labelledInventoryDigest {
			t.Errorf("%s is not covered by the digest", name)
		}
	}
	// The same Services without labels have a different digest in each version.
	if K8sServiceInventoryDigest(42, observedAt, services) == K8sServiceInventoryDigestV2(42, observedAt, services) {
		t.Fatal("version 1 and version 2 digests must differ")
	}
}

func TestK8sServiceInventoryVersion1CarriesNoLabels(t *testing.T) {
	observedAt, services := labelledInventory()
	for _, strip := range []func(*K8sServiceInventoryService){
		func(s *K8sServiceInventoryService) { s.LabelsTruncated = false },
		func(s *K8sServiceInventoryService) { s.Labels = nil },
	} {
		_, withLabels := labelledInventory()
		strip(&withLabels[0])
		report := K8sServiceInventoryReport{Version: K8sServiceInventoryVersion, Sequence: 1, ObservedAt: observedAt, Services: withLabels}
		report.Digest = K8sServiceInventoryDigest(report.Sequence, report.ObservedAt, report.Services)
		if ValidateK8sServiceInventoryReport(report) == nil {
			t.Fatal("a version 1 report that carries label data was accepted")
		}
	}
	report := K8sServiceInventoryReport{Version: 3, Sequence: 1, ObservedAt: observedAt, Services: services}
	report.Digest = K8sServiceInventoryDigestV2(report.Sequence, report.ObservedAt, report.Services)
	if ValidateK8sServiceInventoryReport(report) == nil {
		t.Fatal("an unknown version was accepted")
	}
}

func TestK8sServiceInventoryV2RefusesLabelsBeyondTheBounds(t *testing.T) {
	observedAt := time.Now().UTC()
	valid := func(labels map[string]string) error {
		report := K8sServiceInventoryReport{Version: K8sServiceInventoryVersionLabels, Sequence: 1, ObservedAt: observedAt, Services: []K8sServiceInventoryService{
			{Namespace: "prod", Service: "api", UID: "uid", Ports: []K8sServiceInventoryPort{{Protocol: "tcp", Port: 443}}, Labels: labels}}}
		report.Digest = K8sServiceInventoryReportDigest(report)
		return ValidateK8sServiceInventoryReport(report)
	}
	many := map[string]string{}
	for i := 0; i < MaxK8sServiceInventoryLabels; i++ {
		many["k"+strconv.Itoa(i)] = "v"
	}
	if err := valid(many); err != nil {
		t.Fatalf("exactly %d labels must be accepted: %v", MaxK8sServiceInventoryLabels, err)
	}
	many["one-more"] = "v"
	if valid(many) == nil {
		t.Fatal("33 labels accepted")
	}
	long := strings.Repeat("a", 63)
	heavy := map[string]string{}
	for i := 0; i < 20; i++ { // 20 × (56+63) bytes > 2048
		heavy["example.com/"+strings.Repeat("k", 40)+"-"+strconv.Itoa(100+i)] = long
	}
	if valid(heavy) == nil {
		t.Fatal("labels over the byte bound accepted")
	}
	for _, bad := range []map[string]string{
		{"": "v"}, {"-app": "v"}, {"app": strings.Repeat("a", 64)}, {"app": "has space"}, {"a/b/c": "v"},
		{"Example.com/app": "v"}, {"app": "tab\there"}, {strings.Repeat("a", 64): "v"},
	} {
		if valid(bad) == nil {
			t.Errorf("label %v accepted", bad)
		}
	}
	for _, good := range []map[string]string{
		{"app": ""}, {"app.kubernetes.io/name": "My_App.v2"}, {"tier": "frontend", "A": "1"},
	} {
		if err := valid(good); err != nil {
			t.Errorf("label %v refused: %v", good, err)
		}
	}
}

func TestBoundK8sServiceInventoryLabelsTruncatesInKeyOrderAndSaysSo(t *testing.T) {
	few := map[string]string{"app": "web", "tier": "frontend"}
	kept, truncated := BoundK8sServiceInventoryLabels(few)
	if truncated || len(kept) != 2 || kept["app"] != "web" {
		t.Fatalf("kept=%v truncated=%v", kept, truncated)
	}
	if kept, truncated := BoundK8sServiceInventoryLabels(nil); truncated || kept == nil || len(kept) != 0 {
		t.Fatalf("no labels: kept=%v truncated=%v", kept, truncated)
	}
	many := map[string]string{}
	for i := 0; i < 40; i++ {
		many["k"+strconv.Itoa(100+i)] = "v"
	}
	kept, truncated = BoundK8sServiceInventoryLabels(many)
	if !truncated || len(kept) != MaxK8sServiceInventoryLabels || kept["k100"] != "v" || kept["k131"] != "v" {
		t.Fatalf("40 labels: kept %d truncated=%v", len(kept), truncated)
	}
	if _, late := kept["k132"]; late {
		t.Fatal("labels must be kept in key order")
	}
	heavy := map[string]string{}
	for i := 0; i < 30; i++ {
		heavy["example.com/"+strings.Repeat("k", 40)+"-"+strconv.Itoa(100+i)] = strings.Repeat("a", 63)
	}
	kept, truncated = BoundK8sServiceInventoryLabels(heavy)
	if !truncated || !validK8sServiceInventoryLabels(kept) || len(kept) == 0 {
		t.Fatalf("heavy labels: kept %d truncated=%v", len(kept), truncated)
	}
	// A label that is not valid syntax is left out and the set is marked incomplete; what is sent
	// always passes the control plane's validation.
	kept, truncated = BoundK8sServiceInventoryLabels(map[string]string{"app": "web", "bad key": "v"})
	if !truncated || len(kept) != 1 || !validK8sServiceInventoryLabels(kept) {
		t.Fatalf("invalid label: kept=%v truncated=%v", kept, truncated)
	}
}

func TestReportK8sServiceInventoryNamesARefusal(t *testing.T) {
	status := http.StatusBadRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer server.Close()
	client := &Client{base: server.URL, http: server.Client()}
	observedAt, services := labelledInventory()
	report := K8sServiceInventoryReport{Version: K8sServiceInventoryVersionLabels, Sequence: 42, ObservedAt: observedAt, Digest: labelledInventoryDigest, Services: services}
	if err := client.ReportK8sServiceInventory(context.Background(), report); !errors.Is(err, ErrK8sServiceInventoryRefused) {
		t.Fatalf("a 400 must be ErrK8sServiceInventoryRefused, got %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := client.ReportK8sServiceInventory(context.Background(), report); err == nil || errors.Is(err, ErrK8sServiceInventoryRefused) {
		t.Fatalf("a 503 is a failure but not a refusal, got %v", err)
	}
	status = http.StatusNoContent
	if err := client.ReportK8sServiceInventory(context.Background(), report); err != nil {
		t.Fatal(err)
	}
}

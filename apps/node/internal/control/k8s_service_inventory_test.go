package control

import (
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

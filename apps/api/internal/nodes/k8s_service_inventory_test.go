package nodes

import (
	"testing"
	"time"
)

func TestK8sServiceInventoryDigestMatchesNodeGolden(t *testing.T) {
	observedAt := time.Date(2026, 8, 28, 4, 5, 6, 7000000, time.UTC)
	services := []K8sServiceInventoryService{
		{Namespace: "prod", Service: "dns", UID: "uid-dns", Ports: []K8sServiceInventoryPort{{Protocol: "udp", Port: 53, Name: "dns-udp"}, {Protocol: "tcp", Port: 53, Name: "dns-tcp"}}},
		{Namespace: "apps", Service: "api", UID: "uid-api", Ports: []K8sServiceInventoryPort{{Protocol: "tcp", Port: 443, Name: "https"}}},
	}
	want := "33462a4cabb3727f591d07b293cd914b93f0c5e8cea7d2be3f5a446340c2e4c0"
	if got := K8sServiceInventoryDigest(42, observedAt, services); got != want {
		t.Fatalf("digest=%s", got)
	}
	report := K8sServiceInventoryReport{Version: 1, Sequence: 42, ObservedAt: observedAt, Digest: want, Services: services}
	if _, err := ValidateK8sServiceInventoryReport(report); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryUIDObservationReportDoesNotInventDeletionForUnsupportedService(t *testing.T) {
	report := K8sServiceInventoryReport{Sequence: 8, Services: []K8sServiceInventoryService{{Namespace: "prod", Service: "api", UID: "uid-b", Ports: []K8sServiceInventoryPort{{Protocol: "tcp", Port: 443}}}}}
	uidReport := inventoryUIDObservationReport(report)
	if len(uidReport.Observations) != 1 || uidReport.Observations[0].Service != "api" || uidReport.Observations[0].State != "live" {
		t.Fatalf("observations=%+v", uidReport.Observations)
	}
}

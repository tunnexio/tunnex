package nodes

import (
	"strconv"
	"strings"
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

// K8N-4 slice B. The golden digest is the gateway's (apps/node/internal/control): both sides must agree.
func TestK8sServiceInventoryV2DigestMatchesNodeGoldenAndBoundsLabels(t *testing.T) {
	observedAt := time.Date(2026, 8, 28, 4, 5, 6, 7000000, time.UTC)
	services := func() []K8sServiceInventoryService {
		return []K8sServiceInventoryService{
			{Namespace: "prod", Service: "dns", UID: "uid-dns", Ports: []K8sServiceInventoryPort{{Protocol: "udp", Port: 53, Name: "dns-udp"}},
				Labels: map[string]string{"k8s-app": "kube-dns", "app.kubernetes.io/name": "coredns"}, LabelsTruncated: true},
			{Namespace: "apps", Service: "api", UID: "uid-api", Ports: []K8sServiceInventoryPort{{Protocol: "tcp", Port: 443, Name: "https"}}},
		}
	}
	const want = "0b840796da2076018a7454cbe66815c7cdb8b908d2fba8da5e8b23555dd85723"
	if got := K8sServiceInventoryDigestV2(42, observedAt, services()); got != want {
		t.Fatalf("digest=%s", got)
	}
	canonical, err := ValidateK8sServiceInventoryReport(K8sServiceInventoryReport{Version: 2, Sequence: 42, ObservedAt: observedAt, Digest: want, Services: services()})
	if err != nil {
		t.Fatal(err)
	}
	if canonical.Version != 2 || canonical.Services[1].Labels["k8s-app"] != "kube-dns" || !canonical.Services[1].LabelsTruncated {
		t.Fatalf("canonical=%+v", canonical)
	}

	report := func(version int, change func([]K8sServiceInventoryService)) error {
		list := services()
		if change != nil {
			change(list)
		}
		r := K8sServiceInventoryReport{Version: version, Sequence: 42, ObservedAt: observedAt, Services: list}
		r.Digest = K8sServiceInventoryReportDigest(r)
		_, err := ValidateK8sServiceInventoryReport(r)
		return err
	}
	// An old gateway's report, with no label data, is accepted exactly as before.
	if err := report(1, func(l []K8sServiceInventoryService) { l[0].Labels, l[0].LabelsTruncated = nil, false }); err != nil {
		t.Fatalf("a version 1 report must keep working: %v", err)
	}
	// Version 1 may not carry labels, and no other version exists.
	if report(1, nil) == nil || report(1, func(l []K8sServiceInventoryService) { l[0].Labels = nil }) == nil || report(3, nil) == nil || report(0, nil) == nil {
		t.Fatal("a version 1 report with label data, or an unknown version, was accepted")
	}
	// A version 2 digest does not validate a report relabelled as version 1, nor the reverse.
	relabelled := K8sServiceInventoryReport{Version: 1, Sequence: 42, ObservedAt: observedAt, Digest: want, Services: services()[1:]}
	if _, err := ValidateK8sServiceInventoryReport(relabelled); err == nil {
		t.Fatal("a version 2 digest was accepted on a version 1 report")
	}
	for name, change := range map[string]func([]K8sServiceInventoryService){
		"33 labels": func(l []K8sServiceInventoryService) {
			for i := 0; i < MaxK8sServiceInventoryLabels+1; i++ {
				l[1].Labels = mergeLabel(l[1].Labels, "k"+strconv.Itoa(i), "v")
			}
		},
		"over the byte bound": func(l []K8sServiceInventoryService) {
			for i := 0; i < 20; i++ {
				l[1].Labels = mergeLabel(l[1].Labels, "example.com/"+strings.Repeat("k", 40)+"-"+strconv.Itoa(100+i), strings.Repeat("a", 63))
			}
		},
		"bad key":    func(l []K8sServiceInventoryService) { l[1].Labels = map[string]string{"bad key": "v"} },
		"bad value":  func(l []K8sServiceInventoryService) { l[1].Labels = map[string]string{"app": "new\nline"} },
		"long value": func(l []K8sServiceInventoryService) { l[1].Labels = map[string]string{"app": strings.Repeat("a", 64)} },
	} {
		if report(2, change) == nil {
			t.Errorf("version 2 report with %s accepted", name)
		}
	}
}

func mergeLabel(labels map[string]string, key, value string) map[string]string {
	if labels == nil {
		labels = map[string]string{}
	}
	labels[key] = value
	return labels
}

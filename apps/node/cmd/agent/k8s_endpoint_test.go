package main

import (
	"sync/atomic"
	"testing"
)

func TestEndpointEnvironmentExplicitEndpointWins(t *testing.T) {
	values := map[string]string{
		"TUNNEX_NODE_ENDPOINT":          "20.85.230.33:51820",
		"TUNNEX_K8S_ENDPOINT_SERVICE":   "ignored",
		"TUNNEX_K8S_ENDPOINT_NAMESPACE": "ignored",
		"TUNNEX_K8S_ENDPOINT_PORT":      "invalid",
	}
	config, err := endpointEnvironmentFrom(func(key string) string { return values[key] })
	if err != nil || config.explicitEndpoint != "20.85.230.33:51820" || config.auto != nil || config.kubernetesMode {
		t.Fatalf("explicit endpoint did not win: config=%+v err=%v", config, err)
	}
}

func TestEndpointEnvironmentExplicitEndpointRetainsKubernetesMode(t *testing.T) {
	values := map[string]string{
		"TUNNEX_K8S_MODE":      "true",
		"TUNNEX_NODE_ENDPOINT": "20.85.230.33:51820",
	}
	config, err := endpointEnvironmentFrom(func(key string) string { return values[key] })
	if err != nil || !config.kubernetesMode || config.explicitEndpoint != "20.85.230.33:51820" {
		t.Fatalf("explicit Kubernetes endpoint lost mode: config=%+v err=%v", config, err)
	}
}

func TestEndpointEnvironmentRequiresCompleteAutoDiscoveryTuple(t *testing.T) {
	values := map[string]string{
		"TUNNEX_K8S_MODE":               "true",
		"TUNNEX_K8S_ENDPOINT_SERVICE":   "gateway-wg",
		"TUNNEX_K8S_ENDPOINT_NAMESPACE": "tunnex-system",
		"TUNNEX_K8S_ENDPOINT_PORT":      "51820",
	}
	config, err := endpointEnvironmentFrom(func(key string) string { return values[key] })
	if err != nil || config.auto == nil || config.auto.Port != 51820 {
		t.Fatalf("auto config=%+v err=%v", config, err)
	}
	delete(values, "TUNNEX_K8S_ENDPOINT_NAMESPACE")
	if _, err := endpointEnvironmentFrom(func(key string) string { return values[key] }); err == nil {
		t.Fatal("partial auto-discovery tuple must fail closed")
	}
}

func TestEndpointEnvironmentRequiresClosedKubernetesModeForDiscovery(t *testing.T) {
	values := map[string]string{
		"TUNNEX_K8S_ENDPOINT_SERVICE":   "gateway-wg",
		"TUNNEX_K8S_ENDPOINT_NAMESPACE": "tunnex-system",
		"TUNNEX_K8S_ENDPOINT_PORT":      "51820",
	}
	if _, err := endpointEnvironmentFrom(func(key string) string { return values[key] }); err == nil {
		t.Fatal("automatic discovery was accepted without explicit Kubernetes mode")
	}
	values = map[string]string{"TUNNEX_K8S_MODE": "TRUE"}
	if _, err := endpointEnvironmentFrom(func(key string) string { return values[key] }); err == nil {
		t.Fatal("non-canonical Kubernetes mode value was accepted")
	}
	values = map[string]string{"TUNNEX_K8S_MODE": "true"}
	if _, err := endpointEnvironmentFrom(func(key string) string { return values[key] }); err == nil {
		t.Fatal("Kubernetes mode without endpoint configuration was accepted")
	}
}

func TestEndpointReportRejectsStaleGeneration(t *testing.T) {
	current := reportEndpointSnapshot{Endpoint: "new.example:51820", Generation: 3, Reportable: true}
	source := func() reportEndpointSnapshot { return current }
	if endpointReportIsCurrent(source, reportEndpointSnapshot{Endpoint: "old.example:51820", Generation: 2, Reportable: true}) {
		t.Fatal("stale endpoint report was accepted for readiness")
	}
	if !endpointReportIsCurrent(source, current) {
		t.Fatal("current endpoint report was not accepted")
	}
	current.Reportable = false
	if endpointReportIsCurrent(source, current) {
		t.Fatal("unobservable endpoint was accepted for readiness")
	}
}

func TestEndpointReportRetractsGenerationThatAdvancesWhileReadinessIsStored(t *testing.T) {
	sent := reportEndpointSnapshot{Endpoint: "old.example:51820", Generation: 2, Reportable: true}
	newer := reportEndpointSnapshot{Endpoint: "new.example:51820", Generation: 3, Reportable: true}
	calls := 0
	source := func() reportEndpointSnapshot {
		calls++
		if calls == 1 {
			return sent
		}
		return newer
	}
	var reported atomic.Bool
	current, changed := acceptEndpointReport(source, sent, &reported)
	if current || changed || reported.Load() {
		t.Fatalf("racing endpoint generation retained stale readiness: current=%v changed=%v ready=%v", current, changed, reported.Load())
	}
}

func TestAgentReadinessRequiresEndpointAndK8sNetworkPreparation(t *testing.T) {
	for _, test := range []struct {
		name       string
		reconciled bool
		reported   bool
		k8sMode    bool
		netPrep    bool
		snapshot   bool
		want       bool
	}{
		{name: "Kubernetes all green", reconciled: true, reported: true, k8sMode: true, netPrep: true, snapshot: true, want: true},
		{name: "Kubernetes desired state unhealthy", reported: true, k8sMode: true, netPrep: true, snapshot: true},
		{name: "Kubernetes endpoint not reported", reconciled: true, k8sMode: true, netPrep: true, snapshot: true},
		{name: "Kubernetes network preparation blocked", reconciled: true, reported: true, k8sMode: true, snapshot: true},
		{name: "Kubernetes API snapshot unavailable", reconciled: true, reported: true, k8sMode: true, netPrep: true},
		{name: "legacy VM ignores Kubernetes preparation", reconciled: true, reported: true, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := agentReady(test.reconciled, test.reported, test.k8sMode, test.netPrep, test.snapshot); got != test.want {
				t.Fatalf("agentReady=%v, want %v", got, test.want)
			}
		})
	}
}

func TestAgentReadinessPreservesLegacyVMWithoutK8sNetworkPreparation(t *testing.T) {
	if !agentReady(true, true, false, false, false) {
		t.Fatal("ordinary VM/site gateway was made dependent on Kubernetes network preparation")
	}
}

func TestExplicitEndpointCannotBypassKubernetesAPISnapshotReadiness(t *testing.T) {
	values := map[string]string{
		"TUNNEX_K8S_MODE":      "true",
		"TUNNEX_NODE_ENDPOINT": "20.85.230.33:51820",
	}
	config, err := endpointEnvironmentFrom(func(key string) string { return values[key] })
	if err != nil || !config.kubernetesMode || config.explicitEndpoint == "" {
		t.Fatalf("explicit Kubernetes endpoint setup failed: config=%+v err=%v", config, err)
	}
	if agentReady(true, true, config.kubernetesMode, true, false) {
		t.Fatal("explicit public endpoint bypassed the unavailable Services/EndpointSlices snapshot")
	}
}

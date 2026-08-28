package nodes

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestK8sServiceUIDObservationReplayAndIncarnationFence(t *testing.T) {
	receipt := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	agent, scope := testK8sServiceUIDObservationScope()
	first := testK8sServiceUIDObservationReport(1, K8sServiceUIDObservation{Namespace: "prod", Service: "api", UID: "uid-a", State: "live"})
	accepted, err := ValidateK8sServiceUIDObservations(receipt, agent, scope, first, K8sServiceUIDObservationState{})
	if err != nil || accepted.Duplicate || !accepted.ReceiptTime.Equal(receipt) {
		t.Fatalf("first observation = %+v, %v", accepted, err)
	}

	second := testK8sServiceUIDObservationReport(2, K8sServiceUIDObservation{Namespace: "prod", Service: "api", UID: "uid-b", State: "live"})
	advanced, err := ValidateK8sServiceUIDObservations(receipt.Add(time.Minute), agent, scope, second, accepted.NextState)
	if err != nil || advanced.NextState.Current["prod\x00api"].UID != "uid-b" || !advanced.NextState.Retired["prod\x00api"]["uid-a"] {
		t.Fatalf("recreated Service must be a new incarnation, got %+v, %v", advanced, err)
	}

	duplicate, err := ValidateK8sServiceUIDObservations(receipt.Add(time.Hour), agent, scope, first, advanced.NextState)
	if err != nil || !duplicate.Duplicate || !duplicate.ReceiptTime.Equal(receipt) {
		t.Fatalf("lost-response retry = %+v, %v", duplicate, err)
	}
	oldAgain := testK8sServiceUIDObservationReport(3, K8sServiceUIDObservation{Namespace: "prod", Service: "api", UID: "uid-a", State: "live"})
	if _, err := ValidateK8sServiceUIDObservations(receipt.Add(2*time.Hour), agent, scope, oldAgain, advanced.NextState); !errors.Is(err, ErrK8sServiceUIDObservationStale) {
		t.Fatalf("an old UID must never revive after recreation, got %v", err)
	}
}

func TestK8sServiceUIDObservationRejectsScopeReplayAndMalformedInput(t *testing.T) {
	agent, scope := testK8sServiceUIDObservationScope()
	report := testK8sServiceUIDObservationReport(7, K8sServiceUIDObservation{Namespace: "prod", Service: "api", UID: "uid-a", State: "live"})
	if _, err := ValidateK8sServiceUIDObservations(time.Now(), K8sServiceUIDObservationAgent{NodeID: agent.NodeID, OrgID: uuid.New()}, scope, report, K8sServiceUIDObservationState{}); !errors.Is(err, ErrK8sServiceUIDObservationInvalid) {
		t.Fatalf("cross-org scope must refuse, got %v", err)
	}
	wrongConnector := scope
	wrongConnector.ConnectorNodeID = uuid.New()
	if _, err := ValidateK8sServiceUIDObservations(time.Now(), agent, wrongConnector, report, K8sServiceUIDObservationState{}); !errors.Is(err, ErrK8sServiceUIDObservationInvalid) {
		t.Fatalf("wrong connector must refuse, got %v", err)
	}

	for name, mutate := range map[string]func(*K8sServiceUIDObservationReport){
		"bad version": func(r *K8sServiceUIDObservationReport) { r.Version++ },
		"empty uid":   func(r *K8sServiceUIDObservationReport) { r.Observations[0].UID = "" },
		"oversized uid": func(r *K8sServiceUIDObservationReport) {
			r.Observations[0].UID = strings.Repeat("a", maxK8sServiceUIDBytes+1)
		},
		"uppercase namespace":   func(r *K8sServiceUIDObservationReport) { r.Observations[0].Namespace = "Prod" },
		"duplicate incarnation": func(r *K8sServiceUIDObservationReport) { r.Observations = append(r.Observations, r.Observations[0]) },
		"wrong digest":          func(r *K8sServiceUIDObservationReport) { r.Digest = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := report
			bad.Observations = append([]K8sServiceUIDObservation(nil), report.Observations...)
			mutate(&bad)
			if _, err := ValidateK8sServiceUIDObservationReport(bad); !errors.Is(err, ErrK8sServiceUIDObservationInvalid) {
				t.Fatalf("malformed report must fail closed, got %v", err)
			}
		})
	}

	first, err := ValidateK8sServiceUIDObservations(time.Now(), agent, scope, report, K8sServiceUIDObservationState{})
	if err != nil {
		t.Fatal(err)
	}
	different := report
	different.Observations = []K8sServiceUIDObservation{{Namespace: "prod", Service: "api", UID: "uid-b", State: "live"}}
	different.Digest = K8sServiceUIDObservationDigest(different.Sequence, different.Observations)
	if _, err := ValidateK8sServiceUIDObservations(time.Now(), agent, scope, different, first.NextState); !errors.Is(err, ErrK8sServiceUIDObservationInvalid) {
		t.Fatalf("same sequence with different digest must refuse, got %v", err)
	}
	stale := testK8sServiceUIDObservationReport(6, K8sServiceUIDObservation{Namespace: "prod", Service: "api", UID: "uid-a", State: "deleted"})
	if _, err := ValidateK8sServiceUIDObservations(time.Now(), agent, scope, stale, first.NextState); !errors.Is(err, ErrK8sServiceUIDObservationStale) {
		t.Fatalf("out-of-order sequence must refuse, got %v", err)
	}
}

func TestK8sServiceUIDObservationDigestIsOrderIndependent(t *testing.T) {
	a := []K8sServiceUIDObservation{{Namespace: "prod", Service: "api", UID: "uid-a", State: "deleted"}, {Namespace: "prod", Service: "api", UID: "uid-b", State: "live"}}
	b := []K8sServiceUIDObservation{a[1], a[0]}
	if K8sServiceUIDObservationDigest(9, a) != K8sServiceUIDObservationDigest(9, b) {
		t.Fatal("observation order changed digest")
	}
	if got := K8sServiceUIDObservationDigest(9, a); got != "6d90c9a4a071f6481e867b2b7ae8d2b8d5971013ec6cb420021e43811205de1a" {
		t.Fatalf("cross-module golden digest = %s", got)
	}
}

func testK8sServiceUIDObservationScope() (K8sServiceUIDObservationAgent, K8sServiceUIDObservationScope) {
	org, site, cluster, connector := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	return K8sServiceUIDObservationAgent{NodeID: connector, OrgID: org}, K8sServiceUIDObservationScope{OrgID: org, SiteID: site, ClusterID: cluster, ConnectorNodeID: connector}
}

func testK8sServiceUIDObservationReport(sequence uint64, entries ...K8sServiceUIDObservation) K8sServiceUIDObservationReport {
	return K8sServiceUIDObservationReport{Version: K8sServiceUIDObservationVersion, Sequence: sequence, Digest: K8sServiceUIDObservationDigest(sequence, entries), Observations: entries}
}

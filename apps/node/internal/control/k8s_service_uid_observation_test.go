package control

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestReportK8sServiceUIDObservationsKeepsScopeServerAuthoritative(t *testing.T) {
	ca := newTestCA(t)
	requests := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/k8s-service-uid-observations", func(w http.ResponseWriter, r *http.Request) {
		requests++
		var got map[string]any
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"org_id", "site_id", "cluster_id", "connector_id", "node_id"} {
			if _, ok := got[forbidden]; ok {
				t.Fatalf("client chose server-owned scope field %q", forbidden)
			}
		}
		entry := got["observations"].([]any)[0].(map[string]any)
		for _, forbidden := range []string{"pod_ip", "node", "endpoint", "port"} {
			if _, ok := entry[forbidden]; ok {
				t.Fatalf("observation leaked %q", forbidden)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	client := ownershipDeliveryTestClient(t, ca, mux)
	report := testK8sServiceUIDObservationReport(1, K8sServiceUIDObservation{Namespace: "prod", Service: "api", UID: "opaque-service-uid", State: "live"})
	if err := client.ReportK8sServiceUIDObservations(t.Context(), report); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("requests=%d", requests)
	}

	bad := report
	bad.Observations = []K8sServiceUIDObservation{{Namespace: "prod", Service: "api", UID: strings.Repeat("x", maxK8sServiceUIDBytes+1), State: "live"}}
	bad.Digest = K8sServiceUIDObservationDigest(bad.Sequence, bad.Observations)
	if err := client.ReportK8sServiceUIDObservations(t.Context(), bad); err == nil || requests != 1 {
		t.Fatalf("oversized report must fail before mTLS request, err=%v requests=%d", err, requests)
	}
}

func TestK8sServiceUIDObservationValidationIsBoundedAndCanonical(t *testing.T) {
	a := []K8sServiceUIDObservation{{Namespace: "prod", Service: "api", UID: "uid-a", State: "deleted"}, {Namespace: "prod", Service: "api", UID: "uid-b", State: "live"}}
	if K8sServiceUIDObservationDigest(4, a) != K8sServiceUIDObservationDigest(4, []K8sServiceUIDObservation{a[1], a[0]}) {
		t.Fatal("order changed digest")
	}
	if got := K8sServiceUIDObservationDigest(9, a); got != "6d90c9a4a071f6481e867b2b7ae8d2b8d5971013ec6cb420021e43811205de1a" {
		t.Fatalf("cross-module golden digest = %s", got)
	}
	tooMany := make([]K8sServiceUIDObservation, maxK8sServiceUIDObservations+1)
	for i := range tooMany {
		tooMany[i] = K8sServiceUIDObservation{Namespace: "prod", Service: "api", UID: "uid-" + string(rune('a'+i)), State: "live"}
	}
	if err := ValidateK8sServiceUIDObservationReport(testK8sServiceUIDObservationReport(10, tooMany...)); err == nil {
		t.Fatal("observation count bound was not enforced")
	}
}

func testK8sServiceUIDObservationReport(sequence uint64, entries ...K8sServiceUIDObservation) K8sServiceUIDObservationReport {
	return K8sServiceUIDObservationReport{Version: K8sServiceUIDObservationVersion, Sequence: sequence, Digest: K8sServiceUIDObservationDigest(sequence, entries), Observations: entries}
}

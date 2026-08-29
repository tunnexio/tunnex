package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

func TestK8sServiceUIDObservationHandlerBindsSelectedConnectorAndRetries(t *testing.T) {
	agent, scope := testHTTPK8sUIDScope()
	store := &httpK8sUIDStore{scope: scope}
	channel := &AgentChannel{serviceUIDObservationStore: store}
	report := httpK8sUIDReport(1, nodes.K8sServiceUIDObservation{Namespace: "prod", Service: "api", UID: "uid-a", State: "live"})
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	post := func(body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/agent/k8s-service-uid-observations", bytes.NewReader(body))
		w := httptest.NewRecorder()
		channel.k8sServiceUIDObservationsForAgent(w, r, agent)
		return w
	}
	if w := post(body); w.Code != http.StatusNoContent || store.calls != 1 || store.lastAgent != agent {
		t.Fatalf("first response=%d calls=%d agent=%+v", w.Code, store.calls, store.lastAgent)
	}
	firstReceipt := store.state.Seen[1].ReceiptTime
	if w := post(body); w.Code != http.StatusNoContent || store.calls != 2 || !store.duplicate || !store.state.Seen[1].ReceiptTime.Equal(firstReceipt) {
		t.Fatalf("lost-response retry response=%d calls=%d duplicate=%v", w.Code, store.calls, store.duplicate)
	}

	// Scope is not a payload field. An attempt to add it is a strict-decode
	// failure, before the store can receive any observation.
	if w := post([]byte(`{"version":1,"sequence":2,"digest":"` + report.Digest + `","observations":[],"cluster_id":"` + uuid.NewString() + `"}`)); w.Code != http.StatusBadRequest || store.calls != 2 {
		t.Fatalf("scope injection response=%d calls=%d", w.Code, store.calls)
	}
	wrong := store.scope
	wrong.ConnectorNodeID = uuid.New()
	channel.serviceUIDObservationStore = &httpK8sUIDStore{scope: wrong}
	if w := post(body); w.Code != http.StatusBadRequest {
		t.Fatalf("cross-connector response=%d", w.Code)
	}
}

func TestK8sServiceUIDObservationHandlerFailsClosedAndRequiresMTLS(t *testing.T) {
	channel := &AgentChannel{}
	if w := httptest.NewRecorder(); func() *httptest.ResponseRecorder {
		channel.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/agent/k8s-service-uid-observations", nil))
		return w
	}().Code != http.StatusUnauthorized {
		t.Fatal("route must require an mTLS principal")
	}
	agent, scope := testHTTPK8sUIDScope()
	report := httpK8sUIDReport(1, nodes.K8sServiceUIDObservation{Namespace: "prod", Service: "api", UID: "uid-a", State: "live"})
	body, _ := json.Marshal(report)
	w := httptest.NewRecorder()
	channel.k8sServiceUIDObservationsForAgent(w, httptest.NewRequest(http.MethodPost, "/agent/k8s-service-uid-observations", bytes.NewReader(body)), agent)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired seam response=%d", w.Code)
	}
	store := &httpK8sUIDStore{scope: scope, fail: errors.New("store unavailable")}
	channel.serviceUIDObservationStore = store
	w = httptest.NewRecorder()
	channel.k8sServiceUIDObservationsForAgent(w, httptest.NewRequest(http.MethodPost, "/agent/k8s-service-uid-observations", bytes.NewReader(body)), agent)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("store failure must fail closed, response=%d", w.Code)
	}
}

type httpK8sUIDStore struct {
	scope     nodes.K8sServiceUIDObservationScope
	state     nodes.K8sServiceUIDObservationState
	calls     int
	duplicate bool
	lastAgent nodes.K8sServiceUIDObservationAgent
	fail      error
}

func (s *httpK8sUIDStore) UpdateK8sServiceUIDObservations(_ context.Context, agent nodes.K8sServiceUIDObservationAgent, report nodes.K8sServiceUIDObservationReport, receipt time.Time, validate func(nodes.K8sServiceUIDObservationScope, nodes.K8sServiceUIDObservationState, time.Time) (nodes.K8sServiceUIDObservationValidation, error)) (nodes.K8sServiceUIDObservationValidation, error) {
	s.calls++
	s.lastAgent = agent
	if s.fail != nil {
		return nodes.K8sServiceUIDObservationValidation{}, s.fail
	}
	result, err := validate(s.scope, s.state, receipt)
	if err != nil {
		return nodes.K8sServiceUIDObservationValidation{}, err
	}
	if result.ReceiptTime.IsZero() || receipt.IsZero() {
		return nodes.K8sServiceUIDObservationValidation{}, errors.New("receipt missing")
	}
	s.state, s.duplicate = result.NextState, result.Duplicate
	return result, nil
}

func testHTTPK8sUIDScope() (nodes.K8sServiceUIDObservationAgent, nodes.K8sServiceUIDObservationScope) {
	org, site, cluster, connector := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	return nodes.K8sServiceUIDObservationAgent{NodeID: connector, OrgID: org}, nodes.K8sServiceUIDObservationScope{OrgID: org, SiteID: site, ClusterID: cluster, ConnectorNodeID: connector}
}

func httpK8sUIDReport(sequence uint64, entries ...nodes.K8sServiceUIDObservation) nodes.K8sServiceUIDObservationReport {
	return nodes.K8sServiceUIDObservationReport{Version: nodes.K8sServiceUIDObservationVersion, Sequence: sequence, Digest: nodes.K8sServiceUIDObservationDigest(sequence, entries), Observations: entries}
}

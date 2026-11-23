package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

type recordingInventoryStore struct {
	agent  nodes.K8sServiceUIDObservationAgent
	report nodes.K8sServiceInventoryReport
	result nodes.K8sServiceInventoryWriteResult
	err    error
}

func (s *recordingInventoryStore) WriteK8sServiceInventory(_ context.Context, agent nodes.K8sServiceUIDObservationAgent, report nodes.K8sServiceInventoryReport, _ time.Time) (nodes.K8sServiceInventoryWriteResult, error) {
	s.agent, s.report = agent, report
	return s.result, s.err
}

func TestK8sServiceInventoryRetentionObservability(t *testing.T) {
	nodeID, orgID := uuid.New(), uuid.New()
	report := nodes.K8sServiceInventoryReport{Version: 1, Sequence: 7, ObservedAt: time.Now().UTC(), Services: []nodes.K8sServiceInventoryService{{Namespace: "prod", Service: "api", UID: "opaque-uid", Ports: []nodes.K8sServiceInventoryPort{{Protocol: "tcp", Port: 443}}}}}
	report.Digest = nodes.K8sServiceInventoryDigest(report.Sequence, report.ObservedAt, report.Services)
	body, _ := json.Marshal(report)

	for _, test := range []struct {
		name     string
		store    *recordingInventoryStore
		wantCode int
		wantLog  string
	}{
		{name: "prune count", store: &recordingInventoryStore{result: nodes.K8sServiceInventoryWriteResult{PrunedSnapshots: 3}}, wantCode: stdhttp.StatusNoContent, wantLog: "k8s_service_inventory_retention_pruned"},
		{name: "prune failure", store: &recordingInventoryStore{err: errors.Join(nodes.ErrK8sServiceInventoryRetention, errors.New("forced"))}, wantCode: stdhttp.StatusBadRequest, wantLog: "k8s_service_inventory_retention_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			channel := &AgentChannel{serviceInventoryStore: test.store, logger: slog.New(slog.NewTextHandler(&logs, nil))}
			req := httptest.NewRequest(stdhttp.MethodPost, "/agent/k8s-service-inventory", bytes.NewReader(body))
			recorder := httptest.NewRecorder()
			channel.k8sServiceInventoryForAgent(recorder, req, nodes.K8sServiceUIDObservationAgent{NodeID: nodeID, OrgID: orgID})
			if recorder.Code != test.wantCode || !bytes.Contains(logs.Bytes(), []byte(test.wantLog)) {
				t.Fatalf("code=%d logs=%q", recorder.Code, logs.String())
			}
		})
	}
}

func TestK8sServiceInventoryForAgentUsesAuthenticatedScope(t *testing.T) {
	nodeID, orgID := uuid.New(), uuid.New()
	store := &recordingInventoryStore{}
	channel := &AgentChannel{serviceInventoryStore: store}
	report := nodes.K8sServiceInventoryReport{Version: 1, Sequence: 7, ObservedAt: time.Now().UTC(), Services: []nodes.K8sServiceInventoryService{{Namespace: "prod", Service: "api", UID: "opaque-uid", Ports: []nodes.K8sServiceInventoryPort{{Protocol: "tcp", Port: 443}}}}}
	report.Digest = nodes.K8sServiceInventoryDigest(report.Sequence, report.ObservedAt, report.Services)
	body, _ := json.Marshal(report)
	req := httptest.NewRequest(stdhttp.MethodPost, "/agent/k8s-service-inventory", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	channel.k8sServiceInventoryForAgent(recorder, req, nodes.K8sServiceUIDObservationAgent{NodeID: nodeID, OrgID: orgID})
	if recorder.Code != stdhttp.StatusNoContent || store.agent.NodeID != nodeID || store.agent.OrgID != orgID || store.report.Sequence != 7 {
		t.Fatalf("code=%d agent=%+v report=%+v", recorder.Code, store.agent, store.report)
	}
	if bytes.Contains(body, []byte("org_id")) || bytes.Contains(body, []byte("cluster_id")) || bytes.Contains(body, []byte("connector")) {
		t.Fatalf("payload carried server-owned scope: %s", body)
	}
}

// K8N-4 slice B: the channel takes a version 2 report with labels, still takes a version 1 report, and
// refuses label data on version 1 with the one answer every refused report gets.
func TestK8sServiceInventoryForAgentAcceptsLabelsOnlyAsVersion2(t *testing.T) {
	post := func(report nodes.K8sServiceInventoryReport) (int, *recordingInventoryStore) {
		report.Digest = nodes.K8sServiceInventoryReportDigest(report)
		body, _ := json.Marshal(report)
		store := &recordingInventoryStore{}
		channel := &AgentChannel{serviceInventoryStore: store}
		recorder := httptest.NewRecorder()
		channel.k8sServiceInventoryForAgent(recorder, httptest.NewRequest(stdhttp.MethodPost, "/agent/k8s-service-inventory", bytes.NewReader(body)), nodes.K8sServiceUIDObservationAgent{NodeID: uuid.New(), OrgID: uuid.New()})
		return recorder.Code, store
	}
	service := nodes.K8sServiceInventoryService{Namespace: "prod", Service: "api", UID: "opaque-uid", Ports: []nodes.K8sServiceInventoryPort{{Protocol: "tcp", Port: 443}},
		Labels: map[string]string{"app": "api"}, LabelsTruncated: true}
	now := time.Now().UTC()
	code, store := post(nodes.K8sServiceInventoryReport{Version: 2, Sequence: 7, ObservedAt: now, Services: []nodes.K8sServiceInventoryService{service}})
	if code != stdhttp.StatusNoContent || store.report.Version != 2 || store.report.Services[0].Labels["app"] != "api" || !store.report.Services[0].LabelsTruncated {
		t.Fatalf("version 2: code=%d report=%+v", code, store.report)
	}
	if code, store := post(nodes.K8sServiceInventoryReport{Version: 1, Sequence: 7, ObservedAt: now, Services: []nodes.K8sServiceInventoryService{service}}); code != stdhttp.StatusBadRequest || store.report.Sequence != 0 {
		t.Fatalf("version 1 with labels: code=%d stored=%+v", code, store.report)
	}
	service.Labels, service.LabelsTruncated = nil, false
	if code, store := post(nodes.K8sServiceInventoryReport{Version: 1, Sequence: 7, ObservedAt: now, Services: []nodes.K8sServiceInventoryService{service}}); code != stdhttp.StatusNoContent || store.report.Version != 1 {
		t.Fatalf("an old gateway's report: code=%d report=%+v", code, store.report)
	}
}

func TestK8sServiceInventoryForAgentRejectsUnknownFields(t *testing.T) {
	channel := &AgentChannel{serviceInventoryStore: &recordingInventoryStore{}}
	req := httptest.NewRequest(stdhttp.MethodPost, "/agent/k8s-service-inventory", bytes.NewBufferString(`{"version":1,"sequence":1,"observed_at":"2026-08-28T00:00:00Z","digest":"x","services":[],"org_id":"forbidden"}`))
	recorder := httptest.NewRecorder()
	channel.k8sServiceInventoryForAgent(recorder, req, nodes.K8sServiceUIDObservationAgent{NodeID: uuid.New(), OrgID: uuid.New()})
	if recorder.Code != stdhttp.StatusBadRequest {
		t.Fatalf("code=%d", recorder.Code)
	}
}

// K8N-4: a NEW report runs the namespace rules for the reporting gateway's organization; a replayed
// one does not; and a failing pass never turns an accepted report into an error for the gateway.
func TestK8sServiceInventoryAcceptedRunsNamespaceRules(t *testing.T) {
	nodeID, orgID := uuid.New(), uuid.New()
	report := nodes.K8sServiceInventoryReport{Version: 1, Sequence: 7, ObservedAt: time.Now().UTC(), Services: []nodes.K8sServiceInventoryService{{Namespace: "prod", Service: "api", UID: "opaque-uid", Ports: []nodes.K8sServiceInventoryPort{{Protocol: "tcp", Port: 443}}}}}
	report.Digest = nodes.K8sServiceInventoryDigest(report.Sequence, report.ObservedAt, report.Services)
	body, _ := json.Marshal(report)

	for _, test := range []struct {
		name      string
		store     *recordingInventoryStore
		hookErr   error
		wantCode  int
		wantCalls int
		wantLog   string
	}{
		{name: "new report", store: &recordingInventoryStore{}, wantCode: stdhttp.StatusNoContent, wantCalls: 1},
		{name: "replayed report", store: &recordingInventoryStore{result: nodes.K8sServiceInventoryWriteResult{Duplicate: true}}, wantCode: stdhttp.StatusNoContent, wantCalls: 0},
		{name: "refused report", store: &recordingInventoryStore{err: nodes.ErrK8sServiceInventoryInvalid}, wantCode: stdhttp.StatusBadRequest, wantCalls: 0},
		{name: "pass fails", store: &recordingInventoryStore{}, hookErr: errors.New("forced"), wantCode: stdhttp.StatusNoContent, wantCalls: 1, wantLog: "k8s_namespace_rules_reconcile_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			var calls []uuid.UUID
			channel := &AgentChannel{serviceInventoryStore: test.store, logger: slog.New(slog.NewTextHandler(&logs, nil))}
			channel.SetK8sServiceInventoryAccepted(func(_ context.Context, org uuid.UUID) error {
				calls = append(calls, org)
				return test.hookErr
			})
			req := httptest.NewRequest(stdhttp.MethodPost, "/agent/k8s-service-inventory", bytes.NewReader(body))
			recorder := httptest.NewRecorder()
			channel.k8sServiceInventoryForAgent(recorder, req, nodes.K8sServiceUIDObservationAgent{NodeID: nodeID, OrgID: orgID})
			if recorder.Code != test.wantCode || len(calls) != test.wantCalls || (test.wantCalls == 1 && calls[0] != orgID) {
				t.Fatalf("code=%d calls=%v", recorder.Code, calls)
			}
			if test.wantLog != "" && !bytes.Contains(logs.Bytes(), []byte(test.wantLog)) {
				t.Fatalf("logs=%q", logs.String())
			}
		})
	}
}

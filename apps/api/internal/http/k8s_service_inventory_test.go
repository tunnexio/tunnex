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

func TestK8sServiceInventoryForAgentRejectsUnknownFields(t *testing.T) {
	channel := &AgentChannel{serviceInventoryStore: &recordingInventoryStore{}}
	req := httptest.NewRequest(stdhttp.MethodPost, "/agent/k8s-service-inventory", bytes.NewBufferString(`{"version":1,"sequence":1,"observed_at":"2026-08-28T00:00:00Z","digest":"x","services":[],"org_id":"forbidden"}`))
	recorder := httptest.NewRecorder()
	channel.k8sServiceInventoryForAgent(recorder, req, nodes.K8sServiceUIDObservationAgent{NodeID: uuid.New(), OrgID: uuid.New()})
	if recorder.Code != stdhttp.StatusBadRequest {
		t.Fatalf("code=%d", recorder.Code)
	}
}

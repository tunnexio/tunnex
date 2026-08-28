package http

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

// k8sServiceUIDObservations is a private mTLS-only future seam. Its body has
// no org/site/cluster/connector fields; the injected store supplies that scope
// from the authenticated selected connector and atomically owns replay state.
func (a *AgentChannel) k8sServiceUIDObservations(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	a.k8sServiceUIDObservationsForAgent(w, r, nodes.K8sServiceUIDObservationAgent{NodeID: node.ID, OrgID: node.OrgID})
}

func (a *AgentChannel) k8sServiceUIDObservationsForAgent(w http.ResponseWriter, r *http.Request, agent nodes.K8sServiceUIDObservationAgent) {
	if a.serviceUIDObservationStore == nil {
		http.Error(w, "Kubernetes Service UID observations unavailable", http.StatusServiceUnavailable)
		return
	}
	var report nodes.K8sServiceUIDObservationReport
	decoder := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid Kubernetes Service UID observation", http.StatusBadRequest)
		return
	}
	if _, err := nodes.ValidateK8sServiceUIDObservationReport(report); err != nil {
		http.Error(w, "invalid Kubernetes Service UID observation", http.StatusBadRequest)
		return
	}
	receiptTime := time.Now().UTC()
	_, err := a.serviceUIDObservationStore.UpdateK8sServiceUIDObservations(r.Context(), agent, report, receiptTime, func(scope nodes.K8sServiceUIDObservationScope, state nodes.K8sServiceUIDObservationState, durableReceiptTime time.Time) (nodes.K8sServiceUIDObservationValidation, error) {
		return nodes.ValidateK8sServiceUIDObservations(durableReceiptTime, agent, scope, report, state)
	})
	if err != nil {
		// Scope/replay predicates intentionally share one response; a selected
		// connector cannot use this endpoint as a cluster or incarnation oracle.
		http.Error(w, "invalid Kubernetes Service UID observation", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

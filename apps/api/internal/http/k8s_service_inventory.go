package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

func (a *AgentChannel) k8sServiceInventory(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	a.k8sServiceInventoryForAgent(w, r, nodes.K8sServiceUIDObservationAgent{NodeID: node.ID, OrgID: node.OrgID})
}

func (a *AgentChannel) k8sServiceInventoryForAgent(w http.ResponseWriter, r *http.Request, agent nodes.K8sServiceUIDObservationAgent) {
	if a.serviceInventoryStore == nil {
		http.Error(w, "Kubernetes Service inventory unavailable", http.StatusServiceUnavailable)
		return
	}
	var report nodes.K8sServiceInventoryReport
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid Kubernetes Service inventory", http.StatusBadRequest)
		return
	}
	if _, err := nodes.ValidateK8sServiceInventoryReport(report); err != nil {
		http.Error(w, "invalid Kubernetes Service inventory", http.StatusBadRequest)
		return
	}
	result, err := a.serviceInventoryStore.WriteK8sServiceInventory(r.Context(), agent, report, time.Now().UTC())
	if err != nil {
		if errors.Is(err, nodes.ErrK8sServiceInventoryRetention) && a.logger != nil {
			a.logger.Error("k8s_service_inventory_retention_failed",
				slog.String("org_id", agent.OrgID.String()),
				slog.String("node_id", agent.NodeID.String()),
				slog.String("error", err.Error()))
		}
		// Reporter authority, generation, replay and identity predicates share one
		// response so the channel cannot be used as a cluster incarnation oracle.
		http.Error(w, "invalid Kubernetes Service inventory", http.StatusBadRequest)
		return
	}
	if result.PrunedSnapshots > 0 && a.logger != nil {
		a.logger.Info("k8s_service_inventory_retention_pruned",
			slog.String("org_id", agent.OrgID.String()),
			slog.String("node_id", agent.NodeID.String()),
			slog.Int64("pruned_snapshots", result.PrunedSnapshots))
	}
	if !result.Duplicate && a.serviceInventoryAccepted != nil {
		// The report is stored whatever happens here. Detached from the request so a gateway that hangs
		// up cannot leave a pass half-decided; bounded so a slow pass cannot hold the channel.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Second)
		if err := a.serviceInventoryAccepted(ctx, agent.OrgID); err != nil && a.logger != nil {
			a.logger.Warn("k8s_namespace_rules_reconcile_failed",
				slog.String("org_id", agent.OrgID.String()),
				slog.String("node_id", agent.NodeID.String()),
				slog.String("error", err.Error()))
		}
		cancel()
	}
	w.WriteHeader(http.StatusNoContent)
}

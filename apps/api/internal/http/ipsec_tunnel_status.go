package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"net/http"
)

type ipsecStatusRepository interface {
	ReadStatus(context.Context, uuid.UUID, uuid.UUID) (ipsec.ConnectionStatus, error)
}
type agentIPsecStatusRepository interface {
	ReportStatus(context.Context, ipsec.RuntimePrincipal, uuid.UUID, ipsec.RuntimeStatusReport) error
}

func (s apiServer) GetIPsecConnectionStatus(ctx context.Context, req api.GetIPsecConnectionStatusRequestObject) (api.GetIPsecConnectionStatusResponseObject, error) {
	ctx, e := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if e != nil {
		return nil, e
	}
	if s.ipsecStatus == nil {
		return nil, ipsecProviderError(ipsec.ErrConnectionUnavailable)
	}
	status, e := s.ipsecStatus.ReadStatus(ctx, req.OrgId, req.ConnectionId)
	if e != nil {
		return nil, ipsecProviderError(e)
	}
	body := api.IPsecConnectionStatus{RecoveryVersion: (*api.IPsecConnectionStatusRecoveryVersion)(status.RecoveryVersion), ActiveSlot: status.ActiveSlot, SelectionSequence: status.SelectionSequence, ObservedAt: status.ObservedAt, Tunnels: []api.IPsecTunnelStatus{}}
	for _, t := range status.Tunnels {
		body.Tunnels = append(body.Tunnels, api.IPsecTunnelStatus{Id: t.ID, Slot: t.Slot, Status: api.IPsecTunnelStatusStatus(t.Status), Selected: t.Selected})
	}
	return api.GetIPsecConnectionStatus200JSONResponse{Body: body, Headers: api.GetIPsecConnectionStatus200ResponseHeaders{CacheControl: "no-store", XRequestId: reqID(ctx)}}, nil
}
func (a *AgentChannel) ipsecStatusReport(w http.ResponseWriter, r *http.Request) {
	p, r, ok := a.ipsecPrincipal(w, r)
	if !ok {
		return
	}
	id, ok := agentIPsecConnection(w, r)
	if !ok {
		return
	}
	var body struct {
		RecoveryVersion       *int      `json:"recovery_version,omitempty"`
		SelectionSequence     *uint64   `json:"selection_sequence,omitempty"`
		ActiveSlot            *int      `json:"active_slot,omitempty"`
		DeliveryID            uuid.UUID `json:"delivery_id"`
		DesiredRevision       int64     `json:"desired_revision"`
		ConfigurationRevision int64     `json:"configuration_revision"`
		Tunnels               []struct {
			ID       uuid.UUID `json:"id"`
			Slot     int       `json:"slot"`
			Status   string    `json:"status"`
			Selected *bool     `json:"selected"`
		} `json:"tunnels"`
	}
	if !decodeAgentIPsec(w, r, &body) {
		return
	}
	if len(body.Tunnels) != 2 {
		agentIPsecInvalid(w, r)
		return
	}
	var tunnels [2]ipsec.RuntimeTunnelStatus
	for i, t := range body.Tunnels {
		if t.Selected == nil {
			agentIPsecInvalid(w, r)
			return
		}
		tunnels[i] = ipsec.RuntimeTunnelStatus{ID: t.ID, Slot: t.Slot, Status: t.Status, Selected: *t.Selected}
	}
	store, ok := a.ipsecRuntime.(agentIPsecStatusRepository)
	if !ok {
		writeAgentIPsec(w, r, nil, ipsec.ErrConnectionUnavailable)
		return
	}
	e := store.ReportStatus(r.Context(), p, id, ipsec.RuntimeStatusReport{RecoveryVersion: body.RecoveryVersion, SelectionSequence: body.SelectionSequence, ActiveSlot: body.ActiveSlot, DeliveryID: body.DeliveryID, DesiredRevision: body.DesiredRevision, ConfigurationRevision: body.ConfigurationRevision, Tunnels: tunnels})
	if e != nil {
		writeAgentIPsec(w, r, nil, e)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

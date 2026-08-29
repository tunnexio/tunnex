package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

const kubernetesOwnershipBaseAuthorityAckJSONLimit = 16 << 10

func (a *AgentChannel) withKubernetesOwnershipBaseAuthority(ctx context.Context, node sqlc.Node, state desiredStateWithGatewayDNSRequest) (desiredStateWithGatewayDNSRequest, error) {
	if a.baseAuthorityStore == nil || !node.SiteID.Valid {
		return state, nil
	}
	siteID := uuid.UUID(node.SiteID.Bytes)
	agent := nodes.KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: node.ID, OrgID: node.OrgID, SiteID: siteID}
	authority, found, err := a.baseAuthorityStore.LoadPendingKubernetesOwnershipBaseAuthority(ctx, agent)
	if err != nil {
		return desiredStateWithGatewayDNSRequest{}, err
	}
	if !found {
		return state, nil
	}
	hash, err := nodes.KubernetesOwnershipBaseStateHash(state.DesiredState)
	if err != nil || authority.NodeID != node.ID.String() || authority.OrgID != node.OrgID.String() || authority.SiteID != siteID.String() ||
		authority.BaseVersion != state.Version || authority.BaseHash != hash {
		return desiredStateWithGatewayDNSRequest{}, fmt.Errorf("Kubernetes ownership base authority does not match the exact desired base")
	}
	state.KubernetesOwnershipBaseAuthority = &authority
	return state, nil
}

func (a *AgentChannel) kubernetesOwnershipBaseAuthorityAck(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	if !node.SiteID.Valid {
		http.Error(w, "base-authority acknowledgement unavailable", http.StatusServiceUnavailable)
		return
	}
	a.kubernetesOwnershipBaseAuthorityAckForAgent(w, r, nodes.KubernetesOwnershipBaseAuthorityAgentIdentity{
		NodeID: node.ID, OrgID: node.OrgID, SiteID: uuid.UUID(node.SiteID.Bytes),
	})
}

func (a *AgentChannel) kubernetesOwnershipBaseAuthorityAckForAgent(w http.ResponseWriter, r *http.Request, agent nodes.KubernetesOwnershipBaseAuthorityAgentIdentity) {
	if a.baseAuthorityStore == nil {
		http.Error(w, "base-authority acknowledgement unavailable", http.StatusServiceUnavailable)
		return
	}
	var ack nodes.KubernetesOwnershipBaseAuthorityAck
	if err := decodeKubernetesOwnershipBaseAuthorityAck(r.Body, &ack); err != nil {
		http.Error(w, "invalid base-authority acknowledgement", http.StatusBadRequest)
		return
	}
	if _, err := a.baseAuthorityStore.AcknowledgeKubernetesOwnershipBaseAuthority(r.Context(), agent, ack, time.Now().UTC()); err != nil {
		http.Error(w, "invalid base-authority acknowledgement", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeKubernetesOwnershipBaseAuthorityAck(body io.Reader, ack *nodes.KubernetesOwnershipBaseAuthorityAck) error {
	raw, err := io.ReadAll(io.LimitReader(body, kubernetesOwnershipBaseAuthorityAckJSONLimit+1))
	if err != nil {
		return err
	}
	if len(raw) > kubernetesOwnershipBaseAuthorityAckJSONLimit {
		return fmt.Errorf("base-authority acknowledgement exceeds limit")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(ack); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("multiple base-authority acknowledgement values")
	}
	return nil
}

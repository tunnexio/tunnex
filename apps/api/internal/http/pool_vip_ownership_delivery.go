package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

const poolVIPOwnershipDeliveryCapabilityHeader = "X-Tunnex-Pool-VIP-Ownership-Delivery-Version"

// The ownership protocol is intentionally small and fixed-shape. This cap
// bounds decoder allocation and is shared with the node mirror. The decoder
// reads one extra byte so a valid value followed by oversized trailing input
// cannot be mistaken for a bounded request.
const poolVIPOwnershipDeliveryJSONLimit = 16 << 10

func (a *AgentChannel) poolVIPOwnershipDelivery(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	a.poolVIPOwnershipDeliveryForAgent(w, r, nodes.PoolVIPOwnershipAgentIdentity{NodeID: node.ID, OrgID: node.OrgID})
}

func (a *AgentChannel) poolVIPOwnershipDeliveryForAgent(w http.ResponseWriter, r *http.Request, agent nodes.PoolVIPOwnershipAgentIdentity) {
	version, advertised, err := poolVIPOwnershipDeliveryAdvertised(r)
	if err != nil {
		http.Error(w, "unsupported ownership delivery version", http.StatusBadRequest)
		return
	}
	// A missing capability is not a v1-capable agent. This preserves old agents
	// and a new agent talking to an unwired control plane receives no work.
	if !advertised || a.ownershipDeliveryStore == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if version == nodes.PoolVIPOwnershipDeliveryHandoffVersion {
		store, ok := a.ownershipDeliveryStore.(nodes.PoolVIPOwnershipDeliveryHandoffStore)
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		envelope, found, err := store.LoadIssuedPoolVIPOwnershipDeliveryV3(r.Context(), agent)
		if err != nil {
			http.Error(w, "ownership delivery unavailable", http.StatusServiceUnavailable)
			return
		}
		if !found {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := nodes.ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil || envelope.TargetNodeID != agent.NodeID.String() || envelope.OrgID != agent.OrgID.String() {
			http.Error(w, "ownership delivery unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, envelope)
		return
	}
	if version == nodes.PoolVIPOwnershipDeliveryAttestationVersion {
		store, ok := a.ownershipDeliveryStore.(nodes.PoolVIPOwnershipDeliveryAttestationStore)
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		envelope, found, err := store.LoadIssuedPoolVIPOwnershipDeliveryV2(r.Context(), agent)
		if err != nil {
			http.Error(w, "ownership delivery unavailable", http.StatusServiceUnavailable)
			return
		}
		if !found {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := nodes.ValidatePoolVIPOwnershipDeliveryEnvelopeV2(envelope); err != nil || envelope.TargetNodeID != agent.NodeID.String() || envelope.OrgID != agent.OrgID.String() {
			http.Error(w, "ownership delivery unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, envelope)
		return
	}
	envelope, found, err := a.ownershipDeliveryStore.LoadIssuedPoolVIPOwnershipDelivery(r.Context(), agent)
	if err != nil {
		http.Error(w, "ownership delivery unavailable", http.StatusServiceUnavailable)
		return
	}
	if !found {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := nodes.ValidatePoolVIPOwnershipDeliveryEnvelope(envelope); err != nil || envelope.TargetNodeID != agent.NodeID.String() || envelope.OrgID != agent.OrgID.String() {
		// Issued state that does not match the mTLS principal is a durable-owner
		// fault, not an alternate delivery the handler may reinterpret.
		http.Error(w, "ownership delivery unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, envelope)
}

func (a *AgentChannel) poolVIPOwnershipDeliveryAck(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	a.poolVIPOwnershipDeliveryAckForAgent(w, r, nodes.PoolVIPOwnershipAgentIdentity{NodeID: node.ID, OrgID: node.OrgID})
}

func (a *AgentChannel) poolVIPOwnershipDeliveryAckForAgent(w http.ResponseWriter, r *http.Request, agent nodes.PoolVIPOwnershipAgentIdentity) {
	version, advertised, err := poolVIPOwnershipDeliveryAdvertised(r)
	if err != nil || !advertised {
		http.Error(w, "unsupported ownership delivery version", http.StatusBadRequest)
		return
	}
	if a.ownershipDeliveryStore == nil {
		http.Error(w, "ownership delivery unavailable", http.StatusServiceUnavailable)
		return
	}
	receiptTime := time.Now().UTC()
	if version == nodes.PoolVIPOwnershipDeliveryHandoffVersion {
		var ack nodes.PoolVIPOwnershipDeliveryAckV3
		if err := decodePoolVIPOwnershipDeliveryJSON(r.Body, &ack); err != nil || ack.Version != nodes.PoolVIPOwnershipDeliveryHandoffVersion {
			http.Error(w, "invalid ownership delivery acknowledgement", http.StatusBadRequest)
			return
		}
		store, ok := a.ownershipDeliveryStore.(nodes.PoolVIPOwnershipDeliveryHandoffStore)
		if !ok {
			http.Error(w, "ownership delivery unavailable", http.StatusServiceUnavailable)
			return
		}
		_, err := store.UpdatePoolVIPOwnershipAckV3(r.Context(), agent, ack, receiptTime, func(envelope nodes.PoolVIPOwnershipDeliveryEnvelopeV3, state nodes.PoolVIPOwnershipAckState) (nodes.PoolVIPOwnershipAckValidation, error) {
			return nodes.ValidatePoolVIPOwnershipDeliveryAckV3(receiptTime, agent, envelope, ack, state)
		})
		if err != nil {
			http.Error(w, "invalid ownership delivery acknowledgement", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if version == nodes.PoolVIPOwnershipDeliveryAttestationVersion {
		var ack nodes.PoolVIPOwnershipDeliveryAckV2
		if err := decodePoolVIPOwnershipDeliveryJSON(r.Body, &ack); err != nil || ack.Version != nodes.PoolVIPOwnershipDeliveryAttestationVersion {
			http.Error(w, "invalid ownership delivery acknowledgement", http.StatusBadRequest)
			return
		}
		store, ok := a.ownershipDeliveryStore.(nodes.PoolVIPOwnershipDeliveryAttestationStore)
		if !ok {
			http.Error(w, "ownership delivery unavailable", http.StatusServiceUnavailable)
			return
		}
		_, err := store.UpdatePoolVIPOwnershipAckV2(r.Context(), agent, ack, receiptTime, func(envelope nodes.PoolVIPOwnershipDeliveryEnvelopeV2, state nodes.PoolVIPOwnershipAckState) (nodes.PoolVIPOwnershipAckValidation, error) {
			return nodes.ValidatePoolVIPOwnershipDeliveryAckV2(receiptTime, agent, envelope, ack, state)
		})
		if err != nil {
			http.Error(w, "invalid ownership delivery acknowledgement", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var ack nodes.PoolVIPOwnershipDeliveryAck
	if err := decodePoolVIPOwnershipDeliveryJSON(r.Body, &ack); err != nil || ack.Version != nodes.PoolVIPOwnershipDeliveryVersion {
		http.Error(w, "invalid ownership delivery acknowledgement", http.StatusBadRequest)
		return
	}
	_, err = a.ownershipDeliveryStore.UpdatePoolVIPOwnershipAck(r.Context(), agent, ack, receiptTime, func(envelope nodes.PoolVIPOwnershipDeliveryEnvelope, state nodes.PoolVIPOwnershipAckState) (nodes.PoolVIPOwnershipAckValidation, error) {
		return nodes.ValidatePoolVIPOwnershipDeliveryAck(receiptTime, agent, envelope, ack, state)
	})
	if err != nil {
		// The pure validator intentionally refuses malformed, swapped, stale, and
		// replayed acknowledgements without reporting which predicate failed.
		http.Error(w, "invalid ownership delivery acknowledgement", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func poolVIPOwnershipDeliveryAdvertised(r *http.Request) (int, bool, error) {
	values := r.Header.Values(poolVIPOwnershipDeliveryCapabilityHeader)
	if len(values) == 0 {
		return 0, false, nil
	}
	if len(values) != 1 {
		return 0, false, fmt.Errorf("unsupported ownership delivery capability")
	}
	for _, version := range []int{nodes.PoolVIPOwnershipDeliveryVersion, nodes.PoolVIPOwnershipDeliveryAttestationVersion, nodes.PoolVIPOwnershipDeliveryHandoffVersion} {
		if values[0] == fmt.Sprint(version) {
			return version, true, nil
		}
	}
	return 0, false, fmt.Errorf("unsupported ownership delivery capability")
}

func decodePoolVIPOwnershipDeliveryJSON(body io.Reader, dst any) error {
	raw, err := io.ReadAll(io.LimitReader(body, poolVIPOwnershipDeliveryJSONLimit+1))
	if err != nil {
		return err
	}
	if len(raw) > poolVIPOwnershipDeliveryJSONLimit {
		return fmt.Errorf("ownership delivery JSON exceeds %d bytes", poolVIPOwnershipDeliveryJSONLimit)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

// rejectDuplicateJSONKeys makes the private wire contract unambiguous before
// typed decoding. encoding/json otherwise accepts a duplicate object member and
// silently keeps the last value, which can differ from another parser's view.
func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValueForDuplicateKeys(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func scanJSONValueForDuplicateKeys(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate JSON object key")
			}
			seen[name] = struct{}{}
			if err := scanJSONValueForDuplicateKeys(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			if err != nil {
				return err
			}
			return fmt.Errorf("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValueForDuplicateKeys(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			if err != nil {
				return err
			}
			return fmt.Errorf("unterminated JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}

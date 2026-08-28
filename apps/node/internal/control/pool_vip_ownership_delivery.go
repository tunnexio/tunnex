package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// PoolVIPOwnershipDeliveryVersion is independent from the compiled-policy
// protocol version. A newer agent must reject, rather than acknowledge, a
// future ownership-delivery version.
const PoolVIPOwnershipDeliveryVersion = 1

const poolVIPOwnershipDeliveryCapabilityHeader = "X-Tunnex-Pool-VIP-Ownership-Delivery-Version"

// Keep this wire cap identical to the control-plane decoder. The extra byte
// makes a valid JSON value plus trailing oversized bytes a hard refusal.
const poolVIPOwnershipDeliveryJSONLimit = 16 << 10

var (
	poolVIPOwnershipDeliveryUUIDRE  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	poolVIPOwnershipDeliveryHex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	poolVIPOwnershipDeliveryNilUUID = "00000000-0000-0000-0000-000000000000"
)

// PoolVIPOwnershipDeliveryEnvelope mirrors the private mTLS v1 response. It
// is receipt-only in this slice: it neither changes routes nor transitions a
// gateway into serving.
type PoolVIPOwnershipDeliveryEnvelope struct {
	Version             int    `json:"version"`
	OrgID               string `json:"org_id"`
	SiteID              string `json:"site_id"`
	ClusterID           string `json:"cluster_id"`
	PoolID              string `json:"pool_id"`
	ConnectorNodeID     string `json:"connector_node_id"`
	TargetNodeID        string `json:"target_node_id"`
	OperationID         string `json:"operation_id"`
	ManifestIdentity    string `json:"manifest_identity"`
	Role                string `json:"role"`
	PromotionGeneration uint64 `json:"promotion_generation"`
	ManifestRevision    uint64 `json:"manifest_revision"`
	LeaseEpoch          uint64 `json:"lease_epoch"`
	DeliveryPhase       string `json:"delivery_phase"`
	DeliveryID          string `json:"delivery_id"`
	DeliveryNonce       string `json:"delivery_nonce"`
}

// PoolVIPOwnershipDeliveryAck is the agent's exact receipt echo. ObservedAt is
// diagnostic-only; the control plane records its own receipt time.
type PoolVIPOwnershipDeliveryAck struct {
	Version             int       `json:"version"`
	OrgID               string    `json:"org_id"`
	SiteID              string    `json:"site_id"`
	ClusterID           string    `json:"cluster_id"`
	PoolID              string    `json:"pool_id"`
	ConnectorNodeID     string    `json:"connector_node_id"`
	TargetNodeID        string    `json:"target_node_id"`
	OperationID         string    `json:"operation_id"`
	ManifestIdentity    string    `json:"manifest_identity"`
	Role                string    `json:"role"`
	PromotionGeneration uint64    `json:"promotion_generation"`
	ManifestRevision    uint64    `json:"manifest_revision"`
	LeaseEpoch          uint64    `json:"lease_epoch"`
	DeliveryPhase       string    `json:"delivery_phase"`
	DeliveryID          string    `json:"delivery_id"`
	DeliveryNonce       string    `json:"delivery_nonce"`
	AgentObservedAt     time.Time `json:"agent_observed_at"`
}

// PollPoolVIPOwnershipDelivery advertises precisely v1 on the existing mTLS
// channel, acknowledges only a fully valid v1 envelope, and returns whether an
// acknowledgement was accepted. It is intentionally not scheduled or applied
// by the agent in this prerequisite slice.
func (c *Client) PollPoolVIPOwnershipDelivery(ctx context.Context) (bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/agent/pool-vip-ownership-delivery", nil)
	req.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, fmt.Sprint(PoolVIPOwnershipDeliveryVersion))
	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("ownership delivery status %d", resp.StatusCode)
	}
	var envelope PoolVIPOwnershipDeliveryEnvelope
	if err := decodePoolVIPOwnershipDeliveryJSON(resp.Body, &envelope); err != nil {
		return false, fmt.Errorf("decode ownership delivery: %w", err)
	}
	if err := validPoolVIPOwnershipDeliveryEnvelope(envelope); err != nil {
		return false, fmt.Errorf("invalid ownership delivery: %w", err)
	}
	ack := poolVIPOwnershipDeliveryAck(envelope, time.Now().UTC())
	body, err := json.Marshal(ack)
	if err != nil {
		return false, err
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/pool-vip-ownership-delivery/ack", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, fmt.Sprint(PoolVIPOwnershipDeliveryVersion))
	resp, err = c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return false, fmt.Errorf("ownership delivery acknowledgement status %d", resp.StatusCode)
	}
	return true, nil
}

func poolVIPOwnershipDeliveryAck(envelope PoolVIPOwnershipDeliveryEnvelope, observedAt time.Time) PoolVIPOwnershipDeliveryAck {
	return PoolVIPOwnershipDeliveryAck{
		Version: envelope.Version, OrgID: envelope.OrgID, SiteID: envelope.SiteID, ClusterID: envelope.ClusterID,
		PoolID: envelope.PoolID, ConnectorNodeID: envelope.ConnectorNodeID, TargetNodeID: envelope.TargetNodeID,
		OperationID: envelope.OperationID, ManifestIdentity: envelope.ManifestIdentity, Role: envelope.Role,
		PromotionGeneration: envelope.PromotionGeneration, ManifestRevision: envelope.ManifestRevision,
		LeaseEpoch: envelope.LeaseEpoch, DeliveryPhase: envelope.DeliveryPhase, DeliveryID: envelope.DeliveryID,
		DeliveryNonce: envelope.DeliveryNonce, AgentObservedAt: observedAt,
	}
}

func decodePoolVIPOwnershipDeliveryJSON(body io.Reader, dst any) error {
	raw, err := io.ReadAll(io.LimitReader(body, poolVIPOwnershipDeliveryJSONLimit+1))
	if err != nil {
		return err
	}
	if len(raw) > poolVIPOwnershipDeliveryJSONLimit {
		return fmt.Errorf("ownership delivery JSON exceeds %d bytes", poolVIPOwnershipDeliveryJSONLimit)
	}
	if err := rejectDuplicatePoolVIPOwnershipJSONKeys(raw); err != nil {
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

// rejectDuplicatePoolVIPOwnershipJSONKeys keeps the private mTLS contract
// parser-independent: encoding/json otherwise accepts duplicate members and
// silently retains the last value.
func rejectDuplicatePoolVIPOwnershipJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanPoolVIPOwnershipJSONValue(decoder); err != nil {
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

func scanPoolVIPOwnershipJSONValue(decoder *json.Decoder) error {
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
			if err := scanPoolVIPOwnershipJSONValue(decoder); err != nil {
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
			if err := scanPoolVIPOwnershipJSONValue(decoder); err != nil {
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

func validPoolVIPOwnershipDeliveryEnvelope(envelope PoolVIPOwnershipDeliveryEnvelope) error {
	if envelope.Version != PoolVIPOwnershipDeliveryVersion {
		return fmt.Errorf("unsupported delivery version")
	}
	for field, value := range map[string]string{
		"org_id": envelope.OrgID, "site_id": envelope.SiteID, "cluster_id": envelope.ClusterID,
		"pool_id": envelope.PoolID, "connector_node_id": envelope.ConnectorNodeID,
		"target_node_id": envelope.TargetNodeID, "operation_id": envelope.OperationID,
		"delivery_id": envelope.DeliveryID,
	} {
		if !validPoolVIPOwnershipDeliveryUUID(value) {
			return fmt.Errorf("invalid %s", field)
		}
	}
	if !poolVIPOwnershipDeliveryHex64RE.MatchString(envelope.ManifestIdentity) || !poolVIPOwnershipDeliveryHex64RE.MatchString(envelope.DeliveryNonce) {
		return fmt.Errorf("invalid manifest identity or delivery nonce")
	}
	if envelope.PromotionGeneration == 0 || envelope.ManifestRevision == 0 || envelope.LeaseEpoch == 0 {
		return fmt.Errorf("promotion generation, manifest revision, and lease epoch must be positive")
	}
	switch envelope.Role {
	case nodepolicy.PoolVIPOwnershipPreparedNonServing:
		if envelope.DeliveryPhase != "prepare" {
			return fmt.Errorf("prepared role requires prepare phase")
		}
	case nodepolicy.PoolVIPOwnershipServing:
		if envelope.DeliveryPhase != "serve" {
			return fmt.Errorf("serving role requires serve phase")
		}
	case nodepolicy.PoolVIPOwnershipWithdrawal:
		if envelope.DeliveryPhase != "withdraw" {
			return fmt.Errorf("withdrawal role requires withdraw phase")
		}
	default:
		return fmt.Errorf("invalid delivery role")
	}
	return nil
}

func validPoolVIPOwnershipDeliveryUUID(value string) bool {
	return poolVIPOwnershipDeliveryUUIDRE.MatchString(value) && value != poolVIPOwnershipDeliveryNilUUID
}

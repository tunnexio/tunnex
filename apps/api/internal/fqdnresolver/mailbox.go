package fqdnresolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GatewayDNSNotifier signals the selected gateway after a request is committed.
// It is a convergence hint only: the durable row is the source of truth, so a
// dropped notification or control-plane failover cannot lose the request.
type GatewayDNSNotifier interface {
	NotifyGatewayDNSRequest(context.Context, uuid.UUID, uuid.UUID)
}

// PostgresGatewayDNSMailbox persists request/response state so any API replica
// can serve the agent's desired-state pull or await its authenticated response.
type PostgresGatewayDNSMailbox struct {
	pool     *pgxpool.Pool
	notifier GatewayDNSNotifier
	poll     time.Duration
	now      func() time.Time
	maxAge   time.Duration
}

func NewPostgresGatewayDNSMailbox(pool *pgxpool.Pool) *PostgresGatewayDNSMailbox {
	return &PostgresGatewayDNSMailbox{pool: pool, poll: 100 * time.Millisecond, now: time.Now, maxAge: GatewayDNSResponseMaxAge}
}

func (m *PostgresGatewayDNSMailbox) WithNotifier(notifier GatewayDNSNotifier) *PostgresGatewayDNSMailbox {
	m.notifier = notifier
	return m
}

func (m *PostgresGatewayDNSMailbox) Enqueue(ctx context.Context, request GatewayDNSRequest) error {
	if m == nil || m.pool == nil || request.RequestID == uuid.Nil || request.Deadline.IsZero() || request.Deadline.Before(m.now()) || !validGatewayDNSResolverConfig(request) {
		return ErrGatewayDNSRPCMalformed
	}
	types, err := json.Marshal(request.RecordTypes)
	if err != nil {
		return err
	}
	endpoints, err := json.Marshal(request.ResolverEndpoints)
	if err != nil {
		return err
	}
	tx, err := m.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := validateCurrentMailboxContext(ctx, tx, request); err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
INSERT INTO fqdn_gateway_dns_requests
  (request_id,protocol_version,org_id,resource_id,site_id,gateway_id,resolver_config_id,resolver_config_version,resolver_endpoints,hostname,record_types,deadline,state)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending')
ON CONFLICT (request_id) DO NOTHING`, request.RequestID, request.Version, request.OrgID, request.ResourceID, request.SiteID, request.GatewayID, request.ResolverConfigID, request.ResolverConfigVersion, endpoints, request.Hostname, types, request.Deadline)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if command.RowsAffected() == 1 && m.notifier != nil {
		m.notifier.NotifyGatewayDNSRequest(ctx, request.OrgID, request.GatewayID)
	}
	return nil
}

// PendingForGateway is consumed by the authenticated selected gateway through
// desired state. It never returns a request for another organization/gateway
// and marks expired pending work before reading, so a reconnect cannot revive
// an old request.
func (m *PostgresGatewayDNSMailbox) PendingForGateway(ctx context.Context, orgID, gatewayID uuid.UUID, limit int) ([]GatewayDNSRequest, error) {
	if m == nil || m.pool == nil || orgID == uuid.Nil || gatewayID == uuid.Nil || limit <= 0 {
		return nil, nil
	}
	if _, err := m.pool.Exec(ctx, `UPDATE fqdn_gateway_dns_requests SET state='expired',expired_at=now() WHERE org_id=$1 AND gateway_id=$2 AND state='pending' AND deadline<now()`, orgID, gatewayID); err != nil {
		return nil, err
	}
	rows, err := m.pool.Query(ctx, `
SELECT request_id,protocol_version,org_id,resource_id,site_id,gateway_id,resolver_config_id,resolver_config_version,resolver_endpoints,hostname,record_types,deadline
FROM fqdn_gateway_dns_requests
WHERE org_id=$1 AND gateway_id=$2 AND state='pending' AND deadline>=now()
ORDER BY created_at,request_id LIMIT $3`, orgID, gatewayID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GatewayDNSRequest
	for rows.Next() {
		var request GatewayDNSRequest
		var types, endpoints []byte
		if err := rows.Scan(&request.RequestID, &request.Version, &request.OrgID, &request.ResourceID, &request.SiteID, &request.GatewayID, &request.ResolverConfigID, &request.ResolverConfigVersion, &endpoints, &request.Hostname, &types, &request.Deadline); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(types, &request.RecordTypes); err != nil {
			return nil, fmt.Errorf("decode persisted DNS RPC record types: %w", err)
		}
		if err := json.Unmarshal(endpoints, &request.ResolverEndpoints); err != nil {
			return nil, fmt.Errorf("decode persisted DNS RPC resolver config: %w", err)
		}
		if !validGatewayDNSResolverConfig(request) {
			return nil, ErrGatewayDNSRPCMalformed
		}
		out = append(out, request)
	}
	return out, rows.Err()
}

// Complete is called only after the agent-control handler authenticated the
// client certificate and supplies that authenticated org/gateway pair. It locks
// the durable row, validates the full echoed response, and permits one terminal
// completion. A second completion/replay is refused.
func (m *PostgresGatewayDNSMailbox) Complete(ctx context.Context, authenticatedOrg, authenticatedGateway uuid.UUID, response GatewayDNSResponse) error {
	if m == nil || m.pool == nil || authenticatedOrg == uuid.Nil || authenticatedGateway == uuid.Nil || response.RequestID == uuid.Nil {
		return ErrGatewayDNSRPCMalformed
	}
	tx, err := m.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var request GatewayDNSRequest
	var types, endpoints []byte
	err = tx.QueryRow(ctx, `
SELECT request_id,protocol_version,org_id,resource_id,site_id,gateway_id,resolver_config_id,resolver_config_version,resolver_endpoints,hostname,record_types,deadline
FROM fqdn_gateway_dns_requests WHERE request_id=$1 FOR UPDATE`, response.RequestID).
		Scan(&request.RequestID, &request.Version, &request.OrgID, &request.ResourceID, &request.SiteID, &request.GatewayID, &request.ResolverConfigID, &request.ResolverConfigVersion, &endpoints, &request.Hostname, &types, &request.Deadline)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrGatewayDNSRPCReplay
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(types, &request.RecordTypes); err != nil {
		return err
	}
	if err := json.Unmarshal(endpoints, &request.ResolverEndpoints); err != nil || !validGatewayDNSResolverConfig(request) {
		return ErrGatewayDNSRPCMalformed
	}
	if request.OrgID != authenticatedOrg || request.GatewayID != authenticatedGateway {
		return ErrGatewayDNSRPCIdentity
	}
	if err := validateCurrentMailboxContext(ctx, tx, request); err != nil {
		if errors.Is(err, ErrSuperseded) {
			if _, updateErr := tx.Exec(ctx, `UPDATE fqdn_gateway_dns_requests SET state='expired',expired_at=now() WHERE request_id=$1 AND state='pending'`, request.RequestID); updateErr != nil {
				return updateErr
			}
			if commitErr := tx.Commit(ctx); commitErr != nil {
				return commitErr
			}
		}
		return err
	}
	if m.now().After(request.Deadline) {
		if _, err := tx.Exec(ctx, `UPDATE fqdn_gateway_dns_requests SET state='expired',expired_at=now() WHERE request_id=$1 AND state='pending'`, request.RequestID); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return ErrGatewayDNSRPCStale
	}
	if _, validationErr := validateGatewayDNSResponse(request, response, m.now(), m.maxAge); validationErr != nil && !isTerminalTransportResponse(response, validationErr) {
		return validationErr
	}
	body, err := json.Marshal(response)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE fqdn_gateway_dns_requests SET state='completed',response=$2,completed_at=now() WHERE request_id=$1 AND state='pending'`, request.RequestID, body)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrGatewayDNSRPCReplay
	}
	return tx.Commit(ctx)
}

// validateCurrentMailboxContext is the tenant/context integrity boundary. The
// scheduler derives requests from storage, but a stale replica or programming
// mistake must still never bind a resource in one org to a Site/Gateway from
// another or to a gateway that was reselected/moved after enqueue. Locking the
// resource row serializes this check with resolver-context edits.
func validateCurrentMailboxContext(ctx context.Context, tx pgx.Tx, request GatewayDNSRequest) error {
	if !validGatewayDNSResolverConfig(request) {
		return ErrSuperseded
	}
	var resourceOrg, selectedSite, selectedGateway, siteOrg, gatewayOrg, gatewaySite uuid.UUID
	err := tx.QueryRow(ctx, `
SELECT r.org_id,r.resolver_site_id,r.resolver_node_id,s.org_id,n.org_id,n.site_id
FROM fqdn_resources r
JOIN sites s ON s.id=r.resolver_site_id
JOIN nodes n ON n.id=r.resolver_node_id
WHERE r.id=$1 FOR UPDATE`, request.ResourceID).
		Scan(&resourceOrg, &selectedSite, &selectedGateway, &siteOrg, &gatewayOrg, &gatewaySite)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSuperseded
	}
	if err != nil {
		return err
	}
	if resourceOrg != request.OrgID || siteOrg != request.OrgID || gatewayOrg != request.OrgID || selectedSite != request.SiteID || selectedGateway != request.GatewayID || gatewaySite != request.SiteID {
		return ErrSuperseded
	}
	var configID uuid.UUID
	var configVersion int64
	err = tx.QueryRow(ctx, `
SELECT id,version
FROM fqdn_resolver_context_configs
WHERE org_id=$1 AND site_id=$2 AND gateway_id=$3 AND state='active'
FOR UPDATE`, request.OrgID, request.SiteID, request.GatewayID).Scan(&configID, &configVersion)
	if errors.Is(err, pgx.ErrNoRows) || configID != request.ResolverConfigID || configVersion != request.ResolverConfigVersion {
		return ErrSuperseded
	}
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `
SELECT host(address),port,transport
FROM fqdn_resolver_context_endpoints
WHERE config_id=$1 AND org_id=$2
ORDER BY ordinal`, configID, request.OrgID)
	if err != nil {
		return err
	}
	defer rows.Close()
	endpoints := make([]ResolverEndpoint, 0, len(request.ResolverEndpoints))
	for rows.Next() {
		var raw string
		var endpoint ResolverEndpoint
		if err := rows.Scan(&raw, &endpoint.Port, &endpoint.Transport); err != nil {
			return err
		}
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return ErrSuperseded
		}
		endpoint.Address = address
		endpoints = append(endpoints, endpoint)
	}
	if err := rows.Err(); err != nil || !sameResolverEndpoints(request.ResolverEndpoints, endpoints) {
		return ErrSuperseded
	}
	return nil
}

func sameResolverEndpoints(a, b []ResolverEndpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Address != b[i].Address || a[i].Port != b[i].Port || a[i].Transport != b[i].Transport {
			return false
		}
	}
	return true
}

// isTerminalTransportResponse permits only the declared transport failures to
// be durably completed. Their identity/freshness was validated before the
// error was returned, so the scheduler can observe a compatibility refusal or
// disconnect immediately rather than waiting until the request deadline.
func isTerminalTransportResponse(response GatewayDNSResponse, err error) bool {
	switch response.ErrorCode {
	case GatewayDNSRPCUnsupportedVersion:
		return errors.Is(err, ErrGatewayDNSRPCVersion)
	case GatewayDNSRPCDeadlineExceeded:
		return errors.Is(err, ErrTimeout)
	case GatewayDNSRPCDisconnected, GatewayDNSRPCUnavailable:
		return errors.Is(err, ErrGatewayDNSRPCUnavailable)
	default:
		return false
	}
}

func (m *PostgresGatewayDNSMailbox) Await(ctx context.Context, requestID uuid.UUID) (GatewayDNSResponse, error) {
	if m == nil || m.pool == nil || requestID == uuid.Nil {
		return GatewayDNSResponse{}, ErrGatewayDNSRPCUnavailable
	}
	ticker := time.NewTicker(m.poll)
	defer ticker.Stop()
	for {
		response, state, err := m.read(ctx, requestID)
		if err != nil {
			return GatewayDNSResponse{}, err
		}
		switch state {
		case "completed":
			return response, nil
		case "expired":
			return GatewayDNSResponse{}, ErrTimeout
		}
		select {
		case <-ctx.Done():
			return GatewayDNSResponse{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (m *PostgresGatewayDNSMailbox) Expire(ctx context.Context, requestID uuid.UUID, at time.Time) error {
	if m == nil || m.pool == nil || requestID == uuid.Nil {
		return nil
	}
	_, err := m.pool.Exec(ctx, `UPDATE fqdn_gateway_dns_requests SET state='expired',expired_at=$2 WHERE request_id=$1 AND state='pending'`, requestID, at)
	return err
}

func (m *PostgresGatewayDNSMailbox) read(ctx context.Context, requestID uuid.UUID) (GatewayDNSResponse, string, error) {
	var state string
	var raw []byte
	err := m.pool.QueryRow(ctx, `SELECT state,COALESCE(response,'{}'::jsonb) FROM fqdn_gateway_dns_requests WHERE request_id=$1`, requestID).Scan(&state, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return GatewayDNSResponse{}, "", ErrGatewayDNSRPCReplay
	}
	if err != nil {
		return GatewayDNSResponse{}, "", err
	}
	if state != "completed" {
		return GatewayDNSResponse{}, state, nil
	}
	var response GatewayDNSResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return GatewayDNSResponse{}, "", err
	}
	return response, state, nil
}

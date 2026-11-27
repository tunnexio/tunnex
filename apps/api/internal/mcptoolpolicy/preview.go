package mcptoolpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

// Connection preview states and the reasons a preview fails.
const (
	PreviewWaiting = "waiting"
	PreviewReady   = "ready"
	PreviewFailed  = "failed"

	PreviewUnreachable  = "unreachable"
	PreviewUnauthorized = "unauthorized"
	PreviewInvalid      = "invalid"
	PreviewNoGateway    = "no_gateway"
	PreviewTimedOut     = "timed_out"
)

const (
	// PreviewLifetime is how long a preview can be read and connected from.
	PreviewLifetime = 10 * time.Minute
	// PreviewPatience is how long a preview waits for the gateway before it is shown as timed out. The
	// gateway reads on its 30-second discovery pass; this allows two.
	PreviewPatience = 75 * time.Second
	// maxWaitingPreviews bounds how many addresses an organization can have its gateways reading at once.
	maxWaitingPreviews = 20
	maxPreviewBytes    = 1 << 20
)

// ErrTooManyPreviews means the organization already has as many previews waiting as are allowed.
var ErrTooManyPreviews = errors.New("too many MCP connection previews are waiting")

// Preview is the tool list of an MCP server address, read by a gateway before anything is assigned.
type Preview struct {
	ID                  uuid.UUID
	State               string
	Endpoint            string
	FailureReason       string
	ServerName          string
	SuggestedServerName string
	Tools               []InventoryTool
	ExpiresAt           time.Time
}

const previewColumns = `id, endpoint, state, failure_reason, server_name, tools, expires_at, created_at`

func scanPreview(row pgx.Row, now time.Time) (Preview, error) {
	var p Preview
	var tools []byte
	var created time.Time
	if err := row.Scan(&p.ID, &p.Endpoint, &p.State, &p.FailureReason, &p.ServerName, &tools, &p.ExpiresAt, &created); err != nil {
		return Preview{}, err
	}
	p.Tools = []InventoryTool{}
	_ = json.Unmarshal(tools, &p.Tools)
	// A gateway that never answers (it is offline, or older than connection previews) is shown as
	// timed out. Nothing is written: a late answer still completes the preview.
	if p.State == PreviewWaiting && now.Sub(created) > PreviewPatience {
		p.State, p.FailureReason = PreviewFailed, PreviewTimedOut
	}
	return p, nil
}

// StartPreview asks a gateway to read the tool list of an MCP server address: the gateway of the given
// agent, or of an agent in the given group. It writes one short-lived row and nothing else: no profile,
// no assignment, and no agent can reach the address because of it.
func (s *Service) StartPreview(ctx context.Context, orgID, actorID uuid.UUID, endpoint string, viaDeviceID, viaGroupID *uuid.UUID) (Preview, error) {
	endpoint = strings.TrimSpace(endpoint)
	if s == nil || s.pool == nil || orgID == uuid.Nil || actorID == uuid.Nil || len(endpoint) > 2048 || !ValidEndpoint(endpoint) || (viaDeviceID == nil) == (viaGroupID == nil) {
		return Preview{}, ErrInvalid
	}
	now := time.Now().UTC()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Preview{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Housekeeping for this organization only; previews are useless once expired.
	if _, err := tx.Exec(ctx, `DELETE FROM agent_mcp_connection_previews WHERE org_id=$1 AND expires_at < now()`, orgID); err != nil {
		return Preview{}, err
	}
	var waiting int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM agent_mcp_connection_previews WHERE org_id=$1 AND state='waiting' AND expires_at > now() AND created_at > now() - make_interval(secs => $2)`, orgID, PreviewPatience.Seconds()).Scan(&waiting); err != nil {
		return Preview{}, err
	}
	if waiting >= maxWaitingPreviews {
		return Preview{}, ErrTooManyPreviews
	}
	// The gateway that will read: one that freshly reports its MCP listener. For a group, the freshest
	// such gateway of any of its agents.
	var rows pgx.Rows
	const gateway = `SELECT n.id, n.capabilities,
 (n.status='active' AND n.revoked_at IS NULL AND n.policy_reported_at >= now() - interval '90 seconds' AND n.policy_reported_at <= now()) AS fresh
FROM devices d JOIN nodes n ON n.id=d.node_id AND n.org_id=d.org_id`
	if viaDeviceID != nil {
		rows, err = tx.Query(ctx, gateway+` WHERE d.org_id=$1 AND d.id=$2 AND d.kind='agent' AND d.deleted_at IS NULL`, orgID, *viaDeviceID)
	} else {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT true FROM agent_groups WHERE org_id=$1 AND id=$2 AND archived_at IS NULL`, orgID, *viaGroupID).Scan(&exists); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return Preview{}, ErrNotFound
			}
			return Preview{}, err
		}
		rows, err = tx.Query(ctx, gateway+` JOIN agent_group_members m ON m.org_id=d.org_id AND m.device_id=d.id
WHERE d.org_id=$1 AND m.agent_group_id=$2 AND d.kind='agent' AND d.deleted_at IS NULL ORDER BY n.policy_reported_at DESC NULLS LAST, n.id`, orgID, *viaGroupID)
	}
	if err != nil {
		return Preview{}, err
	}
	var nodeID *uuid.UUID
	candidates := 0
	for rows.Next() {
		var id uuid.UUID
		var capabilities []byte
		var fresh bool
		if err := rows.Scan(&id, &capabilities, &fresh); err != nil {
			rows.Close()
			return Preview{}, err
		}
		candidates++
		var caps map[string]any
		if nodeID == nil && fresh && json.Unmarshal(capabilities, &caps) == nil && caps[mcpwire.CapabilityGatewayReady] == true {
			picked := id
			nodeID = &picked
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Preview{}, err
	}
	if viaDeviceID != nil && candidates == 0 {
		return Preview{}, ErrNotFound
	}
	state, reason := PreviewWaiting, ""
	if nodeID == nil {
		state, reason = PreviewFailed, PreviewNoGateway
	}
	preview, err := scanPreview(tx.QueryRow(ctx, `INSERT INTO agent_mcp_connection_previews (org_id, endpoint, via_device_id, via_group_id, node_id, state, failure_reason, requested_by_user_id, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+previewColumns, orgID, endpoint, viaDeviceID, viaGroupID, nodeID, state, reason, actorID, now.Add(PreviewLifetime)), now)
	if err != nil {
		return Preview{}, err
	}
	return preview, tx.Commit(ctx)
}

// GetPreview reads a preview. An unknown or expired one is ErrNotFound.
func (s *Service) GetPreview(ctx context.Context, orgID, previewID uuid.UUID) (Preview, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || previewID == uuid.Nil {
		return Preview{}, ErrInvalid
	}
	preview, err := scanPreview(s.pool.QueryRow(ctx, `SELECT `+previewColumns+` FROM agent_mcp_connection_previews WHERE id=$1 AND org_id=$2 AND expires_at > now()`, previewID, orgID), time.Now().UTC())
	if errors.Is(err, pgx.ErrNoRows) {
		return Preview{}, ErrNotFound
	}
	if err != nil {
		return Preview{}, err
	}
	if preview.State == PreviewReady {
		// A free local name for the server, from what it calls itself. A suggestion only.
		var suggested string
		if err := s.pool.QueryRow(ctx, `SELECT agent_mcp_free_server_name($1, $2, NULL)`, orgID, preview.ServerName).Scan(&suggested); err == nil && mcpwire.ValidServerName(suggested) {
			preview.SuggestedServerName = suggested
		}
	}
	return preview, nil
}

// CompletePreview records what the gateway read for a preview, once, and only for the gateway that was
// asked. Hashes are computed here from the raw definitions.
func (s *Service) CompletePreview(ctx context.Context, orgID, nodeID, previewID uuid.UUID, in GatewayObservation, now time.Time) error {
	if s == nil || s.pool == nil || orgID == uuid.Nil || nodeID == uuid.Nil || previewID == uuid.Nil || in.Endpoint == "" || len(in.Endpoint) > 2048 {
		return ErrInvalid
	}
	server := observedServer(in, InventoryServer{}, false, now)
	state, reason, tools := PreviewFailed, PreviewInvalid, []byte(`[]`)
	switch server.Status {
	case StatusHealthy:
		raw, err := json.Marshal(server.Tools)
		if err == nil && len(raw) <= maxPreviewBytes && len(server.Tools) <= 1024 {
			state, reason, tools = PreviewReady, "", raw
		}
	case "unavailable":
		reason = PreviewUnreachable
	case "unauthorized":
		reason = PreviewUnauthorized
	}
	name := server.ServerName
	if state != PreviewReady {
		name = ""
	}
	tag, err := s.pool.Exec(ctx, `UPDATE agent_mcp_connection_previews SET state=$1, failure_reason=$2, server_name=$3, tools=$4::jsonb, observed_at=$5
WHERE id=$6 AND org_id=$7 AND node_id=$8 AND endpoint=$9 AND state='waiting' AND expires_at > now()`, state, reason, name, tools, now.UTC(), previewID, orgID, nodeID, in.Endpoint)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

// previewObservation returns a ready preview of the endpoint as a server observation to pin rules to.
func previewObservation(ctx context.Context, q txQuerier, orgID, previewID uuid.UUID, endpoint string) (InventoryServer, time.Time, bool, error) {
	var name string
	var tools []byte
	var observed *time.Time
	err := q.QueryRow(ctx, `SELECT server_name, tools, observed_at FROM agent_mcp_connection_previews
WHERE id=$1 AND org_id=$2 AND endpoint=$3 AND state='ready' AND expires_at > now()`, previewID, orgID, endpoint).Scan(&name, &tools, &observed)
	if errors.Is(err, pgx.ErrNoRows) {
		return InventoryServer{}, time.Time{}, false, nil
	}
	if err != nil {
		return InventoryServer{}, time.Time{}, false, err
	}
	server := InventoryServer{Endpoint: endpoint, ServerName: name, Status: StatusHealthy}
	if json.Unmarshal(tools, &server.Tools) != nil || observed == nil {
		return InventoryServer{}, time.Time{}, false, nil
	}
	return server, *observed, true, nil
}

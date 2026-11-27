package mcptoolpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

var (
	// ErrServerNameTaken means another MCP server of the organization already uses the server name.
	ErrServerNameTaken = errors.New("MCP server name is in use")
	// ErrProfileConflict means an MCP server with that display name exists and is not the same server.
	ErrProfileConflict = errors.New("an MCP server with that name already exists")
	// ErrMCPOff means MCP is not turned on for the organization.
	ErrMCPOff = errors.New("MCP is off for the organization")
	// ErrTargetNotFound means the agent or agent group to connect to does not exist.
	ErrTargetNotFound = errors.New("agent or agent group not found")
)

const autoGroupDescription = "Created when an MCP server was connected to this agent."

// ConnectInput is one "Connect MCP server" request. Exactly one of DeviceID and GroupID is set.
type ConnectInput struct {
	OrgID, ActorID uuid.UUID
	DeviceID       *uuid.UUID
	GroupID        *uuid.UUID
	Name           string
	ServerName     string
	Endpoint       string
	PreviewID      *uuid.UUID
	Tools          []ToolSetting
}

// ConnectedAssignment is the assignment a connection made or found.
type ConnectedAssignment struct {
	ID         uuid.UUID
	State      string
	AssignedAt time.Time
}

// Connection is everything a connection created or reused.
type Connection struct {
	Profile      sqlc.AgentMcpProfile
	Group        sqlc.AgentGroup
	MemberCount  int
	GroupCreated bool
	Assignment   ConnectedAssignment
	Policy       GroupPolicy
	// AffectedAgents is how many agents inherit the server through the group.
	AffectedAgents int
}

// Connect does, in one transaction, everything "Connect MCP server" needs: the MCP profile, for an agent
// target a group named for the agent with the agent in it, the assignment of the profile to the group,
// the group's tool policy for the server and the tool markers. Either all of it is written or none.
//
// A server that was connected before and then taken away is connected again by reusing its profile and
// bringing its assignment back, because a profile can be assigned to a group only once.
func (s *Service) Connect(ctx context.Context, in ConnectInput) (Connection, error) {
	in.Name, in.Endpoint, in.ServerName = strings.TrimSpace(in.Name), strings.TrimSpace(in.Endpoint), strings.TrimSpace(in.ServerName)
	if s == nil || s.pool == nil || in.OrgID == uuid.Nil || in.ActorID == uuid.Nil || (in.DeviceID == nil) == (in.GroupID == nil) ||
		in.Name == "" || len(in.Name) > 128 || len(in.Endpoint) > 2048 || !ValidEndpoint(in.Endpoint) || (in.ServerName != "" && !mcpwire.ValidServerName(in.ServerName)) {
		return Connection{}, ErrInvalid
	}
	now := time.Now().UTC()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Connection{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var out Connection
	if err := RequireMCPOnTx(ctx, tx, in.OrgID); err != nil {
		return Connection{}, err
	}

	if in.GroupID != nil {
		if out.Group, err = scanGroup(tx.QueryRow(ctx, `SELECT `+groupColumns+` FROM agent_groups WHERE org_id=$1 AND id=$2 AND archived_at IS NULL FOR UPDATE`, in.OrgID, *in.GroupID)); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return Connection{}, ErrTargetNotFound
			}
			return Connection{}, err
		}
	} else if out.Group, out.GroupCreated, err = agentGroupTx(ctx, tx, in.OrgID, *in.DeviceID, in.ActorID); err != nil {
		return Connection{}, err
	}

	if out.Profile, err = profileTx(ctx, tx, in); err != nil {
		return Connection{}, err
	}

	if in.DeviceID != nil {
		tag, err := tx.Exec(ctx, `INSERT INTO agent_group_members (org_id, agent_group_id, device_id, created_by_user_id) VALUES ($1,$2,$3,$4) ON CONFLICT (agent_group_id, device_id) DO NOTHING`, in.OrgID, out.Group.ID, *in.DeviceID, in.ActorID)
		if err != nil {
			return Connection{}, err
		}
		if tag.RowsAffected() == 1 {
			if err := auditUser(ctx, tx, in.OrgID, in.ActorID, "agent_group.member_added", "agent_group", out.Group.ID.String(), map[string]any{"device_id": *in.DeviceID, "mcp_inheritance_gained": true}); err != nil {
				return Connection{}, err
			}
		}
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM agent_group_members WHERE org_id=$1 AND agent_group_id=$2`, in.OrgID, out.Group.ID).Scan(&out.MemberCount); err != nil {
		return Connection{}, err
	}
	out.AffectedAgents = out.MemberCount

	// The assignment. A row for this profile and group may exist in any state; it is brought back rather
	// than inserted again. Other servers already assigned to the group stay assigned.
	var state string
	err = tx.QueryRow(ctx, `SELECT id, state, assigned_at FROM agent_mcp_profile_assignments WHERE org_id=$1 AND profile_id=$2 AND agent_group_id=$3 FOR UPDATE`, in.OrgID, out.Profile.ID, out.Group.ID).Scan(&out.Assignment.ID, &state, &out.Assignment.AssignedAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		err = tx.QueryRow(ctx, `INSERT INTO agent_mcp_profile_assignments (org_id, profile_id, agent_group_id) VALUES ($1,$2,$3) RETURNING id, assigned_at`, in.OrgID, out.Profile.ID, out.Group.ID).Scan(&out.Assignment.ID, &out.Assignment.AssignedAt)
	case err == nil && state != "active":
		err = tx.QueryRow(ctx, `UPDATE agent_mcp_profile_assignments SET state='active', assigned_at=now(), ended_at=NULL, ended_by_user_id=NULL, quarantine_reason=NULL WHERE id=$1 RETURNING assigned_at`, out.Assignment.ID).Scan(&out.Assignment.AssignedAt)
	}
	if err != nil {
		return Connection{}, err
	}
	newlyAssigned := state != "active"
	out.Assignment.State = "active"
	if newlyAssigned {
		if err := auditUser(ctx, tx, in.OrgID, in.ActorID, "agent_mcp_profile.assigned", "agent_group", out.Group.ID.String(), map[string]any{"affected_agent_count": out.MemberCount, "profile_id": out.Profile.ID}); err != nil {
			return Connection{}, err
		}
	}

	if _, err := replaceGroupTx(ctx, tx, groupWrite{OrgID: in.OrgID, GroupID: out.Group.ID, ProfileID: out.Profile.ID, ActorID: in.ActorID, Endpoint: in.Endpoint, Tools: in.Tools, PreviewID: in.PreviewID, Now: now}); err != nil {
		return Connection{}, err
	}
	targetType, targetID := "agent_group", out.Group.ID.String()
	if in.DeviceID != nil {
		targetType, targetID = "agent", in.DeviceID.String()
	}
	if err := auditUser(ctx, tx, in.OrgID, in.ActorID, "agent.mcp_server_connected", targetType, targetID, map[string]any{
		"profile_id": out.Profile.ID, "group_id": out.Group.ID, "group_created": out.GroupCreated, "endpoint": in.Endpoint, "server_name": out.Profile.ServerName, "affected_agent_count": out.MemberCount,
	}); err != nil {
		return Connection{}, err
	}
	if out.Policy, err = readGroup(ctx, tx, in.OrgID, out.Group.ID, out.Profile.ID, now); err != nil {
		return Connection{}, err
	}
	if in.PreviewID != nil {
		if _, err := tx.Exec(ctx, `DELETE FROM agent_mcp_connection_previews WHERE id=$1 AND org_id=$2`, *in.PreviewID, in.OrgID); err != nil {
			return Connection{}, err
		}
	}
	return out, tx.Commit(ctx)
}

// RequireMCPOnTx checks, inside a transaction that is about to assign an MCP server, that MCP is on for
// the organization, and holds the setting until the transaction ends. Turning MCP off is refused while
// an assignment is active, so a switch-off racing an assignment cannot leave one behind with MCP off.
func RequireMCPOnTx(ctx context.Context, tx pgx.Tx, orgID uuid.UUID) error {
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT enabled FROM organization_mcp_settings WHERE org_id=$1 FOR SHARE`, orgID).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !enabled) {
		return ErrMCPOff
	}
	return err
}

const groupColumns = `id, org_id, name, description, archived_at, created_at, updated_at`

func scanGroup(row pgx.Row) (sqlc.AgentGroup, error) {
	var g sqlc.AgentGroup
	err := row.Scan(&g.ID, &g.OrgID, &g.Name, &g.Description, &g.ArchivedAt, &g.CreatedAt, &g.UpdatedAt)
	return g, err
}

// agentGroupTx returns the group a server connected to one agent is assigned through: the group named
// for the agent, created when it does not exist. A group of that name is reused only when it holds no
// other agent, so connecting a server to one agent never reaches another.
func agentGroupTx(ctx context.Context, tx pgx.Tx, orgID, deviceID, actorID uuid.UUID) (sqlc.AgentGroup, bool, error) {
	var deviceName string
	if err := tx.QueryRow(ctx, `SELECT name FROM devices WHERE id=$1 AND org_id=$2 AND kind='agent' AND deleted_at IS NULL FOR SHARE`, deviceID, orgID).Scan(&deviceName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.AgentGroup{}, false, ErrTargetNotFound
		}
		return sqlc.AgentGroup{}, false, err
	}
	base := strings.TrimSpace(deviceName)
	if base == "" {
		base = "agent"
	}
	if len(base) > 90 {
		base = strings.TrimSpace(strings.ToValidUTF8(base[:90], ""))
	}
	for attempt := 1; attempt <= 50; attempt++ {
		name := base
		if attempt > 1 {
			name = fmt.Sprintf("%s %d", base, attempt)
		}
		group, err := scanGroup(tx.QueryRow(ctx, `SELECT `+groupColumns+` FROM agent_groups WHERE org_id=$1 AND lower(name)=lower($2) AND archived_at IS NULL FOR UPDATE`, orgID, name))
		if errors.Is(err, pgx.ErrNoRows) {
			group, err = scanGroup(tx.QueryRow(ctx, `INSERT INTO agent_groups (org_id, name, description) VALUES ($1,$2,$3) RETURNING `+groupColumns, orgID, name, autoGroupDescription))
			if err != nil {
				return sqlc.AgentGroup{}, false, err
			}
			return group, true, auditUser(ctx, tx, orgID, actorID, "agent_group.created", "agent_group", group.ID.String(), map[string]any{"name": group.Name, "cause": "mcp_server_connected", "device_id": deviceID})
		}
		if err != nil {
			return sqlc.AgentGroup{}, false, err
		}
		var others int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM agent_group_members WHERE org_id=$1 AND agent_group_id=$2 AND device_id<>$3`, orgID, group.ID, deviceID).Scan(&others); err != nil {
			return sqlc.AgentGroup{}, false, err
		}
		if others == 0 {
			return group, false, nil
		}
	}
	return sqlc.AgentGroup{}, false, ErrProfileConflict
}

const profileColumns = `id, org_id, name, endpoint, created_at, updated_at, archived_at, server_name`

func scanProfile(row pgx.Row) (sqlc.AgentMcpProfile, error) {
	var p sqlc.AgentMcpProfile
	err := row.Scan(&p.ID, &p.OrgID, &p.Name, &p.Endpoint, &p.CreatedAt, &p.UpdatedAt, &p.ArchivedAt, &p.ServerName)
	return p, err
}

// profileTx returns the profile for the server: the existing one of that display name when it is the
// same server (same address, not archived), otherwise a new one.
func profileTx(ctx context.Context, tx pgx.Tx, in ConnectInput) (sqlc.AgentMcpProfile, error) {
	profile, err := scanProfile(tx.QueryRow(ctx, `SELECT `+profileColumns+` FROM agent_mcp_profiles WHERE org_id=$1 AND lower(name)=lower($2) FOR UPDATE`, in.OrgID, in.Name))
	if err == nil {
		if profile.ArchivedAt.Valid || strings.TrimSpace(profile.Endpoint) != in.Endpoint || (in.ServerName != "" && in.ServerName != profile.ServerName) {
			return sqlc.AgentMcpProfile{}, ErrProfileConflict
		}
		return profile, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return sqlc.AgentMcpProfile{}, err
	}
	if in.ServerName != "" {
		var taken bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_mcp_profiles WHERE org_id=$1 AND server_name=$2 AND archived_at IS NULL)`, in.OrgID, in.ServerName).Scan(&taken); err != nil {
			return sqlc.AgentMcpProfile{}, err
		}
		if taken {
			return sqlc.AgentMcpProfile{}, ErrServerNameTaken
		}
	}
	// An empty server name lets the database derive a free one from the display name.
	profile, err = scanProfile(tx.QueryRow(ctx, `INSERT INTO agent_mcp_profiles (org_id, name, endpoint, server_name) VALUES ($1,$2,$3,$4) RETURNING `+profileColumns, in.OrgID, in.Name, in.Endpoint, in.ServerName))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if strings.Contains(pgErr.ConstraintName, "server_name") {
				return sqlc.AgentMcpProfile{}, ErrServerNameTaken
			}
			return sqlc.AgentMcpProfile{}, ErrProfileConflict
		}
		return sqlc.AgentMcpProfile{}, err
	}
	return profile, auditUser(ctx, tx, in.OrgID, in.ActorID, "agent_mcp_profile.created", "agent_mcp_profile", profile.ID.String(), map[string]any{"endpoint": in.Endpoint, "server_name": profile.ServerName})
}

func auditUser(ctx context.Context, tx pgx.Tx, orgID, actorID uuid.UUID, action, targetType, targetID string, metadata map[string]any) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs (org_id, actor_user_id, action, target_type, target_id, metadata) VALUES ($1,$2,$3,$4,$5,$6)`, orgID, actorID, action, targetType, targetID, raw)
	return err
}

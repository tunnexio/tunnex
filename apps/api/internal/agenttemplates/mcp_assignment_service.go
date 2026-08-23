package agenttemplates

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func (s *Service) CreateMCPProfile(ctx context.Context, orgID, actor uuid.UUID, name, endpoint string) (sqlc.AgentMcpProfile, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.AgentMcpProfile{}, err
	}
	defer tx.Rollback(ctx)
	row, err := sqlc.New(tx).CreateAgentMCPProfile(ctx, sqlc.CreateAgentMCPProfileParams{OrgID: orgID, Name: name, Endpoint: endpoint})
	if err != nil {
		return row, err
	}
	if err := audit(ctx, tx, orgID, actor, "agent_mcp_profile.created", "agent_mcp_profile", row.ID, map[string]any{"endpoint": endpoint}); err != nil {
		return row, err
	}
	if err := tx.Commit(ctx); err != nil {
		return row, err
	}
	return row, nil
}

type MCPAssignment struct {
	ID, OrgID, ProfileID, GroupID uuid.UUID
	ProfileName, GroupName, State string
	AssignedAt                    time.Time
	EndedAt                       *time.Time
	QuarantineReason              *string
}

type MCPImpact struct {
	GroupID, CurrentProfileID, ProposedProfileID                           *uuid.UUID
	AffectedAgentCount                                                     int
	AffectedAgentIDs                                                       []uuid.UUID
	EffectiveUpstreamChanges, DesiredRuntimeUpdatesQueued, MutationAllowed bool
	Conflict                                                               *string
}

type MCPMutation struct {
	MCPImpact
	Assignment *MCPAssignment
}

// MCPArchiveBlockedError preserves server-derived blocking facts for an archive
// refusal. It is intentionally typed so HTTP can expose only bounded counts.
type MCPArchiveBlockedError struct{ Groups, Agents int }

func (e *MCPArchiveBlockedError) Error() string { return "MCP profile has active group assignments" }

var (
	ErrMCPProfileNotFound = errors.New("MCP profile not found")
	ErrAgentGroupNotFound = errors.New("agent group not found")
)

func (s *Service) assignmentForGroup(ctx context.Context, tx pgx.Tx, orgID, groupID uuid.UUID) (*MCPAssignment, error) {
	var a MCPAssignment
	err := tx.QueryRow(ctx, `SELECT a.id,a.org_id,a.profile_id,a.agent_group_id,p.name,g.name,a.state,a.assigned_at,a.ended_at,a.quarantine_reason
		FROM agent_mcp_profile_assignments a
		JOIN agent_mcp_profiles p ON p.id=a.profile_id AND p.org_id=a.org_id
		JOIN agent_groups g ON g.id=a.agent_group_id AND g.org_id=a.org_id
		WHERE a.org_id=$1 AND a.agent_group_id=$2 AND a.state='active'`, orgID, groupID).Scan(&a.ID, &a.OrgID, &a.ProfileID, &a.GroupID, &a.ProfileName, &a.GroupName, &a.State, &a.AssignedAt, &a.EndedAt, &a.QuarantineReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Service) ListMCPAssignments(ctx context.Context, orgID uuid.UUID, state *string) ([]MCPAssignment, error) {
	q := `SELECT a.id,a.org_id,a.profile_id,a.agent_group_id,p.name,g.name,a.state,a.assigned_at,a.ended_at,a.quarantine_reason
          FROM agent_mcp_profile_assignments a JOIN agent_mcp_profiles p ON p.id=a.profile_id AND p.org_id=a.org_id
          JOIN agent_groups g ON g.id=a.agent_group_id AND g.org_id=a.org_id WHERE a.org_id=$1`
	args := []any{orgID}
	if state != nil {
		q += ` AND a.state=$2`
		args = append(args, *state)
	}
	q += ` ORDER BY a.assigned_at DESC`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPAssignment
	for rows.Next() {
		var x MCPAssignment
		if err := rows.Scan(&x.ID, &x.OrgID, &x.ProfileID, &x.GroupID, &x.ProfileName, &x.GroupName, &x.State, &x.AssignedAt, &x.EndedAt, &x.QuarantineReason); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Service) mcpImpact(ctx context.Context, tx pgx.Tx, orgID, groupID uuid.UUID, proposed *uuid.UUID) (MCPImpact, error) {
	var i MCPImpact
	i.GroupID = &groupID
	i.ProposedProfileID = proposed
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT true FROM agent_groups WHERE id=$1 AND org_id=$2 FOR UPDATE`, groupID, orgID).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return i, ErrAgentGroupNotFound
		}
		return i, err
	}
	var current *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT profile_id FROM agent_mcp_profile_assignments WHERE org_id=$1 AND agent_group_id=$2 AND state='active' FOR UPDATE`, orgID, groupID).Scan(&current); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return i, err
	}
	i.CurrentProfileID = current
	rows, err := tx.Query(ctx, `SELECT device_id FROM agent_group_members WHERE org_id=$1 AND agent_group_id=$2 ORDER BY device_id`, orgID, groupID)
	if err != nil {
		return i, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return i, err
		}
		i.AffectedAgentIDs = append(i.AffectedAgentIDs, id)
	}
	i.AffectedAgentCount = len(i.AffectedAgentIDs)
	i.EffectiveUpstreamChanges = (current == nil && proposed != nil) || (current != nil && proposed == nil) || (current != nil && proposed != nil && *current != *proposed)
	i.MutationAllowed = true
	return i, rows.Err()
}

func (s *Service) PreviewMCPProfileImpact(ctx context.Context, orgID, groupID uuid.UUID, proposed *uuid.UUID) (MCPImpact, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MCPImpact{}, err
	}
	defer tx.Rollback(ctx)
	return s.mcpImpact(ctx, tx, orgID, groupID, proposed)
}

func (s *Service) SetGroupMCPProfile(ctx context.Context, orgID, groupID, profileID, actor uuid.UUID) (MCPMutation, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MCPMutation{}, err
	}
	defer tx.Rollback(ctx)
	var archived *time.Time
	if err := tx.QueryRow(ctx, `SELECT archived_at FROM agent_mcp_profiles WHERE id=$1 AND org_id=$2 FOR UPDATE`, profileID, orgID).Scan(&archived); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MCPMutation{}, ErrMCPProfileNotFound
		}
		return MCPMutation{}, err
	}
	if archived != nil {
		return MCPMutation{}, ErrConflict
	}
	impact, err := s.mcpImpact(ctx, tx, orgID, groupID, &profileID)
	if err != nil {
		return MCPMutation{}, err
	}
	if impact.CurrentProfileID != nil && *impact.CurrentProfileID == profileID {
		assignment, err := s.assignmentForGroup(ctx, tx, orgID, groupID)
		if err != nil {
			return MCPMutation{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return MCPMutation{}, err
		}
		impact.DesiredRuntimeUpdatesQueued = false
		return MCPMutation{MCPImpact: impact, Assignment: assignment}, nil
	}
	var old uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM agent_mcp_profile_assignments WHERE org_id=$1 AND agent_group_id=$2 AND state='active' FOR UPDATE`, orgID, groupID).Scan(&old)
	if err == nil {
		if _, err = tx.Exec(ctx, `UPDATE agent_mcp_profile_assignments SET state='replaced',ended_at=now(),ended_by_user_id=$1 WHERE id=$2`, actor, old); err != nil {
			return MCPMutation{}, err
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return MCPMutation{}, err
	}
	var a MCPAssignment
	err = tx.QueryRow(ctx, `INSERT INTO agent_mcp_profile_assignments(org_id,profile_id,agent_group_id) VALUES($1,$2,$3) RETURNING id,org_id,profile_id,agent_group_id,state,assigned_at,ended_at,quarantine_reason`, orgID, profileID, groupID).Scan(&a.ID, &a.OrgID, &a.ProfileID, &a.GroupID, &a.State, &a.AssignedAt, &a.EndedAt, &a.QuarantineReason)
	if err != nil {
		return MCPMutation{}, err
	}
	if err := audit(ctx, tx, orgID, actor, map[bool]string{true: "agent_mcp_profile.replaced", false: "agent_mcp_profile.assigned"}[old != uuid.Nil], "agent_group", groupID, map[string]any{"affected_agent_count": impact.AffectedAgentCount}); err != nil {
		return MCPMutation{}, err
	}
	assignment, err := s.assignmentForGroup(ctx, tx, orgID, groupID)
	if err != nil {
		return MCPMutation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return MCPMutation{}, err
	}
	if impact.EffectiveUpstreamChanges && s.pusher != nil {
		s.pusher.PushOrgNodes(ctx, orgID)
		impact.DesiredRuntimeUpdatesQueued = true
	}
	return MCPMutation{MCPImpact: impact, Assignment: assignment}, nil
}

func (s *Service) UnassignGroupMCPProfile(ctx context.Context, orgID, groupID, actor uuid.UUID) (MCPMutation, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MCPMutation{}, err
	}
	defer tx.Rollback(ctx)
	impact, err := s.mcpImpact(ctx, tx, orgID, groupID, nil)
	if err != nil {
		return MCPMutation{}, err
	}
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM agent_mcp_profile_assignments WHERE org_id=$1 AND agent_group_id=$2 AND state='active' FOR UPDATE`, orgID, groupID).Scan(&id); errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return MCPMutation{}, err
		}
		impact.DesiredRuntimeUpdatesQueued = false
		return MCPMutation{MCPImpact: impact}, nil
	} else if err != nil {
		return MCPMutation{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_mcp_profile_assignments SET state='unassigned',ended_at=now(),ended_by_user_id=$1 WHERE id=$2`, actor, id); err != nil {
		return MCPMutation{}, err
	}
	if err = audit(ctx, tx, orgID, actor, "agent_mcp_profile.unassigned", "agent_group", groupID, map[string]any{"affected_agent_count": impact.AffectedAgentCount}); err != nil {
		return MCPMutation{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return MCPMutation{}, err
	}
	if impact.EffectiveUpstreamChanges && s.pusher != nil {
		s.pusher.PushOrgNodes(ctx, orgID)
		impact.DesiredRuntimeUpdatesQueued = true
	}
	return MCPMutation{MCPImpact: impact}, nil
}

func (s *Service) ArchiveMCPProfile(ctx context.Context, orgID, profileID, actor uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var archivedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT archived_at FROM agent_mcp_profiles WHERE id=$1 AND org_id=$2 FOR UPDATE`, profileID, orgID).Scan(&archivedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMCPProfileNotFound
		}
		return err
	}
	if archivedAt != nil {
		return tx.Commit(ctx)
	}
	var groups, agents int
	if err = tx.QueryRow(ctx, `SELECT count(DISTINCT a.agent_group_id), count(DISTINCT m.device_id)
		FROM agent_mcp_profile_assignments a
		LEFT JOIN agent_group_members m ON m.org_id=a.org_id AND m.agent_group_id=a.agent_group_id
		WHERE a.org_id=$1 AND a.profile_id=$2 AND a.state='active'`, orgID, profileID).Scan(&groups, &agents); err != nil {
		return err
	}
	if groups > 0 {
		return &MCPArchiveBlockedError{Groups: groups, Agents: agents}
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_mcp_profiles SET archived_at=now() WHERE id=$1 AND org_id=$2 AND archived_at IS NULL`, profileID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrMCPProfileNotFound
	}
	if err = audit(ctx, tx, orgID, actor, "agent_mcp_profile.archived", "agent_mcp_profile", profileID, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

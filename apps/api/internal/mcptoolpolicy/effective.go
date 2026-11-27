package mcptoolpolicy

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Which policy decided a call.
const (
	// PolicySourceAgent: the agent's own policy, which overrides its group for the endpoints it names.
	PolicySourceAgent = "agent"
	// PolicySourceGroup: the policy of the agent group that assigns the MCP server.
	PolicySourceGroup = "group"
)

// Effective is the one policy that decides for an agent and one of its MCP servers.
type Effective struct {
	// Found is false when neither the agent nor the group has a policy for the server: everything is denied.
	Found   bool
	Source  string
	GroupID uuid.UUID
	Version int64
	Rules   []Rule
}

// Effective picks the policy that decides for the agent and the server, per endpoint:
//
//   - the agent's own policy, when its newest version overrides the server's endpoint (an override with no
//     rule for a tool, or with no rules at all, denies);
//   - otherwise the newest policy of the group that assigns the server;
//   - otherwise none, which denies.
//
// Version numbers of the two kinds are counted separately, so a caller that stores one must store the
// source and the group beside it.
func (s *Service) Effective(ctx context.Context, orgID, deviceID uuid.UUID, server AssignedServer) (Effective, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || deviceID == uuid.Nil || server.Endpoint == "" {
		return Effective{}, ErrInvalid
	}
	var version int64
	var raw []byte
	var overrides []string
	err := s.pool.QueryRow(ctx, `SELECT version, rules, override_endpoints FROM agent_mcp_tool_policy_versions
WHERE org_id=$1 AND device_id=$2 ORDER BY version DESC LIMIT 1`, orgID, deviceID).Scan(&version, &raw, &overrides)
	switch {
	case err == nil:
		if containsEndpoint(overrides, server.Endpoint) {
			out := Effective{Found: true, Source: PolicySourceAgent, Version: version}
			if json.Unmarshal(raw, &out.Rules) != nil {
				return Effective{}, ErrInvalid
			}
			return out, nil
		}
	case !errors.Is(err, pgx.ErrNoRows):
		return Effective{}, err
	}
	if server.GroupID == uuid.Nil || server.ProfileID == uuid.Nil {
		return Effective{}, nil
	}
	err = s.pool.QueryRow(ctx, `SELECT version, rules FROM agent_group_mcp_tool_policy_versions
WHERE org_id=$1 AND agent_group_id=$2 AND profile_id=$3 ORDER BY version DESC LIMIT 1`, orgID, server.GroupID, server.ProfileID).Scan(&version, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Effective{}, nil
	}
	if err != nil {
		return Effective{}, err
	}
	out := Effective{Found: true, Source: PolicySourceGroup, GroupID: server.GroupID, Version: version}
	if json.Unmarshal(raw, &out.Rules) != nil {
		return Effective{}, ErrInvalid
	}
	return out, nil
}

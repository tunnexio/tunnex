package mcptoolpolicy

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// AssignedServer is one MCP server an agent inherits from one of its groups.
type AssignedServer struct {
	AssignmentID uuid.UUID
	GroupID      uuid.UUID
	GroupName    string
	ProfileID    uuid.UUID
	ProfileName  string
	// ServerName is the profile's name on the local proxy and the gateway listener, not the name the MCP
	// server reports for itself.
	ServerName string
	Endpoint   string
	AssignedAt time.Time
}

// AssignedServers lists the MCP servers an agent inherits, first one first. "First" is the earliest active
// assignment. A profile reached through two groups appears once, under the group that assigned it first.
// Endpoints are trimmed and not otherwise checked; each caller applies its own rule for a malformed one.
func AssignedServers(ctx context.Context, q *sqlc.Queries, orgID, deviceID uuid.UUID) ([]AssignedServer, error) {
	rows, err := q.ListAgentMCPServersForDevice(ctx, sqlc.ListAgentMCPServersForDeviceParams{OrgID: orgID, DeviceID: deviceID})
	if err != nil {
		return nil, err
	}
	return orderServers(rows), nil
}

func orderServers(rows []sqlc.ListAgentMCPServersForDeviceRow) []AssignedServer {
	out := make([]AssignedServer, 0, len(rows))
	seen := make(map[uuid.UUID]bool, len(rows))
	for _, row := range rows {
		if seen[row.ProfileID] {
			continue
		}
		seen[row.ProfileID] = true
		out = append(out, AssignedServer{AssignmentID: row.AssignmentID, GroupID: row.AgentGroupID, GroupName: row.GroupName, ProfileID: row.ProfileID, ProfileName: row.ProfileName,
			ServerName: row.ServerName, Endpoint: strings.TrimSpace(row.Endpoint), AssignedAt: row.AssignedAt})
	}
	return out
}

// FindServer picks the server a request names. An empty name is the first server, which is what a client
// that predates server names asks for.
func FindServer(servers []AssignedServer, name string) (AssignedServer, bool) {
	if name == "" {
		if len(servers) == 0 {
			return AssignedServer{}, false
		}
		return servers[0], true
	}
	for _, server := range servers {
		if server.ServerName == name {
			return server, true
		}
	}
	return AssignedServer{}, false
}

// ValidEndpoint accepts a credential-free absolute http(s) URL with no query or fragment.
func ValidEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

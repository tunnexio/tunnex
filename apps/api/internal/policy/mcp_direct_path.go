package policy

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

// AI-SEC-2, snapshot side of "the direct path is closed". The compiler is pure and clockless, so every
// fact that needs the database or the clock is decided HERE and handed to Compile as a finished list:
//
//	deny(device, endpoint)  ⇔  the device's gateway can render a deny
//	                           AND (the runtime forwards through the gateway OR grace is over)
//
// See docs/AI-SEC-2-decisions.md, "Amendments".

// mcpDenyPolicyVersion is the first artifact version that carries a deny list (policyspec v16).
const mcpDenyPolicyVersion = 16

// mcpGraceSweepInterval is how often the leader looks for a grace date that has gone by. The gateway's own
// reconcile poll is the backstop (the snapshot reads the date every time it is built); this is promptness.
const mcpGraceSweepInterval = 30 * time.Second

// mcpDirectPathClosed is the grace mechanism as one predicate.
//
// A gateway that cannot render a deny NEVER receives one: it would refuse the v16 artifact and deny all
// traffic for every device behind it. For such a gateway the control plane withholds MCP instead.
func mcpDirectPathClosed(gatewayRendersDeny, runtimeGatewayCapable, graceOpen bool) bool {
	return gatewayRendersDeny && (runtimeGatewayCapable || !graceOpen)
}

// gatewayRendersMCPDeny reads a node's stored capabilities document. The gateway must report the MCP
// listener capability as a typed true, and its own policy ceiling must cover the deny version: a gateway
// that claimed the listener but would refuse the artifact gets no deny. Report age is deliberately not a
// condition, so a gateway that stops reporting does not get its denies withdrawn.
func gatewayRendersMCPDeny(capabilities []byte) bool {
	var caps map[string]json.RawMessage
	if json.Unmarshal(capabilities, &caps) != nil {
		return false
	}
	var ready bool
	var maxVersion int
	if json.Unmarshal(caps[mcpwire.CapabilityGatewayReady], &ready) != nil || !ready {
		return false
	}
	if json.Unmarshal(caps["max_policy_version"], &maxVersion) != nil {
		return false
	}
	return maxVersion >= mcpDenyPolicyVersion
}

// mcpEndpointTarget extracts what a packet filter can match from a profile endpoint URL: the host (an IP
// literal in canonical form, or a lower-case hostname) and the TCP port. http and ws default to 80, https
// and wss to 443; any other scheme needs an explicit port.
func mcpEndpointTarget(endpoint string) (string, int, bool) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", 0, false
	}
	port := 0
	switch raw := u.Port(); {
	case raw != "":
		if port, err = strconv.Atoi(raw); err != nil {
			return "", 0, false
		}
	case u.Scheme == "http" || u.Scheme == "ws":
		port = 80
	case u.Scheme == "https" || u.Scheme == "wss":
		port = 443
	}
	if port < 1 || port > 65535 {
		return "", 0, false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", 0, false
		}
		host = addr.Unmap().String()
	}
	if host == "" {
		return "", 0, false
	}
	return host, port, true
}

// appendMCPDirectPathDenies fills Snapshot.MCPDirectPathDenies. An organization with no MCP assignment
// reads zero rows and the field stays nil, so its artifacts are exactly what they were.
func appendMCPDirectPathDenies(ctx context.Context, q *sqlc.Queries, snap *Snapshot, orgID uuid.UUID) error {
	present, err := q.MCPDirectPathSchemaPresent(ctx)
	if err != nil || !present {
		return err
	}
	rows, err := q.ListMCPDirectPathInputsForOrg(ctx, orgID)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if !mcpDirectPathClosed(gatewayRendersMCPDeny(row.NodeCapabilities), row.RuntimeGatewayCapable, row.GraceOpen) {
			continue
		}
		host, port, ok := mcpEndpointTarget(row.Endpoint)
		if !ok {
			continue
		}
		snap.MCPDirectPathDenies = append(snap.MCPDirectPathDenies, MCPDirectPathDeny{DeviceID: row.DeviceID, Host: host, Port: port})
	}
	return nil
}

// RecompileOrg signals the organization's gateways to re-fetch their compiled policy. It is the hook for a
// change made OUTSIDE this package that moves the MCP deny set and has no policy mutation of its own: a
// runtime that just became gateway-capable, or a gateway whose MCP capability just changed. Best-effort,
// like every push; the gateway's reconcile poll is the backstop.
func (s *Service) RecompileOrg(ctx context.Context, orgID uuid.UUID) { s.pushOrg(ctx, orgID) }

// SweepMCPDirectPathGrace pushes every organization whose grace date went by after `since`, and returns
// the database time it swept up to (the next call's `since`). Passing the zero time sweeps every grace
// that has ever ended, which is what a newly elected leader does once: a push is only a re-fetch signal,
// so repeating it is harmless, and no window can be skipped across a restart.
func (s *Service) SweepMCPDirectPathGrace(ctx context.Context, since time.Time) (time.Time, error) {
	present, err := s.q.MCPDirectPathSchemaPresent(ctx)
	if err != nil || !present {
		return since, err
	}
	var until time.Time
	if err := s.pool.QueryRow(ctx, `SELECT now()`).Scan(&until); err != nil {
		return since, err
	}
	orgs, err := s.q.ListOrganizationsWithMCPDirectPathGraceEndedBetween(ctx, sqlc.ListOrganizationsWithMCPDirectPathGraceEndedBetweenParams{AfterTime: since, UntilTime: until})
	if err != nil {
		return since, err
	}
	for _, orgID := range orgs {
		s.pushOrg(ctx, orgID)
	}
	if len(orgs) > 0 {
		slog.Info("mcp_direct_path_grace_ended", slog.Int("organizations", len(orgs)))
	}
	return until, nil
}

// StartMCPDirectPathGraceTicker runs the grace sweep until ctx ends. mayTick gates each sweep on scheduler
// leadership (nil = ungated, tests). A replica that is not the leader keeps `since` where it was, so on
// promotion its first sweep covers everything the previous leader may not have reached.
func (s *Service) StartMCPDirectPathGraceTicker(ctx context.Context, mayTick func() bool) {
	t := time.NewTicker(mcpGraceSweepInterval)
	defer t.Stop()
	var since time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if mayTick != nil && !mayTick() {
				continue
			}
			next, err := s.SweepMCPDirectPathGrace(ctx, since)
			if err != nil {
				slog.Warn("mcp_direct_path_grace_sweep_failed", slog.String("error", err.Error()))
				continue
			}
			since = next
		}
	}
}

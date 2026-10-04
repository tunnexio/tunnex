package appaccess

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"time"
)

type BrowserAssignment struct {
	Route
	Stage                           string
	OperationID, ReadinessRequestID *uuid.UUID
	Deadline                        *time.Time
}
type BrowserDesired struct {
	ProtocolVersion int32
	Purpose         string
	Withdrawn       bool
	Reason          string
	Assignments     []BrowserAssignment
}

func (s *Service) ReportBrowserCapability(ctx context.Context, g AuthenticatedGateway, version int32) (GatewayRuntime, error) {
	var out GatewayRuntime
	if version < 0 || version > 65535 {
		return out, apierr.BadRequest("invalid_capability", "invalid browser protocol version")
	}
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := s.gateway(ctx, q, g); e != nil {
			return e
		}
		r, e := q.ReportAppAccessBrowserGatewayRuntime(ctx, sqlc.ReportAppAccessBrowserGatewayRuntimeParams{OrgID: g.OrgID, GatewayID: g.GatewayID, CapabilityVersion: version, ReportedCertSerial: g.CertSerial})
		if e != nil {
			return e
		}
		out = GatewayRuntime{OrgID: g.OrgID, GatewayID: g.GatewayID, CapabilityVersion: version, ReportedAt: &r.ReportedAt, Status: "supported"}
		if version != 1 {
			out.Status = "unsupported"
		}
		return nil
	})
	return out, e
}
func (s *Service) DesiredBrowser(ctx context.Context, g AuthenticatedGateway, entitled bool) (BrowserDesired, error) {
	out := BrowserDesired{ProtocolVersion: 1, Purpose: "browser_proxy", Withdrawn: true, Reason: "authority_unavailable", Assignments: []BrowserAssignment{}}
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := s.gateway(ctx, q, g); e != nil {
			return e
		}
		if !entitled {
			out.Reason = "feature_unavailable"
			return nil
		}
		if !s.publicationDomainReadyWithQueries(ctx, q) {
			out.Reason = "domain_unavailable"
			return nil
		}
		enabled, e := q.LockAppAccessSettings(ctx, g.OrgID)
		if errors.Is(e, pgx.ErrNoRows) || e == nil && !enabled {
			out.Reason = "feature_disabled"
			return nil
		}
		if e != nil {
			return e
		}
		runtime, e := q.GetAppAccessBrowserGatewayRuntime(ctx, sqlc.GetAppAccessBrowserGatewayRuntimeParams{OrgID: g.OrgID, GatewayID: g.GatewayID})
		if errors.Is(e, pgx.ErrNoRows) {
			out.Reason = "capability_unavailable"
			return nil
		}
		if e != nil {
			return e
		}
		if runtime.CapabilityVersion != 1 {
			out.Reason = "capability_unsupported"
			return nil
		}
		if runtime.ReportedCertSerial != g.CertSerial || !runtime.ReportedAt.Add(30*time.Second).After(s.now()) {
			out.Reason = "capability_unavailable"
			return nil
		}
		rows, e := q.ListGatewayAppAccessBrowserAssignments(ctx, sqlc.ListGatewayAppAccessBrowserAssignmentsParams{OrgID: g.OrgID, GatewayID: g.GatewayID})
		if e != nil {
			return e
		}
		for _, r := range rows {
			a := BrowserAssignment{Route: Route{RouteBinding: RouteBinding{OrgID: g.OrgID, AppID: r.AppID, GatewayID: r.GatewayID, Generation: r.Generation, Revision: r.Revision, AuthorityVersion: r.AuthorityVersion, Digest: r.Digest, Hostname: r.Hostname, Purpose: r.Purpose}, OriginURL: r.OriginUrl, AllowedDestinationCIDRs: append([]string{}, r.AllowedDestinationCidrs...), OriginCAPEM: r.OriginCaPem, OriginCADigest: r.OriginCaDigest}, Stage: r.Stage, Deadline: timePointer(r.Deadline)}
			if r.OperationID.Valid {
				id := uuid.UUID(r.OperationID.Bytes)
				a.OperationID = &id
			}
			if r.ReadinessRequestID.Valid {
				id := uuid.UUID(r.ReadinessRequestID.Bytes)
				a.ReadinessRequestID = &id
			}
			out.Assignments = append(out.Assignments, a)
		}
		out.Withdrawn = len(out.Assignments) == 0
		out.Reason = ""
		return nil
	})
	return out, e
}

package appaccess

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"time"
)

const ConnectorProtocolVersion int32 = 1
const originCheckPurpose = "origin_check"

type AuthenticatedGateway struct {
	OrgID, GatewayID uuid.UUID
	CertSerial       string
}
type GatewayRuntime struct {
	OrgID, GatewayID  uuid.UUID
	CapabilityVersion int32
	ReportedAt        *time.Time
	Status            string
}
type Assignment struct {
	OrgID, AppID, GatewayID, Generation uuid.UUID
	Revision                            int64
	Digest, Purpose, OriginURL          string
	AllowedDestinationCIDRs             []string
	OriginCAPEM, OriginCADigest         string
}
type Check struct {
	ID, OrgID, AppID, GatewayID, Generation        uuid.UUID
	Revision                                       int64
	Digest, Purpose, Status                        string
	CreatedAt, Deadline                            time.Time
	CompletedAt                                    *time.Time
	DNSStatus, ConnectStatus, TLSStatus, ErrorCode string
}
type Desired struct {
	ProtocolVersion int32
	Purpose         string
	Withdrawn       bool
	Reason          string
	Assignments     []Assignment
	Checks          []Check
}
type Result struct {
	RequestID, AppID, Generation                                    uuid.UUID
	Revision                                                        int64
	Digest, Purpose, DNSStatus, ConnectStatus, TLSStatus, ErrorCode string
}
type Applied struct {
	AppID, Generation                  uuid.UUID
	Revision                           int64
	Digest, Purpose, Status, ErrorCode string
}

func checkModel(r sqlc.AppAccessOriginCheck) Check {
	return Check{ID: r.ID, OrgID: r.OrgID, AppID: r.AppID, GatewayID: r.GatewayID, Generation: r.Generation, Revision: r.Revision, Digest: r.Digest, Purpose: r.Purpose, Status: r.Status, CreatedAt: r.CreatedAt, Deadline: r.Deadline, CompletedAt: timePointer(r.CompletedAt), DNSStatus: r.DnsStatus, ConnectStatus: r.ConnectStatus, TLSStatus: r.TlsStatus, ErrorCode: r.ErrorCode}
}
func (s *Service) gateway(ctx context.Context, q *sqlc.Queries, g AuthenticatedGateway) error {
	if e := lockGrantOrg(ctx, q, g.OrgID); e != nil {
		return e
	}
	n, e := q.LockAppAccessGateway(ctx, sqlc.LockAppAccessGatewayParams{OrgID: g.OrgID, ID: g.GatewayID})
	if errors.Is(e, pgx.ErrNoRows) {
		return notFound()
	}
	if e != nil {
		return e
	}
	if g.CertSerial == "" || n.CertSerial != g.CertSerial || n.Status != "active" || n.EnrolledKind == nil || *n.EnrolledKind != "gateway" || !n.CertNotAfter.Valid || !n.CertNotAfter.Time.After(s.now()) {
		return apierr.Forbidden("gateway_unavailable", "gateway certificate is no longer current")
	}
	return nil
}
func (s *Service) runtime(r sqlc.AppAccessGatewayRuntime) GatewayRuntime {
	t := r.ReportedAt
	status := "supported"
	if r.CapabilityVersion != 1 {
		status = "unsupported"
	} else if s.now().Sub(t) > 30*time.Second {
		status = "unavailable"
	}
	return GatewayRuntime{OrgID: r.OrgID, GatewayID: r.GatewayID, CapabilityVersion: r.CapabilityVersion, ReportedAt: &t, Status: status}
}
func (s *Service) ReportCapability(ctx context.Context, g AuthenticatedGateway, version int32) (GatewayRuntime, error) {
	var out GatewayRuntime
	if version < 0 || version > 65535 {
		return out, apierr.BadRequest("invalid_capability", "invalid protocol version")
	}
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := s.gateway(ctx, q, g); e != nil {
			return e
		}
		r, e := q.ReportAppAccessGatewayRuntime(ctx, sqlc.ReportAppAccessGatewayRuntimeParams{OrgID: g.OrgID, GatewayID: g.GatewayID, CapabilityVersion: version, ReportedCertSerial: g.CertSerial})
		out = s.runtime(r)
		return e
	})
	return out, mapDB(e)
}
func (s *Service) GetGatewayRuntime(ctx context.Context, org, gw uuid.UUID) (GatewayRuntime, error) {
	out := GatewayRuntime{OrgID: org, GatewayID: gw, Status: "unknown"}
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		n, e := q.LockAppAccessGateway(ctx, sqlc.LockAppAccessGatewayParams{OrgID: org, ID: gw})
		if errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		}
		if e != nil {
			return e
		}
		r, e := q.GetAppAccessGatewayRuntime(ctx, sqlc.GetAppAccessGatewayRuntimeParams{OrgID: org, GatewayID: gw})
		if errors.Is(e, pgx.ErrNoRows) {
			if n.Status != "active" || !n.CertNotAfter.Valid || !n.CertNotAfter.Time.After(s.now()) {
				out.Status = "unavailable"
			}
			return nil
		}
		if e != nil {
			return e
		}
		out = s.runtime(r)
		if n.Status != "active" || n.CertSerial != r.ReportedCertSerial || !n.CertNotAfter.Valid || !n.CertNotAfter.Time.After(s.now()) {
			out.Status = "unavailable"
		}
		return nil
	})
	return out, mapDB(e)
}
func (s *Service) ready(ctx context.Context, q *sqlc.Queries, g AuthenticatedGateway, entitled bool) (string, error) {
	r, e := q.LockAppAccessGatewayRuntime(ctx, sqlc.LockAppAccessGatewayRuntimeParams{OrgID: g.OrgID, GatewayID: g.GatewayID})
	if errors.Is(e, pgx.ErrNoRows) {
		return "capability_unavailable", nil
	}
	if e != nil {
		return "", e
	}
	if r.CapabilityVersion != 1 {
		return "capability_unsupported", nil
	}
	if r.ReportedCertSerial != g.CertSerial || s.runtime(r).Status != "supported" {
		return "capability_unavailable", nil
	}
	if !entitled {
		return "feature_unavailable", nil
	}
	settings, e := q.GetAppAccessSettings(ctx, g.OrgID)
	if e != nil {
		return "", e
	}
	if !settings.Enabled {
		return "feature_disabled", nil
	}
	if !s.domainConfiguredWithQueries(ctx, q) {
		return "feature_unavailable", nil
	}
	return "", nil
}
func maintain(ctx context.Context, q *sqlc.Queries, g AuthenticatedGateway) error {
	if e := q.WithdrawStaleAppAccessAssignments(ctx, sqlc.WithdrawStaleAppAccessAssignmentsParams{OrgID: g.OrgID, GatewayID: g.GatewayID}); e != nil {
		return e
	}
	if e := q.ExpireAppAccessChecks(ctx, sqlc.ExpireAppAccessChecksParams{OrgID: g.OrgID, GatewayID: g.GatewayID}); e != nil {
		return e
	}
	return q.WithdrawInvalidAppAccessChecks(ctx, sqlc.WithdrawInvalidAppAccessChecksParams{OrgID: g.OrgID, GatewayID: g.GatewayID})
}
func (s *Service) DesiredForGateway(ctx context.Context, g AuthenticatedGateway, entitled bool) (Desired, error) {
	out := Desired{ProtocolVersion: 1, Purpose: originCheckPurpose, Assignments: []Assignment{}, Checks: []Check{}}
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := s.gateway(ctx, q, g); e != nil {
			return e
		}
		reason, e := s.ready(ctx, q, g, entitled)
		if e != nil {
			return e
		}
		if reason != "" {
			out.Withdrawn = true
			out.Reason = reason
			if e = q.WithdrawGatewayAppAccessAssignments(ctx, sqlc.WithdrawGatewayAppAccessAssignmentsParams{OrgID: g.OrgID, GatewayID: g.GatewayID}); e != nil {
				return e
			}
			return maintain(ctx, q, g)
		}
		if e = maintain(ctx, q, g); e != nil {
			return e
		}
		counts, e := q.AppAccessGatewayWorkCounts(ctx, sqlc.AppAccessGatewayWorkCountsParams{OrgID: g.OrgID, GatewayID: g.GatewayID})
		if e != nil {
			return e
		}
		if counts.Running < 8 {
			if e = q.ClaimAppAccessChecks(ctx, sqlc.ClaimAppAccessChecksParams{OrgID: g.OrgID, GatewayID: g.GatewayID, Limit: int32(8 - counts.Running)}); e != nil {
				return e
			}
		}
		as, e := q.ListGatewayAppAccessAssignments(ctx, sqlc.ListGatewayAppAccessAssignmentsParams{OrgID: g.OrgID, GatewayID: g.GatewayID})
		if e != nil {
			return e
		}
		for _, a := range as {
			out.Assignments = append(out.Assignments, Assignment{OrgID: a.OrgID, AppID: a.AppID, GatewayID: a.GatewayID, Generation: a.Generation, Revision: a.Revision, Digest: a.Digest, Purpose: a.Purpose, OriginURL: a.OriginUrl, AllowedDestinationCIDRs: a.AllowedDestinationCidrs, OriginCAPEM: a.OriginCaPem, OriginCADigest: a.OriginCaDigest})
		}
		cs, e := q.RunningAppAccessChecks(ctx, sqlc.RunningAppAccessChecksParams{OrgID: g.OrgID, GatewayID: g.GatewayID})
		for _, c := range cs {
			out.Checks = append(out.Checks, checkModel(c))
		}
		return e
	})
	return out, mapDB(e)
}
func (s *Service) RequestCheck(ctx context.Context, org, actor, app uuid.UUID, expectedVersion int64, entitled bool) (Check, error) {
	var out Check
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := lockGrantOrg(ctx, q, org); e != nil {
			return e
		}
		v, e := q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: org, ID: app})
		if errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		}
		if e != nil {
			return e
		}
		if v != expectedVersion {
			return conflict()
		}
		application, e := q.GetAppAccessApplication(ctx, sqlc.GetAppAccessApplicationParams{OrgID: org, ID: app})
		if e != nil {
			return e
		}
		if application.State != "draft" {
			return apierr.Conflict("application_archived", "archived application cannot be checked")
		}
		v = application.DraftRevision
		r, e := q.GetAppAccessRevision(ctx, sqlc.GetAppAccessRevisionParams{OrgID: org, AppID: app, Revision: v})
		if e != nil {
			return e
		}
		n, e := q.LockAppAccessGateway(ctx, sqlc.LockAppAccessGatewayParams{OrgID: org, ID: r.GatewayID})
		if e != nil {
			return e
		}
		g := AuthenticatedGateway{org, r.GatewayID, n.CertSerial}
		if e = s.gateway(ctx, q, g); e != nil {
			return e
		}
		reason, e := s.ready(ctx, q, g, entitled)
		if e != nil {
			return e
		}
		if reason != "" {
			return apierr.Conflict(reason, "origin check is unavailable")
		}
		if e = maintain(ctx, q, g); e != nil {
			return e
		}
		a, e := q.CurrentAppAccessAssignment(ctx, sqlc.CurrentAppAccessAssignmentParams{OrgID: org, AppID: app})
		if e == nil && (a.GatewayID != g.GatewayID || a.Revision != v || a.Digest != r.Digest) {
			if e = q.WithdrawAppAccessApplicationAssignment(ctx, sqlc.WithdrawAppAccessApplicationAssignmentParams{OrgID: org, AppID: app}); e != nil {
				return e
			}
			e = pgx.ErrNoRows
		}
		counts, ce := q.AppAccessGatewayWorkCounts(ctx, sqlc.AppAccessGatewayWorkCountsParams{OrgID: org, GatewayID: g.GatewayID})
		if ce != nil {
			return ce
		}
		if errors.Is(e, pgx.ErrNoRows) {
			if counts.Assignments >= 64 {
				return apierr.Conflict("connector_capacity", "gateway assignment capacity reached")
			}
			a, e = q.CreateAppAccessAssignment(ctx, sqlc.CreateAppAccessAssignmentParams{OrgID: org, AppID: app, GatewayID: g.GatewayID, Revision: v, Digest: r.Digest})
		}
		if e != nil {
			return e
		}
		pending, e := q.PendingAppAccessCheck(ctx, sqlc.PendingAppAccessCheckParams{OrgID: org, AppID: app, Generation: a.Generation})
		if e == nil {
			out = checkModel(pending)
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if counts.Queued >= 32 || counts.Recent >= 60 {
			return apierr.Conflict("connector_capacity", "gateway check capacity reached")
		}
		c, e := q.CreateAppAccessCheck(ctx, sqlc.CreateAppAccessCheckParams{OrgID: org, AppID: app, GatewayID: g.GatewayID, Revision: v, Digest: r.Digest, Generation: a.Generation})
		if e != nil {
			return e
		}
		out = checkModel(c)
		if e = q.FinalizeAppAccessApplicationChecks(ctx, sqlc.FinalizeAppAccessApplicationChecksParams{OrgID: org, AppID: app}); e != nil {
			return e
		}
		if e = q.PruneAppAccessCheckHistory(ctx, sqlc.PruneAppAccessCheckHistoryParams{OrgID: org, AppID: app}); e != nil {
			return e
		}
		if e = q.PruneAppAccessAssignmentHistory(ctx, sqlc.PruneAppAccessAssignmentHistoryParams{OrgID: org, AppID: app}); e != nil {
			return e
		}
		return audit(ctx, q, org, actor, c.ID.String(), "app_access.origin_check_requested", v)
	})
	return out, mapDB(e)
}
func (s *Service) GetCheck(ctx context.Context, org, app, id uuid.UUID) (Check, error) {
	r, e := sqlc.New(s.pool).GetAppAccessCheck(ctx, sqlc.GetAppAccessCheckParams{OrgID: org, AppID: app, ID: id})
	if errors.Is(e, pgx.ErrNoRows) {
		return Check{}, notFound()
	}
	out := checkModel(r)
	if (out.Status == "queued" || out.Status == "running") && !out.Deadline.After(s.now()) {
		out.Status = "expired"
		out.ErrorCode = "deadline_exceeded"
	}
	return out, e
}

func safeResultCode(code string) bool {
	switch code {
	case "", "dns_failed", "target_refused", "connect_failed", "tls_failed", "deadline_exceeded", "assignment_changed", "feature_withdrawn", "connector_failed", "http_failed":
		return true
	}
	return false
}
func (s *Service) exactAssignment(ctx context.Context, q *sqlc.Queries, g AuthenticatedGateway, app, generation uuid.UUID, revision int64, digest, purpose string, entitled bool, withdrawn bool) (sqlc.AppAccessConnectorAssignment, error) {
	var zero sqlc.AppAccessConnectorAssignment
	// Lock the live organization, then application, before the runtime row.
	if e := lockGrantOrg(ctx, q, g.OrgID); e != nil {
		return zero, e
	}
	v, e := q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: g.OrgID, ID: app})
	if errors.Is(e, pgx.ErrNoRows) {
		return zero, notFound()
	}
	if e != nil {
		return zero, e
	}
	application, e := q.GetAppAccessApplication(ctx, sqlc.GetAppAccessApplicationParams{OrgID: g.OrgID, ID: app})
	if e != nil {
		return zero, e
	}
	v = application.DraftRevision
	if e = s.gateway(ctx, q, g); e != nil {
		return zero, e
	}
	reason, e := s.ready(ctx, q, g, entitled)
	if e != nil {
		return zero, e
	}
	a, e := q.GetAppAccessAssignmentGeneration(ctx, sqlc.GetAppAccessAssignmentGenerationParams{OrgID: g.OrgID, Generation: generation})
	if e != nil {
		return zero, conflict()
	}
	if a.AppID != app || a.GatewayID != g.GatewayID || a.Revision != revision || a.Digest != digest || purpose != originCheckPurpose || a.Purpose != purpose {
		return zero, conflict()
	}
	if withdrawn {
		if !a.WithdrawnAt.Valid {
			return zero, conflict()
		}
		return a, nil
	}
	if reason != "" || application.State != "draft" || a.WithdrawnAt.Valid || v != revision {
		return zero, conflict()
	}
	r, e := q.GetAppAccessRevision(ctx, sqlc.GetAppAccessRevisionParams{OrgID: g.OrgID, AppID: app, Revision: v})
	if e != nil {
		return zero, e
	}
	if r.GatewayID != g.GatewayID || r.Digest != digest {
		return zero, conflict()
	}
	return a, nil
}
func (s *Service) CompleteCheck(ctx context.Context, g AuthenticatedGateway, result Result, entitled bool) (Check, error) {
	var out Check
	if !safeResultCode(result.ErrorCode) || (result.DNSStatus != "pending" && result.DNSStatus != "passed" && result.DNSStatus != "failed") || (result.ConnectStatus != "pending" && result.ConnectStatus != "passed" && result.ConnectStatus != "failed") || (result.TLSStatus != "pending" && result.TLSStatus != "passed" && result.TLSStatus != "failed" && result.TLSStatus != "skipped") {
		return out, apierr.BadRequest("invalid_check_result", "invalid bounded check result")
	}
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if _, e := s.exactAssignment(ctx, q, g, result.AppID, result.Generation, result.Revision, result.Digest, result.Purpose, entitled, false); e != nil {
			return e
		}
		c, e := q.LockAppAccessCheck(ctx, sqlc.LockAppAccessCheckParams{OrgID: g.OrgID, ID: result.RequestID})
		if e != nil {
			return conflict()
		}
		if c.AppID != result.AppID || c.GatewayID != g.GatewayID || c.Generation != result.Generation || c.Revision != result.Revision || c.Digest != result.Digest || c.Purpose != result.Purpose || c.Status != "running" || !c.Deadline.After(s.now()) {
			return conflict()
		}
		r, e := q.GetAppAccessRevision(ctx, sqlc.GetAppAccessRevisionParams{OrgID: g.OrgID, AppID: c.AppID, Revision: c.Revision})
		if e != nil {
			return e
		}
		http := len(r.OriginUrl) >= 7 && r.OriginUrl[:7] == "http://"
		if result.TLSStatus == "skipped" && !http {
			return apierr.BadRequest("invalid_check_result", "TLS may only be skipped for HTTP origins")
		}
		success := result.DNSStatus == "passed" && result.ConnectStatus == "passed" && (result.TLSStatus == "passed" || http && result.TLSStatus == "skipped")
		if (!success && result.ErrorCode == "") || result.DNSStatus != "passed" && (result.ConnectStatus != "pending" || result.TLSStatus != "pending") || result.ConnectStatus != "passed" && result.TLSStatus != "pending" {
			return apierr.BadRequest("invalid_check_result", "inconsistent check stages")
		}
		status := "failed"
		if success && result.ErrorCode == "" {
			status = "succeeded"
		}
		c, e = q.CompleteAppAccessCheck(ctx, sqlc.CompleteAppAccessCheckParams{OrgID: g.OrgID, ID: c.ID, Status: status, DnsStatus: result.DNSStatus, ConnectStatus: result.ConnectStatus, TlsStatus: result.TLSStatus, ErrorCode: result.ErrorCode, CompletedCertSerial: g.CertSerial})
		if errors.Is(e, pgx.ErrNoRows) {
			return conflict()
		}
		out = checkModel(c)
		if e != nil {
			return e
		}
		return connectorAudit(ctx, q, g, c.ID.String(), "app_access.origin_check_completed", c.Revision)
	})
	return out, mapDB(e)
}
func (s *Service) ReportApplied(ctx context.Context, g AuthenticatedGateway, in Applied, entitled bool) (GatewayRuntime, error) {
	var out GatewayRuntime
	if (in.Status != "configured" && in.Status != "failed" && in.Status != "withdrawn") || !safeResultCode(in.ErrorCode) || in.Status == "configured" && in.ErrorCode != "" {
		return out, apierr.BadRequest("invalid_applied_report", "invalid connector report")
	}
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		a, e := s.exactAssignment(ctx, q, g, in.AppID, in.Generation, in.Revision, in.Digest, in.Purpose, entitled, in.Status == "withdrawn")
		if e != nil {
			return e
		}
		if a.AppliedStatus == in.Status && a.AppliedErrorCode == in.ErrorCode {
			return nil
		}
		if e := q.ReportAppAccessApplied(ctx, sqlc.ReportAppAccessAppliedParams{OrgID: g.OrgID, Generation: in.Generation, AppliedStatus: in.Status, AppliedErrorCode: in.ErrorCode}); e != nil {
			return e
		}
		return connectorAudit(ctx, q, g, in.Generation.String(), "app_access.connector_applied", in.Revision)
	})
	if e != nil {
		return out, mapDB(e)
	}
	return s.GetGatewayRuntime(ctx, g.OrgID, g.GatewayID)
}

// AuthorizeChannel grants a short, rechecked origin-check lease. It confers no browser authority.
func (s *Service) AuthorizeChannel(ctx context.Context, g AuthenticatedGateway, app, generation uuid.UUID, revision int64, digest, purpose string, entitled bool) (time.Time, error) {
	var until time.Time
	decisionStarted := s.now()
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if _, e := s.exactAssignment(ctx, q, g, app, generation, revision, digest, purpose, entitled, false); e != nil {
			return e
		}
		until = decisionStarted.Add(5 * time.Second)
		if !until.After(s.now()) || ctx.Err() != nil {
			return apierr.Forbidden("assignment_unavailable", "channel authority deadline elapsed")
		}
		return nil
	})
	return until, mapDB(e)
}

func connectorAudit(ctx context.Context, q *sqlc.Queries, g AuthenticatedGateway, target, action string, revision int64) error {
	actor, kind := "app-access-connector", "app_access_origin_check"
	metadata, _ := json.Marshal(map[string]any{"gateway_id": g.GatewayID, "revision": revision})
	_, e := q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{OrgID: pgtype.UUID{Bytes: g.OrgID, Valid: true}, ActorSystem: &actor, Action: action, TargetType: &kind, TargetID: &target, Metadata: metadata})
	return e
}

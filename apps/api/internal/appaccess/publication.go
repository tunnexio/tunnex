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

type PublicationInput struct {
	ExpectedVersion, Revision int64
	Digest                    string
	CheckID, IdempotencyKey   uuid.UUID
}
type PublicationOperation struct {
	ID, AppID, GatewayID, Generation, OriginCheckID, ReadinessRequestID                                                                   uuid.UUID
	Version, Revision, AuthorityVersion, ReviewedApplicationVersion, ExpectedApplicationVersion, ExpectedActiveAuthorityVersion           int64
	Status, Digest, Hostname, PublicDNSStatus, PublicTLSStatus, ConnectorDNSStatus, ConnectorConnectStatus, ConnectorTLSStatus, ErrorCode string
	CreatedAt, Deadline                                                                                                                   time.Time
	CompletedAt                                                                                                                           *time.Time
}
type ActivePublication struct {
	Revision, AuthorityVersion int64
	Digest, Hostname, State    string
	GatewayID, Generation      uuid.UUID
	WithdrawalConfirmed        bool
	WithdrawalConfirmedAt      *time.Time
}
type RollbackRevision struct {
	Revision               int64
	Digest, Name, Hostname string
	GatewayID              uuid.UUID
	ActivatedAt            time.Time
}
type PublicationState struct {
	ApplicationVersion              int64
	ActiveLabel                     *string
	RollbackRevisions               []RollbackRevision
	Active                          *ActivePublication
	PendingOperation, LastOperation *PublicationOperation
	BrowserCapability               string
}

func publicationOperation(r sqlc.AppAccessPublicationOperation) PublicationOperation {
	return PublicationOperation{ID: r.ID, AppID: r.AppID, GatewayID: r.GatewayID, Generation: r.Generation, OriginCheckID: r.OriginCheckID, ReadinessRequestID: r.ReadinessRequestID, Version: r.Version, Revision: r.Revision, AuthorityVersion: r.AuthorityVersion, ReviewedApplicationVersion: r.ReviewedAppVersion, ExpectedApplicationVersion: r.ExpectedAppVersion, ExpectedActiveAuthorityVersion: r.ExpectedActiveAuthorityVersion, Status: r.Status, Digest: r.Digest, Hostname: r.Hostname, PublicDNSStatus: r.PublicDnsStatus, PublicTLSStatus: r.PublicTlsStatus, ConnectorDNSStatus: r.ConnectorDnsStatus, ConnectorConnectStatus: r.ConnectorConnectStatus, ConnectorTLSStatus: r.ConnectorTlsStatus, ErrorCode: r.ErrorCode, CreatedAt: r.CreatedAt, Deadline: r.Deadline, CompletedAt: timePointer(r.CompletedAt)}
}
func (s *Service) projectPublicationOperation(r sqlc.AppAccessPublicationOperation) PublicationOperation {
	out := publicationOperation(r)
	if (out.Status == "queued" || out.Status == "checking") && !out.Deadline.After(s.now()) {
		out.Status = "expired"
		out.ErrorCode = "deadline_exceeded"
	}
	return out
}
func (s *Service) GetPublication(ctx context.Context, org, app uuid.UUID) (PublicationState, error) {
	var out PublicationState
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := lockGrantOrg(ctx, q, org); e != nil {
			return e
		}
		if _, e := q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: org, ID: app}); errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		} else if e != nil {
			return e
		}
		var e error
		out, e = s.getPublication(ctx, q, org, app)
		return e
	})
	return out, e
}
func (s *Service) getPublication(ctx context.Context, q *sqlc.Queries, org, app uuid.UUID) (PublicationState, error) {
	out := PublicationState{BrowserCapability: "unknown"}
	application, e := s.GetApplication(ctx, org, app)
	if e != nil {
		return out, e
	}
	out.ApplicationVersion = application.Version
	out.RollbackRevisions = []RollbackRevision{}
	history, e := q.ListPreviouslyActivatedAppAccessRevisions(ctx, sqlc.ListPreviouslyActivatedAppAccessRevisionsParams{OrgID: org, AppID: app, PageLimit: 50})
	if e != nil {
		return out, publicationUnavailable()
	}
	for _, r := range history {
		out.RollbackRevisions = append(out.RollbackRevisions, RollbackRevision{Revision: r.Revision, Digest: r.Digest, Name: r.Name, Hostname: r.Hostname, GatewayID: r.GatewayID, ActivatedAt: r.ActivatedAt})
	}
	if r, e := q.GetAppAccessServingPublication(ctx, sqlc.GetAppAccessServingPublicationParams{OrgID: org, AppID: app}); e == nil {
		out.Active = &ActivePublication{Revision: r.Revision, AuthorityVersion: r.AuthorityVersion, Digest: r.Digest, Hostname: r.Hostname, State: r.State, GatewayID: r.GatewayID, Generation: r.Generation, WithdrawalConfirmed: r.WithdrawalConfirmedAt.Valid && r.WithdrawalConfirmedAuthorityVersion != nil && *r.WithdrawalConfirmedAuthorityVersion == r.AuthorityVersion && r.WithdrawalConfirmedGeneration.Valid && uuid.UUID(r.WithdrawalConfirmedGeneration.Bytes) == r.Generation, WithdrawalConfirmedAt: timePointer(r.WithdrawalConfirmedAt)}
		rev, err := s.GetRevision(ctx, org, app, r.Revision)
		if err != nil {
			return out, publicationUnavailable()
		}
		out.ActiveLabel = &rev.Name
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	if r, e := q.PendingAppAccessPublicationOperation(ctx, sqlc.PendingAppAccessPublicationOperationParams{OrgID: org, AppID: app}); e == nil {
		op := s.projectPublicationOperation(r)
		if op.Status != "expired" {
			out.PendingOperation = &op
		}
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	if r, e := q.LastAppAccessPublicationOperation(ctx, sqlc.LastAppAccessPublicationOperationParams{OrgID: org, AppID: app}); e == nil {
		op := s.projectPublicationOperation(r)
		if (op.Status == "queued" || op.Status == "checking") && !op.Deadline.After(s.now()) {
			op.Status = "expired"
			op.ErrorCode = "deadline_exceeded"
		}
		out.LastOperation = &op
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	if runtime, e := q.GetAppAccessBrowserGatewayRuntime(ctx, sqlc.GetAppAccessBrowserGatewayRuntimeParams{OrgID: org, GatewayID: application.Draft.GatewayID}); e == nil {
		node, err := q.GetNodeForOrg(ctx, sqlc.GetNodeForOrgParams{OrgID: org, ID: application.Draft.GatewayID})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return out, publicationUnavailable()
		}
		out.BrowserCapability = "supported"
		if runtime.CapabilityVersion != 1 {
			out.BrowserCapability = "unsupported"
		} else if err != nil || node.Status != "active" || node.CertSerial != runtime.ReportedCertSerial || !node.CertNotAfter.Valid || !node.CertNotAfter.Time.After(s.now()) || !runtime.ReportedAt.Add(30*time.Second).After(s.now()) {
			out.BrowserCapability = "unavailable"
		}
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	return out, nil
}
func (s *Service) GetPublicationOperation(ctx context.Context, org, app, id uuid.UUID) (PublicationOperation, error) {
	r, e := sqlc.New(s.pool).GetAppAccessPublicationOperation(ctx, sqlc.GetAppAccessPublicationOperationParams{OrgID: org, AppID: app, OperationID: id})
	if errors.Is(e, pgx.ErrNoRows) {
		return PublicationOperation{}, notFound()
	}
	return s.projectPublicationOperation(r), e
}
func (s *Service) GetPublicationOperationByKey(ctx context.Context, org, app, key uuid.UUID) (PublicationOperation, error) {
	r, e := sqlc.New(s.pool).GetAppAccessPublicationOperationByKey(ctx, sqlc.GetAppAccessPublicationOperationByKeyParams{OrgID: org, AppID: app, IdempotencyKey: key})
	if errors.Is(e, pgx.ErrNoRows) {
		return PublicationOperation{}, notFound()
	}
	return s.projectPublicationOperation(r), e
}
func publicationUnavailable() error {
	return apierr.New(503, "publication_unavailable", "publication authority unavailable")
}

func (s *Service) CreatePublicationOperation(ctx context.Context, org, actor, app uuid.UUID, input PublicationInput, entitled bool) (PublicationOperation, error) {
	var out PublicationOperation
	if input.ExpectedVersion < 1 || input.Revision < 1 || input.CheckID == uuid.Nil || input.IdempotencyKey == uuid.Nil || len(input.Digest) != 64 {
		return out, apierr.BadRequest("invalid_publication", "reviewed version, revision, digest and check required")
	}
	err := s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := lockGrantOrg(ctx, q, org); e != nil {
			return e
		}
		version, e := q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: org, ID: app})
		if errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		}
		if e != nil {
			return e
		}
		prior, e := q.GetAppAccessPublicationOperationByKey(ctx, sqlc.GetAppAccessPublicationOperationByKeyParams{OrgID: org, AppID: app, IdempotencyKey: input.IdempotencyKey})
		if e == nil {
			if prior.ReviewedAppVersion != input.ExpectedVersion || prior.Revision != input.Revision || prior.Digest != input.Digest || prior.OriginCheckID != input.CheckID {
				return apierr.Conflict("idempotency_key_reused", "publication key belongs to a different review")
			}
			out = s.projectPublicationOperation(prior)
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if version != input.ExpectedVersion {
			return conflict()
		}
		a, e := q.GetAppAccessApplication(ctx, sqlc.GetAppAccessApplicationParams{OrgID: org, ID: app})
		if e != nil {
			return e
		}
		if a.State != "draft" {
			return apierr.Conflict("application_archived", "archived application cannot publish")
		}
		if a.DraftRevision != input.Revision {
			return conflict()
		}
		r, e := q.GetAppAccessRevision(ctx, sqlc.GetAppAccessRevisionParams{OrgID: org, AppID: app, Revision: input.Revision})
		if e != nil {
			return e
		}
		if r.Digest != input.Digest {
			return conflict()
		}
		if !s.publicationDomainReadyWithQueries(ctx, q) {
			return apierr.Conflict("app_domain_unavailable", "application domain unavailable")
		}
		if e = requireDraft(ctx, q, org, r.GatewayID, entitled); e != nil {
			return e
		}
		n, e := q.LockAppAccessGateway(ctx, sqlc.LockAppAccessGatewayParams{OrgID: org, ID: r.GatewayID})
		if e != nil {
			return e
		}
		if n.Status != "active" || n.CertSerial == "" || !n.CertNotAfter.Valid || !n.CertNotAfter.Time.After(s.now()) {
			return apierr.Conflict("gateway_unavailable", "current gateway required")
		}
		runtime, e := q.GetAppAccessBrowserGatewayRuntime(ctx, sqlc.GetAppAccessBrowserGatewayRuntimeParams{OrgID: org, GatewayID: r.GatewayID})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.Conflict("browser_capability_unavailable", "browser connector capability required")
		}
		if e != nil {
			return e
		}
		if runtime.CapabilityVersion != 1 || runtime.ReportedCertSerial != n.CertSerial || !runtime.ReportedAt.Add(30*time.Second).After(s.now()) {
			return apierr.Conflict("browser_capability_unavailable", "fresh browser connector capability required")
		}
		check, e := q.GetAppAccessCheck(ctx, sqlc.GetAppAccessCheckParams{OrgID: org, AppID: app, ID: input.CheckID})
		if errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		}
		if e != nil {
			return e
		}
		if check.Status != "succeeded" || check.Revision != input.Revision || check.Digest != input.Digest || check.GatewayID != r.GatewayID || check.CompletedCertSerial != n.CertSerial || !check.CompletedAt.Valid || !check.CompletedAt.Time.Add(5*time.Minute).After(s.now()) {
			return apierr.Conflict("origin_check_required", "fresh exact current-certificate origin check required")
		}
		if e = q.ExpireAppAccessPublicationOperations(ctx, sqlc.ExpireAppAccessPublicationOperationsParams{OrgID: org, AppID: app}); e != nil {
			return e
		}
		if _, e = q.PendingAppAccessPublicationOperation(ctx, sqlc.PendingAppAccessPublicationOperationParams{OrgID: org, AppID: app}); e == nil {
			return apierr.Conflict("publication_pending", "publication already pending")
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		pointer, e := q.GetAppAccessServingPublication(ctx, sqlc.GetAppAccessServingPublicationParams{OrgID: org, AppID: app})
		authority := int64(0)
		if e == nil {
			authority = pointer.AuthorityVersion
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		work, e := q.AppAccessBrowserGatewayWorkCount(ctx, sqlc.AppAccessBrowserGatewayWorkCountParams{OrgID: org, GatewayID: r.GatewayID})
		if e != nil {
			return e
		}
		if work >= 64 {
			return apierr.Conflict("browser_capacity_exceeded", "gateway browser assignment capacity reached")
		}
		next, e := q.AdvanceAppAccessApplicationAuthorityVersion(ctx, sqlc.AdvanceAppAccessApplicationAuthorityVersionParams{OrgID: org, AppID: app, ExpectedVersion: version})
		if e != nil {
			return e
		}
		op, e := q.CreateAppAccessPublicationOperation(ctx, sqlc.CreateAppAccessPublicationOperationParams{OrgID: org, AppID: app, ActorUserID: actor, IdempotencyKey: input.IdempotencyKey, ReviewedAppVersion: version, ExpectedAppVersion: next, Revision: input.Revision, Digest: input.Digest, OriginCheckID: input.CheckID, GatewayID: r.GatewayID, Hostname: r.PublicHostname, ExpectedActiveAuthorityVersion: authority, GatewayCertSerial: n.CertSerial, Deadline: s.now().Add(time.Minute)})
		if e != nil {
			return e
		}
		if e = q.ClearAppAccessPublicationWithdrawalConfirmation(ctx, sqlc.ClearAppAccessPublicationWithdrawalConfirmationParams{OrgID: org, AppID: app}); e != nil {
			return e
		}
		out = s.projectPublicationOperation(op)
		return audit(ctx, q, org, actor, app.String(), "app_access.publication_staged", next)
	})
	return out, err
}

func (s *Service) CancelPublicationOperation(ctx context.Context, org, actor, app, id uuid.UUID, expected int64) (PublicationOperation, error) {
	var out PublicationOperation
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := lockGrantOrg(ctx, q, org); e != nil {
			return e
		}
		version, e := q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: org, ID: app})
		if e != nil {
			return e
		}
		if e = q.ExpireAppAccessPublicationOperations(ctx, sqlc.ExpireAppAccessPublicationOperationsParams{OrgID: org, AppID: app}); e != nil {
			return e
		}
		op, e := q.LockAppAccessPublicationOperation(ctx, sqlc.LockAppAccessPublicationOperationParams{OrgID: org, AppID: app, OperationID: id})
		if errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		}
		if e != nil {
			return e
		}
		if op.Status != "queued" && op.Status != "checking" {
			out = s.projectPublicationOperation(op)
			return nil
		}
		if op.Version != expected {
			return conflict()
		}
		op, e = q.CancelAppAccessPublicationOperation(ctx, sqlc.CancelAppAccessPublicationOperationParams{OrgID: org, AppID: app, OperationID: id, ExpectedVersion: expected})
		if e != nil {
			return e
		}
		next, e := q.AdvanceAppAccessApplicationAuthorityVersion(ctx, sqlc.AdvanceAppAccessApplicationAuthorityVersionParams{OrgID: org, AppID: app, ExpectedVersion: version})
		if e != nil {
			return e
		}
		out = s.projectPublicationOperation(op)
		return audit(ctx, q, org, actor, app.String(), "app_access.publication_cancelled", next)
	})
	return out, e
}

func (s *Service) DisablePublication(ctx context.Context, org, actor, app uuid.UUID, expectedApp, expectedAuthority int64) (PublicationState, error) {
	var disabled sqlc.AppAccessServingPublication
	postDisableVersion := int64(0)
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := lockGrantOrg(ctx, q, org); e != nil {
			return e
		}
		version, e := q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: org, ID: app})
		if errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		}
		if e != nil {
			return e
		}
		if version != expectedApp {
			return conflict()
		}
		pointer, e := q.LockAppAccessServingPublication(ctx, sqlc.LockAppAccessServingPublicationParams{OrgID: org, AppID: app})
		exists := e == nil
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		authority := int64(0)
		if exists {
			authority = pointer.AuthorityVersion
		}
		if authority != expectedAuthority {
			return conflict()
		}
		if e = q.ExpireAppAccessPublicationOperations(ctx, sqlc.ExpireAppAccessPublicationOperationsParams{OrgID: org, AppID: app}); e != nil {
			return e
		}
		pending, e := q.PendingAppAccessPublicationOperation(ctx, sqlc.PendingAppAccessPublicationOperationParams{OrgID: org, AppID: app})
		hasPending := e == nil
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if exists && pointer.State == "disabled" && pointer.WithdrawalConfirmedAt.Valid && !hasPending {
			disabled = pointer
			postDisableVersion = version
			return nil
		}
		if _, e = q.CancelAppAccessPublicationOperations(ctx, sqlc.CancelAppAccessPublicationOperationsParams{OrgID: org, AppID: app}); e != nil {
			return e
		}
		if exists {
			if _, e = q.DisableAppAccessServingPublication(ctx, sqlc.DisableAppAccessServingPublicationParams{OrgID: org, AppID: app}); e != nil {
				return e
			}
		} else if hasPending {
			if _, e = q.CreateDisabledAppAccessPublicationFromOperation(ctx, sqlc.CreateDisabledAppAccessPublicationFromOperationParams{OrgID: org, AppID: app, OperationID: pending.ID}); e != nil {
				return e
			}
		} else {
			if _, e = q.CreateDisabledAppAccessPublicationFromDraft(ctx, sqlc.CreateDisabledAppAccessPublicationFromDraftParams{OrgID: org, AppID: app, ExpectedAppVersion: version}); e != nil {
				return e
			}
		}
		disabled, e = q.GetAppAccessServingPublication(ctx, sqlc.GetAppAccessServingPublicationParams{OrgID: org, AppID: app})
		if e != nil {
			return e
		}
		next, e := q.AdvanceAppAccessApplicationAuthorityVersion(ctx, sqlc.AdvanceAppAccessApplicationAuthorityVersionParams{OrgID: org, AppID: app, ExpectedVersion: version})
		if e != nil {
			return e
		}
		postDisableVersion = next
		return audit(ctx, q, org, actor, app.String(), "app_access.publication_disabled", next)
	})
	if e != nil {
		return PublicationState{}, e
	}
	if !disabled.WithdrawalConfirmedAt.Valid {
		// This monotonic timer starts only after transaction() has confirmed commit.
		// A canceled call or process restart never substitutes wall-clock row age.
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return PublicationState{}, ctx.Err()
		case <-timer.C:
		}
		e = s.transaction(ctx, func(q *sqlc.Queries) error {
			if e := lockGrantOrg(ctx, q, org); e != nil {
				return e
			}
			version, e := q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: org, ID: app})
			if e != nil {
				return e
			}
			if version != postDisableVersion {
				return conflict()
			}
			if _, e = q.PendingAppAccessPublicationOperation(ctx, sqlc.PendingAppAccessPublicationOperationParams{OrgID: org, AppID: app}); e == nil {
				return conflict()
			} else if !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
			_, e = q.ConfirmAppAccessPublicationWithdrawal(ctx, sqlc.ConfirmAppAccessPublicationWithdrawalParams{OrgID: org, AppID: app, ExpectedAuthorityVersion: disabled.AuthorityVersion, ExpectedGeneration: disabled.Generation})
			if errors.Is(e, pgx.ErrNoRows) {
				return conflict()
			}
			return e
		})
		if e != nil {
			return PublicationState{}, e
		}
	}
	return s.GetPublication(ctx, org, app)
}
func (s *Service) ArchiveApplication(ctx context.Context, org, actor, app uuid.UUID, expected int64) error {
	return s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := lockGrantOrg(ctx, q, org); e != nil {
			return e
		}
		v, e := q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: org, ID: app})
		if e != nil {
			return e
		}
		if v != expected {
			return conflict()
		}
		a, e := q.GetAppAccessApplication(ctx, sqlc.GetAppAccessApplicationParams{OrgID: org, ID: app})
		if e != nil {
			return e
		}
		if a.State == "archived" {
			return nil
		}
		if e = q.ExpireAppAccessPublicationOperations(ctx, sqlc.ExpireAppAccessPublicationOperationsParams{OrgID: org, AppID: app}); e != nil {
			return e
		}
		n, e := q.ArchiveAppAccessApplication(ctx, sqlc.ArchiveAppAccessApplicationParams{OrgID: org, AppID: app, ExpectedVersion: expected})
		if e != nil {
			return e
		}
		if n != 1 {
			return apierr.Conflict("withdrawal_required", "disable and confirm withdrawal before archiving")
		}
		return audit(ctx, q, org, actor, app.String(), "app_access.application_archived", expected+1)
	})
}
func (s *Service) RollbackDraft(ctx context.Context, org, actor, app uuid.UUID, expected, revision int64, entitled bool) (Application, error) {
	r, e := sqlc.New(s.pool).GetPreviouslyActivatedAppAccessRevision(ctx, sqlc.GetPreviouslyActivatedAppAccessRevisionParams{OrgID: org, AppID: app, Revision: revision})
	if errors.Is(e, pgx.ErrNoRows) {
		return Application{}, notFound()
	}
	if e != nil {
		return Application{}, publicationUnavailable()
	}
	in := DraftInput{Name: r.Name, Description: r.Description, Icon: r.Icon, IconDataURL: r.IconDataUrl, IconDataURLSet: true, OriginURL: r.OriginUrl, GatewayID: r.GatewayID, PublicHostname: r.PublicHostname, IdleTimeoutSeconds: r.IdleTimeoutSeconds, AbsoluteTimeoutSeconds: r.AbsoluteTimeoutSeconds, AllowedDestinationCIDRs: r.AllowedDestinationCidrs, OriginCAPEM: r.OriginCaPem, AllowedDestinationCIDRsSet: true, OriginCAPEMSet: true}
	return s.UpdateDraft(ctx, org, actor, app, in, expected, entitled)
}

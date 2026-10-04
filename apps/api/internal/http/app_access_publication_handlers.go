package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
)

type appAccessPublicationPort interface {
	GetPublication(context.Context, uuid.UUID, uuid.UUID) (appaccess.PublicationState, error)
	GetPublicationOperation(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (appaccess.PublicationOperation, error)
	GetPublicationOperationByKey(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (appaccess.PublicationOperation, error)
	CreatePublicationOperation(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, appaccess.PublicationInput, bool) (appaccess.PublicationOperation, error)
	CancelPublicationOperation(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, int64) (appaccess.PublicationOperation, error)
	DisablePublication(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64, int64) (appaccess.PublicationState, error)
	ArchiveApplication(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64) error
	RollbackDraft(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64, int64, bool) (appaccess.Application, error)
}

func (s apiServer) publicationPort() (appAccessPublicationPort, error) {
	p, ok := s.appAccess.(appAccessPublicationPort)
	if !ok {
		return nil, apierr.New(503, "publication_unavailable", "publication service unavailable")
	}
	return p, nil
}
func appAccessPublicationOperation(r appaccess.PublicationOperation) api.AppAccessPublicationOperation {
	return api.AppAccessPublicationOperation{Id: r.ID, AppId: r.AppID, GatewayId: r.GatewayID, Generation: r.Generation, OriginCheckId: r.OriginCheckID, ReadinessRequestId: r.ReadinessRequestID, Version: r.Version, Revision: r.Revision, AuthorityVersion: r.AuthorityVersion, ReviewedApplicationVersion: r.ReviewedApplicationVersion, ExpectedApplicationVersion: r.ExpectedApplicationVersion, ExpectedActiveAuthorityVersion: r.ExpectedActiveAuthorityVersion, Status: api.AppAccessPublicationOperationStatus(r.Status), Digest: r.Digest, Hostname: r.Hostname, CreatedAt: r.CreatedAt, Deadline: r.Deadline, CompletedAt: r.CompletedAt, PublicDnsStatus: api.AppAccessPublicationStage(r.PublicDNSStatus), PublicTlsStatus: api.AppAccessPublicationStage(r.PublicTLSStatus), ConnectorDnsStatus: api.AppAccessPublicationStage(r.ConnectorDNSStatus), ConnectorConnectStatus: api.AppAccessPublicationStage(r.ConnectorConnectStatus), ConnectorTlsStatus: api.AppAccessPublicationTLSStage(r.ConnectorTLSStatus), ErrorCode: r.ErrorCode}
}
func appAccessPublication(r appaccess.PublicationState) api.AppAccessPublicationState {
	out := api.AppAccessPublicationState{ApplicationVersion: r.ApplicationVersion, ActiveLabel: r.ActiveLabel, BrowserCapability: api.AppAccessPublicationStateBrowserCapability(r.BrowserCapability), RollbackRevisions: []api.AppAccessRollbackRevision{}}
	for _, h := range r.RollbackRevisions {
		out.RollbackRevisions = append(out.RollbackRevisions, api.AppAccessRollbackRevision{Revision: h.Revision, Digest: h.Digest, Name: h.Name, Hostname: h.Hostname, GatewayId: h.GatewayID, ActivatedAt: h.ActivatedAt})
	}
	if r.Active != nil {
		a := r.Active
		out.Active = &api.AppAccessActivePublication{Revision: a.Revision, Digest: a.Digest, Hostname: a.Hostname, GatewayId: a.GatewayID, Generation: a.Generation, AuthorityVersion: a.AuthorityVersion, State: api.AppAccessActivePublicationState(a.State), WithdrawalConfirmed: a.WithdrawalConfirmed, WithdrawalConfirmedAt: a.WithdrawalConfirmedAt}
	}
	if r.PendingOperation != nil {
		o := appAccessPublicationOperation(*r.PendingOperation)
		out.PendingOperation = &o
	}
	if r.LastOperation != nil {
		o := appAccessPublicationOperation(*r.LastOperation)
		out.LastOperation = &o
	}
	return out
}

func (s apiServer) GetAppAccessPublication(ctx context.Context, req api.GetAppAccessPublicationRequestObject) (api.GetAppAccessPublicationResponseObject, error) {
	ctx, _, err := s.appAccessContext(ctx, req.OrgId, false)
	if err != nil {
		return nil, err
	}
	svc, err := s.publicationPort()
	if err != nil {
		return nil, err
	}
	out, err := svc.GetPublication(ctx, req.OrgId, req.AppId)
	if err != nil {
		return nil, err
	}
	return api.GetAppAccessPublication200JSONResponse{Body: appAccessPublication(out), Headers: api.GetAppAccessPublication200ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) GetAppAccessPublicationOperation(ctx context.Context, req api.GetAppAccessPublicationOperationRequestObject) (api.GetAppAccessPublicationOperationResponseObject, error) {
	ctx, _, err := s.appAccessContext(ctx, req.OrgId, false)
	if err != nil {
		return nil, err
	}
	svc, err := s.publicationPort()
	if err != nil {
		return nil, err
	}
	out, err := svc.GetPublicationOperation(ctx, req.OrgId, req.AppId, req.OperationId)
	if err != nil {
		return nil, err
	}
	return api.GetAppAccessPublicationOperation200JSONResponse{Body: appAccessPublicationOperation(out), Headers: api.GetAppAccessPublicationOperation200ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) GetAppAccessPublicationOperationByKey(ctx context.Context, req api.GetAppAccessPublicationOperationByKeyRequestObject) (api.GetAppAccessPublicationOperationByKeyResponseObject, error) {
	ctx, _, err := s.appAccessContext(ctx, req.OrgId, false)
	if err != nil {
		return nil, err
	}
	svc, err := s.publicationPort()
	if err != nil {
		return nil, err
	}
	out, err := svc.GetPublicationOperationByKey(ctx, req.OrgId, req.AppId, req.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	return api.GetAppAccessPublicationOperationByKey200JSONResponse{Body: appAccessPublicationOperation(out), Headers: api.GetAppAccessPublicationOperationByKey200ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) CreateAppAccessPublicationOperation(ctx context.Context, req api.CreateAppAccessPublicationOperationRequestObject) (api.CreateAppAccessPublicationOperationResponseObject, error) {
	ctx, actor, err := s.appAccessContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	svc, err := s.publicationPort()
	if err != nil {
		return nil, err
	}
	out, err := svc.CreatePublicationOperation(ctx, req.OrgId, actor, req.AppId, appaccess.PublicationInput{ExpectedVersion: req.Body.ExpectedVersion, Revision: req.Body.Revision, Digest: req.Body.Digest, CheckID: req.Body.CheckId, IdempotencyKey: req.Body.IdempotencyKey}, s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	return api.CreateAppAccessPublicationOperation201JSONResponse{Body: appAccessPublicationOperation(out), Headers: api.CreateAppAccessPublicationOperation201ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) CancelAppAccessPublicationOperation(ctx context.Context, req api.CancelAppAccessPublicationOperationRequestObject) (api.CancelAppAccessPublicationOperationResponseObject, error) {
	ctx, actor, err := s.appAccessContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	svc, err := s.publicationPort()
	if err != nil {
		return nil, err
	}
	out, err := svc.CancelPublicationOperation(ctx, req.OrgId, actor, req.AppId, req.OperationId, req.Body.ExpectedOperationVersion)
	if err != nil {
		return nil, err
	}
	return api.CancelAppAccessPublicationOperation200JSONResponse{Body: appAccessPublicationOperation(out), Headers: api.CancelAppAccessPublicationOperation200ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) DisableAppAccessPublication(ctx context.Context, req api.DisableAppAccessPublicationRequestObject) (api.DisableAppAccessPublicationResponseObject, error) {
	ctx, actor, err := s.appAccessContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	svc, err := s.publicationPort()
	if err != nil {
		return nil, err
	}
	out, err := svc.DisablePublication(ctx, req.OrgId, actor, req.AppId, req.Body.ExpectedApplicationVersion, req.Body.ExpectedAuthorityVersion)
	if err != nil {
		return nil, err
	}
	return api.DisableAppAccessPublication200JSONResponse{Body: appAccessPublication(out), Headers: api.DisableAppAccessPublication200ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) RollbackAppAccessDraft(ctx context.Context, req api.RollbackAppAccessDraftRequestObject) (api.RollbackAppAccessDraftResponseObject, error) {
	ctx, actor, err := s.appAccessContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	svc, err := s.publicationPort()
	if err != nil {
		return nil, err
	}
	out, err := svc.RollbackDraft(ctx, req.OrgId, actor, req.AppId, req.Body.ExpectedVersion, req.Body.Revision, s.appAccessEntitled())
	if err != nil {
		return nil, err
	}
	return api.RollbackAppAccessDraft200JSONResponse{Body: appAccessApplication(out), Headers: api.RollbackAppAccessDraft200ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) ArchiveAppAccessApplication(ctx context.Context, req api.ArchiveAppAccessApplicationRequestObject) (api.ArchiveAppAccessApplicationResponseObject, error) {
	ctx, actor, err := s.appAccessContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	svc, err := s.publicationPort()
	if err != nil {
		return nil, err
	}
	if err = svc.ArchiveApplication(ctx, req.OrgId, actor, req.AppId, req.Params.ExpectedVersion); err != nil {
		return nil, err
	}
	return api.ArchiveAppAccessApplication204Response{Headers: api.ArchiveAppAccessApplication204ResponseHeaders{CacheControl: "no-store"}}, nil
}

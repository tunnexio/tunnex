package http

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/workflowprovenance"
)

func (s apiServer) RegisterAgentWorkflowSigningKey(ctx context.Context, req api.RegisterAgentWorkflowSigningKeyRequestObject) (api.RegisterAgentWorkflowSigningKeyResponseObject, error) {
	id, ok := agentruntime.IdentityFromContext(ctx)
	if !ok || req.Body == nil {
		return nil, runtimeUnauthorized()
	}
	if s.workflowProvenance == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "workflow_provenance_unavailable", "workflow provenance is temporarily unavailable")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(req.Body.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, apierr.BadRequest("invalid_workflow_signing_key", "workflow signing key is not acceptable")
	}
	if err := s.workflowProvenance.RegisterKey(ctx, id.OrgID, id.DeviceID, req.Body.Kid, ed25519.PublicKey(publicKey)); err != nil {
		if errors.Is(err, workflowprovenance.ErrInvalidKey) {
			return nil, apierr.BadRequest("invalid_workflow_signing_key", "workflow signing key is not acceptable")
		}
		if errors.Is(err, workflowprovenance.ErrKeyAlreadyRegistered) {
			return nil, apierr.Conflict("workflow_signing_key_conflict", "workflow signing key ID is already registered with different material")
		}
		return nil, apierr.New(http.StatusServiceUnavailable, "workflow_provenance_unavailable", "workflow provenance is temporarily unavailable")
	}
	return api.RegisterAgentWorkflowSigningKey204Response{Headers: api.RegisterAgentWorkflowSigningKey204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ReportAgentWorkflowProvenance(ctx context.Context, req api.ReportAgentWorkflowProvenanceRequestObject) (api.ReportAgentWorkflowProvenanceResponseObject, error) {
	id, ok := agentruntime.IdentityFromContext(ctx)
	if !ok || req.Body == nil {
		return nil, runtimeUnauthorized()
	}
	if s.workflowProvenance == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "workflow_provenance_unavailable", "workflow provenance is temporarily unavailable")
	}
	body := req.Body
	outcome, err := s.workflowProvenance.Report(ctx, id.OrgID, id.DeviceID, workflowprovenance.Assertion{
		Version: int(body.Version),
		Claims: workflowprovenance.Claims{
			AssertionID:          body.AssertionId,
			WorkflowID:           body.WorkflowId,
			RunID:                body.RunId,
			TriggerKind:          body.TriggerKind,
			InitiatingSubjectRef: body.InitiatingSubjectRef,
			Tool:                 body.Tool,
			Resource:             body.Resource,
			IssuedAt:             body.IssuedAt,
			ExpiresAt:            body.ExpiresAt,
			KeyID:                body.Kid,
		},
		Signature: body.Signature,
	})
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "workflow_provenance_unavailable", "workflow provenance is temporarily unavailable")
	}
	return api.ReportAgentWorkflowProvenance201JSONResponse(api.AgentWorkflowProvenanceOutcome{
		Id:                 outcome.ID,
		AssertionId:        outcome.AssertionID,
		VerificationState:  api.AgentWorkflowProvenanceOutcomeVerificationState(outcome.State),
		VerificationReason: api.AgentWorkflowProvenanceOutcomeVerificationReason(outcome.Reason),
	}), nil
}

func (s apiServer) ListAgentWorkflowProvenance(ctx context.Context, req api.ListAgentWorkflowProvenanceRequestObject) (api.ListAgentWorkflowProvenanceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	// This is a read-only detail projection alongside runtime status and F12/F13
	// metadata, so it retains the established privileged-agent-view permission.
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	if s.workflowProvenance == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "workflow_provenance_unavailable", "workflow provenance is temporarily unavailable")
	}
	rows, err := s.workflowProvenance.List(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "workflow_provenance_unavailable", "workflow provenance is temporarily unavailable")
	}
	out := make(api.ListAgentWorkflowProvenance200JSONResponse, 0, len(rows))
	for _, row := range rows {
		item := api.AgentWorkflowProvenanceRecord{
			Id:                 row.ID,
			AssertionId:        row.AssertionID,
			KeyId:              row.KeyID,
			VerificationState:  api.AgentWorkflowProvenanceRecordVerificationState(row.State),
			VerificationReason: api.AgentWorkflowProvenanceRecordVerificationReason(row.Reason),
			ReceivedAt:         row.ReceivedAt,
		}
		if row.Chain != nil {
			item.VerifiedChain = &api.AgentWorkflowProvenanceChain{WorkflowId: row.Chain.WorkflowID, RunId: row.Chain.RunID, TriggerKind: row.Chain.TriggerKind, InitiatingSubjectRef: row.Chain.InitiatingSubjectRef, Tool: row.Chain.Tool, Resource: row.Chain.Resource, IssuedAt: row.Chain.IssuedAt, ExpiresAt: row.Chain.ExpiresAt}
		}
		out = append(out, item)
	}
	return out, nil
}

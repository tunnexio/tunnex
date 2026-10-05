package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
)

type customSkillRepository interface {
	CreateCustomSkill(context.Context, uuid.UUID, uuid.UUID, string, string) (sandboxes.CustomSkill, bool, error)
	CustomSkills(context.Context, uuid.UUID, uuid.UUID) ([]sandboxes.CustomSkill, error)
	GetCustomSkill(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (sandboxes.CustomSkill, error)
	EditCustomSkill(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64, string) (sandboxes.CustomSkill, error)
	DeleteCustomSkill(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64) error
}

func (s apiServer) customSkillActor(ctx context.Context, org uuid.UUID, permission rbac.Permission) (uuid.UUID, customSkillRepository, error) {
	actor, err := s.sandboxActor(ctx, org, permission)
	if err != nil {
		return uuid.Nil, nil, err
	}
	repo, ok := s.sandboxes.(customSkillRepository)
	if !ok {
		return uuid.Nil, nil, apierr.New(503, "sandbox_skill_storage_unavailable", "custom skill storage is unavailable")
	}
	return actor, repo, nil
}
func customSkillResponse(v sandboxes.CustomSkill) api.SandboxCustomSkill {
	return api.SandboxCustomSkill{Id: v.ID, RevisionId: v.RevisionID, Generation: v.Generation, Name: v.Name, Description: v.Description, Digest: v.Digest, Document: v.Document, CreatedAt: v.CreatedAt, Deleted: v.Deleted}
}
func (s apiServer) ListCustomSandboxSkills(ctx context.Context, req api.ListCustomSandboxSkillsRequestObject) (api.ListCustomSandboxSkillsResponseObject, error) {
	actor, repo, err := s.customSkillActor(ctx, req.OrgId, rbac.PermSandboxView)
	if err != nil {
		return nil, err
	}
	items, err := repo.CustomSkills(ctx, req.OrgId, actor)
	if err != nil {
		return nil, sandboxError(err)
	}
	body := api.SandboxCustomSkillList{Items: []api.SandboxCustomSkill{}}
	for _, item := range items {
		body.Items = append(body.Items, customSkillResponse(item))
	}
	return api.ListCustomSandboxSkills200JSONResponse{Body: body, Headers: api.ListCustomSandboxSkills200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) CreateCustomSandboxSkill(ctx context.Context, req api.CreateCustomSandboxSkillRequestObject) (api.CreateCustomSandboxSkillResponseObject, error) {
	actor, repo, err := s.customSkillActor(ctx, req.OrgId, rbac.PermSandboxManage)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_skill_document", "SKILL.md document is required")
	}
	item, _, err := repo.CreateCustomSkill(ctx, req.OrgId, actor, req.Body.Document, req.Params.IdempotencyKey)
	if err != nil {
		return nil, sandboxError(err)
	}
	return api.CreateCustomSandboxSkill201JSONResponse{Body: customSkillResponse(item), Headers: api.CreateCustomSandboxSkill201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) GetCustomSandboxSkill(ctx context.Context, req api.GetCustomSandboxSkillRequestObject) (api.GetCustomSandboxSkillResponseObject, error) {
	actor, repo, err := s.customSkillActor(ctx, req.OrgId, rbac.PermSandboxView)
	if err != nil {
		return nil, err
	}
	item, err := repo.GetCustomSkill(ctx, req.OrgId, actor, req.SkillId)
	if err != nil {
		return nil, sandboxError(err)
	}
	return api.GetCustomSandboxSkill200JSONResponse{Body: customSkillResponse(item), Headers: api.GetCustomSandboxSkill200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) EditCustomSandboxSkill(ctx context.Context, req api.EditCustomSandboxSkillRequestObject) (api.EditCustomSandboxSkillResponseObject, error) {
	actor, repo, err := s.customSkillActor(ctx, req.OrgId, rbac.PermSandboxManage)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_skill_document", "document and generation are required")
	}
	item, err := repo.EditCustomSkill(ctx, req.OrgId, actor, req.SkillId, req.Body.Generation, req.Body.Document)
	if err != nil {
		return nil, sandboxError(err)
	}
	return api.EditCustomSandboxSkill200JSONResponse{Body: customSkillResponse(item), Headers: api.EditCustomSandboxSkill200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) DeleteCustomSandboxSkill(ctx context.Context, req api.DeleteCustomSandboxSkillRequestObject) (api.DeleteCustomSandboxSkillResponseObject, error) {
	actor, repo, err := s.customSkillActor(ctx, req.OrgId, rbac.PermSandboxManage)
	if err != nil {
		return nil, err
	}
	if err = repo.DeleteCustomSkill(ctx, req.OrgId, actor, req.SkillId, req.Params.Generation); err != nil {
		return nil, sandboxError(err)
	}
	if s.sandboxWake != nil {
		s.sandboxWake()
	}
	return api.DeleteCustomSandboxSkill204Response{Headers: api.DeleteCustomSandboxSkill204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

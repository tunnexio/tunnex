package http

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	k8ssvc "github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s/scopeapproval"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) k8sClusterScopesEntitled() bool {
	return licence.Has(s.licence.Evaluate(time.Now()).Tier, licence.FeatK8sClusterScopes)
}

func requireK8sClusterScopesEntitled(entitled bool) error {
	if entitled {
		return nil
	}
	return apierr.New(http.StatusForbidden, "edition_required", "Kubernetes cluster scopes require an entitled licence")
}

func (s apiServer) GetK8sClusterScopeSettings(ctx context.Context, req api.GetK8sClusterScopeSettingsRequestObject) (api.GetK8sClusterScopeSettingsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sScopeView); err != nil {
		return nil, err
	}
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyView); err != nil {
		return nil, err
	}
	entitled := s.k8sClusterScopesEntitled()
	setting, err := s.k8s.GetClusterScopeSetting(ctx, req.OrgId, entitled)
	if err != nil {
		return nil, err
	}
	return api.GetK8sClusterScopeSettings200JSONResponse{Body: toAPIK8sClusterScopeSettings(setting), Headers: api.GetK8sClusterScopeSettings200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) SetK8sClusterScopeSettings(ctx context.Context, req api.SetK8sClusterScopeSettingsRequestObject) (api.SetK8sClusterScopeSettingsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sScopeManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "a request body is required")
	}
	actor, _ := authctx.PrincipalFrom(ctx)
	_, _, cause := auditActor(ctx)
	setting, err := s.k8s.SetClusterScopeSetting(ctx, req.OrgId, actor, s.k8sClusterScopesEntitled(), req.Body.Enabled, req.Body.ExpectedRevision, cause)
	if err != nil {
		return nil, err
	}
	return api.SetK8sClusterScopeSettings200JSONResponse{Body: toAPIK8sClusterScopeSettings(setting), Headers: api.SetK8sClusterScopeSettings200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ListK8sClusterScopes(ctx context.Context, req api.ListK8sClusterScopesRequestObject) (api.ListK8sClusterScopesResponseObject, error) {
	if err := s.authorizeK8sClusterScopeRead(ctx, req.OrgId); err != nil {
		return nil, err
	}
	items, err := s.k8s.ListClusterScopes(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.K8sClusterScope, len(items))
	for i := range items {
		out[i] = toAPIK8sClusterScope(items[i])
	}
	return api.ListK8sClusterScopes200JSONResponse{Body: out, Headers: api.ListK8sClusterScopes200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) CreateK8sClusterScope(ctx context.Context, req api.CreateK8sClusterScopeRequestObject) (api.CreateK8sClusterScopeResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sScopeManage); err != nil {
		return nil, err
	}
	if _, err := authorize(ctx, req.OrgId, rbac.PermPolicyManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "a request body is required")
	}
	entitled := s.k8sClusterScopesEntitled()
	if err := requireK8sClusterScopesEntitled(entitled); err != nil {
		return nil, err
	}
	actor, _ := authctx.PrincipalFrom(ctx)
	_, _, cause := auditActor(ctx)
	source := k8ssvc.ClusterScopeSource{Kind: string(req.Body.Source.Kind)}
	if req.Body.Source.Id != nil {
		source.ID = uuid.UUID(*req.Body.Source.Id)
	}
	if req.Body.Source.Cidr != nil {
		source.CIDR = *req.Body.Source.Cidr
	}
	children := make([]uuid.UUID, len(req.Body.InitialServiceChildIds))
	for i := range req.Body.InitialServiceChildIds {
		children[i] = uuid.UUID(req.Body.InitialServiceChildIds[i])
	}
	item, err := s.k8s.CreateClusterScope(ctx, k8ssvc.CreateClusterScopeInput{
		OrgID: req.OrgId, ClusterID: req.Body.ClusterId, Source: source, InitialChildIDs: children,
		ExpiresAt: req.Body.ExpiresAt, Actor: actor, EntitlementUnlocked: entitled, Cause: cause,
	})
	if err != nil {
		return nil, err
	}
	return api.CreateK8sClusterScope201JSONResponse{Body: toAPIK8sClusterScope(item), Headers: api.CreateK8sClusterScope201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) GetK8sClusterScope(ctx context.Context, req api.GetK8sClusterScopeRequestObject) (api.GetK8sClusterScopeResponseObject, error) {
	if err := s.authorizeK8sClusterScopeRead(ctx, req.OrgId); err != nil {
		return nil, err
	}
	item, err := s.k8s.GetClusterScope(ctx, req.OrgId, req.RuleId)
	if err != nil {
		return nil, err
	}
	return api.GetK8sClusterScope200JSONResponse{Body: toAPIK8sClusterScope(item), Headers: api.GetK8sClusterScope200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) SetK8sClusterScopeActive(ctx context.Context, req api.SetK8sClusterScopeActiveRequestObject) (api.SetK8sClusterScopeActiveResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sScopeManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "a request body is required")
	}
	actor, _ := authctx.PrincipalFrom(ctx)
	_, _, cause := auditActor(ctx)
	item, err := s.k8s.SetClusterScopeActive(ctx, req.OrgId, req.RuleId, actor, s.k8sClusterScopesEntitled(), req.Body.Active, req.Body.ExpectedRevision, cause)
	if err != nil {
		return nil, err
	}
	return api.SetK8sClusterScopeActive200JSONResponse{Body: toAPIK8sClusterScope(item), Headers: api.SetK8sClusterScopeActive200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) DeleteK8sClusterScope(ctx context.Context, req api.DeleteK8sClusterScopeRequestObject) (api.DeleteK8sClusterScopeResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sScopeManage); err != nil {
		return nil, err
	}
	actor, _ := authctx.PrincipalFrom(ctx)
	_, _, cause := auditActor(ctx)
	if err := s.k8s.DeleteClusterScope(ctx, req.OrgId, req.RuleId, actor, req.Params.ExpectedRevision, cause); err != nil {
		return nil, err
	}
	return api.DeleteK8sClusterScope204Response{}, nil
}

func (s apiServer) ListK8sClusterScopeInitialCandidates(ctx context.Context, req api.ListK8sClusterScopeInitialCandidatesRequestObject) (api.ListK8sClusterScopeInitialCandidatesResponseObject, error) {
	if err := s.authorizeK8sClusterScopeRead(ctx, req.OrgId); err != nil {
		return nil, err
	}
	page, err := s.k8s.ListClusterScopeCandidates(ctx, req.OrgId, req.RuleId, s.k8sClusterScopesEntitled(), stringValue(req.Params.Cursor), intValue(req.Params.Limit))
	if err != nil {
		return nil, err
	}
	return api.ListK8sClusterScopeInitialCandidates200JSONResponse{Body: toAPIK8sClusterScopeCandidatePage(page), Headers: api.ListK8sClusterScopeInitialCandidates200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ListK8sClusterScopeMemberships(ctx context.Context, req api.ListK8sClusterScopeMembershipsRequestObject) (api.ListK8sClusterScopeMembershipsResponseObject, error) {
	if err := s.authorizeK8sClusterScopeRead(ctx, req.OrgId); err != nil {
		return nil, err
	}
	page, err := s.k8s.ListClusterScopeMemberships(ctx, req.OrgId, req.RuleId, s.k8sClusterScopesEntitled(), stringValue(req.Params.Cursor), intValue(req.Params.Limit))
	if err != nil {
		return nil, err
	}
	return api.ListK8sClusterScopeMemberships200JSONResponse{Body: toAPIK8sClusterScopeMembershipPage(page.Items, page.NextCursor), Headers: api.ListK8sClusterScopeMemberships200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ListK8sClusterScopeReviewQueue(ctx context.Context, req api.ListK8sClusterScopeReviewQueueRequestObject) (api.ListK8sClusterScopeReviewQueueResponseObject, error) {
	if err := s.authorizeK8sClusterScopeRead(ctx, req.OrgId); err != nil {
		return nil, err
	}
	page, err := s.k8s.ListClusterScopeReviewQueue(ctx, req.OrgId, s.k8sClusterScopesEntitled(), stringValue(req.Params.Cursor), intValue(req.Params.Limit))
	if err != nil {
		return nil, err
	}
	return api.ListK8sClusterScopeReviewQueue200JSONResponse{Body: toAPIK8sClusterScopeMembershipPage(page.Items, page.NextCursor), Headers: api.ListK8sClusterScopeReviewQueue200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) DecideK8sClusterScopeMembership(ctx context.Context, req api.DecideK8sClusterScopeMembershipRequestObject) (api.DecideK8sClusterScopeMembershipResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sScopeApprove); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "a request body is required")
	}
	entitled := s.k8sClusterScopesEntitled()
	if err := requireK8sClusterScopesEntitled(entitled); err != nil {
		return nil, err
	}
	actor, _ := authctx.PrincipalFrom(ctx)
	_, _, cause := auditActor(ctx)
	item, _, err := s.k8s.DecideClusterScopeMembership(ctx, req.OrgId, req.RuleId, req.ServiceChildId, actor, entitled, scopeapproval.Status(req.Body.Decision), cause)
	if err != nil {
		return nil, err
	}
	return api.DecideK8sClusterScopeMembership200JSONResponse{Body: toAPIK8sClusterScopeMembership(item), Headers: api.DecideK8sClusterScopeMembership200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ListK8sClusterInventory(ctx context.Context, req api.ListK8sClusterInventoryRequestObject) (api.ListK8sClusterInventoryResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	page, err := s.k8s.ListClusterScopeInventory(ctx, req.OrgId, req.ClusterId, stringValue(req.Params.Cursor), intValue(req.Params.Limit))
	if err != nil {
		return nil, err
	}
	return api.ListK8sClusterInventory200JSONResponse{Body: toAPIK8sInventoryPage(page), Headers: api.ListK8sClusterInventory200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ExposeK8sInventoryService(ctx context.Context, req api.ExposeK8sInventoryServiceRequestObject) (api.ExposeK8sInventoryServiceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "a request body is required")
	}
	actor, _ := authctx.PrincipalFrom(ctx)
	_, _, cause := auditActor(ctx)
	ports := make([]uuid.UUID, len(req.Body.PortRefs))
	for i := range req.Body.PortRefs {
		ports[i] = uuid.UUID(req.Body.PortRefs[i])
	}
	result, err := s.k8s.ExposeInventoryService(ctx, k8ssvc.ExposeInventoryServiceInput{OrgID: req.OrgId, ClusterID: req.ClusterId, InventoryRef: req.InventoryRef, PortRefs: ports, Actor: actor, Cause: cause})
	if err != nil {
		return nil, err
	}
	return api.ExposeK8sInventoryService201JSONResponse{Body: api.ExposeK8sInventoryServiceResult{ServiceChildIds: result.ServiceChildIDs, PendingReviewCount: result.PendingRows}, Headers: api.ExposeK8sInventoryService201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) authorizeK8sClusterScopeRead(ctx context.Context, orgID uuid.UUID) error {
	if _, err := authorize(ctx, orgID, rbac.PermK8sScopeView); err != nil {
		return err
	}
	if _, err := authorize(ctx, orgID, rbac.PermPolicyView); err != nil {
		return err
	}
	return nil
}

func toAPIK8sClusterScopeSettings(in k8ssvc.ClusterScopeSetting) api.K8sClusterScopeSettings {
	return api.K8sClusterScopeSettings{Enabled: in.Enabled, Revision: in.Revision, EntitlementUnlocked: in.EntitlementUnlocked, Effective: in.Effective, UpdatedAt: in.UpdatedAt}
}

func toAPIK8sClusterScope(in k8ssvc.ClusterScopeRecord) api.K8sClusterScope {
	source := api.K8sClusterScopeSource{Kind: api.K8sClusterScopeSourceKind(in.Source.Kind)}
	if in.Source.ID != uuid.Nil {
		id := in.Source.ID
		source.Id = &id
	}
	if in.Source.CIDR != "" {
		cidr := in.Source.CIDR
		source.Cidr = &cidr
	}
	return api.K8sClusterScope{RuleId: in.RuleID, ClusterId: in.ClusterID, Source: source, Active: in.Active, Revision: in.Revision, InitialCandidateCount: in.InitialCandidateCount, CreatedByUserId: in.CreatedByUserID, ExpiresAt: in.ExpiresAt, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt}
}

func toAPIK8sClusterScopeCandidatePage(in k8ssvc.ClusterScopeCandidatePage) api.K8sClusterScopeCandidatePage {
	out := api.K8sClusterScopeCandidatePage{Items: make([]api.K8sClusterScopeCandidate, len(in.Items)), NextCursor: optionalString(in.NextCursor)}
	for i, item := range in.Items {
		out.Items[i] = api.K8sClusterScopeCandidate{ServiceChildId: item.ChildID, Namespace: item.Namespace, Service: item.Service, Protocol: api.K8sClusterScopeCandidateProtocol(item.Protocol), Port: int(item.ServicePort), Selected: item.Selected, Current: item.Current, Effective: item.Effective, InactiveReason: optionalK8sClusterScopeInactiveReason(item.InactiveReason)}
	}
	return out
}

func toAPIK8sClusterScopeMembershipPage(items []k8ssvc.ClusterScopeMembershipView, cursor string) api.K8sClusterScopeMembershipPage {
	out := api.K8sClusterScopeMembershipPage{Items: make([]api.K8sClusterScopeMembership, len(items)), NextCursor: optionalString(cursor)}
	for i := range items {
		out.Items[i] = toAPIK8sClusterScopeMembership(items[i])
	}
	return out
}

func toAPIK8sClusterScopeMembership(in k8ssvc.ClusterScopeMembershipView) api.K8sClusterScopeMembership {
	return api.K8sClusterScopeMembership{RuleId: in.RuleID, ClusterId: in.ClusterID, ServiceChildId: in.ChildID, Namespace: in.Namespace, Service: in.Service, Protocol: api.K8sClusterScopeMembershipProtocol(in.Protocol), Port: int(in.ServicePort), Origin: api.K8sClusterScopeMembershipOrigin(in.Origin), Status: api.K8sClusterScopeMembershipStatus(in.Status), Current: in.Current, Effective: in.Effective, InactiveReason: optionalK8sClusterScopeInactiveReason(in.InactiveReason), DecidedByUserId: in.DecidedByUserID, DecidedAt: in.DecidedAt, CreatedAt: in.CreatedAt}
}

func optionalK8sClusterScopeInactiveReason(value string) *api.K8sClusterScopeInactiveReason {
	if value == "" {
		return nil
	}
	reason := api.K8sClusterScopeInactiveReason(value)
	return &reason
}

func toAPIK8sInventoryPage(in k8ssvc.ClusterScopeInventoryPage) api.K8sInventoryPage {
	out := api.K8sInventoryPage{Items: make([]api.K8sInventoryService, len(in.Items)), NextCursor: optionalString(in.NextCursor), ObservedAt: in.ObservedAt, FreshUntil: in.FreshUntil}
	for i, item := range in.Items {
		ports := make([]api.K8sInventoryPort, len(item.Ports))
		for j, port := range item.Ports {
			ports[j] = api.K8sInventoryPort{PortRef: port.PortRef, Name: port.Name, Protocol: api.K8sInventoryPortProtocol(port.Protocol), ServicePort: int(port.ServicePort)}
		}
		out.Items[i] = api.K8sInventoryService{InventoryRef: item.InventoryRef, Namespace: item.Namespace, Service: item.Service, Ports: ports}
	}
	return out
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func intValue(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

package http

import (
	"context"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	k8ssvc "github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// K8N-3 stage 1: a cluster's Kubernetes API as a named destination (docs/K8N-3-kubectl-access.md).
// Reading the state is org:view, like the cluster it belongs to. Turning it on or off is k8s_api:manage,
// a permission of its own (never k8s:manage), and needs a signed-in human: the machine operator role does
// not hold it. Nothing here returns, accepts or stores a cluster credential.

func toAPIK8sApiAccess(a k8ssvc.APIAccess) api.K8sApiAccess {
	out := api.K8sApiAccess{
		ClusterId: a.ClusterID, Enabled: a.Enabled, Fqdn: a.FQDN, Port: a.Port,
		RuleCount: a.RuleCount, OrdinaryExposure: a.OrdinaryExposure, EnabledAt: a.EnabledAt,
	}
	if a.VIP != "" {
		vip := a.VIP
		out.Vip = &vip
	}
	return out
}

func (s apiServer) GetK8sClusterApiAccess(ctx context.Context, req api.GetK8sClusterApiAccessRequestObject) (api.GetK8sClusterApiAccessResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	access, err := s.k8s.GetAPIAccess(ctx, req.OrgId, req.ClusterId)
	if err != nil {
		return nil, err
	}
	return api.GetK8sClusterApiAccess200JSONResponse{Body: toAPIK8sApiAccess(access), Headers: api.GetK8sClusterApiAccess200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) SetK8sClusterApiAccess(ctx context.Context, req api.SetK8sClusterApiAccessRequestObject) (api.SetK8sClusterApiAccessResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermK8sAPIManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "a request body is required")
	}
	actor, _ := authctx.PrincipalFrom(ctx)
	access, err := s.k8s.SetAPIAccess(ctx, req.OrgId, req.ClusterId, req.Body.Enabled, actor)
	if err != nil {
		return nil, err
	}
	return api.SetK8sClusterApiAccess200JSONResponse{Body: toAPIK8sApiAccess(access), Headers: api.SetK8sClusterApiAccess200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// k8sAPIRuleTarget is what a rule list says about a rule whose destination is a cluster's API.
type k8sAPIRuleTarget struct {
	clusterID uuid.UUID
	off       bool
}

// k8sAPIRuleTargets resolves, for the rules whose destination is a cluster's Kubernetes API, which
// cluster that is and whether its API access is currently off (the rule is kept and allows nothing).
// It reads nothing when no rule has that kind.
func (s apiServer) k8sAPIRuleTargets(ctx context.Context, orgID uuid.UUID, rules []sqlc.PolicyRule) (map[uuid.UUID]k8sAPIRuleTarget, error) {
	out := map[uuid.UUID]k8sAPIRuleTarget{}
	any := false
	for _, rule := range rules {
		if rule.DstKind == "k8s_api" {
			any = true
			break
		}
	}
	if !any || s.k8s == nil {
		return out, nil
	}
	endpoints, err := s.k8s.APIEndpointsForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	byID := make(map[uuid.UUID]k8ssvc.APIEndpointRef, len(endpoints))
	for _, endpoint := range endpoints {
		byID[endpoint.EndpointID] = endpoint
	}
	for _, rule := range rules {
		if rule.DstKind != "k8s_api" || !rule.DstK8sApiEndpointID.Valid {
			continue
		}
		if endpoint, ok := byID[uuid.UUID(rule.DstK8sApiEndpointID.Bytes)]; ok {
			out[rule.ID] = k8sAPIRuleTarget{clusterID: endpoint.ClusterID, off: !endpoint.Enabled}
		}
	}
	return out, nil
}

// withK8sAPITarget writes the Kubernetes API destination onto a rule's API form.
func withK8sAPITarget(rule api.PolicyRule, target k8sAPIRuleTarget, ok bool) api.PolicyRule {
	if !ok {
		return rule
	}
	clusterID, off := target.clusterID, target.off
	rule.DstK8sApiClusterId = &clusterID
	rule.DstK8sApiAccessOff = &off
	return rule
}

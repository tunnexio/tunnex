package http

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	k8ssvc "github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type clusterScopePolicyStub struct {
	policyPort
	rules       []sqlc.PolicyRule
	deleteCalls int
	extendCalls int
	toggleCalls int
}

func (s *clusterScopePolicyStub) ListPolicyRules(context.Context, uuid.UUID) ([]sqlc.PolicyRule, error) {
	return append([]sqlc.PolicyRule(nil), s.rules...), nil
}

func (s *clusterScopePolicyStub) PolicyRuleCidrWarnings(context.Context, uuid.UUID, []sqlc.PolicyRule) (map[uuid.UUID]bool, error) {
	return map[uuid.UUID]bool{}, nil
}

func (s *clusterScopePolicyStub) AgentTemplateManagedRuleIDs(context.Context, uuid.UUID) (map[uuid.UUID]bool, error) {
	return map[uuid.UUID]bool{}, nil
}

func (s *clusterScopePolicyStub) AgentAccessManagedRules(context.Context, uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	return map[uuid.UUID]uuid.UUID{}, nil
}

func (s *clusterScopePolicyStub) DeletePolicyRule(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, string) error {
	s.deleteCalls++
	return nil
}

func (s *clusterScopePolicyStub) ExtendGrant(_ context.Context, _, ruleID uuid.UUID, _ time.Time) (sqlc.PolicyRule, error) {
	s.extendCalls++
	return s.rule(ruleID), nil
}

func (s *clusterScopePolicyStub) SetPolicyRuleEnabled(_ context.Context, _, ruleID uuid.UUID, enabled bool) (sqlc.PolicyRule, error) {
	s.toggleCalls++
	rule := s.rule(ruleID)
	rule.Disabled = !enabled
	return rule, nil
}

func (s *clusterScopePolicyStub) rule(ruleID uuid.UUID) sqlc.PolicyRule {
	for _, rule := range s.rules {
		if rule.ID == ruleID {
			return rule
		}
	}
	return sqlc.PolicyRule{}
}

func TestGenericPolicyMutationsCannotBypassClusterScopeBoundary(t *testing.T) {
	orgID, ruleID := uuid.New(), uuid.New()
	expiresAt := time.Now().Add(time.Hour)
	operations := []struct {
		name   string
		invoke func(apiServer, context.Context) error
		calls  func(*clusterScopePolicyStub) int
	}{
		{
			name: "delete",
			invoke: func(server apiServer, ctx context.Context) error {
				_, err := server.DeletePolicyRule(ctx, api.DeletePolicyRuleRequestObject{OrgId: orgID, RuleId: ruleID})
				return err
			},
			calls: func(stub *clusterScopePolicyStub) int { return stub.deleteCalls },
		},
		{
			name: "extend",
			invoke: func(server apiServer, ctx context.Context) error {
				_, err := server.ExtendGrant(ctx, api.ExtendGrantRequestObject{OrgId: orgID, RuleId: ruleID, Body: &api.ExtendGrantJSONRequestBody{ExpiresAt: expiresAt}})
				return err
			},
			calls: func(stub *clusterScopePolicyStub) int { return stub.extendCalls },
		},
		{
			name: "toggle",
			invoke: func(server apiServer, ctx context.Context) error {
				_, err := server.SetPolicyRuleEnabled(ctx, api.SetPolicyRuleEnabledRequestObject{OrgId: orgID, RuleId: ruleID, Body: &api.SetPolicyRuleEnabledJSONRequestBody{Enabled: false}})
				return err
			},
			calls: func(stub *clusterScopePolicyStub) int { return stub.toggleCalls },
		},
	}

	operator := authctx.WithPrincipal(context.Background(), authctx.NewMachinePrincipal(uuid.New(), uuid.New(), orgID, "gitops", rbac.RoleOperator, "test"))
	machineAdmin := authctx.WithPrincipal(context.Background(), authctx.NewMachinePrincipal(uuid.New(), uuid.New(), orgID, "overprivileged", rbac.RoleAdmin, "test"))
	unverifiedOwner := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{orgID: rbac.RoleOwner}})
	humanOwner := principalWithRole(orgID, rbac.RoleOwner)

	for _, operation := range operations {
		t.Run(operation.name+"_requires_named_permission", func(t *testing.T) {
			stub := &clusterScopePolicyStub{rules: []sqlc.PolicyRule{{ID: ruleID, OrgID: orgID, SrcKind: "user", DstKind: "k8s_cluster_scope"}}}
			err := operation.invoke(apiServer{policy: stub}, operator)
			if !hasCode(err, 403, "forbidden") {
				t.Fatalf("operator with policy:manage but without k8s_scope:manage: want 403 forbidden, got %v", err)
			}
			if got := operation.calls(stub); got != 0 {
				t.Fatalf("mutation crossed named permission boundary: calls=%d", got)
			}
		})

		t.Run(operation.name+"_requires_human", func(t *testing.T) {
			stub := &clusterScopePolicyStub{rules: []sqlc.PolicyRule{{ID: ruleID, OrgID: orgID, SrcKind: "user", DstKind: "k8s_cluster_scope"}}}
			err := operation.invoke(apiServer{policy: stub}, machineAdmin)
			if !hasCode(err, 403, "human_actor_required") {
				t.Fatalf("machine with both permissions: want 403 human_actor_required, got %v", err)
			}
			if got := operation.calls(stub); got != 0 {
				t.Fatalf("machine crossed human boundary: calls=%d", got)
			}
		})

		t.Run(operation.name+"_requires_verified_human", func(t *testing.T) {
			stub := &clusterScopePolicyStub{rules: []sqlc.PolicyRule{{ID: ruleID, OrgID: orgID, SrcKind: "user", DstKind: "k8s_cluster_scope"}}}
			err := operation.invoke(apiServer{policy: stub}, unverifiedOwner)
			if !hasCode(err, 403, "email_not_verified") {
				t.Fatalf("unverified human owner: want 403 email_not_verified, got %v", err)
			}
			if got := operation.calls(stub); got != 0 {
				t.Fatalf("unverified human crossed verification boundary: calls=%d", got)
			}
		})

		t.Run(operation.name+"_requires_dedicated_scope_api", func(t *testing.T) {
			stub := &clusterScopePolicyStub{rules: []sqlc.PolicyRule{{ID: ruleID, OrgID: orgID, SrcKind: "user", DstKind: "k8s_cluster_scope"}}}
			err := operation.invoke(apiServer{policy: stub}, humanOwner)
			if !hasCode(err, 409, "cluster_scope_dedicated_api_required") {
				t.Fatalf("verified human owner: want 409 cluster_scope_dedicated_api_required, got %v", err)
			}
			if got := operation.calls(stub); got != 0 {
				t.Fatalf("generic mutation crossed dedicated scope boundary: calls=%d", got)
			}
		})
	}
}

func TestGenericPolicyListNeverSurfacesClusterScopes(t *testing.T) {
	orgID := uuid.New()
	ordinaryID, scopeID := uuid.New(), uuid.New()
	stub := &clusterScopePolicyStub{rules: []sqlc.PolicyRule{
		{ID: ordinaryID, OrgID: orgID, SrcKind: "user", DstKind: "resource"},
		{ID: scopeID, OrgID: orgID, SrcKind: "user", DstKind: "k8s_cluster_scope"},
	}}
	server := apiServer{policy: stub}

	operator := authctx.WithPrincipal(context.Background(), authctx.NewMachinePrincipal(uuid.New(), uuid.New(), orgID, "gitops", rbac.RoleOperator, "test"))
	response, err := server.ListPolicyRules(operator, api.ListPolicyRulesRequestObject{OrgId: orgID})
	if err != nil {
		t.Fatal(err)
	}
	operatorBody := response.(api.ListPolicyRules200JSONResponse).Body
	if len(operatorBody) != 1 || operatorBody[0].Id != ordinaryID {
		t.Fatalf("policy:view without k8s_scope:view leaked scope row: %#v", operatorBody)
	}

	response, err = server.ListPolicyRules(principalWithRole(orgID, rbac.RoleOwner), api.ListPolicyRulesRequestObject{OrgId: orgID})
	if err != nil {
		t.Fatal(err)
	}
	ownerBody := response.(api.ListPolicyRules200JSONResponse).Body
	if len(ownerBody) != 1 || ownerBody[0].Id != ordinaryID {
		t.Fatalf("named scope viewer received a dedicated scope row from generic policy list: %#v", ownerBody)
	}
}

func TestClusterScopeRecoveryReadsHaveNoEntitlementRefusal(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "k8s_scope_handlers.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	reads := map[string]bool{
		"GetK8sClusterScopeSettings":           false,
		"ListK8sClusterScopes":                 false,
		"GetK8sClusterScope":                   false,
		"ListK8sClusterScopeInitialCandidates": false,
		"ListK8sClusterScopeMemberships":       false,
		"ListK8sClusterScopeReviewQueue":       false,
		"authorizeK8sClusterScopeRead":         false,
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, ok := reads[function.Name.Name]; !ok {
			continue
		}
		reads[function.Name.Name] = true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			identifier, ok := call.Fun.(*ast.Ident)
			if ok && identifier.Name == "requireK8sClusterScopesEntitled" {
				t.Errorf("%s gates a recovery read on entitlement", function.Name.Name)
			}
			return true
		})
	}
	for function, found := range reads {
		if !found {
			t.Errorf("recovery read function %s was not inspected", function)
		}
	}

	got := toAPIK8sClusterScopeSettings(k8ssvc.ClusterScopeSetting{Enabled: true, EntitlementUnlocked: false, Effective: false})
	if !got.Enabled || got.EntitlementUnlocked || got.Effective {
		t.Fatalf("licence-loss projection must preserve desired=true and report unlocked/effective=false: %#v", got)
	}
}

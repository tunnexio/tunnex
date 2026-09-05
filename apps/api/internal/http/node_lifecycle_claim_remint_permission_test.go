package http

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestRemintNodeLifecycleClaimRequiresCredentialMintPermissionBeforeInput(t *testing.T) {
	orgID := uuid.New()
	operator := authctx.NewMachinePrincipal(
		uuid.New(), uuid.New(), orgID, "gitops", rbac.RoleOperator, "tunnexcluster:default/prod",
	)
	if operator == nil {
		t.Fatal("machine principal fixture was not created")
	}
	operatorContext := authctx.WithPrincipal(context.Background(), operator)

	requests := []api.RemintNodeLifecycleClaimRequestObject{
		{OrgId: orgID, Claim: uuid.New()},
		{
			OrgId: orgID,
			Claim: uuid.New(),
			Body: &api.NodeLifecycleClaimRemintRequest{
				ExpectedGeneration: -1,
				NodeName:           "invalid",
				RequestId:          uuid.New(),
			},
		},
	}
	var firstRefusal string
	for _, request := range requests {
		response, err := (apiServer{}).RemintNodeLifecycleClaim(operatorContext, request)
		if response != nil {
			t.Fatalf("operator remint returned a response: %#v", response)
		}
		if !hasCode(err, 403, "forbidden") {
			t.Fatalf("operator remint refusal = %v, want 403 forbidden", err)
		}
		if firstRefusal == "" {
			firstRefusal = err.Error()
		} else if err.Error() != firstRefusal {
			t.Fatalf("operator remint leaked input shape: first=%q second=%q", firstRefusal, err)
		}
	}

	for _, role := range []string{rbac.RoleOwner, rbac.RoleAdmin} {
		response, err := (apiServer{}).RemintNodeLifecycleClaim(
			principalWithRole(orgID, role),
			api.RemintNodeLifecycleClaimRequestObject{OrgId: orgID, Claim: uuid.New()},
		)
		if response != nil {
			t.Fatalf("%s remint with no body returned a response: %#v", role, response)
		}
		if !hasCode(err, 400, "invalid_request") {
			t.Fatalf("%s did not pass both remint permission gates: %v", role, err)
		}
	}
}

func TestRemintNodeLifecycleClaimPermissionIntersectionPrecedesInputInSource(t *testing.T) {
	source, err := os.ReadFile("node_lifecycle_claim_handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := funcBody(string(source), "func (s apiServer) RemintNodeLifecycleClaim(")
	if body == "" {
		t.Fatal("could not find RemintNodeLifecycleClaim; permission guard is no longer guarding a route")
	}
	k8sGate := strings.Index(body, "rbac.PermK8sManage")
	credentialGate := strings.Index(body, "rbac.PermOrgUpdate")
	inputValidation := strings.Index(body, "if req.Body == nil")
	if k8sGate < 0 || credentialGate < 0 || inputValidation < 0 {
		t.Fatalf("remint source lost a required gate or the guarded input seam")
	}
	if !(k8sGate < credentialGate && credentialGate < inputValidation) {
		t.Fatalf("remint permission order changed: k8s=%d credential=%d input=%d", k8sGate, credentialGate, inputValidation)
	}
}

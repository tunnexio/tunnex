package http

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// TestAuthorizeExemptsMachineFromEmailVerification — S10.2 C1 (the artifact-works probe at the AUTHZ tier).
// A machine principal has EmailVerified=false by construction (no email); WITHOUT the IsMachine() exemption in
// authorize(), every operator mutation 403s email_not_verified and the operator is dead on its first real
// call. This red drives a machine principal THROUGH authorize() — the gate EVERY http mutation traverses — not
// through the service it calls (a service-level red would skip authorize() and reproduce the exact hole that
// Slice 1's svc.RegisterCluster reds missed). Probe rule: a new principal kind must be exercised through every
// GATE a request crosses, not only the service it lands in.
func TestAuthorizeExemptsMachineFromEmailVerification(t *testing.T) {
	org := uuid.New()

	// A machine (operator role, no verified email) must PASS the k8s:manage mutation gate.
	machine := &authctx.Principal{
		MachineID: uuid.New(), MachineName: "gitops",
		AuthMethod: authctx.AuthMachine,
		Roles:      map[uuid.UUID]string{org: rbac.RoleOperator},
	}
	if _, err := authorize(authctx.WithPrincipal(context.Background(), machine), org, rbac.PermK8sManage); err != nil {
		t.Fatalf("a machine principal must pass a mutating gate (no email to verify), got %v", err)
	}

	// A HUMAN with an unverified email is still refused — the gate is intact for people.
	human := &authctx.Principal{
		UserID: uuid.New(), EmailVerified: false,
		AuthMethod: authctx.AuthLocalPassword,
		Roles:      map[uuid.UUID]string{org: rbac.RoleAdmin},
	}
	_, err := authorize(authctx.WithPrincipal(context.Background(), human), org, rbac.PermK8sManage)
	if ae, ok := err.(*apierr.Error); !ok || ae.Code != "email_not_verified" {
		t.Fatalf("an unverified human must still be refused email_not_verified, got %v", err)
	}
}

package http

import (
	"context"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestNodeLifecycleClaimAnonymousValidationIsNoOracle(t *testing.T) {
	next := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusTeapot)
	})
	handler := authBeforeAgentValidation(next)
	paths := []string{
		"/api/v1/organizations/not-a-uuid/nodes/lifecycle-claims/not-a-uuid/remint",
		"/api/v1/organizations/11111111-1111-1111-1111-111111111111/nodes/lifecycle-claims/22222222-2222-2222-2222-222222222222/remint",
	}
	var first string
	for _, path := range paths {
		req := httptest.NewRequest(stdhttp.MethodPost, path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		body, err := io.ReadAll(rr.Result().Body)
		if err != nil {
			t.Fatal(err)
		}
		if rr.Code != stdhttp.StatusUnauthorized {
			t.Fatalf("anonymous lifecycle request %q status=%d body=%s", path, rr.Code, body)
		}
		if first == "" {
			first = string(body)
		} else if string(body) != first {
			t.Fatalf("malformed and well-formed anonymous requests differ:\n%s\n%s", first, body)
		}
	}
}

func TestNodeLifecycleClaimRequiresK8sManage(t *testing.T) {
	org := uuid.New()
	member := &authctx.Principal{
		UserID: uuid.New(), EmailVerified: true, AuthMethod: authctx.AuthLocalPassword,
		Roles: map[uuid.UUID]string{org: rbac.RoleMember},
	}
	if _, err := authorize(authctx.WithPrincipal(context.Background(), member), org, rbac.PermK8sManage); err == nil {
		t.Fatal("ordinary member reached lifecycle claim operation without k8s:manage")
	} else if apiError, ok := err.(*apierr.Error); !ok || apiError.Code != "forbidden" {
		t.Fatalf("ordinary member error = %v", err)
	}
	operator := &authctx.Principal{
		MachineID: uuid.New(), MachineName: "gitops", AuthMethod: authctx.AuthMachine,
		Roles: map[uuid.UUID]string{org: rbac.RoleOperator},
	}
	if _, err := authorize(authctx.WithPrincipal(context.Background(), operator), org, rbac.PermK8sManage); err != nil {
		t.Fatalf("k8s:manage operator denied lifecycle claim operation: %v", err)
	}
}

func TestCheckedLifecycleGenerationRejectsNarrowingAlias(t *testing.T) {
	for _, test := range []struct {
		value     int
		allowZero bool
		want      int32
		wantErr   bool
	}{
		{value: 0, allowZero: true, want: 0},
		{value: 1, allowZero: false, want: 1},
		{value: 2147483647, allowZero: false, want: 2147483647},
		{value: 2147483648, allowZero: true, wantErr: true},
		{value: 4294967297, allowZero: true, wantErr: true},
	} {
		got, err := checkedLifecycleGeneration(test.value, test.allowZero)
		if test.wantErr {
			if err == nil {
				t.Fatalf("generation %d narrowed to %d", test.value, got)
			}
			continue
		}
		if err != nil || got != test.want {
			t.Fatalf("generation %d = %d, %v", test.value, got, err)
		}
	}
}

func TestLifecycleActorFromHumanAndMachinePrincipal(t *testing.T) {
	humanID := uuid.New()
	human, err := lifecycleActorFromPrincipal(&authctx.Principal{UserID: humanID, AuthMethod: authctx.AuthLocalPassword})
	if err != nil || human.IssuerUserID != humanID || human.AuditUserID != humanID || human.AuditSystem != "" {
		t.Fatalf("human lifecycle actor = %+v, %v", human, err)
	}
	owner, machineID, org := uuid.New(), uuid.New(), uuid.New()
	machinePrincipal := authctx.NewMachinePrincipal(owner, machineID, org, "gitops", rbac.RoleOperator, "tunnexcluster:default/prod")
	machine, err := lifecycleActorFromPrincipal(machinePrincipal)
	if err != nil || machine.IssuerUserID != owner || machine.AuditUserID != uuid.Nil || machine.AuditSystem != "operator:gitops" || machine.Cause != "tunnexcluster:default/prod" {
		t.Fatalf("machine lifecycle actor = %+v, %v", machine, err)
	}
	agent := authctx.NewAgentPrincipal(uuid.New(), org, "agent", rbac.RoleAgent, owner, "")
	if _, err := lifecycleActorFromPrincipal(agent); err == nil {
		t.Fatal("agent principal was accepted as lifecycle operator")
	}
}

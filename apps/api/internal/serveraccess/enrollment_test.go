package serveraccess

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/packages/apptransport/bootstrap"
	"strings"
	"testing"
)

func TestEnrollmentInputRejectsUnsafeProvisioning(t *testing.T) {
	valid := api.ServerAccessEnrollmentInput{ManagementAccount: "ubuntu", ManagementPort: 22, ManagementFingerprint: "SHA256:" + strings.Repeat("A", 43), Accounts: []string{}}
	if e := validateEnrollmentInput(valid); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*api.ServerAccessEnrollmentInput){func(v *api.ServerAccessEnrollmentInput) { v.ManagementAccount = "root" }, func(v *api.ServerAccessEnrollmentInput) { v.ManagementAccount = "ubuntu;id" }, func(v *api.ServerAccessEnrollmentInput) { v.ManagementFingerprint = "SHA256:unverified" }, func(v *api.ServerAccessEnrollmentInput) { v.ManagementPort = 0 }, func(v *api.ServerAccessEnrollmentInput) { v.Accounts = []string{"root"} }, func(v *api.ServerAccessEnrollmentInput) { v.Accounts = []string{"ubuntu", "ubuntu"} }} {
		v := valid
		mutate(&v)
		if validateEnrollmentInput(v) == nil {
			t.Fatalf("unsafe setup accepted: %#v", v)
		}
	}
}
func TestEnrollmentResultBindsIdentityAndAccounts(t *testing.T) {
	j := enrollment{Org: uuid.New(), Accounts: []string{"ubuntu"}, View: api.ServerAccessEnrollment{ServerId: uuid.New()}}
	good := bootstrap.Result{Version: 1, OrgID: j.Org.String(), ServerID: j.View.ServerId.String(), SSHPort: 2222, HostFingerprint: "SHA256:" + strings.Repeat("A", 43), Accounts: []string{"ubuntu"}}
	if e := validateEnrollmentResult(j, &good); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*bootstrap.Result){func(r *bootstrap.Result) { r.ServerID = uuid.NewString() }, func(r *bootstrap.Result) { r.OrgID = uuid.NewString() }, func(r *bootstrap.Result) { r.Accounts = []string{"root"} }, func(r *bootstrap.Result) { r.Accounts = []string{"deploy"} }, func(r *bootstrap.Result) { r.HostFingerprint = "invalid" }} {
		r := good
		change(&r)
		if validateEnrollmentResult(j, &r) == nil {
			t.Fatal("foreign/unsafe result accepted")
		}
	}
}

func TestPendingDiscoveryRemainsDisabledAndUntrusted(t *testing.T) {
	v := validServer()
	v.Accounts = []string{}
	v.SshPort = 2222
	if ValidateServer(v) != nil {
		t.Fatal("disabled pending-discovery registration refused")
	}
	v.Enabled = true
	if ValidateServer(v) == nil {
		t.Fatal("empty server could be enabled")
	}
	v.Enabled = false
	v.HostFingerprint = "SHA256:" + strings.Repeat("B", 43)
	if ValidateServer(v) == nil {
		t.Fatal("verified server accepted empty accounts")
	}
}

func TestOnlineAccountSyncRejectsTrustChangesAndAccountRemoval(t *testing.T) {
	fp := "SHA256:" + strings.Repeat("A", 43)
	port := 2222
	server := api.ServerAccessServer{HostFingerprint: &fp, SshPort: &port, Accounts: []string{"ubuntu"}, Enabled: true, ReadyAccounts: []string{"ubuntu"}, Revision: 7}
	result := bootstrap.Result{HostFingerprint: fp, SSHPort: port, Accounts: []string{"ubuntu", "deploy"}}
	if err := validateAccountSync(server, &result); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*bootstrap.Result){
		func(r *bootstrap.Result) { r.HostFingerprint = "SHA256:" + strings.Repeat("B", 43) },
		func(r *bootstrap.Result) { r.SSHPort = 2223 },
		func(r *bootstrap.Result) { r.Accounts = []string{"deploy"} },
	} {
		r := result
		change(&r)
		if validateAccountSync(server, &r) == nil {
			t.Fatal("destructive or trust-changing sync accepted")
		}
	}
}

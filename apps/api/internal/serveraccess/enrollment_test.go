package serveraccess

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/packages/apptransport/bootstrap"
	"strings"
	"testing"
)

func TestEnrollmentInputRejectsUnsafeProvisioning(t *testing.T) {
	fp := "SHA256:" + strings.Repeat("A", 43)
	valid := api.ServerAccessEnrollmentInput{ManagementAccount: "ubuntu", ManagementPort: 22, ManagementFingerprint: &fp, Accounts: []string{}}
	if e := validateEnrollmentInput(valid); e != nil {
		t.Fatal(e)
	}
	// SA-UX-2: the fingerprint is optional (verified by attestation instead), but a given one must be well formed.
	for _, optional := range []*string{nil, new(string)} {
		v := valid
		v.ManagementFingerprint = optional
		if e := validateEnrollmentInput(v); e != nil {
			t.Fatal(e)
		}
	}
	unverified := "SHA256:unverified"
	for _, mutate := range []func(*api.ServerAccessEnrollmentInput){func(v *api.ServerAccessEnrollmentInput) { v.ManagementAccount = "root" }, func(v *api.ServerAccessEnrollmentInput) { v.ManagementAccount = "ubuntu;id" }, func(v *api.ServerAccessEnrollmentInput) { v.ManagementFingerprint = &unverified }, func(v *api.ServerAccessEnrollmentInput) { v.ManagementPort = 0 }, func(v *api.ServerAccessEnrollmentInput) { v.Accounts = []string{"root"} }, func(v *api.ServerAccessEnrollmentInput) { v.Accounts = []string{"ubuntu", "ubuntu"} }} {
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

// SA-UX-3: a target refusal shows its fixed sentence; anything else falls back without refusing the report.
func TestEnrollmentFailureUsesOnlyAllowListedSetupCodes(t *testing.T) {
	message, code, e := enrollmentFailure(bootstrap.Report{Result: "setup_failed", SetupError: "setup_existing_setup"})
	if e != nil || code != "setup_existing_setup" || message != setupErrorMessages["setup_existing_setup"] || !strings.Contains(message, "tunnex-browser-sshd") {
		t.Fatalf("coded refusal not explained: %q %q %v", message, code, e)
	}
	for _, in := range []bootstrap.Report{{Result: "setup_failed"}, {Result: "setup_failed", SetupError: "setup_from_a_newer_gateway"}, {Result: "setup_failed", SetupError: "Existing setup found at /etc"}} {
		message, code, e := enrollmentFailure(in)
		if e != nil || code != "" || message != enrollmentFailures["setup_failed"] {
			t.Fatalf("%+v: got %q %q %v", in, message, code, e)
		}
	}
	if message, code, e := enrollmentFailure(bootstrap.Report{Result: "ssh_unreachable"}); e != nil || code != "" || message != enrollmentFailures["ssh_unreachable"] {
		t.Fatal("transport failure changed")
	}
	for _, in := range []bootstrap.Report{{Result: "ssh_unreachable", SetupError: "setup_existing_setup"}, {Result: "made_up"}, {Result: "failed"}} {
		if _, _, e := enrollmentFailure(in); e == nil {
			t.Fatalf("malformed report accepted: %+v", in)
		}
	}
	if !strings.Contains(enrollmentFailures["setup_failed"], "journalctl -t tunnex-browser-ssh") {
		t.Fatal("generic text must name the journal identifier the helper writes")
	}
}

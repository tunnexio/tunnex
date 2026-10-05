package sandboxes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"golang.org/x/crypto/ssh"
)

func runnerEnrollmentFixture(t *testing.T) (fixture, BoundedRuntimeBinding, map[uuid.UUID]uuid.UUID, context.Context, *RunnerEnrollmentService) {
	t.Helper()
	f, b, devices := organizationAdmissionFixture(t)
	devExec(t, f, `UPDATE memberships SET roles=ARRAY['owner'],role='owner' WHERE org_id=$1 AND user_id=$2`, f.org, f.user)
	ctx := authctx.WithPrincipal(f.ctx, &authctx.Principal{UserID: f.user, Roles: map[uuid.UUID]string{f.org: rbac.RoleOwner}, EmailVerified: true})
	e, err := sandboxrunner.Enroll("controller.example.invalid", "spiffe://tunnex/controller/enroll", "spiffe://tunnex/runner/enroll", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(e.ControllerCertificate, e.ControllerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := sandboxrunner.NewIssuer(e.CA, e.ControllerCAKey, cert, "spiffe://tunnex/runner/enroll")
	if err != nil {
		t.Fatal(err)
	}
	p := b.Profiles[0]
	cfg := RunnerEnrollmentConfig{RunnerURI: "spiffe://tunnex/runner/enroll", RunnerCA: string(e.CA), ModuleState: "enabled", Profile: RunnerEnrollmentProfile{ID: uuid.New(), Name: "qualified Linux", Architecture: "amd64", HostOS: "ubuntu", HostVersion: "26.04", Prerequisites: []string{"Ubuntu26.04 AMD64 with bounded cgroups"}, BootstrapScript: RunnerArtifact{"https://artifacts.example.invalid/enroll.py", strings.Repeat("a", 64)}, Install: RunnerInstallPlan{Version: 1, Edition: "open", SourceSHA: strings.Repeat("1", 40), Bundle: RunnerArtifact{"https://artifacts.example.invalid/bundle.tar.gz", strings.Repeat("b", 64)}, OrgID: f.org, Gateway: RunnerInstallGateway{NodeID: f.node, ContainerID: strings.Repeat("c", 64), ImageDigest: "sha256:" + strings.Repeat("d", 64), Interface: "wg0"}, Controller: RunnerInstallController{URL: "https://controller.example.invalid:8444", ServerName: "controller.example.invalid", URI: "spiffe://tunnex/controller/enroll", APIURL: "https://api.example.invalid"}, Images: []RunnerInstallImage{{TemplateID: p.TemplateID, URL: "https://artifacts.example.invalid/image.tar", SHA256: strings.Repeat("e", 64), ConfigDigest: p.ConfigDigest, Architecture: p.Architecture, QualificationEvidence: p.QualificationEvidence}}}}}
	s, err := NewRunnerEnrollmentService(f.store, b, cfg, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return f, b, devices, ctx, s
}
func runnerMachineInput(t *testing.T) RunnerRedeemInput {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	_, probe, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(probe)
	if err != nil {
		t.Fatal(err)
	}
	return RunnerRedeemInput{CertificateRequest: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})), ProbePublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}
}
func issueRunner(t *testing.T, f fixture, ctx context.Context, s *RunnerEnrollmentService) (RunnerEnrollmentIssue, RunnerEnrollmentBundle, *x509.Certificate) {
	t.Helper()
	issue, err := s.Issue(ctx, f.org, f.user, RunnerEnrollmentCreate{ProfileID: s.config.Profile.ID, Name: "customer runner", IdempotencyKey: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := s.Redeem(f.ctx, issue.Enrollment.ID, issue.BootstrapToken, runnerMachineInput(t))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(bundle.Certificate))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return issue, bundle, leaf
}
func TestRunnerEnrollmentPostgresSecretIdempotencyAndKeyBinding(t *testing.T) {
	f, _, _, ctx, s := runnerEnrollmentFixture(t)
	in := RunnerEnrollmentCreate{ProfileID: s.config.Profile.ID, Name: "my runner", IdempotencyKey: uuid.New()}
	if _, err := s.Issue(f.ctx, f.org, f.user, in); !errors.Is(err, ErrForbidden) {
		t.Fatal("anonymous/missing principal issued", err)
	}
	member := authctx.WithPrincipal(f.ctx, &authctx.Principal{UserID: f.other, Roles: map[uuid.UUID]string{f.org: rbac.RoleMember}, EmailVerified: true})
	if _, err := s.List(member, f.org, f.other); !errors.Is(err, ErrForbidden) {
		t.Fatal("member enrollment administration", err)
	}
	forged := authctx.WithPrincipal(f.ctx, &authctx.Principal{UserID: f.other, Roles: map[uuid.UUID]string{f.org: rbac.RoleOwner}, EmailVerified: true})
	if _, err := s.Issue(forged, f.org, f.other, in); !errors.Is(err, ErrForbidden) {
		t.Fatal("claimed role bypassed current membership", err)
	}
	machine := authctx.WithPrincipal(f.ctx, authctx.NewMachinePrincipal(f.user, uuid.New(), f.org, "fixture", rbac.RoleOwner, ""))
	if _, err := s.Issue(machine, f.org, f.user, in); !errors.Is(err, ErrForbidden) {
		t.Fatal("machine issued administrative enrollment", err)
	}
	// Enrollment breaks the setup cycle without opting user creation in.
	devExec(t, f, `UPDATE organizations SET sandboxes_enabled=false WHERE id=$1`, f.org)
	type result struct {
		out RunnerEnrollmentIssue
		err error
	}
	results := make(chan result, 2)
	var barrier sync.WaitGroup
	barrier.Add(2)
	for range 2 {
		go func() {
			barrier.Done()
			barrier.Wait()
			out, err := s.Issue(ctx, f.org, f.user, in)
			results <- result{out, err}
		}()
	}
	a, c := <-results, <-results
	if a.err != nil || c.err != nil || a.out.Enrollment.ID != c.out.Enrollment.ID || (a.out.BootstrapToken == "") == (c.out.BootstrapToken == "") {
		t.Fatal("single secret/idempotency race failed", a.err, c.err)
	}
	issue := a.out
	if issue.BootstrapToken == "" {
		issue = c.out
	}
	if strings.Contains(issue.Enrollment.InstallCommand, issue.BootstrapToken) {
		t.Fatal("token entered command")
	}
	in.Name = "changed"
	if _, err := s.Issue(ctx, f.org, f.user, in); !errors.Is(err, ErrConflict) {
		t.Fatal("changed intent replay", err)
	}
	input := runnerMachineInput(t)
	if _, err := s.Redeem(f.ctx, issue.Enrollment.ID, strings.Repeat("x", 43), input); !errors.Is(err, ErrForbidden) {
		t.Fatal("wrong token", err)
	}
	bundle, err := s.Redeem(f.ctx, issue.Enrollment.ID, issue.BootstrapToken, input)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Redeem(f.ctx, issue.Enrollment.ID, issue.BootstrapToken, input)
	if err != nil || again.Certificate != bundle.Certificate {
		t.Fatal("exact public receipt recovery", err)
	}
	if _, err = s.Redeem(f.ctx, issue.Enrollment.ID, issue.BootstrapToken, runnerMachineInput(t)); !errors.Is(err, ErrConflict) {
		t.Fatal("consumed challenge switched keys", err)
	}
	var hash []byte
	var audit string
	if err = f.pool.QueryRow(f.ctx, `SELECT token_hash FROM sandbox_runner_enrollments WHERE id=$1`, issue.Enrollment.ID).Scan(&hash); err != nil || string(hash) == issue.BootstrapToken {
		t.Fatal("raw secret stored", err)
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT COALESCE(string_agg(metadata::text,''),'') FROM audit_logs WHERE org_id=$1`, f.org).Scan(&audit); err != nil || strings.Contains(audit, issue.BootstrapToken) {
		t.Fatal("raw secret audited", err)
	}
	block, _ := pem.Decode([]byte(bundle.Certificate))
	leaf, _ := x509.ParseCertificate(block.Bytes)
	credential, err := s.AuthorizeCertificate(f.ctx, leaf)
	if err != nil || credential.ProbePublicKey != input.ProbePublicKey {
		t.Fatal("public probe binding", err)
	}
	if s.RuntimeReady(f.ctx) {
		t.Fatal("enrollment alone made Ready")
	}
	if _, err = s.AuthorizeCertificate(f.ctx, &x509.Certificate{}); !errors.Is(err, ErrForbidden) {
		t.Fatal("foreign certificate", err)
	}
	got, err := s.Get(ctx, f.org, f.user, issue.Enrollment.ID)
	if err != nil || got.State != "awaiting_connection" {
		t.Fatal("truthful status", err)
	}
	if _, err = s.Revoke(ctx, f.org, f.user, issue.Enrollment.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthorizeCertificate(f.ctx, leaf); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked unowned credential", err)
	}
	if _, err = s.Issue(ctx, f.org, f.user, RunnerEnrollmentCreate{ProfileID: s.config.Profile.ID, Name: "replacement", IdempotencyKey: uuid.New()}); err != nil {
		t.Fatal("inert revoke blocked replacement", err)
	}
}

func TestRunnerEnrollmentPostgresExpiredChallengeCannotRecoverOrExtend(t *testing.T) {
	f, _, _, ctx, s := runnerEnrollmentFixture(t)
	id := uuid.New()
	token := strings.Repeat("x", 43)
	hash := sha256.Sum256([]byte(token))
	devExec(t, f, `INSERT INTO sandbox_runner_enrollments(id,org_id,issuer_id,profile_id,name,idempotency_key,request_hash,binding_hash,token_hash,runner_uri,created_at,expires_at) SELECT $1,$2,$3,$4,'expired fixture',$5,$6,$6,$7,$8,t-interval '601 seconds',t-interval '1 second' FROM (SELECT clock_timestamp() t) q`, id, f.org, f.user, s.config.Profile.ID, uuid.New(), s.bindingHash, hash[:], s.config.RunnerURI)
	if _, err := s.Redeem(f.ctx, id, token, runnerMachineInput(t)); !errors.Is(err, ErrForbidden) {
		t.Fatal("expired token recovered authority", err)
	}
	if err := s.Sweep(f.ctx); err != nil {
		t.Fatal(err)
	}
	view, err := s.Get(ctx, f.org, f.user, id)
	if err != nil || view.State != "expired" {
		t.Fatal("expired status", err)
	}
	if _, err := s.Issue(ctx, f.org, f.user, RunnerEnrollmentCreate{ProfileID: s.config.Profile.ID, Name: "fresh bounded attempt", IdempotencyKey: uuid.New()}); err != nil {
		t.Fatal("expired inert attempt retained slot", err)
	}
}

type runnerNativeFixtureProof struct{ allowed bool }

func (p *runnerNativeFixtureProof) VerifyRunnerQualification(context.Context, uuid.UUID, RunnerQualificationReport) error {
	if !p.allowed {
		return ErrDisabled
	}
	return nil
}
func qualificationFixtureReport(s *RunnerEnrollmentService, id uuid.UUID) RunnerQualificationReport {
	r := RunnerQualificationReport{Version: 1, EnrollmentID: id, ProfileID: s.config.Profile.ID, BindingSHA256: hex.EncodeToString(s.bindingHash), SourceSHA: s.config.Profile.Install.SourceSHA, Platform: RunnerQualificationPlatform{"ubuntu", "26.04", "amd64"}, StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now()}
	for _, p := range s.binding.Profiles {
		r.ImageConfigDigests = append(r.ImageConfigDigests, p.ConfigDigest)
	}
	for _, code := range runnerQualificationChecks {
		r.Checks = append(r.Checks, RunnerQualificationCheck{code, "passed", "synthetic source fixture; not native qualification"})
	}
	return r
}
func TestRunnerEnrollmentPostgresQualificationRequiresIndependentProofAndHumanReview(t *testing.T) {
	f, b, _, ctx, s := runnerEnrollmentFixture(t)
	issue, _, leaf := issueRunner(t, f, ctx, s)
	credential, err := s.AuthorizeCertificate(f.ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RecordHealth(f.ctx, credential, b); err != nil {
		t.Fatal(err)
	}
	if s.RuntimeReady(f.ctx) {
		t.Fatal("health selfqualified")
	}
	report := qualificationFixtureReport(s, issue.Enrollment.ID)
	record, err := s.SubmitQualification(f.ctx, leaf, report)
	if err != nil || record.Approvable {
		t.Fatal("host selfqualified", err)
	}
	review := RunnerQualificationReview{record.ReportSHA256, "approve", "Reviewed actual bounded fixture evidence"}
	if _, err = s.ReviewQualification(ctx, f.org, f.user, issue.Enrollment.ID, review); !errors.Is(err, ErrDisabled) {
		t.Fatal("missing control-plane proof admitted", err)
	}
	proof := &runnerNativeFixtureProof{allowed: true}
	s.WithNativeProofVerifier(proof)
	review.ExpectedReportSHA256 = strings.Repeat("f", 64)
	if _, err = s.ReviewQualification(ctx, f.org, f.user, issue.Enrollment.ID, review); !errors.Is(err, ErrConflict) {
		t.Fatal("stale review CAS", err)
	}
	review.ExpectedReportSHA256 = record.ReportSHA256
	record, err = s.ReviewQualification(ctx, f.org, f.user, issue.Enrollment.ID, review)
	if err != nil || record.Decision != "approved" {
		t.Fatal("review", err)
	}
	if !s.RuntimeReady(f.ctx) {
		t.Fatal("qualified current health notready")
	}
	proof.allowed = false
	if s.RuntimeReady(f.ctx) {
		t.Fatal("lost independent proof retainedReady")
	}
	proof.allowed = true
	report.FinishedAt = time.Now()
	report.Checks[0].Result = "unrun"
	record, err = s.SubmitQualification(f.ctx, leaf, report)
	if err != nil || record.Approvable || s.RuntimeReady(f.ctx) {
		t.Fatal("new unrun report retained approval", err)
	}
	review.ExpectedReportSHA256 = record.ReportSHA256
	if _, err = s.ReviewQualification(ctx, f.org, f.user, issue.Enrollment.ID, review); !errors.Is(err, ErrInvalid) {
		t.Fatal("unrun approved", err)
	}
	report.Checks[0].Result = "passed"
	report.Platform.Architecture = "arm64"
	report.FinishedAt = time.Now()
	record, err = s.SubmitQualification(f.ctx, leaf, report)
	if err != nil || record.Approvable {
		t.Fatal("unsupported platform approved", err)
	}
}
func TestRunnerEnrollmentPostgresRevokeCleanupFenceAndRetainedSlot(t *testing.T) {
	f, b, devices, ctx, s := runnerEnrollmentFixture(t)
	issue, _, leaf := issueRunner(t, f, ctx, s)
	s.config.QualifiedRunnerSPKIHash = hex.EncodeToString(runnerKeyHash(leaf))
	s.config.HostQualificationEvidence = "synthetic fixture, not native qualification"
	credential, err := s.AuthorizeCertificate(f.ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RecordHealth(f.ctx, credential, b); err != nil {
		t.Fatal(err)
	}
	sb, _, err := f.store.Create(f.ctx, f.org, f.user, organizationInput(f, b, devices[f.user], "runner-work"))
	if err != nil {
		t.Fatal(err)
	}
	a := RuntimeAuthorization{SandboxID: sb.Identity.ID, OrgID: f.org, CreatorID: f.user, GatewayID: b.GatewayID, TerminalDeviceID: devices[f.user], TemplateID: sb.TemplateVersionID, Profile: b.Profiles[0], Generation: sb.Revision, Desired: sb.DesiredState, CreatedAt: sb.CreatedAt, ExpiresAt: sb.ExpiresAt}
	raw, _ := json.Marshal(workerRequest{Version: 1, Operation: "authorize", ID: a.SandboxID, Generation: a.Generation, Authorization: &a})
	if err = s.AuthorizeCommand(f.ctx, credential, raw); err != nil {
		t.Fatal("bind workload", err)
	}
	if _, err = s.Revoke(ctx, f.org, f.user, issue.Enrollment.ID); err != nil {
		t.Fatal(err)
	}
	withdrawn, err := f.store.Get(f.ctx, f.org, f.user, sb.Identity.ID)
	if err != nil || withdrawn.DesiredState != "deleted" || withdrawn.Revision != 2 || withdrawn.State == StateDeleted {
		t.Fatal("atomic bounded withdrawal", err)
	}
	credential, err = s.AuthorizeCertificate(f.ctx, leaf)
	if err != nil || !credential.CleanupOnly || credential.RetainedSandboxID == nil || *credential.RetainedSandboxID != sb.Identity.ID {
		t.Fatal("cleanup credential", err)
	}
	if _, err = s.RenewCertificate(f.ctx, leaf); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked renewal", err)
	}
	if err = s.AuthorizeCommand(f.ctx, credential, raw); err == nil {
		t.Fatal("stale start authorized")
	}
	a.Generation, a.Desired = withdrawn.Revision, "deleted"
	raw, _ = json.Marshal(workerRequest{Version: 1, Operation: "authorize", ID: a.SandboxID, Generation: a.Generation, Authorization: &a})
	if err = s.AuthorizeCommand(f.ctx, credential, raw); err != nil {
		t.Fatal("cleanup authorization", err)
	}
	for _, op := range []string{"inspect", "stop", "delete", "check-config", "remove-network", "gateway-absence", "retire"} {
		raw, _ = json.Marshal(workerRequest{Version: 1, Operation: op, ID: a.SandboxID, Generation: a.Generation})
		if err = s.AuthorizeCommand(f.ctx, credential, raw); err != nil {
			t.Fatal("cleanup denied", op, err)
		}
	}
	for _, op := range []string{"create", "start", "materialize", "enroll", "apply-network", "probe", "verify-assets"} {
		raw, _ = json.Marshal(workerRequest{Version: 1, Operation: op, ID: a.SandboxID, Generation: a.Generation})
		if err = s.AuthorizeCommand(f.ctx, credential, raw); !errors.Is(err, ErrForbidden) {
			t.Fatal("revoked effect admitted", op, err)
		}
	}
	if _, err = s.Issue(ctx, f.org, f.user, RunnerEnrollmentCreate{ProfileID: s.config.Profile.ID, Name: "replacement", IdempotencyKey: uuid.New()}); !errors.Is(err, ErrConflict) {
		t.Fatal("unretired slot replaced", err)
	}
	devExec(t, f, `UPDATE sandboxes SET observed_state='deleted' WHERE id=$1`, sb.Identity.ID)
	devExec(t, f, `UPDATE sandbox_runtime_bindings SET worker_retired_at=now() WHERE sandbox_id=$1`, sb.Identity.ID)
	if _, err = s.AuthorizeCertificate(f.ctx, leaf); !errors.Is(err, ErrForbidden) {
		t.Fatal("cleanup authority survived retirement", err)
	}
	if _, err = s.Issue(ctx, f.org, f.user, RunnerEnrollmentCreate{ProfileID: s.config.Profile.ID, Name: "replacement", IdempotencyKey: uuid.New()}); err != nil {
		t.Fatal("confirmed retired slot notavailable", err)
	}
}
func TestRunnerEnrollmentPostgresAuthorityLossAndExpiry(t *testing.T) {
	for _, scenario := range []string{"membership", "optout-policy", "module", "certificate-expiry"} {
		t.Run(scenario, func(t *testing.T) {
			f, _, _, ctx, s := runnerEnrollmentFixture(t)
			issue, _, leaf := issueRunner(t, f, ctx, s)
			switch scenario {
			case "membership":
				devExec(t, f, `UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, f.org, f.user)
			case "optout-policy":
				devExec(t, f, `UPDATE organizations SET sandboxes_enabled=false,zero_trust_mode='off' WHERE id=$1`, f.org)
			case "module":
				s.config.ModuleState = "draining"
			case "certificate-expiry":
				devExec(t, f, `UPDATE sandbox_runner_enrollments SET certificate_expires_at=now()-interval '1 second' WHERE id=$1`, issue.Enrollment.ID)
			}
			if _, err := s.AuthorizeCertificate(f.ctx, leaf); !errors.Is(err, ErrForbidden) {
				t.Fatal("withdrawn current authority", err)
			}
			if err := s.Sweep(f.ctx); err != nil {
				t.Fatal(err)
			}
			var revoked bool
			if err := f.pool.QueryRow(f.ctx, `SELECT revoked_at IS NOT NULL FROM sandbox_runner_enrollments WHERE id=$1`, issue.Enrollment.ID).Scan(&revoked); err != nil || !revoked {
				t.Fatal("sweep retained lostgrant", err)
			}
		})
	}
}

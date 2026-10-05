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
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
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

func TestRunnerEnrollmentPostgresTwoOwnersKeepCanonicalAuthorityAndPolicy(t *testing.T) {
	f, b, devices, ctx, s := runnerEnrollmentFixture(t)
	issue, _, leaf := issueRunner(t, f, ctx, s)
	// This source-only fixture supplies qualification; it is not native evidence.
	s.config.QualifiedRunnerSPKIHash = hex.EncodeToString(runnerKeyHash(leaf))
	s.config.HostQualificationEvidence = "synthetic two-owner fixture; not native qualification"
	credential, err := s.AuthorizeCertificate(f.ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RecordHealth(f.ctx, credential, b); err != nil {
		t.Fatal(err)
	}
	command := func(a RuntimeAuthorization) error {
		t.Helper()
		raw, marshalErr := json.Marshal(workerRequest{Version: 1, Operation: "authorize", ID: a.SandboxID, Generation: a.Generation, Authorization: &a})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return s.AuthorizeCommand(f.ctx, credential, raw)
	}
	for i, owner := range []uuid.UUID{f.user, f.other} {
		other := f.other
		if owner == f.other {
			other = f.user
		}
		sb, _, createErr := f.store.Create(f.ctx, f.org, owner, organizationInput(f, b, devices[owner], "shared-owner-key"))
		if createErr != nil {
			t.Fatal("sequential owner admission", createErr)
		}
		a := RuntimeAuthorization{SandboxID: sb.Identity.ID, OrgID: f.org, CreatorID: owner, GatewayID: b.GatewayID, TerminalDeviceID: devices[owner], TemplateID: sb.TemplateVersionID, Profile: b.Profiles[0], Generation: sb.Revision, Desired: sb.DesiredState, CreatedAt: sb.CreatedAt, ExpiresAt: sb.ExpiresAt}
		changed := a
		changed.CreatorID = other
		if err = command(changed); !errors.Is(err, ErrForbidden) {
			t.Fatal("runner substituted the other owner or enrollment issuer", err)
		}
		changed = a
		changed.TerminalDeviceID = devices[other]
		if err = command(changed); !errors.Is(err, ErrForbidden) {
			t.Fatal("runner substituted another owner's terminal", err)
		}
		if err = command(a); err != nil {
			t.Fatal("canonical owner/terminal rejected", err)
		}
		var mapped, creator, issuer, terminal uuid.UUID
		if err = f.pool.QueryRow(f.ctx, `SELECT w.enrollment_id,s.creator_id,e.issuer_id,s.terminal_device_id FROM sandbox_runner_workloads w JOIN sandboxes s ON s.id=w.sandbox_id AND s.org_id=w.org_id JOIN sandbox_runner_enrollments e ON e.id=w.enrollment_id AND e.org_id=w.org_id WHERE s.id=$1`, sb.Identity.ID).Scan(&mapped, &creator, &issuer, &terminal); err != nil || mapped != issue.Enrollment.ID || creator != owner || issuer != f.user || terminal != devices[owner] {
			t.Fatal("enrollment issuer became workload authority", err)
		}
		if other == f.other {
			if _, err = f.store.Get(f.ctx, f.org, other, sb.Identity.ID); !errors.Is(err, ErrNotFound) {
				t.Fatal("unprivileged other owner read workload", err)
			}
			if _, err = f.store.SetDesired(f.ctx, f.org, other, sb.Identity.ID, sb.Revision, "stopped"); !errors.Is(err, ErrNotFound) {
				t.Fatal("unprivileged other owner mutated workload", err)
			}
		} else {
			// Existing administrator visibility does not transfer workload identity.
			view, viewErr := f.store.Get(f.ctx, f.org, f.user, sb.Identity.ID)
			if viewErr != nil || view.Identity.CreatorID != owner {
				t.Fatal("administrative visibility transferred creator", viewErr)
			}
		}

		// Bind actual sandbox subjects to the compiled policy. The issuer has a
		// broad 10.1.0.0/16 user rule in newFixture; neither sandbox may inherit it.
		peer, address := uuid.New(), []string{"10.99.0.4", "10.99.0.5"}[i]
		tx, beginErr := f.pool.Begin(f.ctx)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		if _, err = tx.Exec(f.ctx, `INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,kind) VALUES($1,$2,$3,$4,'two-owner sandbox',$5,$6,'sandbox')`, peer, f.org, owner, f.node, peer.String(), address); err == nil {
			_, err = tx.Exec(f.ctx, `UPDATE sandboxes SET peer_id=$2 WHERE id=$1`, sb.Identity.ID, peer)
		}
		if err != nil {
			_ = tx.Rollback(f.ctx)
			t.Fatal(err)
		}
		if err = tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
		snapshot, snapshotErr := policy.BuildSnapshotWithQueries(f.ctx, sqlc.New(f.pool), f.org)
		if snapshotErr != nil {
			t.Fatal(snapshotErr)
		}
		incoming := 0
		for _, allow := range policy.Compile(snapshot)[f.node].Allow {
			if allow.SrcIP == address {
				t.Fatal("sandbox inherited an owner's broad outbound rule", allow)
			}
			if allow.DstCIDR == address+"/32" {
				incoming++
				if allow.SrcIP != []string{"10.99.0.2", "10.99.0.3"}[i] || allow.Protocol != "tcp" || allow.PortLow != 22 || allow.PortHigh != 22 {
					t.Fatal("incoming SSH escaped the canonical owned terminal", allow)
				}
			}
		}
		if incoming != 1 {
			t.Fatal("missing exact owned-terminal SSH grant", incoming)
		}
		if _, _, err = f.store.Create(f.ctx, f.org, other, organizationInput(f, b, devices[other], "shared-slot-denied")); !errors.Is(err, ErrQuota) {
			t.Fatal("owners bypassed the one retained runner slot", err)
		}
		if owner == f.other {
			devExec(t, f, `UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, f.org, owner)
			if err = command(a); !errors.Is(err, ErrForbidden) {
				t.Fatal("enrollment issuer's membership replaced revoked creator authority", err)
			}
			devExec(t, f, `UPDATE memberships SET access_revoked_at=NULL WHERE org_id=$1 AND user_id=$2`, f.org, owner)
			devExec(t, f, `UPDATE devices SET user_id=$2 WHERE id=$1`, devices[owner], f.user)
			if err = command(a); !errors.Is(err, ErrForbidden) {
				t.Fatal("enrolled credential ignored terminal reassignment", err)
			}
			devExec(t, f, `UPDATE devices SET user_id=$2 WHERE id=$1`, devices[owner], owner)
			if err = command(a); err != nil {
				t.Fatal("restored canonical authority rejected", err)
			}
		}
		// Fixture tombstones model confirmed cleanup only, never physical proof.
		devExec(t, f, `UPDATE devices SET deleted_at=now(),health_blocked=true WHERE id=$1`, peer)
		devExec(t, f, `UPDATE sandboxes SET desired_state='deleted',observed_state='deleted' WHERE id=$1`, sb.Identity.ID)
		if i == 0 {
			if _, _, err = f.store.Create(f.ctx, f.org, other, organizationInput(f, b, devices[other], "shared-owner-key")); !errors.Is(err, ErrQuota) {
				t.Fatal("unretired owner released the shared slot", err)
			}
		}
		devExec(t, f, `UPDATE sandbox_runtime_bindings SET worker_retired_at=now() WHERE sandbox_id=$1`, sb.Identity.ID)
	}
}

func TestRunnerEnrollmentPostgresRecentInventoryKeepsCurrentAndCleanupControls(t *testing.T) {
	for _, state := range []string{"awaiting_connection", "pending_cleanup"} {
		t.Run(state, func(t *testing.T) {
			f, b, devices, ctx, s := runnerEnrollmentFixture(t)
			issue, _, _ := issueRunner(t, f, ctx, s)
			if state == "pending_cleanup" {
				sb, _, err := f.store.Create(f.ctx, f.org, f.user, organizationInput(f, b, devices[f.user], "inventory-cleanup"))
				if err != nil {
					t.Fatal(err)
				}
				// Synthetic bookkeeping represents a retained workload; no runner
				// health, native readiness or physical cleanup is claimed here.
				devExec(t, f, `INSERT INTO sandbox_runner_workloads(sandbox_id,org_id,enrollment_id) VALUES($1,$2,$3)`, sb.Identity.ID, f.org, issue.Enrollment.ID)
				if _, err = s.Revoke(ctx, f.org, f.user, issue.Enrollment.ID); err != nil {
					t.Fatal(err)
				}
			}
			// Newer closed history must not crowd out an older current grant.
			devExec(t, f, `INSERT INTO sandbox_runner_enrollments(org_id,issuer_id,profile_id,name,idempotency_key,request_hash,binding_hash,token_hash,runner_uri,created_at,expires_at,revoked_at)
 SELECT $1,$2,$3,'closed synthetic fixture',gen_random_uuid(),$4,$4,$4,$5,t,t+interval '10 minutes',clock_timestamp()
 FROM (SELECT clock_timestamp()+n*interval '1 second' t FROM generate_series(1,101) n) history`, f.org, f.user, s.config.Profile.ID, s.bindingHash, s.config.RunnerURI)
			list, err := s.List(ctx, f.org, f.user)
			if err != nil || len(list.Enrollments) != 20 || list.Enrollments[0].ID != issue.Enrollment.ID || list.Enrollments[0].State != state {
				t.Fatal("closed history disabled or hid current controls", err, len(list.Enrollments))
			}
			if s.RuntimeReady(f.ctx) || list.Enrollments[0].LastSeenAt != nil {
				t.Fatal("inventory pretended an unobserved runner was ready")
			}
			var count int
			if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM sandbox_runner_enrollments WHERE org_id=$1`, f.org).Scan(&count); err != nil || count != 102 {
				t.Fatal("inventory deleted closed history", err, count)
			}
		})
	}
}

func TestRunnerEnrollmentPostgresAdmissionMappingPrecedesFirstDispatch(t *testing.T) {
	f, b, devices, ctx, s := runnerEnrollmentFixture(t)
	issue, _, leaf := issueRunner(t, f, ctx, s)
	sb, _, err := f.store.Create(f.ctx, f.org, f.other, organizationInput(f, b, devices[f.other], "admission-before-dispatch"))
	if err != nil {
		t.Fatal(err)
	}
	bind := func(candidate Sandbox) error {
		t.Helper()
		tx, beginErr := f.pool.Begin(f.ctx)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		defer tx.Rollback(f.ctx)
		if _, beginErr = s.orgLock(f.ctx, tx); beginErr != nil {
			t.Fatal(beginErr)
		}
		if beginErr = s.BindSandboxAdmission(f.ctx, tx, candidate); beginErr != nil {
			return beginErr
		}
		return tx.Commit(f.ctx)
	}
	if err = bind(sb); !errors.Is(err, ErrDisabled) {
		t.Fatal("unqualified, unseen enrollment admitted a normal workload", err)
	}
	// This fixture tests durable admission fencing only; it supplies no actual
	// native qualification or provider/network effect.
	s.config.QualifiedRunnerSPKIHash = hex.EncodeToString(runnerKeyHash(leaf))
	s.config.HostQualificationEvidence = "synthetic atomic admission fixture; not native qualification"
	credential, err := s.AuthorizeCertificate(f.ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RecordHealth(f.ctx, credential, b); err != nil {
		t.Fatal(err)
	}
	changed := sb
	changed.Identity.CreatorID = f.user
	if err = bind(changed); !errors.Is(err, ErrForbidden) {
		t.Fatal("admission mapping substituted enrollment issuer for creator", err)
	}
	devExec(t, f, `UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, f.org, f.other)
	if err = bind(sb); !errors.Is(err, ErrDisabled) {
		t.Fatal("admission mapping ignored current creator membership", err)
	}
	devExec(t, f, `UPDATE memberships SET access_revoked_at=NULL WHERE org_id=$1 AND user_id=$2`, f.org, f.other)
	if err = bind(sb); err != nil {
		t.Fatal("canonical normal admission mapping", err)
	}
	var mapped uuid.UUID
	if err = f.pool.QueryRow(f.ctx, `SELECT enrollment_id FROM sandbox_runner_workloads WHERE sandbox_id=$1 AND org_id=$2`, sb.Identity.ID, f.org).Scan(&mapped); err != nil || mapped != issue.Enrollment.ID {
		t.Fatal("accepted workload awaits first RPC before becoming revocable", err)
	}
	if _, err = s.Revoke(ctx, f.org, f.user, issue.Enrollment.ID); err != nil {
		t.Fatal(err)
	}
	withdrawn, err := f.store.Get(f.ctx, f.org, f.other, sb.Identity.ID)
	if err != nil || withdrawn.DesiredState != "deleted" || withdrawn.Revision != sb.Revision+1 || withdrawn.State == StateDeleted {
		t.Fatal("pre-dispatch workload was not atomically withdrawn", err)
	}
	credential, err = s.AuthorizeCertificate(f.ctx, leaf)
	if err != nil || !credential.CleanupOnly || credential.RetainedSandboxID == nil || *credential.RetainedSandboxID != sb.Identity.ID {
		t.Fatal("pre-dispatch retained workload lost cleanup authority", err)
	}
	if err = bind(sb); !errors.Is(err, ErrDisabled) {
		t.Fatal("revoked enrollment rebound ordinary admission", err)
	}
}

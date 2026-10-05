package http

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

type runnerEnrollmentStub struct {
	calls, issued, revoked, redeemed, reviewed int
	org, actor                                 uuid.UUID
	enrollment                                 sandboxes.RunnerEnrollment
	trial                                      *sandboxes.RunnerQualificationTrial
	latestError                                error
}

func (f *runnerEnrollmentStub) List(_ context.Context, org, actor uuid.UUID) (sandboxes.RunnerEnrollmentList, error) {
	f.calls++
	f.org, f.actor = org, actor
	return sandboxes.RunnerEnrollmentList{Profiles: []sandboxes.RunnerEnrollmentProfile{}, Enrollments: []sandboxes.RunnerEnrollment{f.enrollment}, BlockedReasons: []string{}}, nil
}
func (f *runnerEnrollmentStub) Issue(_ context.Context, org, actor uuid.UUID, in sandboxes.RunnerEnrollmentCreate) (sandboxes.RunnerEnrollmentIssue, error) {
	f.calls++
	f.issued++
	f.org, f.actor = org, actor
	result := sandboxes.RunnerEnrollmentIssue{Enrollment: f.enrollment}
	if f.issued == 1 {
		result.BootstrapToken = strings.Repeat("t", 43)
	}
	return result, nil
}
func (f *runnerEnrollmentStub) Get(_ context.Context, org, actor, id uuid.UUID) (sandboxes.RunnerEnrollment, error) {
	f.calls++
	f.org, f.actor = org, actor
	return f.enrollment, nil
}
func (f *runnerEnrollmentStub) Revoke(_ context.Context, org, actor, id uuid.UUID) (sandboxes.RunnerEnrollment, error) {
	f.calls++
	f.revoked++
	f.org, f.actor = org, actor
	f.enrollment.State = "pending_cleanup"
	return f.enrollment, nil
}
func (f *runnerEnrollmentStub) Redeem(_ context.Context, id uuid.UUID, token string, in sandboxes.RunnerRedeemInput) (sandboxes.RunnerEnrollmentBundle, error) {
	f.calls++
	f.redeemed++
	return sandboxes.RunnerEnrollmentBundle{EnrollmentID: id, ProfileID: f.enrollment.ProfileID, BindingSHA256: strings.Repeat("b", 64), Certificate: "synthetic public certificate", RunnerCA: "synthetic public CA"}, nil
}
func (f *runnerEnrollmentStub) ReviewQualification(_ context.Context, org, actor, id uuid.UUID, in sandboxes.RunnerQualificationReview) (sandboxes.RunnerQualificationRecord, error) {
	f.calls++
	f.reviewed++
	f.org, f.actor = org, actor
	return sandboxes.RunnerQualificationRecord{}, nil
}
func (f *runnerEnrollmentStub) LatestQualificationTrial(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (sandboxes.RunnerQualificationTrial, error) {
	if f.latestError != nil {
		return sandboxes.RunnerQualificationTrial{}, f.latestError
	}
	if f.trial == nil {
		return sandboxes.RunnerQualificationTrial{}, sandboxes.ErrNotFound
	}
	return *f.trial, nil
}
func (f *runnerEnrollmentStub) BeginQualification(_ context.Context, org, actor, enrollment uuid.UUID, in sandboxes.RunnerQualificationTrialInput) (sandboxes.RunnerQualificationTrial, bool, error) {
	f.calls++
	f.org, f.actor = org, actor
	return *f.trial, false, nil
}
func (f *runnerEnrollmentStub) StatusQualification(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) (sandboxes.RunnerQualificationTrial, error) {
	f.calls++
	return *f.trial, nil
}

func runnerEnrollmentRouter(t *testing.T, repo *runnerEnrollmentStub, org uuid.UUID, principal **authctx.Principal, wake func()) http.Handler {
	t.Helper()
	handler, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{SandboxRunnerEnrollment: repo, SandboxRunnerQualification: repo, SandboxWake: wake, Orgs: tenancy.NewService(nil), AuthFn: func(*http.Request) *authctx.Principal { return *principal }})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
func runnerEnrollmentRequestFor(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw string
	if text, ok := body.(string); ok {
		raw = text
	} else if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		raw = string(b)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(raw))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestRunnerEnrollmentGeneratedHumanBoundaryBeforeValidation(t *testing.T) {
	org, user := uuid.New(), uuid.New()
	repo := &runnerEnrollmentStub{}
	var principal *authctx.Principal
	handler := runnerEnrollmentRouter(t, repo, org, &principal, nil)
	path := "/api/v1/organizations/" + org.String() + "/sandbox-runner-enrollments"
	for _, tc := range []struct {
		name   string
		p      *authctx.Principal
		status int
	}{
		{"anonymous", nil, 401},
		{"member", &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}, 403},
		{"other org", &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): rbac.RoleOwner}}, 404},
		{"machine", &authctx.Principal{UserID: user, MachineID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403},
		{"agent", &authctx.Principal{UserID: user, AuthMethod: authctx.AuthAgent, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			principal = tc.p
			rr := runnerEnrollmentRequestFor(t, handler, "POST", path, "{")
			if rr.Code != tc.status || repo.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", rr.Code, repo.calls, rr.Body.String())
			}
		})
	}
}

func TestRunnerEnrollmentGeneratedOneTimeSecretAndCanonicalProgress(t *testing.T) {
	org, user := uuid.New(), uuid.New()
	now := time.Now().UTC()
	repo := &runnerEnrollmentStub{enrollment: sandboxes.RunnerEnrollment{ID: uuid.New(), ProfileID: uuid.New(), Name: "customer runner", State: "awaiting_install", CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), BlockedReasons: []string{}, InstallCommand: "public install command"}}
	principal := &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleAdmin}}
	wakes := 0
	handler := runnerEnrollmentRouter(t, repo, org, &principal, func() { wakes++ })
	path := "/api/v1/organizations/" + org.String() + "/sandbox-runner-enrollments"
	intent := map[string]any{"name": "customer runner", "profile_id": repo.enrollment.ProfileID, "idempotency_key": uuid.New()}
	first := runnerEnrollmentRequestFor(t, handler, "POST", path, intent)
	replay := runnerEnrollmentRequestFor(t, handler, "POST", path, intent)
	for _, rr := range []*httptest.ResponseRecorder{first, replay} {
		if rr.Code != 201 || rr.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%d %s", rr.Code, rr.Body.String())
		}
	}
	if !strings.Contains(first.Body.String(), "bootstrap_token") || strings.Contains(replay.Body.String(), "bootstrap_token") || repo.org != org || repo.actor != user {
		t.Fatal("one-time secret or actor binding lost")
	}
	repo.trial = &sandboxes.RunnerQualificationTrial{ID: uuid.New(), EnrollmentID: repo.enrollment.ID, State: "awaiting_expiry", Phase: "offline_expiry", BlockedReasons: []string{}, Phases: []sandboxes.RunnerQualificationTrialPhase{}}
	read := runnerEnrollmentRequestFor(t, handler, "GET", path+"/"+repo.enrollment.ID.String(), nil)
	if read.Code != 200 || !strings.Contains(read.Body.String(), "qualification_trial") || strings.Contains(read.Body.String(), "bootstrap_token") {
		t.Fatalf("canonical reload progress missing: %d %s", read.Code, read.Body.String())
	}
	repo.latestError = sandboxes.ErrConflict
	failed := runnerEnrollmentRequestFor(t, handler, "GET", path+"/"+repo.enrollment.ID.String(), nil)
	if failed.Code < 400 {
		t.Fatal("failed canonical trial read returned stale success")
	}
	repo.latestError = nil
	revoked := runnerEnrollmentRequestFor(t, handler, "DELETE", path+"/"+repo.enrollment.ID.String(), nil)
	if revoked.Code != 200 || !strings.Contains(revoked.Body.String(), "pending_cleanup") || repo.revoked != 1 || wakes != 1 {
		t.Fatalf("revocation misreported: %d %s wakes=%d", revoked.Code, revoked.Body.String(), wakes)
	}
}

func TestRunnerEnrollmentGeneratedBootstrapBodyOnlyAndBounded(t *testing.T) {
	org := uuid.New()
	repo := &runnerEnrollmentStub{enrollment: sandboxes.RunnerEnrollment{ProfileID: uuid.New()}}
	var principal *authctx.Principal
	handler := runnerEnrollmentRouter(t, repo, org, &principal, nil)
	body := map[string]any{"enrollment_id": uuid.New(), "bootstrap_token": strings.Repeat("t", 43), "certificate_request": "synthetic CSR", "probe_public_key": sandboxFixtureSSHKey}
	rr := runnerEnrollmentRequestFor(t, handler, "POST", "/api/v1/sandbox-runners/bootstrap", body)
	if rr.Code != 200 || repo.redeemed != 1 || rr.Header().Get("Cache-Control") != "no-store" || strings.Contains(rr.Body.String(), "bootstrap_token") {
		t.Fatalf("public body bootstrap failed: %d %s", rr.Code, rr.Body.String())
	}
	before := repo.calls
	for _, path := range []string{"/api/v1/sandbox-runners/bootstrap?bootstrap_token=forbidden", "/api/v1/organizations/" + org.String() + "/sandbox-runner-enrollments?token=forbidden"} {
		rr = runnerEnrollmentRequestFor(t, handler, "POST", path, body)
		if rr.Code != 400 || repo.calls != before {
			t.Fatal("URL credential accepted", rr.Code)
		}
	}
	body["certificate_request"] = strings.Repeat("x", 20000)
	rr = runnerEnrollmentRequestFor(t, handler, "POST", "/api/v1/sandbox-runners/bootstrap", body)
	if rr.Code < 400 || repo.calls != before {
		t.Fatal("oversize credential body reached service", rr.Code)
	}
	body["certificate_request"] = "synthetic CSR"
	body["private_key"] = "must not be accepted"
	rr = runnerEnrollmentRequestFor(t, handler, "POST", "/api/v1/sandbox-runners/bootstrap", body)
	if rr.Code < 400 || repo.calls != before {
		t.Fatal("unrecognized private material reached service", rr.Code)
	}
}

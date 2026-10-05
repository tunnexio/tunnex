package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
)

type sandboxRunnerEnrollmentRepository interface {
	List(context.Context, uuid.UUID, uuid.UUID) (sandboxes.RunnerEnrollmentList, error)
	Issue(context.Context, uuid.UUID, uuid.UUID, sandboxes.RunnerEnrollmentCreate) (sandboxes.RunnerEnrollmentIssue, error)
	Get(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (sandboxes.RunnerEnrollment, error)
	Revoke(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (sandboxes.RunnerEnrollment, error)
	ReviewQualification(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, sandboxes.RunnerQualificationReview) (sandboxes.RunnerQualificationRecord, error)
	Redeem(context.Context, uuid.UUID, string, sandboxes.RunnerRedeemInput) (sandboxes.RunnerEnrollmentBundle, error)
}

type sandboxRunnerQualificationRepository interface {
	BeginQualification(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, sandboxes.RunnerQualificationTrialInput) (sandboxes.RunnerQualificationTrial, bool, error)
	StatusQualification(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) (sandboxes.RunnerQualificationTrial, error)
	LatestQualificationTrial(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (sandboxes.RunnerQualificationTrial, error)
}

func sandboxRunnerEnrollmentActor(ctx context.Context, org uuid.UUID) (context.Context, uuid.UUID, error) {
	ctx, err := authorize(ctx, org, rbac.PermSandboxRunnerManage)
	if err != nil {
		return ctx, uuid.Nil, err
	}
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok || p.IsMachine() || p.IsAgent() || p.UserID == uuid.Nil {
		return ctx, uuid.Nil, apierr.New(403, "forbidden", "human runner administration required")
	}
	return ctx, p.UserID, nil
}

func (s apiServer) runnerEnrollmentRepository() (sandboxRunnerEnrollmentRepository, error) {
	if s.runnerEnrollment == nil {
		return nil, apierr.New(503, "sandbox_runner_enrollment_unavailable", "Runner enrollment is unavailable. Configure the supported installer distribution and approved runtime profile.")
	}
	return s.runnerEnrollment, nil
}

// Domain wire DTOs and generated response models share the OpenAPI contract.
// Conversion failure is an internal error, never a partial credential response.
func runnerEnrollmentAPI[T any](value any) (T, error) {
	var result T
	body, err := json.Marshal(value)
	if err == nil {
		err = json.Unmarshal(body, &result)
	}
	if err != nil {
		return result, apierr.Internal()
	}
	return result, nil
}

func (s apiServer) ListSandboxRunnerEnrollments(ctx context.Context, req api.ListSandboxRunnerEnrollmentsRequestObject) (api.ListSandboxRunnerEnrollmentsResponseObject, error) {
	ctx, actor, err := sandboxRunnerEnrollmentActor(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	repo, err := s.runnerEnrollmentRepository()
	if err != nil {
		return nil, err
	}
	result, err := repo.List(ctx, req.OrgId, actor)
	if err != nil {
		return nil, sandboxError(err)
	}
	body, err := runnerEnrollmentAPI[api.SandboxRunnerEnrollmentList](result)
	if err != nil {
		return nil, err
	}
	for i, enrollment := range result.Enrollments {
		body.Enrollments[i], err = s.runnerEnrollmentView(ctx, req.OrgId, actor, enrollment)
		if err != nil {
			return nil, err
		}
	}
	return api.ListSandboxRunnerEnrollments200JSONResponse{Body: body, Headers: api.ListSandboxRunnerEnrollments200ResponseHeaders{XRequestId: reqID(ctx)}}, err
}

func (s apiServer) CreateSandboxRunnerEnrollment(ctx context.Context, req api.CreateSandboxRunnerEnrollmentRequestObject) (api.CreateSandboxRunnerEnrollmentResponseObject, error) {
	ctx, actor, err := sandboxRunnerEnrollmentActor(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	repo, err := s.runnerEnrollmentRepository()
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.IdempotencyKey == uuid.Nil || req.Body.ProfileId == uuid.Nil || len(req.Body.Name) > 80 || strings.TrimSpace(req.Body.Name) == "" {
		return nil, apierr.BadRequest("invalid_runner_enrollment", "A runner name, approved profile and idempotency key are required.")
	}
	result, err := repo.Issue(ctx, req.OrgId, actor, sandboxes.RunnerEnrollmentCreate{ProfileID: req.Body.ProfileId, Name: req.Body.Name, IdempotencyKey: req.Body.IdempotencyKey})
	if err != nil {
		return nil, sandboxError(err)
	}
	body, err := runnerEnrollmentAPI[api.SandboxRunnerEnrollmentIssue](result)
	if err != nil {
		return nil, err
	}
	body.Enrollment, err = s.runnerEnrollmentView(ctx, req.OrgId, actor, result.Enrollment)
	return api.CreateSandboxRunnerEnrollment201JSONResponse{Body: body, Headers: api.CreateSandboxRunnerEnrollment201ResponseHeaders{XRequestId: reqID(ctx)}}, err
}

func (s apiServer) GetSandboxRunnerEnrollment(ctx context.Context, req api.GetSandboxRunnerEnrollmentRequestObject) (api.GetSandboxRunnerEnrollmentResponseObject, error) {
	ctx, actor, err := sandboxRunnerEnrollmentActor(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	repo, err := s.runnerEnrollmentRepository()
	if err != nil {
		return nil, err
	}
	result, err := repo.Get(ctx, req.OrgId, actor, req.EnrollmentId)
	if err != nil {
		return nil, sandboxError(err)
	}
	body, err := s.runnerEnrollmentView(ctx, req.OrgId, actor, result)
	return api.GetSandboxRunnerEnrollment200JSONResponse{Body: body, Headers: api.GetSandboxRunnerEnrollment200ResponseHeaders{XRequestId: reqID(ctx)}}, err
}

func (s apiServer) RevokeSandboxRunnerEnrollment(ctx context.Context, req api.RevokeSandboxRunnerEnrollmentRequestObject) (api.RevokeSandboxRunnerEnrollmentResponseObject, error) {
	ctx, actor, err := sandboxRunnerEnrollmentActor(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	repo, err := s.runnerEnrollmentRepository()
	if err != nil {
		return nil, err
	}
	result, err := repo.Revoke(ctx, req.OrgId, actor, req.EnrollmentId)
	if err != nil {
		return nil, sandboxError(err)
	}
	if s.sandboxWake != nil {
		s.sandboxWake()
	}
	body, err := s.runnerEnrollmentView(ctx, req.OrgId, actor, result)
	return api.RevokeSandboxRunnerEnrollment200JSONResponse{Body: body, Headers: api.RevokeSandboxRunnerEnrollment200ResponseHeaders{XRequestId: reqID(ctx)}}, err
}

func (s apiServer) BootstrapSandboxRunner(ctx context.Context, req api.BootstrapSandboxRunnerRequestObject) (api.BootstrapSandboxRunnerResponseObject, error) {
	repo, err := s.runnerEnrollmentRepository()
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.EnrollmentId == uuid.Nil || len(req.Body.BootstrapToken) < 32 || len(req.Body.BootstrapToken) > 128 || len(req.Body.CertificateRequest) > 4096 || len(req.Body.ProbePublicKey) > 1024 {
		return nil, apierr.BadRequest("invalid_runner_bootstrap", "Invalid runner bootstrap request.")
	}
	result, err := repo.Redeem(ctx, req.Body.EnrollmentId, req.Body.BootstrapToken, sandboxes.RunnerRedeemInput{CertificateRequest: req.Body.CertificateRequest, ProbePublicKey: req.Body.ProbePublicKey})
	if err != nil {
		return nil, sandboxError(err)
	}
	body, err := runnerEnrollmentAPI[api.SandboxRunnerBootstrapResponse](result)
	return api.BootstrapSandboxRunner200JSONResponse{Body: body, Headers: api.BootstrapSandboxRunner200ResponseHeaders{XRequestId: reqID(ctx)}}, err
}

func (s apiServer) ReviewSandboxRunnerQualification(ctx context.Context, req api.ReviewSandboxRunnerQualificationRequestObject) (api.ReviewSandboxRunnerQualificationResponseObject, error) {
	ctx, actor, err := sandboxRunnerEnrollmentActor(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	repo, err := s.runnerEnrollmentRepository()
	if err != nil {
		return nil, err
	}
	if req.Body == nil || len(req.Body.ExpectedReportSha256) != 64 || len(req.Body.ReviewNote) > 512 || strings.TrimSpace(req.Body.ReviewNote) == "" {
		return nil, apierr.BadRequest("invalid_runner_qualification_review", "An exact report hash and review note are required.")
	}
	if _, err = repo.ReviewQualification(ctx, req.OrgId, actor, req.EnrollmentId, sandboxes.RunnerQualificationReview{ExpectedReportSHA256: req.Body.ExpectedReportSha256, Decision: string(req.Body.Decision), ReviewNote: req.Body.ReviewNote}); err != nil {
		return nil, sandboxError(err)
	}
	result, err := repo.Get(ctx, req.OrgId, actor, req.EnrollmentId)
	if err != nil {
		return nil, sandboxError(err)
	}
	body, err := s.runnerEnrollmentView(ctx, req.OrgId, actor, result)
	return api.ReviewSandboxRunnerQualification200JSONResponse{Body: body, Headers: api.ReviewSandboxRunnerQualification200ResponseHeaders{XRequestId: reqID(ctx)}}, err
}

// Latest trial progress is read from the canonical service, never browser state.
// A failed read removes confidence in readiness instead of returning stale data.
func (s apiServer) runnerEnrollmentView(ctx context.Context, org, actor uuid.UUID, enrollment sandboxes.RunnerEnrollment) (api.SandboxRunnerEnrollment, error) {
	body, err := runnerEnrollmentAPI[api.SandboxRunnerEnrollment](enrollment)
	if err != nil || s.runnerQualification == nil {
		return body, err
	}
	trial, err := s.runnerQualification.LatestQualificationTrial(ctx, org, actor, enrollment.ID)
	if errors.Is(err, sandboxes.ErrNotFound) {
		return body, nil
	}
	if err != nil {
		return body, sandboxError(err)
	}
	view, err := runnerEnrollmentAPI[api.SandboxRunnerQualificationTrial](trial)
	if err == nil {
		body.QualificationTrial = &view
	}
	return body, err
}

func (s apiServer) StartSandboxRunnerQualificationTrial(ctx context.Context, req api.StartSandboxRunnerQualificationTrialRequestObject) (api.StartSandboxRunnerQualificationTrialResponseObject, error) {
	ctx, actor, err := sandboxRunnerEnrollmentActor(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if s.runnerQualification == nil {
		return nil, apierr.New(503, "sandbox_runner_qualification_unavailable", "Configure the bounded runner qualification service before starting a trial.")
	}
	if req.Body == nil || req.Body.IdempotencyKey == uuid.Nil || req.Body.TerminalDeviceId == uuid.Nil || len(req.Body.SshPublicKeys) < 1 || len(req.Body.SshPublicKeys) != 1 {
		return nil, apierr.BadRequest("invalid_runner_qualification_trial", "Select your terminal and public SSH key for the bounded trial.")
	}
	for _, key := range req.Body.SshPublicKeys {
		if len(key) > 4096 {
			return nil, apierr.BadRequest("invalid_runner_qualification_trial", "Invalid public SSH key.")
		}
	}
	trial, _, err := s.runnerQualification.BeginQualification(ctx, req.OrgId, actor, req.EnrollmentId, sandboxes.RunnerQualificationTrialInput{TerminalDeviceID: req.Body.TerminalDeviceId, SSHPublicKeys: req.Body.SshPublicKeys, IdempotencyKey: req.Body.IdempotencyKey})
	if err != nil {
		return nil, sandboxError(err)
	}
	if s.sandboxWake != nil {
		s.sandboxWake()
	}
	body, err := runnerEnrollmentAPI[api.SandboxRunnerQualificationTrial](trial)
	return api.StartSandboxRunnerQualificationTrial202JSONResponse{Body: body, Headers: api.StartSandboxRunnerQualificationTrial202ResponseHeaders{XRequestId: reqID(ctx)}}, err
}

func (s apiServer) GetSandboxRunnerQualificationTrial(ctx context.Context, req api.GetSandboxRunnerQualificationTrialRequestObject) (api.GetSandboxRunnerQualificationTrialResponseObject, error) {
	ctx, actor, err := sandboxRunnerEnrollmentActor(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if s.runnerQualification == nil {
		return nil, apierr.New(503, "sandbox_runner_qualification_unavailable", "Runner qualification is unavailable.")
	}
	trial, err := s.runnerQualification.StatusQualification(ctx, req.OrgId, actor, req.EnrollmentId, req.TrialId)
	if err != nil {
		return nil, sandboxError(err)
	}
	body, err := runnerEnrollmentAPI[api.SandboxRunnerQualificationTrial](trial)
	return api.GetSandboxRunnerQualificationTrial200JSONResponse{Body: body, Headers: api.GetSandboxRunnerQualificationTrial200ResponseHeaders{XRequestId: reqID(ctx)}}, err
}

// Bootstrap secrets are body-only and all enrollment responses are uncached.
// Apply the size bound before generated JSON validation or decoding.
func runnerEnrollmentRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "/sandbox-runner-enrollments") || req.URL.Path == "/api/v1/sandbox-runners/bootstrap" {
			w.Header().Set("Cache-Control", "no-store")
			if req.URL.RawQuery != "" {
				apierr.Write(w, req, apierr.BadRequest("invalid_runner_enrollment", "Runner enrollment does not accept URL parameters."))
				return
			}
			req.Body = http.MaxBytesReader(w, req.Body, 16384)
		}
		next.ServeHTTP(w, req)
	})
}

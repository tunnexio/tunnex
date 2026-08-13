package http

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

// S5.1 CLI credential flow. Auth contracts (relied on by the 401-walk and the
// verified-gate): CliAuthorize + CliDeviceApprove are cookie-session-only in
// the SPEC and verified-gated here; list/revoke accept any authenticated
// principal (self-scoped, logout-class); token/device-start/device-token are
// public (the CLI holds nothing yet).

// CliAuthorize POST /api/v1/auth/cli/authorize — mints the one-time loopback
// code (browser consent leg; the SPA calls this ONLY on the consent click).
func (s apiServer) CliAuthorize(ctx context.Context, req api.CliAuthorizeRequestObject) (api.CliAuthorizeResponseObject, error) {
	p, err := requireVerifiedSessionUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	code, expiresIn, err := s.cliAuth.MintAuthCode(ctx, p.UserID, req.Body.RedirectUri, req.Body.CodeChallenge)
	if err != nil {
		return nil, err
	}
	return api.CliAuthorize200JSONResponse{
		Body:    api.CliAuthorizeResult{Code: code, State: req.Body.State, ExpiresIn: expiresIn},
		Headers: api.CliAuthorize200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// CliToken POST /api/v1/auth/cli/token — public code→credential exchange.
func (s apiServer) CliToken(ctx context.Context, req api.CliTokenRequestObject) (api.CliTokenResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	cred, err := s.cliAuth.ExchangeCode(ctx, req.Body.Code, req.Body.CodeVerifier, req.Body.RedirectUri)
	if err != nil {
		return nil, err
	}
	return api.CliToken200JSONResponse{
		Body:    api.CliCredentialGrant{Token: cred.Token, ExpiresAt: cred.ExpiresAt, Fingerprint: cred.Fingerprint},
		Headers: api.CliToken200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// ListCliCredentials GET /api/v1/auth/cli/credentials — self-scoped metadata.
func (s apiServer) ListCliCredentials(ctx context.Context, _ api.ListCliCredentialsRequestObject) (api.ListCliCredentialsResponseObject, error) {
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required")
	}
	rows, err := s.cliAuth.List(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	out := make([]api.CliCredential, 0, len(rows))
	for _, c := range rows {
		item := api.CliCredential{
			Id: c.ID, Name: c.Name, Fingerprint: c.Fingerprint,
			CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt,
		}
		if c.LastUsedAt.Valid {
			t := c.LastUsedAt.Time
			item.LastUsedAt = &t
		}
		out = append(out, item)
	}
	return api.ListCliCredentials200JSONResponse{
		Body:    out,
		Headers: api.ListCliCredentials200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// RevokeCliCredential DELETE /api/v1/auth/cli/credentials/{credentialId} —
// self-scoped, idempotent, allowed unverified (logout-class).
func (s apiServer) RevokeCliCredential(ctx context.Context, req api.RevokeCliCredentialRequestObject) (api.RevokeCliCredentialResponseObject, error) {
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required")
	}
	if err := s.cliAuth.Revoke(ctx, p.UserID, req.CredentialId); err != nil {
		return nil, err
	}
	return api.RevokeCliCredential204Response{
		Headers: api.RevokeCliCredential204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// CliDeviceStart POST /api/v1/auth/cli/device — public device-flow start.
func (s apiServer) CliDeviceStart(ctx context.Context, _ api.CliDeviceStartRequestObject) (api.CliDeviceStartResponseObject, error) {
	d, err := s.cliAuth.StartDevice(ctx)
	if err != nil {
		return nil, err
	}
	return api.CliDeviceStart200JSONResponse{
		Body: api.CliDeviceStartResult{
			DeviceCode: d.DeviceCode, UserCode: d.UserCode,
			VerificationUri: s.appBaseURL + "/cli-device",
			Interval:        d.Interval, ExpiresIn: d.ExpiresIn,
		},
		Headers: api.CliDeviceStart200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// CliDeviceApprove POST /api/v1/auth/cli/device/approve — the human checkpoint.
func (s apiServer) CliDeviceApprove(ctx context.Context, req api.CliDeviceApproveRequestObject) (api.CliDeviceApproveResponseObject, error) {
	p, err := requireVerifiedSessionUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if err := s.cliAuth.ApproveDevice(ctx, p.UserID, req.Body.UserCode); err != nil {
		return nil, err
	}
	return api.CliDeviceApprove200JSONResponse{
		Body:    api.GenericMessage{Message: "Approved — the CLI will receive its credential."},
		Headers: api.CliDeviceApprove200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// CliDeviceToken POST /api/v1/auth/cli/device/token — public polling exchange.
func (s apiServer) CliDeviceToken(ctx context.Context, req api.CliDeviceTokenRequestObject) (api.CliDeviceTokenResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	cred, err := s.cliAuth.PollDevice(ctx, req.Body.DeviceCode)
	if err != nil {
		return nil, err
	}
	return api.CliDeviceToken200JSONResponse{
		Body:    api.CliCredentialGrant{Token: cred.Token, ExpiresAt: cred.ExpiresAt, Fingerprint: cred.Fingerprint},
		Headers: api.CliDeviceToken200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type ipsecSettingsRepository interface {
	Read(context.Context, uuid.UUID) (ipsec.Settings, error)
	Configure(context.Context, uuid.UUID, uuid.UUID, bool, int64) (ipsec.Settings, error)
}

func (s apiServer) GetIPsecSettings(ctx context.Context, req api.GetIPsecSettingsRequestObject) (api.GetIPsecSettingsResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	if s.ipsecSettings == nil {
		return nil, ipsecSettingsError(ipsec.ErrSettingsUnavailable)
	}
	settings, err := s.ipsecSettings.Read(ctx, req.OrgId)
	if err != nil {
		return nil, ipsecSettingsError(err)
	}
	return api.GetIPsecSettings200JSONResponse{Body: api.IPsecSettings{Enabled: settings.Enabled, Revision: settings.Revision}, Headers: api.GetIPsecSettings200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) SetIPsecSettings(ctx context.Context, req api.SetIPsecSettingsRequestObject) (api.SetIPsecSettingsResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermIPsecManage)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.ExpectedRevision < 0 {
		return nil, ipsecSettingsError(ipsec.ErrSettingsInvalid)
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if p.UserID == uuid.Nil || p.IsMachine() {
		return nil, apierr.Forbidden("forbidden", "a verified user is required to configure IPsec")
	}
	if s.ipsecSettings == nil {
		return nil, ipsecSettingsError(ipsec.ErrSettingsUnavailable)
	}
	settings, err := s.ipsecSettings.Configure(ctx, req.OrgId, p.UserID, req.Body.Enabled, req.Body.ExpectedRevision)
	if err != nil {
		return nil, ipsecSettingsError(err)
	}
	return api.SetIPsecSettings200JSONResponse{Body: api.IPsecSettings{Enabled: settings.Enabled, Revision: settings.Revision}, Headers: api.SetIPsecSettings200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func ipsecSettingsError(err error) error {
	switch {
	case errors.Is(err, ipsec.ErrSettingsOrgUnavailable):
		return apierr.NotFound("org_not_found", "organization not found")
	case errors.Is(err, ipsec.ErrSettingsConflict):
		return apierr.Conflict("ipsec_settings_conflict", "IPsec settings changed; refresh and retry")
	case errors.Is(err, ipsec.ErrSettingsInvalid):
		return apierr.BadRequest("invalid_ipsec_settings", "enabled and a nonnegative expected_revision are required")
	default:
		return apierr.New(http.StatusInternalServerError, "ipsec_settings_unavailable", "IPsec settings are unavailable")
	}
}

// Validation middleware runs before Chi resolves its route pattern.
func isIPsecSettingsRequest(r *http.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	return (r.Method == http.MethodGet || r.Method == http.MethodPut) && len(parts) == 6 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "organizations" && parts[4] == "ipsec" && parts[5] == "settings"
}

// Both the schema validator and generated decoder accept a first JSON value;
// reject trailing content before either can accept a mutation.
func validateIPsecSettingsBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isIPsecSettingsRequest(r) || r.Method != http.MethodPut {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128*1024))
		if err != nil || !json.Valid(body) {
			apierr.Write(w, r, apierr.BadRequest("invalid_ipsec_settings", "invalid IPsec settings request"))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

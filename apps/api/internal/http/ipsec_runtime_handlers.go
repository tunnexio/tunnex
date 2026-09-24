package http

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

type ipsecRuntimeRepository interface {
	SetIntent(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64, string) (ipsec.Connection, error)
}

func (s apiServer) SetIPsecConnectionIntent(ctx context.Context, req api.SetIPsecConnectionIntentRequestObject) (api.SetIPsecConnectionIntentResponseObject, error) {
	ctx, err := authorizeIPsecConfigurationCheck(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	revision, ok := connectionRevision(req.Params.IfMatch)
	if !ok || req.Body == nil || (req.Body.Intent != api.IPsecIntentEnabled && req.Body.Intent != api.IPsecIntentDisabled) {
		return nil, ipsecProviderError(ipsec.ErrConnectionInvalid)
	}
	if s.ipsecRuntime == nil {
		return nil, ipsecProviderError(ipsec.ErrConnectionUnavailable)
	}
	principal, _ := authctx.PrincipalFrom(ctx)
	record, err := s.ipsecRuntime.SetIntent(ctx, req.OrgId, principal.UserID, req.ConnectionId, revision, string(req.Body.Intent))
	if err != nil {
		return nil, ipsecProviderError(err)
	}
	return api.SetIPsecConnectionIntent200JSONResponse{Body: publicIPsecConnection(record), Headers: api.SetIPsecConnectionIntent200ResponseHeaders{CacheControl: "no-store", ETag: connectionETag(record.DesiredRevision), XRequestId: reqID(ctx)}}, nil
}
func isIPsecRuntimeIntentRequest(r *http.Request) bool {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	return r.Method == http.MethodPut && len(p) == 8 && p[0] == "api" && p[1] == "v1" && p[2] == "organizations" && p[4] == "ipsec" && p[5] == "connections" && p[7] == "intent"
}
func validateIPsecRuntimeIntent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isIPsecRuntimeIntentRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		org, err := uuid.Parse(parts[3])
		if err != nil {
			apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionInvalid))
			return
		}
		ctx, err := authorizeIPsecConfigurationCheck(r.Context(), org)
		if err != nil {
			apierr.Write(w, r, err)
			return
		}
		r = r.WithContext(ctx)
		headers := r.Header.Values("If-Match")
		if len(headers) != 1 {
			apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionInvalid))
			return
		}
		if _, ok := connectionRevision(headers[0]); !ok {
			apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionInvalid))
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128*1024))
		if err != nil {
			apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionInvalid))
			return
		}
		defer clear(body)
		if !singleUniqueJSON(body) {
			apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionInvalid))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

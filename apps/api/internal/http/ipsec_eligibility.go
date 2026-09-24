package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"net/http"
	"strings"
)

type ipsecEligibilityRepository interface {
	ReadEligibility(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (ipsec.Eligibility, error)
}

func (s apiServer) GetIPsecEligibility(ctx context.Context, r api.GetIPsecEligibilityRequestObject) (api.GetIPsecEligibilityResponseObject, error) {
	ctx, err := authorize(ctx, r.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	if r.Params.SiteId == uuid.Nil || r.Params.GatewayNodeId == uuid.Nil {
		return nil, ipsecProviderError(ipsec.ErrConnectionInvalid)
	}
	if s.ipsecEligibility == nil {
		return nil, ipsecProviderError(ipsec.ErrConnectionUnavailable)
	}
	e, err := s.ipsecEligibility.ReadEligibility(ctx, r.OrgId, r.Params.SiteId, r.Params.GatewayNodeId)
	if err != nil {
		return nil, ipsecProviderError(err)
	}
	return api.GetIPsecEligibility200JSONResponse{Body: api.IPsecEligibility{Eligible: e.Eligible, Reason: api.IPsecEligibilityReason(e.Reason)}, Headers: api.GetIPsecEligibility200ResponseHeaders{CacheControl: "no-store", XRequestId: reqID(ctx)}}, nil
}
func isIPsecEligibilityRequest(r *http.Request) bool {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	return r.Method == http.MethodGet && len(p) == 6 && p[0] == "api" && p[1] == "v1" && p[2] == "organizations" && p[4] == "ipsec" && p[5] == "eligibility"
}
func validateIPsecEligibilityRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isIPsecEligibilityRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		p := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		org, err := uuid.Parse(p[3])
		if err != nil {
			apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionInvalid))
			return
		}
		ctx, err := authorize(r.Context(), org, rbac.PermOrgView)
		if err != nil {
			apierr.Write(w, r, err)
			return
		}
		// Repeated selector values are ambiguous; fail closed before binding.
		for _, key := range []string{"site_id", "gateway_node_id"} {
			if len(r.URL.Query()[key]) != 1 {
				apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionInvalid))
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

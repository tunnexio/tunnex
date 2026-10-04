package http

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
	"github.com/tunnexio/tunnex/apps/api/internal/publicurl"
)

type appDomainRuntime interface {
	Effective(context.Context) (appdomains.Config, error)
}

// Resolve once for the entire request so auth links and SSO callbacks cannot
// observe different domain revisions within one operation.
func appDomainRuntimeMiddleware(store appDomainRuntime) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if store == nil || !strings.HasPrefix(r.URL.Path, "/api/v1/") {
				next.ServeHTTP(w, r)
				return
			}
			lookupContext, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			settings, err := store.Effective(lookupContext)
			cancel()
			if err != nil {
				apierr.Write(w, r, apierr.New(http.StatusServiceUnavailable, "app_domains_unavailable", "Public address settings are unavailable. Try again."))
				return
			}
			next.ServeHTTP(w, r.WithContext(publicurl.With(r.Context(), settings.PortalURL)))
		})
	}
}

func (s apiServer) publicURL(ctx context.Context) string {
	return publicurl.From(ctx, s.appBaseURL)
}

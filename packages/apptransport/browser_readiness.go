package apptransport

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
)

const BrowserReadinessPath = "/__tunnex_app/readiness-origin"

// BrowserReadiness handles a diagnostic stream only. Pending assignments must
// never install BrowserOrigin or forward arbitrary requests to application data.
func BrowserReadiness(binding Binding, operationID, requestID string, deadline time.Time, check func(context.Context) originpolicy.Result, slots chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refused := func() { http.Error(w, "Application unavailable", http.StatusForbidden) }
		if binding.Purpose != "browser_proxy" || binding.ValidateHeaders(r.Header) != nil || r.Host != binding.Hostname || r.Method != "GET" || r.URL.IsAbs() || r.URL.Host != "" || r.URL.Path != BrowserReadinessPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Header.Values("Upgrade")) != 0 || len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("X-App-Readiness-ID")) != 1 || r.Header.Get("X-App-Readiness-ID") != requestID || len(r.Header.Values("X-App-Operation-ID")) != 1 || r.Header.Get("X-App-Operation-ID") != operationID || requestID == "" || operationID == "" || !deadline.After(time.Now()) {
			refused()
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			refused()
			return
		}
		ctx, cancel := context.WithDeadline(r.Context(), deadline)
		defer cancel()
		ctx, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		result := check(ctx)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Connection", "close")
		_ = json.NewEncoder(w).Encode(result)
	})
}

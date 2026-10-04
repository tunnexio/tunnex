package proxy

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Operational is a separate operator listener. It never includes request paths,
// origins, hosts, organization/user/application IDs, cookies or credentials.
type Operational struct {
	Handler   *Handler
	Readiness *ReadinessWorker
	Draining  atomic.Bool
}

func (o *Operational) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != "GET" || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "Unavailable", 404)
		return
	}
	switch r.URL.Path {
	case "/livez":
		if o.Draining.Load() {
			http.Error(w, "Draining", 503)
			return
		}
		_, _ = fmt.Fprintln(w, "OK")
	case "/readyz":
		if o.Draining.Load() || o.Readiness == nil || !o.Readiness.authorityHealthy() {
			http.Error(w, "Unavailable", 503)
			return
		}
		_, _ = fmt.Fprintln(w, "OK")
	case "/metrics":
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if o.Handler == nil || o.Handler.Broker == nil {
			http.Error(w, "Unavailable", 503)
			return
		}
		h := o.Handler
		h.mu.Lock()
		active := h.counts["global"]
		h.mu.Unlock()
		pool := h.Broker.Capacity()
		ready := 0
		if !o.Draining.Load() && o.Readiness != nil && o.Readiness.authorityHealthy() {
			ready = 1
		}
		challenges := 0
		if o.Readiness != nil {
			o.Readiness.mu.Lock()
			challenges = len(o.Readiness.challenges)
			o.Readiness.mu.Unlock()
		}
		for _, gauge := range []struct {
			name  string
			value int
		}{{"ready", ready}, {"active_requests", active}, {"request_limit", 256}, {"request_authority_callbacks", len(h.callbacks)}, {"request_authority_callback_limit", 128}, {"termination_callbacks", len(h.terminationCallbacks)}, {"termination_callback_limit", 128}, {"channel_connections", pool.Connections}, {"channel_active", pool.Active}, {"channel_ready", pool.Ready}, {"channel_pending_admissions", pool.PendingAdmissions}, {"channel_limit", 128}, {"channel_authority_callbacks", pool.AuthorityCallbacks}, {"channel_authority_callback_limit", 128}, {"readiness_challenges", challenges}, {"readiness_limit", 8}} {
			_, _ = fmt.Fprintf(w, "# TYPE tunnex_app_proxy_%s gauge\ntunnex_app_proxy_%s %d\n", gauge.name, gauge.name, gauge.value)
		}
		fmt.Fprintf(w, "# TYPE tunnex_app_proxy_channel_admission_saturated_total counter\ntunnex_app_proxy_channel_admission_saturated_total %d\n", pool.AdmissionSaturated)
		h.metrics.write(w)
	default:
		http.Error(w, "Unavailable", 404)
	}
}
func (w *ReadinessWorker) authorityHealthy() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.lastClaimSuccess.IsZero() && time.Since(w.lastClaimSuccess) <= 6*time.Second
}

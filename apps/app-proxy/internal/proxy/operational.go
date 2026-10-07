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
	// AuthorityReady is used by Beam's separately scoped authority client.
	AuthorityReady func() bool
	// Beam exposes only the minimum serving-certificate deadline, never identities.
	CertificateExpiresAt time.Time
	Draining             atomic.Bool
}

func (o *Operational) ready() bool {
	if o.Draining.Load() {
		return false
	}
	if o.Readiness != nil {
		return o.Readiness.authorityHealthy()
	}
	return o.AuthorityReady != nil && o.AuthorityReady()
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
		if !o.ready() {
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
		if o.ready() {
			ready = 1
		}
		challenges := 0
		if o.Readiness != nil {
			o.Readiness.mu.Lock()
			challenges = len(o.Readiness.challenges)
			o.Readiness.mu.Unlock()
		}
		prefix := "tunnex_app_proxy"
		if h.beam {
			prefix = "tunnex_beam_proxy"
			if !o.CertificateExpiresAt.IsZero() {
				fmt.Fprintf(w, "# TYPE %s_tls_seconds_until_expiry gauge\n%s_tls_seconds_until_expiry %g\n", prefix, prefix, time.Until(o.CertificateExpiresAt).Seconds())
			}
		}
		for _, gauge := range []struct {
			name  string
			value int
		}{{"ready", ready}, {"active_requests", active}, {"request_limit", 256}, {"request_authority_callbacks", len(h.callbacks)}, {"request_authority_callback_limit", 128}, {"termination_callbacks", len(h.terminationCallbacks)}, {"termination_callback_limit", 128}, {"channel_connections", pool.Connections}, {"channel_active", pool.Active}, {"channel_ready", pool.Ready}, {"channel_pending_admissions", pool.PendingAdmissions}, {"channel_limit", 128}, {"channel_authority_callbacks", pool.AuthorityCallbacks}, {"channel_authority_callback_limit", 128}, {"readiness_challenges", challenges}, {"readiness_limit", 8}} {
			_, _ = fmt.Fprintf(w, "# TYPE %s_%s gauge\n%s_%s %d\n", prefix, gauge.name, prefix, gauge.name, gauge.value)
		}
		if h.beam {
			for _, gauge := range []struct {
				name  string
				value int
			}{{"organization_channel_limit", 64}, {"share_channel_limit", 34}, {"organization_request_limit", 64}} {
				_, _ = fmt.Fprintf(w, "# TYPE %s_%s gauge\n%s_%s %d\n", prefix, gauge.name, prefix, gauge.name, gauge.value)
			}
		}
		fmt.Fprintf(w, "# TYPE %s_channel_admission_saturated_total counter\n%s_channel_admission_saturated_total %d\n", prefix, prefix, pool.AdmissionSaturated)
		h.metrics.writePrefix(w, prefix)
	default:
		http.Error(w, "Unavailable", 404)
	}
}
func (w *ReadinessWorker) authorityHealthy() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.lastClaimSuccess.IsZero() && time.Since(w.lastClaimSuccess) <= 6*time.Second
}

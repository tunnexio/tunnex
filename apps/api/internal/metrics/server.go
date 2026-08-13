package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// DefaultAddr is the metrics listener's default bind (S11 D3.2).
//
// LOOPBACK BY DEFAULT, DELIBERATELY. The metrics surface carries operational data about the fleet, and on a
// VM deployment a listener bound to 0.0.0.0 is reachable from the internet the moment a security group is
// loose — an information-disclosure finding that no amount of documentation prevents. The default therefore
// makes public exposure IMPOSSIBLE BY CONSTRUCTION: an operator who wants remote scraping must opt in
// explicitly by setting the address (e.g. a private interface, or 0.0.0.0 inside a k8s pod whose Service is
// not exposed). Documented-against is not the same as impossible; this is the latter.
const DefaultAddr = "127.0.0.1:9090"

// Serve runs the metrics listener on addr until ctx is cancelled. It is a SEPARATE listener from the public
// API (D3.2, the Prometheus convention): operational data never rides the public router, so no
// authentication decision has to be right for it to stay private — the bind address is the control.
//
// It serves exactly two paths:
//   - /metrics — the Prometheus exposition
//   - /readyz  — readiness. The CP previously had only /healthz (liveness); the node-agent already served
//     both. This closes that gap, and D4's leader election will express "follower: serving, not ticking"
//     here rather than inventing a second readiness vocabulary.
//
// Role reports whether this replica currently leads the schedulers. Optional; nil means "not applicable".
type Role func() bool

func Serve(ctx context.Context, addr string, reg *prometheus.Registry, ready func() error, log *slog.Logger, role Role) error {
	if addr == "" {
		addr = DefaultAddr
	}
	if log != nil && isWildcard(addr) {
		// Not refused — a k8s pod legitimately binds 0.0.0.0 behind an unexposed Service — but never silent:
		// an operator who did this by accident on a VM gets a line naming the exposure.
		log.Warn("metrics_listener_wildcard_bind",
			"addr", addr,
			"detail", "metrics are exposed on ALL interfaces; ensure a firewall or an unexposed Service fronts it")
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		// A scrape must never hang the scraper or leak internals into the response body.
		ErrorHandling: promhttp.HTTPErrorOnError,
		Timeout:       10 * time.Second,
	}))
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready != nil {
			if err := ready(); err != nil {
				// Honest readiness: name the reason. A bare 503 tells an operator nothing about which
				// dependency is down, which is the diagnosis-from-logs failure at the readiness tier.
				http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		// ROLE IS REPORTED, NEVER CONFLATED WITH READINESS (S11 D4). A follower SERVES — it is a fully
		// functional API replica that simply does not tick the schedulers — so it is READY. Reporting a
		// follower as not-ready would pull healthy replicas out of a load balancer and turn an HA feature
		// into an outage. The role is surfaced as information for an operator, not as a health verdict.
		body := "ok"
		if role != nil {
			if role() {
				body = "ok leader"
			} else {
				body = "ok follower"
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if log != nil {
		log.Info("metrics_listener_start", "addr", addr, "paths", "/metrics /readyz")
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// isWildcard reports whether addr binds every interface (":9090", "0.0.0.0:9090", "[::]:9090").
func isWildcard(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	return host == "" || host == "0.0.0.0" || host == "::" || host == "[::]"
}

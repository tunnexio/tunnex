package proxy

import (
	"context"
	"fmt"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

var latencyBounds = [...]time.Duration{5 * time.Millisecond, 25 * time.Millisecond, 100 * time.Millisecond, 500 * time.Millisecond, time.Second, 5 * time.Second, 30 * time.Second, 60 * time.Second}

type latencyHistogram struct {
	buckets     [len(latencyBounds) + 1]atomic.Uint64
	count       atomic.Uint64
	nanoseconds atomic.Uint64
}

func (h *latencyHistogram) observe(d time.Duration) {
	if d < 0 {
		return
	}
	h.count.Add(1)
	h.nanoseconds.Add(uint64(d))
	for i, b := range latencyBounds {
		if d <= b {
			h.buckets[i].Add(1)
		}
	}
	h.buckets[len(latencyBounds)].Add(1)
}
func (h *latencyHistogram) write(w io.Writer, name string) {
	fmt.Fprintf(w, "# TYPE %s histogram\n", name)
	for i, b := range latencyBounds {
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", name, b.Seconds(), h.buckets[i].Load())
	}
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n%s_sum %g\n%s_count %d\n", name, h.buckets[len(latencyBounds)].Load(), name, float64(h.nanoseconds.Load())/float64(time.Second), name, h.count.Load())
}

type measurements struct {
	connectorDialFailures   atomic.Uint64
	upstreamFailures        atomic.Uint64
	admissionSaturated      atomic.Uint64
	authoritySaturated      atomic.Uint64
	terminationDropped      atomic.Uint64
	terminationFailed       atomic.Uint64
	terminationAccepted     atomic.Uint64
	upstreamHeaders         latencyHistogram
	originHeaders           latencyHistogram
	originTimingUnavailable atomic.Uint64
	originTimingInvalid     atomic.Uint64
}

func (m *measurements) write(w io.Writer) {
	for _, counter := range []struct {
		name  string
		value uint64
	}{
		{"connector_dial_failures_total", m.connectorDialFailures.Load()},
		{"upstream_roundtrip_failures_total", m.upstreamFailures.Load()},
		{"origin_timing_unavailable_total", m.originTimingUnavailable.Load()},
		{"origin_timing_invalid_total", m.originTimingInvalid.Load()},
		{"request_admission_saturated_total", m.admissionSaturated.Load()},
		{"authority_callback_saturated_total", m.authoritySaturated.Load()},
		{"termination_notifications_dropped_total", m.terminationDropped.Load()},
		{"termination_notifications_failed_total", m.terminationFailed.Load()},
		{"termination_notifications_accepted_total", m.terminationAccepted.Load()},
	} {
		fmt.Fprintf(w, "# TYPE tunnex_app_proxy_%s counter\ntunnex_app_proxy_%s %d\n", counter.name, counter.name, counter.value)
	}
	m.upstreamHeaders.write(w, "tunnex_app_proxy_upstream_response_header_seconds")
	m.originHeaders.write(w, "tunnex_app_proxy_gateway_origin_response_header_seconds")
}

type observedTransport struct {
	base    http.RoundTripper
	metrics *measurements
}

func (t observedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	response, err := t.base.RoundTrip(r)
	if err != nil {
		t.metrics.upstreamFailures.Add(1)
	} else {
		t.metrics.upstreamHeaders.observe(time.Since(start))
	}
	return response, err
}

func (h *Handler) observeOriginHeaders(headers http.Header) {
	values := headers.Values(apptransport.OriginHeaderTiming)
	defer headers.Del(apptransport.OriginHeaderTiming)
	if len(values) == 0 {
		h.metrics.originTimingUnavailable.Add(1)
		return
	}
	if len(values) == 1 {
		if nanos, err := strconv.ParseInt(values[0], 10, 64); err == nil && nanos > 0 && nanos <= int64(60*time.Second) {
			h.metrics.originHeaders.observe(time.Duration(nanos))
			return
		}
	}
	h.metrics.originTimingInvalid.Add(1)
}

func (h *Handler) dialConnector(ctx context.Context, b Binding) (net.Conn, error) {
	conn, err := h.Broker.Dial(ctx, b.Transport())
	if err != nil {
		h.metrics.connectorDialFailures.Add(1)
	}
	return conn, err
}

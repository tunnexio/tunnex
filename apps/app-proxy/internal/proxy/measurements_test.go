package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type measuredTransportFunc func(*http.Request) (*http.Response, error)

func (f measuredTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestMeasurementsObserveHeadersFailuresAndRedact(t *testing.T) {
	h := NewHandler("apps.example.net", nil, apptransport.NewBrowserBroker(nil))
	defer h.Broker.Close()
	success := observedTransport{base: measuredTransportFunc(func(*http.Request) (*http.Response, error) {
		time.Sleep(10 * time.Millisecond)
		return &http.Response{StatusCode: 401}, nil
	}), metrics: &h.metrics}
	_, _ = success.RoundTrip(&http.Request{})
	failure := observedTransport{base: measuredTransportFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("private-origin-token") }), metrics: &h.metrics}
	_, _ = failure.RoundTrip(&http.Request{})
	if h.metrics.upstreamHeaders.count.Load() != 1 || h.metrics.upstreamFailures.Load() != 1 {
		t.Fatal("observed transport outcome incorrect")
	}
	for _, values := range [][]string{nil, {"20000000"}, {"0"}, {"secret"}, {"-1"}, {"60000000001"}, {"1", "2"}} {
		headers := http.Header{apptransport.OriginHeaderTiming: values}
		h.observeOriginHeaders(headers)
		if len(headers) != 0 {
			t.Fatal("internal timing retained")
		}
	}
	if h.metrics.originTimingUnavailable.Load() != 1 || h.metrics.originTimingInvalid.Load() != 5 {
		t.Fatal("missing/invalid timing availability incorrect")
	}
	if h.metrics.originHeaders.count.Load() != 1 || h.metrics.originHeaders.buckets[1].Load() != 1 {
		t.Fatal("malformed timing counted or valid timing missed")
	}
	response := httptest.NewRecorder()
	(&Operational{Handler: h}).ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	body := response.Body.String()
	if !strings.Contains(body, "upstream_roundtrip_failures_total 1") || !strings.Contains(body, "gateway_origin_response_header_seconds_count 1") || strings.Contains(body, "private-origin-token") {
		t.Fatal("incorrect/private metrics")
	}
}

func TestConnectorDialFailureAndAdmissionAreObserved(t *testing.T) {
	broker := apptransport.NewBrowserBroker(nil)
	defer broker.Close()
	h := NewHandler("apps.example.net", nil, broker)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.dialConnector(ctx, Binding{Purpose: "browser_proxy"}); err == nil {
		t.Fatal("unavailable connector accepted")
	}
	if h.metrics.connectorDialFailures.Load() != 1 {
		t.Fatal("dial failure not counted")
	}
	var releases []func()
	for i := 0; i < 16; i++ {
		releases = append(releases, h.reserve(Binding{AppID: "private-app"}, "private-token"))
	}
	if h.reserve(Binding{AppID: "private-app"}, "private-token") != nil || h.metrics.admissionSaturated.Load() != 1 {
		t.Fatal("admission saturation not measured")
	}
	for _, release := range releases {
		release()
	}
}

type failedTermination struct {
	launchAuthority
	called chan struct{}
}

func (a *failedTermination) Terminated(context.Context, authoritywire.AppProxyStreamTerminatedInput) error {
	defer close(a.called)
	return errors.New("private-token")
}
func TestCallbackSaturationAndNotificationFailureCounters(t *testing.T) {
	a := &failedTermination{called: make(chan struct{})}
	h := NewHandler("apps.example.net", a, nil)
	for i := 0; i < cap(h.callbacks); i++ {
		h.callbacks <- struct{}{}
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.Host = "payroll.apps.example.net"
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	h.ServeHTTP(httptest.NewRecorder(), request)
	if h.metrics.authoritySaturated.Load() != 1 {
		t.Fatal("callback saturation not counted")
	}
	h.terminationCallbacks = make(chan struct{}, 1)
	h.terminationCallbacks <- struct{}{}
	h.notifyTerminated(Binding{}, "stream", false)
	if h.metrics.terminationDropped.Load() != 1 {
		t.Fatal("dropped notification not counted")
	}
	<-h.terminationCallbacks
	h.notifyTerminated(Binding{}, "stream", false)
	select {
	case <-a.called:
	case <-time.After(time.Second):
		t.Fatal("notification not called")
	}
	deadline := time.Now().Add(time.Second)
	for h.metrics.terminationFailed.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.metrics.terminationFailed.Load() != 1 || h.metrics.terminationAccepted.Load() != 0 {
		t.Fatal("notification failure falsely accepted")
	}
}

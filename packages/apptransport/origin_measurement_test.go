package apptransport

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

type timingTransportFunc func(*http.Request) (*http.Response, error)

func (f timingTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestOriginTimingOverwritesAllSpoofedValuesAndExcludesBody(t *testing.T) {
	tr := originMeasuredTransport{base: timingTransportFunc(func(*http.Request) (*http.Response, error) {
		time.Sleep(10 * time.Millisecond)
		return &http.Response{StatusCode: 401, Header: http.Header{OriginHeaderTiming: []string{"99999999999999999999", "secret"}}, Body: io.NopCloser(strings.NewReader("ordinary application body"))}, nil
	})}
	response, err := tr.RoundTrip(&http.Request{})
	if err != nil {
		t.Fatal(err)
	}
	values := response.Header.Values(OriginHeaderTiming)
	if len(values) != 1 {
		t.Fatal("spoofed values retained")
	}
	n, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || n < int64(10*time.Millisecond) || n > int64(time.Second) {
		t.Fatal("header duration incorrect")
	}
	StripCredentials(response.Header)
	if len(response.Header.Values(OriginHeaderTiming)) != 0 {
		t.Fatal("internal metric forwarded")
	}
	body, _ := io.ReadAll(response.Body)
	if string(body) != "ordinary application body" {
		t.Fatal("body changed")
	}
}

func TestChannelAdmissionSaturationCounterObserved(t *testing.T) {
	broker := NewBrowserBroker(func(context.Context, Binding, string) (time.Time, error) {
		t.Fatal("saturated channel reached authority")
		return time.Time{}, nil
	})
	defer broker.Close()
	broker.pendingCount = 128
	response := httptest.NewRecorder()
	request := httptest.NewRequest("CONNECT", "/app-access/channel", nil)
	if broker.Accept(response, request, Binding{Purpose: "browser_proxy"}, "serial") == nil || response.Code != 503 {
		t.Fatal("channel bound not refused")
	}
	if broker.Capacity().AdmissionSaturated != 1 {
		t.Fatal("saturated admission not counted")
	}
}

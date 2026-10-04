package apptransport

import (
	"context"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPendingReadinessRejectsArbitraryTrafficAndCorrelation(t *testing.T) {
	binding := Binding{OrgID: "org", GatewayID: "gw", AppID: "app", Generation: "gen", Digest: "digest", Revision: 1, AuthorityVersion: 1, Hostname: "app.apps.example.net", Purpose: "browser_proxy"}
	var calls atomic.Int32
	slots := make(chan struct{}, 1)
	handler := BrowserReadiness(binding, "operation", "request", time.Now().Add(time.Minute), func(context.Context) originpolicy.Result { calls.Add(1); return originpolicy.Result{Status: "ready"} }, slots)
	for _, mode := range []string{"path", "method", "query", "body", "chunked", "operation", "request", "duplicate", "binding", "absolute", "upgrade", "cookie", "authorization"} {
		request := httptest.NewRequest("GET", BrowserReadinessPath, nil)
		request.Host = binding.Hostname
		BindingHeaders(request.Header, binding)
		request.Header.Set("X-App-Operation-ID", "operation")
		request.Header.Set("X-App-Readiness-ID", "request")
		switch mode {
		case "path":
			request.URL.Path = "/private"
		case "method":
			request.Method = "POST"
		case "query":
			request.URL.RawQuery = "x=y"
		case "body":
			request.ContentLength = 1
		case "chunked":
			request.ContentLength = -1
			request.TransferEncoding = []string{"chunked"}
		case "operation":
			request.Header.Set("X-App-Operation-ID", "other")
		case "request":
			request.Header.Set("X-App-Readiness-ID", "other")
		case "duplicate":
			request.Header.Add("X-App-Readiness-ID", "request")
		case "binding":
			request.Header.Set("X-App-Revision", "2")
		case "absolute":
			request.URL.Scheme = "https"
			request.URL.Host = binding.Hostname
		case "cookie":
			request.Header.Set("Cookie", "app=secret")
		case "authorization":
			request.Header.Set("Authorization", "Bearer app-token")
		case "upgrade":
			request.Header.Set("Upgrade", "websocket")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatal(mode, response.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("refused traffic probed origin")
	}
	slots <- struct{}{}
	request := httptest.NewRequest("GET", BrowserReadinessPath, nil)
	request.Host = binding.Hostname
	BindingHeaders(request.Header, binding)
	request.Header.Set("X-App-Operation-ID", "operation")
	request.Header.Set("X-App-Readiness-ID", "request")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 403 || calls.Load() != 0 {
		t.Fatal("full probe capacity bypassed")
	}
	<-slots
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if calls.Load() != 1 || len(slots) != 0 {
		t.Fatal("probe slot not released")
	}
}

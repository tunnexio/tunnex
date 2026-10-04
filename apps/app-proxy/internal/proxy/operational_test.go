package proxy

import (
	"github.com/tunnexio/tunnex/packages/apptransport"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOperationalReadinessAndRedactedCapacity(t *testing.T) {
	broker := apptransport.NewBrowserBroker(nil)
	defer broker.Close()
	handler := NewHandler("apps.secret.example", nil, broker)
	handler.counts = map[string]int{"global": 3, "app:private-org:private-app": 3, "session:private-token": 3}
	worker := &ReadinessWorker{challenges: map[string]readinessChallenge{}}
	operational := &Operational{Handler: handler, Readiness: worker}
	response := httptest.NewRecorder()
	operational.ServeHTTP(response, httptest.NewRequest("GET", "/readyz", nil))
	if response.Code != 503 {
		t.Fatal("ready before authority claim")
	}
	worker.lastClaimSuccess = time.Now()
	response = httptest.NewRecorder()
	operational.ServeHTTP(response, httptest.NewRequest("GET", "/readyz", nil))
	if response.Code != 200 {
		t.Fatal("recent authority unavailable")
	}
	response = httptest.NewRecorder()
	operational.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	body := response.Body.String()
	if !strings.Contains(body, "tunnex_app_proxy_active_requests 3") || !strings.Contains(body, "tunnex_app_proxy_channel_limit 128") {
		t.Fatal("missing bounded capacity gauges")
	}
	for _, secret := range []string{"private-org", "private-app", "private-token", "apps.secret.example", "https://"} {
		if strings.Contains(body, secret) {
			t.Fatal("operational identity/URL leak")
		}
	}
	worker.lastClaimSuccess = time.Now().Add(-7 * time.Second)
	response = httptest.NewRecorder()
	operational.ServeHTTP(response, httptest.NewRequest("GET", "/readyz", nil))
	if response.Code != 503 {
		t.Fatal("stale authority healthy")
	}
	worker.lastClaimSuccess = time.Now()
	operational.Draining.Store(true)
	for _, path := range []string{"/livez", "/readyz"} {
		response = httptest.NewRecorder()
		operational.ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if response.Code != 503 {
			t.Fatal("draining healthy")
		}
	}
}

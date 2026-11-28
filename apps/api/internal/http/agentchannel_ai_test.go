package http

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
)

func TestVPNInferenceRequiresNodeCertificate(t *testing.T) {
	routes := aigateway.VPNInferenceRoutes()
	if len(routes) != 9 {
		t.Fatalf("relayed routes changed: %v", routes)
	}
	for _, route := range routes {
		for _, prefix := range []string{"/agent/ai/organizations/00000000-0000-0000-0000-000000000001", "/agent/ai", "/agent/ai-http", "/agent/ai-http/organizations/00000000-0000-0000-0000-000000000001"} {
			a := &AgentChannel{}
			r := httptest.NewRequest("POST", "https://control"+prefix+route, strings.NewReader(`{}`))
			for _, h := range []string{"Authorization", "X-Tunnex-VPN-IP", "X-Tunnex-VPN-Key", "X-Forwarded-For"} {
				r.Header.Set(h, "forged")
			}
			w := httptest.NewRecorder()
			a.Handler().ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("%s%s: unauthenticated node received %d", prefix, route, w.Code)
			}
		}
	}
	// Video jobs are not relayed.
	w := httptest.NewRecorder()
	(&AgentChannel{}).Handler().ServeHTTP(w, httptest.NewRequest("POST", "https://control/agent/ai/v1/videos", strings.NewReader(`{}`)))
	if w.Code != 404 && w.Code != 405 {
		t.Fatalf("video route registered: %d", w.Code)
	}
}

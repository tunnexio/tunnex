package http

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVPNInferenceRequiresNodeCertificate(t *testing.T) {
	a := &AgentChannel{}
	r := httptest.NewRequest("POST", "https://control/agent/ai/organizations/00000000-0000-0000-0000-000000000001/v1/chat/completions", strings.NewReader(`{}`))
	for _, h := range []string{"Authorization", "X-Tunnex-VPN-IP", "X-Tunnex-VPN-Key", "X-Forwarded-For"} {
		r.Header.Set(h, "forged")
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("unauthenticated node received %d", w.Code)
	}
}

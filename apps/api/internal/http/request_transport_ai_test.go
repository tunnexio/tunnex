package http

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aitransport"
)

// Exercise the real router order: forwarded headers must be validated before
// RealIP or the AI admission gate. Once transport is allowed, authentication
// still refuses this anonymous request with 401.
func TestTrustedRequestTransportControlsAIRouterAdmission(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		peers                       []string
		remote                      string
		proto                       []string
		tls, allowHTTP              bool
		wantStatus, wantPolicyReads int
	}{
		{name: "trusted HTTPS bypasses disabled HTTP", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:80", proto: []string{"https"}, wantStatus: 401},
		{name: "trusted HTTP defaults denied", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:80", proto: []string{"http"}, wantStatus: 403, wantPolicyReads: 1},
		{name: "trusted HTTP explicit opt in retains auth", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:80", proto: []string{"http"}, allowHTTP: true, wantStatus: 401, wantPolicyReads: 1},
		{name: "public peer cannot forge HTTPS", peers: []string{"192.0.2.1"}, remote: "198.51.100.2:80", proto: []string{"https"}, wantStatus: 400},
		{name: "malformed trusted scheme fails before policy", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:80", proto: []string{"https", "http"}, wantStatus: 400},
		{name: "native TLS permitted", peers: []string{"192.0.2.1"}, remote: "198.51.100.2:80", tls: true, wantStatus: 401},
		{name: "TLS proxy hop preserves HTTP denial", peers: []string{"192.0.2.1"}, remote: "192.0.2.1:80", tls: true, proto: []string{"http"}, wantStatus: 403, wantPolicyReads: 1},
		{name: "advertised HTTPS and untrusted headers do not infer TLS", remote: "198.51.100.2:80", proto: []string{"https"}, wantStatus: 403, wantPolicyReads: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &aiTransportStub{value: aitransport.Settings{Revision: 1, AllowHTTP: tc.allowHTTP}}
			h, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{TrustedProxies: tc.peers, AITransport: repo, AppBaseURL: "https://console.example.test"})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://console.example.test/api/v1/organizations/"+uuid.NewString()+"/ai-gateway/providers", nil)
			req.RemoteAddr = tc.remote
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			for _, proto := range tc.proto {
				req.Header.Add("X-Forwarded-Proto", proto)
			}
			req.Header.Set("X-Forwarded-For", "192.0.2.1")
			req.Header.Set("X-Real-IP", "192.0.2.1")
			req.Header.Set("Forwarded", "proto=https;for=192.0.2.1")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus || repo.calls.Load() != int64(tc.wantPolicyReads) {
				t.Fatalf("status=%d policy reads=%d body=%s", rec.Code, repo.calls.Load(), rec.Body.String())
			}
		})
	}
}

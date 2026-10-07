package http

import (
	"crypto/tls"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/beam"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBeamPrivateAuthorityAuthenticatesBeforeBody(t *testing.T) {
	proxy := &denyProxyAuthority{}
	service := beam.New(nil, beam.Config{BaseDomain: "beam.example.net", PortalURL: "https://console.other.org"}, nil, nil)
	h := NewBeamProxyAuthorityHandler(service, proxy, http.NotFoundHandler())
	for _, tc := range []struct {
		name, method, auth, body string
		tls                      uint16
		status                   int
	}{
		{"noTLS", "POST", "AppProxy " + appaccess.ProxyTokenPrefix + strings.Repeat("a", 43), "malformed", 0, 401},
		{"oldTLS", "POST", "AppProxy " + appaccess.ProxyTokenPrefix + strings.Repeat("a", 43), "malformed", tls.VersionTLS12, 401},
		{"cookieisnotproxy", "POST", "Bearer human", "malformed", tls.VersionTLS13, 401},
		{"authenticatedstrictbody", "POST", "AppProxy " + appaccess.ProxyTokenPrefix + strings.Repeat("a", 43), `{"caller_override":true}`, tls.VersionTLS13, 400},
		{"oversizedbody", "POST", "AppProxy " + appaccess.ProxyTokenPrefix + strings.Repeat("a", 43), strings.Repeat(" ", 33000) + `{}`, tls.VersionTLS13, 413},
		{"unknownmethod", "GET", "AppProxy " + appaccess.ProxyTokenPrefix + strings.Repeat("a", 43), "", tls.VersionTLS13, 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/internal/beam/domains", strings.NewReader(tc.body))
			if tc.tls != 0 {
				r.TLS = &tls.ConnectionState{Version: tc.tls}
			}
			r.Header.Set("Authorization", tc.auth)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("got%d want%d body%s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}

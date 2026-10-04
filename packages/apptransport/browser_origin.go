package apptransport

import (
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
)

// BrowserOrigin serves only a proxy-authorized browser channel's immutable
// assignment. It is installed on an outbound stream, never an inbound listener.
// The channel broker and public proxy enforce current route/session leases.
func BrowserOrigin(binding Binding, transport *originpolicy.Transport) http.Handler {
	reverse := &httputil.ReverseProxy{Transport: originMeasuredTransport{base: transport}, FlushInterval: -1, Rewrite: func(p *httputil.ProxyRequest) {
		// Keep only forwarding metadata constructed by the trusted public proxy.
		forwardedFor := p.In.Header.Get("X-Forwarded-For")
		StripCredentials(p.Out.Header)
		p.Out.Header.Set("X-Forwarded-For", forwardedFor)
		p.Out.Header.Set("X-Forwarded-Host", binding.Hostname)
		p.Out.Header.Set("X-Forwarded-Proto", "https")
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "Application unavailable", http.StatusBadGateway)
	}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if binding.Purpose != "browser_proxy" || binding.Hostname == "" || binding.AuthorityVersion < 1 || binding.ValidateHeaders(r.Header) != nil || r.Host != binding.Hostname || r.Method == "CONNECT" || r.Method == "TRACE" || len(r.Header.Values("X-App-Stream-ID")) != 1 || r.Header.Get("X-App-Stream-ID") == "" || len(r.Header.Get("X-App-Stream-ID")) > 128 || r.ContentLength > 64<<20 || strings.Contains(r.Header.Get("X-Forwarded-For"), "\n") {
			http.Error(w, "Application unavailable", http.StatusForbidden)
			return
		}
		if _, err := RelativeTarget(r.URL); err != nil {
			http.Error(w, "Application unavailable", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
		reverse.ServeHTTP(w, r)
	})
}

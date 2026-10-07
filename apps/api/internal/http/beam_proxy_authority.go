package http

import (
	"crypto/tls"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/beam"
	"net/http"
	"strings"
)

func NewBeamProxyAuthorityHandler(service *beam.Service, proxies appProxyAuthorityPort, fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/internal/beam/") {
			fallback.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		unauth := func() { apierr.Write(w, r, apierr.New(401, "proxy_unauthenticated", "Proxy authentication required")) }
		if service == nil || proxies == nil || r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "AppProxy ") {
			unauth()
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "AppProxy ")
		if _, e := proxies.AuthenticateProxy(r.Context(), token); e != nil {
			unauth()
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		var result any
		var e error
		ctx := r.Context()
		switch r.URL.Path {
		case "/internal/beam/domains":
			var in struct{}
			if e = beamDecode(w, r, &in); e == nil {
				portal, base, err := service.DomainsContext(ctx)
				e = err
				result = map[string]string{"portal_url": portal, "app_base_domain": base}
			}
		case "/internal/beam/resolve":
			var in appProxyLookupWire
			if e = beamDecode(w, r, &in); e == nil {
				var b beam.Binding
				b, e = service.Resolve(ctx, in.Hostname)
				result = map[string]any{"binding": b, "origin_url": "http://beam-connector.internal"}
			}
		case "/internal/beam/connector":
			var in struct {
				Binding beam.Binding `json:"binding"`
				Serial  string       `json:"certificate_serial"`
			}
			if e = beamDecode(w, r, &in); e == nil {
				until, err := service.Channel(ctx, in.Binding, in.Serial)
				e = err
				result = map[string]any{"expires_at": until}
			}
		case "/internal/beam/pending":
			var in struct {
				Binding   beam.Binding `json:"binding"`
				NonceHash string       `json:"nonce_hash"`
				Target    string       `json:"relative_target"`
			}
			if e = beamDecode(w, r, &in); e == nil {
				until, err := service.Pending(ctx, in.Binding, in.NonceHash, in.Target)
				e = err
				result = map[string]any{"expires_at": until}
			}
		case "/internal/beam/redeem":
			var in appProxyRedeemWire
			if e = beamDecode(w, r, &in); e == nil {
				result, e = service.Redeem(ctx, in.Hostname, in.Code, in.Nonce)
			}
		case "/internal/beam/authorize":
			var in struct {
				Binding beam.Binding  `json:"binding"`
				Token   string        `json:"app_session_token"`
				Request beam.Metadata `json:"request"`
			}
			if e = beamDecode(w, r, &in); e == nil {
				result, e = service.Authorize(ctx, in.Binding, in.Token, in.Request)
			}
		case "/internal/beam/renew":
			var in appProxyLeaseWire
			if e = beamDecode(w, r, &in); e == nil {
				result, e = service.Renew(ctx, beamBinding(in.Binding), in.StreamID)
			}
		case "/internal/beam/terminated":
			var in appProxyTerminatedWire
			if e = beamDecode(w, r, &in); e == nil {
				e = service.Terminated(ctx, beamBinding(in.Binding), in.StreamID)
				result = struct{}{}
			}
		default:
			apierr.Write(w, r, apierr.NotFound("route_not_found", "Route not found"))
			return
		}
		if e != nil {
			apierr.Write(w, r, e)
			return
		}
		writeJSON(w, result)
	})
}
func beamBinding(b appProxyBindingWire) beam.Binding {
	return beam.Binding{OrgID: b.OrgID, AppID: b.AppID, GatewayID: b.GatewayID, Generation: b.Generation, Revision: b.Revision, AuthorityVersion: b.AuthorityVersion, Digest: b.Digest, Hostname: b.Hostname, Purpose: b.Purpose}
}

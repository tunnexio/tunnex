// Package aivpn relays SDK chat requests from a VPN-only socket over node mTLS.
package aivpn

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// PeerKey resolves a kernel WireGuard allowed-ips readback. Only a single host
// peer qualifies. Site routes, ambiguous ownership and IPv6 are refused.
func PeerKey(readback, source string) (string, error) {
	ip, err := netip.ParseAddr(source)
	if err != nil || !ip.Is4() {
		return "", errors.New("invalid source")
	}
	key := ""
	for _, line := range strings.Split(readback, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, raw := range strings.Split(strings.Join(fields[1:], ""), ",") {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || !prefix.Contains(ip) {
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(fields[0])
			if err != nil || len(decoded) != 32 || prefix.Bits() != 32 || len(fields) != 2 || strings.Contains(fields[1], ",") || key != "" {
				return "", errors.New("not an individual peer")
			}
			key = fields[0]
		}
	}
	if key == "" {
		return "", errors.New("unknown peer")
	}
	return key, nil
}

type KernelPeers func(context.Context) (string, error)

// Handler must ONLY be served by an interface-bound VPN listener. The caller's
// Forwarded, Authorization, Cookie and custom identity headers are never used.
func Handler(host string, control *url.URL, transport http.RoundTripper, peers KernelPeers, web http.Handler) http.Handler {
	slots := make(chan struct{}, 16)
	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(control)
			pr.Out.Host = control.Host
			pr.Out.Header = http.Header{"Content-Type": {pr.In.Header.Get("Content-Type")}}
			evidence := pr.In.Context().Value(peerContextKey{}).(peerEvidence)
			pr.Out.Header.Set("X-Tunnex-VPN-IP", evidence.ip)
			pr.Out.Header.Set("X-Tunnex-VPN-Key", evidence.key)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) { http.Error(w, "gateway unavailable", 502) },
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHost := r.Host
		if h, _, err := net.SplitHostPort(requestHost); err == nil {
			requestHost = h
		}
		if !strings.EqualFold(requestHost, host) {
			http.Error(w, "wrong host", 421)
			return
		}
		prefix := "/api/v1/organizations/"
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
		isChat := strings.HasPrefix(r.URL.Path, prefix) && len(parts) == 6 && parts[1] == "ai-gateway" && parts[2] == "inference" && parts[3] == "v1" && parts[4] == "chat" && parts[5] == "completions"
		isAlias := r.URL.Path == "/ai/v1/chat/completions"
		if !isChat && !isAlias {
			web.ServeHTTP(w, r)
			return
		}
		if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.RawPath != "" {
			http.Error(w, "invalid request", 400)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", 429)
			return
		}
		source, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
		defer cancel()
		readback, err := peers(ctx)
		if err != nil {
			http.Error(w, "VPN identity unavailable", 503)
			return
		}
		key, err := PeerKey(readback, source)
		if err != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		clone := r.Clone(context.WithValue(ctx, peerContextKey{}, peerEvidence{source, key}))
		if isAlias {
			clone.URL.Path = "/agent/ai/v1/chat/completions"
		} else {
			clone.URL.Path = "/agent/ai/organizations/" + parts[0] + "/v1/chat/completions"
		}
		clone.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		proxy.ServeHTTP(w, clone)
	})
}

type peerContextKey struct{}
type peerEvidence struct{ ip, key string }

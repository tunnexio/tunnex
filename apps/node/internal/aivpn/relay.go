// Package aivpn relays SDK inference requests (every synchronous mode) and the
// model list from a VPN-only socket over node mTLS.
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

// PeerKey resolves a kernel WireGuard allowed-ips readback. An individual peer
// owns exactly one IPv4 /32 and optionally one IPv6 /128. Routed/site prefixes,
// multiple addresses of either family and ambiguous source ownership are refused.
// The automatic listener is IPv4-only, so IPv6 sources remain unsupported.
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
		matches, individual := false, true
		ipv4, ipv6 := 0, 0
		// wg's machine-readable output separates allowed IPs by whitespace;
		// configured/fixture forms may use commas. Reject empty comma groups
		// instead of quietly dropping a malformed or extra route.
		for _, group := range strings.Split(strings.Join(fields[1:], " "), ",") {
			if strings.TrimSpace(group) == "" {
				individual = false
			}
			for _, raw := range strings.Fields(group) {
				prefix, err := netip.ParsePrefix(raw)
				if err != nil {
					individual = false
					continue
				}
				if prefix.Contains(ip) {
					matches = true
				}
				switch {
				case prefix.Addr().Is4() && prefix.Bits() == 32:
					ipv4++
				case prefix.Addr().Is6() && !prefix.Addr().Is4In6() && prefix.Bits() == 128:
					ipv6++
				default:
					individual = false
				}
			}
		}
		if !matches {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(fields[0])
		if err != nil || len(decoded) != 32 || !individual || ipv4 != 1 || ipv6 > 1 || key != "" {
			return "", errors.New("not an individual peer")
		}
		key = fields[0]
	}
	if key == "" {
		return "", errors.New("unknown peer")
	}
	return key, nil
}

type KernelPeers func(context.Context) (string, error)

// Outer bounds of the relay. The control plane enforces the configured limits
// (TUNNEX_AI_*); these only have to be above the largest allowed settings
// (32 MiB bodies, 30-minute requests, 60-minute streams).
const (
	MaxBodyBytes          = 33 << 20
	RequestTimeout        = 61 * time.Minute
	ResponseHeaderTimeout = 31 * time.Minute
	Slots                 = 64
)

// Routes are the exact inference routes relayed, the same list the control
// plane registers. Video jobs (asynchronous, with follow-up GET routes) are not
// relayed.
var Routes = []string{"/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/audio/speech", "/v1/audio/transcriptions",
	"/v1/images/generations", "/v1/rerank", "/v1/responses", "/anthropic/v1/messages"}

func relayedRoute(route string) bool {
	for _, r := range Routes {
		if r == route {
			return true
		}
	}
	return false
}

// Handler must ONLY be served by an interface-bound VPN listener. The caller's
// Forwarded, Authorization, Cookie and custom identity headers are never used.
func Handler(host string, control *url.URL, transport http.RoundTripper, peers KernelPeers, web http.Handler) http.Handler {
	return handler(host, control, transport, peers, web, "/agent/ai")
}

// HTTPHandler is inference-only. Its distinct upstream route lets the control
// plane enforce the current HTTP policy without trusting a caller-supplied scheme.
func HTTPHandler(host string, control *url.URL, transport http.RoundTripper, peers KernelPeers) http.Handler {
	return handler(host, control, transport, peers, http.NotFoundHandler(), "/agent/ai-http")
}

func handler(host string, control *url.URL, transport http.RoundTripper, peers KernelPeers, web http.Handler, routePrefix string) http.Handler {
	slots := make(chan struct{}, Slots)
	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(control)
			pr.Out.Host = control.Host
			pr.Out.Header = http.Header{"Content-Type": {pr.In.Header.Get("Content-Type")}}
			if pr.In.Method == http.MethodGet {
				pr.Out.Header = http.Header{}
			}
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
		org, scopedRoute := "", ""
		if strings.HasPrefix(r.URL.Path, prefix) && len(parts) >= 4 && parts[0] != "" && parts[1] == "ai-gateway" && parts[2] == "inference" {
			org, scopedRoute = parts[0], "/"+strings.Join(parts[3:], "/")
		}
		route := ""
		switch {
		case org != "" && relayedRoute(scopedRoute):
			route = scopedRoute
		case strings.HasPrefix(r.URL.Path, "/ai/") && relayedRoute(strings.TrimPrefix(r.URL.Path, "/ai")):
			route = strings.TrimPrefix(r.URL.Path, "/ai")
		}
		isInference, isAlias := route != "", route != "" && org == ""
		// SDK discovery: the caller's own granted models, same identity path.
		isModels := org != "" && scopedRoute == "/v1/models"
		isAliasModels := r.URL.Path == "/ai/v1/models"
		listing := isModels || isAliasModels
		if !isInference && !listing {
			web.ServeHTTP(w, r)
			return
		}
		method := "POST"
		if listing {
			method = "GET"
		}
		if r.Method != method || r.URL.RawQuery != "" || r.URL.RawPath != "" || (listing && r.ContentLength != 0) {
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
		ctx, cancel := context.WithTimeout(r.Context(), RequestTimeout)
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
		switch {
		case isAlias:
			clone.URL.Path = routePrefix + route
		case isInference:
			clone.URL.Path = routePrefix + "/organizations/" + org + route
		case isAliasModels:
			clone.URL.Path = routePrefix + "/v1/models"
		default:
			clone.URL.Path = routePrefix + "/organizations/" + parts[0] + "/v1/models"
		}
		if listing {
			clone.Body, clone.ContentLength = http.NoBody, 0
		} else {
			clone.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		}
		proxy.ServeHTTP(w, clone)
	})
}

type peerContextKey struct{}
type peerEvidence struct{ ip, key string }

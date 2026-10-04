package proxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
)

// ConsoleRouter optionally shares the public TLS listener. The only network
// destination is an operator-fixed HTTPS console upstream; the live authority
// chooses which exact browser hostname is the portal, never where to dial.
type ConsoleRouter struct {
	applications *Handler
	upstream     *httputil.ReverseProxy
	transport    *http.Transport
}

func NewConsoleRouter(applications *Handler, endpoint string, config *tls.Config) (*ConsoleRouter, error) {
	target, err := url.Parse(endpoint)
	if applications == nil || err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || (target.Path != "" && target.Path != "/") || target.RawPath != "" || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" || strings.ContainsAny(endpoint, "#\\\r\n\t ") {
		return nil, ErrDenied
	}
	if _, err := browserAuthority(target.Host); err != nil {
		return nil, ErrDenied
	}
	if config == nil {
		config = &tls.Config{}
	}
	if config.InsecureSkipVerify || (config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS13) {
		return nil, ErrDenied
	}
	tlsConfig := config.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.NextProtos = []string{"http/1.1"}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, MaxConnsPerHost: 128, MaxIdleConnsPerHost: 16, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 65 * time.Second, MaxResponseHeaderBytes: 32 << 10, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext}
	target.Path = ""
	router := &ConsoleRouter{applications: applications, transport: transport}
	router.upstream = &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		// ReverseProxy errors must not log login codes or application return URLs.
		ErrorLog: log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			consoleUnavailable(w)
		},
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(target)
			p.Out.Host = p.In.Host
			for name := range p.Out.Header {
				lower := strings.ToLower(name)
				if lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || lower == "x-real-ip" || lower == "true-client-ip" || lower == "cf-connecting-ip" || lower == "client-ip" {
					p.Out.Header.Del(name)
				}
			}
			p.Out.Header.Del("Proxy-Authorization")
			peer, _, err := net.SplitHostPort(p.In.RemoteAddr)
			if err == nil {
				p.Out.Header.Set("X-Forwarded-For", peer)
				p.Out.Header.Set("X-Real-IP", peer)
			}
			p.Out.Header.Set("X-Forwarded-Host", p.In.Host)
			p.Out.Header.Set("X-Forwarded-Proto", "https")
		},
		ModifyResponse: func(response *http.Response) error {
			// Console responses retain cookies and policy; they never pass through
			// private-app cookie/redirect rewriting. Add an independent framing
			// restriction without replacing the console's existing CSP.
			response.Header.Set("Origin-Agent-Cluster", "?1")
			response.Header.Set("X-Frame-Options", "DENY")
			response.Header.Add("Content-Security-Policy", "frame-ancestors 'none'")
			return nil
		},
	}
	return router, nil
}

func (r *ConsoleRouter) CloseIdleConnections() { r.transport.CloseIdleConnections() }

// browserAuthority compares HTTPS authorities with only the default port
// normalized. It does not accept userinfo, paths, wildcard hosts or IP zones.
func browserAuthority(raw string) (string, error) {
	u, err := url.Parse("https://" + raw)
	if err != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "/?#\\\r\n\t ") {
		return "", ErrDenied
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil {
		if canonical, err := apptransport.ExactHost(host, ""); err != nil || canonical != host {
			return "", ErrDenied
		}
	}
	canonical := host
	if strings.Contains(host, ":") {
		canonical = "[" + host + "]"
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", ErrDenied
		}
		canonical += ":" + port
	}
	if canonical != raw {
		return "", ErrDenied
	}
	if port == "443" {
		canonical = strings.TrimSuffix(canonical, ":443")
	}
	return canonical, nil
}

func (router *ConsoleRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, err := browserAuthority(r.Host)
	if err != nil || r.TLS == nil || len(r.Header.Values("Host")) != 0 || r.URL.IsAbs() || r.URL.Host != "" || r.URL.Opaque != "" || r.URL.Fragment != "" || r.Method == "CONNECT" || r.Method == "TRACE" {
		deny(w)
		return
	}
	console, err := router.applications.launchConsole(r.Context())
	if err != nil {
		deny(w)
		return
	}
	portal, err := browserAuthority(console.Host)
	if err != nil {
		deny(w)
		return
	}
	if host == portal {
		router.upstream.ServeHTTP(w, r)
		return
	}
	router.applications.ServeHTTP(w, r)
}

func consoleUnavailable(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Origin-Agent-Cluster", "?1")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	http.Error(w, "Console unavailable", http.StatusServiceUnavailable)
}

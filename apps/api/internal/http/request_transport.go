package http

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

// Forwarded transport is trusted only from explicit immediate proxy peers. DNS
// entries support recreated container services without trusting a whole network.
// Resolve on each request: retaining an old proxy IP could trust its next owner.
type requestTransport struct {
	prefixes []netip.Prefix
	names    []string
	lookup   func(context.Context, string, string) ([]netip.Addr, error)
}

type requestTransportKey struct{}
type requestTransportState struct {
	secure       bool
	splitCookies bool
	flowBinding  string
}

var proxyDNSName = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)

func newRequestTransport(peers []string) (*requestTransport, error) {
	t := &requestTransport{lookup: net.DefaultResolver.LookupNetIP}
	for _, peer := range peers {
		peer = strings.TrimSpace(peer)
		if ip, err := netip.ParseAddr(peer); err == nil {
			ip = ip.Unmap()
			t.prefixes = append(t.prefixes, netip.PrefixFrom(ip, ip.BitLen()))
		} else if prefix, err := netip.ParsePrefix(peer); err == nil {
			t.prefixes = append(t.prefixes, prefix.Masked())
		} else if len(peer) <= 253 && proxyDNSName.MatchString(peer) {
			t.names = append(t.names, peer)
		} else {
			return nil, fmt.Errorf("invalid TUNNEX_TRUSTED_PROXIES entry %q: use an IP, CIDR, or DNS peer name", peer)
		}
	}
	return t, nil
}

func (t *requestTransport) trusted(ctx context.Context, remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	peer = peer.Unmap()
	for _, prefix := range t.prefixes {
		if prefix.Contains(peer) {
			return true
		}
	}
	// Bound total DNS work, including when more than one peer name is supplied.
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	for _, name := range t.names {
		ips, err := t.lookup(ctx, "ip", name)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.Unmap() == peer {
				return true
			}
		}
	}
	return false
}

func (t *requestTransport) middleware(next http.Handler) http.Handler {
	configured := len(t.prefixes)+len(t.names) > 0
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := requestTransportState{secure: r.TLS != nil, splitCookies: configured}
		if configured {
			values := r.Header.Values("X-Forwarded-Proto")
			trusted := t.trusted(r.Context(), r.RemoteAddr)
			if len(values) > 0 && (trusted || !state.secure) {
				if len(values) != 1 || (values[0] != "http" && values[0] != "https") || !trusted {
					apierr.Write(w, r, apierr.BadRequest("invalid_forwarded_transport", "request transport could not be verified"))
					return
				}
				state.secure = values[0] == "https"
			} else if len(values) == 0 && trusted {
				// A configured proxy must supply its observed client scheme.
				// Never silently mint an insecure cookie on a broken TLS path.
				apierr.Write(w, r, apierr.BadRequest("invalid_forwarded_transport", "request transport could not be verified"))
				return
			}
		}
		ctx := context.WithValue(r.Context(), requestTransportKey{}, state)
		if c, err := r.Cookie(connectionFlowCookieName(ctx)); err == nil {
			state.flowBinding = c.Value
			ctx = context.WithValue(r.Context(), requestTransportKey{}, state)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requestHTTPS reports the observed request transport, never APP_BASE_URL. The
// second value is false only when a handler is invoked without HTTP middleware.
func requestHTTPS(ctx context.Context) (bool, bool) {
	state, ok := ctx.Value(requestTransportKey{}).(requestTransportState)
	return state.secure, ok
}

func sessionCookieName(ctx context.Context) string {
	state, _ := ctx.Value(requestTransportKey{}).(requestTransportState)
	if !state.splitCookies {
		return session.CookieName
	}
	if state.secure {
		return "__Host-tunnex_session"
	}
	return "tunnex_session_http"
}

func requestCookieSecure(ctx context.Context, legacy bool) bool {
	state, _ := ctx.Value(requestTransportKey{}).(requestTransportState)
	if state.splitCookies {
		return state.secure
	}
	return legacy
}

func connectionFlowCookieName(ctx context.Context) string {
	state, _ := ctx.Value(requestTransportKey{}).(requestTransportState)
	if !state.splitCookies {
		return "tnx_oidc_flow"
	}
	if state.secure {
		return "__Host-tnx_oidc_flow"
	}
	return "tnx_oidc_flow_http"
}

func connectionFlowBinding(ctx context.Context, legacy *string) string {
	state, _ := ctx.Value(requestTransportKey{}).(requestTransportState)
	if state.splitCookies {
		return state.flowBinding
	}
	if legacy != nil {
		return *legacy
	}
	return ""
}

func clearSessionCookies(w http.ResponseWriter, name string, secure bool) {
	session.ClearNamedCookie(w, name, secure)
	if name == "" || name == session.CookieName {
		return
	}
	// Clear the pre-migration cookie too; HTTP never writes the HTTPS cookie.
	session.ClearNamedCookie(w, session.CookieName, secure)
	if secure {
		session.ClearNamedCookie(w, "tunnex_session_http", false)
	}
}

// IdP callback URLs are registered against APP_BASE_URL. An HTTP flow cannot
// carry its isolated browser binding into an HTTPS callback. Direct users to
// that console before creating a flow rather than weakening the secure cookie.
func requireSSOCallbackTransport(ctx context.Context, baseURL string) error {
	state, _ := ctx.Value(requestTransportKey{}).(requestTransportState)
	if state.splitCookies && !state.secure && strings.HasPrefix(baseURL, "https://") {
		return apierr.BadRequest("sso_https_required", "Open the HTTPS console to sign in with SSO or test an SSO connection.")
	}
	return nil
}

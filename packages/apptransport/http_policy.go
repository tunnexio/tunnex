package apptransport

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"unicode"
)

var ErrRequest = errors.New("application request refused")

const AppSessionCookie = "__Host-tunnex_app_session"
const AppNonceCookie = "__Host-tunnex_app_nonce"

func ExactHost(raw, base string) (string, error) {
	if raw == "" || len(raw) > 253 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, ":/@\\?#") || strings.Contains(raw, "..") || strings.HasSuffix(raw, ".") {
		return "", ErrRequest
	}
	host := strings.ToLower(raw)
	for _, r := range host {
		if r > 127 {
			return "", ErrRequest
		}
	}
	if _, e := netip.ParseAddr(host); e == nil {
		return "", ErrRequest
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrRequest
		}
		for _, r := range label {
			if r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return "", ErrRequest
			}
		}
	}
	if base != "" && (!strings.HasSuffix(host, "."+strings.ToLower(base)) || host == strings.ToLower(base)) {
		return "", ErrRequest
	}
	return host, nil
}
func RelativeTarget(u *url.URL) (string, error) {
	if u == nil || u.IsAbs() || u.Host != "" || u.Opaque != "" || u.Fragment != "" {
		return "", ErrRequest
	}
	value := u.RequestURI()
	if len(value) > 8192 || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "", ErrRequest
	}
	decoded, e := url.PathUnescape(u.EscapedPath())
	if e != nil || strings.HasPrefix(decoded, "//") || strings.Contains(decoded, "\\") || strings.IndexFunc(decoded, unicode.IsControl) >= 0 || strings.IndexFunc(u.RawQuery, unicode.IsControl) >= 0 || strings.Contains(u.RawQuery, "\\") {
		return "", ErrRequest
	}
	return value, nil
}
func SameOrigin(r *http.Request, host string, websocket bool) bool {
	origin := r.Header.Get("Origin")
	if len(r.Header.Values("Origin")) > 1 || len(r.Header.Values("Referer")) > 1 {
		return false
	}
	if origin != "" {
		u, e := url.Parse(origin)
		return e == nil && u.Scheme == "https" && u.Host == host && u.User == nil && u.Path == "" && u.RawQuery == "" && !u.ForceQuery && !strings.Contains(origin, "#") && u.Fragment == ""
	}
	if websocket {
		return false
	}
	if len(r.Header.Values("Referer")) != 1 {
		return false
	}
	u, e := url.Parse(r.Header.Get("Referer"))
	return e == nil && u.Scheme == "https" && u.Host == host && u.User == nil
}
func reservedCookie(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "__host-tunnex_app_") || name == "__host-tunnex_session" || name == "tunnex_session" || name == "tunnex_session_http" || name == "__host-tnx_oidc_flow" || name == "tnx_oidc_flow" || name == "tnx_oidc_flow_http"
}
func AppToken(r *http.Request) (string, error) {
	token := ""
	seen := map[string]bool{}
	for _, c := range r.Cookies() {
		if reservedCookie(c.Name) {
			name := strings.ToLower(c.Name)
			if seen[name] {
				return "", ErrRequest
			}
			seen[name] = true
			if c.Name == AppSessionCookie {
				token = c.Value
			}
		}
	}
	if len(token) > 256 {
		return "", ErrRequest
	}
	return token, nil
}
func StripCredentials(h http.Header) {
	for key := range h {
		lower := strings.ToLower(key)
		if internalHeader(lower) || strings.HasPrefix(lower, "x-tunnex-") || lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || lower == "x-real-ip" || lower == "remote-user" {
			h.Del(key)
		}
	}
	for _, auth := range h.Values("Authorization") {
		fields := strings.Fields(auth)
		if len(fields) > 0 && strings.EqualFold(fields[0], "AppProxy") || len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") && (strings.HasPrefix(fields[1], "tnx_") || strings.HasPrefix(fields[1], "tnxm_") || strings.HasPrefix(fields[1], "tnxap_")) {
			h.Del("Authorization")
			break
		}
	}
	h.Del("Proxy-Authorization")
	request := &http.Request{Header: h}
	cookies := []string{}
	for _, c := range request.Cookies() {
		if !reservedCookie(c.Name) {
			cookies = append(cookies, c.String())
		}
	}
	h.Del("Cookie")
	if len(cookies) > 0 {
		h.Set("Cookie", strings.Join(cookies, "; "))
	}
}

// RewriteResponse never edits bodies. Cookies can belong only to this exact
// origin; registered-origin redirects map to the published HTTPS host.
func RewriteResponse(response *http.Response, origin *url.URL, host string) error {
	if len(response.Header.Values("Location")) > 1 {
		return ErrRequest
	}
	StripCredentials(response.Header)
	if value := response.Header.Get("Location"); value != "" {
		location, e := url.Parse(value)
		if e != nil || strings.Contains(value, "\\") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return ErrRequest
		}
		resolved := origin.ResolveReference(location)
		if resolved.Scheme != origin.Scheme || !strings.EqualFold(resolved.Host, origin.Host) || resolved.User != nil {
			return ErrRequest
		}
		relative := &url.URL{Path: resolved.Path, RawPath: resolved.RawPath, RawQuery: resolved.RawQuery}
		if relative.Path == "" {
			relative.Path = "/"
		}
		if _, e = RelativeTarget(relative); e != nil {
			return e
		}
		resolved.Scheme = "https"
		resolved.Host = host
		response.Header.Set("Location", resolved.String())
	}
	values := response.Header.Values("Set-Cookie")
	response.Header.Del("Set-Cookie")
	for _, raw := range values {
		cookie, e := http.ParseSetCookie(raw)
		if e != nil || reservedCookie(cookie.Name) {
			return ErrRequest
		}
		domain := strings.TrimPrefix(cookie.Domain, ".")
		if domain != "" && !strings.EqualFold(domain, origin.Hostname()) {
			return ErrRequest
		}
		cookie.Domain = ""
		cookie.Secure = true
		response.Header.Add("Set-Cookie", cookie.String())
	}
	for key := range response.Header {
		if strings.HasPrefix(strings.ToLower(key), "access-control-") || strings.EqualFold(key, "Clear-Site-Data") {
			response.Header.Del(key)
		}
	}
	// A private app must not clear the portal's cookies: Clear-Site-Data's
	// cookie directive affects the whole registrable domain. Origin keying
	// also prevents cooperating documents from relaxing document.domain in
	// supporting browsers. This does not replace host-prefixed auth cookies
	// or exact-origin CSRF checks at the console and application authorities.
	response.Header.Set("Origin-Agent-Cluster", "?1")
	return nil
}

func internalHeader(name string) bool {
	switch name {
	case "x-app-origin-response-nanoseconds", "x-app-operation-id", "x-app-readiness-id", "x-app-org-id", "x-app-gateway-id", "x-app-session", "x-app-session-id", "x-app-session-token", "x-user-id", "x-user-email", "x-user-groups", "x-remote-user", "x-app-id", "x-app-revision", "x-app-digest", "x-app-generation", "x-app-purpose", "x-app-hostname", "x-app-authority-version", "x-app-check-id", "x-app-stream-id", "x-auth-user", "x-auth-email", "x-auth-groups", "x-authenticated-user", "x-authenticated-email", "x-authenticated-groups":
		return true
	}
	return false
}

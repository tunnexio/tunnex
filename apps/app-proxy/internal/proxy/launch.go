package proxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
)

const StartPath = "/__tunnex_app/start"
const RedeemPath = "/__tunnex_app/redeem"

func secret32(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(value)
	return e == nil && len(raw) == 32
}
func navigationTarget(value string) (string, error) {
	if len(value) > 8192 || !strings.HasPrefix(value, "/") {
		return "", apptransport.ErrRequest
	}
	u, e := url.Parse(value)
	if e != nil {
		return "", e
	}
	if strings.HasPrefix(u.Path, "/__tunnex_app") {
		return "", apptransport.ErrRequest
	}
	return apptransport.RelativeTarget(u)
}
func redirectHeaders(w http.ResponseWriter) {
	w.Header().Set("Origin-Agent-Cluster", "?1")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
}
func (w *Handler) loginRoute(ctx context.Context, host string) (Route, error) {
	select {
	case w.callbacks <- struct{}{}:
	default:
		w.metrics.authoritySaturated.Add(1)
		return Route{}, ErrDenied
	}
	defer func() { <-w.callbacks }()
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	route, e := w.Authority.Lookup(bounded, host)
	if e != nil || bounded.Err() != nil || !Binding(route.Binding).Valid() || route.Binding.Hostname != host {
		return Route{}, ErrDenied
	}
	return route, nil
}

// launch owns the reserved namespace: none of these requests reach an origin.
func (h *Handler) launch(w http.ResponseWriter, r *http.Request, host string) {
	if (r.URL.Path != StartPath && r.URL.Path != RedeemPath) || r.Header.Get("Upgrade") != "" || !h.hasConsole() || r.Method != "GET" || r.URL.RawPath != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.URL.RequestURI()) > 32<<10 {
		deny(w)
		return
	}
	if _, e := apptransport.AppToken(r); e != nil {
		deny(w)
		return
	}
	console, e := h.launchConsole(r.Context())
	if e != nil {
		deny(w)
		return
	}
	route, e := h.loginRoute(r.Context(), host)
	if e != nil {
		deny(w)
		return
	}
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil || len(query) > 1 {
		deny(w)
		return
	}
	switch r.URL.Path {
	case StartPath:
		target := "/"
		if len(query) != 0 {
			values, ok := query["target"]
			if !ok || len(values) != 1 {
				deny(w)
				return
			}
			target = values[0]
		}
		target, e = navigationTarget(target)
		if e != nil {
			deny(w)
			return
		}
		nonce := make([]byte, 32)
		source := h.NonceSource
		if source == nil {
			source = rand.Reader
		}
		if _, e = io.ReadFull(source, nonce); e != nil {
			deny(w)
			return
		}
		cookieNonce := base64.RawURLEncoding.EncodeToString(nonce)
		hash := sha256.Sum256([]byte(cookieNonce))
		select {
		case h.callbacks <- struct{}{}:
		default:
			h.metrics.authoritySaturated.Add(1)
			deny(w)
			return
		}
		started := time.Now()
		bounded, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		pending, err := h.Authority.Pending(bounded, PendingInput{Binding: route.Binding, NonceHash: hex.EncodeToString(hash[:]), RelativeTarget: target})
		ended := bounded.Err()
		cancel()
		<-h.callbacks
		now := time.Now()
		expires := pending.ExpiresAt
		if err != nil || ended != nil || !expires.After(now) || expires.After(now.Add(10*time.Minute)) {
			deny(w)
			return
		}
		if limit := started.Add(10 * time.Minute); expires.After(limit) {
			expires = limit
		}
		destination := *console
		destination.Path = "/app-access/launch"
		destination.RawQuery = url.Values{"orgId": {route.Binding.OrgID}, "appId": {route.Binding.AppID}, "nonce_hash": {hex.EncodeToString(hash[:])}, "target": {target}}.Encode()
		redirectHeaders(w)
		http.SetCookie(w, &http.Cookie{Name: apptransport.AppNonceCookie, Value: cookieNonce, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(time.Until(expires).Seconds()), Expires: expires})
		http.Redirect(w, r, destination.String(), http.StatusSeeOther)
	case RedeemPath:
		codes, ok := query["code"]
		if !ok || len(codes) != 1 || !secret32(codes[0]) {
			deny(w)
			return
		}
		nonce, e := r.Cookie(apptransport.AppNonceCookie)
		if e != nil || !secret32(nonce.Value) {
			deny(w)
			return
		}
		select {
		case h.callbacks <- struct{}{}:
		default:
			h.metrics.authoritySaturated.Add(1)
			deny(w)
			return
		}
		bounded, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		result, e := h.Authority.Redeem(bounded, RedeemInput{Code: codes[0], Nonce: nonce.Value, Hostname: host})
		ended := bounded.Err()
		cancel()
		<-h.callbacks
		target, e2 := navigationTarget(result.RelativeTarget)
		expires := result.ExpiresAt
		cookie := &http.Cookie{Name: apptransport.AppSessionCookie, Value: result.AppSessionToken, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires, MaxAge: int(time.Until(expires).Seconds())}
		if e != nil || ended != nil || e2 != nil || len(cookie.Value) < 32 || len(cookie.Value) > 256 || cookie.Valid() != nil || !expires.After(time.Now()) || expires.After(time.Now().Add(8*time.Hour)) {
			deny(w)
			return
		}
		redirectHeaders(w)
		http.SetCookie(w, cookie)
		http.SetCookie(w, &http.Cookie{Name: apptransport.AppNonceCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
		http.Redirect(w, r, target, http.StatusSeeOther)
	default:
		deny(w)
	}
}
func (h *Handler) restart(w http.ResponseWriter, r *http.Request, target string) {
	redirectHeaders(w)
	http.Redirect(w, r, StartPath+"?"+url.Values{"target": {target}}.Encode(), http.StatusSeeOther)
}

package proxy

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/tunnexio/tunnex/packages/apptransport"
	"golang.org/x/net/publicsuffix"
)

// ConsoleURL accepts one configured HTTPS root on an independent ICANN
// registrable domain, or exactly the app base's parent portal. The latter
// requires host-only console authority and exact-origin CSRF protection; it
// never permits an app host to be the console. Caller-provided return URLs
// and origins never enter this configuration boundary. An explicitly configured
// HTTPS IP console is also supported; application origins still require DNS.
func ConsoleURL(raw, appBase string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || u.Fragment != "" {
		return nil, ErrDenied
	}
	console := u.Hostname()
	consoleIP := net.ParseIP(console)
	if consoleIP == nil {
		if normalized, err := apptransport.ExactHost(console, ""); err != nil || normalized != console {
			return nil, ErrDenied
		}
	}
	canonicalHost := console
	if strings.Contains(console, ":") {
		canonicalHost = "[" + console + "]"
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return nil, ErrDenied
		}
		canonicalHost += ":" + port
	}
	if u.Host != canonicalHost {
		return nil, ErrDenied
	}
	base, e := apptransport.ExactHost(appBase, "")
	if e != nil {
		return nil, ErrDenied
	}
	_, appICANN := publicsuffix.PublicSuffix(base)
	appDomain, e := publicsuffix.EffectiveTLDPlusOne(base)
	if !appICANN || e != nil {
		return nil, ErrDenied
	}
	if consoleIP == nil {
		_, consoleICANN := publicsuffix.PublicSuffix(console)
		consoleDomain, err := publicsuffix.EffectiveTLDPlusOne(console)
		if !consoleICANN || err != nil || (consoleDomain == appDomain && console != base) {
			return nil, ErrDenied
		}
	}
	u.Path = ""
	return u, nil
}

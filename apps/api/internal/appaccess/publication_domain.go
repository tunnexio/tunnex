package appaccess

import (
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Draft registry configuration remains inspectable on local development names.
// Serving publication additionally requires the same public DNS and HTTPS portal
// boundary enforced by the production proxy (independent site or portal parent).
func (s *Service) publicationDomainReady() bool {
	if !s.domainReady {
		return false
	}
	raw := s.config.ConsoleURL
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || u.Fragment != "" {
		return false
	}
	console, e := apptransport.ExactHost(u.Hostname(), "")
	if net.ParseIP(u.Hostname()) != nil {
		console, e = u.Hostname(), nil
	}
	if e != nil || console != u.Hostname() {
		return false
	}
	canonical := console
	if strings.Contains(console, ":") {
		canonical = "[" + console + "]"
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return false
		}
		canonical += ":" + port
	}
	if u.Host != canonical {
		return false
	}
	base, e := apptransport.ExactHost(s.config.AppBaseDomain, "")
	if e != nil {
		return false
	}
	if _, err := appdomains.Normalize(appdomains.Config{PortalURL: raw, AppBaseDomain: base}); err != nil {
		return false
	}
	found := false
	for _, host := range s.config.ConsoleHosts {
		if host == console {
			found = true
		}
	}
	return found
}

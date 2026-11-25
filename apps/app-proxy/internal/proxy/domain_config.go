package proxy

import (
	"context"
	"net/url"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
)

// DomainConfig is read from the authenticated private authority, never from
// browser query parameters. It controls new launches, not existing route IDs.
type DomainConfig struct {
	PortalURL     string `json:"portal_url"`
	AppBaseDomain string `json:"app_base_domain"`
}

type DomainAuthority interface {
	Domains(context.Context) (DomainConfig, error)
}

func (c *Client) Domains(ctx context.Context) (DomainConfig, error) {
	var config DomainConfig
	if err := c.call(ctx, "domains", struct{}{}, &config); err != nil {
		return DomainConfig{}, err
	}
	if _, err := ConsoleURL(config.PortalURL, config.AppBaseDomain); err != nil {
		return DomainConfig{}, err
	}
	return config, nil
}

// Dynamic deployments keep previously published hostnames usable through their
// exact authority bindings. Static fake/legacy authorities retain their suffix
// guard. Canonical syntax alone never grants a route or a connector channel.
func authorityHost(raw, base string, authority any) (string, error) {
	if _, dynamic := authority.(DomainAuthority); dynamic {
		base = ""
	}
	return apptransport.ExactHost(raw, base)
}

func (h *Handler) hasConsole() bool {
	_, dynamic := h.Authority.(DomainAuthority)
	return dynamic || h.Console != nil
}

func (h *Handler) launchConsole(ctx context.Context) (*url.URL, error) {
	authority, dynamic := h.Authority.(DomainAuthority)
	if !dynamic {
		if h.Console == nil {
			return nil, ErrDenied
		}
		console := *h.Console
		h.rememberConsole(&console)
		return &console, nil
	}
	select {
	case h.callbacks <- struct{}{}:
	default:
		h.metrics.authoritySaturated.Add(1)
		return nil, ErrDenied
	}
	defer func() { <-h.callbacks }()
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	config, err := authority.Domains(bounded)
	if err != nil || bounded.Err() != nil {
		return nil, ErrDenied
	}
	console, err := ConsoleURL(config.PortalURL, config.AppBaseDomain)
	if err == nil {
		h.rememberConsole(console)
	}
	return console, err
}

// rememberConsole keeps the My Applications link for the refusal page. The URL already passed ConsoleURL
// validation (https, host only), and it is the same for every host, so linking it reveals nothing about the app.
func (h *Handler) rememberConsole(console *url.URL) {
	if console == nil || h.beam {
		return
	}
	link := (&url.URL{Scheme: console.Scheme, Host: console.Host, Path: "/app-access/my-applications"}).String()
	h.myApps.Store(&link)
}

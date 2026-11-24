package appaccess

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
)

// ProxyMode is the gateway-local App Access proxy setting (AA-EN-1 E5), from
// TUNNEX_APP_PROXY_URL. Same tri-state shape as SA-UI-1's Server Access mode.
type ProxyMode int

const (
	// ProxyFollow (unset or empty): use the endpoint the control plane delivers.
	ProxyFollow ProxyMode = iota
	// ProxyURL (any other value): a local override that always wins, exactly the
	// behaviour before AA-EN-1. An invalid URL is refused and runs nothing.
	ProxyURL
	// ProxyOff ("off"): gateway-local hard lock, never run the browser pool.
	ProxyOff
)

func (m ProxyMode) String() string {
	switch m {
	case ProxyURL:
		return "url"
	case ProxyOff:
		return "off"
	}
	return "follow"
}

// ProxyModeFromEnv parses TUNNEX_APP_PROXY_URL.
func ProxyModeFromEnv(value string) (ProxyMode, string) {
	switch v := strings.TrimSpace(value); v {
	case "":
		return ProxyFollow, ""
	case "off":
		return ProxyOff, ""
	default:
		return ProxyURL, v
	}
}

// ProxyFollowInterval is how often a following gateway asks for the endpoint.
const ProxyFollowInterval = 5 * time.Second

var errEndpoint = errors.New("invalid delivered App Access proxy endpoint")

// EndpointURL turns a delivered endpoint into the URL the browser pool dials.
// A missing host means the agent channel's own host. Only a bare hostname or IP
// and a valid port are accepted; the TLS server name stays pinned to
// "tunnex-app-proxy" by NewBrowserPool whatever this host is.
func EndpointURL(agentHost string, e control.AppProxyEndpoint) (string, error) {
	host := strings.TrimSpace(e.Host)
	if host == "" {
		host = agentHost
	}
	if e.Port < 1 || e.Port > 65535 || host == "" || strings.ContainsAny(host, "/@:[]?#% ") && net.ParseIP(host) == nil {
		return "", errEndpoint
	}
	u := url.URL{Scheme: "https", Host: net.JoinHostPort(host, strconv.Itoa(e.Port))}
	if parsed, err := url.Parse(u.String()); err != nil || parsed.Hostname() != host {
		return "", errEndpoint
	}
	return u.String(), nil
}

// FollowProxy runs the browser pool while the control plane delivers an
// enabled endpoint, restarts it when the endpoint changes, and stops it when
// delivery turns off. A poll error (including an older control plane's 404)
// keeps the current state. start returns a wait function for a clean stop.
func FollowProxy(ctx context.Context, interval time.Duration, agentHost string,
	poll func(context.Context) (control.AppProxyEndpoint, error),
	start func(ctx context.Context, endpoint string) (wait func(), err error),
	logger *slog.Logger) {
	var running struct {
		endpoint string
		cancel   context.CancelFunc
		wait     func()
	}
	stop := func() {
		if running.cancel != nil {
			running.cancel()
			running.wait()
			running.endpoint, running.cancel, running.wait = "", nil, nil
		}
	}
	defer stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	unsupportedLogged := false
	for {
		delivered, err := poll(ctx)
		switch {
		case errors.Is(err, control.ErrProxyEndpointUnsupported):
			if !unsupportedLogged {
				logger.Info("app_browser_endpoint_unsupported", slog.String("remedy", "upgrade the control plane, or set TUNNEX_APP_PROXY_URL on this gateway"))
				unsupportedLogged = true
			}
		case err != nil:
			// Keep the current state; the pool itself needs live CP authority.
		case !delivered.Enabled:
			if running.cancel != nil {
				stop()
				logger.Info("app_browser_stopped", slog.String("source", "control_plane"))
			}
		default:
			endpoint, e := EndpointURL(agentHost, delivered)
			if e != nil {
				logger.Error("app_browser_configuration_refused", slog.String("source", "control_plane"))
				stop()
				break
			}
			if running.cancel != nil && running.endpoint == endpoint {
				break
			}
			stop()
			child, cancel := context.WithCancel(ctx)
			wait, e := start(child, endpoint)
			if e != nil {
				cancel()
				logger.Error("app_browser_configuration_refused", slog.String("source", "control_plane"))
				break
			}
			running.endpoint, running.cancel, running.wait = endpoint, cancel, wait
			logger.Info("app_browser_started", slog.String("source", "control_plane"), slog.String("endpoint", endpoint))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

package http

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// AppProxyEndpoint is the installation's gateway-facing App Access proxy
// listener (AA-EN-1 E5). Gateways whose TUNNEX_APP_PROXY_URL is unset learn it
// over their mTLS agent channel instead of an environment variable and a hosts
// entry. The gateway pins the TLS server name "tunnex-app-proxy" and trusts only
// the enrollment CA, so this address can cause unavailability, never
// impersonation.
type AppProxyEndpoint struct {
	// Port is the published gateway listener port. Zero means this installation
	// does not compose the proxy for remote gateways: delivery is off.
	Port int
	// Host overrides the address gateways dial (split networks). Empty means each
	// gateway dials the host it already uses for its agent channel.
	Host string
	// Locked is TUNNEX_APP_ACCESS_LOCKED, the operator hard-off.
	Locked bool
}

var errAppProxyEndpoint = errors.New("invalid App Access gateway endpoint configuration")

// NewAppProxyEndpoint validates TUNNEX_APP_PROXY_GATEWAY_PORT and
// TUNNEX_APP_PROXY_GATEWAY_HOST. The host is a bare hostname or IP address:
// no scheme, port, path, brackets or credentials.
func NewAppProxyEndpoint(port, host string, locked bool) (AppProxyEndpoint, error) {
	port, host = strings.TrimSpace(port), strings.TrimSpace(host)
	if port == "" {
		if host != "" {
			return AppProxyEndpoint{}, errAppProxyEndpoint
		}
		return AppProxyEndpoint{Locked: locked}, nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return AppProxyEndpoint{}, errAppProxyEndpoint
	}
	if host != "" && !validEndpointHost(host) {
		return AppProxyEndpoint{}, errAppProxyEndpoint
	}
	return AppProxyEndpoint{Port: n, Host: host, Locked: locked}, nil
}

func validEndpointHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	numeric := true
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
				numeric = false
			default:
				return false
			}
		}
	}
	// "999.1.1.1" is neither an address nor a name a resolver should see.
	return !numeric
}

type appProxyEndpointWire struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port,omitempty"`
	Host    string `json:"host,omitempty"`
}

// SetAppProxyEndpoint attaches the endpoint and the organization feature
// reader. A nil reader leaves delivery off.
func (a *AgentChannel) SetAppProxyEndpoint(endpoint AppProxyEndpoint, orgEnabled func(context.Context, uuid.UUID) (bool, error)) {
	a.appProxyEndpoint = endpoint
	a.appProxyOrgEnabled = orgEnabled
}

// appProxyEndpointFor is enabled only when the installation composes the
// proxy, the operator lock is not set, App Access is entitled, and the
// gateway's organization has the feature on. An unreadable organization
// setting is an error, never "off": the gateway then keeps its current state.
func (a *AgentChannel) appProxyEndpointFor(ctx context.Context, org uuid.UUID) (appProxyEndpointWire, error) {
	e := a.appProxyEndpoint
	if e.Port == 0 || e.Locked || a.appProxyOrgEnabled == nil || !a.appAccessHasEntitlement() {
		return appProxyEndpointWire{}, nil
	}
	on, err := a.appProxyOrgEnabled(ctx, org)
	if err != nil {
		return appProxyEndpointWire{}, err
	}
	if !on {
		return appProxyEndpointWire{}, nil
	}
	return appProxyEndpointWire{Enabled: true, Port: e.Port, Host: e.Host}, nil
}

// appAccessProxyEndpoint answers GET /agent/app-access/proxy-endpoint. Older
// control planes answer 404, which a following gateway treats as "keep the
// current state".
func (a *AgentChannel) appAccessProxyEndpoint(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	if node.EnrolledKind == nil || *node.EnrolledKind != "gateway" {
		apierr.Write(w, r, apierr.Forbidden("gateway_required", "Gateway authority required"))
		return
	}
	out, err := a.appProxyEndpointFor(r.Context(), node.OrgID)
	if err != nil {
		apierr.Write(w, r, apierr.New(http.StatusServiceUnavailable, "app_access_endpoint_unavailable", "The App Access proxy endpoint could not be read"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

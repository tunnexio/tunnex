package http

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// SetVPNInference exposes inference only on the certificate-authenticated node
// channel. Public HTTP handlers never consume these peer-evidence headers.
func (a *AgentChannel) SetVPNInference(adapter *aigateway.Adapter, policies *aigateway.Policies) {
	a.vpnAIAdapter, a.vpnAIPolicies = adapter, policies
}

func (a *AgentChannel) SetVPNHTTPTransport(settings aiTransportRepository) {
	a.vpnHTTPTransport = settings
}

func (a *AgentChannel) vpnAIChat(w http.ResponseWriter, r *http.Request) {
	a.serveVPNChat(w, r, false)
}

func (a *AgentChannel) vpnAIHTTPChat(w http.ResponseWriter, r *http.Request) {
	a.serveVPNChat(w, r, true)
}

func (a *AgentChannel) serveVPNChat(w http.ResponseWriter, r *http.Request, automaticHTTP bool) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	explicitOrg := chi.URLParam(r, "orgId")
	if explicitOrg != "" && explicitOrg != node.OrgID.String() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if a.vpnAIAdapter == nil || a.vpnAIPolicies == nil {
		http.Error(w, "AI gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	if automaticHTTP {
		if !a.vpnAIPolicies.AutomaticVPNEnabled() {
			apierr.Write(w, r, apierr.New(403, "ai_vpn_unavailable", "Automatic VPN AI access is unavailable."))
			return
		}
		if err := requireAIHTTP(r.Context(), a.vpnHTTPTransport); err != nil {
			apierr.Write(w, r, err)
			return
		}
	}
	ips, keys := r.Header.Values("X-Tunnex-VPN-IP"), r.Header.Values("X-Tunnex-VPN-Key")
	if len(ips) != 1 || len(keys) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	clone := r.Clone(r.Context())
	clone.URL.Path = "/v1/chat/completions"
	// Only gateway-observed evidence crosses this mTLS boundary. Caller credentials
	// and identity headers are not forwarded to the provider adapter.
	clone.Header = http.Header{"Content-Type": {r.Header.Get("Content-Type")}}
	a.vpnAIAdapter.ServeAuthorized(w, clone, func(ctx context.Context, _ string, model string) (aigateway.Grant, error) {
		if automaticHTTP {
			return a.vpnAIPolicies.ResolveAutomaticVPNModel(ctx, node.OrgID, node.ID, ips[0], keys[0], model, explicitOrg == "")
		}
		if explicitOrg == "" {
			return a.vpnAIPolicies.ResolveSingleOrgVPNModel(ctx, node.OrgID, node.ID, ips[0], keys[0], model)
		}
		return a.vpnAIPolicies.ResolveVPNModel(ctx, node.OrgID, node.ID, ips[0], keys[0], model)
	})
}

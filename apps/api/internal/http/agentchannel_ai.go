package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
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

// vpnAIInference serves one exact adapter route over the node channel. The
// route comes from the registration, never from the request.
func (a *AgentChannel) vpnAIInference(route string, automaticHTTP bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { a.serveVPNInference(w, r, automaticHTTP, route) }
}

// vpnRequest is the shared node-channel prelude for VPN inference and the VPN
// model list: node certificate, org match, configured services, the automatic
// HTTP policy, and exactly one gateway-observed evidence pair.
type vpnRequest struct {
	node            sqlc.Node
	explicitOrg     string
	source, peerKey string
}

func (a *AgentChannel) vpnPrelude(w http.ResponseWriter, r *http.Request, automaticHTTP bool) (vpnRequest, *http.Request, bool) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return vpnRequest{}, r, false
	}
	explicitOrg := chi.URLParam(r, "orgId")
	if explicitOrg != "" && explicitOrg != node.OrgID.String() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return vpnRequest{}, r, false
	}
	if a.vpnAIAdapter == nil || a.vpnAIPolicies == nil {
		http.Error(w, "AI gateway unavailable", http.StatusServiceUnavailable)
		return vpnRequest{}, r, false
	}
	if automaticHTTP {
		if !a.vpnAIPolicies.AutomaticVPNEnabled() {
			apierr.Write(w, r, apierr.New(403, "ai_vpn_unavailable", "Automatic VPN AI access is unavailable."))
			return vpnRequest{}, r, false
		}
		if err := requireVPNAIHTTP(r.Context(), a.vpnHTTPTransport); err != nil {
			apierr.Write(w, r, err)
			return vpnRequest{}, r, false
		}
	}
	ips, keys := r.Header.Values("X-Tunnex-VPN-IP"), r.Header.Values("X-Tunnex-VPN-Key")
	if len(ips) != 1 || len(keys) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return vpnRequest{}, r, false
	}
	return vpnRequest{node: node, explicitOrg: explicitOrg, source: ips[0], peerKey: keys[0]}, r, true
}

func (a *AgentChannel) serveVPNInference(w http.ResponseWriter, r *http.Request, automaticHTTP bool, route string) {
	v, r, ok := a.vpnPrelude(w, r, automaticHTTP)
	if !ok {
		return
	}
	node, explicitOrg := v.node, v.explicitOrg
	clone := r.Clone(r.Context())
	clone.URL.Path = route
	// Only gateway-observed evidence crosses this mTLS boundary. Caller credentials
	// and identity headers are not forwarded to the provider adapter.
	clone.Header = http.Header{"Content-Type": {r.Header.Get("Content-Type")}}
	tw, traced, trace, finish := a.vpnAIAdapter.RequestLog().Begin(w, clone, aigateway.IngressVPN, middleware.GetReqID(r.Context()))
	defer finish()
	trace.SetOrganization(node.OrgID, "user")
	a.vpnAIAdapter.ServeAuthorized(tw, traced, aigateway.TraceAuthorize(func(ctx context.Context, _ string, model string) (aigateway.Grant, error) {
		if automaticHTTP {
			g, err := a.vpnAIPolicies.ResolveAutomaticVPNModel(ctx, node.OrgID, node.ID, v.source, v.peerKey, model, explicitOrg == "")
			return a.withVPNHTTPRenewalGates(g), err
		}
		if explicitOrg == "" {
			return a.vpnAIPolicies.ResolveSingleOrgVPNModel(ctx, node.OrgID, node.ID, v.source, v.peerKey, model)
		}
		return a.vpnAIPolicies.ResolveVPNModel(ctx, node.OrgID, node.ID, v.source, v.peerKey, model)
	}))
}

func (a *AgentChannel) vpnAIModels(w http.ResponseWriter, r *http.Request) {
	a.serveVPNModels(w, r, false)
}

func (a *AgentChannel) vpnAIHTTPModels(w http.ResponseWriter, r *http.Request) {
	a.serveVPNModels(w, r, true)
}

// serveVPNModels answers the OpenAI model list for the user behind the VPN
// evidence: that user's granted models for every mode the relay serves,
// resolved exactly like inference.
func (a *AgentChannel) serveVPNModels(w http.ResponseWriter, r *http.Request, automaticHTTP bool) {
	w.Header().Set("Cache-Control", "no-store")
	v, r, ok := a.vpnPrelude(w, r, automaticHTTP)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || r.ContentLength != 0 {
		apierr.Write(w, r, apierr.New(400, "invalid_request", "invalid model list request"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	singleOrg := v.explicitOrg == ""
	var models []aigateway.UserModel
	var err error
	if automaticHTTP {
		models, err = a.vpnAIPolicies.AutomaticVPNModels(ctx, v.node.OrgID, v.node.ID, v.source, v.peerKey, singleOrg)
	} else {
		models, err = a.vpnAIPolicies.VPNModels(ctx, v.node.OrgID, v.node.ID, v.source, v.peerKey, singleOrg)
	}
	if err != nil {
		// Like the inference adapter, never forward resolver codes or messages.
		var domain *apierr.Error
		if errors.As(err, &domain) && domain.Status == http.StatusServiceUnavailable {
			apierr.Write(w, r, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable"))
		} else {
			apierr.Write(w, r, apierr.New(403, "ai_policy_denied", "AI access is not available under the current policy"))
		}
		return
	}
	data := []map[string]string{}
	for _, m := range models {
		data = append(data, map[string]string{"id": m.Model, "object": "model", "owned_by": "tunnex", "mode": string(aigateway.DefaultModelMode(m.Mode))})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
}

// withVPNHTTPRenewalGates makes lease renewal of an automatic HTTP relay
// request repeat that route's gates: the automatic VPN switch and the saved
// "Inside the VPN" HTTP policy.
func (a *AgentChannel) withVPNHTTPRenewalGates(g aigateway.Grant) aigateway.Grant {
	if g.Renew == nil {
		return g
	}
	inner := g.Renew
	g.Renew = func(ctx context.Context) (aigateway.Grant, error) {
		if !a.vpnAIPolicies.AutomaticVPNEnabled() {
			return aigateway.Grant{}, apierr.New(403, "ai_vpn_unavailable", "Automatic VPN AI access is unavailable.")
		}
		if err := requireVPNAIHTTP(ctx, a.vpnHTTPTransport); err != nil {
			return aigateway.Grant{}, err
		}
		return inner(ctx)
	}
	return g
}

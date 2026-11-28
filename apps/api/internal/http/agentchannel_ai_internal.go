package http

import (
	"context"
	"encoding/json"
	"github.com/go-chi/chi/v5/middleware"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// AI-KEYS-1 phase 2: the internal AI endpoint, control plane side. Every route
// here is on the certificate-authenticated node channel. The organization,
// node and endpoint come from the node certificate and the endpoint row, never
// from the request.

// SetAIInternal exposes the internal endpoint routes on the node channel.
func (a *AgentChannel) SetAIInternal(endpoints *aigateway.InternalEndpoints, adapter *aigateway.Adapter) {
	a.aiInternal, a.aiInternalAdapter = endpoints, adapter
}

// NotifyNode wakes one gateway's watch so it re-reads its documents now.
func (a *AgentChannel) NotifyNode(_ context.Context, node uuid.UUID) {
	if a.hub != nil {
		a.hub.Notify(node)
	}
}

// internalKeyPaths are the only inference paths relayed for static keys.
// Videos need the video job routes and are not proxied.
var internalKeyPaths = map[string]bool{
	"/v1/chat/completions": true, "/v1/completions": true, "/v1/embeddings": true,
	"/v1/audio/speech": true, "/v1/audio/transcriptions": true, "/v1/images/generations": true,
	"/v1/rerank": true, "/anthropic/v1/messages": true,
}

func (a *AgentChannel) aiInternalDesiredState(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	if a.aiInternal == nil {
		http.Error(w, "AI gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	doc, err := a.aiInternal.DesiredState(r.Context(), node.OrgID, node.ID)
	if err != nil {
		http.Error(w, "AI gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (a *AgentChannel) aiInternalCertificate(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	if a.aiInternal == nil {
		http.Error(w, "AI gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		CSRPEM string `json:"csr_pem"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || d.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	cert, err := a.aiInternal.SignCSR(r.Context(), node.OrgID, node.ID, body.CSRPEM)
	if err != nil {
		apierr.Write(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cert)
}

// aiKey is the mTLS inference route for internal static keys. It builds the
// Internal ingress from the node certificate and re-checks the organization,
// the enabled endpoint row and the gateway-observed peer address against the
// endpoint's ranges (the key's own ranges are checked in Authorize).
func (a *AgentChannel) aiKey(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	path := strings.TrimPrefix(r.URL.Path, "/agent/ai-key")
	models := path == "/v1/models"
	if models && r.Method != http.MethodGet || !models && (r.Method != http.MethodPost || !internalKeyPaths[path]) {
		apierr.Write(w, r, apierr.New(404, "not_found", "inference route not found"))
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		apierr.Write(w, r, apierr.New(400, "invalid_request", "invalid inference request"))
		return
	}
	if a.aiInternal == nil || a.aiInternal.Keys() == nil || a.aiInternalAdapter == nil {
		apierr.Write(w, r, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable"))
		return
	}
	raw, claimed, credentialOK := staticCredential(r, "/agent/ai-key/anthropic/v1/messages")
	if !claimed || !credentialOK {
		apierr.Write(w, r, apierr.New(401, "unauthenticated", "authentication required"))
		return
	}
	peers := r.Header.Values("X-Tunnex-Peer-IP")
	if len(peers) != 1 {
		apierr.Write(w, r, apierr.New(403, "ai_policy_denied", "AI access is not available under the current policy"))
		return
	}
	peer, err := netip.ParseAddr(strings.TrimSpace(peers[0]))
	if err != nil || !peer.Is4() || peer.String() != strings.TrimSpace(peers[0]) {
		apierr.Write(w, r, apierr.New(403, "ai_policy_denied", "AI access is not available under the current policy"))
		return
	}
	endpoint, cidrs, err := a.aiInternal.EnabledEndpoint(r.Context(), node.OrgID, node.ID)
	if err != nil {
		writeStaticKeyRefusal(w, r, err)
		return
	}
	inside := false
	for _, v := range cidrs {
		if prefix, perr := netip.ParsePrefix(v); perr == nil && prefix.Contains(peer) {
			inside = true
		}
	}
	if !inside {
		apierr.Write(w, r, apierr.New(403, "ai_policy_denied", "AI access is not available under the current policy"))
		return
	}
	keys := a.aiInternal.Keys()
	ingress := aigateway.InternalIngress(node.OrgID, node.ID, endpoint, peer)
	if models {
		serveStaticKeyModels(w, r, keys, raw, ingress)
		return
	}
	clone := r.Clone(r.Context())
	clone.URL.Path = path
	// Only gateway-observed evidence crosses this boundary. The credential is
	// bound into the closure; no caller header reaches the adapter.
	clone.Header = http.Header{"Content-Type": {r.Header.Get("Content-Type")}}
	tw, traced, trace, finish := a.aiInternalAdapter.RequestLog().Begin(w, clone, aigateway.IngressInternal, middleware.GetReqID(r.Context()))
	defer finish()
	trace.SetOrganization(node.OrgID, "workload_key")
	a.aiInternalAdapter.ServeAuthorized(tw, traced, aigateway.TraceAuthorize(func(ctx context.Context, _ string, model string) (aigateway.Grant, error) {
		return keys.Authorize(ctx, raw, model, ingress)
	}))
}

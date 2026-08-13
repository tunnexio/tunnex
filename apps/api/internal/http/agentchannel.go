package http

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// AgentChannel is the mTLS control channel the tunnex-node agent reconciles
// against. It authorizes every request by the client CERTIFICATE (serial ->
// node), never by anything in the request body (the machine-edition IDOR rule).
type AgentChannel struct {
	svc       *nodes.Service
	ca        *agentca.CA
	hub       *nodepush.Hub
	logger    *slog.Logger
	watchHold time.Duration
	ingest    *accesslog.Ingester // nil until flow logging is configured (S7.5.1)
}

// NewAgentChannel builds the channel handler. hub may be nil (watch then falls
// back to the timed long-poll only; the interval reconcile still converges).
func NewAgentChannel(svc *nodes.Service, ca *agentca.CA, hub *nodepush.Hub, logger *slog.Logger) *AgentChannel {
	return &AgentChannel{svc: svc, ca: ca, hub: hub, logger: logger, watchHold: 25 * time.Second}
}

// SetFlowIngester wires the S7.5.1 flow-event ingester. Optional: when nil, the
// /agent/flow-events endpoint replies 503 (flow logging not configured) — enforcement and
// the rest of the channel are unaffected.
func (a *AgentChannel) SetFlowIngester(ing *accesslog.Ingester) { a.ingest = ing }

// TLSConfig requires and verifies agent client certs against the CA, and
// presents a CA-signed server cert.
func (a *AgentChannel) TLSConfig(serverDNSName string) (*tls.Config, error) {
	serverCert, err := a.ca.ServerTLSCertificate(serverDNSName)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    a.ca.Pool(),
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Handler returns the routes served on the mTLS listener.
func (a *AgentChannel) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Get("/agent/desired-state", a.desiredState)
	r.Get("/agent/watch", a.watch)
	r.Post("/agent/renew", a.renew)
	r.Post("/agent/report", a.report)
	r.Post("/agent/status", a.status)
	r.Post("/agent/flow-events", a.flowEvents)
	return r
}

// flowEvents ingests a batch of gateway flow observations (S7.5.1). Authorized by the
// client CERTIFICATE (serial -> node -> org), exactly as report/status — no new
// unauthenticated surface. The batch is best-effort observability; a decode/ingest failure
// is reported to the agent (which keeps retrying) but never touches the data plane.
func (a *AgentChannel) flowEvents(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	if a.ingest == nil {
		http.Error(w, "flow logging not configured", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Events  []accesslog.WireEvent `json:"events"`
		Dropped int64                 `json:"dropped"`
	}
	// A full drained batch is bounded (≤16384 events); 8 MiB is generous headroom.
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if err := a.ingest.IngestBatch(r.Context(), node.OrgID, node.ID, body.Events, body.Dropped); err != nil {
		apierr.Write(w, r, err) // S11-5: route through the ONE seam — logs the cause + request_id
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// status ingests per-peer live telemetry (handshake/bytes/endpoint) from the
// agent and upserts it against the node's devices.
func (a *AgentChannel) status(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	var body struct {
		Peers []struct {
			PublicKey     string `json:"public_key"`
			LastHandshake int64  `json:"last_handshake"`
			RxBytes       int64  `json:"rx_bytes"`
			TxBytes       int64  `json:"tx_bytes"`
			Endpoint      string `json:"endpoint"`
		} `json:"peers"`
	}
	// Bound the body (a report is capped at ~1000 peers agent-side).
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	stats := make([]nodes.PeerStatus, 0, len(body.Peers))
	for _, p := range body.Peers {
		stats = append(stats, nodes.PeerStatus{
			PublicKey: p.PublicKey, LastHandshake: p.LastHandshake,
			RxBytes: p.RxBytes, TxBytes: p.TxBytes,
		})
	}
	if err := a.svc.ReportStatus(r.Context(), node, stats); err != nil {
		apierr.Write(w, r, err) // S11-5: route through the ONE seam — logs the cause + request_id
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// report records the agent's locally-generated WireGuard public key.
func (a *AgentChannel) report(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	var body struct {
		PublicKey  string `json:"public_key"`
		Endpoint   string `json:"endpoint"`
		EgressNAT  bool   `json:"egress_nat"`  // S3.7: gateway can source-NAT IPv4 full-tunnel egress
		EgressIPv6 bool   `json:"egress_ipv6"` // S15: gateway can source-NAT IPv6 full-tunnel egress
		// S7.2 staleness: the policy IN FORCE on the gateway (version + canonical hash
		// of the last successfully applied Compiled) + the last apply error, if any.
		PolicyVersion int    `json:"policy_version"`
		PolicyHash    string `json:"policy_hash"`
		PolicyError   string `json:"policy_error"`
		PolicyFailing string `json:"policy_failing_since"`
		// S8.1 D1: the compiled-artifact version the agent REFUSED as unsupported (0 = none).
		PolicyRefusedVersion int `json:"policy_refused_version"`
		// S8.2 H5: a site-link peer has a stale/absent handshake (site-to-site link down).
		SiteLinkStale         bool `json:"site_link_stale"`
		SiteSubnetUnreachable bool `json:"site_subnet_unreachable"` // S8.2c D3
		// S8.3 CW: the agent's max-supported policy version (0 when a pre-CW agent omits it → below-ceiling).
		MaxPolicyVersion int `json:"max_policy_version"`
		// S9.1 4d: the OpenVPN server's refuse-loudly health kind ("" / ovpn_certs_absent / ovpn_binary_absent).
		OVPNHealth string `json:"ovpn_health"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&body); err != nil || body.PublicKey == "" {
		http.Error(w, "public_key required", http.StatusBadRequest)
		return
	}
	applied := nodes.AppliedPolicy{Version: body.PolicyVersion, Hash: body.PolicyHash, Error: body.PolicyError, FailingSince: body.PolicyFailing, RefusedVersion: body.PolicyRefusedVersion, SiteLinkStale: body.SiteLinkStale, SiteSubnetUnreachable: body.SiteSubnetUnreachable, MaxSupportedVersion: body.MaxPolicyVersion, OVPNHealth: body.OVPNHealth}
	if err := a.svc.ReportWGInfo(r.Context(), node, body.PublicKey, body.Endpoint, body.EgressNAT, body.EgressIPv6, applied); err != nil {
		// ONE seam for BOTH cases (S11-5): apierr.Write renders a typed *apierr.Error with its own
		// status+code and turns an unmapped error into a logged 500 — so the hand-rolled errors.As branch
		// that used to answer typed errors as bare text (no envelope, no request_id) is gone.
		apierr.Write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *AgentChannel) desiredState(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	// Read the change-version BEFORE the peer query so the reported version can
	// never be newer than the data it accompanies (a change landing after this
	// read leaves the agent with a stale version -> its next watch resyncs).
	var version uint64
	if a.hub != nil {
		version = a.hub.Version(node.ID)
	}
	ds, err := a.svc.DesiredState(r.Context(), node)
	if err != nil {
		apierr.Write(w, r, err) // S11-5: route through the ONE seam — logs the cause + request_id
		return
	}
	ds.Version = version
	writeJSON(w, ds)
}

// watch is a long-poll: it returns the instant this node's desired state changes
// (pushed via the hub) so revocations apply within the S3.1 <5s bound, or after
// watchHold as a safety net. The agent re-fetches on return.
func (a *AgentChannel) watch(w http.ResponseWriter, r *http.Request) {
	// ⚠ ROUTED THROUGH THE SAME SEAM. This handler used to tolerate a missing TLS block and pass an empty
	// serial to AuthenticateCert, relying on the lookup to fail. That is the same outcome by a longer road,
	// and it is one more place a principal would not have been built.
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	var changed <-chan struct{}
	if a.hub != nil {
		// Subscribe BEFORE reading the version so no Notify is missed in between.
		ch, unsubscribe := a.hub.Subscribe(node.ID)
		defer unsubscribe()
		changed = ch
		// If the node changed since the version the agent last fetched, return
		// immediately — the change happened during the agent's fetch/apply gap.
		since, _ := strconv.ParseUint(r.URL.Query().Get("v"), 10, 64)
		if a.hub.Version(node.ID) != since {
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	select {
	case <-r.Context().Done():
	case <-changed: // pushed change for this node -> return now
	case <-time.After(a.watchHold):
	}
	w.WriteHeader(http.StatusOK)
}

func (a *AgentChannel) renew(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	csr, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	cert, err := a.svc.Renew(r.Context(), node, string(csr), r.Header.Get("X-Agent-Version"))
	if err != nil {
		http.Error(w, "renew refused", http.StatusUnauthorized) // revoked node lands here
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write([]byte(cert))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// authenticateAgent is THE ONE SEAM where an agent becomes a principal (S15.2, D4).
//
// ⛔ ONE SEAM, NOT SIX. This exact block — TLS check, serial, AuthenticateCert, 401 — was repeated at every
// agent route. Attaching the principal at each of them would have made the construction the CALLER's
// responsibility, which is the class this repo has already paid for: a guard the next route is free to
// forget, and a census that has to be re-run every time someone adds a handler.
//
// ⚠ AND IT IS WHY THE CENSUS GATE CAN BE HONEST. `agent_principal_census_test.go` asserts that `NodeID` is
// written inside a `Principal` literal in exactly one file. That claim is only worth making because there is
// one place an agent principal is ever built — here, through NewAgentPrincipal.
//
// Returns the node, a request whose context carries the principal, and ok=false when it has already written
// the 401 (the caller must simply return).
func (a *AgentChannel) authenticateAgent(w http.ResponseWriter, r *http.Request) (sqlc.Node, *http.Request, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return sqlc.Node{}, r, false
	}
	serial := hex.EncodeToString(r.TLS.PeerCertificates[0].SerialNumber.Bytes())
	node, err := a.svc.AuthenticateCert(r.Context(), serial)
	if err != nil {
		// ⚠ ONE MESSAGE FOR EVERY FAILURE — unknown serial, revoked node, wrong org. No oracle: an agent
		// learning WHICH of those it hit is an agent learning about nodes it is not.
		http.Error(w, "unauthorized agent", http.StatusUnauthorized)
		return sqlc.Node{}, r, false
	}
	// ⚠ owner_user_id may be NULL — D25(C). The principal is still built, and it reports itself
	// UNATTRIBUTABLE rather than being refused: an unattributable tunnel is a logging failure, not an
	// access-control one, and the policy engine enforces every rule regardless.
	var owner uuid.UUID
	if node.OwnerUserID.Valid {
		owner = uuid.UUID(node.OwnerUserID.Bytes)
	}
	p := authctx.NewAgentPrincipal(node.ID, node.OrgID, node.Name, rbac.RoleAgent, owner, "agent_mtls")
	if p == nil {
		// Defensive: NewAgentPrincipal refuses a nil node/org, which an authenticated row cannot produce.
		// If it ever does, refusing is correct — an agent principal with no identity is not a principal.
		http.Error(w, "unauthorized agent", http.StatusUnauthorized)
		return sqlc.Node{}, r, false
	}
	return node, r.WithContext(authctx.WithPrincipal(r.Context(), p)), true
}

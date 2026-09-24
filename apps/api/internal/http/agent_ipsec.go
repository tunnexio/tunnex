package http

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

type agentIPsecRepository interface {
	Pending(context.Context, ipsec.RuntimePrincipal, *uuid.UUID, int) (ipsec.RuntimePendingPage, error)
	Material(context.Context, ipsec.RuntimePrincipal, uuid.UUID, int64, *crypto.Sealer) (ipsec.RuntimeMaterial, error)
	Cleanup(context.Context, ipsec.RuntimePrincipal, uuid.UUID, int64) (ipsec.RuntimeCleanup, error)
	Acknowledge(context.Context, ipsec.RuntimePrincipal, uuid.UUID, ipsec.RuntimeAcknowledgement) error
	PermitLease(context.Context, ipsec.RuntimePrincipal, uuid.UUID, ipsec.RuntimeLeaseRequest) (ipsec.RuntimeLease, error)
}

func (a *AgentChannel) SetIPsecRuntime(store agentIPsecRepository, sealer *crypto.Sealer) {
	a.ipsecRuntime = store
	a.ipsecSealer = sealer
}
func (a *AgentChannel) ipsecPrincipal(w http.ResponseWriter, r *http.Request) (ipsec.RuntimePrincipal, *http.Request, bool) {
	w.Header().Set("Cache-Control", "no-store")
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return ipsec.RuntimePrincipal{}, r, false
	}
	if a.ipsecRuntime == nil {
		apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionUnavailable))
		return ipsec.RuntimePrincipal{}, r, false
	}
	return ipsec.RuntimePrincipal{OrgID: node.OrgID, NodeID: node.ID, CertificateSerial: hex.EncodeToString(r.TLS.PeerCertificates[0].SerialNumber.Bytes())}, r, true
}
func agentIPsecInvalid(w http.ResponseWriter, r *http.Request) {
	apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionInvalid))
}
func decodeAgentIPsec(w http.ResponseWriter, r *http.Request, target any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128*1024))
	if err != nil {
		agentIPsecInvalid(w, r)
		return false
	}
	defer clear(body)
	if !singleUniqueJSON(body) {
		agentIPsecInvalid(w, r)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		agentIPsecInvalid(w, r)
		return false
	}
	return true
}
func agentIPsecConnection(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "connectionId"))
	if err != nil || id == uuid.Nil {
		agentIPsecInvalid(w, r)
		return uuid.Nil, false
	}
	return id, true
}
func writeAgentIPsec(w http.ResponseWriter, r *http.Request, value any, err error) {
	if err != nil {
		if errors.Is(err, ipsec.ErrRuntimeUnauthorized) {
			apierr.Write(w, r, apierr.New(http.StatusUnauthorized, "unauthorized_agent", "unauthorized agent"))
			return
		}
		apierr.Write(w, r, ipsecProviderError(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func (a *AgentChannel) ipsecPending(w http.ResponseWriter, r *http.Request) {
	p, r, ok := a.ipsecPrincipal(w, r)
	if !ok {
		return
	}
	var after *uuid.UUID
	limit := 50
	for key, values := range r.URL.Query() {
		if len(values) != 1 || (key != "after" && key != "limit") {
			agentIPsecInvalid(w, r)
			return
		}
	}
	if raw := r.URL.Query().Get("after"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil {
			agentIPsecInvalid(w, r)
			return
		}
		after = &id
	}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			agentIPsecInvalid(w, r)
			return
		}
		limit = n
	}
	result, err := a.ipsecRuntime.Pending(r.Context(), p, after, limit)
	writeAgentIPsec(w, r, result, err)
}
func (a *AgentChannel) ipsecMaterial(w http.ResponseWriter, r *http.Request) {
	p, r, ok := a.ipsecPrincipal(w, r)
	if !ok {
		return
	}
	id, ok := agentIPsecConnection(w, r)
	if !ok {
		return
	}
	var body struct {
		DesiredRevision int64 `json:"desired_revision"`
	}
	if !decodeAgentIPsec(w, r, &body) {
		return
	}
	if body.DesiredRevision <= 0 {
		agentIPsecInvalid(w, r)
		return
	}
	if a.ipsecSealer == nil {
		apierr.Write(w, r, ipsecProviderError(ipsec.ErrConnectionUnavailable))
		return
	}
	// Material returns only after the authoritative transaction commits. Never
	// write headers/body containing material before that return; a failed socket
	// write must not roll back the already-persisted cleanup obligation.
	result, err := a.ipsecRuntime.Material(r.Context(), p, id, body.DesiredRevision, a.ipsecSealer)
	defer func() {
		for i := range result.Secrets {
			result.Secrets[i].PSK = ""
		}
	}()
	writeAgentIPsec(w, r, result, err)
}
func (a *AgentChannel) ipsecCleanup(w http.ResponseWriter, r *http.Request) {
	p, r, ok := a.ipsecPrincipal(w, r)
	if !ok {
		return
	}
	id, ok := agentIPsecConnection(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	if len(query) != 1 || len(query["desired_revision"]) != 1 {
		agentIPsecInvalid(w, r)
		return
	}
	rev, ok := connectionRevision(`"` + query.Get("desired_revision") + `"`)
	if !ok {
		agentIPsecInvalid(w, r)
		return
	}
	result, err := a.ipsecRuntime.Cleanup(r.Context(), p, id, rev)
	writeAgentIPsec(w, r, result, err)
}
func (a *AgentChannel) ipsecAcknowledgement(w http.ResponseWriter, r *http.Request) {
	p, r, ok := a.ipsecPrincipal(w, r)
	if !ok {
		return
	}
	id, ok := agentIPsecConnection(w, r)
	if !ok {
		return
	}
	var body ipsec.RuntimeAcknowledgement
	if !decodeAgentIPsec(w, r, &body) {
		return
	}
	if body.DeliveryID == uuid.Nil || body.DesiredRevision <= 0 || !agentIPsecHex32(body.OwnershipDigest) || !((body.Kind == "apply" && body.Result == "applied" && !body.GuardRetained) || (body.Kind == "cleanup" && body.Result == "cleaned" && body.GuardRetained)) {
		agentIPsecInvalid(w, r)
		return
	}
	if err := a.ipsecRuntime.Acknowledge(r.Context(), p, id, body); err != nil {
		writeAgentIPsec(w, r, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (a *AgentChannel) ipsecPermitLease(w http.ResponseWriter, r *http.Request) {
	p, r, ok := a.ipsecPrincipal(w, r)
	if !ok {
		return
	}
	id, ok := agentIPsecConnection(w, r)
	if !ok {
		return
	}
	var body ipsec.RuntimeLeaseRequest
	if !decodeAgentIPsec(w, r, &body) {
		return
	}
	if body.DeliveryID == uuid.Nil || body.DesiredRevision <= 0 || !agentIPsecHex32(body.PolicyHash) || !agentIPsecHex32(body.Nonce) {
		agentIPsecInvalid(w, r)
		return
	}
	if nonce, err := hex.DecodeString(body.Nonce); err != nil || len(nonce) != 32 {
		agentIPsecInvalid(w, r)
		return
	}
	result, err := a.ipsecRuntime.PermitLease(r.Context(), p, id, body)
	writeAgentIPsec(w, r, result, err)
}

func agentIPsecHex32(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

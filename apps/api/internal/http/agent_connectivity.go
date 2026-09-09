package http

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/connectivity"
)

func (a *AgentChannel) SetConnectivityStore(store *connectivity.Store) { a.connectivity = store }

func (a *AgentChannel) connectivityPending(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if a.connectivity == nil {
		http.Error(w, "connectivity unavailable", 503)
		return
	}
	after := uuid.Nil
	if raw := r.URL.Query().Get("after"); raw != "" {
		var err error
		after, err = uuid.Parse(raw)
		if err != nil {
			http.Error(w, "invalid cursor", 400)
			return
		}
	}
	page, err := a.connectivity.Pending(r.Context(), connectivity.Principal{Side: connectivity.GatewaySide, OrgID: node.OrgID, SubjectID: node.ID}, after)
	if err != nil {
		http.Error(w, "connectivity unavailable", 503)
		return
	}
	out := struct {
		Items []api.ConnectivityMailbox `json:"items"`
		Next  string                    `json:"next_cursor,omitempty"`
	}{Items: make([]api.ConnectivityMailbox, 0, len(page.Items))}
	for _, m := range page.Items {
		out.Items = append(out.Items, toConnectivityMailbox(m))
	}
	if page.Next != uuid.Nil {
		out.Next = page.Next.String()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (a *AgentChannel) connectivitySession(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if a.connectivity == nil {
		http.Error(w, "connectivity unavailable", 503)
		return
	}
	device, err := uuid.Parse(chi.URLParam(r, "deviceId"))
	if err != nil {
		http.Error(w, "invalid session", 400)
		return
	}
	session, err := uuid.Parse(chi.URLParam(r, "sessionId"))
	if err != nil {
		http.Error(w, "invalid session", 400)
		return
	}
	generation, err := strconv.ParseUint(r.URL.Query().Get("generation"), 10, 63)
	if err != nil || generation == 0 {
		http.Error(w, "invalid session", 400)
		return
	}
	p := connectivity.Principal{Side: connectivity.GatewaySide, OrgID: node.OrgID, SubjectID: node.ID}
	var m connectivity.Mailbox
	switch r.Method {
	case http.MethodGet:
		m, err = a.connectivity.Read(r.Context(), p, device, session, generation)
	case http.MethodPut:
		var req api.ConnectivitySnapshotRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128*1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&req) != nil || decoder.Decode(new(any)) != io.EOF || req.Sequence < 1 || req.Sequence > connectivity.MaxMessages {
			http.Error(w, "invalid snapshot", 400)
			return
		}
		m, err = a.connectivity.Publish(r.Context(), p, device, session, generation, uint64(req.Sequence), json.RawMessage(req.Payload))
	case http.MethodDelete:
		err = a.connectivity.Close(r.Context(), p, device, session, generation)
	}
	if err != nil {
		http.Error(w, "connectivity session unavailable", agentConnectivityErrorStatus(err))
		return
	}
	if r.Method == http.MethodDelete {
		w.WriteHeader(204)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toConnectivityMailbox(m))
}

// A storage timeout is not an authorization verdict. The gateway retains its
// existing bounded lease on transient failure; only a genuine denial ends it
// immediately. Never renew a lease merely because the store is unavailable.
func agentConnectivityErrorStatus(err error) int {
	if errors.Is(err, connectivity.ErrDenied) {
		return http.StatusForbidden
	}
	if errors.Is(err, connectivity.ErrPayload) {
		return http.StatusBadRequest
	}
	return http.StatusServiceUnavailable
}

package http

import (
	"bufio"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/serveraccess"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"net"
	"net/http"
	"time"
)

func (a *AgentChannel) SetServerAccess(s *serveraccess.Service) { a.serverAccess = s }
func (a *AgentChannel) terminalAgent(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	if a.serverAccess == nil || node.EnrolledKind == nil || *node.EnrolledKind != "gateway" {
		apierr.Write(w, r, apierr.New(503, "server_access_disabled", "Terminal capability unavailable"))
		return
	}
	if chi.URLParam(r, "sessionId") == "" {
		out, e := a.serverAccess.Desired(r.Context(), node.OrgID, node.ID, node.CertSerial, r.Header.Get("X-Tunnex-Editor-Version") == "1")
		if e != nil {
			apierr.Write(w, r, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	}
	id, e := uuid.Parse(chi.URLParam(r, "sessionId"))
	if e != nil {
		apierr.Write(w, r, apierr.BadRequest("invalid_session", "Invalid terminal session"))
		return
	}
	var out any
	switch chi.URLParam(r, "operation") {
	case "material":
		var in struct {
			PublicKey string `json:"public_key"`
		}
		if !decodeAppAccessAgent(w, r, &in) {
			return
		}
		out, e = a.serverAccess.Material(r.Context(), node.OrgID, node.ID, id, node.CertSerial, in.PublicKey)
	case "lease":
		out, e = a.serverAccess.Lease(r.Context(), node.OrgID, node.ID, id, node.CertSerial)
	case "status":
		var in struct {
			Result string `json:"result"`
		}
		if !decodeAppAccessAgent(w, r, &in) {
			return
		}
		if _, valid := terminalwire.ResultReason(in.Result); !valid {
			apierr.Write(w, r, apierr.BadRequest("invalid_result", "Invalid terminal result"))
			return
		}
		e = a.serverAccess.Complete(r.Context(), node.OrgID, node.ID, id, node.CertSerial, in.Result)
		out = map[string]string{"status": "accepted"}
	case "channel":
		if r.Method != "CONNECT" || r.Header.Get("X-Tunnex-Purpose") != terminalwire.Purpose {
			apierr.Write(w, r, apierr.Forbidden("invalid_channel_purpose", "Invalid channel purpose"))
			return
		}
		if _, e = a.serverAccess.Lease(r.Context(), node.OrgID, node.ID, id, node.CertSerial); e != nil {
			apierr.Write(w, r, e)
			return
		}
		h, ok := w.(http.Hijacker)
		if !ok {
			apierr.Write(w, r, apierr.New(503, "stream_unavailable", "Terminal transport unavailable"))
			return
		}
		conn, rw, err := h.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Time{})
		wrapped := &terminalBufferedConn{Conn: conn, reader: rw.Reader}
		rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if rw.Flush() != nil {
			return
		}
		if e = a.serverAccess.Attach(r.Context(), node.OrgID, node.ID, id, node.CertSerial, wrapped); e != nil {
			return
		}
		a.serverAccess.WaitChannel(id)
		return
	default:
		apierr.Write(w, r, apierr.NotFound("not_found", "Unknown terminal operation"))
		return
	}
	if e != nil {
		apierr.Write(w, r, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

type terminalBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *terminalBufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

package aiegress

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	policy   *Policy
	auth     string
	slots    chan struct{}
	dial     func(context.Context, string) (net.Conn, error)
	lifetime time.Duration
}

func NewServer(policy *Policy, user, password string) (*Server, error) {
	if policy == nil || policy.rules == nil || user == "" || password == "" || strings.ContainsAny(user, ":\r\n") || strings.ContainsAny(password, "\r\n") {
		return nil, ErrDenied
	}
	return &Server{policy: policy, auth: "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password)), slots: make(chan struct{}, 64), dial: policy.dial, lifetime: 35 * time.Second}, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Proxy-Authorization")), []byte(s.auth)) != 1 {
		w.Header().Set("Proxy-Authenticate", `Basic realm="custom-egress"`)
		http.Error(w, "proxy authentication required", 407)
		return
	}
	if r.Method != http.MethodConnect || r.URL.Host != r.Host || r.URL.Path != "" || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		http.Error(w, "CONNECT required", 405)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "busy", 503)
		return
	}
	upstream, e := s.dial(r.Context(), r.Host)
	if e != nil {
		http.Error(w, "destination denied", 403)
		return
	}
	defer upstream.Close()
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "unavailable", 503)
		return
	}
	client, buf, e := h.Hijack()
	if e != nil {
		return
	}
	defer client.Close()
	deadline := time.Now().Add(s.lifetime)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	if _, e = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
		return
	}
	if buf.Flush() != nil {
		return
	}
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, buf)
		if c, ok := upstream.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

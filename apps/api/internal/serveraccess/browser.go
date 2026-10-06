package serveraccess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/packages/apptransport/rdpwire"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"golang.org/x/net/websocket"
)

type liveSession struct {
	started  time.Time
	reason   atomic.Pointer[string]
	mu       sync.Mutex
	gateway  net.Conn
	browser  *websocket.Conn
	attached chan struct{}
	done     chan struct{}
	once     sync.Once
}

func (l *liveSession) close() {
	l.once.Do(func() {
		close(l.done)
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.gateway != nil {
			l.gateway.Close()
		}
		if l.browser != nil {
			l.browser.Close()
		}
	})
}

// Browser binds a single websocket to the exact initiating human session. The
// lease timer does not wait for Redis/Postgres or a blocked stream writer.
func (s *Service) Browser(w http.ResponseWriter, req *http.Request, org, id uuid.UUID, p *authctx.Principal, secure bool) error {
	if !terminalOriginMatches(req, secure) {
		return deny("invalid_terminal_origin")
	}
	r, e := s.load(req.Context(), org, id)
	if e != nil {
		return e
	}
	hash := sha256.Sum256([]byte(p.SessionID))
	if r.View.UserId != p.UserID || string(hash[:]) != string(r.ParentHash) || r.View.Kind != "terminal" {
		return deny("parent_binding_mismatch")
	}
	server, until, e := s.validate(req.Context(), org, r)
	if e != nil {
		return e
	}
	if serverOS(server) == "windows" && !secure {
		return deny("rdp_requires_https")
	}
	l := &liveSession{attached: make(chan struct{}), done: make(chan struct{}), started: time.Now()}
	s.mu.Lock()
	if s.live[id] != nil || len(s.live) >= 128 {
		s.mu.Unlock()
		return deny("channel_already_claimed")
	}
	s.live[id] = l
	s.mu.Unlock()
	defer s.closeLive(id)
	tag, e := s.pool.Exec(req.Context(), `UPDATE server_access_sessions SET browser_claimed_at=now(),status='connecting' WHERE org_id=$1 AND id=$2 AND status='pending' AND browser_claimed_at IS NULL`, org, id)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return deny("channel_already_claimed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fail := func(why string) { l.reason.CompareAndSwap(nil, &why); l.close() }
	capture := func(frame terminalwire.Frame) bool {
		if !r.View.RecordingEnabled {
			return true
		}
		bounded, stop := context.WithTimeout(ctx, time.Second)
		err := s.capture(bounded, org, id, l.started, frame)
		stop()
		if err != nil {
			why := "recording_failed"
			if authorityReason(err) == "recording_quota_reached" {
				why = "recording_quota_reached"
			}
			fail(why)
			return false
		}
		return true
	}
	var idle atomic.Int64
	idle.Store(r.Idle.UnixNano())
	var lease atomic.Int64
	lease.Store(until.UnixNano())
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-l.done:
				return
			case <-ticker.C:
				if time.Now().UnixNano() >= lease.Load() || time.Now().UnixNano() >= idle.Load() {
					why := "authority_expired"
					if !time.Now().Before(r.View.ExpiresAt) {
						why = "session_expired"
					} else if time.Now().UnixNano() >= idle.Load() {
						why = "idle_timeout"
					}
					fail(why)
					return
				}
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-l.done:
				return
			case <-ticker.C:
				check, stop := context.WithTimeout(ctx, time.Second)
				fresh, err := s.load(check, org, id)
				var deadline time.Time
				if err == nil {
					_, deadline, err = s.validate(check, org, fresh)
				}
				stop()
				if err != nil {
					fail(authorityReason(err))
					return
				}
				extendDeadline(&idle, fresh.Idle.UnixNano())
				lease.Store(deadline.UnixNano())
			}
		}
	}()
	websocket.Server{Handshake: func(*websocket.Config, *http.Request) error { return nil }, Handler: func(ws *websocket.Conn) {
		ws.MaxPayloadBytes = terminalwire.MaxFrameBytes
		if ws.SetDeadline(time.Time{}) != nil {
			return
		}
		l.mu.Lock()
		select {
		case <-l.done:
			l.mu.Unlock()
			ws.Close()
			return
		default:
		}
		l.browser = ws
		l.mu.Unlock()
		defer l.close()
		select {
		case <-l.done:
			return
		case <-l.attached:
		}
		l.mu.Lock()
		gateway := l.gateway
		l.mu.Unlock()
		go func() {
			defer l.close()
			reader := bufio.NewReaderSize(gateway, terminalwire.MaxFrameBytes)
			for {
				frame, err := terminalwire.Read(reader)
				if err != nil {
					return
				}
				if frame.Type != "output" || len(frame.Data) == 0 || len(frame.Data) > terminalwire.MaxDataBytes || frame.Rows != 0 || frame.Cols != 0 || frame.Reason != "" {
					return
				}
				if !capture(frame) {
					return
				}
				ws.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if websocket.JSON.Send(ws, frame) != nil {
					return
				}
			}
		}()
		window := time.Now()
		count := 0
		for {
			var raw []byte
			if websocket.Message.Receive(ws, &raw) != nil {
				return
			}
			var frame terminalwire.Frame
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&frame) != nil || decoder.Decode(new(any)) != io.EOF || validateBrowserFrame(server, r.View.Account, frame) != nil {
				return
			}
			if time.Since(window) >= time.Second {
				window = time.Now()
				count = 0
			}
			count++
			if count > 100 {
				return
			}
			if frame.Type == "clipboard" || frame.Type == "input" || frame.Type == "desktop" && rdpwire.HasUserInput(frame.Data) {
				touch, stop := context.WithTimeout(ctx, time.Second)
				var refreshed time.Time
				err := s.pool.QueryRow(touch, `UPDATE server_access_sessions SET idle_deadline=LEAST(expires_at,now()+make_interval(secs => (SELECT idle_timeout_seconds FROM server_access_servers WHERE org_id=$1 AND id=$3))) WHERE org_id=$1 AND id=$2 AND status='connected' AND idle_deadline>now() AND expires_at>now() RETURNING idle_deadline`, org, id, r.View.ServerId).Scan(&refreshed)
				stop()
				if err != nil {
					return
				}
				extendDeadline(&idle, refreshed.UnixNano())
			}
			if frame.Type == "resize" && !capture(frame) {
				return
			}
			gateway.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if terminalwire.Write(gateway, frame) != nil {
				return
			}
		}
	}}.ServeHTTP(w, req)
	cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	why := "terminal_closed"
	if v := l.reason.Load(); v != nil {
		why = *v
	}
	return s.end(cleanup, org, id, p.UserID, why)
}

func terminalOriginMatches(req *http.Request, secure bool) bool {
	origin, e := url.Parse(req.Header.Get("Origin"))
	scheme := "http"
	if secure {
		scheme = "https"
	}
	return e == nil && origin.Scheme == scheme && origin.Host == req.Host && origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == ""
}

// Only fixed internal error codes are retained; raw dependency errors never enter audit metadata.
func authorityReason(err error) string {
	var coded *apierr.Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	return "authority_unavailable"
}

// Idle deadlines only move forward after a successful live-session touch. An
// older renewal snapshot must not overwrite a concurrent accepted input.
func extendDeadline(deadline *atomic.Int64, next int64) {
	for current := deadline.Load(); next > current; current = deadline.Load() {
		if deadline.CompareAndSwap(current, next) {
			return
		}
	}
}

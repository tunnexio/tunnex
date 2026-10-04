// Owned local protocol driver. It never changes authority; the orchestrator must
// perform and identify an actual CP/Redis mutation before supplying the marker.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const owned = "/Users/pawangupta/tunnex/tests/app-access-local"
const host = "payroll.apps.127.0.0.1.nip.io"
const cookieName = "__Host-tunnex_app_session"

type credentials struct {
	AppSessionToken string `json:"app_session_token"`
}
type marker struct {
	Phase           string    `json:"phase,omitempty"`
	Trigger         string    `json:"trigger"`
	Started         time.Time `json:"mutation_started_at"`
	Completed       time.Time `json:"mutation_completed_at"`
	Evidence        string    `json:"evidence_ref"`
	PersistedExpiry time.Time `json:"persisted_expires_at,omitempty"`
}
type stream struct {
	mode   string
	conn   *tls.Conn
	reader *bufio.Reader
	ready  chan error
	closed chan struct{}
	once   sync.Once
	forced atomic.Bool
	bytes  atomic.Int64
	sent   atomic.Int64
	mu     sync.Mutex
	ended  time.Time
}

func (s *stream) end() {
	s.once.Do(func() { s.mu.Lock(); s.ended = time.Now(); s.mu.Unlock(); close(s.closed) })
}
func (s *stream) stop() {
	s.forced.Store(true)
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}
func output(value any) { _ = json.NewEncoder(os.Stdout).Encode(value) }
func load(path string) (credentials, *tls.Config, error) {
	if os.Getenv("APP_ACCESS_OWNED_PROJECT") != "tunnex-app-access-aa0-1003" || os.Getenv("APP_ACCESS_OWNED_CHECKOUT") != owned {
		return credentials{}, nil, errors.New("owned project/checkout refused")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) || !strings.HasPrefix(resolved, owned+"/.runtime/") {
		return credentials{}, nil, errors.New("credential file boundary refused")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return credentials{}, nil, errors.New("credential file must be private and bounded")
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return credentials{}, nil, errors.New("credential file unreadable")
	}
	var c credentials
	if json.Unmarshal(data, &c) != nil || len(c.AppSessionToken) < 32 || len(c.AppSessionToken) > 256 || strings.ContainsAny(c.AppSessionToken, ";\r\n \t\"\\") {
		return credentials{}, nil, errors.New("invalid app cookie")
	}
	ca, err := os.ReadFile(owned + "/.runtime/aa6-proxy/ca-cert.pem")
	if err != nil {
		return credentials{}, nil, errors.New("owned CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return credentials{}, nil, errors.New("owned CA invalid")
	}
	return c, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host, RootCAs: roots, NextProtos: []string{"http/1.1"}}, nil
}
func connect(config *tls.Config) (*tls.Conn, error) {
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", "127.0.0.1:443")
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, config.Clone())
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	if err = conn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
func request(token, method, path string) *http.Request {
	r, _ := http.NewRequest(method, "https://"+host+path, nil)
	r.Host = host
	r.Header.Set("Cookie", cookieName+"="+token)
	r.Header.Set("Origin", "https://"+host)
	r.Header.Set("Connection", "close")
	return r
}
func start(s *stream, c credentials, config *tls.Config, trigger <-chan struct{}) {
	conn, err := connect(config)
	if err != nil {
		s.ready <- errors.New("TLS connection failed")
		s.end()
		return
	}
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	s.reader = bufio.NewReader(conn)
	path := map[string]string{"sse": "/events", "websocket": "/ws", "download": "/download", "long_http": "/long-response", "upload": "/upload"}[s.mode]
	r := request(c.AppSessionToken, "GET", path)
	var wsKey string
	if s.mode == "websocket" {
		raw := make([]byte, 16)
		_, _ = rand.Read(raw)
		wsKey = base64.StdEncoding.EncodeToString(raw)
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-WebSocket-Key", wsKey)
	}
	if s.mode == "upload" {
		r.Method = "POST"
		r.ContentLength = 64 << 20
		r.Header.Set("Content-Type", "application/octet-stream")
		r.Header.Set("Expect", "100-continue")
	}
	// Writing only headers keeps a declared upload streaming rather than buffered.
	if s.mode == "upload" {
		_, err = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nCookie: %s=%s\r\nOrigin: https://%s\r\nContent-Length: %d\r\nContent-Type: application/octet-stream\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n", path, host, cookieName, c.AppSessionToken, host, 64<<20)
	} else {
		err = r.Write(conn)
	}
	if err != nil {
		s.ready <- errors.New("request write failed")
		s.end()
		return
	}
	response, err := http.ReadResponse(s.reader, r)
	if err != nil {
		s.ready <- errors.New("response headers failed")
		s.end()
		return
	}
	expected := 200
	if s.mode == "websocket" {
		expected = 101
	}
	if s.mode == "upload" {
		expected = 100
	}
	if response.StatusCode != expected {
		s.ready <- fmt.Errorf("unexpected initial status %d", response.StatusCode)
		s.end()
		return
	}
	if s.mode == "websocket" {
		hash := sha1.Sum([]byte(wsKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		if response.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(hash[:]) {
			s.ready <- errors.New("invalid RFC6455 accept")
			s.end()
			return
		}
		if maskedFrame(conn, []byte("aa7")) != nil {
			s.ready <- errors.New("WebSocket write failed")
			s.end()
			return
		}
		if readFrame(s.reader) != nil {
			s.ready <- errors.New("WebSocket initial echo failed")
			s.end()
			return
		}
		s.ready <- nil
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-s.closed:
					return
				case <-ticker.C:
					if maskedFrame(conn, []byte("aa7")) != nil {
						return
					}
				}
			}
		}()
		for {
			if readFrame(s.reader) != nil {
				s.end()
				return
			}
			s.bytes.Add(3)
		}
	}
	if s.mode == "upload" {
		s.ready <- nil
		go func() {
			block := make([]byte, 4096)
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-s.closed:
					return
				case <-ticker.C:
					n, err := conn.Write(block)
					s.sent.Add(int64(n))
					if err != nil {
						return
					}
				}
			}
		}()
		// Final upload status is not a commit guarantee; interruption may follow
		// acceptance of bytes or application mutations already performed upstream.
		for {
			_, err := http.ReadResponse(s.reader, r)
			if err != nil {
				s.end()
				return
			}
		}
	}
	defer response.Body.Close()
	first := make([]byte, 1)
	n, err := response.Body.Read(first)
	s.bytes.Add(int64(n))
	if err != nil {
		s.ready <- errors.New("stream did not deliver initial content")
		s.end()
		return
	}
	s.ready <- nil
	if s.mode == "download" {
		<-trigger
	} // create actual backpressure, then drain delivered buffers
	block := make([]byte, 32<<10)
	for {
		n, err = response.Body.Read(block)
		s.bytes.Add(int64(n))
		if err != nil {
			s.end()
			return
		}
	}
}
func maskedFrame(w io.Writer, payload []byte) error {
	if len(payload) > 125 {
		return errors.New("fixture frame bound")
	}
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	frame := append([]byte{0x81, 0x80 | byte(len(payload))}, mask...)
	for i, value := range payload {
		frame = append(frame, value^mask[i%4])
	}
	_, err := w.Write(frame)
	return err
}
func readFrame(r io.Reader) error {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	if header[1]&0x80 != 0 || header[0]&0x70 != 0 || header[1]&0x7f > 125 {
		return errors.New("unsupported fixture frame")
	}
	if header[0]&0x0f == 8 {
		return io.EOF
	}
	payload := make([]byte, int(header[1]&0x7f))
	_, err := io.ReadFull(r, payload)
	return err
}
func freshRequest(c credentials, config *tls.Config) (int, bool, bool) {
	conn, err := connect(config)
	if err != nil {
		return 0, false, outageTransportError(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	r := request(c.AppSessionToken, "GET", "/")
	if err := r.Write(conn); err != nil {
		return 0, false, outageTransportError(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), r)
	if err != nil {
		return 0, false, outageTransportError(err)
	}
	defer response.Body.Close()
	return response.StatusCode, response.StatusCode == 403 || (response.StatusCode == 303 && strings.HasPrefix(response.Header.Get("Location"), "/__tunnex_app/start?")), false
}

func outageTransportError(err error) bool {
	var timeout net.Error
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || (errors.As(err, &timeout) && timeout.Timeout())
}

func outageTrigger(trigger string) bool {
	switch trigger {
	case "gateway_pause", "gateway_stop", "cp_pause", "redis_pause", "proxy_shutdown":
		return true
	}
	return false
}
func main() { os.Exit(run()) }
func run() int {
	file := flag.String("session-file", "", "private owned app-session JSON")
	flag.Parse()
	c, config, err := load(*file)
	if err != nil {
		output(map[string]any{"state": "refused", "reason": err.Error()})
		return 2
	}
	trigger := make(chan struct{})
	var triggerOnce sync.Once
	releaseTrigger := func() { triggerOnce.Do(func() { close(trigger) }) }
	defer releaseTrigger()
	var streams []*stream
	for _, mode := range []string{"sse", "websocket", "long_http", "download", "upload"} {
		s := &stream{mode: mode, ready: make(chan error, 1), closed: make(chan struct{})}
		streams = append(streams, s)
		go start(s, c, config, trigger)
	}
	defer func() {
		for _, s := range streams {
			s.stop()
		}
	}()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for _, s := range streams {
		select {
		case err := <-s.ready:
			if err != nil {
				output(map[string]any{"state": "setup_failed", "protocol": s.mode, "reason": err.Error()})
				return 2
			}
		case <-deadline.C:
			output(map[string]any{"state": "setup_failed", "reason": "protocol readiness timeout"})
			return 2
		}
	}
	readyAt := time.Now()
	output(map[string]any{"state": "ready", "protocols": []string{"sse", "websocket", "long_http", "download", "upload"}, "notifications_used": false})
	commands := make(chan marker, 1)
	go func() {
		decoder := json.NewDecoder(os.Stdin)
		for i := 0; i < 2; i++ {
			var m marker
			if decoder.Decode(&m) != nil {
				return
			}
			commands <- m
			if m.Phase != "mutation_started" {
				return
			}
		}
	}()
	var m marker
	var announcedStart time.Time
	markerTimer := time.NewTimer(10 * time.Second)
	defer markerTimer.Stop()
	for {
		select {
		case m = <-commands:
			if m.Phase == "mutation_started" {
				now := time.Now()
				if !announcedStart.IsZero() || !validAnnouncement(m, readyAt, now) {
					output(map[string]any{"state": "invalid_marker", "reason": "require one recent exact mutation-start announcement after readiness"})
					return 2
				}
				announcedStart = m.Started
				releaseTrigger()
				continue
			}
		case <-markerTimer.C:
			output(map[string]any{"state": "no_trigger", "reason": "real mutation marker timeout"})
			return 2
		}
		break
	}
	received := time.Now()
	if !validFinalMarker(m, received, announcedStart) {
		output(map[string]any{"state": "invalid_marker", "reason": "require recent actual mutation start/completion and evidence reference"})
		return 2
	}
	releaseTrigger()
	// Convert same-host wall timestamps into this process's monotonic clock.
	startBoundary := received.Add(-received.Sub(m.Started))
	completeBoundary := received.Add(-received.Sub(m.Completed))
	if m.Trigger == "grant-expiry" && (!m.PersistedExpiry.Equal(m.Started) || !readyAt.Before(startBoundary)) {
		output(map[string]any{"state": "invalid_marker", "reason": "expiry requires exact persisted deadline and positive readiness before expiry"})
		return 2
	}
	bound := startBoundary.Add(5 * time.Second)
	type observation struct {
		Protocol                string `json:"protocol"`
		ClosedAfterStartMS      int64  `json:"closed_after_start_ms"`
		ClosedAfterCompletionMS int64  `json:"closed_after_completion_ms"`
		Observed                bool   `json:"observed_close"`
		Passed                  bool   `json:"within_conservative_bound"`
		WireBytes               int64  `json:"body_bytes_read"`
		UploadBytes             int64  `json:"upload_bytes_sent"`
	}
	var observations []observation
	passed := true
	for _, s := range streams {
		remaining := time.Until(bound)
		if remaining < 0 {
			remaining = 0
		}
		timer := time.NewTimer(remaining)
		observed := false
		select {
		case <-s.closed:
			observed = true
			timer.Stop()
		default:
			select {
			case <-s.closed:
				observed = true
				timer.Stop()
			case <-timer.C:
				s.stop()
			}
		}
		s.mu.Lock()
		ended := s.ended
		s.mu.Unlock()
		ok := closureQualified(m.Trigger, observed, s.forced.Load(), ended, readyAt, startBoundary, bound)
		passed = passed && ok
		observations = append(observations, observation{s.mode, ended.Sub(startBoundary).Milliseconds(), ended.Sub(completeBoundary).Milliseconds(), observed, ok, s.bytes.Load(), s.sent.Load()})
	}
	status, newDenied, transportUnavailable := freshRequest(c, config)
	unavailable := outageTrigger(m.Trigger) && transportUnavailable
	passed = passed && (newDenied || unavailable)
	output(map[string]any{"state": "measured", "trigger": m.Trigger, "evidence_ref": m.Evidence, "streams": observations, "new_request_status": status, "new_request_denied": newDenied, "new_request_transport_unavailable": unavailable, "fresh_request_phase": "while_trigger_remains_in_effect", "passed": passed, "bound_ms": 5000, "clock": "monotonic translated from same-host marker timestamps", "limitations": "No authority mutation performed by this driver. Already delivered bytes and upstream mutations cannot be erased. A passed timing uses mutation-start as conservative boundary; retained CP/Redis evidence must establish the named trigger. Outage transport unavailability is not an HTTP authority denial; recovery must be measured separately and may legitimately restore access."})
	if passed {
		return 0
	}
	return 1
}

func closureQualified(trigger string, observed, forced bool, ended, ready, start, bound time.Time) bool {
	lower := start
	if trigger == "grant-expiry" {
		lower = ready
	}
	return observed && !forced && !ended.Before(lower) && !ended.After(bound)
}

func validMarker(m marker, received time.Time) bool {
	return m.Phase == "" && m.Trigger != "" && m.Evidence != "" && !m.Started.IsZero() && !m.Completed.Before(m.Started) && !m.Completed.After(received) && received.Sub(m.Completed) <= time.Second && received.Sub(m.Started) <= 8*time.Second
}

func validAnnouncement(m marker, ready, received time.Time) bool {
	return m.Phase == "mutation_started" && !m.Started.IsZero() && !m.Started.Before(ready) && !m.Started.After(received) && received.Sub(m.Started) <= time.Second
}

func validFinalMarker(m marker, received, announced time.Time) bool {
	return validMarker(m, received) && (announced.IsZero() || m.Started.Equal(announced))
}

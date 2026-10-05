// Package sandboxrunner contains the external runner control boundary. It never
// owns a provider, user credentials, database pool or local execution fallback.
package sandboxrunner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Match the existing worker RPC ceiling so sixteen approved 32KiB skill
// documents plus their configurations fit without a separate transfer stack.
// The broker holds one pending effect and one fixed read-only health probe.
const PayloadLimit = 1 << 20
const QualificationReportLimit = 16 << 10

var ErrUnavailable = errors.New("runner unavailable")
var ErrInvalid = errors.New("invalid runner message")

type Command struct {
	ID       uuid.UUID       `json:"id"`
	Deadline time.Time       `json:"deadline"`
	Payload  json.RawMessage `json:"payload"`
}
type Reply struct {
	ID      uuid.UUID       `json:"id"`
	Payload json.RawMessage `json:"payload"`
}
type pending struct {
	command Command
	result  chan json.RawMessage
	// The fixed health command broadcasts one fresh reply to current callers.
	// It never retains a completed result for a later call.
	done    chan struct{}
	payload json.RawMessage
	err     error
	waiters int
	timer   *time.Timer
}

// Broker admits one outstanding effect and one independent read-only probe.
// Runner reconnects redeliver an effect's stable
// ID; effects must be durably deduplicated by the runner before replying.
type Broker struct {
	RunnerURI string
	mu        sync.Mutex
	pending   *pending
	health    *pending
	Revoked   bool
	Renew     func(*x509.Certificate) ([]byte, error)
	// Enrolled runners revalidate durable grant and certificate authority on
	// every request, including an already established TLS connection. Nil keeps
	// the explicitly pinned legacy runner identity unchanged.
	Authorize func(context.Context, *x509.Certificate) (cleanupOnly bool, err error)
	// Command authority is checked again when a command is polled or receipted.
	// A revoked runner can receive only its exact retained workload's cleanup.
	AuthorizeCommand    func(context.Context, *x509.Certificate, json.RawMessage) error
	RenewAuthorized     func(context.Context, *x509.Certificate) ([]byte, error)
	SubmitQualification func(context.Context, *x509.Certificate, json.RawMessage) error
	QualificationTrial  func(context.Context, *x509.Certificate, uuid.UUID, string, json.RawMessage) (json.RawMessage, error)
}

func NewBroker(identity string) (*Broker, error) {
	u, e := url.Parse(identity)
	if e != nil || u.Scheme != "spiffe" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Path == "" {
		return nil, ErrInvalid
	}
	return &Broker{RunnerURI: identity}, nil
}
func TLSConfig(cert tls.Certificate, roots *x509.CertPool) (*tls.Config, error) {
	if roots == nil || len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return nil, ErrInvalid
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}
func authenticated(r *http.Request, identity string) bool {
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if len(leaf.URIs) != 1 {
		return false
	}
	return leaf.URIs[0].String() == identity
}

func (b *Broker) authorize(r *http.Request) (*x509.Certificate, bool, error) {
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 || len(r.TLS.VerifiedChains[0][0].URIs) != 1 {
		return nil, false, ErrUnavailable
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if leaf.URIs[0].String() != b.RunnerURI {
		return nil, false, ErrUnavailable
	}
	if b.Authorize == nil {
		if !authenticated(r, b.RunnerURI) {
			return nil, false, ErrUnavailable
		}
		return leaf, false, nil
	}
	// TLS verifies time only during the handshake. Keep-alive requests must not
	// extend the original certificate's authority or cleanup lifetime.
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, false, ErrUnavailable
	}
	cleanupOnly, err := b.Authorize(r.Context(), leaf)
	return leaf, cleanupOnly, err
}
func (b *Broker) Call(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	return b.call(ctx, payload)
}

// This lane has no caller-controlled operation or workload authority. Health
// probes are read-only and need not enter the durable effect/replay machinery.
const healthPayload = `{"Version":1,"Operation":"ping"}`

const healthProbeLifetime = 30 * time.Second

func (b *Broker) CallHealth(ctx context.Context) (json.RawMessage, error) {
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) || time.Until(deadline) > healthProbeLifetime {
		return nil, ErrInvalid
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	b.mu.Lock()
	if b.Revoked {
		b.mu.Unlock()
		return nil, ErrUnavailable
	}
	p := b.health
	if p != nil && !p.command.Deadline.After(time.Now()) {
		b.completeHealthLocked(p, nil, ErrUnavailable)
		p = nil
	}
	if p == nil {
		// A canceled or short-lived first caller cannot expire another caller's
		// probe. The command has its own fixed protocol bound, and the last
		// departing waiter closes it sooner. Joining never extends this bound.
		p = &pending{command: Command{uuid.New(), time.Now().Add(healthProbeLifetime), json.RawMessage(healthPayload)}, done: make(chan struct{})}
		b.health = p
		p.timer = time.AfterFunc(time.Until(p.command.Deadline), func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.completeHealthLocked(p, nil, ErrUnavailable)
		})
	}
	p.waiters++
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		p.waiters--
		if p.waiters == 0 {
			b.completeHealthLocked(p, nil, ErrUnavailable)
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ErrUnavailable
	case <-p.done:
		if ctx.Err() != nil || !deadline.After(time.Now()) {
			return nil, ErrUnavailable
		}
		return append(json.RawMessage(nil), p.payload...), p.err
	}
}

// Called only under b.mu. Clearing the exact pointer prevents a late timer,
// cancellation or reply from retiring a newer probe.
func (b *Broker) completeHealthLocked(p *pending, payload json.RawMessage, err error) {
	if b.health != p {
		return
	}
	b.health = nil
	if p.timer != nil {
		p.timer.Stop()
	}
	p.payload, p.err = append(json.RawMessage(nil), payload...), err
	close(p.done)
}

func (b *Broker) call(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) || time.Until(deadline) > 30*time.Second || len(payload) > PayloadLimit || !json.Valid(payload) {
		return nil, ErrInvalid
	}
	p := &pending{command: Command{uuid.New(), deadline, append(json.RawMessage(nil), payload...)}, result: make(chan json.RawMessage, 1)}
	b.mu.Lock()
	if b.Revoked || b.pending != nil {
		b.mu.Unlock()
		return nil, ErrUnavailable
	}
	b.pending = p
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if b.pending == p {
			b.pending = nil
		}
		b.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return nil, ErrUnavailable
	case result := <-p.result:
		return result, nil
	}
}
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	leaf, cleanupOnly, authErr := b.authorize(r)
	if b.Revoked || authErr != nil {
		http.Error(w, "forbidden", 403)
		return
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		http.Error(w, "invalid", 400)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/internal/sandbox-runners/v1/qualification-trials/") {
		if cleanupOnly || b.Authorize == nil {
			http.Error(w, "forbidden", 403)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/internal/sandbox-runners/v1/qualification-trials/"), "/")
		if len(parts) != 2 {
			http.Error(w, "invalid", 400)
			return
		}
		id, err := uuid.Parse(parts[0])
		if err != nil || id == uuid.Nil || id.String() != parts[0] || (parts[1] != "status" && parts[1] != "witness") {
			http.Error(w, "invalid", 400)
			return
		}
		if b.QualificationTrial == nil {
			http.NotFound(w, r)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, QualificationReportLimit))
		if err != nil || (parts[1] == "status" && len(raw) != 0) || (parts[1] == "witness" && (r.Header.Get("Content-Type") != "application/json" || len(raw) == 0 || !json.Valid(raw))) {
			http.Error(w, "invalid", 400)
			return
		}
		out, err := b.QualificationTrial(r.Context(), leaf, id, parts[1], raw)
		if err != nil {
			if errors.Is(err, ErrInvalid) {
				http.Error(w, "invalid", 400)
			} else {
				http.Error(w, "unavailable", 503)
			}
			return
		}
		if parts[1] == "witness" {
			w.WriteHeader(204)
			return
		}
		if len(out) == 0 || len(out) > QualificationReportLimit || !json.Valid(out) {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
		return
	}
	switch r.URL.Path {
	case "/internal/sandbox-runners/v1/qualification":
		if cleanupOnly || b.Authorize == nil {
			http.Error(w, "forbidden", 403)
			return
		}
		if b.SubmitQualification == nil {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "invalid", 400)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, QualificationReportLimit))
		if err != nil || len(raw) == 0 || !json.Valid(raw) {
			http.Error(w, "invalid", 400)
			return
		}
		if err := b.SubmitQualification(r.Context(), leaf, raw); err != nil {
			if errors.Is(err, ErrInvalid) {
				http.Error(w, "invalid", 400)
			} else {
				http.Error(w, "unavailable", 503)
			}
			return
		}
		// A stored report is not native proof, an approval or a readiness claim.
		w.WriteHeader(204)
	case "/internal/sandbox-runners/v1/renew":
		if cleanupOnly {
			http.Error(w, "forbidden", 403)
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, 2))
		if e != nil || len(body) != 0 || (b.Renew == nil && b.RenewAuthorized == nil) {
			http.Error(w, "invalid", 400)
			return
		}
		var raw []byte
		if b.RenewAuthorized != nil {
			raw, e = b.RenewAuthorized(r.Context(), leaf)
		} else {
			raw, e = b.Renew(leaf)
		}
		if e != nil || len(raw) > 8192 {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(raw)

	case "/internal/sandbox-runners/v1/poll", "/internal/sandbox-runners/v1/health/poll":
		if cleanupOnly && r.URL.Path == "/internal/sandbox-runners/v1/health/poll" {
			http.Error(w, "forbidden", 403)
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, 2))
		if e != nil || len(body) != 0 {
			http.Error(w, "invalid", 400)
			return
		}
		b.mu.Lock()
		p := b.pending
		if r.URL.Path == "/internal/sandbox-runners/v1/health/poll" {
			p = b.health
		}
		if p == nil || !p.command.Deadline.After(time.Now()) {
			b.mu.Unlock()
			w.WriteHeader(204)
			return
		}
		command := p.command
		b.mu.Unlock()
		if (cleanupOnly && b.AuthorizeCommand == nil) || (b.AuthorizeCommand != nil && b.AuthorizeCommand(r.Context(), leaf, command.Payload) != nil) {
			http.Error(w, "forbidden", 403)
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		current := b.pending
		if r.URL.Path == "/internal/sandbox-runners/v1/health/poll" {
			current = b.health
		}
		if current != p || !command.Deadline.After(time.Now()) {
			w.WriteHeader(204)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(command)
	case "/internal/sandbox-runners/v1/reply", "/internal/sandbox-runners/v1/health/reply":
		if cleanupOnly && r.URL.Path == "/internal/sandbox-runners/v1/health/reply" {
			http.Error(w, "forbidden", 403)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "invalid", 400)
			return
		}
		var reply Reply
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, PayloadLimit+1024))
		d.DisallowUnknownFields()
		if d.Decode(&reply) != nil || d.Decode(new(any)) != io.EOF || len(reply.Payload) > PayloadLimit || !json.Valid(reply.Payload) {
			http.Error(w, "invalid", 400)
			return
		}
		b.mu.Lock()
		p := b.pending
		if r.URL.Path == "/internal/sandbox-runners/v1/health/reply" {
			p = b.health
		}
		if p == nil || reply.ID != p.command.ID || !p.command.Deadline.After(time.Now()) {
			b.mu.Unlock()
			http.Error(w, "conflict", 409)
			return
		}
		command := p.command
		b.mu.Unlock()
		if (cleanupOnly && b.AuthorizeCommand == nil) || (b.AuthorizeCommand != nil && b.AuthorizeCommand(r.Context(), leaf, command.Payload) != nil) {
			http.Error(w, "forbidden", 403)
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		current := b.pending
		if r.URL.Path == "/internal/sandbox-runners/v1/health/reply" {
			current = b.health
		}
		if current != p || !command.Deadline.After(time.Now()) {
			http.Error(w, "conflict", 409)
			return
		}
		if r.URL.Path == "/internal/sandbox-runners/v1/health/reply" {
			b.completeHealthLocked(p, reply.Payload, nil)
			w.WriteHeader(204)
			return
		}
		select {
		case p.result <- append(json.RawMessage(nil), reply.Payload...):
			w.WriteHeader(204)
		default:
			http.Error(w, "conflict", 409)
		}
	default:
		http.NotFound(w, r)
	}
}

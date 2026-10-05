package sandboxrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Client connects only to a configured HTTPS controller. Standard certificate
// DNS verification remains enabled; the verified leaf also pins controller URI.
type Client struct {
	base        string
	http        *http.Client
	Store       LeaseStore
	certMu      sync.Mutex
	certificate tls.Certificate
	roots       *x509.CertPool
}

func NewClient(base, serverName, controllerURI string, certificate tls.Certificate, roots *x509.CertPool, root *os.Root) (*Client, error) {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || serverName == "" || roots == nil || root == nil || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, ErrInvalid
	}
	if _, e = NewBroker(controllerURI); e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(certificate.Certificate[0])
	if e != nil || len(leaf.URIs) != 1 {
		return nil, ErrInvalid
	}
	certificate.Leaf = leaf
	c := &Client{base: "https://" + u.Host, Store: LeaseStore{root}, certificate: certificate, roots: roots}
	var saved struct{ Certificate []byte }
	if err := c.Store.read("runner-control-certificate.json", &saved); err == nil {
		renewed, err := c.validateRenewal(saved.Certificate)
		if err != nil {
			return nil, err
		}
		c.certificate = renewed
	} else if !os.IsNotExist(err) {
		return nil, ErrInvalid
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		c.certMu.Lock()
		defer c.certMu.Unlock()
		snapshot := c.certificate
		return &snapshot, nil
	}, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
			return ErrUnavailable
		}
		leaf := state.VerifiedChains[0][0]
		if len(leaf.URIs) != 1 || leaf.URIs[0].String() != controllerURI {
			return ErrUnavailable
		}
		return nil
	}}
	c.http = &http.Client{Transport: &http.Transport{TLSClientConfig: config, MaxResponseHeaderBytes: 4096, MaxConnsPerHost: 1}, Timeout: 25 * time.Second}
	return c, nil
}
func (c *Client) exchange(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if e != nil {
		return nil, 0, ErrInvalid
	}
	r.Header.Set("Content-Type", "application/json")
	out, e := c.http.Do(r)
	if e != nil {
		return nil, 0, ErrUnavailable
	}
	defer out.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(out.Body, PayloadLimit+1025))
	if e != nil || len(raw) > PayloadLimit+1024 {
		return nil, 0, ErrUnavailable
	}
	return raw, out.StatusCode, nil
}

type executionRecord struct {
	Command Command `json:"command"`
	Reply   *Reply  `json:"reply,omitempty"`
}

// ExecuteOne durably pins request identity before invoking an idempotent effect.
// A crash after effect/before receipt retries the same ID, never a new authority.
func (c *Client) ExecuteOne(ctx context.Context, command Command, execute func(context.Context, Command) (json.RawMessage, error)) (Reply, error) {
	if command.ID == [16]byte{} || !command.Deadline.After(time.Now()) || time.Until(command.Deadline) > 30*time.Second || len(command.Payload) > PayloadLimit || !json.Valid(command.Payload) || execute == nil {
		return Reply{}, ErrInvalid
	}
	if err := c.pruneCommands(time.Now(), command.ID.String()+".command.json"); err != nil {
		return Reply{}, err
	}
	name := command.ID.String() + ".command.json"
	record := executionRecord{Command: command}
	var old executionRecord
	e := c.Store.read(name, &old)
	if e == nil {
		if old.Command.ID != command.ID || !old.Command.Deadline.Equal(command.Deadline) || sha256.Sum256(old.Command.Payload) != sha256.Sum256(command.Payload) {
			return Reply{}, ErrInvalid
		}
		if old.Reply != nil {
			if old.Reply.ID != command.ID || len(old.Reply.Payload) > PayloadLimit || !json.Valid(old.Reply.Payload) {
				return Reply{}, ErrInvalid
			}
			return *old.Reply, nil
		}
	} else if !os.IsNotExist(e) {
		return Reply{}, e
	} else if e = c.Store.write(name, record); e != nil {
		return Reply{}, e
	}
	effectCtx, cancel := context.WithDeadline(ctx, command.Deadline)
	defer cancel()
	payload, e := execute(effectCtx, command)
	if e != nil {
		return Reply{}, e
	}
	if len(payload) > PayloadLimit || !json.Valid(payload) {
		return Reply{}, ErrInvalid
	}
	reply := Reply{command.ID, payload}
	record.Reply = &reply
	if e = c.Store.write(name, record); e != nil {
		return Reply{}, e
	}
	return reply, nil
}

// Run polls sequentially with a one-second bound between attempts. It does not
// log payloads, acquire provider authority or fall back to local CP execution.
func (c *Client) Run(ctx context.Context, execute func(context.Context, Command) (json.RawMessage, error)) error {
	if c == nil || c.http == nil || execute == nil {
		return ErrInvalid
	}
	healthCtx, healthCancel := context.WithCancel(ctx)
	healthDone := make(chan struct{})
	go func() {
		defer close(healthDone)
		c.runHealth(healthCtx, execute)
	}()
	defer func() { healthCancel(); <-healthDone }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		_ = c.renewIfDue(ctx)
		raw, status, e := c.exchange(ctx, "/internal/sandbox-runners/v1/poll", nil)
		if e != nil || status != 200 {
			continue
		}
		var command Command
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&command) != nil || d.Decode(new(any)) != io.EOF {
			continue
		}
		reply, e := c.ExecuteOne(ctx, command, execute)
		if e != nil {
			continue
		}
		body, e := json.Marshal(reply)
		if e != nil {
			continue
		}
		_, _, _ = c.exchange(ctx, "/internal/sandbox-runners/v1/reply", body)
	}
}

// Poll a separate, fixed read-only lane while an effect is awaiting an API
// callback. No arbitrary operation, durable effect, or extra effect concurrency
// is admitted here. The worker also validates ping before bypassing its lock.
func (c *Client) runHealth(ctx context.Context, execute func(context.Context, Command) (json.RawMessage, error)) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		raw, status, err := c.exchange(ctx, "/internal/sandbox-runners/v1/health/poll", nil)
		if err != nil || status != 200 {
			continue
		}
		var command Command
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&command) != nil || d.Decode(new(any)) != io.EOF || command.ID == [16]byte{} || !command.Deadline.After(time.Now()) || time.Until(command.Deadline) > 30*time.Second || string(command.Payload) != healthPayload {
			continue
		}
		probeCtx, cancel := context.WithDeadline(ctx, command.Deadline)
		payload, err := execute(probeCtx, command)
		cancel()
		if err != nil || len(payload) > PayloadLimit || !json.Valid(payload) {
			continue
		}
		body, err := json.Marshal(Reply{command.ID, payload})
		if err == nil {
			_, _, _ = c.exchange(ctx, "/internal/sandbox-runners/v1/health/reply", body)
		}
	}
}

// Bound durable protocol records independently of workload assets.
func (c *Client) pruneCommands(now time.Time, current string) error {
	dir, err := c.Store.Root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return err
	}
	count := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".command.json") {
			continue
		}
		var record executionRecord
		if err = c.Store.read(entry.Name(), &record); err != nil {
			return err
		}
		if !record.Command.Deadline.After(now) {
			if err = c.Store.Root.Remove(entry.Name()); err != nil {
				return err
			}
		} else if entry.Name() != current {
			count++
		}
	}
	if count >= 32 {
		return ErrUnavailable
	}
	return nil
}

func (c *Client) validateRenewal(raw []byte) (tls.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return tls.Certificate{}, ErrInvalid
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return tls.Certificate{}, ErrInvalid
	}
	original := c.certificate.Leaf
	if len(leaf.URIs) != 1 || len(original.URIs) != 1 || leaf.URIs[0].String() != original.URIs[0].String() || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, original.RawSubjectPublicKeyInfo) || time.Until(leaf.NotAfter) > 24*time.Hour+time.Minute {
		return tls.Certificate{}, ErrInvalid
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: c.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return tls.Certificate{}, ErrInvalid
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: c.certificate.PrivateKey, Leaf: leaf}, nil
}
func (c *Client) renewIfDue(ctx context.Context) error {
	c.certMu.Lock()
	due := time.Until(c.certificate.Leaf.NotAfter) < 12*time.Hour
	c.certMu.Unlock()
	if !due {
		return nil
	}
	raw, status, e := c.exchange(ctx, "/internal/sandbox-runners/v1/renew", nil)
	if e != nil || status != 200 || len(raw) > 8192 {
		return ErrUnavailable
	}
	renewed, e := c.validateRenewal(raw)
	if e != nil {
		return e
	}
	if e = c.Store.write("runner-control-certificate.json", struct{ Certificate []byte }{raw}); e != nil {
		return e
	}
	c.certMu.Lock()
	c.certificate = renewed
	c.certMu.Unlock()
	return nil
}

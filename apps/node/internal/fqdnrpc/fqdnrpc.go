// Package fqdnrpc implements the gateway half of the versioned, brokered FQDN
// resolution RPC. The control plane sends a request in authenticated desired
// state; only the selected gateway resolves it and posts the bound response
// back on the same mTLS channel. There is intentionally no control-plane or
// public-DNS fallback in this package.
package fqdnrpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Version is the first brokered FQDN-resolution wire version. A zero/missing
// version is an older agent/control plane and must be refused loudly, rather
// than silently falling back to a public resolver.
const Version = 1

const (
	maxRecords       = 32
	maxRequestFuture = 30 * time.Second
	cacheLifetime    = 10 * time.Minute
)

// RecordType is a DNS answer type. Requests carry the full A/AAAA/CNAME record
// set so a selected gateway returns one correlated dual-stack observation.
type RecordType string

const (
	RecordA     RecordType = "A"
	RecordAAAA  RecordType = "AAAA"
	RecordCNAME RecordType = "CNAME"
)

// Request binds a DNS lookup to one tenant, resource, selected Site and
// selected gateway. All identifiers are echoed in Response and must be checked
// by the control plane before accepting the answer.
type Request struct {
	Version     int          `json:"version"`
	RequestID   string       `json:"request_id"`
	OrgID       string       `json:"org_id"`
	ResourceID  string       `json:"resource_id"`
	SiteID      string       `json:"site_id"`
	GatewayID   string       `json:"gateway_id"`
	Hostname    string       `json:"hostname"`
	RecordTypes []RecordType `json:"record_types"`
	Deadline    time.Time    `json:"deadline"`
}

// Record is one response record. Data is a canonical IP literal for A/AAAA and
// an exact normalized FQDN for CNAME. TTLSeconds is the resolver-observed TTL;
// the control plane applies the approved 30s–1h effective bound.
type Record struct {
	Name       string     `json:"name"`
	Type       RecordType `json:"type"`
	Address    string     `json:"address,omitempty"`
	Target     string     `json:"target,omitempty"`
	TTLSeconds int        `json:"ttl_seconds"`
}

type Status string

const (
	StatusNoError  Status = "noerror"
	StatusNXDomain Status = "nxdomain"
	StatusServFail Status = "servfail"
)

// Response deliberately echoes the complete request binding. ObservedAt is a
// gateway observation, not a control-plane receipt timestamp, so stale/replay
// detection remains possible after a disconnect or delayed response post.
type Response struct {
	Version     int          `json:"version"`
	RequestID   string       `json:"request_id"`
	OrgID       string       `json:"org_id"`
	ResourceID  string       `json:"resource_id"`
	SiteID      string       `json:"site_id"`
	GatewayID   string       `json:"gateway_id"`
	Hostname    string       `json:"hostname"`
	RecordTypes []RecordType `json:"record_types"`
	Status      Status       `json:"status"`
	ErrorCode   string       `json:"error_code,omitempty"`
	ObservedAt  time.Time    `json:"observed_at"`
	Records     []Record     `json:"records,omitempty"`
}

// Resolver is deliberately injected. The production agent uses its selected
// gateway's local resolver context; this package cannot and does not contact a
// public resolver as a fallback.
type Resolver interface {
	Resolve(context.Context, string, []RecordType) ([]Record, error)
}

// LocalResolver resolves through the selected gateway's configured local DNS
// context. It is invoked only by that selected gateway after the full request
// binding passes validation; no alternative resolver is attempted on failure.
type LocalResolver struct{ Resolver *net.Resolver }

func (r LocalResolver) Resolve(ctx context.Context, hostname string, types []RecordType) ([]Record, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	var out []Record
	if cname, err := resolver.LookupCNAME(ctx, hostname); err == nil {
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")
		if cname != hostname {
			out = append(out, Record{Name: hostname, Type: RecordCNAME, Target: cname, TTLSeconds: 30})
		}
	} else {
		return nil, err
	}
	for _, typ := range types {
		if typ == RecordCNAME {
			continue // LookupCNAME above already supplied the observed canonical name.
		}
		family := "ip4"
		if typ == RecordAAAA {
			family = "ip6"
		}
		addrs, err := resolver.LookupNetIP(ctx, family, hostname)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if (typ == RecordA && !addr.Is4()) || (typ == RecordAAAA && !addr.Is6()) {
				continue
			}
			out = append(out, Record{Name: hostname, Type: typ, Address: addr.String(), TTLSeconds: 30})
		}
	}
	return out, nil
}

// Responder caches a response per exact request identity. A retry following a
// disconnected response post returns the same observation; a reused request ID
// with changed tenant/resource/site/gateway/hostname input is refused and never
// reaches DNS.
type Responder struct {
	resolver Resolver
	now      func() time.Time
	mu       sync.Mutex
	seen     map[string]cached
}

type cached struct {
	fingerprint string
	response    Response
	expiresAt   time.Time
}

func NewResponder(resolver Resolver) *Responder {
	return &Responder{resolver: resolver, now: time.Now, seen: make(map[string]cached)}
}

// Handle resolves only an authenticated desired-state request addressed to the
// gateway currently running this agent. It returns a typed refusal for every
// invalid/expired/unsupported request; callers should post that response over
// mTLS so the control plane can withdraw generation rather than guessing.
func (r *Responder) Handle(ctx context.Context, gatewayID string, req Request) Response {
	now := r.now().UTC()
	if code := validateRequest(req, gatewayID, now); code != "" {
		return responseFor(req, StatusServFail, code, now)
	}
	if r.resolver == nil {
		return responseFor(req, StatusServFail, "resolver_unavailable", now)
	}

	fp := requestFingerprint(req)
	r.mu.Lock()
	for id, old := range r.seen {
		if !now.Before(old.expiresAt) {
			delete(r.seen, id)
		}
	}
	if old, ok := r.seen[req.RequestID]; ok {
		r.mu.Unlock()
		if old.fingerprint != fp {
			return responseFor(req, StatusServFail, "resolver_unavailable", now)
		}
		return old.response
	}
	r.mu.Unlock()

	deadline := req.Deadline
	if max := now.Add(maxRequestFuture); deadline.After(max) {
		deadline = max
	}
	lookupCtx, cancel := context.WithDeadline(ctx, deadline)
	records, err := r.resolver.Resolve(lookupCtx, req.Hostname, req.RecordTypes)
	cancel()
	observed := r.now().UTC()
	resp := responseFor(req, StatusNoError, "", observed)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			resp = responseFor(req, StatusNXDomain, "", observed)
		} else if errors.Is(err, context.DeadlineExceeded) || !observed.Before(req.Deadline) {
			resp = responseFor(req, StatusServFail, "deadline_exceeded", observed)
		} else {
			resp = responseFor(req, StatusServFail, "disconnected", observed)
		}
	} else if code := validateRecords(req, records); code != "" {
		resp = responseFor(req, StatusServFail, "resolver_unavailable", observed)
	} else {
		resp.Records = records
	}

	r.mu.Lock()
	r.seen[req.RequestID] = cached{fingerprint: fp, response: resp, expiresAt: now.Add(cacheLifetime)}
	r.mu.Unlock()
	return resp
}

func responseFor(req Request, status Status, code string, observed time.Time) Response {
	return Response{Version: Version, RequestID: req.RequestID, OrgID: req.OrgID,
		ResourceID: req.ResourceID, SiteID: req.SiteID, GatewayID: req.GatewayID,
		Hostname: req.Hostname, RecordTypes: append([]RecordType(nil), req.RecordTypes...),
		Status: status, ErrorCode: code, ObservedAt: observed}
}

func validateRequest(req Request, gatewayID string, now time.Time) string {
	if req.Version != Version {
		return "unsupported_version"
	}
	if !isUUID(req.RequestID) || !isUUID(req.OrgID) || !isUUID(req.ResourceID) || !isUUID(req.SiteID) || !isUUID(req.GatewayID) {
		return "resolver_unavailable"
	}
	if req.GatewayID != gatewayID {
		return "disconnected"
	}
	if !validRecordTypes(req.RecordTypes) {
		return "resolver_unavailable"
	}
	if !validHostname(req.Hostname) {
		return "resolver_unavailable"
	}
	if req.Deadline.IsZero() || !req.Deadline.After(now) {
		return "deadline_exceeded"
	}
	return ""
}

func validateRecords(req Request, records []Record) string {
	if len(records) > maxRecords {
		return "answer_overflow"
	}
	for _, record := range records {
		if !validHostname(record.Name) || record.TTLSeconds < 0 {
			return "resolver_unavailable"
		}
		switch record.Type {
		case RecordCNAME:
			if record.Address != "" || !validHostname(record.Target) {
				return "resolver_unavailable"
			}
		case RecordA:
			addr, err := netip.ParseAddr(record.Address)
			if err != nil || !addr.Is4() {
				return "resolver_unavailable"
			}
		case RecordAAAA:
			addr, err := netip.ParseAddr(record.Address)
			if err != nil || !addr.Is6() {
				return "resolver_unavailable"
			}
		default:
			return "resolver_unavailable"
		}
	}
	return ""
}

func requestFingerprint(req Request) string {
	s := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s", req.Version, req.OrgID, req.ResourceID,
		req.SiteID, req.GatewayID, req.Hostname, strings.Join(recordTypeNames(req.RecordTypes), ","), req.Deadline.UTC().Format(time.RFC3339Nano), req.RequestID)
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func validRecordTypes(types []RecordType) bool {
	if len(types) != 3 {
		return false
	}
	return types[0] == RecordA && types[1] == RecordAAAA && types[2] == RecordCNAME
}

func recordTypeNames(types []RecordType) []string {
	out := make([]string, len(types))
	for i, typ := range types {
		out[i] = string(typ)
	}
	return out
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func validHostname(s string) bool {
	if s == "" || len(s) > 253 || strings.HasSuffix(s, ".") || strings.ToLower(s) != s {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}

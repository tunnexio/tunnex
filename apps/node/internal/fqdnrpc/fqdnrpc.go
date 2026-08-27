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
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
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
	// ResolverConfig* are the immutable server-managed direct resolver snapshot
	// bound to this Site/Gateway request. Their JSON names deliberately mirror
	// the durable mailbox/control payload. Missing/invalid values are a refusal,
	// never permission to consult resolv.conf, net.DefaultResolver, public DNS,
	// or the control plane.
	ResolverConfigID      string             `json:"resolver_config_id"`
	ResolverConfigVersion int64              `json:"resolver_config_version"`
	ResolverEndpoints     []ResolverEndpoint `json:"resolver_endpoints"`
}

type ResolverConfig struct {
	ID        string             `json:"id"`
	Version   int64              `json:"version"`
	Endpoints []ResolverEndpoint `json:"endpoints"`
}

type ResolverEndpoint struct {
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Transport string `json:"transport"` // udp | tcp
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
	Version               int          `json:"version"`
	RequestID             string       `json:"request_id"`
	OrgID                 string       `json:"org_id"`
	ResourceID            string       `json:"resource_id"`
	SiteID                string       `json:"site_id"`
	GatewayID             string       `json:"gateway_id"`
	ResolverConfigID      string       `json:"resolver_config_id,omitempty"`
	ResolverConfigVersion int64        `json:"resolver_config_version,omitempty"`
	Hostname              string       `json:"hostname"`
	RecordTypes           []RecordType `json:"record_types"`
	Status                Status       `json:"status"`
	ErrorCode             string       `json:"error_code,omitempty"`
	ObservedAt            time.Time    `json:"observed_at"`
	Records               []Record     `json:"records,omitempty"`
}

// Resolver is deliberately injected. The production agent uses its selected
// gateway's local resolver context; this package cannot and does not contact a
// public resolver as a fallback.
type Resolver interface {
	Resolve(context.Context, string, []RecordType) ([]Record, error)
}

// BoundResolver receives the immutable endpoint snapshot that the control
// plane bound to this Site/Gateway request. It must never select a resolver
// itself. DirectResolver below is the production implementation.
type BoundResolver interface {
	ResolveBound(context.Context, string, []RecordType, ResolverConfig) ([]Record, error)
}

var errResolverConfig = errors.New("resolver configuration unavailable")

// DirectResolver sends DNS packets only to server-managed literal IP endpoints.
// Each configured endpoint must return the same bounded observation; timeout,
// malformed response, transport failure, or disagreement fails the request
// closed. It deliberately has no net.Resolver field or system fallback.
type DirectResolver struct {
	exchange func(context.Context, ResolverEndpoint, string, RecordType) ([]Record, error)
}

func (d DirectResolver) ResolveBound(ctx context.Context, hostname string, types []RecordType, config ResolverConfig) ([]Record, error) {
	if !validResolverConfig(config) {
		return nil, errResolverConfig
	}
	var canonical []Record
	for _, endpoint := range config.Endpoints {
		records, err := d.resolveEndpoint(ctx, endpoint, hostname, types)
		if err != nil {
			return nil, errResolverConfig
		}
		records = canonicalRecords(records)
		if !validDirectRecords(hostname, types, records) {
			return nil, errResolverConfig
		}
		if canonical == nil {
			canonical = records
			continue
		}
		if !sameRecords(canonical, records) {
			return nil, errResolverConfig
		}
	}
	addresses := 0
	for _, record := range canonical {
		if record.Type == RecordA || record.Type == RecordAAAA {
			addresses++
		}
	}
	if addresses == 0 {
		return nil, errResolverConfig
	}
	return canonical, nil
}

func (d DirectResolver) resolveEndpoint(ctx context.Context, endpoint ResolverEndpoint, hostname string, types []RecordType) ([]Record, error) {
	exchange := d.exchange
	if exchange == nil {
		exchange = directExchange
	}
	current := hostname
	seen := map[string]bool{}
	var all []Record
	for depth := 0; depth <= 8; depth++ {
		if seen[current] {
			return nil, fmt.Errorf("cname loop")
		}
		seen[current] = true
		var step []Record
		for _, typ := range types {
			if typ == RecordCNAME {
				continue
			}
			got, err := exchange(ctx, endpoint, current, typ)
			if err != nil {
				return nil, err
			}
			step = append(step, got...)
		}
		step = canonicalRecords(step)
		all = append(all, step...)
		targets := map[string]bool{}
		for _, record := range step {
			if record.Type == RecordCNAME && record.Name == current {
				targets[record.Target] = true
			}
		}
		if len(targets) == 0 {
			return canonicalRecords(all), nil
		}
		if len(targets) != 1 {
			return nil, fmt.Errorf("cname disagreement")
		}
		for current = range targets {
		}
	}
	return nil, fmt.Errorf("cname depth exceeded")
}

func validResolverConfig(config ResolverConfig) bool {
	if !isUUID(config.ID) || config.Version < 1 || len(config.Endpoints) == 0 || len(config.Endpoints) > 8 {
		return false
	}
	seen := map[string]bool{}
	for _, endpoint := range config.Endpoints {
		ip, err := netip.ParseAddr(endpoint.Address)
		if err != nil || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || endpoint.Port < 1 || endpoint.Port > 65535 || (endpoint.Transport != "udp" && endpoint.Transport != "tcp") {
			return false
		}
		key := ip.String() + ":" + strconv.Itoa(endpoint.Port) + ":" + endpoint.Transport
		if seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func canonicalRecords(in []Record) []Record {
	out := append([]Record(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.Name+"|"+string(a.Type)+"|"+a.Address+"|"+a.Target+"|"+strconv.Itoa(a.TTLSeconds) < b.Name+"|"+string(b.Type)+"|"+b.Address+"|"+b.Target+"|"+strconv.Itoa(b.TTLSeconds)
	})
	if len(out) < 2 {
		return out
	}
	unique := out[:1]
	for _, r := range out[1:] {
		if r != unique[len(unique)-1] {
			unique = append(unique, r)
		}
	}
	return unique
}

func validDirectRecords(hostname string, types []RecordType, records []Record) bool {
	if validateRecords(Request{Hostname: hostname, RecordTypes: types}, records) != "" {
		return false
	}
	addresses, cnames := 0, 0
	for _, record := range records {
		switch record.Type {
		case RecordA, RecordAAAA:
			addresses++
		case RecordCNAME:
			cnames++
		}
	}
	return addresses <= maxRecords && cnames <= 8
}

func sameRecords(a, b []Record) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func directExchange(ctx context.Context, endpoint ResolverEndpoint, hostname string, typ RecordType) ([]Record, error) {
	name, err := dnsmessage.NewName(hostname + ".")
	if err != nil {
		return nil, err
	}
	qtype := dnsmessage.TypeA
	if typ == RecordAAAA {
		qtype = dnsmessage.TypeAAAA
	}
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}}}
	payload, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	address := net.JoinHostPort(endpoint.Address, strconv.Itoa(endpoint.Port))
	var response []byte
	if endpoint.Transport == "udp" {
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		if _, err := conn.Write(payload); err != nil {
			return nil, err
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		response = buf[:n]
	} else {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		frame := append([]byte{byte(len(payload) >> 8), byte(len(payload))}, payload...)
		if _, err := conn.Write(frame); err != nil {
			return nil, err
		}
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		n := int(size[0])<<8 | int(size[1])
		if n == 0 || n > 65535 {
			return nil, fmt.Errorf("invalid dns tcp frame")
		}
		response = make([]byte, n)
		if _, err := io.ReadFull(conn, response); err != nil {
			return nil, err
		}
	}
	var decoded dnsmessage.Message
	if err := decoded.Unpack(response); err != nil {
		return nil, err
	}
	if !decoded.Header.Response || decoded.Header.ID != msg.Header.ID || decoded.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("invalid dns response")
	}
	var out []Record
	for _, answer := range decoded.Answers {
		name := strings.TrimSuffix(strings.ToLower(answer.Header.Name.String()), ".")
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			if typ == RecordA {
				out = append(out, Record{Name: name, Type: RecordA, Address: netip.AddrFrom4(body.A).String(), TTLSeconds: int(answer.Header.TTL)})
			}
		case *dnsmessage.AAAAResource:
			if typ == RecordAAAA {
				out = append(out, Record{Name: name, Type: RecordAAAA, Address: netip.AddrFrom16(body.AAAA).String(), TTLSeconds: int(answer.Header.TTL)})
			}
		case *dnsmessage.CNAMEResource:
			out = append(out, Record{Name: name, Type: RecordCNAME, Target: strings.TrimSuffix(strings.ToLower(body.CNAME.String()), "."), TTLSeconds: int(answer.Header.TTL)})
		}
	}
	return out, nil
}

// LocalResolver resolves through the selected gateway's configured local DNS
// context. It is invoked only by that selected gateway after the full request
// binding passes validation; no alternative resolver is attempted on failure.
type LocalResolver struct {
	Resolver    *net.Resolver
	lookupCNAME func(context.Context, string) (string, error)
	lookupNetIP func(context.Context, string, string) ([]netip.Addr, error)
}

func (r LocalResolver) Resolve(ctx context.Context, hostname string, types []RecordType) ([]Record, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	lookupCNAME := r.lookupCNAME
	if lookupCNAME == nil {
		lookupCNAME = resolver.LookupCNAME
	}
	lookupNetIP := r.lookupNetIP
	if lookupNetIP == nil {
		lookupNetIP = resolver.LookupNetIP
	}
	var out []Record
	if cname, err := lookupCNAME(ctx, hostname); err == nil {
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")
		if cname != hostname {
			out = append(out, Record{Name: hostname, Type: RecordCNAME, Target: cname, TTLSeconds: 30})
		}
	}
	var lookupErrs []error
	usableFamily := false
	for _, typ := range types {
		if typ == RecordCNAME {
			continue // LookupCNAME above already supplied the observed canonical name.
		}
		family := "ip4"
		if typ == RecordAAAA {
			family = "ip6"
		}
		addrs, err := lookupNetIP(ctx, family, hostname)
		if err != nil {
			// A and AAAA are independently useful. One family failing must not
			// discard a usable answer from the other family; the control plane
			// will reject only the unusable family and publish only what remains.
			lookupErrs = append(lookupErrs, err)
			continue
		}
		for _, addr := range addrs {
			if (typ == RecordA && !addr.Is4()) || (typ == RecordAAAA && !addr.Is6()) {
				continue
			}
			out = append(out, Record{Name: hostname, Type: typ, Address: addr.String(), TTLSeconds: 30})
			usableFamily = true
		}
	}
	if !usableFamily && len(lookupErrs) > 0 {
		return nil, errors.Join(lookupErrs...)
	}
	return out, nil
}

// Responder caches a response per exact request identity. A retry following a
// disconnected response post returns the same observation; a reused request ID
// with changed tenant/resource/site/gateway/hostname input is refused and never
// reaches DNS.
type Responder struct {
	resolver any // Resolver or BoundResolver; production uses BoundResolver only.
	now      func() time.Time
	mu       sync.Mutex
	seen     map[string]cached
}

type cached struct {
	fingerprint string
	response    Response
	expiresAt   time.Time
}

func NewResponder(resolver any) *Responder {
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
	var records []Record
	var err error
	if bound, ok := r.resolver.(BoundResolver); ok {
		records, err = bound.ResolveBound(lookupCtx, req.Hostname, req.RecordTypes, ResolverConfig{ID: req.ResolverConfigID, Version: req.ResolverConfigVersion, Endpoints: req.ResolverEndpoints})
	} else if plain, ok := r.resolver.(Resolver); ok {
		records, err = plain.Resolve(lookupCtx, req.Hostname, req.RecordTypes)
	} else {
		err = errResolverConfig
	}
	cancel()
	observed := r.now().UTC()
	resp := responseFor(req, StatusNoError, "", observed)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.Is(err, errResolverConfig) {
			resp = responseFor(req, StatusServFail, "resolver_unavailable", observed)
		} else if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
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
		ResolverConfigID: req.ResolverConfigID, ResolverConfigVersion: req.ResolverConfigVersion,
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
	config := ""
	if req.ResolverConfigID != "" {
		config = req.ResolverConfigID + "|" + strconv.FormatInt(req.ResolverConfigVersion, 10)
		for _, endpoint := range req.ResolverEndpoints {
			config += "|" + endpoint.Address + ":" + strconv.Itoa(endpoint.Port) + "/" + endpoint.Transport
		}
	}
	s := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s|%s", req.Version, req.OrgID, req.ResourceID,
		req.SiteID, req.GatewayID, req.Hostname, strings.Join(recordTypeNames(req.RecordTypes), ","), req.Deadline.UTC().Format(time.RFC3339Nano), req.RequestID, config)
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

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
const Version = 2

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
	ResolverProfileID     string             `json:"resolver_profile_id"`
	ResolverMatchSuffix   string             `json:"resolver_match_suffix,omitempty"`
	ResolverEndpoints     []ResolverEndpoint `json:"resolver_endpoints"`
	ResolverIPsecPath     *IPsecPath         `json:"resolver_ipsec_path,omitempty"`
}

type ResolverConfig struct {
	ID            string             `json:"id"`
	Version       int64              `json:"version"`
	ProfileID     string             `json:"profile_id"`
	MatchedSuffix string             `json:"matched_suffix"`
	Endpoints     []ResolverEndpoint `json:"endpoints"`
	IPsecPath     *IPsecPath         `json:"ipsec_path,omitempty"`
}

// IPsecPath is an immutable server-bound resolver transport selection. It
// conveys no packet authority: a transport must independently prove the exact
// connection, native path, owned source and current leased DNS-only guard.
type IPsecPath struct {
	ConnectionID          string `json:"connection_id"`
	ConfigurationRevision int64  `json:"configuration_revision"`
	SourceAddress         string `json:"source_address"`
}

// BoundTransport sends a DNS message through the already selected resolver
// profile. Implementations must fail closed rather than choosing a WAN route.
type BoundTransport interface {
	ExchangeDNS(context.Context, ResolverConfig, ResolverEndpoint, []byte) ([]byte, error)
}

// BoundTransportValidator reproves authority before returning a retry cache
// entry. A DNS answer cache must never survive IPsec lease or native path loss.
type BoundTransportValidator interface {
	ValidateDNSPath(context.Context, ResolverConfig, ResolverEndpoint) error
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
	StatusNoError  Status = "NOERROR"
	StatusNXDomain Status = "NXDOMAIN"
	StatusServFail Status = "SERVFAIL"
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
	ResolverProfileID     string       `json:"resolver_profile_id,omitempty"`
	ResolverMatchSuffix   string       `json:"resolver_match_suffix,omitempty"`
	ResolverIPsecPath     *IPsecPath   `json:"resolver_ipsec_path,omitempty"`
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

// resolverStatusError carries an authoritative DNS terminal outcome from a
// configured endpoint. It is distinct from transport/configuration failure so
// NXDOMAIN and SERVFAIL withdraw with their truthful lifecycle causes.
type resolverStatusError struct{ status Status }

func (e resolverStatusError) Error() string { return string(e.status) }

// DirectResolver sends DNS packets only to server-managed literal IP endpoints.
// Each configured endpoint must return the same bounded observation; timeout,
// malformed response, transport failure, or disagreement fails the request
// closed. It deliberately has no net.Resolver field or system fallback.
type DirectResolver struct {
	exchange  func(context.Context, ResolverEndpoint, string, RecordType) ([]Record, error)
	Transport BoundTransport
}

func (d DirectResolver) ResolveBound(ctx context.Context, hostname string, types []RecordType, config ResolverConfig) (result []Record, resultErr error) {
	defer func() { finishLookupTiming(ctx, resultErr) }()
	if !validResolverConfig(config) {
		return nil, errResolverConfig
	}
	// Each endpoint remains independently authoritative. Bound concurrency to
	// four complete endpoint workflows, each with at most two independent record
	// exchanges. CNAME steps remain sequential; every exchange keeps its proofs.
	config.Endpoints = append([]ResolverEndpoint(nil), config.Endpoints...)
	types = append([]RecordType(nil), types...)
	if config.IPsecPath != nil {
		path := *config.IPsecPath
		config.IPsecPath = &path
	}
	type endpointResult struct {
		records []Record
		err     error
	}
	results := make([]endpointResult, len(config.Endpoints))
	jobs := make(chan int, len(config.Endpoints))
	for i := range config.Endpoints {
		jobs <- i
	}
	close(jobs)
	var workers sync.WaitGroup
	for range min(4, len(config.Endpoints)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range jobs {
				if err := ctx.Err(); err != nil {
					results[i].err = err
					continue
				}
				results[i].records, results[i].err = d.resolveEndpoint(ctx, config, config.Endpoints[i], hostname, types)
			}
		}()
	}
	// Drain before returning, including on cancellation. Reduce in configured
	// order, so faster replies never decide consensus or DNS error precedence.
	workers.Wait()
	markLookupWorkersDrained(ctx)
	var canonical []Record
	for _, result := range results {
		records, err := result.records, result.err
		if err != nil {
			var statusErr resolverStatusError
			if errors.As(err, &statusErr) {
				return nil, err
			}
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
		// TTL is a cache observation, not record identity. Sequential queries to
		// equally authoritative endpoints (especially UDP followed by TCP to the
		// same resolver) can legitimately return different remaining TTLs. Keep
		// endpoint consensus fail-closed for names/types/values, while publishing
		// the most conservative TTL observed across every configured endpoint.
		for i := range canonical {
			if records[i].TTLSeconds < canonical[i].TTLSeconds {
				canonical[i].TTLSeconds = records[i].TTLSeconds
			}
		}
	}
	addresses := 0
	for _, record := range canonical {
		if record.Type == RecordA || record.Type == RecordAAAA {
			addresses++
		}
	}
	if addresses == 0 || ctx.Err() != nil {
		return nil, errResolverConfig
	}
	return canonical, nil
}

func (d DirectResolver) ValidateBound(ctx context.Context, config ResolverConfig) error {
	if config.IPsecPath == nil {
		return nil
	}
	validator, ok := d.Transport.(BoundTransportValidator)
	if !ok || !validResolverConfig(config) {
		return errResolverConfig
	}
	for _, endpoint := range config.Endpoints {
		if validator.ValidateDNSPath(ctx, config, endpoint) != nil {
			return errResolverConfig
		}
	}
	return nil
}

func (d DirectResolver) resolveEndpoint(ctx context.Context, config ResolverConfig, endpoint ResolverEndpoint, hostname string, types []RecordType) ([]Record, error) {
	exchange := d.exchange
	if config.IPsecPath != nil {
		// An injected ordinary resolver never bypasses a declared IPsec path.
		if d.Transport == nil {
			return nil, errResolverConfig
		}
		exchange = func(ctx context.Context, e ResolverEndpoint, name string, typ RecordType) ([]Record, error) {
			return directBoundExchange(ctx, d.Transport, config, e, name, typ)
		}
	} else if exchange == nil {
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
		// A and AAAA at the same name are independent exchanges. Reduce in
		// requested type order after draining both, preserving error precedence.
		type typeResult struct {
			records []Record
			err     error
		}
		results := make([]typeResult, len(types))
		jobs := make(chan int, len(types))
		for i, typ := range types {
			if typ != RecordCNAME {
				jobs <- i
			}
		}
		close(jobs)
		var workers sync.WaitGroup
		for range min(2, len(types)) {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for i := range jobs {
					if err := ctx.Err(); err != nil {
						results[i].err = err
						continue
					}
					results[i].records, results[i].err = exchange(ctx, endpoint, current, types[i])
				}
			}()
		}
		workers.Wait()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var step []Record
		for _, result := range results {
			if result.err != nil {
				return nil, result.err
			}
			step = append(step, result.records...)
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
	if !isUUID(config.ID) || !isUUID(config.ProfileID) || config.Version < 1 || len(config.Endpoints) == 0 || len(config.Endpoints) > 8 {
		return false
	}
	seen := map[string]bool{}
	if config.IPsecPath != nil && !validIPsecPath(*config.IPsecPath) {
		return false
	}
	for _, endpoint := range config.Endpoints {
		ip, err := netip.ParseAddr(endpoint.Address)
		if err != nil || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || endpoint.Port < 1 || endpoint.Port > 65535 || (endpoint.Transport != "udp" && endpoint.Transport != "tcp") {
			return false
		}
		if config.IPsecPath != nil && (!ip.Is4() || endpoint.Port != 53) {
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
		last := &unique[len(unique)-1]
		if r.Name == last.Name && r.Type == last.Type && r.Address == last.Address && r.Target == last.Target {
			if r.TTLSeconds < last.TTLSeconds {
				last.TTLSeconds = r.TTLSeconds
			}
		} else {
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
		if a[i].Name != b[i].Name || a[i].Type != b[i].Type || a[i].Address != b[i].Address || a[i].Target != b[i].Target {
			return false
		}
	}
	return true
}

func directExchange(ctx context.Context, endpoint ResolverEndpoint, hostname string, typ RecordType) ([]Record, error) {
	return directBoundExchange(ctx, configlessTransport{}, ResolverConfig{}, endpoint, hostname, typ)
}

func directBoundExchange(ctx context.Context, transport BoundTransport, config ResolverConfig, endpoint ResolverEndpoint, hostname string, typ RecordType) ([]Record, error) {
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
	response, err := exchangeDNSPacket(ctx, transport, config, endpoint, payload)
	if err != nil {
		return nil, err
	}
	var decoded dnsmessage.Message
	if err := decoded.Unpack(response); err != nil {
		return nil, err
	}
	if !decoded.Header.Response || decoded.Header.ID != msg.Header.ID {
		return nil, fmt.Errorf("invalid dns response")
	}
	switch decoded.Header.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, resolverStatusError{status: StatusNXDomain}
	case dnsmessage.RCodeServerFailure:
		return nil, resolverStatusError{status: StatusServFail}
	default:
		return nil, fmt.Errorf("dns rcode %d", decoded.Header.RCode)
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
	inflight map[string]string
}

type cached struct {
	fingerprint string
	response    Response
	expiresAt   time.Time
}

func NewResponder(resolver any) *Responder {
	return &Responder{resolver: resolver, now: time.Now, seen: make(map[string]cached)}
}

// RunDisposition is admission only, never a DNS answer or native authority.
type RunDisposition uint8

const (
	RunCompleted RunDisposition = iota
	RunDuplicatePending
	RunConflictingPending
	RunAtCapacity
)
const maxInflightRequests = 64

// Run admits one complete Handle/report workflow for an immutable pending ID.
// Completed replay remains in Handle; this registry never caches answers, waits
// for another request, or displaces a live job. The callback retains its original
// context/deadline and proofs. Release includes report failure and panic paths.
func (r *Responder) Run(ctx context.Context, gatewayID string, req Request, run func()) RunDisposition {
	fp := gatewayID + "|" + requestFingerprint(req)
	r.mu.Lock()
	if active, ok := r.inflight[req.RequestID]; ok {
		r.mu.Unlock()
		if active != fp {
			return RunConflictingPending
		}
		return RunDuplicatePending
	}
	// Preserve the original typed refusal path for malformed/expired/cancelled
	// inputs; they do not allocate persistent admission entries.
	if ctx.Err() != nil || validateRequest(req, gatewayID, r.now().UTC()) != "" {
		r.mu.Unlock()
		run()
		return RunCompleted
	}
	if len(r.inflight) >= maxInflightRequests {
		r.mu.Unlock()
		return RunAtCapacity
	}
	if r.inflight == nil {
		r.inflight = make(map[string]string)
	}
	r.inflight[req.RequestID] = fp
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.inflight, req.RequestID); r.mu.Unlock() }()
	run()
	return RunCompleted
}

// Handle resolves only an authenticated desired-state request addressed to the
// gateway currently running this agent. It returns a typed refusal for every
// invalid/expired/unsupported request; callers should post that response over
// mTLS so the control plane can withdraw generation rather than guessing.
func (r *Responder) Handle(ctx context.Context, gatewayID string, req Request) Response {
	if req.ResolverIPsecPath != nil {
		path := *req.ResolverIPsecPath
		req.ResolverIPsecPath = &path
	}
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
		if req.ResolverIPsecPath != nil {
			validator, ok := r.resolver.(interface {
				ValidateBound(context.Context, ResolverConfig) error
			})
			lookupCtx, cancel := context.WithDeadline(ctx, req.Deadline)
			valid := ok && validator.ValidateBound(lookupCtx, ResolverConfig{ID: req.ResolverConfigID, Version: req.ResolverConfigVersion, ProfileID: req.ResolverProfileID, MatchedSuffix: req.ResolverMatchSuffix, Endpoints: req.ResolverEndpoints, IPsecPath: req.ResolverIPsecPath}) == nil
			cancel()
			if !valid {
				return responseFor(req, StatusServFail, "resolver_unavailable", now)
			}
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
		records, err = bound.ResolveBound(lookupCtx, req.Hostname, req.RecordTypes, ResolverConfig{ID: req.ResolverConfigID, Version: req.ResolverConfigVersion, ProfileID: req.ResolverProfileID, MatchedSuffix: req.ResolverMatchSuffix, Endpoints: req.ResolverEndpoints, IPsecPath: req.ResolverIPsecPath})
	} else if plain, ok := r.resolver.(Resolver); ok && req.ResolverIPsecPath == nil {
		records, err = plain.Resolve(lookupCtx, req.Hostname, req.RecordTypes)
	} else {
		err = errResolverConfig
	}
	cancel()
	observed := r.now().UTC()
	resp := responseFor(req, StatusNoError, "", observed)
	if err != nil {
		var dnsErr *net.DNSError
		var statusErr resolverStatusError
		if errors.As(err, &statusErr) {
			resp = responseFor(req, statusErr.status, "", observed)
		} else if errors.Is(err, errResolverConfig) {
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
		ResolverProfileID: req.ResolverProfileID, ResolverMatchSuffix: req.ResolverMatchSuffix,
		ResolverIPsecPath: req.ResolverIPsecPath,
		Hostname:          req.Hostname, RecordTypes: append([]RecordType(nil), req.RecordTypes...),
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
	if !isUUID(req.ResolverConfigID) || !isUUID(req.ResolverProfileID) || req.ResolverConfigVersion < 1 {
		return "resolver_unavailable"
	}
	if req.ResolverMatchSuffix != "" && req.Hostname != req.ResolverMatchSuffix && !strings.HasSuffix(req.Hostname, "."+req.ResolverMatchSuffix) {
		return "resolver_unavailable"
	}
	if req.ResolverIPsecPath != nil && !validIPsecPath(*req.ResolverIPsecPath) {
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
		config += "|" + req.ResolverProfileID + "|" + req.ResolverMatchSuffix
		for _, endpoint := range req.ResolverEndpoints {
			config += "|" + endpoint.Address + ":" + strconv.Itoa(endpoint.Port) + "/" + endpoint.Transport
		}
	}
	if req.ResolverIPsecPath != nil {
		config += "|ipsec:" + req.ResolverIPsecPath.ConnectionID + ":" + strconv.FormatInt(req.ResolverIPsecPath.ConfigurationRevision, 10) + ":" + req.ResolverIPsecPath.SourceAddress
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

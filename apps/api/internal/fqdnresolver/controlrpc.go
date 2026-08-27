package fqdnresolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// GatewayDNSRPCVersion is the version carried by every brokered selected-
// gateway DNS request and response. It is intentionally independent from the
// desired-policy protocol version: an agent that cannot speak this RPC must
// refuse it loudly instead of returning an unverifiable DNS observation.
const GatewayDNSRPCVersion uint16 = 1

// GatewayDNSResponseMaxAge bounds how long a gateway observation may sit in a
// broker queue before the control plane refuses it. This is a response
// freshness bound, not a DNS TTL and never extends last-known-good authority.
const GatewayDNSResponseMaxAge = 30 * time.Second

var (
	ErrGatewayDNSRPCVersion     = errors.New("fqdn gateway DNS RPC version mismatch")
	ErrGatewayDNSRPCIdentity    = errors.New("fqdn gateway DNS RPC response identity mismatch")
	ErrGatewayDNSRPCStale       = errors.New("fqdn gateway DNS RPC response is stale")
	ErrGatewayDNSRPCReplay      = errors.New("fqdn gateway DNS RPC response replay")
	ErrGatewayDNSRPCLimit       = errors.New("fqdn gateway DNS RPC response exceeds limits")
	ErrGatewayDNSRPCMalformed   = errors.New("fqdn gateway DNS RPC response is malformed")
	ErrGatewayDNSRPCUnavailable = errors.New("fqdn gateway DNS RPC transport unavailable")
)

// GatewayDNSRequest is the versioned, authenticated agent-control payload.
// Every identity is control-plane-owned: the broker routes to GatewayID only
// after the existing mTLS node-control authentication identifies that gateway.
// RecordTypes deliberately request both independently usable address families
// and CNAME chain data in one atomic selected-resolver observation.
type GatewayDNSRequest struct {
	Version               uint16             `json:"version"`
	RequestID             uuid.UUID          `json:"request_id"`
	OrgID                 uuid.UUID          `json:"org_id"`
	ResourceID            uuid.UUID          `json:"resource_id"`
	SiteID                uuid.UUID          `json:"site_id"`
	GatewayID             uuid.UUID          `json:"gateway_id"`
	ResolverConfigID      uuid.UUID          `json:"resolver_config_id"`
	ResolverConfigVersion int64              `json:"resolver_config_version"`
	ResolverEndpoints     []ResolverEndpoint `json:"resolver_endpoints"`
	Hostname              string             `json:"hostname"`
	RecordTypes           []RecordType       `json:"record_types"`
	Deadline              time.Time          `json:"deadline"`
}

// GatewayDNSResponse must echo every request identity. ObservedAt is generated
// by the selected gateway and verified against the request deadline and the
// broker's current clock; a delayed response is never published.
type GatewayDNSResponse struct {
	Version               uint16                 `json:"version"`
	RequestID             uuid.UUID              `json:"request_id"`
	OrgID                 uuid.UUID              `json:"org_id"`
	ResourceID            uuid.UUID              `json:"resource_id"`
	SiteID                uuid.UUID              `json:"site_id"`
	GatewayID             uuid.UUID              `json:"gateway_id"`
	ResolverConfigID      uuid.UUID              `json:"resolver_config_id"`
	ResolverConfigVersion int64                  `json:"resolver_config_version"`
	Hostname              string                 `json:"hostname"`
	RecordTypes           []RecordType           `json:"record_types"`
	ObservedAt            time.Time              `json:"observed_at"`
	Status                Status                 `json:"status"`
	ErrorCode             GatewayDNSRPCErrorCode `json:"error_code,omitempty"`
	Records               []GatewayDNSRecord     `json:"records"`
}

// GatewayDNSRPCErrorCode is the transport-level failure vocabulary mirrored by
// the agent. DNS statuses remain DNS observations; these codes mean the
// authenticated control exchange itself could not supply one.
type GatewayDNSRPCErrorCode string

const (
	GatewayDNSRPCUnsupportedVersion GatewayDNSRPCErrorCode = "unsupported_version"
	GatewayDNSRPCDeadlineExceeded   GatewayDNSRPCErrorCode = "deadline_exceeded"
	GatewayDNSRPCDisconnected       GatewayDNSRPCErrorCode = "disconnected"
	GatewayDNSRPCUnavailable        GatewayDNSRPCErrorCode = "resolver_unavailable"
	// ResolverDisagreement means the selected direct endpoints returned
	// non-equivalent usable answers. It is terminal for this refresh: choosing
	// one endpoint would silently broaden authority.
	GatewayDNSRPCDisagreement GatewayDNSRPCErrorCode = "resolver_disagreement"
)

// GatewayDNSRecord is the transport-neutral, JSON-safe record form mirrored
// by the node-control client. Address is textual only on the wire; the control
// plane parses and type-validates it before it can reach resolver lifecycle or
// policy compilation. TTLSeconds avoids Go duration's implementation-specific
// JSON representation.
type GatewayDNSRecord struct {
	Name       string     `json:"name"`
	Type       RecordType `json:"type"`
	Address    string     `json:"address,omitempty"`
	Target     string     `json:"target,omitempty"`
	TTLSeconds uint32     `json:"ttl_seconds"`
}

// GatewayDNSMailbox is the durable, multi-replica-safe agent-pull seam. A
// request is first committed, then delivered as node desired state, and the
// mTLS-authenticated selected gateway completes it with the echoed response.
// It is deliberately not an outbound HTTP call: the existing node-control
// channel is agent-pull and an in-memory waiter would lose work on failover.
type GatewayDNSMailbox interface {
	Enqueue(context.Context, GatewayDNSRequest) error
	Await(context.Context, uuid.UUID) (GatewayDNSResponse, error)
	Expire(context.Context, uuid.UUID, time.Time) error
}

// GatewayDNSRPCTransport adapts a versioned selected-gateway RPC broker to the
// scheduler's WorkResolver seam.
type GatewayDNSRPCTransport struct {
	mailbox      GatewayDNSMailbox
	now          func() time.Time
	newRequestID func() uuid.UUID
	maxAge       time.Duration
}

func NewGatewayDNSRPCTransport(mailbox GatewayDNSMailbox) *GatewayDNSRPCTransport {
	return &GatewayDNSRPCTransport{
		mailbox: mailbox, now: time.Now, newRequestID: uuid.New, maxAge: GatewayDNSResponseMaxAge,
	}
}

// Lookup satisfies Resolver for scheduler construction, but a bare Resolver
// call deliberately cannot issue a gateway RPC: it lacks the control-plane
// owned organization and resource IDs. Scheduler detects WorkResolver and
// calls LookupWork instead. Returning an unbound-context failure here is safer
// than permitting a hostname-only request to choose or infer authority.
func (t *GatewayDNSRPCTransport) Lookup(context.Context, Context, string) ([]Response, error) {
	return nil, ErrUnboundContext
}

// LookupWork issues one bounded request containing the A, AAAA and CNAME
// requirements. A broker must return one complete observation; it cannot mix
// answers from another request, Site, gateway, resource, or organization.
func (t *GatewayDNSRPCTransport) LookupWork(ctx context.Context, w Work) ([]Response, error) {
	if t == nil || t.mailbox == nil || !w.Context.valid() || !w.ResolverConfig.valid() || w.OrgID == uuid.Nil || w.ResourceID == uuid.Nil {
		return nil, ErrUnboundContext
	}
	site, err := uuid.Parse(w.Context.ResolverID)
	if err != nil {
		return nil, ErrUnboundContext
	}
	gateway, err := uuid.Parse(w.Context.GatewayID)
	if err != nil {
		return nil, ErrUnboundContext
	}
	now := t.now()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = now.Add(5 * time.Second)
	}
	req := GatewayDNSRequest{
		Version: GatewayDNSRPCVersion, RequestID: t.newRequestID(),
		OrgID: w.OrgID, ResourceID: w.ResourceID, SiteID: site, GatewayID: gateway,
		ResolverConfigVersion: w.ResolverConfig.Version,
		ResolverEndpoints:     append([]ResolverEndpoint(nil), w.ResolverConfig.Endpoints...),
		Hostname:              dnsName(w.Hostname), RecordTypes: []RecordType{TypeA, TypeAAAA, TypeCNAME}, Deadline: deadline,
	}
	if req.ResolverConfigID, err = uuid.Parse(w.ResolverConfig.ID); err != nil {
		return nil, ErrUnboundContext
	}
	if req.RequestID == uuid.Nil || req.Hostname == "" || !validGatewayDNSResolverConfig(req) {
		return nil, ErrGatewayDNSRPCMalformed
	}
	// The durable mailbox receives a context bounded by the same absolute
	// deadline it carries to the gateway. A disconnected or late agent cannot
	// outlive this scheduler attempt or turn into a late publish.
	requestCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := t.mailbox.Enqueue(requestCtx, req); err != nil {
		return nil, err
	}
	response, err := t.mailbox.Await(requestCtx, req.RequestID)
	if err != nil {
		_ = t.mailbox.Expire(context.Background(), req.RequestID, t.now())
		return nil, err
	}
	records, err := validateGatewayDNSResponse(req, response, now, t.maxAge)
	if err != nil {
		return nil, err
	}
	return []Response{{Status: response.Status, Records: records}}, nil
}

func validGatewayDNSResolverConfig(req GatewayDNSRequest) bool {
	return req.ResolverConfigID != uuid.Nil && req.ResolverConfigVersion > 0 && ResolverConfig{ID: req.ResolverConfigID.String(), Version: req.ResolverConfigVersion, Endpoints: req.ResolverEndpoints}.valid()
}

func validateGatewayDNSResponse(req GatewayDNSRequest, response GatewayDNSResponse, now time.Time, maxAge time.Duration) ([]Record, error) {
	if response.Version != GatewayDNSRPCVersion {
		return nil, fmt.Errorf("%w: got %d want %d", ErrGatewayDNSRPCVersion, response.Version, GatewayDNSRPCVersion)
	}
	if response.RequestID != req.RequestID {
		return nil, fmt.Errorf("%w: request id", ErrGatewayDNSRPCReplay)
	}
	if response.OrgID != req.OrgID || response.ResourceID != req.ResourceID || response.SiteID != req.SiteID || response.GatewayID != req.GatewayID || response.ResolverConfigID != req.ResolverConfigID || response.ResolverConfigVersion != req.ResolverConfigVersion || dnsName(response.Hostname) != req.Hostname {
		return nil, ErrGatewayDNSRPCIdentity
	}
	if !sameRecordTypes(req.RecordTypes, response.RecordTypes) {
		return nil, fmt.Errorf("%w: record types", ErrGatewayDNSRPCIdentity)
	}
	if response.ObservedAt.IsZero() || response.ObservedAt.After(req.Deadline) || response.ObservedAt.After(now.Add(time.Second)) || now.Sub(response.ObservedAt) > maxAge {
		return nil, ErrGatewayDNSRPCStale
	}
	if response.ErrorCode != "" {
		return nil, response.error()
	}
	if response.Status != StatusNoError && response.Status != StatusNXDOMAIN && response.Status != StatusSERVFAIL {
		return nil, ErrGatewayDNSRPCMalformed
	}
	if len(response.Records) > MaxAnswers+MaxCNAMEDepth {
		return nil, ErrGatewayDNSRPCLimit
	}
	addresses, cnames := 0, 0
	records := make([]Record, 0, len(response.Records))
	for _, r := range response.Records {
		wire := Record{Name: r.Name, Type: r.Type, Target: r.Target, TTL: time.Duration(r.TTLSeconds) * time.Second}
		switch r.Type {
		case TypeA:
			addresses++
			address, err := netip.ParseAddr(r.Address)
			if err != nil || !address.Is4() || r.Target != "" {
				return nil, ErrGatewayDNSRPCMalformed
			}
			wire.Address = address
		case TypeAAAA:
			addresses++
			address, err := netip.ParseAddr(r.Address)
			if err != nil || !address.Is6() || r.Target != "" {
				return nil, ErrGatewayDNSRPCMalformed
			}
			wire.Address = address
		case TypeCNAME:
			cnames++
			if r.Address != "" || dnsName(r.Name) == "" || dnsName(r.Target) == "" {
				return nil, ErrGatewayDNSRPCMalformed
			}
		default:
			return nil, ErrGatewayDNSRPCMalformed
		}
		records = append(records, wire)
	}
	if addresses > MaxAnswers || cnames > MaxCNAMEDepth {
		return nil, ErrGatewayDNSRPCLimit
	}
	return records, nil
}

func (r GatewayDNSResponse) error() error {
	switch r.ErrorCode {
	case GatewayDNSRPCUnsupportedVersion:
		return ErrGatewayDNSRPCVersion
	case GatewayDNSRPCDeadlineExceeded:
		return ErrTimeout
	case GatewayDNSRPCDisconnected, GatewayDNSRPCUnavailable:
		return ErrGatewayDNSRPCUnavailable
	case GatewayDNSRPCDisagreement:
		return ErrDisagreement
	default:
		return ErrGatewayDNSRPCMalformed
	}
}

func sameRecordTypes(want, got []RecordType) bool {
	if len(want) != len(got) {
		return false
	}
	seen := make(map[RecordType]bool, len(want))
	for _, r := range want {
		seen[r] = true
	}
	for _, r := range got {
		if !seen[r] {
			return false
		}
		delete(seen, r)
	}
	return len(seen) == 0
}

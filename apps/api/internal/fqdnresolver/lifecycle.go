// Package fqdnresolver owns the fail-closed DNS answer lifecycle for FQDN
// resources. It deliberately does not use the control-plane's default resolver:
// callers must provide the server-selected Site/Gateway resolver context.
package fqdnresolver

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	MaxCNAMEDepth  = 8
	MaxAnswers     = 32
	MinTTL         = 30 * time.Second
	MaxTTL         = time.Hour
	RefreshAt      = 80
	LastGoodMaxAge = 5 * time.Minute
)

var (
	ErrUnboundContext    = errors.New("fqdn resolver context is not server-selected")
	ErrTimeout           = errors.New("fqdn resolver timeout")
	ErrNXDOMAIN          = errors.New("fqdn resolver NXDOMAIN")
	ErrSERVFAIL          = errors.New("fqdn resolver SERVFAIL")
	ErrDisagreement      = errors.New("fqdn resolver disagreement")
	ErrAnswerOverflow    = errors.New("fqdn resolver answer overflow")
	ErrCNAMEChain        = errors.New("fqdn resolver invalid CNAME chain")
	ErrNoUsableAddresses = errors.New("fqdn resolver has no usable addresses")
)

// Context identifies the Site/Gateway resolver selected by the server. A public
// control-plane resolver must never be substituted when this context is absent.
// ResolverID is an auditable stable identifier; GatewayID identifies the selected
// execution context, not a browser supplied preference.
type Context struct {
	ResolverID string
	GatewayID  string
}

func (c Context) valid() bool { return c.ResolverID != "" && c.GatewayID != "" }

type Status string

const (
	StatusNoError  Status = "NOERROR"
	StatusNXDOMAIN Status = "NXDOMAIN"
	StatusSERVFAIL Status = "SERVFAIL"
)

type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
)

// Record is an already parsed DNS answer. Name and Target are DNS names; Address
// is used only by A/AAAA records. The context adapter is responsible for retaining
// DNSSEC/transport details if its resolver provides them.
type Record struct {
	Name    string
	Type    RecordType
	Address netip.Addr
	Target  string
	TTL     time.Duration
}

// Response is one answer from one resolver in the selected context. More than one
// response is permitted for HA, but they must resolve to the same canonical result.
type Response struct {
	Status  Status
	Records []Record
}

// Resolver is implemented by the Site/Gateway resolver transport. It returns all
// authoritative attempts used for this refresh; returning an error represents a
// timeout or transport failure. It must not silently fall back to a public resolver.
type Resolver interface {
	Lookup(context.Context, Context, string) ([]Response, error)
}

type State string

const (
	StateResolving State = "resolving"
	StateHealthy   State = "healthy"
	StateStale     State = "stale"
	StateNXDOMAIN  State = "nxdomain"
	StateFailed    State = "failed"
)

// Generation is immutable after publication. Addresses are canonical sorted and
// deduplicated, and all are /32 or /128 candidates for the later compiler lane.
type Generation struct {
	ID         uint64
	Hostname   string
	Context    Context
	Addresses  []netip.Addr
	TTL        time.Duration
	RefreshAt  time.Time
	ResolvedAt time.Time
}

func (g Generation) clone() Generation {
	g.Addresses = append([]netip.Addr(nil), g.Addresses...)
	return g
}

// Snapshot is the lifecycle projection for policy compilation and diagnostics.
// Active is nil for every failure condition: stale information is diagnostic only
// and never authorizes new traffic.
type Snapshot struct {
	State       State
	Active      *Generation
	LastGood    *Generation
	LastRefresh time.Time
	LastGoodAt  time.Time
	Failure     error
}

func (s Snapshot) clone() Snapshot {
	if s.Active != nil {
		g := s.Active.clone()
		s.Active = &g
	}
	if s.LastGood != nil {
		g := s.LastGood.clone()
		s.LastGood = &g
	}
	return s
}

// Lifecycle serializes publication of bounded immutable answer generations.
// A refresh failure always withdraws Active immediately (D4). LastGood is retained
// for no longer than LastGoodMaxAge solely to report the honest stale state.
type Lifecycle struct {
	mu   sync.RWMutex
	next uint64
	s    Snapshot
}

func (l *Lifecycle) Snapshot(now time.Time) Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLastGood(now)
	return l.s.clone()
}

// Refresh resolves hostname only through ctx and atomically publishes either a
// complete new generation or a withdrawn failure state. A partial answer is never
// published. The returned snapshot is safe for callers to retain.
func (l *Lifecycle) Refresh(ctx context.Context, now time.Time, r Resolver, resolverContext Context, hostname string) Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLastGood(now)
	l.s.LastRefresh = now
	if !resolverContext.valid() || r == nil {
		l.withdraw(now, ErrUnboundContext)
		return l.s.clone()
	}
	responses, err := r.Lookup(ctx, resolverContext, hostname)
	if err != nil {
		l.withdraw(now, fmt.Errorf("%w: %v", ErrTimeout, err))
		return l.s.clone()
	}
	result, err := canonical(hostname, responses)
	if err != nil {
		l.withdraw(now, err)
		return l.s.clone()
	}
	l.next++
	g := Generation{
		ID: l.next, Hostname: hostname, Context: resolverContext,
		Addresses: result.addresses, TTL: jitteredTTL(hostname, result.ttl), ResolvedAt: now,
	}
	g.RefreshAt = now.Add(g.TTL * RefreshAt / 100)
	l.s = Snapshot{State: StateHealthy, Active: &g, LastGood: &g, LastRefresh: now, LastGoodAt: now}
	return l.s.clone()
}

func (l *Lifecycle) withdraw(now time.Time, err error) {
	l.s.Active = nil
	l.s.Failure = err
	// NXDOMAIN is a distinct, operator-visible terminal answer even while the
	// previous generation remains available as bounded diagnostic history.
	if errors.Is(err, ErrNXDOMAIN) {
		l.s.State = StateNXDOMAIN
		return
	}
	if l.s.LastGood != nil && now.Sub(l.s.LastGoodAt) <= LastGoodMaxAge {
		l.s.State = StateStale
	} else {
		l.s.LastGood = nil
		l.s.LastGoodAt = time.Time{}
		l.s.State = StateFailed
	}
}

func (l *Lifecycle) expireLastGood(now time.Time) {
	if l.s.LastGood != nil && now.Sub(l.s.LastGoodAt) > LastGoodMaxAge {
		l.s.LastGood = nil
		l.s.LastGoodAt = time.Time{}
		if l.s.Active == nil && l.s.State == StateStale {
			l.s.State = StateFailed
		}
	}
}

type canonicalResult struct {
	addresses []netip.Addr
	ttl       time.Duration
}

func canonical(hostname string, responses []Response) (canonicalResult, error) {
	if len(responses) == 0 {
		return canonicalResult{}, ErrTimeout
	}
	var first canonicalResult
	for i, response := range responses {
		result, err := resolveResponse(hostname, response)
		if err != nil {
			return canonicalResult{}, err
		}
		if i > 0 && !sameResult(first, result) {
			return canonicalResult{}, ErrDisagreement
		}
		first = result
	}
	return first, nil
}

func resolveResponse(hostname string, response Response) (canonicalResult, error) {
	switch response.Status {
	case StatusNXDOMAIN:
		return canonicalResult{}, ErrNXDOMAIN
	case StatusSERVFAIL:
		return canonicalResult{}, ErrSERVFAIL
	case StatusNoError:
	default:
		return canonicalResult{}, fmt.Errorf("%w: response status %q", ErrSERVFAIL, response.Status)
	}
	byName := make(map[string][]Record)
	for _, r := range response.Records {
		byName[dnsName(r.Name)] = append(byName[dnsName(r.Name)], r)
	}
	name := dnsName(hostname)
	if name == "" {
		return canonicalResult{}, ErrNoUsableAddresses
	}
	minTTL := MaxTTL
	seenNames := map[string]bool{}
	for depth := 0; ; depth++ {
		if seenNames[name] {
			return canonicalResult{}, ErrCNAMEChain
		}
		seenNames[name] = true
		records := byName[name]
		var cnames []Record
		var addresses []Record
		for _, r := range records {
			switch r.Type {
			case TypeCNAME:
				cnames = append(cnames, r)
			case TypeA, TypeAAAA:
				addresses = append(addresses, r)
			}
		}
		if len(cnames) > 0 {
			if len(cnames) != 1 || len(addresses) != 0 || depth >= MaxCNAMEDepth {
				return canonicalResult{}, ErrCNAMEChain
			}
			if cnames[0].TTL < minTTL {
				minTTL = cnames[0].TTL
			}
			next := dnsName(cnames[0].Target)
			if next == "" {
				return canonicalResult{}, ErrCNAMEChain
			}
			name = next
			continue
		}
		set := map[netip.Addr]bool{}
		for _, r := range addresses {
			if !r.Address.IsValid() || (r.Type == TypeA && !r.Address.Is4()) || (r.Type == TypeAAAA && !r.Address.Is6()) || prohibited(r.Address.Unmap()) {
				continue
			}
			if r.TTL < minTTL {
				minTTL = r.TTL
			}
			set[r.Address.Unmap()] = true
		}
		if len(set) == 0 {
			return canonicalResult{}, ErrNoUsableAddresses
		}
		if len(set) > MaxAnswers {
			return canonicalResult{}, ErrAnswerOverflow
		}
		out := make([]netip.Addr, 0, len(set))
		for a := range set {
			out = append(out, a)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
		return canonicalResult{addresses: out, ttl: clampTTL(minTTL)}, nil
	}
}

func sameResult(a, b canonicalResult) bool {
	if a.ttl != b.ttl || len(a.addresses) != len(b.addresses) {
		return false
	}
	for i := range a.addresses {
		if a.addresses[i] != b.addresses[i] {
			return false
		}
	}
	return true
}

func dnsName(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".") }

func clampTTL(ttl time.Duration) time.Duration {
	if ttl < MinTTL {
		return MinTTL
	}
	if ttl > MaxTTL {
		return MaxTTL
	}
	return ttl
}

// jitteredTTL uses a stable hash rather than randomness: identical resolver input
// yields identical scheduling, while separate names spread refresh load by ±10%.
func jitteredTTL(hostname string, ttl time.Duration) time.Duration {
	sum := sha256.Sum256([]byte(hostname))
	v := binary.BigEndian.Uint16(sum[:2])
	factor := 0.9 + float64(v)/65535*0.2
	return clampTTL(time.Duration(float64(ttl) * factor))
}

func prohibited(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	if addr.Is4() {
		return netip.MustParsePrefix("192.0.2.0/24").Contains(addr) || netip.MustParsePrefix("198.51.100.0/24").Contains(addr) || netip.MustParsePrefix("203.0.113.0/24").Contains(addr) || netip.MustParseAddr("100.100.100.200") == addr
	}
	return netip.MustParsePrefix("2001:db8::/32").Contains(addr)
}

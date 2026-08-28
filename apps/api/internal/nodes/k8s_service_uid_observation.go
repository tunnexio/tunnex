package nodes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// K8sServiceUIDObservationVersion versions this private mTLS report only. It
// has no public API; its durable persistence is owned by the private agent
// channel store and ordered database migrations.
const K8sServiceUIDObservationVersion = 1

const (
	maxK8sServiceUIDObservations = 32
	maxK8sServiceUIDReportBytes  = 4096
	maxK8sServiceUIDBytes        = 253
)

var k8sServiceUIDDNSLabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// K8sServiceUIDObservationReport deliberately carries neither tenant nor
// cluster routing fields. The authenticated server-side scope owner supplies
// those from the selected connector binding.
type K8sServiceUIDObservationReport struct {
	Version      int                        `json:"version"`
	Sequence     uint64                     `json:"sequence"`
	Digest       string                     `json:"digest"`
	Observations []K8sServiceUIDObservation `json:"observations"`
}

// K8sServiceUIDObservation is the minimum Kubernetes incarnation fact. UID is
// opaque; endpoint, Pod, Node, IP, and EndpointSlice data are intentionally
// absent.
type K8sServiceUIDObservation struct {
	Namespace string `json:"namespace"`
	Service   string `json:"service"`
	UID       string `json:"uid"`
	State     string `json:"state"` // live | deleted
}

// K8sServiceUIDObservationScope is supplied only by the server-authoritative
// selected-connector resolver, never decoded from an agent payload.
type K8sServiceUIDObservationScope struct {
	OrgID           uuid.UUID
	SiteID          uuid.UUID
	ClusterID       uuid.UUID
	ConnectorNodeID uuid.UUID
}

// K8sServiceUIDObservationReceipt retains the original CP receipt time for an
// exact lost-response retry. Agent time is intentionally not part of this wire
// contract or freshness evidence.
type K8sServiceUIDObservationReceipt struct {
	Digest      string
	ReceiptTime time.Time
}

// K8sServiceUIDObservationState is store-owned replay/incarnation state. The
// pure validator creates no in-memory authoritative fallback.
type K8sServiceUIDObservationState struct {
	ScopeIdentity string
	Sequence      uint64
	Seen          map[uint64]K8sServiceUIDObservationReceipt
	Current       map[string]K8sServiceUIDObservation
	Retired       map[string]map[string]bool
}

type K8sServiceUIDObservationValidation struct {
	Duplicate   bool
	ReceiptTime time.Time
	NextState   K8sServiceUIDObservationState
}

// K8sServiceUIDObservationStore must atomically load the selected-connector
// scope and replay state, run validate, then persist the result. It is an
// nil is fail-closed and the AgentChannel never accepts observations without
// a durable implementation.
type K8sServiceUIDObservationStore interface {
	UpdateK8sServiceUIDObservations(ctx context.Context, agent K8sServiceUIDObservationAgent, report K8sServiceUIDObservationReport, receiptTime time.Time, validate func(K8sServiceUIDObservationScope, K8sServiceUIDObservationState, time.Time) (K8sServiceUIDObservationValidation, error)) (K8sServiceUIDObservationValidation, error)
}

// K8sServiceUIDObservationAgent is constructed from the mTLS principal.
type K8sServiceUIDObservationAgent struct {
	NodeID uuid.UUID
	OrgID  uuid.UUID
}

var (
	ErrK8sServiceUIDObservationInvalid = errors.New("invalid Kubernetes Service UID observation")
	ErrK8sServiceUIDObservationStale   = errors.New("stale Kubernetes Service UID observation")
)

// ValidateK8sServiceUIDObservationReport validates and canonicalizes one node
// payload without assigning it to a cluster. Scope authority is intentionally
// separate and server-side.
func ValidateK8sServiceUIDObservationReport(report K8sServiceUIDObservationReport) (K8sServiceUIDObservationReport, error) {
	if report.Version != K8sServiceUIDObservationVersion || report.Sequence == 0 || len(report.Observations) == 0 || len(report.Observations) > maxK8sServiceUIDObservations || k8sServiceUIDObservationReportStringBytes(report) > maxK8sServiceUIDReportBytes {
		return K8sServiceUIDObservationReport{}, ErrK8sServiceUIDObservationInvalid
	}
	entries := append([]K8sServiceUIDObservation(nil), report.Observations...)
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if !validK8sServiceUIDObservation(entry) {
			return K8sServiceUIDObservationReport{}, ErrK8sServiceUIDObservationInvalid
		}
		key := k8sServiceUIDObservationKey(entry)
		if seen[key] {
			return K8sServiceUIDObservationReport{}, ErrK8sServiceUIDObservationInvalid
		}
		seen[key] = true
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.UID != b.UID {
			return a.UID < b.UID
		}
		return a.State < b.State
	})
	canonical := K8sServiceUIDObservationReport{Version: report.Version, Sequence: report.Sequence, Digest: report.Digest, Observations: entries}
	digest := K8sServiceUIDObservationDigest(canonical.Sequence, canonical.Observations)
	if report.Digest != digest {
		return K8sServiceUIDObservationReport{}, ErrK8sServiceUIDObservationInvalid
	}
	return canonical, nil
}

// K8sServiceUIDObservationDigest is domain-separated and order-independent.
func K8sServiceUIDObservationDigest(sequence uint64, observations []K8sServiceUIDObservation) string {
	entries := append([]K8sServiceUIDObservation(nil), observations...)
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.UID != b.UID {
			return a.UID < b.UID
		}
		return a.State < b.State
	})
	h := sha256.New()
	_, _ = h.Write([]byte("tunnex.k8s-service-uid-observation.v1\n"))
	_, _ = h.Write([]byte(strconv.FormatUint(sequence, 10) + "\n"))
	for _, entry := range entries {
		_, _ = h.Write([]byte(strconv.Quote(entry.Namespace) + "\t" + strconv.Quote(entry.Service) + "\t" + strconv.Quote(entry.UID) + "\t" + entry.State + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateK8sServiceUIDObservations applies the authenticated scope and replay
// fence. A UID once retired for a namespace/name can never be reported live
// again, so an out-of-order old incarnation cannot revive after delete/recreate.
func ValidateK8sServiceUIDObservations(receiptTime time.Time, agent K8sServiceUIDObservationAgent, scope K8sServiceUIDObservationScope, report K8sServiceUIDObservationReport, state K8sServiceUIDObservationState) (K8sServiceUIDObservationValidation, error) {
	if receiptTime.IsZero() || agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil || !validK8sServiceUIDObservationScope(scope) || scope.OrgID != agent.OrgID || scope.ConnectorNodeID != agent.NodeID {
		return K8sServiceUIDObservationValidation{}, ErrK8sServiceUIDObservationInvalid
	}
	canonical, err := ValidateK8sServiceUIDObservationReport(report)
	if err != nil {
		return K8sServiceUIDObservationValidation{}, err
	}
	return validateCanonicalK8sServiceUIDObservations(receiptTime, agent, scope, canonical, state)
}

// validateCanonicalK8sServiceUIDObservations is shared by the narrow legacy
// exact-Service report and the bounded full inventory writer. Callers must
// validate and canonicalize their own wire contract before entering here.
func validateCanonicalK8sServiceUIDObservations(receiptTime time.Time, agent K8sServiceUIDObservationAgent, scope K8sServiceUIDObservationScope, canonical K8sServiceUIDObservationReport, state K8sServiceUIDObservationState) (K8sServiceUIDObservationValidation, error) {
	scopeID := k8sServiceUIDObservationScopeIdentity(scope)
	if state.ScopeIdentity != "" && state.ScopeIdentity != scopeID {
		return K8sServiceUIDObservationValidation{}, ErrK8sServiceUIDObservationInvalid
	}
	if prior, ok := state.Seen[canonical.Sequence]; ok {
		if prior.Digest != canonical.Digest {
			return K8sServiceUIDObservationValidation{}, ErrK8sServiceUIDObservationInvalid
		}
		return K8sServiceUIDObservationValidation{Duplicate: true, ReceiptTime: prior.ReceiptTime, NextState: cloneK8sServiceUIDObservationState(state)}, nil
	}
	if canonical.Sequence <= state.Sequence {
		return K8sServiceUIDObservationValidation{}, ErrK8sServiceUIDObservationStale
	}
	next := cloneK8sServiceUIDObservationState(state)
	if next.Seen == nil {
		next.Seen = map[uint64]K8sServiceUIDObservationReceipt{}
	}
	if next.Current == nil {
		next.Current = map[string]K8sServiceUIDObservation{}
	}
	if next.Retired == nil {
		next.Retired = map[string]map[string]bool{}
	}
	for _, entry := range canonical.Observations {
		nameKey := entry.Namespace + "\x00" + entry.Service
		if next.Retired[nameKey][entry.UID] && entry.State == "live" {
			return K8sServiceUIDObservationValidation{}, ErrK8sServiceUIDObservationStale
		}
		current := next.Current[nameKey]
		if entry.State == "live" {
			if current.UID != "" && current.UID != entry.UID {
				if next.Retired[nameKey] == nil {
					next.Retired[nameKey] = map[string]bool{}
				}
				next.Retired[nameKey][current.UID] = true
			}
			next.Current[nameKey] = entry
			continue
		}
		if next.Retired[nameKey] == nil {
			next.Retired[nameKey] = map[string]bool{}
		}
		next.Retired[nameKey][entry.UID] = true
		if current.UID == entry.UID {
			next.Current[nameKey] = entry
		}
	}
	next.ScopeIdentity, next.Sequence = scopeID, canonical.Sequence
	receiptTime = receiptTime.UTC()
	next.Seen[canonical.Sequence] = K8sServiceUIDObservationReceipt{Digest: canonical.Digest, ReceiptTime: receiptTime}
	return K8sServiceUIDObservationValidation{ReceiptTime: receiptTime, NextState: next}, nil
}

func validK8sServiceUIDObservation(entry K8sServiceUIDObservation) bool {
	return validK8sServiceUIDDNSLabel(entry.Namespace) && validK8sServiceUIDDNSLabel(entry.Service) && validOpaqueK8sServiceUID(entry.UID) && (entry.State == "live" || entry.State == "deleted")
}
func validK8sServiceUIDDNSLabel(value string) bool {
	return len(value) >= 1 && len(value) <= 63 && k8sServiceUIDDNSLabelRE.MatchString(value)
}
func validOpaqueK8sServiceUID(value string) bool {
	if len(value) == 0 || len(value) > maxK8sServiceUIDBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func validK8sServiceUIDObservationScope(scope K8sServiceUIDObservationScope) bool {
	return scope.OrgID != uuid.Nil && scope.SiteID != uuid.Nil && scope.ClusterID != uuid.Nil && scope.ConnectorNodeID != uuid.Nil
}
func k8sServiceUIDObservationScopeIdentity(scope K8sServiceUIDObservationScope) string {
	// UUID components are fixed canonical strings. Use a non-NUL separator so
	// this pure identity remains safe to persist in PostgreSQL text; NUL is not
	// accepted by PostgreSQL even though it is useful for in-memory map keys.
	return strings.Join([]string{scope.OrgID.String(), scope.SiteID.String(), scope.ClusterID.String(), scope.ConnectorNodeID.String()}, "\x1f")
}
func k8sServiceUIDObservationKey(entry K8sServiceUIDObservation) string {
	return entry.Namespace + "\x00" + entry.Service + "\x00" + entry.UID
}
func k8sServiceUIDObservationReportStringBytes(report K8sServiceUIDObservationReport) int {
	n := len(report.Digest)
	for _, e := range report.Observations {
		n += len(e.Namespace) + len(e.Service) + len(e.UID) + len(e.State)
	}
	return n
}
func cloneK8sServiceUIDObservationState(in K8sServiceUIDObservationState) K8sServiceUIDObservationState {
	out := in
	if in.Seen != nil {
		out.Seen = make(map[uint64]K8sServiceUIDObservationReceipt, len(in.Seen))
		for k, v := range in.Seen {
			out.Seen[k] = v
		}
	}
	if in.Current != nil {
		out.Current = make(map[string]K8sServiceUIDObservation, len(in.Current))
		for k, v := range in.Current {
			out.Current[k] = v
		}
	}
	if in.Retired != nil {
		out.Retired = make(map[string]map[string]bool, len(in.Retired))
		for k, values := range in.Retired {
			out.Retired[k] = make(map[string]bool, len(values))
			for uid, v := range values {
				out.Retired[k][uid] = v
			}
		}
	}
	return out
}

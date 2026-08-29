package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// PoolVIPOwnershipDeliveryAttestationVersion is deliberately separate from the
// receipt-only v1 contract. v1 remains exactly as-is for rolling compatibility.
const PoolVIPOwnershipDeliveryAttestationVersion = 2

const (
	// Matches the control-plane v2 boundary. This is an internal safety cap
	// derived from the 16 KiB protocol frame, never a customer route quota.
	poolVIPOwnershipMaxOwnedRoutes     = 512
	poolVIPOwnershipMaxOwnedRouteBytes = len("255.255.255.255/32")
	// This local, opaque retry record has no reason to grow without bound. The
	// cap protects restart-time decoding from a corrupted state file; it is not
	// an ownership or customer-service quota.
	poolVIPOwnershipAppliedStateFileLimit = 1 << 20
)

// PoolVIPOwnershipDeliveryEnvelopeV2 carries the evidence plan an agent must
// apply and read back before it can acknowledge. It is not emitted by the v1
// control plane yet; PollPoolVIPOwnershipDeliveryV2 is deliberately unwired.
type PoolVIPOwnershipDeliveryEnvelopeV2 struct {
	PoolVIPOwnershipDeliveryEnvelope
	OwnedRoutes          []string `json:"owned_routes"`
	ExpectedRouteDigest  string   `json:"expected_route_digest"`
	ExpectedVIPMapDigest string   `json:"expected_vip_map_digest"`
	PriorLeaseEpoch      uint64   `json:"prior_lease_epoch,omitempty"`
}

// PoolVIPOwnershipDeliveryAckV2 is an exact v2 echo plus applied-state
// evidence. AgentObservedAt remains diagnostic-only; CP receipt time is the
// only authoritative freshness timestamp.
type PoolVIPOwnershipDeliveryAckV2 struct {
	PoolVIPOwnershipDeliveryAck
	AppliedRole                string `json:"applied_role"`
	AppliedManifestIdentity    string `json:"applied_manifest_identity"`
	AppliedPromotionGeneration uint64 `json:"applied_promotion_generation"`
	AppliedManifestRevision    uint64 `json:"applied_manifest_revision"`
	AppliedLeaseEpoch          uint64 `json:"applied_lease_epoch"`
	OwnedRouteDigest           string `json:"owned_route_digest"`
	VIPMapDigest               string `json:"vip_map_digest"`
}

// PoolVIPOwnershipAppliedReadback is returned by the injected owner of the
// local route/VIP state. It must be an actual read-back after Apply, never a
// desired-state echo.
type PoolVIPOwnershipAppliedReadback struct {
	Role                string
	ManifestIdentity    string
	PromotionGeneration uint64
	ManifestRevision    uint64
	LeaseEpoch          uint64
	OwnedRoutes         []string
	VIPMapDigest        string
}

// PoolVIPOwnershipApplyReadback owns the future local dataplane operation. No
// production implementation is wired in this slice, so v2 cannot mutate live
// routes or nft state merely by existing.
type PoolVIPOwnershipApplyReadback interface {
	ApplyPoolVIPOwnershipV2(ctx context.Context, envelope PoolVIPOwnershipDeliveryEnvelopeV2) error
	ReadPoolVIPOwnershipV2(ctx context.Context, envelope PoolVIPOwnershipDeliveryEnvelopeV2) (PoolVIPOwnershipAppliedReadback, error)
}

// PoolVIPOwnershipAppliedState persists a completed apply/read-back proof. It
// is an ACK retry aid only, not leader-session binding or serving readiness.
type PoolVIPOwnershipAppliedState struct {
	Scope           string                          `json:"scope"`
	DeliveryID      string                          `json:"delivery_id"`
	Fingerprint     string                          `json:"fingerprint"`
	Readback        PoolVIPOwnershipAppliedReadback `json:"readback"`
	WireVersion     int                             `json:"wire_version,omitempty"`
	LeaseExpiresAt  *time.Time                      `json:"lease_expires_at,omitempty"`
	AppliedManifest *PoolVIPOwnershipManifestV3     `json:"applied_manifest,omitempty"`
}

// PoolVIPOwnershipAppliedStateStore serializes one COMPLETE scope transition.
// The callback runs while the current state remains stable; its accepted next
// state is atomically persisted before Transition returns. Splitting this into
// Load/Apply/Store would permit two attestors to apply conflicting successors.
type PoolVIPOwnershipAppliedStateStore interface {
	TransitionPoolVIPOwnershipAppliedState(ctx context.Context, scope string, fn func(PoolVIPOwnershipAppliedState, bool) (PoolVIPOwnershipAppliedState, bool, error)) error
}

// PoolVIPOwnershipAttestor applies only through its injected adapter, requires
// exact read-back, and persists the resulting proof before returning an ACK.
// It is intentionally not attached to the agent's polling scheduler.
type PoolVIPOwnershipAttestor struct {
	apply PoolVIPOwnershipApplyReadback
	state PoolVIPOwnershipAppliedStateStore
	now   func() time.Time
}

func NewPoolVIPOwnershipAttestor(apply PoolVIPOwnershipApplyReadback, state PoolVIPOwnershipAppliedStateStore) *PoolVIPOwnershipAttestor {
	return &PoolVIPOwnershipAttestor{apply: apply, state: state, now: time.Now}
}

func (a *PoolVIPOwnershipAttestor) PreparePoolVIPOwnershipDeliveryAckV2(ctx context.Context, envelope PoolVIPOwnershipDeliveryEnvelopeV2) (PoolVIPOwnershipDeliveryAckV2, error) {
	if a == nil || a.apply == nil || a.state == nil {
		return PoolVIPOwnershipDeliveryAckV2{}, fmt.Errorf("ownership attestor is not configured")
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV2(envelope); err != nil {
		return PoolVIPOwnershipDeliveryAckV2{}, err
	}
	scope := poolVIPOwnershipAttestationScope(envelope)
	fingerprint, err := poolVIPOwnershipAttestationFingerprint(envelope)
	if err != nil {
		return PoolVIPOwnershipDeliveryAckV2{}, err
	}
	var ack PoolVIPOwnershipDeliveryAckV2
	err = a.state.TransitionPoolVIPOwnershipAppliedState(ctx, scope, func(prior PoolVIPOwnershipAppliedState, found bool) (PoolVIPOwnershipAppliedState, bool, error) {
		if found {
			if !validPoolVIPOwnershipStoredAttestation(prior, scope) {
				return PoolVIPOwnershipAppliedState{}, false, fmt.Errorf("stored ownership attestation scope is invalid")
			}
			if prior.DeliveryID == envelope.DeliveryID {
				if prior.Fingerprint != fingerprint {
					return PoolVIPOwnershipAppliedState{}, false, fmt.Errorf("delivery ID replayed with different applied-state evidence")
				}
				actual, err := a.apply.ReadPoolVIPOwnershipV2(ctx, envelope)
				if err != nil {
					return PoolVIPOwnershipAppliedState{}, false, err
				}
				if err := validatePoolVIPOwnershipAppliedReadback(envelope, actual); err != nil {
					return PoolVIPOwnershipAppliedState{}, false, err
				}
				ack = poolVIPOwnershipDeliveryAckV2(envelope, actual, a.now().UTC())
				return prior, false, nil
			}
			if envelope.PromotionGeneration < prior.Readback.PromotionGeneration || envelope.ManifestRevision <= prior.Readback.ManifestRevision || envelope.LeaseEpoch < prior.Readback.LeaseEpoch {
				return PoolVIPOwnershipAppliedState{}, false, fmt.Errorf("stale ownership promotion generation, manifest revision, or lease epoch")
			}
		}
		if err := a.apply.ApplyPoolVIPOwnershipV2(ctx, envelope); err != nil {
			return PoolVIPOwnershipAppliedState{}, false, fmt.Errorf("apply ownership delivery: %w", err)
		}
		actual, err := a.apply.ReadPoolVIPOwnershipV2(ctx, envelope)
		if err != nil {
			return PoolVIPOwnershipAppliedState{}, false, fmt.Errorf("read back ownership delivery: %w", err)
		}
		if err := validatePoolVIPOwnershipAppliedReadback(envelope, actual); err != nil {
			return PoolVIPOwnershipAppliedState{}, false, err
		}
		ack = poolVIPOwnershipDeliveryAckV2(envelope, actual, a.now().UTC())
		return PoolVIPOwnershipAppliedState{Scope: scope, DeliveryID: envelope.DeliveryID, Fingerprint: fingerprint, Readback: actual}, true, nil
	})
	if err != nil {
		return PoolVIPOwnershipDeliveryAckV2{}, err
	}
	return ack, nil
}

func validPoolVIPOwnershipStoredAttestation(state PoolVIPOwnershipAppliedState, scope string) bool {
	return state.Scope == scope && validPoolVIPOwnershipDeliveryUUID(state.DeliveryID) &&
		poolVIPOwnershipDeliveryHex64RE.MatchString(state.Fingerprint) &&
		poolVIPOwnershipDeliveryHex64RE.MatchString(state.Readback.ManifestIdentity) &&
		state.Readback.PromotionGeneration > 0 && state.Readback.ManifestRevision > 0 && state.Readback.LeaseEpoch > 0
}

// PollPoolVIPOwnershipDeliveryV2 is intentionally manual/unwired. Unlike v1,
// it acknowledges only after Prepare… completes apply + exact read-back + local
// durable state persistence. An old v1 CP rejects capability 2; that refusal
// produces no ACK and leaves v1 behavior unchanged.
func (c *Client) PollPoolVIPOwnershipDeliveryV2(ctx context.Context, attestor *PoolVIPOwnershipAttestor) (bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/agent/pool-vip-ownership-delivery", nil)
	req.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, "2")
	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("ownership delivery status %d", resp.StatusCode)
	}
	var envelope PoolVIPOwnershipDeliveryEnvelopeV2
	if err := decodePoolVIPOwnershipDeliveryJSON(resp.Body, &envelope); err != nil {
		return false, fmt.Errorf("decode ownership delivery: %w", err)
	}
	ack, err := attestor.PreparePoolVIPOwnershipDeliveryAckV2(ctx, envelope)
	if err != nil {
		return false, err
	}
	body, err := json.Marshal(ack)
	if err != nil {
		return false, err
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/pool-vip-ownership-delivery/ack", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(poolVIPOwnershipDeliveryCapabilityHeader, "2")
	resp, err = c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return false, fmt.Errorf("ownership delivery acknowledgement status %d", resp.StatusCode)
	}
	return true, nil
}

func ValidatePoolVIPOwnershipDeliveryEnvelopeV2(envelope PoolVIPOwnershipDeliveryEnvelopeV2) error {
	base := envelope.PoolVIPOwnershipDeliveryEnvelope
	if base.Version != PoolVIPOwnershipDeliveryAttestationVersion {
		return fmt.Errorf("unsupported ownership attestation version")
	}
	base.Version = PoolVIPOwnershipDeliveryVersion
	if err := validPoolVIPOwnershipDeliveryEnvelope(base); err != nil {
		return err
	}
	routeDigest, err := PoolVIPOwnershipOwnedRouteDigest(envelope.OwnedRoutes)
	if err != nil || routeDigest != envelope.ExpectedRouteDigest {
		return fmt.Errorf("invalid expected owned-route digest")
	}
	switch envelope.Role {
	case nodepolicy.PoolVIPOwnershipServing:
		if len(envelope.OwnedRoutes) == 0 || !poolVIPOwnershipDeliveryHex64RE.MatchString(envelope.ExpectedVIPMapDigest) || envelope.PriorLeaseEpoch != 0 {
			return fmt.Errorf("serving attestation requires routes, VIP digest, and no prior lease")
		}
	case nodepolicy.PoolVIPOwnershipPreparedNonServing:
		if len(envelope.OwnedRoutes) != 0 || envelope.ExpectedVIPMapDigest != "" || envelope.PriorLeaseEpoch != 0 {
			return fmt.Errorf("prepared attestation requires zero owned routes")
		}
	case nodepolicy.PoolVIPOwnershipWithdrawal:
		if len(envelope.OwnedRoutes) != 0 || envelope.ExpectedVIPMapDigest != "" || envelope.PriorLeaseEpoch == 0 || envelope.PriorLeaseEpoch >= envelope.LeaseEpoch {
			return fmt.Errorf("withdrawal attestation requires the prior lease and zero owned routes")
		}
	}
	return nil
}

func ValidatePoolVIPOwnershipDeliveryAckV2(envelope PoolVIPOwnershipDeliveryEnvelopeV2, ack PoolVIPOwnershipDeliveryAckV2) error {
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV2(envelope); err != nil {
		return err
	}
	base := ack.PoolVIPOwnershipDeliveryAck
	if base.Version != envelope.Version || base.OrgID != envelope.OrgID || base.SiteID != envelope.SiteID || base.ClusterID != envelope.ClusterID || base.PoolID != envelope.PoolID || base.ConnectorNodeID != envelope.ConnectorNodeID || base.TargetNodeID != envelope.TargetNodeID || base.OperationID != envelope.OperationID || base.ManifestIdentity != envelope.ManifestIdentity || base.Role != envelope.Role || base.PromotionGeneration != envelope.PromotionGeneration || base.ManifestRevision != envelope.ManifestRevision || base.LeaseEpoch != envelope.LeaseEpoch || base.DeliveryPhase != envelope.DeliveryPhase || base.DeliveryID != envelope.DeliveryID || base.DeliveryNonce != envelope.DeliveryNonce {
		return fmt.Errorf("attestation acknowledgement does not exactly match delivery")
	}
	return validatePoolVIPOwnershipAppliedReadback(envelope, PoolVIPOwnershipAppliedReadback{Role: ack.AppliedRole, ManifestIdentity: ack.AppliedManifestIdentity, PromotionGeneration: ack.AppliedPromotionGeneration, ManifestRevision: ack.AppliedManifestRevision, LeaseEpoch: ack.AppliedLeaseEpoch, VIPMapDigest: ack.VIPMapDigest, OwnedRoutes: nil}, ack.OwnedRouteDigest)
}

func validatePoolVIPOwnershipAppliedReadback(envelope PoolVIPOwnershipDeliveryEnvelopeV2, actual PoolVIPOwnershipAppliedReadback, routeDigestOverride ...string) error {
	routeDigest, err := PoolVIPOwnershipOwnedRouteDigest(actual.OwnedRoutes)
	if len(routeDigestOverride) != 0 {
		routeDigest = routeDigestOverride[0]
	}
	if err != nil || actual.Role != envelope.Role || actual.ManifestIdentity != envelope.ManifestIdentity || actual.PromotionGeneration != envelope.PromotionGeneration || actual.ManifestRevision != envelope.ManifestRevision || routeDigest != envelope.ExpectedRouteDigest {
		return fmt.Errorf("applied ownership state does not exactly match delivery")
	}
	wantLease := envelope.LeaseEpoch
	if envelope.Role == nodepolicy.PoolVIPOwnershipWithdrawal {
		wantLease = envelope.PriorLeaseEpoch
	}
	if actual.LeaseEpoch != wantLease {
		return fmt.Errorf("applied ownership lease epoch does not match delivery")
	}
	if envelope.Role == nodepolicy.PoolVIPOwnershipServing {
		if actual.VIPMapDigest != envelope.ExpectedVIPMapDigest {
			return fmt.Errorf("applied ownership VIP digest does not match delivery")
		}
	} else if actual.VIPMapDigest != "" {
		return fmt.Errorf("non-serving ownership state must not attest a VIP digest")
	}
	return nil
}

func poolVIPOwnershipDeliveryAckV2(envelope PoolVIPOwnershipDeliveryEnvelopeV2, actual PoolVIPOwnershipAppliedReadback, observed time.Time) PoolVIPOwnershipDeliveryAckV2 {
	digest, _ := PoolVIPOwnershipOwnedRouteDigest(actual.OwnedRoutes)
	return PoolVIPOwnershipDeliveryAckV2{PoolVIPOwnershipDeliveryAck: poolVIPOwnershipDeliveryAck(envelope.PoolVIPOwnershipDeliveryEnvelope, observed), AppliedRole: actual.Role, AppliedManifestIdentity: actual.ManifestIdentity, AppliedPromotionGeneration: actual.PromotionGeneration, AppliedManifestRevision: actual.ManifestRevision, AppliedLeaseEpoch: actual.LeaseEpoch, OwnedRouteDigest: digest, VIPMapDigest: actual.VIPMapDigest}
}

func PoolVIPOwnershipOwnedRouteDigest(routes []string) (string, error) {
	if len(routes) > poolVIPOwnershipMaxOwnedRoutes {
		return "", fmt.Errorf("too many owned routes")
	}
	canonical := append([]string(nil), routes...)
	for _, route := range canonical {
		if len(route) > poolVIPOwnershipMaxOwnedRouteBytes {
			return "", fmt.Errorf("owned route exceeds canonical IPv4 length")
		}
		p, err := netip.ParsePrefix(route)
		if err != nil || !p.Addr().Is4() || p.String() != route {
			return "", fmt.Errorf("noncanonical owned route")
		}
	}
	sort.Strings(canonical)
	for i := 1; i < len(canonical); i++ {
		if canonical[i] == canonical[i-1] {
			return "", fmt.Errorf("duplicate owned route")
		}
	}
	b, _ := json.Marshal(struct {
		Domain string   `json:"domain"`
		Routes []string `json:"routes"`
	}{"tunnex.pool-vip-ownership-owned-routes/v1", canonical})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func poolVIPOwnershipAttestationScope(e PoolVIPOwnershipDeliveryEnvelopeV2) string {
	return strings.Join([]string{e.OrgID, e.SiteID, e.ClusterID, e.PoolID, e.ConnectorNodeID, e.TargetNodeID}, "\x00")
}
func poolVIPOwnershipAttestationFingerprint(e PoolVIPOwnershipDeliveryEnvelopeV2) (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// FilePoolVIPOwnershipAppliedStateStore is an optional atomic local-state seam.
// It is never constructed by the agent loop in this slice. Its file contains no
// credentials and only permits exact per-scope retry evidence after restart.
type FilePoolVIPOwnershipAppliedStateStore struct {
	path    string
	write   func(*os.File, []byte) (int, error)
	syncDir func(string) error
}

func NewFilePoolVIPOwnershipAppliedStateStore(path string) *FilePoolVIPOwnershipAppliedStateStore {
	return &FilePoolVIPOwnershipAppliedStateStore{path: path, write: (*os.File).Write, syncDir: syncPoolVIPOwnershipStateDir}
}

var poolVIPOwnershipStatePathLocks sync.Map // canonical path -> *sync.Mutex, shared by every store instance

type poolVIPOwnershipAppliedStateFile struct {
	Version int                                     `json:"version"`
	States  map[string]PoolVIPOwnershipAppliedState `json:"states"`
}

func (s *FilePoolVIPOwnershipAppliedStateStore) TransitionPoolVIPOwnershipAppliedState(_ context.Context, scope string, fn func(PoolVIPOwnershipAppliedState, bool) (PoolVIPOwnershipAppliedState, bool, error)) error {
	if scope == "" || fn == nil {
		return fmt.Errorf("ownership attestation scope transition required")
	}
	_, lock, err := poolVIPOwnershipStatePathLock(s.path)
	if err != nil {
		return err
	}
	lock.Lock()
	defer lock.Unlock()
	f, err := s.read()
	if os.IsNotExist(err) {
		f = poolVIPOwnershipAppliedStateFile{Version: 1, States: map[string]PoolVIPOwnershipAppliedState{}}
	} else if err != nil {
		return err
	}
	if f.Version != 1 {
		return fmt.Errorf("unsupported ownership attestation state version")
	}
	if f.States == nil {
		f.States = map[string]PoolVIPOwnershipAppliedState{}
	}
	prior, found := f.States[scope]
	next, commit, err := fn(prior, found)
	if err != nil {
		return err
	}
	if !commit {
		return nil
	}
	if next.Scope != scope || !validPoolVIPOwnershipStoredAttestation(next, scope) {
		return fmt.Errorf("invalid ownership attestation successor")
	}
	f.States[scope] = next
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".ownership-attestation-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = s.write(tmp, b); err == nil {
		if len(b) != 0 {
			// os.File.Write may legally short-write without an error.
			if info, statErr := tmp.Stat(); statErr != nil || info.Size() != int64(len(b)) {
				if statErr != nil {
					return statErr
				}
				return io.ErrShortWrite
			}
		}
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(name, s.path); err != nil {
		return err
	}
	return s.syncDir(filepath.Dir(s.path))
}

func poolVIPOwnershipStatePathLock(path string) (string, *sync.Mutex, error) {
	if path == "" {
		return "", nil, fmt.Errorf("ownership attestation state path required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	canonical := filepath.Clean(abs)
	value, _ := poolVIPOwnershipStatePathLocks.LoadOrStore(canonical, &sync.Mutex{})
	return canonical, value.(*sync.Mutex), nil
}

func syncPoolVIPOwnershipStateDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (s *FilePoolVIPOwnershipAppliedStateStore) read() (poolVIPOwnershipAppliedStateFile, error) {
	file, err := os.Open(s.path)
	if err != nil {
		return poolVIPOwnershipAppliedStateFile{}, err
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, poolVIPOwnershipAppliedStateFileLimit+1))
	if err != nil {
		return poolVIPOwnershipAppliedStateFile{}, err
	}
	if len(b) > poolVIPOwnershipAppliedStateFileLimit {
		return poolVIPOwnershipAppliedStateFile{}, fmt.Errorf("ownership attestation state exceeds %d bytes", poolVIPOwnershipAppliedStateFileLimit)
	}
	if err := rejectDuplicatePoolVIPOwnershipJSONKeys(b); err != nil {
		return poolVIPOwnershipAppliedStateFile{}, err
	}
	var f poolVIPOwnershipAppliedStateFile
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		return poolVIPOwnershipAppliedStateFile{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return poolVIPOwnershipAppliedStateFile{}, fmt.Errorf("multiple ownership attestation state values")
		}
		return poolVIPOwnershipAppliedStateFile{}, err
	}
	if f.Version != 1 {
		return poolVIPOwnershipAppliedStateFile{}, fmt.Errorf("unsupported ownership attestation state version")
	}
	for scope, state := range f.States {
		if scope == "" || !validPoolVIPOwnershipStoredAttestation(state, scope) {
			return poolVIPOwnershipAppliedStateFile{}, fmt.Errorf("invalid ownership attestation state record")
		}
	}
	return f, nil
}

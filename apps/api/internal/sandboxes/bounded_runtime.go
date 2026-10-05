package sandboxes

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

// BoundedRuntimeBinding is operator configuration, never a create request.
// Trial expiry closes new creation even if an old record is deleted. Persistent
// authority admits exact qualified profiles with independent per-sandbox TTLs.
// Cleanup remains possible after expiry. No database/policy opt-in is implied.
// QualifiedRuntimeProfile is a trusted operator attestation to exact native
// qualification evidence. Candidate metadata and browser input cannot supply it.
type QualifiedRuntimeProfile struct {
	TemplateID                                        uuid.UUID
	ConfigDigest, Architecture, QualificationEvidence string
	PIDs                                              int
}

type BoundedRuntimeBinding struct {
	// Empty preserves exact creator/device admission and legacy serialized pins.
	Admission                               string `json:",omitempty"`
	RemoteTerminal                          *RemoteTerminalBinding
	Mode                                    string
	Profiles                                []QualifiedRuntimeProfile
	DevReservation                          *DevHistoricalReservation
	OrgID, CreatorID, GatewayID, TemplateID uuid.UUID
	TerminalDeviceID                        uuid.UUID
	ImageDigest                             string
	MemoryMiB, CPUs, PIDs                   int
	MaxTTLSeconds                           int32
	ExpiresAt                               time.Time
}

func (b BoundedRuntimeBinding) Persistent() bool         { return b.Mode == "persistent" }
func (b BoundedRuntimeBinding) OrganizationScoped() bool { return b.Admission == "organization" }
func (b BoundedRuntimeBinding) Validate() error {
	if !b.validRemoteTerminal() || b.OrgID == uuid.Nil || b.GatewayID == uuid.Nil || b.MemoryMiB != 128 || b.CPUs != 1 || b.MaxTTLSeconds < 300 {
		return ErrInvalid
	}
	if b.OrganizationScoped() {
		if !b.Persistent() || b.CreatorID != uuid.Nil || b.TerminalDeviceID != uuid.Nil || b.DevReservation != nil {
			return ErrInvalid
		}
	} else if b.Admission != "" || b.CreatorID == uuid.Nil || b.TerminalDeviceID == uuid.Nil {
		return ErrInvalid
	}
	if b.Persistent() {
		if !b.ExpiresAt.IsZero() || b.TemplateID != uuid.Nil || b.ImageDigest != "" || b.PIDs != 0 || b.MaxTTLSeconds > 900 || len(b.Profiles) < 1 || len(b.Profiles) > 4 {
			return ErrInvalid
		}
		seen := map[uuid.UUID]bool{}
		for _, p := range b.Profiles {
			if p.TemplateID == uuid.Nil || seen[p.TemplateID] || p.Architecture != "amd64" || strings.TrimSpace(p.QualificationEvidence) == "" || len(p.QualificationEvidence) > 512 || (p.PIDs != 64 && p.PIDs != 128) {
				return ErrInvalid
			}
			if _, err := sandboxruntime.Fingerprint(sandboxruntime.Spec{ID: p.TemplateID, ImageDigest: p.ConfigDigest, MemoryMiB: b.MemoryMiB, CPUs: b.CPUs, PIDs: p.PIDs, Architecture: p.Architecture}); err != nil {
				return ErrInvalid
			}
			// Measured manifests must never substitute for their OCI config ID, and
			// measured foreign-architecture configs must not gain native admission.
			if measured := ImageProfileForDigest(p.ConfigDigest); measured != nil && (measured.ConfigDigest != p.ConfigDigest || measured.Architecture != p.Architecture) {
				return ErrInvalid
			}
			seen[p.TemplateID] = true
		}
		if b.DevReservation != nil && !b.validDevReservation() {
			return ErrInvalid
		}
		return nil
	}
	if b.DevReservation != nil || (b.Mode != "" && b.Mode != "trial") || len(b.Profiles) != 0 || b.TemplateID == uuid.Nil || b.MaxTTLSeconds > 3600 || b.PIDs != 128 || b.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	if _, err := sandboxruntime.Fingerprint(sandboxruntime.Spec{ID: b.TemplateID, ImageDigest: b.ImageDigest, MemoryMiB: b.MemoryMiB, CPUs: b.CPUs, PIDs: b.PIDs}); err != nil {
		return ErrInvalid
	}
	return nil
}
func (b BoundedRuntimeBinding) profile(id uuid.UUID) (QualifiedRuntimeProfile, bool) {
	if !b.Persistent() {
		return QualifiedRuntimeProfile{TemplateID: b.TemplateID, ConfigDigest: b.ImageDigest, PIDs: b.PIDs}, id == b.TemplateID
	}
	for _, p := range b.Profiles {
		if p.TemplateID == id {
			return p, true
		}
	}
	return QualifiedRuntimeProfile{}, false
}
func (b BoundedRuntimeBinding) templateIDs() []uuid.UUID {
	if !b.Persistent() {
		return []uuid.UUID{b.TemplateID}
	}
	ids := make([]uuid.UUID, 0, len(b.Profiles))
	for _, p := range b.Profiles {
		ids = append(ids, p.TemplateID)
	}
	return ids
}
func (b BoundedRuntimeBinding) available(now time.Time) bool {
	return b.Validate() == nil && (b.Persistent() || now.Before(b.ExpiresAt))
}
func (b BoundedRuntimeBinding) Allows(org, creator uuid.UUID, now time.Time) bool {
	return b.available(now) && org == b.OrgID && creator != uuid.Nil && (b.OrganizationScoped() || creator == b.CreatorID)
}

// terminalDevice resolves only the identity requested at Create. The store
// separately verifies current ownership and gateway placement under its org lock.
func (b BoundedRuntimeBinding) terminalDevice(in *uuid.UUID) (uuid.UUID, error) {
	if b.OrganizationScoped() {
		if in == nil || *in == uuid.Nil {
			return uuid.Nil, ErrInvalid
		}
		return *in, nil
	}
	if in != nil && *in != b.TerminalDeviceID {
		return uuid.Nil, ErrForbidden
	}
	return b.TerminalDeviceID, nil
}

// The runtime ceiling never raises a lower organization or user quota.
func (b BoundedRuntimeBinding) quotas(perUser, total int32) (int32, int32) {
	return min(perUser, b.retainedLimit()), min(total, b.retainedLimit())
}

func bindingEqual(a, b BoundedRuntimeBinding) bool {
	if !a.ExpiresAt.Equal(b.ExpiresAt) {
		return false
	}
	a.ExpiresAt, b.ExpiresAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(a, b)
}

// Includes a Deleted record whose worker files/proofs have not yet been retired.
const retainedBoundedWorkload = `(observed_state<>'deleted' OR NOT EXISTS(SELECT 1 FROM sandbox_runtime_bindings r WHERE r.sandbox_id=sandboxes.id AND r.worker_retired_at IS NOT NULL))`

func (s *Store) WithBoundedRuntime(b BoundedRuntimeBinding) (*Store, error) {
	if s == nil || b.Validate() != nil || s.qualificationOrg != uuid.Nil {
		return nil, ErrInvalid
	}
	b.Profiles = append([]QualifiedRuntimeProfile(nil), b.Profiles...)
	if b.RemoteTerminal != nil {
		copy := *b.RemoteTerminal
		b.RemoteTerminal = &copy
	}
	if b.DevReservation != nil {
		copy := *b.DevReservation
		b.DevReservation = &copy
	}
	s.boundedRuntime = &b
	return s, nil
}

// CreationAvailable scopes the UI signal to the same principal as admission.
// It does not confer organization opt-in or runtime adapter availability.
func (s *Store) CreationAvailable(org, actor uuid.UUID) bool {
	if s == nil {
		return false
	}
	if s.boundedRuntime != nil {
		return s.boundedRuntime.Allows(org, actor, time.Now())
	}
	return s.qualificationOrg == uuid.Nil || s.qualificationOrg == org
}
func (s *Store) boundedCreate(ctx context.Context, org, actor uuid.UUID, in CreateInput) error {
	b := s.boundedRuntime
	if b == nil {
		return nil
	}
	if !b.Allows(org, actor, time.Now()) {
		return ErrDisabled
	}
	p, ok := b.profile(in.TemplateID)
	if !ok || in.TTLSeconds > b.MaxTTLSeconds || (b.Persistent() && len(in.Requested) != 0) {
		return ErrInvalid
	}
	var image string
	var memory int
	var ttl int32
	var scope []byte
	if err := s.pool.QueryRow(ctx, `SELECT image_digest,memory_mib,max_ttl_seconds,maximum_scope FROM sandbox_templates WHERE id=$1 AND org_id=$2 AND enabled`, in.TemplateID, b.OrgID).Scan(&image, &memory, &ttl, &scope); err != nil {
		return ErrDisabled
	}
	if image != p.ConfigDigest || memory != b.MemoryMiB || !strings.HasPrefix(image, "sha256:") {
		return ErrDisabled
	}
	if b.Persistent() {
		var maximum []Scope
		if ttl > b.MaxTTLSeconds || json.Unmarshal(scope, &maximum) != nil || len(maximum) != 0 {
			return ErrDisabled
		}
	}
	return nil
}

func (s *Store) retainedPredicate() string {
	if s.boundedRuntime != nil && s.boundedRuntime.Persistent() {
		return retainedBoundedWorkload
	}
	return "observed_state<>'deleted'"
}

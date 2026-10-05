package sandboxes

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

// RuntimeAuthorization is issued by the API's current durable lifecycle, never
// the browser. No database, policy authority or main key crosses this boundary.
type RuntimeAuthorization struct {
	SandboxID, OrgID, CreatorID, GatewayID, TerminalDeviceID, TemplateID uuid.UUID
	Profile                                                              QualifiedRuntimeProfile
	Generation                                                           int64
	Desired                                                              string
	CreatedAt, ExpiresAt                                                 time.Time
}
type RuntimeAuthorizer interface {
	AuthorizeRuntime(context.Context, RuntimeAuthorization) error
}

func (a RuntimeAuthorization) spec() sandboxruntime.Spec {
	return sandboxruntime.Spec{ID: a.SandboxID, ImageDigest: a.Profile.ConfigDigest, Architecture: a.Profile.Architecture, MemoryMiB: 128, CPUs: 1, PIDs: a.Profile.PIDs}
}
func (a RuntimeAuthorization) valid(b BoundedRuntimeBinding) bool {
	p, ok := b.profile(a.TemplateID)
	return b.Persistent() && b.Validate() == nil && ok && p == a.Profile && a.SandboxID != uuid.Nil && !b.deniesRuntimeID(a.SandboxID) && a.OrgID == b.OrgID && a.CreatorID != uuid.Nil && (b.OrganizationScoped() || a.CreatorID == b.CreatorID) && a.GatewayID == b.GatewayID && a.TerminalDeviceID != uuid.Nil && (b.OrganizationScoped() || a.TerminalDeviceID == b.TerminalDeviceID) && a.Generation > 0 && (a.Desired == "started" || a.Desired == "stopped" || a.Desired == "deleted") && !a.CreatedAt.IsZero() && a.ExpiresAt.After(a.CreatedAt) && a.ExpiresAt.Sub(a.CreatedAt) <= time.Duration(b.MaxTTLSeconds)*time.Second
}
func sameWorkload(a, b RuntimeAuthorization) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) || !a.ExpiresAt.Equal(b.ExpiresAt) {
		return false
	}
	a.CreatedAt, b.CreatedAt = time.Time{}, time.Time{}
	a.ExpiresAt, b.ExpiresAt = time.Time{}, time.Time{}
	a.Generation, b.Generation = 0, 0
	a.Desired, b.Desired = "", ""
	return reflect.DeepEqual(a, b)
}
func (c *WorkerRPCClient) AuthorizeRuntime(ctx context.Context, a RuntimeAuthorization) error {
	if _, err := c.call(ctx, workerRequest{Operation: "authorize", ID: a.SandboxID, Authorization: &a, Generation: a.Generation}); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.grants == nil {
		c.grants = map[uuid.UUID]int64{}
	}
	c.grants[a.SandboxID] = a.Generation
	return nil
}

// Publish complete records atomically; a crash cannot leave a partial final
// cleanup marker that permanently prevents recovery. Unpublished scratch is inert.
func (s *WorkerRPCServer) writeRecord(destination string, raw []byte) error {
	name := "api-record-" + uuid.NewString() + ".tmp"
	f, err := s.ControlRoot.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrConflict
	}
	defer s.ControlRoot.Remove(name)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || s.ControlRoot.Rename(name, destination) != nil || syncTerminalDirectory(s.ControlRoot) != nil {
		return ErrConflict
	}
	return nil
}
func (s *WorkerRPCServer) writePin(p workerPin) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return ErrInvalid
	}
	if err = s.writeRecord("api-binding.json", raw); err != nil {
		return err
	}
	s.sandboxID = p.SandboxID
	s.active = p.Authorization
	s.epoch = p.Epoch
	s.withdrawn = p.Withdrawn
	s.epochGeneration = p.EpochGeneration
	return nil
}
func (s *WorkerRPCServer) currentPin() workerPin {
	return workerPin{Binding: s.Binding, SandboxID: s.sandboxID, Authorization: s.active, Epoch: s.epoch, Withdrawn: s.withdrawn, EpochGeneration: s.epochGeneration}
}
func completedName(id uuid.UUID) string { return "api-completed-" + id.String() + ".json" }
func (s *WorkerRPCServer) completed(id uuid.UUID) (workerPin, error) {
	raw, err := readControlFile(s.ControlRoot, completedName(id), 32768)
	if err != nil {
		if _, statErr := s.ControlRoot.Lstat(completedName(id)); errors.Is(statErr, os.ErrNotExist) {
			return workerPin{}, os.ErrNotExist
		}
		return workerPin{}, ErrConflict
	}
	var p workerPin
	if json.Unmarshal(raw, &p) != nil || !bindingEqual(p.Binding, s.Binding) || p.SandboxID != id || p.Authorization == nil || !p.Authorization.valid(s.Binding) || p.Authorization.Desired != "deleted" {
		return workerPin{}, ErrConflict
	}
	return p, nil
}
func (s *WorkerRPCServer) authorize(ctx context.Context, a RuntimeAuthorization) error {
	if !a.valid(s.Binding) {
		return ErrForbidden
	}
	if done, err := s.completed(a.SandboxID); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return err
		}
		if a.Desired == "deleted" && a.Generation == done.Authorization.Generation && sameWorkload(a, *done.Authorization) {
			return nil
		}
		return ErrForbidden
	}
	if a.Desired == "started" && !time.Now().Before(a.ExpiresAt) {
		return ErrDisabled
	}
	if s.active == nil {
		if s.sandboxID != uuid.Nil {
			return ErrConflict
		}
		return s.writeAuthorizedPin(workerPin{Binding: s.Binding, SandboxID: a.SandboxID, Authorization: &a})
	}
	old := *s.active
	if !sameWorkload(old, a) || a.Generation < old.Generation || (a.Generation == old.Generation && a.Desired != old.Desired) || old.Desired == "deleted" && a.Desired != "deleted" {
		return ErrForbidden
	}
	if a.Generation > old.Generation && a.Desired == "started" {
		var err error
		ctx, err = s.actorProviderContext(ctx, old)
		if err != nil {
			return err
		}
		status, err := s.Provider.Inspect(ctx, a.SandboxID)
		if old.Desired != "stopped" || err != nil || status.Running || !s.withdrawn || sandboxruntime.Matches(a.spec(), status) != nil {
			return ErrConflict
		}
	}
	if a.Generation == old.Generation {
		return s.persistActorLease(a)
	}
	p := s.currentPin()
	p.Authorization = &a
	return s.writeAuthorizedPin(p)
}
func sameNetworkTarget(a, b *PrivateNetworkTarget) bool { return reflect.DeepEqual(a, b) }
func (s *WorkerRPCServer) persistentTarget(ctx context.Context, op string, t *PrivateNetworkTarget) error {
	a := s.active
	hash, _ := sandboxruntime.Fingerprint(a.spec())
	if t == nil || t.OrgID != a.OrgID || t.GatewayID != a.GatewayID || t.SandboxID != a.SandboxID || t.SpecHash != hash || t.OperationID == uuid.Nil || t.RuntimeID == "" {
		return ErrForbidden
	}
	if sameNetworkTarget(s.epoch, t) {
		if (op == "apply-network" || op == "probe") && (a.Desired != "started" || s.epochGeneration != a.Generation || s.withdrawn) {
			return ErrForbidden
		}
		return nil
	}
	cleanupFirstEpoch := s.epoch == nil && a.Desired != "started" && (op == "check-config" || op == "remove-network" || op == "gateway-absence") && t.Generation <= a.Generation
	if !cleanupFirstEpoch && (!time.Now().Before(a.ExpiresAt) || (op != "check-config" && op != "apply-network") || a.Desired != "started" || t.Generation != 1 || (s.epoch != nil && (!s.withdrawn || a.Generation <= s.epochGeneration || enrollmentOperation(*t) != enrollmentOperation(*s.epoch)))) {
		return ErrForbidden
	}
	// Persist only an epoch backed by the original immutable enrollment files and
	// exact provider identity. Reading config does not mint another credential.
	if _, err := s.Files.ReadPrivateNetworkConfig(ctx, *t); err != nil {
		return err
	}
	status, err := s.Provider.Inspect(ctx, a.SandboxID)
	if err != nil || status.RuntimeID != t.RuntimeID || sandboxruntime.Matches(a.spec(), status) != nil {
		return ErrConflict
	}
	p := s.currentPin()
	copy := *t
	p.Epoch = &copy
	p.EpochGeneration = a.Generation
	p.Withdrawn = false
	return s.writePin(p)
}
func (s *WorkerRPCServer) retirePersistent(ctx context.Context, id uuid.UUID, generation int64) error {
	if done, err := s.completed(id); err == nil {
		if done.Authorization.Generation != generation {
			return ErrForbidden
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if s.active == nil || s.sandboxID != id || s.active.Generation != generation || s.active.Desired != "deleted" || (s.epoch != nil && !s.withdrawn) {
		return ErrForbidden
	}
	var err error
	ctx, err = s.actorProviderContext(ctx, *s.active)
	if err != nil {
		return err
	}
	if _, err := s.Provider.Inspect(ctx, id); !errors.Is(err, sandboxruntime.ErrMissing) {
		return ErrConflict
	}
	// API's physical tombstone already requires canonical withdrawal and freshness;
	// worker independently requires its own epoch's gateway-absence checkpoint.
	if err := s.AssetsRoot.RemoveAll(id.String()); err != nil {
		return ErrConflict
	}
	if err := s.ControlRoot.RemoveAll(id.String()); err != nil {
		return ErrConflict
	}
	for _, root := range []*os.Root{s.AssetsRoot, s.ControlRoot} {
		if _, err := root.Lstat(id.String()); !errors.Is(err, os.ErrNotExist) {
			return ErrConflict
		}
		if syncTerminalDirectory(root) != nil {
			return ErrConflict
		}
	}
	p := s.currentPin()
	raw, _ := json.Marshal(p)
	if err := s.writeRecord(completedName(id), raw); err != nil {
		return err
	}
	// Marker precedes slot removal. Restart can finish this exact interrupted step.
	if s.ControlRoot.Remove("api-binding.json") != nil || syncTerminalDirectory(s.ControlRoot) != nil {
		return ErrConflict
	}
	s.sandboxID = uuid.Nil
	s.active = nil
	s.epoch = nil
	s.withdrawn = false
	s.epochGeneration = 0
	return nil
}

package sandboxnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/google/uuid"
)

type inactiveManifestStore interface{ ReserveInactive(Plan, uint32) error }

// Inactive cleanup is admitted only from the configured worker after it proves
// its exact immutable provider resource has PID0 and no retained namespace.
// This root helper can only touch an exact owned birth-link residue; it cannot
// enter a namespace, configure WireGuard or grant gateway/policy access here.
func (c Controller) RemoveInactive(ctx context.Context, p Plan, workerUID uint32) error {
	p, err := Normalize(p)
	if err != nil {
		return err
	}
	store, ok := c.Store.(inactiveManifestStore)
	if !ok || c.Driver == nil || workerUID == 0 {
		return ErrUnavailable
	}
	if err = store.ReserveInactive(p, workerUID); err != nil {
		return err
	}
	link, err := c.Driver.BirthLink(ctx, p)
	if err == nil {
		if !ownedLink(p, link) {
			return ErrOwnership
		}
		if err = c.Driver.DeleteBirthLink(ctx, p, link); err != nil {
			return err
		}
	} else if !errors.Is(err, ErrMissing) {
		return err
	}
	return c.InspectInactiveRemoved(ctx, p, workerUID)
}

func (c Controller) InspectInactiveRemoved(ctx context.Context, p Plan, workerUID uint32) error {
	p, err := Normalize(p)
	if err != nil {
		return err
	}
	store, ok := c.Store.(inactiveManifestStore)
	if !ok || c.Driver == nil || workerUID == 0 {
		return ErrUnavailable
	}
	if err = store.ReserveInactive(p, workerUID); err != nil {
		return err
	}
	if _, err = c.Driver.BirthLink(ctx, p); !errors.Is(err, ErrMissing) {
		return ErrOwnership
	}
	return nil
}

type inactiveManifest struct {
	Plan      Plan   `json:"plan"`
	WorkerUID uint32 `json:"worker_uid"`
}

// Keep a helper-owned tombstone bound to the entire immutable plan, including
// its original namespace manifest if one existed. Missing initial application
// is allowed, but this operation can never later be activated or repurposed.
func (s FilesystemManifests) ReserveInactive(p Plan, workerUID uint32) error {
	if s.Root == nil || workerUID == 0 {
		return ErrInvalid
	}
	p, err := Normalize(p)
	if err != nil {
		return err
	}
	if raw, err := s.readManifest(p.Binding.OperationID.String() + ".json"); err == nil {
		var old Manifest
		if json.Unmarshal(raw, &old) != nil || old.Namespace.OwnerUID != workerUID || old.Namespace.Inode == 0 || !old.Matches(p, old.Namespace) {
			return ErrOwnership
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	name := p.Binding.OperationID.String() + ".inactive.json"
	want := inactiveManifest{p, workerUID}
	if raw, err := s.readManifest(name); err == nil {
		var old inactiveManifest
		if json.Unmarshal(raw, &old) != nil || old.WorkerUID != workerUID {
			return ErrOwnership
		}
		a, ea := Identity(old.Plan)
		b, eb := Identity(p)
		if ea != nil || eb != nil || a != b {
			return ErrOwnership
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.Marshal(want)
	if err != nil {
		return ErrInvalid
	}
	stage := "." + name + "." + uuid.NewString() + ".pending"
	f, err := s.Root.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrOwnership
	}
	defer s.Root.Remove(stage)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || s.Root.Rename(stage, name) != nil {
		return ErrUnavailable
	}
	dir, err := s.Root.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

func (s FilesystemManifests) readManifest(name string) ([]byte, error) {
	info, err := s.Root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > 16384 {
		return nil, ErrOwnership
	}
	return s.Root.ReadFile(name)
}

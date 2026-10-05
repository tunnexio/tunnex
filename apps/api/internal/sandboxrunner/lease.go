package sandboxrunner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
)

type Lease struct {
	SandboxID  uuid.UUID `json:"sandbox_id"`
	Generation int64     `json:"generation"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}
type ExpiryReceipt struct {
	Lease Lease `json:"lease"`
	// StoppedAt is the sampled sweep time, written only after stop confirms
	// execution fenced. It is not a measurement of physical stop completion.
	StoppedAt time.Time `json:"stopped_at"`
}

// LeaseStore is runner-local. Expiry fences execution, never asserts canonical
// gateway withdrawal/address release or deletes persistence before CP reconciliation.
type LeaseStore struct{ Root *os.Root }

func validLease(l Lease) bool {
	return l.SandboxID != uuid.Nil && l.Generation > 0 && !l.CreatedAt.IsZero() && l.ExpiresAt.After(l.CreatedAt) && l.ExpiresAt.Sub(l.CreatedAt) <= 900*time.Second
}
func (s LeaseStore) write(name string, v any) error {
	raw, e := json.Marshal(v)
	if e != nil {
		return e
	}
	tmp := ".lease-" + uuid.NewString()
	f, e := s.Root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer s.Root.Remove(tmp)
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = s.Root.Rename(tmp, name); e != nil {
		return e
	}
	dir, e := s.Root.Open(".")
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func (s LeaseStore) read(name string, v any) error {
	f, e := s.Root.Open(name)
	if e != nil {
		return e
	}
	defer f.Close()
	const recordLimit = 2*PayloadLimit + 4097
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > recordLimit {
		return ErrInvalid
	}
	d := json.NewDecoder(io.LimitReader(f, recordLimit))
	d.DisallowUnknownFields()
	if e = d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}

// Get restores a single actor-owned original lifetime. The generation may be
// ahead of its execution pin after a failed publication; callers must preserve
// that fence rather than recreate the lower pin generation after restart.
func (s LeaseStore) Get(id uuid.UUID) (Lease, error) {
	if s.Root == nil || id == uuid.Nil {
		return Lease{}, ErrInvalid
	}
	var l Lease
	if err := s.read(id.String()+".lease.json", &l); err != nil {
		return Lease{}, err
	}
	if !validLease(l) || l.SandboxID != id {
		return Lease{}, ErrInvalid
	}
	return l, nil
}

func (s LeaseStore) Put(l Lease) error {
	if s.Root == nil || !validLease(l) {
		return ErrInvalid
	}
	name := l.SandboxID.String() + ".lease.json"
	var old Lease
	e := s.read(name, &old)
	if e == nil {
		if old.SandboxID != l.SandboxID || !old.CreatedAt.Equal(l.CreatedAt) || !old.ExpiresAt.Equal(l.ExpiresAt) || l.Generation < old.Generation {
			return ErrInvalid
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	return s.write(name, l)
}

// Sweep must be serialized with Put by the runtime owner. stop must fence exact
// provider identity and be idempotent: a crash can occur after stop before receipt.
func (s LeaseStore) Sweep(ctx context.Context, now time.Time, stop func(context.Context, Lease) error) error {
	if s.Root == nil || stop == nil {
		return ErrInvalid
	}
	dir, e := s.Root.Open(".")
	if e != nil {
		return e
	}
	defer dir.Close()
	var failures error
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(failures, err)
		}
		// Historical receipts do not increase the in-memory directory batch.
		entries, readErr := dir.ReadDir(32)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return errors.Join(failures, readErr)
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return errors.Join(failures, err)
			}
			id, e := uuid.Parse(entry.Name()[:min(len(entry.Name()), 36)])
			if e != nil || entry.Name() != id.String()+".lease.json" {
				continue
			}
			var l Lease
			if e = s.read(entry.Name(), &l); e != nil {
				failures = errors.Join(failures, e)
				continue
			}
			if !validLease(l) || l.SandboxID != id {
				failures = errors.Join(failures, ErrInvalid)
				continue
			}
			if now.Before(l.ExpiresAt) {
				continue
			}
			name := id.String() + ".expired.json"
			var receipt ExpiryReceipt
			e = s.read(name, &receipt)
			if e == nil {
				if receipt.Lease.SandboxID != l.SandboxID || receipt.Lease.Generation > l.Generation || !receipt.Lease.CreatedAt.Equal(l.CreatedAt) || !receipt.Lease.ExpiresAt.Equal(l.ExpiresAt) || receipt.StoppedAt.Before(l.ExpiresAt) {
					failures = errors.Join(failures, ErrInvalid)
				}
				continue
			}
			if !os.IsNotExist(e) {
				failures = errors.Join(failures, e)
				continue
			}
			if e = stop(ctx, l); e != nil {
				failures = errors.Join(failures, fmt.Errorf("runner expiry incomplete: %w", e))
				continue
			}
			if e = s.write(name, ExpiryReceipt{l, now}); e != nil {
				failures = errors.Join(failures, e)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return failures
		}
	}
}

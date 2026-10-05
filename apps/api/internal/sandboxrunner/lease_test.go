package sandboxrunner

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOfflineLeaseGetRestoresOnlyValidatedOriginalIdentity(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	s := LeaseStore{Root: root}
	now := time.Now().UTC()
	l := Lease{SandboxID: uuid.New(), Generation: 2, CreatedAt: now, ExpiresAt: now.Add(900 * time.Second)}
	if err := s.Put(l); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(l.SandboxID); err != nil || got != l {
		t.Fatal("Get changed original lifetime/generation", got, err)
	}
	for _, scenario := range []string{"foreign-id", "zero-generation", "overlong-lifetime", "unknown-field", "trailing-record", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			bad := l
			switch scenario {
			case "foreign-id":
				bad.SandboxID = uuid.New()
			case "zero-generation":
				bad.Generation = 0
			case "overlong-lifetime":
				bad.ExpiresAt = bad.ExpiresAt.Add(time.Second)
			}
			raw, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "unknown-field":
				raw = append(raw[:len(raw)-1], []byte(",\"foreign\":true}")...)
			case "trailing-record":
				raw = append(raw, []byte(" {}")...)
			case "oversized":
				raw = append(raw, []byte(strings.Repeat(" ", 2*PayloadLimit+4098))...)
			}
			f, err := root.OpenFile(l.SandboxID.String()+".lease.json", os.O_TRUNC|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := f.Write(raw)
			closeErr := f.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatal(writeErr, closeErr)
			}
			if _, err := s.Get(l.SandboxID); err == nil {
				t.Fatal("invalid durable identity restored", scenario)
			}
		})
	}
	if _, err := s.Get(uuid.Nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil lease identity accepted", err)
	}
	if _, err := (LeaseStore{}).Get(l.SandboxID); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing lease root accepted", err)
	}
}

func TestOfflineExpiryFailureCannotStarveLaterLease(t *testing.T) {
	for _, scenario := range []string{"stop-error", "corrupt-lease", "invalid-lease", "invalid-receipt"} {
		t.Run(scenario, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			s := LeaseStore{root}
			now := time.Now().UTC()
			leases := map[uuid.UUID]Lease{}
			for range 2 {
				l := Lease{uuid.New(), 1, now.Add(-301 * time.Second), now.Add(-time.Second)}
				leases[l.SandboxID] = l
				if err = s.Put(l); err != nil {
					t.Fatal(err)
				}
			}
			// Use actual directory order: the failed record is encountered before
			// the valid one, so the old return-on-first-error sweep would fail.
			dir, err := root.Open(".")
			if err != nil {
				t.Fatal(err)
			}
			entries, err := dir.ReadDir(-1)
			dir.Close()
			if err != nil || len(entries) != 2 {
				t.Fatal("lease directory", err)
			}
			badID, err := uuid.Parse(entries[0].Name()[:36])
			if err != nil {
				t.Fatal(err)
			}
			goodID, err := uuid.Parse(entries[1].Name()[:36])
			if err != nil {
				t.Fatal(err)
			}
			write := func(name string, raw []byte) {
				t.Helper()
				f, e := root.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				_, e = f.Write(raw)
				closeErr := f.Close()
				if e != nil || closeErr != nil {
					t.Fatal(e, closeErr)
				}
			}
			switch scenario {
			case "corrupt-lease":
				write(entries[0].Name(), []byte("{"))
			case "invalid-lease":
				bad := leases[badID]
				bad.ExpiresAt = bad.CreatedAt.Add(901 * time.Second)
				raw, _ := json.Marshal(bad)
				write(entries[0].Name(), raw)
			case "invalid-receipt":
				bad := ExpiryReceipt{leases[badID], now}
				bad.Lease.CreatedAt = bad.Lease.CreatedAt.Add(-time.Second)
				raw, _ := json.Marshal(bad)
				write(badID.String()+".expired.json", raw)
			}
			stopFailure := errors.New("pending exact-runtime confirmation")
			var called []uuid.UUID
			stop := func(_ context.Context, l Lease) error {
				called = append(called, l.SandboxID)
				if l.SandboxID == badID {
					return stopFailure
				}
				return nil
			}
			if err = s.Sweep(context.Background(), now, stop); err == nil {
				t.Fatal("failed lease was hidden")
			}
			if scenario == "stop-error" && (!errors.Is(err, stopFailure) || len(called) != 2 || called[0] != badID || called[1] != goodID) {
				t.Fatal("did not continue after first stop error", called, err)
			}
			if _, err = root.Stat(goodID.String() + ".expired.json"); err != nil {
				t.Fatal("failed historical record starved later execution fence", err)
			}
			if scenario != "invalid-receipt" {
				if _, err = root.Stat(badID.String() + ".expired.json"); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed lease acquired receipt", err)
				}
			}
			before := len(called)
			_ = s.Sweep(context.Background(), now, stop)
			for _, id := range called[before:] {
				if id == goodID {
					t.Fatal("confirmed later receipt was not idempotent")
				}
			}
		})
	}
}

func TestOfflineExpiryCancellationPreventsFurtherEffects(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	s := LeaseStore{root}
	now := time.Now().UTC()
	for range 2 {
		if err = s.Put(Lease{uuid.New(), 1, now.Add(-301 * time.Second), now.Add(-time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err = s.Sweep(ctx, now, func(context.Context, Lease) error {
		calls++
		cancel()
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("canceled sweep continued effects", calls, err)
	}
}

func TestOfflineExpiryRetryAndImmutableDeadline(t *testing.T) {
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	s := LeaseStore{root}
	now := time.Now().UTC()
	l := Lease{uuid.New(), 1, now, now.Add(900 * time.Second)}
	if e = s.Put(l); e != nil {
		t.Fatal(e)
	}
	extended := l
	extended.ExpiresAt = extended.ExpiresAt.Add(time.Second)
	if s.Put(extended) == nil {
		t.Fatal("extension allowed")
	}
	calls := 0
	stop := func(context.Context, Lease) error {
		calls++
		if calls == 1 {
			return errors.New("failure")
		}
		return nil
	}
	if e = s.Sweep(context.Background(), now, stop); e != nil || calls != 0 {
		t.Fatal(e)
	}
	expired := l.ExpiresAt.Add(time.Second)
	if s.Sweep(context.Background(), expired, stop) == nil {
		t.Fatal("failure hidden")
	}
	if e = s.Sweep(context.Background(), expired, stop); e != nil {
		t.Fatal(e)
	}
	if e = s.Sweep(context.Background(), expired, stop); e != nil || calls != 2 {
		t.Fatal(calls, e)
	}
}

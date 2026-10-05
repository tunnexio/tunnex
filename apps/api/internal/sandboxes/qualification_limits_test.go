package sandboxes

import (
	"errors"
	"testing"
)

func TestStartPostgresQualification64Default128AndBindingImmutable(t *testing.T) {
	for _, qualification := range []bool{false, true} {
		f := newFixture(t)
		if qualification {
			f.store.WithQualificationOrg(f.org)
		}
		sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("pid-limits"))
		if err != nil {
			t.Fatal(err)
		}
		provider := &startProvider{}
		if err = f.store.ReconcileQuarantinedStart(f.ctx, sandbox.Identity.ID, provider); err != nil {
			t.Fatal(err)
		}
		var pids int
		if err = f.pool.QueryRow(f.ctx, `SELECT pids FROM sandbox_runtime_bindings WHERE sandbox_id=$1`, sandbox.Identity.ID).Scan(&pids); err != nil {
			t.Fatal(err)
		}
		want := 128
		if qualification {
			want = 64
		}
		if pids != want {
			t.Fatal("incorrect durable PID cap", pids, want)
		}
		if !qualification {
			f.store.WithQualificationOrg(f.org)
			if err = f.store.ReconcileQuarantinedStart(f.ctx, sandbox.Identity.ID, provider); !errors.Is(err, ErrConflict) {
				t.Fatal("existing resource binding changed", err)
			}
		}
	}
}

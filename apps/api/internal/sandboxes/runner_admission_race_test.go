package sandboxes

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestRunnerTrialPostgresAdmissionRevocationRaceRollsBackOrOwnsCleanup(t *testing.T) {
	for _, revokeBeforeCommit := range []bool{true, false} {
		t.Run(map[bool]string{true: "revoked-after-availability", false: "created-before-revoke"}[revokeBeforeCommit], func(t *testing.T) {
			f, b, ctx, s, _, in, enrollmentID := runnerTrialFixture(t)
			er, err := s.read(f.ctx, f.pool, enrollmentID, false)
			if err != nil {
				t.Fatal(err)
			}
			// Explicit synthetic prequalified-key fixture exercises admission atomicity;
			// it does not establish native qualification of a real host.
			s.config.QualifiedRunnerSPKIHash = hex.EncodeToString(er.keyHash)
			s.config.HostQualificationEvidence = "synthetic-admission-fixture"
			devExec(t, f, `UPDATE organizations SET sandboxes_enabled=true WHERE id=$1`, f.org)
			devExec(t, f, `UPDATE sandbox_templates SET enabled=true WHERE id=$1`, b.Profiles[0].TemplateID)
			if !s.RuntimeReady(f.ctx) {
				t.Fatal("synthetic ready fixture")
			}
			f.store.WithRunnerAdmission(s.BindSandboxAdmission)
			f.store.WithRunnerAvailability(func(c context.Context) bool {
				ready := s.RuntimeReady(c)
				if ready && revokeBeforeCommit {
					if _, err := s.Revoke(ctx, f.org, f.user, enrollmentID); err != nil {
						t.Fatal(err)
					}
				}
				return ready
			})
			sb, _, err := f.store.Create(f.ctx, f.org, f.user, organizationInput(f, b, in.TerminalDeviceID, "atomic-grant-map"))
			if revokeBeforeCommit {
				if !errors.Is(err, ErrDisabled) && !errors.Is(err, ErrForbidden) {
					t.Fatal("revocation race admitted", err)
				}
				var count int
				if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM sandboxes WHERE org_id=$1`, f.org).Scan(&count); err != nil || count != 0 {
					t.Fatal("rollback left retained inert workload", count, err)
				}
				return
			}
			if err != nil {
				t.Fatal("qualified admission", err)
			}
			var mapped uuid.UUID
			if err = f.pool.QueryRow(f.ctx, `SELECT enrollment_id FROM sandbox_runner_workloads WHERE sandbox_id=$1`, sb.Identity.ID).Scan(&mapped); err != nil || mapped != enrollmentID {
				t.Fatal("creation not atomically mapped", mapped, err)
			}
			if _, err = s.Revoke(ctx, f.org, f.user, enrollmentID); err != nil {
				t.Fatal(err)
			}
			var desired, observed string
			var generation int64
			if err = f.pool.QueryRow(f.ctx, `SELECT desired_state,observed_state,generation FROM sandboxes WHERE id=$1`, sb.Identity.ID).Scan(&desired, &observed, &generation); err != nil || desired != "deleted" || generation != 2 || observed == "deleted" {
				t.Fatal("revoke lost bounded cleanup or claimed physical deletion", desired, observed, generation, err)
			}
		})
	}
}

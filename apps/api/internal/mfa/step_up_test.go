package mfa

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestStepUpAuthorityAndSharedFactorReplay(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := seed(t, pool)
	svc, clock := newSvc(t, pool)
	secret, recovery := enroll(t, svc, clock, f.userA)
	_, otherRecovery := enroll(t, svc, clock, f.userB)
	q := sqlc.New(pool)
	user, err := q.GetUserByID(ctx, f.userA)
	if err != nil {
		t.Fatal(err)
	}
	// Confirmation stamped the replay clock already.
	if _, _, err = svc.VerifyStepUp(ctx, f.userA, user.AppAuthEpoch, codeAt(t, secret, clock.Unix())); code(err) != "invalid_code" {
		t.Fatal("confirmation replay accepted", err)
	}
	*clock = clock.Add(60 * time.Second)
	at, via, err := svc.VerifyStepUp(ctx, f.userA, user.AppAuthEpoch, codeAt(t, secret, clock.Unix()))
	if err != nil || via || !at.Equal(*clock) {
		t.Fatal("fresh TOTP failed", at, via, err)
	}
	// Login and step-up share the same replay clock.
	challenge, _, err := svc.CreateChallengeWithAuthority(ctx, f.userA, user.AppAuthEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = svc.VerifyChallenge(ctx, challenge, codeAt(t, secret, clock.Unix())); code(err) != "invalid_code" {
		t.Fatal("step-up TOTP reused for login", err)
	}
	if _, _, err = svc.VerifyStepUp(ctx, f.userA, user.AppAuthEpoch, otherRecovery[0]); code(err) != "invalid_code" {
		t.Fatal("another user's factor accepted", err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, recovered, e := svc.VerifyStepUp(context.Background(), f.userA, user.AppAuthEpoch, recovery[0])
			if e == nil && !recovered {
				t.Error("recovery source lost")
			}
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	successes, failures := 0, 0
	for e := range results {
		if e == nil {
			successes++
		} else if code(e) == "invalid_code" {
			failures++
		} else {
			t.Fatal(e)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("single-use recovery race: success=%d failure=%d", successes, failures)
	}
	updated, err := q.SetUserPasswordAndBumpAppAuthEpoch(ctx, sqlc.SetUserPasswordAndBumpAppAuthEpochParams{UserID: f.userA})
	if err != nil {
		t.Fatal(err)
	}
	before, err := q.CountUnusedRecoveryCodes(ctx, f.userA)
	if err != nil {
		t.Fatal(err)
	}
	for _, epoch := range []int64{0, user.AppAuthEpoch} {
		if _, _, err = svc.VerifyStepUp(ctx, f.userA, epoch, recovery[1]); code(err) != "mfa_session_invalid" {
			t.Fatal("stale parent acquired proof", err)
		}
	}
	after, err := q.CountUnusedRecoveryCodes(ctx, f.userA)
	if err != nil || before != after {
		t.Fatal("invalid parent consumed recovery factor", err)
	}
	if _, _, err = svc.VerifyStepUp(ctx, f.userA, updated.AppAuthEpoch, recovery[1]); err != nil {
		t.Fatal("fresh parent failed", err)
	}
	if _, err = pool.Exec(ctx, "UPDATE users SET status='deactivated' WHERE id=$1", f.userA); err != nil {
		t.Fatal(err)
	}
	if _, _, err = svc.VerifyStepUp(ctx, f.userA, updated.AppAuthEpoch, recovery[2]); code(err) != "mfa_session_invalid" {
		t.Fatal("inactive user acquired proof", err)
	}
}

func TestFactorResetAdvancesAllParentAuthority(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := seed(t, pool)
	svc, clock := newSvc(t, pool)
	q := sqlc.New(pool)
	_, _ = enroll(t, svc, clock, f.userA)
	before, err := q.GetUserByID(ctx, f.userA)
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.Disenroll(ctx, f.userA, f.userA, "mfa.disenrolled"); err != nil {
		t.Fatal(err)
	}
	after, err := q.GetUserByID(ctx, f.userA)
	if err != nil || after.AppAuthEpoch != before.AppAuthEpoch+1 {
		t.Fatal("disenroll retained existing local/SSO authority", err)
	}
	if _, _, err = svc.StartEnrollmentWithAuthority(ctx, f.userA, before.AppAuthEpoch); code(err) != "mfa_session_invalid" {
		t.Fatal("old parent re-enrolled", err)
	}
	_, _ = enroll(t, svc, clock, f.userA)
	if err = svc.AdminReset(ctx, f.org, f.userB, f.userA); err != nil {
		t.Fatal(err)
	}
	reset, err := q.GetUserByID(ctx, f.userA)
	if err != nil || reset.AppAuthEpoch != after.AppAuthEpoch+1 {
		t.Fatal("admin reset retained existing authority", err)
	}
	var enforced bool
	if err = pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM org_mfa WHERE org_id=$1 AND enforce)", f.org).Scan(&enforced); err != nil || enforced {
		t.Fatal("factor ceremony changed org enforcement", err)
	}
}

func TestEnrollmentConfirmAndRestartCannotReplaceVerifiedFactor(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := seed(t, pool)
	svc, clock := newSvc(t, pool)
	user, err := svc.q.GetUserByID(ctx, f.userA)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := svc.StartEnrollmentWithAuthority(ctx, f.userA, user.AppAuthEpoch)
	if err != nil {
		t.Fatal(err)
	}
	codeValue := codeAt(t, secret, clock.Unix())
	type result struct {
		confirm bool
		err     error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	go func() {
		<-start
		_, _, e := svc.ConfirmEnrollmentWithAuthority(ctx, f.userA, user.AppAuthEpoch, codeValue)
		results <- result{true, e}
	}()
	go func() {
		<-start
		_, _, e := svc.StartEnrollmentWithAuthority(ctx, f.userA, user.AppAuthEpoch)
		results <- result{false, e}
	}()
	close(start)
	a, b := <-results, <-results
	for _, r := range []result{a, b} {
		if r.confirm && r.err == nil {
			row, e := svc.q.GetTOTP(ctx, f.userA)
			if e != nil || !row.Confirmed {
				t.Fatal("confirmed factor overwritten by restart", e)
			}
			got, e := svc.sealer.Open(string(row.SecretEnc))
			if e != nil || string(got) != secret {
				t.Fatal("verified factor secret replaced", e)
			}
		}
		if r.err != nil && code(r.err) != "already_enrolled" && code(r.err) != "invalid_code" {
			t.Fatal(r.err)
		}
	}
}

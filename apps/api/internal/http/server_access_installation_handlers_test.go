package http

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"github.com/tunnexio/tunnex/apps/api/internal/serveraccess"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestServerAccessInstallationRequiresCPAdminHumanSession(t *testing.T) {
	s := apiServer{serverAccess: serveraccess.New(nil, nil, nil, true)}
	for _, p := range []*authctx.Principal{
		nil,
		{UserID: uuid.New(), SessionID: "s", EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): "owner"}},
		{UserID: uuid.New(), SessionID: "s", CPAdmin: true},
		{UserID: uuid.New(), SessionID: "s", CPAdmin: true, EmailVerified: true, MustChangePassword: true},
		{UserID: uuid.New(), CPAdmin: true, EmailVerified: true},
		{UserID: uuid.New(), SessionID: "s", CPAdmin: true, EmailVerified: true, AuthMethod: authctx.AuthBearer},
	} {
		ctx := context.Background()
		if p != nil {
			ctx = authctx.WithPrincipal(ctx, p)
		}
		if _, err := s.GetServerAccessInstallation(ctx, api.GetServerAccessInstallationRequestObject{}); err == nil {
			t.Fatalf("read bypass for %+v", p)
		}
		if _, err := s.UpdateServerAccessInstallation(ctx, api.UpdateServerAccessInstallationRequestObject{Body: &api.ServerAccessInstallationInput{Enabled: true}}); err == nil {
			t.Fatalf("write bypass for %+v", p)
		}
	}
}

func TestServerAccessInstallationReauthentication(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	q := sqlc.New(pool)
	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "sa-installation@app.test", Name: "Server admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE users SET email_verified_at=now() WHERE id=$1", user.ID); err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	store := session.NewWithClient(rdb, time.Hour, 24*time.Hour)
	parent, err := store.CreateWithAuthority(ctx, user.ID, authctx.AuthSSO, user.AppAuthEpoch)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := crypto.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	server := apiServer{system: q, sessions: store, mfa: mfa.NewService(pool, sealer, nil, nil), serverAccess: serveraccess.New(pool, store, sealer, false)}
	var got api.GetServerAccessInstallationResponseObject
	admin := func(p session.Session) context.Context {
		c := mfaHandlerContext(ctx, p)
		principal, _ := authctx.PrincipalFrom(c)
		principal.CPAdmin = true
		return c
	}
	save := func(c context.Context, enabled bool, version int64, pw *string) (api.ServerAccessInstallation, error) {
		out, err := server.UpdateServerAccessInstallation(c, api.UpdateServerAccessInstallationRequestObject{Body: &api.ServerAccessInstallationInput{Enabled: enabled, ExpectedVersion: version, CurrentPassword: pw}})
		if err != nil {
			return api.ServerAccessInstallation{}, err
		}
		return out.(api.UpdateServerAccessInstallation200JSONResponse).Body, nil
	}
	str := func(v string) *string { return &v }

	// SSO account with neither a local password nor MFA cannot prove recent authentication.
	got, err = server.GetServerAccessInstallation(admin(parent), api.GetServerAccessInstallationRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	view := got.(api.GetServerAccessInstallation200JSONResponse).Body
	if view.Reauthentication.Available || view.Source != "environment" || view.Enabled {
		t.Fatalf("view = %+v", view)
	}
	if _, err = save(admin(parent), true, 0, nil); mfaHandlerErrorCode(err) != "reauthentication_unavailable" {
		t.Fatalf("no factor = %v", err)
	}

	// A local password must be re-entered and is rate limited with the step-up budget.
	hash, err := password.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, parent.UserID, hash); err != nil {
		t.Fatal(err)
	}
	if _, err = save(admin(parent), true, 0, nil); mfaHandlerErrorCode(err) != "current_password_required" {
		t.Fatalf("missing password = %v", err)
	}
	if _, err = save(admin(parent), true, 0, str("wrong")); mfaHandlerErrorCode(err) != "invalid_credentials" {
		t.Fatalf("wrong password = %v", err)
	}
	view, err = save(admin(parent), true, 0, str("correct horse battery staple"))
	if err != nil || !view.Enabled || !view.Effective || view.Source != "database" || view.Version != 1 || !view.Reauthentication.Password {
		t.Fatalf("password save = %+v, %v", view, err)
	}

	// With MFA enrolled, a fresh session MFA verification is also required.
	mfaHandlerEnroll(t, ctx, server, parent)
	if _, err = save(admin(parent), false, 1, str("correct horse battery staple")); mfaHandlerErrorCode(err) != "mfa_step_up_required" {
		t.Fatalf("stale MFA = %v", err)
	}
	stale, err := server.sessions.CreateWithMFAAuthority(ctx, parent.UserID, authctx.AuthLocalPassword, parent.AppAuthEpoch, time.Now().Add(-6*time.Minute), session.MFAAssuranceLocalTOTP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = save(admin(stale), false, 1, str("correct horse battery staple")); mfaHandlerErrorCode(err) != "mfa_step_up_required" {
		t.Fatalf("six-minute-old MFA = %v", err)
	}
	verified, err := server.sessions.CreateWithMFAAuthority(ctx, parent.UserID, authctx.AuthLocalPassword, parent.AppAuthEpoch, time.Now(), session.MFAAssuranceLocalTOTP)
	if err != nil {
		t.Fatal(err)
	}
	view, err = save(admin(verified), false, 1, str("correct horse battery staple"))
	if err != nil || view.Enabled || view.Effective || view.EndedSessions == nil || *view.EndedSessions != 0 || !view.Reauthentication.Mfa {
		t.Fatalf("MFA save = %+v, %v", view, err)
	}

	// Password guessing through this endpoint shares the five-attempt step-up budget.
	for i := 0; i < 5; i++ {
		_, err = save(admin(verified), true, 2, str("guess"))
	}
	if mfaHandlerErrorCode(err) != "reauthentication_rate_limited" {
		t.Fatalf("sixth guess = %v", err)
	}
}

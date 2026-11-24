package http

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/hostupgrade"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"github.com/tunnexio/tunnex/apps/api/internal/release"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestHostUpgradeRequiresDeploymentAdminNotOrgOwner(t *testing.T) {
	orgOwner := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): "owner"}}
	ctx := authctx.WithPrincipal(context.Background(), orgOwner)
	server := apiServer{}
	if _, err := server.RequestHostUpgrade(ctx, api.RequestHostUpgradeRequestObject{}); err == nil {
		t.Fatal("organization owner requested a deployment-wide host upgrade")
	}
}

func TestHostUpgradePinsServerVerifiedTarget(t *testing.T) {
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request")
	svc := hostupgrade.New(requestPath, filepath.Join(dir, "status"), func(context.Context, uuid.UUID, uuid.UUID, hostupgrade.Target) error { return nil })
	server := apiServer{hostUpgrade: svc, releaseStatus: &release.Status{
		Available: true, Verified: true, SourceSHA: strings.Repeat("a", 40), Version: "v9.9.9", Sequence: 99,
	}}
	admin := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, CPAdmin: true}
	response, err := server.RequestHostUpgrade(authctx.WithPrincipal(context.Background(), admin), api.RequestHostUpgradeRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	accepted, ok := response.(api.RequestHostUpgrade202JSONResponse)
	if !ok || accepted.Body.State != api.HostUpgradeStatusStateRequested || accepted.Body.TargetVersion == nil || *accepted.Body.TargetVersion != "v9.9.9" {
		t.Fatalf("unexpected response: %#v", response)
	}
	body, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"source_sha=" + strings.Repeat("a", 40), "sequence=99", "requested_by=" + admin.UserID.String()} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("server request omitted %q: %s", want, body)
		}
	}
}

func TestHostUpgradeRefusesUnverifiedCatalog(t *testing.T) {
	dir := t.TempDir()
	svc := hostupgrade.New(filepath.Join(dir, "request"), filepath.Join(dir, "status"), func(context.Context, uuid.UUID, uuid.UUID, hostupgrade.Target) error { return nil })
	server := apiServer{hostUpgrade: svc, releaseStatus: &release.Status{Available: true, Verified: false, SourceSHA: strings.Repeat("a", 40), Version: "v9.9.9", Sequence: 99}}
	admin := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, CPAdmin: true}
	if _, err := server.RequestHostUpgrade(authctx.WithPrincipal(context.Background(), admin), api.RequestHostUpgradeRequestObject{}); err == nil {
		t.Fatal("unverified release reached the host runner")
	}
	if _, err := os.Stat(filepath.Join(dir, "request")); !os.IsNotExist(err) {
		t.Fatal("unverified release created a host request")
	}
}

// AA-EN-1 (UPG-1 D2): after a failed upgrade whose new release is already
// installed, release.Compare refuses it as "no newer release is available"
// (Available=false) and RequestHostUpgrade answered 409 upgrade_not_available,
// so the forward fix was command-line only. A server administrator may now
// re-run exactly that release from the dashboard: same sequence AND source SHA,
// only after a failure, never an older release, with the same authorization
// and audit as an upgrade.
func TestHostUpgradeRerunsOnlyTheSameFailedRelease(t *testing.T) {
	sha := strings.Repeat("a", 40)
	installed := &release.Status{Verified: true, Rerunnable: true, SourceSHA: sha, Version: "v9.9.9", Sequence: 99, Reason: "no newer release is available"}
	admin := &authctx.Principal{UserID: uuid.New(), SessionID: "s", EmailVerified: true, CPAdmin: true}
	setup := func(t *testing.T, status string, rel *release.Status) (apiServer, string, *[]hostupgrade.Target) {
		t.Helper()
		dir := t.TempDir()
		if status != "" {
			if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		var audited []hostupgrade.Target
		svc := hostupgrade.New(filepath.Join(dir, "request"), filepath.Join(dir, "status"), func(_ context.Context, _ uuid.UUID, _ uuid.UUID, target hostupgrade.Target) error {
			audited = append(audited, target)
			return nil
		})
		return apiServer{hostUpgrade: svc, releaseStatus: rel}, filepath.Join(dir, "request"), &audited
	}
	failed := func(source, reason string) string {
		return "request_id=12345678-1234-1234-1234-123456789abc\nstate=failed\ntarget_source_sha=" + source +
			"\ntarget_version=v9.9.9\nbackup_dump=\nbackup_manifest=\nreason_code=" + reason + "\nupdated_at=2026-11-24T10:00:00Z\n"
	}
	ctx := authctx.WithPrincipal(context.Background(), admin)

	t.Run("eligible re-run is offered but still needs re-authentication", func(t *testing.T) {
		server, requestPath, audited := setup(t, failed(sha, "health_check_failed"), installed)
		got, err := server.GetHostUpgrade(ctx, api.GetHostUpgradeRequestObject{})
		if err != nil || got.(api.GetHostUpgrade200JSONResponse).Body.RerunAvailable == nil || !*got.(api.GetHostUpgrade200JSONResponse).Body.RerunAvailable {
			t.Fatalf("GET did not offer the re-run: %#v %v", got, err)
		}
		// No session store is wired here: re-authentication cannot be proved.
		if _, err := server.RerunHostUpgrade(ctx, api.RerunHostUpgradeRequestObject{Body: &api.HostUpgradeRerunInput{}}); err == nil {
			t.Fatal("re-run accepted without re-authentication")
		}
		if _, err := os.Stat(requestPath); !os.IsNotExist(err) || len(*audited) != 0 {
			t.Fatal("unauthenticated re-run created or audited a request")
		}
	})
	t.Run("bearer credentials and sessionless principals are refused", func(t *testing.T) {
		server, requestPath, _ := setup(t, failed(sha, "health_check_failed"), installed)
		for _, p := range []*authctx.Principal{
			{UserID: uuid.New(), EmailVerified: true, CPAdmin: true},
			{UserID: uuid.New(), SessionID: "s", EmailVerified: true, CPAdmin: true, AuthMethod: authctx.AuthBearer},
		} {
			_, err := server.RerunHostUpgrade(authctx.WithPrincipal(context.Background(), p), api.RerunHostUpgradeRequestObject{Body: &api.HostUpgradeRerunInput{}})
			if mfaHandlerErrorCode(err) != "human_session_required" {
				t.Fatalf("%+v = %v", p, err)
			}
		}
		if _, err := os.Stat(requestPath); !os.IsNotExist(err) {
			t.Fatal("refused re-run created a host request")
		}
	})

	for _, tc := range []struct {
		name   string
		status string
		rel    *release.Status
		plain  bool // the ordinary upgrade request, not the re-run
		admin  bool
	}{
		{"ordinary upgrade request for the installed release", failed(sha, "health_check_failed"), installed, true, true},
		{"last upgrade succeeded", strings.Replace(failed(sha, ""), "state=failed", "state=healthy", 1), installed, false, true},
		{"no upgrade has run", "", installed, false, true},
		{"failed upgrade was to another source", failed(strings.Repeat("c", 40), "health_check_failed"), installed, false, true},
		{"authority changed: do not re-run", failed(sha, "app_access_authority_changed"), installed, false, true},
		{"catalog is not the installed release", failed(sha, "health_check_failed"), &release.Status{Verified: true, SourceSHA: sha, Version: "v9.9.9", Sequence: 99}, false, true},
		{"catalog unverified", failed(sha, "health_check_failed"), &release.Status{Verified: false, Rerunnable: true, SourceSHA: sha, Version: "v9.9.9", Sequence: 99}, false, true},
		{"organization owner", failed(sha, "health_check_failed"), installed, false, false},
	} {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			server, requestPath, audited := setup(t, tc.status, tc.rel)
			who := admin
			if !tc.admin {
				who = &authctx.Principal{UserID: uuid.New(), SessionID: "s", EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): "owner"}}
			}
			c := authctx.WithPrincipal(context.Background(), who)
			var err error
			if tc.plain {
				_, err = server.RequestHostUpgrade(c, api.RequestHostUpgradeRequestObject{})
			} else {
				_, err = server.RerunHostUpgrade(c, api.RerunHostUpgradeRequestObject{Body: &api.HostUpgradeRerunInput{}})
			}
			want := "rerun_not_available"
			if tc.plain {
				want = "upgrade_not_available"
			} else if !tc.admin {
				want = "cp_admin_required"
			}
			if mfaHandlerErrorCode(err) != want {
				t.Fatalf("refusal = %v, want %s", err, want)
			}
			if _, err := os.Stat(requestPath); !os.IsNotExist(err) {
				t.Fatal("refused re-run created a host request")
			}
			if len(*audited) != 0 {
				t.Fatal("refused re-run was audited as requested")
			}
			if tc.admin {
				got, err := server.GetHostUpgrade(c, api.GetHostUpgradeRequestObject{})
				if err != nil {
					t.Fatal(err)
				}
				if b := got.(api.GetHostUpgrade200JSONResponse).Body; b.RerunAvailable != nil && *b.RerunAvailable && !tc.plain {
					t.Fatal("GET offered a re-run that POST refuses")
				}
			}
		})
	}

	t.Run("a newer release is still requested normally, never as a re-run", func(t *testing.T) {
		server, _, _ := setup(t, failed(sha, "health_check_failed"), &release.Status{Available: true, Verified: true, SourceSHA: strings.Repeat("d", 40), Version: "v10.0.0", Sequence: 100})
		if _, err := server.RerunHostUpgrade(ctx, api.RerunHostUpgradeRequestObject{Body: &api.HostUpgradeRerunInput{}}); mfaHandlerErrorCode(err) != "rerun_not_available" {
			t.Fatal("re-run accepted while a newer release is available")
		}
		if _, err := server.RequestHostUpgrade(ctx, api.RequestHostUpgradeRequestObject{}); err != nil {
			t.Fatalf("newer release refused: %v", err)
		}
	})
}

// The re-run uses SA-UI-1's re-authentication rules with its own password
// budget: a correct password (and fresh MFA when enrolled) is required, and only
// then is the pinned request written and audited as a re-run.
func TestHostUpgradeRerunReauthentication(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	q := sqlc.New(pool)
	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "rerun-admin@app.test", Name: "Server admin"})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := password.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE users SET email_verified_at=now(), password_hash=$2 WHERE id=$1", user.ID, hash); err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	store := session.NewWithClient(rdb, time.Hour, 24*time.Hour)
	parent, err := store.CreateWithAuthority(ctx, user.ID, authctx.AuthLocalPassword, user.AppAuthEpoch)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := crypto.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 40)
	dir := t.TempDir()
	statusFile := "request_id=12345678-1234-1234-1234-123456789abc\nstate=failed\ntarget_source_sha=" + sha +
		"\ntarget_version=v9.9.9\nbackup_dump=\nbackup_manifest=\nreason_code=health_check_failed\nupdated_at=2026-11-24T10:00:00Z\n"
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(statusFile), 0o644); err != nil {
		t.Fatal(err)
	}
	var audited []hostupgrade.Target
	svc := hostupgrade.New(filepath.Join(dir, "request"), filepath.Join(dir, "status"), func(_ context.Context, _ uuid.UUID, _ uuid.UUID, target hostupgrade.Target) error {
		audited = append(audited, target)
		return nil
	})
	server := apiServer{system: q, sessions: store, mfa: mfa.NewService(pool, sealer, nil, nil), hostUpgrade: svc,
		releaseStatus: &release.Status{Verified: true, Rerunnable: true, SourceSHA: sha, Version: "v9.9.9", Sequence: 99}}
	admin := func(p session.Session) context.Context {
		c := mfaHandlerContext(ctx, p)
		principal, _ := authctx.PrincipalFrom(c)
		principal.CPAdmin = true
		return c
	}
	rerun := func(c context.Context, pw *string) error {
		_, err := server.RerunHostUpgrade(c, api.RerunHostUpgradeRequestObject{Body: &api.HostUpgradeRerunInput{CurrentPassword: pw}})
		return err
	}
	str := func(v string) *string { return &v }

	got, err := server.GetHostUpgrade(admin(parent), api.GetHostUpgradeRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	if r := got.(api.GetHostUpgrade200JSONResponse).Body.RerunReauthentication; r == nil || !r.Password || r.Mfa || !r.Available {
		t.Fatalf("GET re-authentication requirements = %+v", r)
	}
	if err = rerun(admin(parent), nil); mfaHandlerErrorCode(err) != "current_password_required" {
		t.Fatalf("missing password = %v", err)
	}
	if err = rerun(admin(parent), str("wrong")); mfaHandlerErrorCode(err) != "invalid_credentials" {
		t.Fatalf("wrong password = %v", err)
	}
	// The failure was charged to the re-run's own budget, not Server Access's.
	if allowed, err := store.ReauthPasswordAllowed(ctx, serverAccessInstallationReauthScope, user.ID); err != nil || !allowed {
		t.Fatal("Server Access budget was charged by a re-run failure")
	}
	mfaHandlerEnroll(t, ctx, server, parent)
	if err = rerun(admin(parent), str("correct horse battery staple")); mfaHandlerErrorCode(err) != "mfa_step_up_required" {
		t.Fatalf("stale MFA = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "request")); !os.IsNotExist(err) || len(audited) != 0 {
		t.Fatal("a refused re-run wrote or audited a request")
	}
	verified, err := store.CreateWithMFAAuthority(ctx, user.ID, authctx.AuthLocalPassword, parent.AppAuthEpoch, time.Now(), session.MFAAssuranceLocalTOTP)
	if err != nil {
		t.Fatal(err)
	}
	if err = rerun(admin(verified), str("correct horse battery staple")); err != nil {
		t.Fatalf("re-authenticated re-run = %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "request"))
	if !strings.Contains(string(body), "source_sha="+sha) || !strings.Contains(string(body), "sequence=99") {
		t.Fatalf("request = %s", body)
	}
	if len(audited) != 1 || !audited[0].Rerun || audited[0].Sequence != 99 {
		t.Fatalf("audit = %+v", audited)
	}
}

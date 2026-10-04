package http

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func mfaHandlerErrorCode(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func mfaHandlerContext(ctx context.Context, parent session.Session) context.Context {
	ctx = authctx.WithPrincipal(ctx, &authctx.Principal{UserID: parent.UserID, SessionID: parent.ID, EmailVerified: true, AuthMethod: parent.AuthMethod})
	return context.WithValue(ctx, requestTransportKey{}, requestTransportState{secure: true, sessionToken: parent.ID})
}

func mfaHandlerFixture(t *testing.T) (context.Context, apiServer, session.Session, *miniredis.Miniredis) {
	t.Helper()
	ctx, pool := testpostgres.New(t)
	q := sqlc.New(pool)
	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "stepup-handler@app.test", Name: "Step-up"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE users SET email_verified_at=now() WHERE id=$1", user.ID); err != nil {
		t.Fatal(err)
	}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
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
	return ctx, apiServer{system: q, sessions: store, mfa: mfa.NewService(pool, sealer, nil, nil)}, parent, mr
}

func mfaEnrollmentCode(t *testing.T, secret string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}
func mfaHandlerEnroll(t *testing.T, ctx context.Context, server apiServer, parent session.Session) []string {
	t.Helper()
	_, secret, err := server.mfa.StartEnrollmentWithAuthority(ctx, parent.UserID, parent.AppAuthEpoch)
	if err != nil {
		t.Fatal(err)
	}
	codes, _, err := server.mfa.ConfirmEnrollmentWithAuthority(ctx, parent.UserID, parent.AppAuthEpoch, mfaEnrollmentCode(t, secret))
	if err != nil {
		t.Fatal(err)
	}
	return codes
}

func TestMFAStepUpRequiresVerifiedNativeCookie(t *testing.T) {
	for _, tc := range []struct {
		name, method, sessionID, cookie string
		verified, ambiguous             bool
	}{
		{"bearer", authctx.AuthBearer, "", "", true, false},
		{"mismatched-cookie", authctx.AuthSSO, "parent", "different", true, false},
		{"ambiguous", authctx.AuthSSO, "parent", "parent", true, true},
		{"unverified", authctx.AuthLocalPassword, "parent", "parent", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{SessionID: tc.sessionID, EmailVerified: tc.verified, AuthMethod: tc.method})
			ctx = context.WithValue(ctx, requestTransportKey{}, requestTransportState{sessionToken: tc.cookie, ambiguousSession: tc.ambiguous})
			if _, err := (apiServer{}).MfaStepUp(ctx, api.MfaStepUpRequestObject{Body: &api.MFAStepUpInput{Code: "123456"}}); err == nil {
				t.Fatal("non-session acquired proof")
			}
		})
	}
}

func TestMFAStepUpKeepsSSOParentAndHonorsEpochLogout(t *testing.T) {
	ctx, server, parent, mr := mfaHandlerFixture(t)
	codes := mfaHandlerEnroll(t, ctx, server, parent)
	native := mfaHandlerContext(ctx, parent)
	mr.FastForward(time.Minute)
	ttl := mr.TTL("sess:" + parent.ID)
	response, err := server.MfaStepUp(native, api.MfaStepUpRequestObject{Body: &api.MFAStepUpInput{Code: codes[0]}})
	if err != nil {
		t.Fatal(err)
	}
	if response.(api.MfaStepUp200JSONResponse).VerifiedAt.IsZero() {
		t.Fatal("missing timestamp")
	}
	got, _, err := server.sessions.GetNoTouch(ctx, parent.ID)
	if err != nil || got.ID != parent.ID || got.AuthMethod != authctx.AuthSSO || got.MFAAssuranceSource != session.MFAAssuranceLocalRecovery || !got.ExpiresAt.Equal(parent.ExpiresAt) {
		t.Fatal("parent replaced or proof lost", err)
	}
	if mr.TTL("sess:"+parent.ID) != ttl {
		t.Fatal("step-up extended parent idle TTL")
	}
	if _, err = server.MfaStepUp(native, api.MfaStepUpRequestObject{Body: &api.MFAStepUpInput{Code: codes[0]}}); mfaHandlerErrorCode(err) != "invalid_code" {
		t.Fatal("recovery replay accepted", err)
	}
	hash := sha256.Sum256([]byte(parent.ID))
	if err = server.system.RecordAppParentLogout(ctx, sqlc.RecordAppParentLogoutParams{ParentHash: hash[:], UserID: parent.UserID, ParentExpiresAt: parent.ExpiresAt}); err != nil {
		t.Fatal(err)
	}
	if _, err = server.MfaStepUp(native, api.MfaStepUpRequestObject{Body: &api.MFAStepUpInput{Code: codes[1]}}); mfaHandlerErrorCode(err) != "mfa_session_invalid" {
		t.Fatal("durable logout ignored", err)
	}
	n, err := server.system.CountUnusedRecoveryCodes(ctx, parent.UserID)
	if err != nil || n != int64(len(codes)-1) {
		t.Fatal("logged-out parent consumed factor", err)
	}
	fresh, err := server.sessions.CreateWithAuthority(ctx, parent.UserID, authctx.AuthSSO, parent.AppAuthEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.system.SetUserPasswordAndBumpAppAuthEpoch(ctx, sqlc.SetUserPasswordAndBumpAppAuthEpochParams{UserID: parent.UserID}); err != nil {
		t.Fatal(err)
	}
	if _, err = server.MfaStepUp(mfaHandlerContext(ctx, fresh), api.MfaStepUpRequestObject{Body: &api.MFAStepUpInput{Code: codes[1]}}); mfaHandlerErrorCode(err) != "mfa_session_invalid" {
		t.Fatal("old SSO epoch promoted", err)
	}
}

func TestMFAStepUpGeneratedRouteCookieOriginAndCSRF(t *testing.T) {
	ctx, server, parent, mr := mfaHandlerFixture(t)
	codes := mfaHandlerEnroll(t, ctx, server, parent)
	router, err := NewRouter(slog.Default(), Deps{System: server.system, Sessions: server.sessions, Mfa: server.mfa, AuthFn: SessionAuth(server.sessions, server.system), TrustedProxies: []string{"192.0.2.1"}})
	if err != nil {
		t.Fatal(err)
	}
	fire := func(cookie, origin, csrf string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "https://console.example/api/v1/auth/mfa/step-up", strings.NewReader(fmt.Sprintf("{\"code\":%q}", codes[0])))
		req.RemoteAddr = "198.51.100.2:1234"
		req.Header.Set("Content-Type", "application/json")
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "__Host-tunnex_session", Value: cookie})
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if csrf != "" {
			req.Header.Set("X-Tunnex-CSRF", csrf)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	for _, tc := range []struct {
		cookie, origin, csrf string
		status               int
	}{
		{"", "https://console.example", "browser", 401},
		{parent.ID, "https://console.example", "", 403},
		{parent.ID, "https://evil.console.example", "browser", 403},
		{parent.ID, "null", "browser", 403},
	} {
		r := fire(tc.cookie, tc.origin, tc.csrf)
		if r.Code != tc.status {
			t.Fatalf("expected %d got %d: %s", tc.status, r.Code, r.Body.String())
		}
	}
	mr.FastForward(time.Minute)
	before := mr.TTL("sess:" + parent.ID)
	r := fire(parent.ID, "https://console.example", "browser")
	if mr.TTL("sess:"+parent.ID) != before {
		t.Fatal("real SessionAuth refreshed parent TTL during step-up")
	}
	if r.Code != 200 {
		t.Fatalf("verified native step-up route failed: %d %s", r.Code, r.Body.String())
	}
	if len(r.Result().Cookies()) != 0 {
		t.Fatal("step-up minted a new login cookie")
	}
	r = fire(parent.ID, "https://console.example", "browser")
	if r.Code != 401 || !strings.Contains(r.Body.String(), "invalid_code") {
		t.Fatal("route accepted replay", r.Code, r.Body.String())
	}
}

type mfaConfirmRedisFailure struct {
	reads int
	fail  func()
}

func (h *mfaConfirmRedisFailure) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *mfaConfirmRedisFailure) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *mfaConfirmRedisFailure) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "eval" && len(cmd.Args()) > 1 && strings.Contains(cmd.Args()[1].(string), "return {value, redis.call('PTTL'") {
			h.reads++
			if h.reads == 3 {
				h.fail()
			}
		}
		return next(ctx, cmd)
	}
}

func TestMFAEnrollmentReturnsRecoveryCodesWhenPromotionStoreFails(t *testing.T) {
	ctx, server, parent, mr := mfaHandlerFixture(t)
	_, secret, err := server.mfa.StartEnrollmentWithAuthority(ctx, parent.UserID, parent.AppAuthEpoch)
	if err != nil {
		t.Fatal(err)
	}
	hook := &mfaConfirmRedisFailure{fail: func() { mr.SetError("unavailable") }}
	server.sessions.Client().AddHook(hook)
	response, err := server.MfaEnrollConfirm(mfaHandlerContext(ctx, parent), api.MfaEnrollConfirmRequestObject{Body: &api.MfaCodeRequest{Code: mfaEnrollmentCode(t, secret)}})
	if err != nil {
		t.Fatal("committed recovery codes lost", err)
	}
	if len(response.(api.MfaEnrollConfirm200JSONResponse).Body.RecoveryCodes) == 0 {
		t.Fatal("recovery codes omitted")
	}
	if hook.reads != 3 {
		t.Fatal("store failure did not run after confirmation", hook.reads)
	}
	mr.SetError("")
	current, _, err := server.sessions.GetNoTouch(ctx, parent.ID)
	if err != nil || !current.MFAVerifiedAt.IsZero() {
		t.Fatal("unverified promotion claimed", err)
	}
	if ok, err := server.mfa.HasConfirmedTOTP(ctx, parent.UserID); err != nil || !ok {
		t.Fatal("confirmed factor lost", err)
	}
}

// This runs through the actual SessionAuth middleware. Successful verification
// may update assurance only; it must not refresh the parent before the handler.
func TestMFAEnrollConfirmGeneratedRoutePreservesParentIdleTTL(t *testing.T) {
	ctx, server, parent, mr := mfaHandlerFixture(t)
	_, secret, err := server.mfa.StartEnrollmentWithAuthority(ctx, parent.UserID, parent.AppAuthEpoch)
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(slog.Default(), Deps{System: server.system, Sessions: server.sessions, Mfa: server.mfa, AuthFn: SessionAuth(server.sessions, server.system), TrustedProxies: []string{"192.0.2.1"}})
	if err != nil {
		t.Fatal(err)
	}
	mr.FastForward(time.Minute)
	before := mr.TTL("sess:" + parent.ID)
	req := httptest.NewRequest("POST", "https://console.example/api/v1/auth/mfa/enroll/confirm", strings.NewReader(fmt.Sprintf("{\"code\":%q}", mfaEnrollmentCode(t, secret))))
	req.RemoteAddr = "198.51.100.2:1234"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://console.example")
	req.Header.Set("X-Tunnex-CSRF", "browser")
	req.AddCookie(&http.Cookie{Name: "__Host-tunnex_session", Value: parent.ID})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("confirmation failed: %d %s", rec.Code, rec.Body.String())
	}
	if mr.TTL("sess:"+parent.ID) != before {
		t.Fatal("confirmation refreshed parent idle TTL before promotion")
	}
	current, _, err := server.sessions.GetNoTouch(ctx, parent.ID)
	if err != nil || current.MFAVerifiedAt.IsZero() || current.MFAAssuranceSource != session.MFAAssuranceLocalTOTP || !current.ExpiresAt.Equal(parent.ExpiresAt) {
		t.Fatal("confirmation proof or absolute lifetime changed", err)
	}
}

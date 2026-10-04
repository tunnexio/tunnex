package appaccess

import (
	"context"
	"crypto/sha256"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"testing"
	"time"
)

func TestParentAuthorityLocalDatabase(t *testing.T) {
	p := grantPool(t)
	for _, v := range []uint{171, 170, 171} {
		if e := db.MigrateTo(p.Config().ConnString(), v); e != nil {
			t.Fatal(e)
		}
	}
	c := context.Background()
	q := sqlc.New(p)
	id := uuid.New()
	old, fresh := "old", "reset"
	if _, e := p.Exec(c, "INSERT INTO users(id,email,name,password_hash)VALUES($1,'epoch@fixture.test','Epoch',$2)", id, old); e != nil {
		t.Fatal(e)
	}
	u, e := q.GetUserByID(c, id)
	if e != nil || u.AppAuthEpoch != 1 {
		t.Fatal(e)
	}
	u, e = q.SetUserPasswordAndBumpAppAuthEpoch(c, sqlc.SetUserPasswordAndBumpAppAuthEpochParams{UserID: id, NewHash: &fresh})
	if e != nil || u.AppAuthEpoch != 2 {
		t.Fatal(e)
	}
	n, e := q.CASUserPasswordRehash(c, sqlc.CASUserPasswordRehashParams{UserID: id, NewHash: &old, ExpectedHash: &old, ExpectedEpoch: 1})
	if e != nil || n != 0 {
		t.Fatal("stale rehash", e)
	}
	if _, e = q.ChangePasswordCASAndBumpAppAuthEpoch(c, sqlc.ChangePasswordCASAndBumpAppAuthEpochParams{UserID: id, NewHash: &old, ExpectedHash: &old, ExpectedEpoch: 1}); e == nil {
		t.Fatal("stale password change")
	}
	hash := sha256.Sum256([]byte("isolated"))
	expiry := time.Now().Add(time.Hour)
	for _, epoch := range []int64{1, 2} {
		n, e = q.CreateMfaChallengeWithAuthority(c, sqlc.CreateMfaChallengeWithAuthorityParams{UserID: id, TokenHash: hash[:], ExpiresAt: expiry, VerifiedEpoch: epoch})
		if e != nil || n != epoch-1 {
			t.Fatal("MFA stale guard", e)
		}
	}
	challenge, e := q.GetMfaChallengeForUpdate(c, hash[:])
	if e != nil || challenge.VerifiedAppAuthEpoch == nil || *challenge.VerifiedAppAuthEpoch != 2 {
		t.Fatal("MFA stamp", e)
	}
	for _, end := range []time.Time{expiry, time.Now().Add(-time.Hour)} {
		if e = q.RecordAppParentLogout(c, sqlc.RecordAppParentLogoutParams{ParentHash: hash[:], UserID: id, ParentExpiresAt: end}); e != nil {
			t.Fatal(e)
		}
	}
	var retained time.Time
	if e = p.QueryRow(c, "SELECT parent_expires_at FROM app_access_parent_logout_tombstones").Scan(&retained); e != nil || retained.Before(expiry.Add(-time.Microsecond)) {
		t.Fatal("expiry shortened", e)
	}
	if _, e = p.Exec(c, "UPDATE app_access_parent_logout_tombstones SET parent_expires_at=now()-interval '1 day'"); e != nil {
		t.Fatal(e)
	}
	denied, e := q.IsAppParentLogoutRevoked(c, hash[:])
	if e != nil || !denied {
		t.Fatal("retained logout resurrected", e)
	}
	if e = db.MigrateTo(p.Config().ConnString(), 170); e == nil {
		t.Fatal("history rollback accepted")
	}
}
func TestParentNoTouchLocalRedis(t *testing.T) {
	_ = grantPool(t) // owned child DB/network guard; Redis target is fixed, never inherited.
	c := context.Background()
	s, e := session.New("redis://redis:6379/0", time.Minute, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Client().Close()
	parent, e := s.CreateWithAuthority(c, uuid.New(), "sso", 3)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Delete(c, parent.ID)
	before, e := s.Client().PTTL(c, "sess:"+parent.ID).Result()
	if e != nil {
		t.Fatal(e)
	}
	got, end, e := s.GetNoTouch(c, parent.ID)
	if e != nil || got.AppAuthEpoch != 3 {
		t.Fatal(e)
	}
	after, e := s.Client().PTTL(c, "sess:"+parent.ID).Result()
	if e != nil || after > before || end.After(time.Now().Add(before)) {
		t.Fatal("TTL extended", e)
	}
	if e = s.Client().Persist(c, "sess:"+parent.ID).Err(); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.GetNoTouch(c, parent.ID); e == nil {
		t.Fatal("nonexpiring accepted")
	}
}

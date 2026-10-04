package session

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestNoTouchAtomicTTLAndAuthority(t *testing.T) {
	s, mr := newTestStore(t, time.Hour, 24*time.Hour)
	ctx := context.Background()
	legacy, e := s.Create(ctx, uuid.New(), "sso")
	if e != nil {
		t.Fatal(e)
	}
	if legacy.AppAuthEpoch != 0 {
		t.Fatal("legacy create acquired authority")
	}
	stamped, e := s.CreateWithAuthority(ctx, uuid.New(), "local_password", 7)
	if e != nil {
		t.Fatal(e)
	}
	mr.FastForward(20 * time.Minute)
	before := mr.TTL(sessKey(stamped.ID))
	got, deadline, e := s.GetNoTouch(ctx, stamped.ID)
	if e != nil || got.AppAuthEpoch != 7 || mr.TTL(sessKey(stamped.ID)) != before {
		t.Fatal("no-touch changed authority/TTL", e)
	}
	if deadline.After(time.Now().Add(before)) || deadline.Before(time.Now().Add(before-time.Second)) {
		t.Fatal("incorrect bounded deadline")
	}
	if _, _, e = s.GetNoTouch(ctx, legacy.ID); e != nil {
		t.Fatal("legacy parent read compatibility", e)
	}
	mr.SetTTL(sessKey(stamped.ID), 0)
	if _, _, e = s.GetNoTouch(ctx, stamped.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("nonexpiring parent accepted", e)
	}
	bytes, _ := json.Marshal(stamped)
	mr.Set(sessKey(stamped.ID), string(bytes))
	mr.SetTTL(sessKey(stamped.ID), time.Minute)
	started := time.Now()
	s.now = func() time.Time { started = started.Add(2 * time.Minute); return started }
	if _, _, e = s.GetNoTouch(ctx, stamped.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("late Redis result extended deadline", e)
	}
	if mr.TTL(sessKey(stamped.ID)) != time.Minute {
		t.Fatal("expired decision mutated parent")
	}
	if _, e = s.CreateWithAuthority(ctx, uuid.New(), "sso", 0); e == nil {
		t.Fatal("zero authority epoch accepted")
	}
}

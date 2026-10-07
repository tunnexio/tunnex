package beam

import (
	"testing"

	"github.com/google/uuid"
)

func TestNativeResumeRequiresOriginalSourceBeforeStateChange(t *testing.T) {
	f := newFixture(t)
	r := f.create()
	paused, err := f.s.Action(f.ctx, f.org, r.ID, f.a, ActionInput{Action: "pause", ExpectedVersion: r.Version})
	if err != nil {
		t.Fatal(err)
	}
	foreign := f.a
	foreign.CredentialID = uuid.New()
	if _, err = f.s.Action(f.ctx, f.org, r.ID, foreign, ActionInput{Action: "resume", ExpectedVersion: paused.Version}); err == nil {
		t.Fatal("another source credential resumed the share")
	}
	unchanged, err := f.s.Get(f.ctx, f.org, r.ID, f.a)
	if err != nil || unchanged.State != "paused" || unchanged.Version != paused.Version || !unchanged.ExpiresAt.Equal(paused.ExpiresAt) {
		t.Fatal("rejected native resume changed the share")
	}
	resumed, err := f.s.Action(f.ctx, f.org, r.ID, f.a, ActionInput{Action: "resume", ExpectedVersion: paused.Version})
	if err != nil || resumed.State != "starting" || resumed.URL != paused.URL || !resumed.ExpiresAt.Equal(paused.ExpiresAt) {
		t.Fatal("original source could not resume with unchanged URL/expiry", err)
	}
	pausedAgain, err := f.s.Action(f.ctx, f.org, r.ID, f.a, ActionInput{Action: "pause", ExpectedVersion: resumed.Version})
	if err != nil {
		t.Fatal(err)
	}
	browser := f.a
	browser.CredentialID = uuid.Nil
	browserResumed, err := f.s.Action(f.ctx, f.org, r.ID, browser, ActionInput{Action: "resume", ExpectedVersion: pausedAgain.Version})
	if err != nil || browserResumed.State != "starting" || !browserResumed.ExpiresAt.Equal(paused.ExpiresAt) {
		t.Fatal("native source guard changed authorized browser management", err)
	}
}

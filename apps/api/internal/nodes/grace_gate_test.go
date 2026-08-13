package nodes

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

// ⛔ THE GATE PROVEN WHERE IT FIRES, NOT WHERE IT WAS WRITTEN. licence's own tests prove the ladder
// computes the right state; this proves the enrolment path ASKS. The two are independent failures and the
// second one is the one that ships an unenforced licence.
func TestEnrolmentGateFollowsTheLadder(t *testing.T) {
	exp := time.Now().Add(-time.Hour)

	if (&Service{}).checkNewPrincipalAllowed() != nil {
		t.Fatal("⛔ an unwired manager refused an enrolment — every open-source deployment just lost the " +
			"ability to enrol a gateway")
	}
	if (&Service{licence: licence.NewTestManager("growth", time.Now().Add(time.Hour))}).checkNewPrincipalAllowed() != nil {
		t.Fatal("a valid licence refused an enrolment")
	}

	err := (&Service{licence: licence.NewTestManager("growth", exp)}).checkNewPrincipalAllowed()
	if err == nil {
		t.Fatal("⛔ AN EXPIRED LICENCE ENROLLED A NEW GATEWAY. Growth is the one thing grace stops")
	}
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("the refusal is not an API error, so the agent sees a 500: %v", err)
	}
	if ae.Status != 403 || ae.Code != "licence_expired" {
		t.Errorf("refusal = %d/%s, want 403/licence_expired", ae.Status, ae.Code)
	}
	// ⭐ The agent operator reads this in a log with no UI around it.
	if !strings.Contains(ae.Message, "keeps working") {
		t.Errorf("the refusal does not say the existing fleet is unaffected: %s", ae.Message)
	}
}

// ⛔ THE REFUSAL SAYS THE TOKEN SURVIVES — AND IT DOES NOW, WHICH IS THE POINT.
//
// This test used to assert the OPPOSITE ("used up — mint a new one"), because the ceiling check ran after
// ConsumeJoinToken and every refusal destroyed the operator's token. That was registered as a known
// asymmetry and then bit twice in one session, so the ordering was fixed rather than documented: peek,
// validate, consume. A refusal the operator can fix must not destroy what they need to retry.
func TestBandRefusalSaysTheTokenSurvives(t *testing.T) {
	msg := (&Service{}).ceilingRefusal(licence.TierTrial, 2, 2)
	for _, want := range []string{"still valid", "keep working", "upgrade the licence"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the band refusal never says %q:\n%s", want, msg)
		}
	}
	// ⛔ AND IT MUST NOT TELL THEM TO MINT A NEW ONE. That instruction was correct while the token burned
	// and is now actively wrong — it would send an operator to replace something that still works.
	if strings.Contains(msg, "used up") || strings.Contains(msg, "mint a new") {
		t.Error("the refusal still claims the token is spent — it is not, since the ceiling check now " +
			"runs BEFORE ConsumeJoinToken")
	}
	// ⚠ The count pluralises separately from the ceiling.
	if one := (&Service{}).ceilingRefusal(licence.TierCommunity, 1, 1); !strings.Contains(one, "1 is already enrolled") {
		t.Errorf("singular count reads wrong:\n%s", one)
	}
}

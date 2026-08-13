package licence

import "testing"

// ⛔ THE TRIAL MUST BE ABLE TO EVALUATE THE THING BEING SOLD (founder-ruled).
//
// A trial that cannot configure Google or Entra cannot test SSO, and SSO is the capability most likely to
// decide an enterprise purchase. The evaluation could not reach the feature the evaluation is for.
//
// ⚠ AND THE GRANT IS BOUNDED, WHICH IS THE HALF THAT IS EASY TO LOSE. SSO LOGIN is deliberately never
// gated — a licence state must never lock a human out of the console where the licence is renewed — so a
// trial that could configure SSO would otherwise buy PERMANENT free SSO for anyone who takes one. That is
// the trial-band law exactly: a temporary grant of a create-time capability is a permanent grant of
// everything created under it.
//
// ⭐ What lapses is ADMISSION (JIT provisioning + domain-capture auto-join, see sso.Service.mayOnboard),
// so the free-forever surface is capped at the humans who already existed during the trial.
func TestTheTrialCanEvaluateSSO(t *testing.T) {
	for _, f := range []Feature{FeatSSO, FeatIdpSync} {
		if !Has(TierTrial, f) {
			t.Errorf("⛔ the trial does not carry %q — an enterprise evaluation cannot test the capability "+
				"it is evaluating, and the trial answers no question", f)
		}
	}

	// ⛔ AND COMMUNITY STILL DOES NOT. The trial is a paid tier's shape with a clock on it; Community is
	// the free forever product, and moving SSO into it would give away the thing the trial exists to sell.
	for _, f := range []Feature{FeatSSO, FeatIdpSync} {
		if Has(TierCommunity, f) {
			t.Errorf("⛔ COMMUNITY NOW CARRIES %q. The trial grant was meant to bound itself by expiring; "+
				"granting it to the free tier removes the expiry along with the boundary.", f)
		}
	}

	// ⚠ MULTI-ORG IS DELIBERATELY NOT IN THE TRIAL, and this states why so nobody "completes the set".
	// Every finite ceiling multiplies by the number of organizations a deployment may create; the trial's
	// org ceiling of 1 is what keeps its 2-gateway band meaning 2. See the gateway-ceiling census.
	if Has(TierTrial, FeatMultiOrg) {
		t.Error("⛔ the trial gained multi_org — its gateway band is enforced per DEPLOYMENT precisely " +
			"because one org cannot be multiplied; granting multi-org to a free tier re-opens that")
	}
}

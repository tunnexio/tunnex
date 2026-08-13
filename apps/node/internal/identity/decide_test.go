package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// certFor mints a self-signed leaf with the given CN and NotAfter — enough for a decision that only reads the
// subject and the validity window. Deliberately NOT a fixture constant: the walk's fixture-fidelity lesson was
// that a fixture which cannot express the failing case cannot catch it, and expiry is the whole subject here.
func certFor(t *testing.T, cn string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notAfter.Add(-48 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	der8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	testKeys[string(certPEM)] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8})
	return certPEM
}

// testKeys remembers the private key certFor minted for each certificate, so `st` can assemble a MATCHING pair.
// The gate now routes on whether cert.pem and key.pem belong to the same identity, so a fixture that cannot
// express a matching pair cannot express the common case either — and one that cannot express a MISMATCHED pair
// cannot catch the defect (fixture-fidelity law).
var testKeys = map[string][]byte{}

// st assembles the complete local set the gate reads. Defaults are the HEALTHY ones — a matching key and a
// parseable anchor — so a test that means to damage one field says so explicitly rather than by omission.
func st(t *testing.T, certPEM []byte, loadErr error) Stored {
	t.Helper()
	return Stored{
		CertPEM: certPEM, CertErr: loadErr,
		KeyPEM: testKeys[string(certPEM)], KeyErr: loadErr,
		CAPEM: anchorPEM(t),
	}
}

// anchorPEM is any parseable certificate: the gate asks whether the anchor PARSES, not what it signed.
func anchorPEM(t *testing.T) []byte {
	t.Helper()
	return certFor(t, "tunnex-agent-ca", time.Now().Add(24*time.Hour))
}

// TestExpiredIdentityRECOVERSInPlace — ASSERTION AMENDED, and the amendment is a capability change rather than a
// correction.
//
// It previously asserted UseToken: an expired certificate must yield to a join token. That was right when written,
// because the token was the ONLY recovery path — proof of possession did not exist. It does now, and it is strictly
// better: re-key returns the SAME node with its id, site binding, devices and metrics series intact, where a token
// enrolment creates a new node and discards all four. So the original ruling is SUPERSEDED BY A NEW CAPABILITY, not
// corrected.
//
// Review finding #2 is why this could not stay as it was: preferring the token whenever one is present meant that on
// the shipped Helm shape — TUNNEX_JOIN_TOKEN injected on every pod start — re-key was NEVER attempted, and the
// enrolment then collided with this node's own expired-but-not-revoked row, returning 409 and exiting the agent into
// CrashLoopBackOff.
func TestExpiredIdentityRECOVERSInPlace(t *testing.T) {
	now := time.Date(2026, 7, 30, 6, 0, 0, 0, time.UTC)
	expired := certFor(t, "aws-gw-1", now.Add(-72*time.Hour))

	v := Decide(st(t, expired, nil), "aws-gw-1", true, now)
	if v.Action != Recover {
		t.Fatalf("an expired identity must attempt RE-KEY first, got action %v (%s). A token enrolment would also "+
			"work and would discard this node's identity, site binding and devices — so it is the fallback, not the "+
			"first choice", v.Action, v.Reason)
	}
	if !v.HaveToken {
		t.Error("the verdict must report that a fallback token exists, so the caller knows it has one")
	}
	if v.Reason != "stored_identity_expired" {
		t.Errorf("reason must name the determination, got %q", v.Reason)
	}
	// The ruling requires the DETERMINATION to be cited, not merely asserted.
	for _, want := range []string{"expired", "NotAfter", "aws-gw-1"} {
		if !strings.Contains(v.Evidence, want) {
			t.Errorf("evidence must cite %q so an operator can verify the determination; got %q", want, v.Evidence)
		}
	}
}

// TestNameMismatchOnAValidCertKEEPSTheIdentity is the case where the literal reading of the ruling would be
// DESTRUCTIVE, and it is drawn from the walk's own incident.
//
// The enrollment command was pasted on the wrong host: azure-gw, holding azure-gw's VALID certificate, with
// TUNNEX_NODE_NAME=aws-gw-1. If a name mismatch authorized using the token, the agent would have abandoned
// azure-gw's identity and enrolled that host as aws-gw-1 — a live gateway made to look dead while a second node
// took its name. That is exactly the S8.2c WF-2 disaster the stored-identity preference exists to prevent.
func TestNameMismatchOnAValidCertKEEPSTheIdentity(t *testing.T) {
	now := time.Date(2026, 7, 30, 6, 0, 0, 0, time.UTC)
	valid := certFor(t, "azure-gw", now.Add(24*time.Hour))

	v := Decide(st(t, valid, nil), "aws-gw-1", true, now)
	if v.Action != UseStored {
		t.Fatalf("a name mismatch on a STILL-VALID certificate must KEEP the stored identity, got %v (%s). "+
			"Discarding it abandons a working gateway on what is almost always operator error", v.Action, v.Reason)
	}
	if !v.NameMismatch {
		t.Error("the mismatch must be reported even though it does not change the action — it is the signal")
	}
	if v.StoredCN != "azure-gw" {
		t.Errorf("StoredCN must be the identity actually kept, got %q", v.StoredCN)
	}
	// WF-S11-11b: the operator must be told which identity is in use, not which was requested.
	if got := EffectiveName(v, "aws-gw-1"); got != "azure-gw" {
		t.Errorf("the effective name must come from the CERTIFICATE when the stored identity is used, got %q — "+
			"reporting the requested name is what hid a wrong-host run on the walk", got)
	}
}

// TestMismatchAndExpiredAttemptsRecovery — the composition. Once the certificate is dead there is nothing left to
// protect, so the mismatch no longer argues for keeping it. (Amended from UseToken to Recover with the rest.)
func TestMismatchAndExpiredAttemptsRecovery(t *testing.T) {
	now := time.Date(2026, 7, 30, 6, 0, 0, 0, time.UTC)
	dead := certFor(t, "azure-gw", now.Add(-1*time.Hour))

	v := Decide(st(t, dead, nil), "aws-gw-1", true, now)
	if v.Action != Recover {
		t.Fatalf("expired beats mismatch: an unusable certificate is not worth protecting, got %v (%s)",
			v.Action, v.Reason)
	}
	if !v.NameMismatch {
		t.Error("the mismatch must still be reported — it remains a real signal about the host")
	}
}

// TestUncertaintyFailsTowardTheStoredIdentity — the ruled condition, stated as a property rather than a case.
// No input that leaves the stored certificate USABLE may result in discarding it.
func TestUncertaintyFailsTowardTheStoredIdentity(t *testing.T) {
	now := time.Date(2026, 7, 30, 6, 0, 0, 0, time.UTC)
	usable := certFor(t, "gw", now.Add(time.Hour))

	for _, tc := range []struct {
		name      string
		requested string
		haveToken bool
	}{
		{"matching name, token present", "gw", true},
		{"matching name, no token", "gw", false},
		{"mismatched name, token present", "other", true},
		{"mismatched name, no token", "other", false},
		{"empty requested name, token present", "", true},
	} {
		if v := Decide(st(t, usable, nil), tc.requested, tc.haveToken, now); v.Action != UseStored {
			t.Errorf("%s: a usable certificate must never be discarded, got %v (%s)", tc.name, v.Action, v.Reason)
		}
	}
}

// TestUnusableWithoutATokenIdlesLOUDLY — the case an operator actually meets first, and the one that used to
// produce a wall of identical TLS warnings with no remedy in them. Idling is correct (liveness stays up); silence
// is not.
func TestUnusableWithoutATokenIdlesLOUDLY(t *testing.T) {
	now := time.Date(2026, 7, 30, 6, 0, 0, 0, time.UTC)

	// AMENDED: an EXPIRED certificate with no token no longer idles — it attempts re-key, which needs no token
	// because the proof is the stored key itself. Only an identity that cannot prove anything idles.
	if v := Decide(st(t, certFor(t, "gw", now.Add(-time.Hour)), nil), "gw", false, now); v.Action != Recover {
		t.Fatalf("expired with no token must still ATTEMPT re-key — proof of possession needs the stored key, not "+
			"a token; got %v (%s)", v.Action, v.Reason)
	}
	// An UNREADABLE identity is the real idle case: nothing to prove possession OF, and no token to fall back on.
	v := Decide(st(t, []byte("garbage"), nil), "gw", false, now)
	if v.Action != Idle {
		t.Fatalf("an unreadable identity with no token must idle; got %v", v.Action)
	}
	// The remedy, not just the condition — the teaching-text convention.
	for _, want := range []string{"re-enrolled", "no join token"} {
		if !strings.Contains(v.Evidence, want) {
			t.Errorf("the idle message must name the REMEDY; missing %q in %q", want, v.Evidence)
		}
	}
}

// TestUnreadableAndAbsentIdentities — the remaining branches, so every path in Decide is reachable from a test.
func TestUnreadableAndAbsentIdentities(t *testing.T) {
	now := time.Date(2026, 7, 30, 6, 0, 0, 0, time.UTC)

	if v := Decide(st(t, nil, errors.New("open: no such file")), "gw", true, now); v.Action != UseToken ||
		v.Reason != "no_stored_identity" {
		t.Errorf("no stored identity + token = enroll; got %v (%s)", v.Action, v.Reason)
	}
	if v := Decide(st(t, nil, errors.New("open: no such file")), "gw", false, now); v.Action != Idle {
		t.Errorf("no stored identity and no token must idle; got %v", v.Action)
	}
	garbage := []byte("-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n")
	if v := Decide(st(t, garbage, nil), "gw", true, now); v.Action != UseToken ||
		v.Reason != "stored_identity_unreadable" {
		t.Errorf("an unparseable certificate + token = enroll; got %v (%s)", v.Action, v.Reason)
	}
	if v := Decide(st(t, garbage, nil), "gw", false, now); v.Action != Idle {
		t.Errorf("an unparseable certificate with no token must idle; got %v", v.Action)
	}
	// Not-a-PEM at all.
	if v := Decide(st(t, []byte("hello"), nil), "gw", true, now); v.Action != UseToken {
		t.Errorf("non-PEM content + token = enroll; got %v (%s)", v.Action, v.Reason)
	}
}

// TestExpiryBoundaryIsExclusive pins the edge. A certificate is usable UP TO NotAfter; the boundary itself must
// not be treated as expired, because a clock a millisecond fast would otherwise re-enroll a live gateway.
func TestExpiryBoundaryIsExclusive(t *testing.T) {
	notAfter := time.Date(2026, 7, 30, 6, 0, 0, 0, time.UTC)
	c := certFor(t, "gw", notAfter)

	if v := Decide(st(t, c, nil), "gw", true, notAfter); v.Action != UseStored {
		t.Errorf("at exactly NotAfter the certificate is still usable, got %v (%s) — a fast clock must not "+
			"re-enroll a live gateway", v.Action, v.Reason)
	}
	if v := Decide(st(t, c, nil), "gw", true, notAfter.Add(time.Nanosecond)); v.Action != Recover {
		t.Errorf("one instant past NotAfter it is expired, got %v (%s)", v.Action, v.Reason)
	}
}

// TestRekeyCannotBeTriggeredByConnectionFAILURE — the condition on the agent's re-key trigger, asserted
// structurally rather than behaviourally, which is the stronger form.
//
// THE FAILURE MODE THIS FORBIDS: an agent that attempts re-key whenever it cannot reach the control plane would
// hammer an UNAUTHENTICATED endpoint during every transient outage — a partition, a CP restart, a DNS blip — turning
// an ordinary incident into a self-inflicted flood, and doing it hardest at the moment the CP is least able to cope.
//
// Decide is structurally incapable of it: it takes a stored certificate, a load error, a requested name, whether a
// token exists, and a clock. THERE IS NO NETWORK ARGUMENT TO PASS. Its verdict comes from the agent's own clock
// against its own stored certificate, so a handshake outcome cannot reach it even by mistake — the same shape as
// RekeyAuthorized on the server having no liveness parameter.
//
// This test's real value is that it must be EDITED before that can change. A future author who adds a
// "lastHandshakeFailed bool" to make the trigger "smarter" stops it compiling and has to come back to the reasoning.
func TestRekeyCannotBeTriggeredByConnectionFAILURE(t *testing.T) {
	// SIGNATURE assertion: exactly these inputs, none of them a network signal.
	//
	// EDITED DELIBERATELY (S13.1 pass-3 fold). The gate widened from `certPEM []byte, loadErr error` to a `Stored`
	// struct so it could route a mismatched pair, an unusable anchor and an unreadable key — states that
	// previously ended in os.Exit(1) or a spent join token. This assertion refused to compile until an author came
	// back to the reasoning, which is what it is for.
	//
	// The property is UNCHANGED and is what must be re-checked at every widening: every field of Stored is a FILE
	// ON THIS HOST, and `now` is this host's clock. No handshake outcome, no status code, no reachability signal
	// can reach the verdict, because none can be passed.
	var decide func(st Stored, requestedName string, haveToken bool, now time.Time) Verdict = Decide
	if decide == nil {
		t.Fatal("unreachable")
	}

	// VERDICT-SET assertion: the only reasons that may authorize a re-key attempt are the two locally-provable
	// expiry verdicts. If a new reason is added, this list must be revisited deliberately — and in particular no
	// reason derived from reachability may appear, because none can be: see the signature above.
	// THE RE-KEYABLE SET. Widened with the pass-3 fold, and every addition states the LOCAL fact it rests on —
	// which is the property this test exists to protect. Each is a determination about files on this disk.
	rekeyable := map[string]bool{
		"stored_identity_expired":           true, // this host's clock is past the stored certificate's NotAfter
		"stored_pair_mismatch":              true, // cert.pem and key.pem are each readable and disagree
		"stored_cert_unusable_key_provable": true, // cert.pem is gone; key.pem — what the CP recorded — is not
	}
	now := time.Now()
	valid := certFor(t, "gw", now.Add(time.Hour))
	expired := certFor(t, "gw", now.Add(-time.Hour))
	other := certFor(t, "other-gw", now.Add(time.Hour))

	mismatchedPair := st(t, valid, nil)
	mismatchedPair.KeyPEM = testKeys[string(other)] // a readable key from a DIFFERENT identity

	noAnchor := st(t, valid, nil)
	noAnchor.CAPEM = nil

	certGone := st(t, nil, errors.New("open cert.pem: no such file"))
	certGone.KeyPEM = testKeys[string(valid)] // the key survived; the certificate did not
	certGone.KeyErr = nil

	cases := []struct {
		name  string
		in    Stored
		req   string
		token bool
	}{
		{"no identity, no token", st(t, nil, errors.New("missing")), "gw", false},
		{"no identity, token", st(t, nil, errors.New("missing")), "gw", true},
		{"unreadable cert, no token", st(t, []byte("garbage"), nil), "gw", false},
		{"unreadable cert, token", st(t, []byte("garbage"), nil), "gw", true},
		{"valid", st(t, valid, nil), "gw", true},
		{"name mismatch", st(t, valid, nil), "other", true},
		{"expired, no token", st(t, expired, nil), "gw", false},
		{"expired, token", st(t, expired, nil), "gw", true},
		{"mismatched pair", mismatchedPair, "gw", true},
		{"unusable anchor", noAnchor, "gw", true},
		{"cert gone, key provable", certGone, "gw", true},
	}

	for _, tc := range cases {
		v := Decide(tc.in, tc.req, tc.token, now)
		if !rekeyable[v.Reason] {
			continue
		}
		// REPRODUCIBILITY, asserted by re-deciding rather than by consulting a second list. A re-keyable verdict
		// must follow from the stored set and the clock ALONE — so deciding twice over identical local inputs must
		// reach an identical verdict. This can fail: a Decide that consulted anything outside its arguments (a
		// package global, an env var, the wall clock directly) would drift between the two calls.
		if again := Decide(tc.in, tc.req, tc.token, now); again.Reason != v.Reason || again.Action != v.Action {
			t.Errorf("%s: verdict %q is treated as re-keyable but is NOT reproducible from local inputs alone "+
				"(re-deciding gave %q/%v); a re-key trigger must rest on a locally-provable fact, never on "+
				"whether the control plane answered", tc.name, v.Reason, again.Reason, again.Action)
		}
	}
	// And the re-keyable verdicts must actually be REACHABLE, or the trigger is dead code and this test vacuous.
	for reason := range rekeyable {
		found := false
		for _, tc := range cases {
			if Decide(tc.in, tc.req, tc.token, now).Reason == reason {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("re-keyable reason %q is not produced by any case in this table — either it is dead code, "+
				"or the table no longer covers the gate", reason)
		}
	}
}

// TestTheGATEIsCOMPLETE — THE structural red for the pass-3 fold, and it tests the question that kept failing.
//
// Five separate defects landed in this gate because each was reasoned about ALONE: an expired certificate routed
// to Recover, and every OTHER damaged state fell through to whatever the table happened to do next — os.Exit(1)
// for a mismatched pair, a spent join token for an unreadable ca.pem, a crash loop for a zero-length anchor.
// Five per-path reds would each have passed while the gate as a whole stayed incomplete.
//
// So this asserts the ROUTING TABLE, not a path: every state the local inputs can be in, and where each must go.
// A new state added without a routing decision fails here, which is the property no per-path red can hold.
func TestTheGATEIsCOMPLETE(t *testing.T) {
	now := time.Now()
	valid := certFor(t, "gw", now.Add(time.Hour))
	expired := certFor(t, "gw", now.Add(-time.Hour))
	other := certFor(t, "other-gw", now.Add(time.Hour))

	mk := func(mut func(*Stored)) Stored {
		x := st(t, valid, nil)
		if mut != nil {
			mut(&x)
		}
		return x
	}

	cases := []struct {
		state string
		in    Stored
		token bool
		want  Action
		why   string
	}{
		{"healthy: valid cert, matching key, parseable anchor", mk(nil), true, UseStored,
			"the common path; a token alongside it is ignored on purpose (WF-2)"},

		{"expired certificate", mk(func(s *Stored) { *s = st(t, expired, nil) }), true, Recover,
			"the case the epic exists for: /agent/renew needs the certificate that expired"},

		{"mismatched pair (interrupted promotion)", mk(func(s *Stored) { s.KeyPEM = testKeys[string(other)] }), true, Recover,
			"pass-1 #11: the new certificate is VALID, so the old gate said UseStored and NewClient exited — a " +
				"crash loop that never reached Recover"},

		{"unreadable key, cert fine", mk(func(s *Stored) { s.KeyPEM, s.KeyErr = nil, errors.New("EIO") }), true, UseToken,
			"nothing local can prove possession, so re-key has no material and the token is the honest remedy"},

		{"unreadable key, cert fine, NO token", mk(func(s *Stored) { s.KeyPEM, s.KeyErr = nil, errors.New("EIO") }), false, Idle,
			"say why and stay up rather than exit"},

		{"cert gone, key survives", mk(func(s *Stored) { s.CertPEM, s.CertErr = nil, errors.New("ENOENT") }), true, Recover,
			"pass-3 #18/#19: the key is what the CP recorded, so the node is still provable by fingerprint — this " +
				"used to spend the token and destroy it"},

		{"zero-length trust anchor", mk(func(s *Stored) { s.CAPEM = []byte{} }), true, Idle,
			"pass-3 #30/32/37/46/52: renewLoop wrote this from a discarded read error and the next boot " +
				"os.Exit(1)'d forever. Idle, NOT UseToken — ca.pem is the same file on every gateway, so " +
				"destroying the node to replace one restorable file is the worse outcome (claim 50)"},

		{"unreadable trust anchor", mk(func(s *Stored) { s.CAPEM, s.CAErr = nil, errors.New("EIO") }), true, Idle,
			"same: nothing can be verified, and nothing may be destroyed for it"},

		{"anchor present but not a certificate", mk(func(s *Stored) { s.CAPEM = []byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----") }), true, Idle,
			"the anchor must PARSE, not merely exist"},

		{"nothing stored at all, token", mk(func(s *Stored) {
			*s = Stored{CertErr: errors.New("ENOENT"), KeyErr: errors.New("ENOENT"), CAErr: errors.New("ENOENT")}
		}), true, UseToken,
			"the bootstrap case: a fresh host has no anchor either, so it must be tested BEFORE the anchor"},

		{"nothing stored at all, no token", mk(func(s *Stored) {
			*s = Stored{CertErr: errors.New("ENOENT"), KeyErr: errors.New("ENOENT"), CAErr: errors.New("ENOENT")}
		}), false, Idle,
			"nothing to do and nothing to destroy"},
	}

	for _, tc := range cases {
		v := Decide(tc.in, "gw", tc.token, now)
		if v.Action != tc.want {
			t.Errorf("STATE %q\n  routed to %v (%s)\n  must route to %v\n  because: %s",
				tc.state, v.Action, v.Reason, tc.want, tc.why)
		}
		if v.Reason == "" || v.Evidence == "" {
			t.Errorf("STATE %q produced Action %v with an empty Reason/Evidence — every verdict must be able to "+
				"say what made it so (the WF-S11-11 determination rule)", tc.state, v.Action)
		}
	}
}

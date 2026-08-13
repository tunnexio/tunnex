// Package identity decides, at agent boot, whether to use the stored gateway identity or enroll with a join
// token (EPIC 13 / S13.1, from EPIC 11 walk finding WF-S11-11).
//
// WHY THIS IS A PACKAGE AND NOT AN `if`. Before this, the choice was an inline branch in main.go: if credentials
// loaded, use them; otherwise enroll. Untestable, and wrong in one case that matters enormously — a stored
// identity whose certificate has EXPIRED. The agent preferred it, discarded a valid join token it had just been
// handed, logged a WARN, and looped forever on `remote error: tls: expired certificate`, because /agent/renew sits
// behind the same client-cert requirement as every other agent route. The operator did exactly what the docs
// prescribe and the product silently ignored them.
//
// The EPIC 11 walk also taught why the decision must be a pure function: a check written as an inline condition
// cannot be red-tested, and a red that cannot fail is worse than none (docs/laws.md, COULD THIS CHECK HAVE
// FAILED?). Every branch below is reachable from a test.
package identity

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"
)

// Action is what the agent should do with the identity it found (or failed to find).
type Action int

const (
	// UseStored — proceed with the stored certificate. The DEFAULT and the safe direction.
	UseStored Action = iota
	// UseToken — enroll fresh with the join token, replacing whatever is stored. Creates a NEW node.
	UseToken
	// Recover — re-key IN PLACE by proving possession of the stored (expired) keypair.
	//
	// RANKED ABOVE UseToken (S13.1, amending WF-S11-11(a)). That earlier ruling chose the token because, when it
	// was made, the token was the ONLY recovery path — proof-of-possession did not exist. It does now, and it is
	// strictly better: re-key returns the SAME node, keeping its id, its site binding, its devices and its metrics
	// series, where a token enrolment creates a new node and discards all four. The original ruling is superseded
	// by a new capability, not corrected.
	Recover
	// Idle — there is no usable identity AND no token. Stay up (liveness) but not ready, and say why.
	Idle
)

// Verdict is the decision plus the evidence for it. Evidence is not decoration: the ruling on WF-S11-11 requires
// that "unusable" be a DETERMINATION rather than an assumption, so the agent must be able to say what made it so.
// An operator reading the log needs to distinguish "your certificate expired three days ago" from "I could not
// parse your certificate" — the causes differ and so do the remedies.
type Verdict struct {
	Action   Action
	Reason   string // short, stable, machine-greppable
	Evidence string // the specific fact behind Reason, for a human
	StoredCN string // the common name of the STORED identity; "" when none/unparseable
	// NameMismatch: the stored certificate names a different node than TUNNEX_NODE_NAME requested (WF-S11-11b).
	// Reported SEPARATELY from Action, because on its own it must never authorize discarding a working identity.
	NameMismatch bool
	// HaveToken records whether a join token is also available, so a caller attempting Recover knows whether it
	// has a fallback. Reported rather than acted on here: this package decides, the caller executes.
	HaveToken bool
}

// Stored is EVERYTHING the gate reads. Every field is LOCAL — a file on this host, or this host's clock, which
// arrives as Decide's `now` argument.
//
// THERE IS NO NETWORK FIELD, AND THERE MUST NEVER BE ONE. An agent that re-keys because it cannot reach the
// control plane would hammer an unauthenticated endpoint during every partition, CP restart and DNS blip —
// hardest at the moment the CP can least cope. The guarantee is structural rather than disciplinary: there is
// nothing to pass. Widening this struct is the edit a future author must make, and must justify.
//
// The per-file errors are SEPARATE on purpose. loadCreds used to collapse three files into one error, so an
// unreadable ca.pem was reported as "no credentials" and spent the join token on a node whose identity was
// perfectly provable (pass-3 claims 16-19, 50). Which file failed changes the verdict, so the verdict must be
// able to see which file failed.
type Stored struct {
	CertPEM, KeyPEM, CAPEM []byte
	CertErr, KeyErr, CAErr error
}

func (st Stored) certUsable() bool { return st.CertErr == nil && len(st.CertPEM) > 0 }
func (st Stored) keyUsable() bool  { return st.KeyErr == nil && len(st.KeyPEM) > 0 }

// anchorUsable — the trust anchor must PARSE, not merely exist. A zero-length ca.pem is the shape renewLoop used
// to write when it discarded a read error (pass-3 claims 30/32/37/46/52), and it reached AppendCertsFromPEM as a
// hard os.Exit(1) on the NEXT boot: a crash loop with no diagnosis, from one transient read.
func (st Stored) anchorUsable() bool {
	if st.CAErr != nil || len(st.CAPEM) == 0 {
		return false
	}
	return x509.NewCertPool().AppendCertsFromPEM(st.CAPEM)
}

// pairMatches asks the SAME question control.NewClient asks, with the same function, so the gate and the client
// can never disagree about whether a credential set is usable. NewClient's disagreement is fatal (os.Exit); the
// gate's is recoverable, and the gate runs first.
func (st Stored) pairMatches() bool {
	_, err := tls.X509KeyPair(st.CertPEM, st.KeyPEM)
	return err == nil
}

// Decide is the whole rule. now is injected so expiry is testable.
//
// THE SAFE DIRECTION IS UseStored, and every uncertain case resolves there. That is not timidity: enrolling
// with a token abandons the stored identity, and abandoning a LIVE gateway's identity makes it appear dead to the
// control plane while a second node takes its name. The S8.2c WF-2 incident (a re-used VM silently keeping its
// old identity and org) is why the stored identity is preferred at all; this function narrows that preference to
// the cases where the stored identity can actually still work.
//
// THE SECOND SAFE DIRECTION, added after the pass-3 triage: where an identity is DAMAGED but still PROVABLE,
// route to Recover rather than to UseToken. Proof of possession repairs the node in place; a token replaces it.
// Three previously-unrouted states are provable — an unreadable certificate beside a readable key, a mismatched
// pair, and a pair the promotion sequence interrupted — and each used to end in os.Exit(1) or a spent token.
func Decide(st Stored, requestedName string, haveToken bool, now time.Time) Verdict {
	// 1. NOTHING STORED. The original bootstrap case: no certificate AND no key. A fresh host has no ca.pem
	//    either, so this must be tested before the anchor.
	if !st.certUsable() && !st.keyUsable() {
		if haveToken {
			return Verdict{Action: UseToken, Reason: "no_stored_identity",
				Evidence: "no credentials in the state directory; enrolling with the join token"}
		}
		return Verdict{Action: Idle, Reason: "no_identity_no_token",
			Evidence: "no credentials in the state directory and TUNNEX_JOIN_TOKEN is unset — " +
				"provide a join token to enroll this gateway"}
	}

	// 2. THE TRUST ANCHOR IS UNUSABLE, but identity material exists.
	//
	//    IDLE, AND DELIBERATELY NOT UseToken. Without an anchor nothing can be verified — not the control plane's
	//    server certificate, and not a re-key response (verifyIssued needs it) — so no path preserves the identity.
	//    But spending the token would DESTROY a node whose only fault is one missing, entirely reconstructible file:
	//    ca.pem is the control plane's agent CA, identical on every gateway. Idling keeps the node recoverable by an
	//    operator who copies one file; enrolling makes that impossible. That is pass-3 claim 50's defect, and the
	//    ruling is to refuse to destroy rather than to proceed.
	if !st.anchorUsable() {
		return Verdict{Action: Idle, Reason: "trust_anchor_unusable", HaveToken: haveToken,
			Evidence: "ca.pem is missing, unreadable or not a certificate, so NOTHING can be verified — not the " +
				"control plane's identity and not a re-key response. This gateway's own certificate and key are " +
				"NOT being discarded: restore ca.pem (it is the control plane's agent CA, the same file on every " +
				"gateway) and restart. Enrolling with a join token would create a NEW node and throw away this " +
				"one's site binding and devices, to fix a missing file"}
	}

	// 3. THE CERTIFICATE IS UNUSABLE BUT THE KEY IS NOT — and the key is what the control plane RECORDED.
	//
	//    Recoverable: re-key identifies by the key's fingerprint, so the certificate is not needed to prove who
	//    this is. This branch used to spend the join token (pass-3 claims 18/19), destroying an identity the
	//    control plane could still prove, because the table read only cert.pem.
	if !st.certUsable() {
		return Verdict{Action: Recover, Reason: "stored_cert_unusable_key_provable", HaveToken: haveToken,
			Evidence: "the stored certificate is missing or unreadable, but key.pem is intact — and the key is " +
				"what the control plane recorded, so this node can still PROVE who it is. Attempting re-key by " +
				"key fingerprint, which recovers it in place"}
	}

	leaf, parseErr := parseLeaf(st.CertPEM)

	// 4. STORED BUT UNPARSEABLE, with no usable key to fall back on.
	if parseErr != nil {
		if haveToken {
			return Verdict{Action: UseToken, Reason: "stored_identity_unreadable",
				Evidence: "stored certificate could not be parsed (" + parseErr.Error() +
					"); enrolling with the join token"}
		}
		return Verdict{Action: Idle, Reason: "stored_identity_unreadable_no_token",
			Evidence: "stored certificate could not be parsed (" + parseErr.Error() +
				") and no join token was supplied — this gateway must be re-enrolled"}
	}

	cn := leaf.Subject.CommonName
	mismatch := requestedName != "" && cn != "" && requestedName != cn
	expired := now.After(leaf.NotAfter)

	// 5. THE KEY IS UNUSABLE WHILE THE CERTIFICATE IS FINE. Nothing local can prove possession, so re-key has no
	//    material to work with and the token is the honest remedy.
	if !st.keyUsable() {
		if haveToken {
			return Verdict{Action: UseToken, Reason: "stored_key_unusable", StoredCN: cn,
				Evidence: "key.pem is missing or unreadable, so possession of this node's recorded key cannot be " +
					"proven and re-key has nothing to offer; enrolling with the join token"}
		}
		return Verdict{Action: Idle, Reason: "stored_key_unusable_no_token", StoredCN: cn,
			Evidence: "key.pem is missing or unreadable and no join token was supplied — re-key needs the private " +
				"key the control plane recorded, so this gateway must be re-enrolled"}
	}

	// 6. THE PAIR DOES NOT MATCH. cert.pem and key.pem are each fine and belong to different identities.
	//
	//    THIS IS THE INTERRUPTED PROMOTION (pass-1 #11, never actually fixed — the fold made the failure testable
	//    and survivable and left the state itself unrouted). saveCreds renames ca.pem, cert.pem, key.pem in turn;
	//    an interruption between the second and third leaves a NEW certificate beside the OLD key. That new
	//    certificate is VALID, so the old gate said UseStored, NewClient's X509KeyPair failed, and the process
	//    exited — into a restart that reproduced the identical state. A permanent crash loop that never once
	//    reached Recover, from an interruption lasting milliseconds.
	//
	//    RECOVER, because it is provable both ways: the pending key from the interrupted re-key is still on disk
	//    (saveCreds removes it only after the final rename), and key.pem still holds whatever the control plane
	//    last recorded. One of the two identities re-key tries will be the one the control plane holds.
	if !st.pairMatches() {
		return Verdict{Action: Recover, Reason: "stored_pair_mismatch", StoredCN: cn,
			NameMismatch: mismatch, HaveToken: haveToken,
			Evidence: "cert.pem and key.pem do not belong to the same identity — the signature of a credential " +
				"write interrupted partway. Re-keying by proof of possession, which repairs it in place. This " +
				"state is NOT a reason to enroll fresh: the material to prove this node is still on disk"}
	}

	// 7. EXPIRED. The case this package exists for. /agent/renew requires the certificate that expired, so no
	//    amount of waiting recovers it.
	//
	//    RECOVER FIRST, token second. The agent still holds the private key the control plane recorded, so proving
	//    possession of it re-keys this node IN PLACE — same id, same site binding, same devices. A token enrolment
	//    would work too and would throw all of that away, so it is the FALLBACK, tried only when re-key fails.
	if expired {
		age := now.Sub(leaf.NotAfter).Round(time.Minute)
		ev := fmt.Sprintf("stored certificate for %q expired %s ago (NotAfter %s)",
			cn, age, leaf.NotAfter.UTC().Format(time.RFC3339))
		fallback := " No join token is available, so re-key is the ONLY route back: if the control plane refuses " +
			"it (this node's key predates key recording, or it was revoked), an operator must mint a join token."
		if haveToken {
			fallback = " A join token is also present and is the FALLBACK — used only if re-key is refused, " +
				"because enrolling with it would create a NEW node and discard this one's site binding and devices."
		}
		return Verdict{Action: Recover, Reason: "stored_identity_expired", StoredCN: cn,
			NameMismatch: mismatch, HaveToken: haveToken,
			Evidence: ev + "; attempting re-key by proof of possession, which recovers this node IN PLACE." + fallback}
	}

	// 8. NAME MISMATCH ON A STILL-VALID CERTIFICATE — loud, but it does NOT authorize re-enrollment.
	//
	//    On the EPIC 11 walk the enrollment command was pasted on the WRONG HOST: azure-gw, carrying azure-gw's
	//    valid identity, with TUNNEX_NODE_NAME=aws-gw-1. Had a mismatch authorized using the token, the agent
	//    would have abandoned azure-gw's identity and enrolled that host as aws-gw-1 — a working gateway made to
	//    look dead, which is exactly the S8.2c WF-2 disaster the stored-identity preference was built to prevent.
	if mismatch {
		return Verdict{Action: UseStored, Reason: "stored_identity_name_mismatch", StoredCN: cn,
			NameMismatch: true,
			Evidence: fmt.Sprintf("stored certificate is for %q but TUNNEX_NODE_NAME requests %q — KEEPING the "+
				"stored identity because its certificate is still valid. If you meant to re-enroll this host as "+
				"%q, wipe the state directory first; if you are on the wrong host, stop this agent",
				cn, requestedName, requestedName)}
	}

	// 9. A valid stored identity that matches, with a matching key and a usable anchor. The common path, and a
	//    token present alongside it is ignored ON PURPOSE — that is the WF-2 protection, still intact.
	return Verdict{Action: UseStored, Reason: "stored_identity_valid", StoredCN: cn,
		Evidence: fmt.Sprintf("stored certificate for %q is valid until %s",
			cn, leaf.NotAfter.UTC().Format(time.RFC3339))}
}

// EffectiveName is the name the agent should present. It comes from the STORED CERTIFICATE whenever one is being
// used (WF-S11-11b): `nodeName` was read from TUNNEX_NODE_NAME and never reconciled with the certificate, so the
// reuse warning reported the name the operator ASKED for rather than the identity actually kept. On the walk that
// printed `node_name: aws-gw-1` while reusing azure-gw's certificate — the diagnostic that exists to reveal which
// identity is in use named the one that was not.
func EffectiveName(v Verdict, requestedName string) string {
	if v.Action == UseStored && v.StoredCN != "" {
		return v.StoredCN
	}
	return requestedName
}

// StoredSerial returns the hex serial of the stored certificate — the identifier the re-key challenge is keyed on
// (S13.1 D9, keyed on the serial rather than the node name because names are guessable and serials are not).
//
// Empty when there is no readable certificate, which is also when re-key is impossible, so callers get one check.
func StoredSerial(certPEM []byte) string {
	leaf, err := parseLeaf(certPEM)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(leaf.SerialNumber.Bytes())
}

func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// NotAfter returns the stored certificate's expiry, or the zero time when it cannot be read. Exported so the
// renewal schedule can anchor to the CERTIFICATE rather than to process start — a ticker from boot lets a restart
// past half-life expire while running (review pass 3 claims 5/12).
func NotAfter(certPEM []byte) time.Time {
	c, err := parseLeaf(certPEM)
	if err != nil {
		return time.Time{}
	}
	return c.NotAfter
}

// Package licence verifies Tunnex licence keys OFFLINE.
//
// ⛔ NO NETWORK CALL, EVER. Air-gapped verification is the product's promise, not a feature of this
// package — it is the reason a sovereignty buyer chooses Tunnex, and it is also why revocation is
// impossible. A verifier that "falls back to an online check" has broken the product, not improved it.
// Enforced by construction: this package imports no network package, and TestPackageMakesNoNetworkCalls
// asserts it.
//
// ⛔ AND NOTHING HERE GATES ANYTHING (S12.2 scope). Verify returns what the key says; no capability
// changes behaviour. Entitlements are S12.1 — mixing them would mean a bug in parsing an unfamiliar
// format becomes a customer locked out of a feature.
package licence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// WireVersion is the payload version this build understands.
const WireVersion = 1

// Prefix marks a Tunnex licence key.
const Prefix = "tnxl_"

// Reason is why a key was refused. Every value is legible to an operator and INERT in this story: the
// deployment behaves identically whichever one is returned.
type Reason string

const (
	// ReasonMalformed: not a tnxl_ key, bad base64, or unparseable JSON.
	ReasonMalformed Reason = "malformed"
	// ReasonUnknownVersion: the payload is newer than this build.
	//
	// ⭐ THE ONE REFUSAL WHOSE REMEDY IS AN UPGRADE, so the message must say so. Best-effort parsing of a
	// shape we are guessing at is how a verifier reads a claim that is not there.
	ReasonUnknownVersion Reason = "unknown_version"
	// ReasonUnknownKid: signed by a key this build does not trust — retired, or foreign.
	ReasonUnknownKid Reason = "unknown_kid"
	// ReasonBadSignature: tampered, or truncated in transit.
	ReasonBadSignature Reason = "bad_signature"
	// ReasonExpired: exp is in the past. ⚠ REPORTED, NOT ENFORCED (S12.1 owns grace and degradation).
	ReasonExpired Reason = "expired"
)

// Claims are what a licence key asserts. Field names and JSON tags MIRROR the signer
// (tunnex-web/src/lib/licence.ts) exactly — they are not a redesign, and the golden vector is what keeps
// them honest across two repos and two languages.
type Claims struct {
	Version int    `json:"v"`
	Kid     string `json:"kid"`
	ID      string `json:"id"`
	// Domain is the eTLD+1 the key is bound to, proven by the trial's email verification. It is the
	// BINDING; there is no company-name field, because a name nobody verified would be gated on.
	Domain string `json:"dom"`
	// Tier is the commercial tier this key grants.
	//
	// ⚠ EMPTY MEANS COMMUNITY, and that is the same ruling as an ABSENT LICENCE — the safe direction. Keys
	// minted before S12.1 carry no tier and are valid; reading them as Community matches exactly what they
	// could do when they were signed, and never grants more than was attested.
	Tier string `json:"tier"`
	// Band is the gateway band: trial | starter | growth | scale. ⚠ `band` IS the spec's gateway_band —
	// the field name predates the wording.
	Band string `json:"band"`
	// Gateways is the ceiling the band buys, RESOLVED AT MINT. nil means unlimited — never a sentinel,
	// which is a ceiling somebody eventually hits. Resolved at mint so a later band-table change cannot
	// silently re-price a key already in a customer's hands.
	Gateways  *int  `json:"gw"`
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

// Expired reports whether the key's expiry is in the past relative to now.
//
// ⚠ SEPARATE FROM Verify ON PURPOSE. A signature is a fact; an expiry is a fact ABOUT A CLOCK, and the
// clock can lie in both directions (see Clock). Callers that care about time ask for it explicitly.
func (c Claims) Expired(now time.Time) bool { return now.Unix() > c.ExpiresAt }

// Result is a verification outcome.
type Result struct {
	OK     bool
	Reason Reason
	Claims Claims
}

// ErrNoKeys is returned when the trusted set is empty — a build error, not a key problem.
var ErrNoKeys = errors.New("licence: no trusted signing keys are compiled into this build")

// Verify checks a wire key against a SET of trusted public keys, selected by kid.
//
// ⛔ AN UNKNOWN kid IS A REFUSAL, NEVER A FALLBACK TO "the only key we have".
//
//	key, ok := keys[claims.Kid]; if !ok { key = anyOf(keys) }   // ⛔ NEVER
//
// That looks like defensive coding and reads like a sensible default. It turns the key SET back into a
// single key while every other test stays green, and it accepts keys signed by a RETIRED — possibly
// compromised — kid. Without refusal, dropping a kid from the set stops nothing, which un-buys the exact
// property D4 was ruled for.
func Verify(keys map[string]ed25519.PublicKey, wire string) (Result, error) {
	if len(keys) == 0 {
		return Result{Reason: ReasonMalformed}, ErrNoKeys
	}
	if !strings.HasPrefix(wire, Prefix) {
		return Result{Reason: ReasonMalformed}, nil
	}
	rest := wire[len(Prefix):]
	dot := strings.IndexByte(rest, '.')
	if dot < 0 {
		return Result{Reason: ReasonMalformed}, nil
	}
	body, sigPart := rest[:dot], rest[dot+1:]

	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Result{Reason: ReasonMalformed}, nil
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Result{Reason: ReasonMalformed}, nil
	}
	// Version BEFORE signature: a payload whose shape we do not understand must not be reported as
	// merely "badly signed", which would send an operator looking for the wrong problem.
	if claims.Version != WireVersion {
		return Result{Reason: ReasonUnknownVersion, Claims: claims}, nil
	}
	key, known := keys[claims.Kid]
	if !known {
		return Result{Reason: ReasonUnknownKid, Claims: claims}, nil
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return Result{Reason: ReasonMalformed}, nil
	}
	// ⛔ THE SIGNATURE COVERS THE PAYLOAD SEGMENT AS TRANSMITTED. Never re-serialise the JSON to check it:
	// Go and JavaScript disagree on key order and number formatting, so a re-encoding verifier would
	// reject keys that are perfectly valid.
	if !ed25519.Verify(key, []byte(body), sig) {
		return Result{Reason: ReasonBadSignature, Claims: claims}, nil
	}
	return Result{OK: true, Claims: claims}, nil
}

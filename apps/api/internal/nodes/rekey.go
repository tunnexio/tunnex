package nodes

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rekey"
)

// challengeTTL bounds a re-key nonce's life. Short because the agent fetches it and immediately signs — minutes,
// not hours — and every second of validity is a second a captured challenge could be replayed against.
const challengeTTL = 2 * time.Minute

// ErrRekeyRefused is the ONE error every re-key failure returns, and the uniformity is the point (D8).
//
// A live node, a nonexistent serial, an expired nonce, a replayed nonce, a malformed CSR and a wrong-key signature
// are all indistinguishable to the caller. Anything finer turns an unauthenticated endpoint into an oracle — for
// whether a serial is known, for whether a gateway is alive, for whether a key guess was close. The specific reason
// goes to the log, where an operator can read it and an attacker cannot.
var ErrRekeyRefused = apierr.New(http.StatusForbidden, "rekey_refused",
	"re-key refused. If this gateway was revoked, recover it with a join token instead.")

// IssueRekeyChallenge mints a single-use nonce for an IDENTIFIER — a certificate serial or a key fingerprint (D10).
//
// IT DOES NOT CHECK THAT THE IDENTIFIER EXISTS. A challenge that succeeded only for known identifiers would be an
// enumeration oracle, and both kinds would then be probeable one request at a time. So the nonce is minted and
// recorded for whatever is asked about; an identifier nobody has fails at SUBMIT, with the same uniform refusal as
// every other failure. Flood protection is the endpoint's rate limit, not this function.
//
// The nonce is bound to the identifier AND ITS KIND, so a challenge taken out under one cannot be spent under the
// other.
func (s *Service) IssueRekeyChallenge(ctx context.Context, ident RekeyIdentifier) ([]byte, error) {
	// The KIND is validated here, not only where the wire is parsed. Found by
	// TestBothIdentifiersRefuseIndistinguishably: an unrecognised kind reached the INSERT and came back as a CHECK
	// constraint violation — a 500, distinguishable at a glance from the 403 every other refusal returns. The
	// handler cannot currently produce one (ParseRekeyIdentifier emits only these two), so this is the second layer;
	// the point of the second layer is that the first one might change.
	switch ident.Kind {
	case IdentifierCertSerial, IdentifierKeyFingerprint:
	default:
		return nil, ErrRekeyRefused
	}
	if ident.Value == "" {
		return nil, ErrRekeyRefused
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// A pointer because migration 0061 leaves `identifier` NULLABLE for one release: SET NOT NULL would break the
	// rolling upgrade (the previous version inserts without it). It is never nil here — the contract migration makes
	// that structural.
	value := ident.Value
	if err := s.q.CreateRekeyChallenge(ctx, sqlc.CreateRekeyChallengeParams{
		Nonce:          nonce,
		Identifier:     &value,
		IdentifierKind: ident.Kind,
		ExpiresAt:      time.Now().Add(challengeTTL),
	}); err != nil {
		return nil, err
	}
	return nonce, nil
}

// resolveRekeyIdentity turns an identifier into exactly one node, or refuses.
//
// THE AMBIGUITY CASE IS THE REASON THIS IS A FUNCTION. cert_key_fingerprint is not unique (migration 0061 states
// why), so the fingerprint lookup can return more than one row — and an identifier that resolves to two nodes is
// ambiguous at exactly the moment it is being TRUSTED. That fails closed, here, with the same refusal as an unknown
// identifier: the caller cannot learn that it hit an ambiguity, and the log records which one it was.
//
// Neither lookup filters revoked rows. A revoked node must be refused by the GONE-GATE — the same stage, the same
// logged reason, whichever identifier named it — because an operator reading "no node holds this key" for a gateway
// they revoked yesterday is being misled by their own tooling.
func (s *Service) resolveRekeyIdentity(ctx context.Context, ident RekeyIdentifier, log *slog.Logger) (sqlc.Node, error) {
	switch ident.Kind {
	case IdentifierCertSerial:
		node, err := s.q.GetNodeByCertSerial(ctx, ident.Value)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				log.Warn("rekey_refused", "reason", "no node holds this certificate serial")
				return sqlc.Node{}, ErrRekeyRefused
			}
			return sqlc.Node{}, err
		}
		return node, nil

	case IdentifierKeyFingerprint:
		v := ident.Value
		rows, err := s.q.GetNodesByCertKeyFingerprint(ctx, &v)
		if err != nil {
			return sqlc.Node{}, err
		}
		switch len(rows) {
		case 0:
			log.Warn("rekey_refused", "reason", "no node holds this key fingerprint")
			return sqlc.Node{}, ErrRekeyRefused
		case 1:
			return rows[0], nil
		default:
			// Two nodes recorded the same public key. Nothing prevents it (a copied state directory plus a second
			// join token), and it is not evidence of an attack — but it makes the claim unresolvable, and guessing
			// which node the caller meant is the one thing this must never do.
			log.Error("rekey_refused",
				"reason", "AMBIGUOUS: more than one node records this public key, so the identifier does not name a node",
				"remedy", "recover this gateway with a join token, and re-key the duplicate so the fleet holds one key per node")
			return sqlc.Node{}, ErrRekeyRefused
		}

	default:
		log.Warn("rekey_refused", "reason", "unknown identifier kind")
		return sqlc.Node{}, ErrRekeyRefused
	}
}

// Rekey issues a fresh certificate for an EXISTING node, authenticated by proof of possession of the keypair the
// control plane already recorded for it (S13.1 D1(c) + D2 + D3 + D9).
//
// THE ORDER OF OPERATIONS IS THE SECURITY DESIGN, not an implementation detail:
//
//  1. CONSUME the nonce — single-use, so a captured request cannot be replayed. Consumed even when the attempt then
//     fails, so a probe cannot retry with the same challenge.
//  2. RESOLVE the node by serial.
//  3. GATE (D3) — BEFORE any cryptographic work. RSA verification is the expensive, timing-visible step; running it
//     before the gate would let response latency reveal whether a node is alive. Expiry authorizes; revocation
//     REFUSES (a proof of possession must never overturn a human decision — see RekeyAuthorized).
//  4. VERIFY the proof against the recorded public key, bound to (nonce ‖ CSR).
//  5. SIGN the new CSR.
//  6. COMMIT the identity change and its audited succession in ONE transaction.
//  7. PUSH — AFTER the commit, never inside it.
//
// WHY THE PUSH IS OUTSIDE THE TRANSACTION. A database transaction must not depend on a network call to a fleet.
// Inside, the transaction's success is hostage to gateway reachability: a slow or partitioned agent holds a write
// lock on the node row, and a failed push rolls back a re-key that already succeeded cryptographically. Outside, the
// CP's record is authoritative the instant it commits and the push is a reconciliation that retries — which is what
// every other desired-state change in this product already does.
//
// THE WINDOW THIS LEAVES, STATED HONESTLY: between commit and push the control plane believes the new key and the
// fleet has not been told. The recovering gateway's own next reconcile closes it for itself; other gateways converge
// on the push, or on their next poll if the push is lost. A lost push is a DELAYED convergence, never a lost one.
func (s *Service) Rekey(ctx context.Context, ident RekeyIdentifier, nonce, csrPEM, signature []byte, agentVersion string) (certPEM, caPEM string, err error) {
	log := slog.With("op", "rekey", "identifier_kind", ident.Kind)

	// (1) Single-use nonce, bound to this identifier AND kind. The UPDATE's own WHERE enforces it, so two concurrent
	//     submits cannot both win.
	value := ident.Value
	if _, e := s.q.ConsumeRekeyChallenge(ctx, sqlc.ConsumeRekeyChallengeParams{
		Nonce: nonce, Identifier: &value, IdentifierKind: ident.Kind,
	}); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			log.Warn("rekey_refused", "reason", "challenge unknown, expired, already used, or bound to another identifier")
			return "", "", ErrRekeyRefused
		}
		return "", "", e
	}

	// (2) Resolve — by either identifier, refusing on ambiguity.
	node, e := s.resolveRekeyIdentity(ctx, ident, log)
	if e != nil {
		return "", "", e
	}
	log = log.With("node_id", node.ID.String(), "org_id", node.OrgID.String())

	// (3) GATE FIRST — before any cryptographic work, so timing cannot become a liveness oracle.
	//
	// The redelivery input is computed here, from a CSR PARSE and a byte comparison. Parsing is not the expensive,
	// timing-visible step the ordering law is about — that is the RSA verification in (4), which still runs after
	// the gate. What this establishes is only "does the CSR carry the key we already have on file"; whether the
	// caller HOLDS that key is settled in (4), so the carve-out cannot authorize anyone who fails the proof.
	// UNDELIVERED, not "proves the current key" — see RekeyAuthorized. Both facts are required: the certificate
	// on record was never used (so this cannot be a live gateway) AND the caller asks for one over the key already
	// recorded (so this is redelivery, never rotation).
	redeliverable := false
	if !node.CertDelivered && ident.Kind == IdentifierKeyFingerprint && node.CertPublicKey != nil {
		if blk, _ := pem.Decode(csrPEM); blk != nil {
			if csr, perr := x509.ParseCertificateRequest(blk.Bytes); perr == nil {
				if spki, merr := x509.MarshalPKIXPublicKey(csr.PublicKey); merr == nil {
					redeliverable = base64.StdEncoding.EncodeToString(spki) == *node.CertPublicKey
				}
			}
		}
	}
	authorized, why := RekeyAuthorized(node.Status, node.CertNotAfter.Time, node.CertNotAfter.Valid, time.Now(), redeliverable)
	if !authorized {
		log.Warn("rekey_refused", "reason", why)
		return "", "", ErrRekeyRefused
	}

	// (4) Proof of possession, bound to this exact CSR and nonce.
	recorded := ""
	if node.CertPublicKey != nil {
		recorded = *node.CertPublicKey
	}
	if e := rekey.Verify(recorded, nonce, csrPEM, signature); e != nil {
		log.Warn("rekey_refused", "reason", e.Error())
		return "", "", ErrRekeyRefused
	}

	// (5) Sign.
	iss, e := s.ca.SignCSR(csrPEM, node.Name)
	if e != nil {
		log.Warn("rekey_refused", "reason", "CSR could not be signed: "+e.Error())
		return "", "", ErrRekeyRefused
	}

	// (6) ONE transaction: the identity change AND its audit row. The audit commits WITH the change — a re-key that
	//     happened must leave a record even if the push never lands.
	oldFP, newFP := keyFingerprint(recorded), keyFingerprint(base64.StdEncoding.EncodeToString(iss.PublicKeySPKI))
	if e := s.withTx(ctx, func(q *sqlc.Queries) error {
		updated, ue := q.RekeyNode(ctx, sqlc.RekeyNodeParams{
			ID:            node.ID,
			CertSerial:    iss.Serial,
			CertPublicKey: spkiText(iss.PublicKeySPKI),
			CertNotAfter:  pgtype.Timestamptz{Time: iss.NotAfter, Valid: true},
			AgentVersion:  agentVersion,
			// The compare-and-swap guard is the row's OWN current serial, read in (2) — not the caller's
			// identifier, which may be a fingerprint. Same protection either way: a concurrent re-key or revoke
			// that moved the row makes this match nothing, and the decision made in (3) is refused rather than
			// applied to a state that no longer holds.
			CertSerial_2: node.CertSerial,
		})
		if ue != nil {
			if errors.Is(ue, pgx.ErrNoRows) {
				// The row moved under us — revoked, or already re-keyed by a concurrent request. Refusing is
				// correct: the decision in (3) was made about a state that no longer holds.
				return ErrRekeyRefused
			}
			return ue
		}
		// A SUCCESSION, not a mutation: one node whose credential changed, with both key fingerprints, so
		// "this gateway was rebuilt on the 4th" is answerable later. actor_system because no human was present —
		// the caller is the gateway itself, proving possession.
		//
		// NOTE for S11-6 (audit-action unification): `node.rekeyed` is added in the EXISTING style deliberately.
		// Inventing a parallel mechanism now would hand that story fifteen helpers to collapse instead of
		// fourteen, with the newest one as the exception.
		return audit(ctx, q, node.OrgID, nil, "node.rekeyed", "node", node.ID.String(), map[string]any{
			"identified_by":       ident.Kind,
			"old_cert_serial":     node.CertSerial,
			"new_cert_serial":     updated.CertSerial,
			"old_key_fingerprint": oldFP,
			"new_key_fingerprint": newFP,
			"authorized_by":       why,
		})
	}); e != nil {
		return "", "", e
	}
	log.Info("node_rekeyed", "new_cert_serial", iss.Serial, "old_key_fingerprint", oldFP,
		"new_key_fingerprint", newFP, "authorized_by", why)

	// (7) AFTER commit — RESTORE THE USERS, then push.
	//
	// WALL 6 (S13.1 D5): revoking a gateway cascades to every device homed on it, so recovery WITHOUT this step
	// hands back a working gateway with ZERO users, each needing a re-issued one-time config — one rebuild becoming
	// a fleet-wide user event, invisible until people call. Only cause='cascade' devices come back; a deliberately
	// revoked laptop is never revived by a gateway rebuild.
	//
	// Outside the transaction for the same reason the push is: it allocates addresses under the org lock and can
	// fail on an exhausted pool, and a re-key that already succeeded cryptographically must not be rolled back by
	// it. A failed restore leaves those devices cascade-revoked and a retry picks them up — delayed, not lost.
	if s.restoreDevices != nil {
		restored, readdressed, rerr := s.restoreDevices(ctx, node.OrgID, node.ID)
		switch {
		case rerr != nil:
			log.Error("device_restore_after_rekey_failed", "error", rerr.Error(),
				"consequence", "the gateway is recovered but its devices are still cascade-revoked; they are "+
					"restorable and a later retry will pick them up")
		case restored > 0:
			log.Info("devices_restored_after_rekey", "restored", restored, "readdressed", readdressed)
		}
	}
	// The WireGuard public key will change on the agent's next report, so every peer's AllowedIPs and every site
	// link must reconcile — a full sweep, not a field update.
	if s.pushOrg != nil {
		s.pushOrg(ctx, node.OrgID)
	}
	return iss.CertPEM, string(s.ca.CertPEM()), nil
}

// keyFingerprint renders a short, non-reversible id for a recorded public key, for audit and logs. Public keys are
// not secret, so this is for READABILITY rather than protection — a 12-hex prefix is comparable at a glance where a
// 392-character base64 blob is not.
//
// IT IS NOW A PREFIX OF THE IDENTIFIER, and that is a deliberate REDEFINITION (D10). It used to digest the base64
// TEXT; it now digests the SPKI DER, so `old_key_fingerprint` in an audit row is the first 12 hex of the same value
// an agent sends as `key_fingerprint`, and an operator can match the two. The consequence, stated rather than
// discovered: fingerprints in audit rows written BEFORE this change are not comparable with ones written after,
// because they were computed over a different input.
func keyFingerprint(spkiB64 string) string {
	full := KeyFingerprintFromStored(spkiB64)
	if full == "" {
		return "none"
	}
	return full[:12]
}

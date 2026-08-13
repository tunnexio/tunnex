// Package machineauth is the server side of the S10.2 MACHINE credential — a first-class, org-scoped,
// NON-USER org principal for the GitOps operator (and future automation).
//
// It mirrors the cliauth hygiene class (random secret, stored sha256-hashed, keyed fingerprint in audit,
// revoke-severs-on-next-request), with three deliberate differences that make it a MACHINE identity, not a
// user credential:
//   - ORG-scoped, not user-scoped: it carries org_id + a fixed 'operator' role, and NO user_id — a
//     non-human is kept OUT of the identity-binding subject space (S10.2 D4). Audit rows for its
//     lifecycle (mint/revoke, human-initiated) are org-scoped.
//   - a MACHINE prefix `tnxm_` (scanner-matchable, distinct from the CLI's `tnx_`), so the auth path
//     routes it to the machine principal, never the user path.
//   - its OWN use downstream attributes to a SYSTEM actor (actor_system, migration 0027) — see
//     authctx.Principal.AuditActor; a GitOps change never masquerades as a human (D3).
package machineauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// TokenPrefix makes leaked machine credentials pattern-matchable by secret scanners, and distinct from the
// CLI's `tnx_` so the auth path can route without ambiguity.
const TokenPrefix = "tnxm_"

// Service mints/revokes/lists machine credentials.
type Service struct {
	pool   *pgxpool.Pool
	q      *sqlc.Queries
	sealer *crypto.Sealer
}

// NewService builds the machine-credential service.
func NewService(pool *pgxpool.Pool, sealer *crypto.Sealer) *Service {
	return &Service{pool: pool, q: sqlc.New(pool), sealer: sealer}
}

func (s *Service) withTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	if s.pool == nil {
		return fn(s.q)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if err := fn(sqlc.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Credential is the mint result. Token is the raw secret — shown ONCE at mint, empty on List.
type Credential struct {
	ID          uuid.UUID
	Name        string
	Fingerprint string
	Token       string
}

// Mint creates an org-scoped machine credential holding the fixed 'operator' role (D3 — scoped to exactly
// the operator's verbs), and audits the creation as the HUMAN who minted it (org-scoped, fingerprint-only).
// The raw token is returned ONCE and never stored.
func (s *Service) Mint(ctx context.Context, orgID, actor uuid.UUID, name string) (Credential, error) {
	raw, h, err := newSecret(TokenPrefix)
	if err != nil {
		return Credential{}, err
	}
	fp := s.sealer.Fingerprint([]byte(raw))
	var cred Credential
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		row, e := q.CreateMachineCredential(ctx, sqlc.CreateMachineCredentialParams{
			OrgID: orgID, Name: name, Role: rbac.RoleOperator, TokenHash: h, Fingerprint: fp,
		})
		if e != nil {
			return e
		}
		cred = Credential{ID: row.ID, Name: row.Name, Fingerprint: fp, Token: raw}
		// Human-initiated lifecycle audit (org-scoped, fingerprint-only — never the token).
		return audit(ctx, q, orgID, actor, "machine.credential_issued",
			map[string]any{"fingerprint": fp, "name": name, "credential_id": row.ID.String()})
	})
	if err != nil {
		return Credential{}, err
	}
	return cred, nil
}

// Revoke severs a machine credential (org-scoped, idempotent — an unknown/other-org id is indistinguishable
// from an already-revoked one, no leak). Revocation takes effect on the credential's very next request (the
// auth path re-reads the row every time). Audits the revocation as the human who did it.
func (s *Service) Revoke(ctx context.Context, orgID, actor, credID uuid.UUID) (bool, error) {
	var revoked bool
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		n, e := q.RevokeMachineCredential(ctx, sqlc.RevokeMachineCredentialParams{ID: credID, OrgID: orgID})
		if e != nil {
			return e
		}
		revoked = n > 0
		if !revoked {
			return nil // nothing revoked (unknown/other-org/already-revoked) → no audit, no leak
		}
		return audit(ctx, q, orgID, actor, "machine.credential_revoked",
			map[string]any{"credential_id": credID.String()})
	})
	return revoked, err
}

// List returns the org's ACTIVE machine credentials — metadata only (fingerprint, never the secret),
// each carrying its owner's email resolved from `users` (D22).
func (s *Service) List(ctx context.Context, orgID uuid.UUID) ([]sqlc.ListMachineCredentialsForOrgRow, error) {
	return s.q.ListMachineCredentialsForOrg(ctx, orgID)
}

// OwnerEligible reports whether a user may be NAMED as a machine credential's accountable owner.
//
// ⛔ D21 RULED NO FOR UNVERIFIED ACCOUNTS, and this read exists ONLY so the refusal can say which
// precondition failed. The refusal itself is in the UPDATE statement, which cannot be raced by a
// verification revoked between this read and that write.
//
// Returns (false, nil) for an unverified member and (false, ErrNoRows-wrapped) for a non-member — the
// handler collapses the second back into the existing undifferentiated not-found so no membership oracle
// is created.
func (s *Service) OwnerEligible(ctx context.Context, orgID, userID uuid.UUID) (verified bool, isMember bool, err error) {
	v, e := s.q.GetOrgMemberVerification(ctx, sqlc.GetOrgMemberVerificationParams{OrgID: orgID, UserID: userID})
	if errors.Is(e, pgx.ErrNoRows) {
		return false, false, nil
	}
	if e != nil {
		return false, false, e
	}
	return v, true, nil
}

// AssignOwner names the HUMAN a machine credential acts for (S15.1, D14/D19 step 2).
//
// ⛔ THE ADMIN IS CHOOSING, NOT CONFIRMING. There is no `created_by` on this table, so the minting user is not
// recoverable from the row — nothing here derives, suggests or defaults an owner. The statement itself scopes
// the user to the credential's org through `memberships` (users has no org_id), so a cross-org pair updates
// ZERO rows rather than succeeding quietly.
//
// Audited as the HUMAN who assigned, with both the credential and the new owner in the metadata: this is the
// act that decides whose cap the credential spends and whose name rides the delegation link, so an
// unattributed assignment would be the missing-audit-write class in a new place.
func (s *Service) AssignOwner(ctx context.Context, orgID, actor, credID, ownerID uuid.UUID) (bool, error) {
	var assigned bool
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		n, e := q.AssignMachineCredentialOwner(ctx, sqlc.AssignMachineCredentialOwnerParams{
			ID: credID, OrgID: orgID, UserID: pgUUID(ownerID),
		})
		if e != nil {
			return e
		}
		// Zero rows is NOT success. It means the credential is missing/revoked, OR the user is not a live
		// member of this org — deliberately indistinguishable to the caller (no oracle for which).
		assigned = n > 0
		if !assigned {
			return nil
		}
		return audit(ctx, q, orgID, actor, "machine_credential.owner_assigned", map[string]any{
			"credential_id": credID.String(),
			"owner_user_id": ownerID.String(),
		})
	})
	return assigned, err
}

// ---- helpers ----------------------------------------------------------------

func newSecret(prefix string) (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw := prefix + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:], nil
}

func pgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// audit writes an org-scoped, actor-attributed (HUMAN) lifecycle row in the caller's tx.
func audit(ctx context.Context, q *sqlc.Queries, orgID, actor uuid.UUID, action string, meta map[string]any) error {
	b, _ := json.Marshal(meta)
	targetType := "machine_credential"
	targetID, _ := meta["credential_id"].(string)
	_, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       pgUUID(orgID),
		ActorUserID: pgUUID(actor),
		Action:      action, TargetType: &targetType, TargetID: &targetID, Metadata: b,
	})
	return err
}

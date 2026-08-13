package http

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// Machine-credential endpoints (S10.2 Slice 1) — the GitOps operator's org identity. machine:manage is
// OWNER-ONLY (minting a non-human actor that can rewrite access policy is org-delete-grade). The mint is a
// one-time-secret ceremony: the token is returned ONCE and never re-displayed (revoke + re-mint if lost);
// the list + audit carry the keyed fingerprint only.

func (s apiServer) ListMachineCredentials(ctx context.Context, req api.ListMachineCredentialsRequestObject) (api.ListMachineCredentialsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMachineManage); err != nil {
		return nil, err
	}
	rows, err := s.machine.List(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	// ⛔ owner_email IS RESOLVED HERE (D22 ruled), REVERSING THE ORIGINAL CALL RECORDED ABOVE THIS LINE.
	//
	// It used to say: the web already fetches the member roster, so resolving server-side too would be a
	// second source of truth. That reasoning was sound and INCOMPLETE — the roster cannot name an owner who
	// has LEFT THE ORG, and that is exactly the row an accountability screen exists for. A field documented
	// as resolved and never populated is also a trap: it caught the first consumer it ever had.
	//
	// One resolver, and it is this one. The client's roster lookup is REMOVED, not kept alongside.
	out := make([]api.MachineCredential, len(rows))
	for i, c := range rows {
		// ⛔ owner_user_id is NULL for every credential minted before S15.1 — that is the migration's whole
		// subject, and the surface must render it as UNASSIGNED rather than blank. owner_email is resolved,
		// never guessed: there is no created_by, so an absent owner is an absent fact.
		mc := api.MachineCredential{Id: c.ID, Name: c.Name, Fingerprint: c.Fingerprint, CreatedAt: c.CreatedAt, LastUsedAt: timePtr(c.LastUsedAt)}
		if c.UserID.Valid {
			owner := uuid.UUID(c.UserID.Bytes)
			mc.OwnerUserId = &owner
			// ⚠ THE RECORDED IDENTITY, WHICH IS NOT THE SAME AS A CURRENT MEMBER. Resolved by LEFT JOIN on
			// `users`, so it survives the owner leaving the org and being deactivated. The FK is
			// ON DELETE RESTRICT, so an assigned credential cannot outlive its user row.
			mc.OwnerEmail = c.OwnerEmail
		}
		out[i] = mc
	}
	return api.ListMachineCredentials200JSONResponse{Body: out, Headers: api.ListMachineCredentials200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) MintMachineCredential(ctx context.Context, req api.MintMachineCredentialRequestObject) (api.MintMachineCredentialResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMachineManage); err != nil {
		return nil, err
	}
	if req.Body == nil || strings.TrimSpace(req.Body.Name) == "" {
		return nil, apierr.BadRequest("invalid_request", "a name is required — it appears in the audit trail as operator:<name>")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	cred, err := s.machine.Mint(ctx, req.OrgId, p.UserID, strings.TrimSpace(req.Body.Name))
	if err != nil {
		return nil, err
	}
	// The token rides the 201 body ONCE — the response is no-store (router), and no other endpoint re-serves
	// it (List returns the fingerprint only). Loss path: revoke + re-mint.
	return api.MintMachineCredential201JSONResponse{
		Body:    api.MintedMachineCredential{Id: cred.ID, Name: cred.Name, Fingerprint: cred.Fingerprint, Token: cred.Token},
		Headers: api.MintMachineCredential201ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}

func (s apiServer) RevokeMachineCredential(ctx context.Context, req api.RevokeMachineCredentialRequestObject) (api.RevokeMachineCredentialResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMachineManage); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	// Idempotent + org-scoped in the service: an unknown/other-org/already-revoked id is a no-op (204), never
	// a leak. Revocation severs on the credential's very next request (the auth path re-reads the row).
	if _, err := s.machine.Revoke(ctx, req.OrgId, p.UserID, req.CredentialId); err != nil {
		return nil, err
	}
	return api.RevokeMachineCredential204Response{}, nil
}

func timePtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

// AssignMachineCredentialOwner names the human a machine credential acts for (S15.1, D14/D19 step 2).
//
// ⛔ OWNER-GATED (machine:manage), AND THE GATE IS REASONED RATHER THAN INHERITED: assigning an owner decides
// whose per-user device cap the credential spends and whose name appears in the delegation link, so it is at
// least as consequential as minting. A narrower gate would be a hole; a wider one would let a non-owner assign
// accountability to somebody else.
func (s apiServer) AssignMachineCredentialOwner(ctx context.Context, req api.AssignMachineCredentialOwnerRequestObject) (api.AssignMachineCredentialOwnerResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMachineManage); err != nil {
		return nil, err
	}
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.New(401, "unauthenticated", "authentication required")
	}
	if req.Body == nil || req.Body.UserId == uuid.Nil {
		return nil, apierr.BadRequest("user_id_required", "an owner must be named — the system does not know who minted this credential")
	}
	// ⛔ AN UNVERIFIED ACCOUNT CANNOT BE NAMED AS AN ACCOUNTABLE OWNER (D21 ruled).
	//
	// Ownership is an ACCOUNTABILITY CLAIM. `requireVerifiedUser` already gates every org-mutating action,
	// so an unverified account cannot act — and an account that cannot act cannot be held accountable for
	// what a credential does. Nameable-but-unable-to-act is a contradiction this screen would render as fact.
	//
	// ⚠ THE PICKER FILTERS TOO, AND THAT IS NOT THIS. A client-side filter is a PRESENTATION decision; this
	// is an AUTHORIZATION decision, and it is also enforced inside the UPDATE statement, which cannot be
	// raced by a verification revoked between this read and that write. Three layers, one of them
	// authoritative.
	//
	// A non-member falls through to the existing undifferentiated not-found below — no membership oracle.
	verified, isMember, err := s.machine.OwnerEligible(ctx, req.OrgId, req.Body.UserId)
	if err != nil {
		return nil, err
	}
	if isMember && !verified {
		return nil, apierr.New(422, "owner_must_be_verified",
			"that account has not verified its email address, so it cannot be named as the party accountable for this credential")
	}
	assigned, err := s.machine.AssignOwner(ctx, req.OrgId, p.UserID, req.CredentialId, req.Body.UserId)
	if err != nil {
		return nil, err
	}
	if !assigned {
		return nil, apierr.NotFound("machine_credential_or_member_not_found",
			"no such active machine credential, or that user is not an active member of this organization")
	}
	return api.AssignMachineCredentialOwner204Response{}, nil
}

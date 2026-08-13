package http

import (
	"context"
	"errors"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/invites"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// ListMembers GET /api/v1/organizations/{orgId}/members — the org roster
// (incl. deactivated members). Any member may list (PermMemberList).
func (s apiServer) ListMembers(ctx context.Context, req api.ListMembersRequestObject) (api.ListMembersResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMemberList); err != nil {
		return nil, err
	}
	rows, err := s.members.ListMembersWithUser(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.Member, 0, len(rows))
	for _, r := range rows {
		out = append(out, toAPIMember(r))
	}
	return api.ListMembers200JSONResponse{
		Body:    out,
		Headers: api.ListMembers200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func toAPIMember(r sqlc.ListOrgMembersWithUserRow) api.Member {
	// ⛔ WHAT DEACTIVATION WOULD STOP, ON THE ROSTER THAT OFFERS THE BUTTON (D23). A machine credential
	// dies with its owner's deactivation; until this number reached the screen, an operator could not learn
	// that before acting, and a broken GitOps pipeline was never connected back to the offboarding.
	mc := int(r.MachineCredentials)
	return api.Member{
		MachineCredentials: &mc,
		UserId:             r.UserID,
		Email:              openapi_types.Email(r.Email),
		Name:               r.Name,
		Role:               api.MemberRole(r.Role),
		Status:             api.MemberStatus(r.Status),
		EmailVerified:      r.EmailVerified,
		JoinedAt:           r.JoinedAt,
	}
}

// ChangeMemberRole PUT /api/v1/organizations/{orgId}/members/{userId}/role.
// Gated on PermMemberManage; the service applies the RBAC relational rules
// (only an owner manages/creates owners) and the last-owner invariant.
func (s apiServer) ChangeMemberRole(ctx context.Context, req api.ChangeMemberRoleRequestObject) (api.ChangeMemberRoleResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if _, err := authorize(ctx, req.OrgId, rbac.PermMemberManage); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	actorRole, _ := p.RoleIn(req.OrgId)
	if _, err := s.members.ChangeMemberRole(ctx, &p.UserID, actorRole, req.OrgId, req.UserId, string(req.Body.Role)); err != nil {
		return nil, err
	}
	return api.ChangeMemberRole204Response{
		Headers: api.ChangeMemberRole204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// ListInvitations GET /api/v1/organizations/{orgId}/invitations.
//
// ⛔ THE READ THAT MAKES RESEND AND REVOKE REACHABLE. Both are keyed by EMAIL, and nothing served the
// addresses — so an operator could create an invitation and then never see, resend or revoke it. Gated on
// PermMemberInvite, the SAME permission as the three verbs it exists to serve: seeing which addresses are
// outstanding is only actionable to someone who can act on them, so this reuses that permission rather than
// minting a read-only one whose grant table would have to answer "who may see who was invited, but do
// nothing about it".
func (s apiServer) ListInvitations(ctx context.Context, req api.ListInvitationsRequestObject) (api.ListInvitationsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMemberInvite); err != nil {
		return nil, err
	}
	rows, err := s.invites.List(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.Invitation, 0, len(rows))
	for _, r := range rows {
		inv := api.Invitation{
			Id:        r.ID,
			Email:     openapi_types.Email(r.Email),
			Role:      api.InvitationRole(r.Role),
			ExpiresAt: r.ExpiresAt,
			CreatedAt: r.CreatedAt,
		}
		// Timestamps stay NULLABLE end to end rather than being flattened into a status string: EXPIRED is
		// DERIVED from expires_at plus the clock, so a stored status would go stale the moment it was written.
		if r.AcceptedAt.Valid {
			t := r.AcceptedAt.Time
			inv.AcceptedAt = &t
		}
		if r.RevokedAt.Valid {
			t := r.RevokedAt.Time
			inv.RevokedAt = &t
		}
		if r.InvitedByUserID.Valid {
			id := uuid.UUID(r.InvitedByUserID.Bytes)
			inv.InvitedByUserId = &id
		}
		// The inviter can be GONE (ON DELETE SET NULL), and the LEFT JOIN keeps the row rather than
		// dropping it — hiding an outstanding invitation because its sender left is the exact failure
		// this endpoint exists to end.
		if r.InvitedByEmail != "" {
			e := r.InvitedByEmail
			inv.InvitedByEmail = &e
		}
		out = append(out, inv)
	}
	return api.ListInvitations200JSONResponse{
		Body:    out,
		Headers: api.ListInvitations200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// CreateInvitation POST /api/v1/organizations/{orgId}/invitations.
func (s apiServer) CreateInvitation(ctx context.Context, req api.CreateInvitationRequestObject) (api.CreateInvitationResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if _, err := authorize(ctx, req.OrgId, rbac.PermMemberInvite); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	token, err := s.invites.Create(ctx, p.UserID, req.OrgId, string(req.Body.Email), string(req.Body.Role))
	// ⛔ TWO FACTS, BOTH TRUE: the invitation exists and the email did not leave. This used to answer 202
	// "Invitation created." whatever happened to delivery — and invitations are now the ONLY way anyone
	// joins a deployment, so a silently dropped one is a person who never gets in and an operator with no
	// reason to look.
	//
	// ⭐ STILL A 202 WITH THE TOKEN, because the link is valid and the operator can hand it over another
	// way — that is exactly what the copyable accept link is for. What changes is that the message stops
	// claiming a send happened.
	delivered := true
	if errors.Is(err, invites.ErrNotDelivered) {
		delivered, err = false, nil
	}
	if err != nil {
		return nil, err
	}
	msg := "Invitation created."
	if !delivered {
		msg = "Invitation created — BUT THE EMAIL COULD NOT BE SENT. Copy the link below and send it to " +
			"them yourself. Check this deployment's SMTP settings."
	}
	// Return the raw token so the dashboard can show a copyable accept link (the
	// SMTP-less delivery path). Shown once; never retrievable again.
	return api.CreateInvitation202JSONResponse{
		Body:    api.InviteCreated{Message: msg, InviteToken: token, Delivered: &delivered},
		Headers: api.CreateInvitation202ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// AcceptInvitation POST /api/v1/auth/invitations/accept (public).
func (s apiServer) AcceptInvitation(ctx context.Context, req api.AcceptInvitationRequestObject) (api.AcceptInvitationResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	name, pw := "", ""
	if req.Body.Name != nil {
		name = *req.Body.Name
	}
	if req.Body.Password != nil {
		pw = *req.Body.Password
	}
	// No auto-login: the invite link is admin-visible (shown in the dashboard for
	// SMTP-less delivery), so the accept must NOT mint a session — otherwise anyone
	// holding the link could land in an existing invitee's account. The invitee sets
	// their password here (new user) or keeps their existing one, then signs in.
	if _, _, err := s.invites.Accept(ctx, req.Body.Token, name, pw); err != nil {
		return nil, err
	}
	return api.AcceptInvitation200JSONResponse{
		Body:    api.GenericMessage{Message: "Invitation accepted — you can now sign in."},
		Headers: api.AcceptInvitation200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// ResendInvitation POST /api/v1/organizations/{orgId}/invitations/resend.
func (s apiServer) ResendInvitation(ctx context.Context, req api.ResendInvitationRequestObject) (api.ResendInvitationResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if _, err := authorize(ctx, req.OrgId, rbac.PermMemberInvite); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	msg := "Invitation re-sent."
	if err := s.invites.Resend(ctx, p.UserID, req.OrgId, string(req.Body.Email)); err != nil {
		if !errors.Is(err, invites.ErrNotDelivered) {
			return nil, err
		}
		// ⚠ The token WAS re-minted — only the delivery failed. Saying "re-sent" here would be the same
		// lie one endpoint over.
		msg = "The invitation was renewed, but the email could not be sent. Check this deployment's SMTP " +
			"settings, or copy the link from the invitations list and send it yourself."
	}
	return api.ResendInvitation202JSONResponse{
		Body:    api.GenericMessage{Message: msg},
		Headers: api.ResendInvitation202ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// RevokeInvitation POST /api/v1/organizations/{orgId}/invitations/revoke.
func (s apiServer) RevokeInvitation(ctx context.Context, req api.RevokeInvitationRequestObject) (api.RevokeInvitationResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if _, err := authorize(ctx, req.OrgId, rbac.PermMemberInvite); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.invites.Revoke(ctx, p.UserID, req.OrgId, string(req.Body.Email)); err != nil {
		return nil, err
	}
	return api.RevokeInvitation204Response{
		Headers: api.RevokeInvitation204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// DeactivateMember POST /api/v1/organizations/{orgId}/members/{userId}/deactivate.
func (s apiServer) DeactivateMember(ctx context.Context, req api.DeactivateMemberRequestObject) (api.DeactivateMemberResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMemberManage); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.members.DeactivateMember(ctx, p.UserID, req.OrgId, req.UserId); err != nil {
		return nil, err
	}
	return api.DeactivateMember204Response{
		Headers: api.DeactivateMember204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// ReactivateMember POST /api/v1/organizations/{orgId}/members/{userId}/reactivate.
func (s apiServer) ReactivateMember(ctx context.Context, req api.ReactivateMemberRequestObject) (api.ReactivateMemberResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMemberManage); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.members.ReactivateMember(ctx, p.UserID, req.OrgId, req.UserId); err != nil {
		return nil, err
	}
	return api.ReactivateMember204Response{
		Headers: api.ReactivateMember204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

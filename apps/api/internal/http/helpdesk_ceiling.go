package http

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// RBAC-1 Helpdesk ceiling for device actions. A person who holds perm ONLY through the Helpdesk role may not
// act on a device that belongs to someone with an admin-grade role (owner, admin, network admin, AI Agents
// admin, auditor, AI Gateway admin). Another role that grants perm lifts the ceiling.

func helpdeskCeilingRefusal() error {
	return apierr.New(403, "forbidden", rbac.HelpdeskTargetRefusal)
}

// requireHelpdeskDeviceCeiling refuses a Helpdesk-only actor acting on an admin-grade person's device. A
// device with no active owner membership has nobody to protect and passes; the action itself then decides.
func (s apiServer) requireHelpdeskDeviceCeiling(ctx context.Context, orgID, deviceID uuid.UUID, perm rbac.Permission) error {
	p, _ := authctx.PrincipalFrom(ctx)
	if !rbac.HelpdeskCeilingApplies(p.RolesIn(orgID), perm) {
		return nil
	}
	if s.system == nil {
		return helpdeskCeilingRefusal()
	}
	row, err := s.system.GetDeviceOwnerMembershipRoles(ctx, sqlc.GetDeviceOwnerMembershipRolesParams{OrgID: orgID, ID: deviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if rbac.IsAdminGrade(rbac.MembershipRoles(row.Role, row.Roles)) {
		return helpdeskCeilingRefusal()
	}
	return nil
}

// requireHelpdeskNodeCeiling is the gateway-level form (restore and transfer act on every device homed on a
// gateway): a Helpdesk-only actor is refused when ANY device on the gateway belongs to an admin-grade person.
// The whole operation is refused rather than silently skipping those devices.
func (s apiServer) requireHelpdeskNodeCeiling(ctx context.Context, orgID, nodeID uuid.UUID, perm rbac.Permission) error {
	p, _ := authctx.PrincipalFrom(ctx)
	if !rbac.HelpdeskCeilingApplies(p.RolesIn(orgID), perm) {
		return nil
	}
	if s.system == nil {
		return helpdeskCeilingRefusal()
	}
	found, err := s.system.NodeHasDeviceOwnedByRoles(ctx, sqlc.NodeHasDeviceOwnedByRolesParams{OrgID: orgID, NodeID: nodeID, Roles: rbac.AdminGradeRoles()})
	if err != nil {
		return err
	}
	if found {
		return helpdeskCeilingRefusal()
	}
	return nil
}

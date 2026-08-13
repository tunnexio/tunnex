package devices

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// TransferResult reports what a transfer did to ONE device.
type TransferResult struct {
	DeviceID uuid.UUID
	Name     string
	UserID   uuid.UUID
	// NeedsReissue is TRUE when this device's ISSUED CONFIG is now wrong and the user must re-import it.
	//
	// ⛔ THIS IS THE HALF THAT GETS UNDER-SCOPED, AND IT IS THE HALF THAT DECIDES WHETHER THE TRANSFER WORKED.
	// Moving `node_id` is a row edit; a device whose config still names the old gateway's endpoint and public
	// key is moved in the database and broken on the wire. Reporting the row count as the result would tell an
	// operator that thirty devices moved when thirty people are about to lose their connection.
	NeedsReissue bool
	// ReissueCause names WHY, because the two causes have different remedies and the operator can only act on
	// one of them. Empty when NeedsReissue is false.
	ReissueCause string
}

// ErrTransferTargetUnusable is returned when the named destination cannot host the devices.
//
// Same shape and same reasoning as ErrRestoreTargetUnusable: refused rather than silently falling back to the
// source, because devices that are `active` and point at something that will never serve them read healthy on
// every surface and work nowhere.
var ErrTransferTargetUnusable = apierr.New(http.StatusBadRequest, "transfer_target_unusable",
	"the destination must be an active, unrevoked gateway in this organization, and not the gateway being moved from")

// ErrTransferSourceUnknown is returned when the source node is not this org's.
var ErrTransferSourceUnknown = apierr.New(http.StatusNotFound, "not_found", "no such gateway in this organization")

// TransferDevicesToNode moves every LIVE device homed on one gateway to another (S12.12 D1).
//
// ⛔ WHY IT EXISTS: A GATEWAY REVOKE CASCADES, AND THE CASCADE IS PERMANENT. RevokeDevicesForNode sweeps
// every active and pending device in the same transaction as the revoke, and a revoked gateway is never
// active again — so until now the only way to retire a gateway was to disconnect everyone homed to it and
// then restore them onto a replacement, which is a fleet-wide outage with a manual recovery step in the
// middle. The founder met this: he revoked a gateway and his device read `revoked`, which he had not done.
//
// ⭐ TRANSFER-FIRST IS THE RULED ORDER, AND THE REASON IS THE ABANDONED STATE, NOT THE ELEGANCE. Move-then-
// revoke leaves "devices moved, old gateway still running" if the operator closes the tab halfway: harmless
// and resumable. Revoke-then-restore leaves a disconnected fleet and a revoked gateway with no un-revoke —
// an outage the product cannot undo. A multi-step destructive flow is designed around the state it is
// ABANDONED in, not the state it ends in.
//
// WHAT IT DELIBERATELY DOES NOT DO, and both are differences from the restore path next door:
//
//   - IT DOES NOT TOUCH STATUS (D4). Restore resurrects, so it must resolve what each row used to be; these
//     rows are already in a state a human chose. A PENDING device transfers and stays pending — an
//     outstanding approval is about the PERSON, not the gateway, so a move must neither grant it nor discard
//     it.
//   - IT DOES NOT REALLOCATE ADDRESSES. The pool is ORG-scoped (organizations.pool_cidr, uniqueness on
//     (org_id, ip)), so a same-org move cannot collide: the device holds that address before and after.
//     Reallocating would cost every moved user a re-import for a contention that does not exist. This is a
//     measured fact, not an assumption — and it is the one place transfer is CHEAPER than restore, where the
//     original address may genuinely have been taken while the gateway was down.
//
// ⚠ AND IT REPORTS RE-ISSUE PER DEVICE (D7), because the row moving and the config following are different
// events — see TransferResult.NeedsReissue.
func (s *Service) TransferDevicesToNode(ctx context.Context, actor, orgID, sourceNodeID, targetNodeID uuid.UUID) ([]TransferResult, error) {
	if sourceNodeID == targetNodeID {
		return nil, ErrTransferTargetUnusable
	}
	if _, err := s.q.GetNodeForOrg(ctx, sqlc.GetNodeForOrgParams{ID: sourceNodeID, OrgID: orgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTransferSourceUnknown
		}
		return nil, err
	}
	// WHICH GATEWAYS A MANAGED DEVICE CAN FOLLOW ITSELF ONTO. Read BEFORE the transaction because it is a
	// reporting input, not a correctness one: a topology blip must not fail a transfer, and an unknown answer
	// resolves to "assume the config must be re-issued" below — the safe direction, because telling a user to
	// re-import a config that would have healed itself costs them a minute, and the opposite costs them their
	// connection with no signal anywhere.
	selfHoming := map[uuid.UUID]bool{}
	selfHomingKnown := false
	if s.selfHomingNodes != nil {
		if m, err := s.selfHomingNodes(ctx, orgID); err == nil {
			selfHoming, selfHomingKnown = m, true
		} else {
			s.logger.Warn("transfer_self_homing_lookup_failed", slog.String("error", err.Error()),
				slog.String("consequence", "every moved managed device is reported as needing a re-import, "+
					"which is the safe direction but may overstate the work"))
		}
	}

	var out []TransferResult
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		// THE TARGET MUST STILL BE ALIVE AT COMMIT TIME, not merely when the caller decided to transfer —
		// the same finding restore.go carries at #7, and reachable here for the same reason: a revoke landing
		// in this window would otherwise receive devices it is about to cascade. FOR UPDATE, because revoke
		// takes the same row lock: a concurrent revoke either commits first (we see it and refuse) or waits.
		target, terr := q.GetNodeForOrgForUpdate(ctx, sqlc.GetNodeForOrgForUpdateParams{ID: targetNodeID, OrgID: orgID})
		if terr != nil {
			if errors.Is(terr, pgx.ErrNoRows) {
				return ErrTransferTargetUnusable
			}
			return terr
		}
		if target.RevokedAt.Valid || target.Status != "active" {
			return ErrTransferTargetUnusable
		}
		candidates, cerr := q.ListLiveDevicesForNode(ctx, sourceNodeID)
		if cerr != nil {
			return cerr
		}
		// ⛔ ONE AUDIT EVENT, NAMING THE COUNT AND BOTH GATEWAYS (D6). Per-device rows would drown the log on a
		// fleet move, and the question an operator asks afterwards is "what moved", singular.
		//
		// Written BEFORE the result is known and UNCONDITIONALLY, above the zero-candidate return — "an admin
		// transferred a gateway's devices and nothing moved" is exactly the event someone will later need to
		// find, and an audit that only fires when work happened cannot answer "did anyone try?". Same
		// transaction, so a partial failure takes the record with it. (The swallowed-audit law.)
		if aerr := audit(ctx, q, orgID, &actor, "node.devices_transferred", "node", sourceNodeID.String(),
			map[string]any{
				"target_node_id": targetNodeID.String(),
				"devices":        len(candidates),
			}); aerr != nil {
			return aerr
		}
		if len(candidates) == 0 {
			return nil
		}
		for _, c := range candidates {
			moved, merr := q.TransferDeviceToNode(ctx, sqlc.TransferDeviceToNodeParams{
				ID: c.ID, OrgID: orgID, NodeID: targetNodeID,
			})
			if merr != nil {
				return merr
			}
			needs, cause := reissueAfterTransfer(c.ProvisioningMode, targetNodeID, selfHoming, selfHomingKnown)
			out = append(out, TransferResult{
				DeviceID: moved.ID, Name: moved.Name, UserID: moved.UserID,
				NeedsReissue: needs, ReissueCause: cause,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) > 0 {
		reissue := 0
		for _, r := range out {
			if r.NeedsReissue {
				reissue++
			}
		}
		s.logger.Info("devices_transferred_between_gateways",
			slog.Int("moved", len(out)),
			slog.Int("needing_reissue", reissue))
		// BOTH GATEWAYS RECONCILE, not just the destination. The source must DROP these peers — a device that
		// left is still in the old gateway's WireGuard peer set until it is pushed, and a peer that can still
		// hand its key to a gateway it no longer belongs to is the identity-credential binding failing quietly.
		// PushOrgNodes covers the org, which covers both ends with one call and no chance of pushing one half.
		s.PushOrgNodes(ctx, orgID)
	}
	return out, nil
}

// reissueAfterTransfer answers, for ONE moved device, whether its issued config still works — the question
// TransferResult.NeedsReissue carries and the one a row count cannot answer. PURE, so the reds can drive
// every combination without a topology.
//
// STATIC IS ALWAYS A RE-ISSUE. A static export is a FILE. It bakes the gateway's endpoint and public key
// (devices/config.go) and it never polls, so nothing can re-point it — the device now names a gateway that
// will not serve it, and the only remedy is a new profile.
//
// ⛔ MANAGED IS A RE-ISSUE TOO WHENEVER THE DESTINATION IS NOT SELF-HOMING, AND THAT IS THE CASE THIS
// FUNCTION EXISTS FOR. "Managed devices re-home themselves" is true only for hub-set members: NodeDial
// returns derived=false for a node outside the active hub set and the client KEEPS ITS BAKED ENDPOINT
// (activeHubDialFrom). So a managed device transferred onto an ordinary gateway dials the gateway it just
// left. The restore path registered this as a residual because restore was rare and already a re-issue
// event; transfer makes re-homing routine, which is what turns a registered residual into a defect.
//
// ⚠ UNKNOWN RESOLVES TO RE-ISSUE, breaking the usual unknown-is-not-stale rule DELIBERATELY. That rule
// protects a steady-state surface from a permanent false positive on a healthy fleet. This is not a standing
// surface — it is a one-shot report about an act that just happened, where a false negative means a user
// discovers the move by failing to connect and no surface anywhere disagrees.
func reissueAfterTransfer(mode string, targetNodeID uuid.UUID, selfHoming map[uuid.UUID]bool, known bool) (bool, string) {
	if mode == "static" {
		return true, "static_export"
	}
	if !known {
		return true, "destination_self_homing_unknown"
	}
	if !selfHoming[targetNodeID] {
		return true, "destination_not_hub_set_member"
	}
	return false, ""
}

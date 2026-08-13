package devices

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
)

// RestoreResult reports what a cascade restore actually did, per device.
type RestoreResult struct {
	DeviceID uuid.UUID
	Name     string
	// KeptAddress is true when the device got its ORIGINAL address back. False means a fresh one was allocated,
	// which is the case that costs the user a re-import — and the case that must be audited and surfaced distinctly.
	KeptAddress bool
	OldIP       string
	NewIP       string
}

// RestoreCascadeRevokedDevices brings back the devices that were revoked BECAUSE their gateway was (S13.1 D5,
// Wall 6).
//
// WHY THIS EXISTS. Revoking a gateway cascades to every device homed on it, so the documented recovery procedure
// handed back a working gateway with ZERO users, each needing a re-issued one-time config. One rebuild became a
// fleet-wide user event, invisible until people called.
//
// THE RULED SHAPE — reclaim first, allocate second:
//
//   - ATTEMPT THE ORIGINAL ADDRESS. The common case is a gateway rebuilt within minutes with nothing else having
//     taken it, and that case must cost users NOTHING: their existing WireGuard config keeps working, because the
//     interface address it embeds is still theirs.
//   - ALLOCATE A FRESH ONE only when the original is genuinely held. Then the user's config IS stale and must be
//     re-imported, which is why that case alone is marked and audited.
//
// Unconditionally allocating fresh would impose a fleet-wide re-import for a contention that usually did not
// happen; refusing to restore unless the original is free would let whoever took one address decide whether a
// user's device returns.
//
// THE ORACLE IS ASKED, NEVER INFERRED. Whether an address is free is a fact ListActiveDeviceAllocations owns — its
// own comment calls it "the SINGLE definition of live allocation... so there are no two filtered reads to drift
// apart". This reads it once, under the same org advisory lock device-create takes, so allocation and restore
// serialize on one snapshot rather than racing to hand the same address to two devices.
//
// DELIBERATELY REVOKED DEVICES ARE NEVER TOUCHED: the candidate query filters on cause='cascade', and the restore
// statement repeats that predicate so a caller who skipped the filter still cannot revive one.
// TWO CALLERS, AND THE SECOND ONE IS WHY THIS IS REACHABLE AT ALL (S13.1 Slice 7).
//
// The first is re-key: a gateway recovers itself and its devices come back where they were (targetNodeID ==
// sourceNodeID). The second is an OPERATOR, restoring a revoked gateway's devices onto a REPLACEMENT gateway.
//
// The second exists because the first could never fire. Devices are cascade-revoked only by nodes.Revoke, and
// re-key REFUSES a revoked node (D3) — so the only trigger that creates this work put the node into the one state
// that could never reach the code which undoes it. The mechanism was correct and unreachable, which the
// dormant-machinery law names and which the reds could not see: a unit test proves behaviour, never reachability.
//
// actor is the human who asked. nil on the re-key path — no person was present, the gateway proved possession of
// its own key — and set on the operator path, because a human undoing a human's revoke is the whole authorization
// story (D3 refuses to let a proof do it).
func (s *Service) RestoreCascadeRevokedDevices(ctx context.Context, orgID, sourceNodeID, targetNodeID uuid.UUID, actor *uuid.UUID) ([]RestoreResult, error) {
	var out []RestoreResult
	crlDirty := false
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		// The ORG advisory lock, the same one device-create takes, so allocation and restore serialize on one
		// snapshot instead of racing to hand the same free address to two devices.
		if e := q.LockDeviceKey(ctx, orgID.String()); e != nil {
			return e
		}
		// #7 — THE TARGET MUST STILL BE ALIVE AT COMMIT TIME, not merely when the caller decided to restore.
		//
		// The re-key path calls this AFTER its own transaction committed, so the authorization was taken against a
		// state that may since have changed: an operator revoke landing in that window cascaded these very devices,
		// and restoring them re-activated what a human had just deliberately switched off — the device tier
		// contradicting D3 while the node tier obeyed it. FOR UPDATE, because revoke takes the same row lock: a
		// concurrent revoke either commits first (we see it and refuse) or waits behind us.
		target, terr := q.GetNodeForOrgForUpdate(ctx, sqlc.GetNodeForOrgForUpdateParams{ID: targetNodeID, OrgID: orgID})
		if terr != nil {
			if errors.Is(terr, pgx.ErrNoRows) {
				return ErrRestoreTargetUnusable
			}
			return terr
		}
		if target.RevokedAt.Valid || target.Status != "active" {
			return ErrRestoreTargetUnusable
		}
		candidates, err := q.ListCascadeRevokedDevicesForNode(ctx, sourceNodeID)
		if err != nil {
			return err
		}
		// THE OPERATOR ACT IS RECORDED BEFORE ITS RESULT IS KNOWN, and unconditionally.
		//
		// In the SAME transaction as the restores, so a partial failure takes the record with it — and above the
		// zero-candidates early return, because "an admin restored a gateway's devices and nothing came back" is
		// exactly the event someone will later need to find. An audit that only fires when work happened cannot
		// answer "did anyone try?", which is the swallowed-audit law one step earlier.
		if actor != nil {
			if aerr := audit(ctx, q, orgID, actor, "node.devices_restored", "node", sourceNodeID.String(),
				map[string]any{
					"target_node_id": targetNodeID.String(),
					"candidates":     len(candidates),
					"authorized_by": "operator (device:restore) — a human undoing a human's revoke, which is the " +
						"only thing permitted to: proof of possession must never overturn a human decision (D3)",
				}); aerr != nil {
				return aerr
			}
		}
		if len(candidates) == 0 {
			return nil
		}
		org, err := q.GetOrganizationByID(ctx, orgID)
		if err != nil {
			return err
		}
		// #8 — a device whose approval was never granted must not be granted BY A RESTORE. The org's gate decides
		// what an unknown prior status resolves to: with approval ON, unknown becomes `pending` (one operator
		// click) rather than `active` (a silent bypass). Rows written before 0062 are the unknown case.
		approvalOn := org.DeviceApproval == "on"
		// ONE read of the oracle, then tracked locally as we hand addresses out — otherwise two devices in this
		// same loop could both be told the same free address is theirs.
		allocs, err := q.ListActiveDeviceAllocations(ctx, orgID)
		if err != nil {
			return err
		}
		taken := map[string]bool{}
		used := make([]string, 0, len(allocs)+len(candidates))
		for _, a := range allocs {
			if a.AssignedIp != nil {
				taken[*a.AssignedIp] = true
				used = append(used, *a.AssignedIp)
			}
		}

		for _, c := range candidates {
			old := ""
			if c.AssignedIp != nil {
				old = *c.AssignedIp
			}
			ip := old
			kept := true
			// Reclaim only if we recorded an address AND nobody holds it now. An empty `old` means the row predates
			// 0059's stop-destroying-the-address change: unknown, so allocate rather than guess.
			//
			// TWO LOAD-BEARING LAYERS, and neither is vestigial. This check is the first; the partial unique index
			// devices_org_ip_key is the second. Removing this check does NOT silently double-assign — the index
			// raises a constraint violation instead, which a mutation test confirmed (the failure arrived as
			// SQLSTATE 23505, not as this function's assertion). Worth naming: "defence in depth" and "a blind
			// guard I have not noticed yet" look identical until you check which layer caught it.
			// #14 — taken-ness and VALIDITY are different questions, and only the first was being asked. A pool
			// shrink cannot see revoked rows (the orphan guard inspects live allocations), so a remembered address
			// can be outside the org's current pool: reclaiming it hands the user an address nothing routes, and
			// every surface reads clean.
			if old != "" && !ipalloc.InPool(org.PoolCidr, old) {
				old = ""
			}
			if old == "" || taken[old] {
				fresh, aerr := ipalloc.Allocate(org.PoolCidr, used)
				if aerr != nil {
					// Pool exhausted mid-restore: stop rather than restore a partial set with no addresses. The
					// remaining devices stay cascade-revoked and a retry after freeing space picks them up.
					return aerr
				}
				ip, kept = fresh, false
			}
			// #8 — restore to the status the cascade FOUND, never a declared one.
			status := "active"
			switch {
			case c.RevokedPrevStatus != nil && *c.RevokedPrevStatus != "":
				status = *c.RevokedPrevStatus
			case approvalOn:
				status = "pending" // unknown prior status + an approval gate: refuse to grant what nobody granted
			}
			restored, rerr := q.RestoreCascadeRevokedDevice(ctx, sqlc.RestoreCascadeRevokedDeviceParams{
				ID: c.ID, AssignedIp: &ip, NodeID: targetNodeID, Status: status,
			})
			if rerr != nil {
				return rerr
			}
			// #9 — the THIRD PART OF THE ACT. Revoking a node revoked the device, its OpenVPN client certificate
			// and the org CRL; restoring only the device left an `active` row whose credential the data plane still
			// refuses. cause='cascade' only, so an operator's deliberate certificate revocation survives a gateway
			// rebuild. The CRL is rebuilt after commit, by the same shared seam the revoke path uses.
			if restored.Transport == "openvpn" {
				revived, oerr := q.RestoreCascadeRevokedOVPNCertsForDevice(ctx, restored.ID)
				if oerr != nil {
					return oerr
				}
				if len(revived) > 0 {
					crlDirty = true
				}
			}
			taken[ip] = true
			used = append(used, ip)
			out = append(out, RestoreResult{
				DeviceID: restored.ID, Name: restored.Name, KeptAddress: kept, OldIP: old, NewIP: ip,
			})

			// AUDITED DISTINCTLY when the address changed, because the operator's mental model is "my gateway came
			// back" and a changed address is the surprise: that user's config no longer works and must be
			// re-imported. Same row otherwise, so the restore itself is always on the record.
			action := "device.restored"
			meta := map[string]any{"cause": "gateway_recovered", "assigned_ip": ip, "kept_address": kept,
				"restored_to_status": status}
			if targetNodeID != sourceNodeID {
				// RE-HOMED, and it is recorded per device because the consequence is per device: this config now
				// names a different gateway (endpoint and public key), so it must be re-imported even when the
				// address was reclaimed.
				meta["cause"] = "operator_restore"
				meta["previous_node_id"] = sourceNodeID.String()
				meta["node_id"] = targetNodeID.String()
			}
			if !kept {
				action = "device.restored_readdressed"
				meta["previous_assigned_ip"] = old
				meta["consequence"] = "the device's exported profile embeds the OLD address and will not connect " +
					"until re-imported"
				// The device SURFACE carries this too, as of Slice 6: devices.provisioned_ip snapshots the address
				// the config baked, and needs_reexport now compares it for every provisioning mode. No flag is
				// written here — staleness stays DERIVED at read time, so re-addressing cannot leave a stored bit
				// that disagrees with the row. Deliberately: the fork's third condition ("mark stale only in the
				// fallback case") is satisfied by the comparison being true only when the address actually moved.
				//
				// Slice 5 shipped with this as a NAMED interim gap (the audit event was the only signal, and the
				// meta carried a `surface_gap` key saying so). Slice 6 closed it; the key is gone rather than left
				// to age into a false claim.
			}
			if aerr := audit(ctx, q, orgID, actor, action, "device", restored.ID.String(), meta); aerr != nil {
				return aerr
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) > 0 {
		readdressed := 0
		for _, r := range out {
			if !r.KeptAddress {
				readdressed++
			}
		}
		s.logger.Info("devices_restored_after_gateway_recovery",
			slog.Int("restored", len(out)),
			slog.Int("kept_original_address", len(out)-readdressed),
			slog.Int("readdressed_needing_reimport", readdressed))
		s.PushOrgNodes(ctx, orgID)
		// #9 — the CRL is derived from the certificate rows, so reviving certificates without rebuilding it leaves
		// the fleet refusing credentials the control plane now considers valid. After commit, like the push and for
		// the same reason: a transaction must not depend on a network call, and a failed rebuild is a delayed
		// convergence rather than a lost restore.
		if crlDirty && s.rebuildCRL != nil {
			if rerr := s.rebuildCRL(ctx, orgID); rerr != nil {
				s.logger.Error("crl_rebuild_after_restore_failed", slog.String("error", rerr.Error()),
					slog.String("consequence", "restored OpenVPN devices will keep being refused by the gateway "+
						"until the next scheduled CRL rebuild"))
			}
		}
	}
	return out, nil
}

// ErrRestoreTargetUnusable is returned when the named replacement gateway cannot host restored devices.
//
// Distinct from a generic bad-request so the UI can say WHICH half was wrong, and refused rather than silently
// falling back to the source node: restoring onto the revoked gateway would produce devices that are `active` and
// point at something that will never serve them — a state that reads healthy on every surface and works nowhere.
var ErrRestoreTargetUnusable = errors.New("the target gateway must be an active, unrevoked node in this organization")

// ErrRestoreSourceUnknown is returned when the source node is not this org's.
var ErrRestoreSourceUnknown = errors.New("no such gateway in this organization")

// RestoreCascadedDevicesByOperator is THE REACHABLE TRIGGER (S13.1 Slice 7) — the entry point an operator's request
// actually lands on, and the one the reachability red must drive.
//
// It exists because the re-key path could never fire for a REVOKED gateway (D3 refuses it), which is the only way
// devices become cascade-revoked. A human, holding device:restore, names the dead gateway and the live replacement.
//
// VALIDATION IS THE AUTHORIZATION: the source must be this org's, and the target must be this org's AND alive.
// Both are checked here rather than in the handler, so a second caller (a CLI, a future bulk tool) cannot reach the
// restore without them.
func (s *Service) RestoreCascadedDevicesByOperator(ctx context.Context, actor, orgID, sourceNodeID, targetNodeID uuid.UUID) ([]RestoreResult, error) {
	if _, err := s.q.GetNodeForOrg(ctx, sqlc.GetNodeForOrgParams{ID: sourceNodeID, OrgID: orgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRestoreSourceUnknown
		}
		return nil, err
	}
	target, err := s.q.GetNodeForOrg(ctx, sqlc.GetNodeForOrgParams{ID: targetNodeID, OrgID: orgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRestoreTargetUnusable
		}
		return nil, err
	}
	// A revoked target is the failure mode worth naming: the obvious operator mistake is to name the gateway they
	// just revoked, which is the one node that can never serve these devices again.
	if target.RevokedAt.Valid || target.Status != "active" {
		return nil, ErrRestoreTargetUnusable
	}
	return s.RestoreCascadeRevokedDevices(ctx, orgID, sourceNodeID, targetNodeID, &actor)
}

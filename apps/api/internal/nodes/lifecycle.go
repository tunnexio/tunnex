package nodes

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// ErrNodeNotRevoked refuses a delete on a gateway that is still live (S12.12 D2).
//
// ⛔ THE STATUS PREDICATE IS THE WHOLE SAFETY ARGUMENT, so the refusal explains it rather than just saying
// no. Deleting a node CASCADES to its devices, its peer telemetry and its OpenVPN server credential; that
// cascade is harmless only because the revoke refuses while any device is homed there, so a revoked node has
// already had its devices moved. Delete a LIVE one and the cascade is the outage the whole story exists to
// prevent — silently, with no revoked rows left behind to explain it.
var ErrNodeNotRevoked = apierr.New(http.StatusConflict, "node_not_revoked",
	"only a revoked gateway can be deleted. Revoke it first — which will itself require moving any devices "+
		"homed to it.")

// DeleteRevokedNode permanently removes a revoked gateway and the enrolment token that produced it.
func (s *Service) DeleteRevokedNode(ctx context.Context, actor, orgID, nodeID uuid.UUID) error {
	node, err := s.q.GetNodeForOrg(ctx, sqlc.GetNodeForOrgParams{ID: nodeID, OrgID: orgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.NotFound("node_not_found", "no such gateway in this organization")
		}
		return err
	}
	if !node.RevokedAt.Valid {
		return ErrNodeNotRevoked
	}
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		// ⛔ THE AUDIT IS WRITTEN BEFORE THE ROW IS GONE, and it carries the NAME. After the delete there is
		// nothing left to join against, so an audit row holding only a uuid answers "something was deleted"
		// and never "which gateway" — which is the only version of the question anyone asks.
		if aerr := audit(ctx, q, orgID, &actor, "node.deleted", "node", nodeID.String(),
			map[string]any{"name": node.Name, "endpoint": node.Endpoint}); aerr != nil {
			return aerr
		}
		// D2 — THE TOKEN IS CLEANED WITH THE DELETE. `consumed_node_id` is ON DELETE SET NULL, so it would
		// have survived unlinked and still enrolled a gateway. Deliberate cleanup, not the removal of an
		// obstacle: it never blocked anything, and the ruling was made against the opposite premise.
		if _, e := q.DeleteJoinTokensForNode(ctx, pgtype.UUID{Bytes: [16]byte(nodeID), Valid: true}); e != nil {
			return e
		}
		n, e := q.DeleteRevokedNode(ctx, sqlc.DeleteRevokedNodeParams{ID: nodeID, OrgID: orgID})
		if e != nil {
			return e
		}
		if n == 0 {
			// The node was revoked when we read it and is not now — someone else got here first, or it was
			// restored between the two statements. Refuse rather than report a delete that did not happen.
			return ErrNodeNotRevoked
		}
		return nil
	})
}

// ErrNodeNameRequired refuses an empty rename rather than storing one.
var ErrNodeNameRequired = apierr.BadRequest("invalid_request",
	"a gateway needs a name — it is how an operator tells one from another on every screen")

// RenameNode edits a gateway's display name (S12.12 D3).
//
// ⛔ THE NAME IS THE ONE FIELD THAT IS SAFE TO EDIT, and the asymmetry is the finding rather than a
// limitation. Nothing consumes the name structurally: it is a label on a row, so changing it costs nothing
// and breaks nothing. The ENDPOINT is the opposite — peers hold it and every issued device config bakes it —
// and this product has no snapshot of the endpoint a config was issued against, so an endpoint edit would be
// invisible to needs_reexport and every affected user would find out by failing to connect. Shipping it
// without that snapshot would reproduce, one story later, exactly the defect the transfer's re-issue report
// was built to prevent.
//
// ⚠ A REVOKED NODE IS EXCLUDED (the query's predicate). It is terminal and nothing will serve it again;
// renaming one produces a tidier record of something that does not exist.
func (s *Service) RenameNode(ctx context.Context, actor, orgID, nodeID uuid.UUID, name string) (sqlc.Node, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return sqlc.Node{}, ErrNodeNameRequired
	}
	var out sqlc.Node
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		before, e := q.GetNodeForOrg(ctx, sqlc.GetNodeForOrgParams{ID: nodeID, OrgID: orgID})
		if e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return apierr.NotFound("node_not_found", "no such gateway in this organization")
			}
			return e
		}
		updated, e := q.UpdateNodeIdentity(ctx, sqlc.UpdateNodeIdentityParams{
			ID: nodeID, OrgID: orgID, Name: &name,
		})
		if e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				// The row exists (we just read it) but the update matched nothing, so the only predicate that
				// can have excluded it is `revoked_at IS NULL`.
				return apierr.New(http.StatusConflict, "node_revoked",
					"a revoked gateway cannot be renamed — it is terminal and will never serve anything again")
			}
			return e
		}
		out = updated
		// BOTH NAMES, because "renamed" without the old one cannot answer the question an audit log is read
		// for: an operator looking for a gateway they remember by its former name finds nothing.
		return audit(ctx, q, orgID, &actor, "node.renamed", "node", nodeID.String(),
			map[string]any{"from": before.Name, "to": name})
	})
	return out, err
}

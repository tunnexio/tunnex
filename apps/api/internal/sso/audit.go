package sso

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// audit writes an SSO configuration/login audit row in the caller's transaction.
// Metadata is deliberately secret-free; provider credentials are never persisted in an audit event.
func audit(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, actor *uuid.UUID, action, targetType, targetID string, meta map[string]any) error {
	b := []byte("{}")
	if meta != nil {
		b, _ = json.Marshal(meta)
	}
	actorID := pgtype.UUID{}
	if actor != nil {
		actorID = pgtype.UUID{Bytes: [16]byte(*actor), Valid: true}
	}
	_, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       pgtype.UUID{Bytes: [16]byte(orgID), Valid: true},
		ActorUserID: actorID,
		Action:      action,
		TargetType:  &targetType,
		TargetID:    &targetID,
		Metadata:    b,
	})
	return err
}

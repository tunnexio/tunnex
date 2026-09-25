package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"math"
)

// RotatePSK is write-only human input. Never serialize it into logs or audits.
type RotatePSK struct {
	TunnelID uuid.UUID
	PSK      string
}

// RotatePSKs requires an already authorized verified human with ipsec:manage.
// It changes credentials only on disabled, never-delivered or exactly-cleaned
// connections. It neither enables connectivity nor expands licence usage.
func (s *ConnectionStore) RotatePSKs(ctx context.Context, org, actor, id uuid.UUID, revision int64, replacements []RotatePSK, sealer *crypto.Sealer) (Connection, error) {
	return s.rotatePSKs(ctx, org, actor, id, revision, replacements, sealer, SealPSK)
}

func (s *ConnectionStore) rotatePSKs(ctx context.Context, org, actor, id uuid.UUID, revision int64, replacements []RotatePSK, sealer *crypto.Sealer, seal func(*crypto.Sealer, PSKBinding, string) (string, error)) (Connection, error) {
	if org == uuid.Nil || actor == uuid.Nil || id == uuid.Nil || revision <= 0 || revision == math.MaxInt64 || len(replacements) < 1 || len(replacements) > 2 {
		return Connection{}, ErrConnectionInvalid
	}
	if sealer == nil {
		return Connection{}, ErrConnectionUnavailable
	}
	chosen := map[uuid.UUID]string{}
	for _, r := range replacements {
		if r.TunnelID == uuid.Nil || !awsStaticPSK(r.PSK) {
			return Connection{}, ErrConnectionInvalid
		}
		if _, ok := chosen[r.TunnelID]; ok {
			return Connection{}, ErrConnectionInvalid
		}
		chosen[r.TunnelID] = r.PSK
	}
	tx, l, e := s.runtimeLock(ctx, org, id, nil)
	if e != nil {
		return Connection{}, e
	}
	defer tx.Rollback(ctx)
	c := l.connection
	if c.DesiredRevision != revision || c.DesiredIntent != "disabled" || c.FinalizedAt != nil || l.state.cleanup != nil || runtimeRevision(l.state.delivered) != runtimeRevision(l.state.cleaned) {
		return Connection{}, ErrConnectionConflict
	}
	if runtimeRevision(l.state.delivered) > 0 {
		var covered bool
		e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ipsec_retained_guards g JOIN ipsec_runtime_deliveries d ON d.id=g.cleanup_delivery_id WHERE g.connection_id=$1 AND g.org_id=$2 AND d.covers_delivery_revision=$3)`, id, org, *l.state.delivered).Scan(&covered)
		if e != nil {
			return Connection{}, ErrConnectionUnavailable
		}
		if !covered {
			return Connection{}, ErrConnectionConflict
		}
	}
	rows, e := tx.Query(ctx, `SELECT t.id,t.secret_revision,s.sealed_psk FROM ipsec_tunnels t JOIN ipsec_tunnel_secrets s ON s.tunnel_id=t.id AND s.org_id=t.org_id AND s.connection_id=t.connection_id AND s.secret_revision=t.secret_revision WHERE t.connection_id=$1 AND t.org_id=$2 ORDER BY t.slot FOR UPDATE OF t,s`, id, org)
	if e != nil {
		return Connection{}, ErrConnectionUnavailable
	}
	type update struct {
		id       uuid.UUID
		revision int64
		sealed   string
	}
	updates := []update{}
	for rows.Next() {
		var tid uuid.UUID
		var rev int64
		var currentSealed string
		if rows.Scan(&tid, &rev, &currentSealed) != nil {
			rows.Close()
			return Connection{}, ErrConnectionUnavailable
		}
		if psk, ok := chosen[tid]; ok {
			if rev == math.MaxInt64 {
				rows.Close()
				return Connection{}, ErrConnectionConflict
			}
			current, err := OpenPSK(sealer, PSKBinding{OrgID: org, ConnectionID: id, TunnelID: tid, Revision: rev}, currentSealed)
			if err != nil {
				rows.Close()
				return Connection{}, ErrConnectionUnavailable
			}
			if current == psk {
				rows.Close()
				return Connection{}, ErrConnectionInvalid
			}
			sealed, err := seal(sealer, PSKBinding{OrgID: org, ConnectionID: id, TunnelID: tid, Revision: rev + 1}, psk)
			if err != nil {
				rows.Close()
				return Connection{}, ErrConnectionUnavailable
			}
			updates = append(updates, update{tid, rev + 1, sealed})
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return Connection{}, ErrConnectionUnavailable
	}
	if len(updates) != len(replacements) {
		return Connection{}, ErrConnectionInvalid
	}
	audit := uuid.New()
	metadata, _ := json.Marshal(struct {
		Revision int64 `json:"revision"`
	}{revision + 1})
	if _, e = tx.Exec(ctx, `INSERT INTO audit_logs(id,org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'ipsec.psk_rotated','ipsec_connection',$4,$5)`, audit, org, actor, id.String(), metadata); e != nil {
		return Connection{}, ErrConnectionUnavailable
	}
	ids := make([]uuid.UUID, len(updates))
	for i, u := range updates {
		ids[i] = u.id
	}
	if _, e = tx.Exec(ctx, `INSERT INTO ipsec_psk_rotations(connection_id,org_id,desired_revision,previous_revision,actor_id,audit_id,tunnel_ids) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, org, revision+1, revision, actor, audit, ids); e != nil {
		return Connection{}, createError(e)
	}
	if _, e = tx.Exec(ctx, `SET CONSTRAINTS ipsec_secret_revision_fk DEFERRED`); e != nil {
		return Connection{}, ErrConnectionUnavailable
	}
	for _, u := range updates {
		if _, e = tx.Exec(ctx, `UPDATE ipsec_tunnels SET secret_revision=$3 WHERE id=$1 AND org_id=$2`, u.id, org, u.revision); e != nil {
			return Connection{}, createError(e)
		}
		if _, e = tx.Exec(ctx, `UPDATE ipsec_tunnel_secrets SET secret_revision=$3,sealed_psk=$4 WHERE tunnel_id=$1 AND org_id=$2`, u.id, org, u.revision, u.sealed); e != nil {
			return Connection{}, createError(e)
		}
	}
	if _, e = tx.Exec(ctx, `UPDATE ipsec_connections SET desired_revision=desired_revision+1 WHERE id=$1 AND org_id=$2`, id, org); e != nil {
		return Connection{}, createError(e)
	}
	out, e := scanConnection(tx.QueryRow(ctx, `SELECT `+connectionColumns+` FROM ipsec_connections c WHERE c.id=$1 AND c.org_id=$2`, id, org))
	if e != nil {
		return Connection{}, createError(e)
	}
	if e = tx.Commit(ctx); e != nil {
		return Connection{}, createError(e)
	}
	return out, nil
}

package beam

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

// Admission evidence contains only durable identity/resource IDs and fixed
// outcome enums. It deliberately excludes paths, queries, headers and tokens.
func auditAllowed(ctx context.Context, tx pgx.Tx, b Binding, tokenHash []byte) error {
	_, e := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) SELECT $1,user_id,'beam.access.allowed','beam_share',$2,'{"outcome":"allowed","reason":"admission"}' FROM beam_browser_sessions WHERE org_id=$1 AND share_id=$3 AND token_hash=$4`, b.OrgID, b.AppID.String(), b.AppID, tokenHash)
	return e
}

// Only an identifiable Beam session produces denied evidence. Deduplication
// bounds repeated refusal writes per user/share over five seconds. Unknown
// cookies remain in the serving proxy's bounded denial metrics.
func (s *Service) auditDenied(ctx context.Context, b Binding, token string) {
	if len(token) != 49 {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	tx, e := s.pool.Begin(bounded)
	if e != nil {
		return
	}
	defer tx.Rollback(context.Background())
	var user uuid.UUID
	if e = tx.QueryRow(bounded, `SELECT user_id FROM beam_browser_sessions WHERE org_id=$1 AND share_id=$2 AND token_hash=$3`, b.OrgID, b.AppID, hash(token)).Scan(&user); e != nil {
		return
	}
	// Separate statements retain READ COMMITTED visibility after a concurrent
	// writer releases this transaction-scoped lock. A single CTE would keep the
	// old statement snapshot and could duplicate evidence despite serialization.
	if _, e = tx.Exec(bounded, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "beam-denied:"+b.OrgID.String()+":"+b.AppID.String()+":"+user.String()); e != nil {
		return
	}
	if _, e = tx.Exec(bounded, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) SELECT $1,$3,'beam.access.denied','beam_share',$2,'{"outcome":"denied","reason":"authority_unavailable"}' WHERE NOT EXISTS(SELECT 1 FROM audit_logs a WHERE a.org_id=$1 AND a.actor_user_id=$3 AND a.target_type='beam_share' AND a.target_id=$2 AND a.action='beam.access.denied' AND a.created_at>now()-interval '5 seconds')`, b.OrgID, b.AppID.String(), user); e == nil {
		_ = tx.Commit(bounded)
	}
}

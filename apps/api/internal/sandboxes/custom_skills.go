package sandboxes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"time"
)

type CustomSkill struct {
	ID                                  uuid.UUID
	RevisionID                          uuid.UUID
	Generation                          int64
	Name, Description, Digest, Document string
	CreatedAt                           time.Time
	Deleted                             bool
}

const customSkillColumns = `c.id,c.current_revision_id,c.generation,r.manifest,r.document,c.created_at,c.deleted_at IS NOT NULL`

func scanCustomSkill(row pgx.Row) (CustomSkill, error) {
	var out CustomSkill
	var raw []byte
	err := row.Scan(&out.ID, &out.RevisionID, &out.Generation, &raw, &out.Document, &out.CreatedAt, &out.Deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	var revision SkillRevision
	if json.Unmarshal(raw, &revision) != nil || revision.ID != out.RevisionID || validateSkill(revision) != nil {
		return out, ErrInvalid
	}
	out.Name, out.Description, out.Digest = revision.Name, revision.Description, revision.Digest
	return out, nil
}
func (s *Store) CreateCustomSkill(ctx context.Context, org, actor uuid.UUID, document, key string) (CustomSkill, bool, error) {
	revision, document, err := parseCustomSkill(document, uuid.New(), 1)
	if err != nil || len(key) == 0 || len(key) > 128 {
		return CustomSkill{}, false, ErrInvalid
	}
	hash := sha256.Sum256([]byte(document))
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CustomSkill{}, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err = tx.Exec(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, org); err != nil {
		return CustomSkill{}, false, err
	}
	if _, err = authorize(ctx, tx, org, actor, rbac.PermSandboxManage); err != nil {
		return CustomSkill{}, false, err
	}
	var existing uuid.UUID
	var priorHash []byte
	err = tx.QueryRow(ctx, `SELECT id,request_hash FROM sandbox_custom_skills WHERE org_id=$1 AND owner_id=$2 AND idempotency_key=$3`, org, actor, key).Scan(&existing, &priorHash)
	if err == nil {
		if !equalHash(priorHash, hash[:]) {
			return CustomSkill{}, false, ErrConflict
		}
		out, e := scanCustomSkill(tx.QueryRow(ctx, `SELECT `+customSkillColumns+` FROM sandbox_custom_skills c JOIN sandbox_skill_revisions r ON r.id=c.current_revision_id WHERE c.id=$1`, existing))
		if e != nil {
			return out, false, e
		}
		return out, true, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return CustomSkill{}, false, err
	}
	var own, total int
	err = tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE owner_id=$2),count(*) FROM sandbox_custom_skills WHERE org_id=$1 AND deleted_at IS NULL`, org, actor).Scan(&own, &total)
	if err != nil {
		return CustomSkill{}, false, err
	}
	if own >= 20 || total >= 500 {
		return CustomSkill{}, false, ErrQuota
	}
	id := uuid.New()
	raw, _ := json.Marshal(revision)
	if _, err = tx.Exec(ctx, `INSERT INTO sandbox_custom_skills(id,org_id,owner_id,current_revision_id,idempotency_key,request_hash) VALUES($1,$2,$3,$4,$5,$6)`, id, org, actor, revision.ID, key, hash[:]); err != nil {
		return CustomSkill{}, false, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO sandbox_skill_revisions(id,org_id,owner_id,custom_skill_id,manifest,document,enabled) VALUES($1,$2,$3,$4,$5,$6,true)`, revision.ID, org, actor, id, raw, document); err != nil {
		return CustomSkill{}, false, err
	}
	out, err := scanCustomSkill(tx.QueryRow(ctx, `SELECT `+customSkillColumns+` FROM sandbox_custom_skills c JOIN sandbox_skill_revisions r ON r.id=c.current_revision_id WHERE c.id=$1`, id))
	if err != nil {
		return out, false, err
	}
	if err = auditCustomSkill(ctx, tx, org, actor, id, 1, "sandbox.skill_create"); err != nil {
		return out, false, err
	}
	return out, false, tx.Commit(ctx)
}
func (s *Store) CustomSkills(ctx context.Context, org, actor uuid.UUID) ([]CustomSkill, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err = authorize(ctx, tx, org, actor, rbac.PermSandboxView); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT `+customSkillColumns+` FROM sandbox_custom_skills c JOIN sandbox_skill_revisions r ON r.id=c.current_revision_id WHERE c.org_id=$1 AND c.owner_id=$2 AND c.deleted_at IS NULL ORDER BY c.id LIMIT 20`, org, actor)
	if err != nil {
		return nil, err
	}
	out := []CustomSkill{}
	for rows.Next() {
		item, e := scanCustomSkill(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}
func (s *Store) GetCustomSkill(ctx context.Context, org, actor, id uuid.UUID) (CustomSkill, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CustomSkill{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err = authorize(ctx, tx, org, actor, rbac.PermSandboxView); err != nil {
		return CustomSkill{}, err
	}
	out, err := scanCustomSkill(tx.QueryRow(ctx, `SELECT `+customSkillColumns+` FROM sandbox_custom_skills c JOIN sandbox_skill_revisions r ON r.id=c.current_revision_id WHERE c.org_id=$1 AND c.owner_id=$2 AND c.id=$3 AND c.deleted_at IS NULL`, org, actor, id))
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
func (s *Store) EditCustomSkill(ctx context.Context, org, actor, id uuid.UUID, generation int64, document string) (CustomSkill, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CustomSkill{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err = authorize(ctx, tx, org, actor, rbac.PermSandboxManage); err != nil {
		return CustomSkill{}, err
	}
	current, err := scanCustomSkill(tx.QueryRow(ctx, `SELECT `+customSkillColumns+` FROM sandbox_custom_skills c JOIN sandbox_skill_revisions r ON r.id=c.current_revision_id WHERE c.org_id=$1 AND c.owner_id=$2 AND c.id=$3 AND c.deleted_at IS NULL FOR UPDATE OF c`, org, actor, id))
	if err != nil {
		return current, err
	}
	if current.Generation != generation {
		return CustomSkill{}, ErrConflict
	}
	if generation >= 20 {
		return CustomSkill{}, ErrQuota
	}
	revision, document, err := parseCustomSkill(document, uuid.New(), int(generation+1))
	if err != nil {
		return CustomSkill{}, err
	}
	raw, _ := json.Marshal(revision)
	if _, err = tx.Exec(ctx, `INSERT INTO sandbox_skill_revisions(id,org_id,owner_id,custom_skill_id,revision,manifest,document,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,true)`, revision.ID, org, actor, id, generation+1, raw, document); err != nil {
		return CustomSkill{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE sandbox_custom_skills SET current_revision_id=$2,generation=generation+1 WHERE id=$1`, id, revision.ID); err != nil {
		return CustomSkill{}, err
	}
	out, err := scanCustomSkill(tx.QueryRow(ctx, `SELECT `+customSkillColumns+` FROM sandbox_custom_skills c JOIN sandbox_skill_revisions r ON r.id=c.current_revision_id WHERE c.id=$1`, id))
	if err != nil {
		return out, err
	}
	if err = auditCustomSkill(ctx, tx, org, actor, id, out.Generation, "sandbox.skill_edit"); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
func (s *Store) DeleteCustomSkill(ctx context.Context, org, actor, id uuid.UUID, generation int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err = authorize(ctx, tx, org, actor, rbac.PermSandboxManage); err != nil {
		return err
	}
	var current int64
	var deleted bool
	err = tx.QueryRow(ctx, `SELECT generation,deleted_at IS NOT NULL FROM sandbox_custom_skills WHERE org_id=$1 AND owner_id=$2 AND id=$3 FOR UPDATE`, org, actor, id).Scan(&current, &deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if current != generation {
		return ErrConflict
	}
	if deleted {
		return tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `UPDATE sandbox_skill_revisions SET enabled=false WHERE org_id=$1 AND custom_skill_id=$2 AND owner_id=$3`, org, id, actor); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE sandbox_custom_skills SET deleted_at=now() WHERE id=$1`, id); err != nil {
		return err
	}
	if err = auditCustomSkill(ctx, tx, org, actor, id, current, "sandbox.skill_delete"); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	s.notifyPolicy(ctx, org)
	return nil
}
func auditCustomSkill(ctx context.Context, tx pgx.Tx, org, actor, id uuid.UUID, generation int64, action string) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'sandbox_custom_skill',$4,jsonb_build_object('generation',$5::bigint))`, org, actor, action, id.String(), generation)
	return err
}

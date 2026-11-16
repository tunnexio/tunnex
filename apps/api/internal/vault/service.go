// Package vault owns the tenant-scoped credential ledger. Every operation checks
// live identity and membership; administrators cannot read personal entries.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type Service struct {
	pool   *pgxpool.Pool
	sealer *crypto.Sealer
}

func New(pool *pgxpool.Pool, sealer *crypto.Sealer) *Service {
	return &Service{pool: pool, sealer: sealer}
}

func invalid() error {
	return apierr.BadRequest("invalid_vault_entry", "Check the entry, service and assignment fields")
}
func missing() error { return apierr.NotFound("vault_entry_not_found", "Vault entry not found") }
func denied() error  { return apierr.Forbidden("vault_access_denied", "Vault access is unavailable") }
func conflict() error {
	return apierr.New(409, "vault_version_conflict", "This entry changed. Refresh it before saving")
}

func validText(v string, max int, empty bool) bool {
	return utf8.ValidString(v) && !strings.ContainsRune(v, 0) && utf8.RuneCountInString(v) <= max && (empty || strings.TrimSpace(v) != "")
}

type authority struct{ canAssign bool }

// Holding share locks until the operation commits serializes sensitive reads
// with membership removal, role changes, user deactivation and organization deletion.
func (s *Service) begin(ctx context.Context, org, user uuid.UUID) (pgx.Tx, authority, error) {
	if s == nil || s.pool == nil || s.sealer == nil {
		return nil, authority{}, apierr.New(503, "vault_unavailable", "Vault is unavailable")
	}
	if org == uuid.Nil || user == uuid.Nil {
		return nil, authority{}, denied()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, authority{}, err
	}
	var roles []string
	err = tx.QueryRow(ctx, `SELECT coalesce(m.roles,ARRAY[m.role]) FROM memberships m
 JOIN users u ON u.id=m.user_id JOIN organizations o ON o.id=m.org_id
 WHERE m.org_id=$1 AND m.user_id=$2 AND m.access_revoked_at IS NULL
 AND u.status='active' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND o.deleted_at IS NULL
 FOR SHARE OF m,u,o`, org, user).Scan(&roles)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !rbac.CanAny(roles, rbac.PermVaultUse) {
		_ = tx.Rollback(ctx)
		return nil, authority{}, denied()
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, authority{}, err
	}
	return tx, authority{canAssign: rbac.CanAny(roles, rbac.PermVaultAssign)}, nil
}

func audit(ctx context.Context, tx pgx.Tx, org, actor, id uuid.UUID, action string, version int) error {
	targetType := "vault_entry"
	if action == "service_created" {
		targetType = "vault_service"
	}
	meta, err := json.Marshal(struct {
		Version int `json:"version,omitempty"`
	}{version})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata)
 VALUES($1,$2,$3,$4,$5,$6)`, org, actor, "vault."+action, targetType, id.String(), meta)
	return err
}

func (s *Service) Services(ctx context.Context, org, user uuid.UUID) ([]api.VaultService, error) {
	tx, _, err := s.begin(ctx, org, user)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id,name FROM vault_services WHERE org_id=$1 ORDER BY lower(name),id`, org)
	if err != nil {
		return nil, err
	}
	out := []api.VaultService{}
	for rows.Next() {
		var v api.VaultService
		if err = rows.Scan(&v.Id, &v.Name); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) AddService(ctx context.Context, org, user uuid.UUID, name string) (api.VaultService, error) {
	name = strings.TrimSpace(name)
	if !validText(name, 120, false) {
		return api.VaultService{}, invalid()
	}
	tx, a, err := s.begin(ctx, org, user)
	if err != nil {
		return api.VaultService{}, err
	}
	defer tx.Rollback(ctx)
	if !a.canAssign {
		return api.VaultService{}, denied()
	}
	var v api.VaultService
	err = tx.QueryRow(ctx, `INSERT INTO vault_services(org_id,name,created_by) VALUES($1,$2,$3) RETURNING id,name`, org, name, user).Scan(&v.Id, &v.Name)
	var pge *pgconn.PgError
	if errors.As(err, &pge) && pge.Code == "23505" {
		return v, apierr.New(409, "vault_service_exists", "A service with this name already exists")
	}
	if err != nil {
		return v, err
	}
	if err = audit(ctx, tx, org, user, v.Id, "service_created", 0); err != nil {
		return v, err
	}
	if err = tx.Commit(ctx); err != nil {
		return v, err
	}
	return v, nil
}

func (s *Service) Subjects(ctx context.Context, org, user uuid.UUID) (api.VaultSubjects, error) {
	out := api.VaultSubjects{Users: []api.VaultSubject{}, Groups: []api.VaultSubject{}}
	tx, a, err := s.begin(ctx, org, user)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	if !a.canAssign {
		return out, denied()
	}
	rows, err := tx.Query(ctx, `SELECT u.id,coalesce(nullif(u.name,''),u.email::text) FROM memberships m JOIN users u ON u.id=m.user_id
 WHERE m.org_id=$1 AND m.access_revoked_at IS NULL AND u.status='active' AND u.deleted_at IS NULL ORDER BY lower(u.name),u.id`, org)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var v api.VaultSubject
		if err = rows.Scan(&v.Id, &v.Name); err != nil {
			rows.Close()
			return out, err
		}
		out.Users = append(out.Users, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = tx.Query(ctx, `SELECT id,name FROM user_groups WHERE org_id=$1 ORDER BY lower(name),id`, org)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var v api.VaultSubject
		if err = rows.Scan(&v.Id, &v.Name); err != nil {
			rows.Close()
			return out, err
		}
		out.Groups = append(out.Groups, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}

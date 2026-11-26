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

// maxSecret is the secret length in characters (runes). It is not a byte limit: existing multibyte
// secrets must keep opening. The HTTP body limit is sized for its worst-case JSON escaping (V17).
const maxSecret = 16384

func validText(v string, max int, empty bool) bool {
	return utf8.ValidString(v) && !strings.ContainsRune(v, 0) && utf8.RuneCountInString(v) <= max && (empty || strings.TrimSpace(v) != "")
}

func detailsForbidden() error {
	return apierr.Forbidden("vault_details_forbidden", "Only Vault administrators can change the details of a shared credential")
}
func recipientWithoutAccess() error {
	return apierr.BadRequest("vault_recipient_without_access", "This person can't use Vault yet. They need the Vault role and a verified email.")
}

type authority struct{ canAssign bool }

// eligibleMembership is the ONE rule for who can use Vault in an organization (VAULT-UX-1 V1): begin(),
// the recipient list and target validation all apply it, together with rbac.PermVaultUse checked in Go.
const eligibleMembership = `m.access_revoked_at IS NULL AND u.status='active' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL`

func canUseVault(roles []string) bool { return rbac.CanAny(roles, rbac.PermVaultUse) }

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
 WHERE m.org_id=$1 AND m.user_id=$2 AND `+eligibleMembership+` AND o.deleted_at IS NULL
 FOR SHARE OF m,u,o`, org, user).Scan(&roles)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !canUseVault(roles) {
		_ = tx.Rollback(ctx)
		return nil, authority{}, denied()
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, authority{}, err
	}
	return tx, authority{canAssign: rbac.CanAny(roles, rbac.PermVaultAssign)}, nil
}

// audit records labels only (VAULT-UX-1 V3). A personal entry is recorded by kind and visibility alone:
// organization audit is readable by administrators, who must not learn what is in a personal Vault.
func audit(ctx context.Context, tx pgx.Tx, org, actor uuid.UUID, entry api.VaultEntry, action string, version int, extra map[string]any) error {
	meta := map[string]any{"kind": string(entry.Kind), "visibility": string(entry.Visibility)}
	if version > 0 {
		meta["version"] = version
	}
	if string(entry.Visibility) == "assigned" {
		meta["title"] = entry.Title
		meta["service"] = entry.ServiceName
		if entry.SubjectKind != nil {
			meta["recipient_kind"] = string(*entry.SubjectKind)
		}
		if entry.SubjectName != nil {
			meta["recipient"] = *entry.SubjectName
		}
	}
	for k, v := range extra {
		meta[k] = v
	}
	return writeAudit(ctx, tx, org, actor, "vault."+action, "vault_entry", entry.Id, meta)
}

func writeAudit(ctx context.Context, tx pgx.Tx, org, actor uuid.UUID, action, targetType string, id uuid.UUID, meta map[string]any) error {
	raw, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata)
 VALUES($1,$2,$3,$4,$5,$6)`, org, actor, action, targetType, id.String(), raw)
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
	if err = writeAudit(ctx, tx, org, user, "vault.service_created", "vault_service", v.Id, map[string]any{"service": v.Name}); err != nil {
		return v, err
	}
	if err = tx.Commit(ctx); err != nil {
		return v, err
	}
	return v, nil
}

// Subjects lists the people and groups an entry can be assigned to. People are listed only when they can
// use Vault; a group lists the members who cannot, so the picker can name them (VAULT-UX-1 V1, V9).
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
	rows, err := tx.Query(ctx, `SELECT u.id,coalesce(nullif(u.name,''),u.email::text),u.email::text,coalesce(m.roles,ARRAY[m.role])
 FROM memberships m JOIN users u ON u.id=m.user_id
 WHERE m.org_id=$1 AND `+eligibleMembership+` ORDER BY lower(coalesce(nullif(u.name,''),u.email::text)),u.id`, org)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var v api.VaultSubject
		var email string
		var roles []string
		if err = rows.Scan(&v.Id, &v.Name, &email, &roles); err != nil {
			rows.Close()
			return out, err
		}
		if canUseVault(roles) {
			v.Email = &email
			out.Users = append(out.Users, v)
		}
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
	index := map[uuid.UUID]int{}
	for rows.Next() {
		var v api.VaultSubject
		if err = rows.Scan(&v.Id, &v.Name); err != nil {
			rows.Close()
			return out, err
		}
		count, missing := 0, []api.VaultPerson{}
		v.MemberCount, v.MembersWithoutAccess = &count, &missing
		index[v.Id] = len(out.Groups)
		out.Groups = append(out.Groups, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = tx.Query(ctx, `SELECT gm.group_id,u.id,coalesce(nullif(u.name,''),u.email::text),u.email::text,
 coalesce(m.roles,ARRAY[m.role],ARRAY[]::text[]),coalesce(m.user_id IS NOT NULL AND `+eligibleMembership+`,false)
 FROM group_members gm JOIN users u ON u.id=gm.user_id
 LEFT JOIN memberships m ON m.org_id=gm.org_id AND m.user_id=gm.user_id
 WHERE gm.org_id=$1 ORDER BY lower(coalesce(nullif(u.name,''),u.email::text)),u.id`, org)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var group uuid.UUID
		var p api.VaultPerson
		var roles []string
		var eligible bool
		if err = rows.Scan(&group, &p.Id, &p.Name, &p.Email, &roles, &eligible); err != nil {
			rows.Close()
			return out, err
		}
		i, ok := index[group]
		if !ok {
			continue
		}
		g := &out.Groups[i]
		*g.MemberCount++
		if !eligible || !canUseVault(roles) {
			*g.MembersWithoutAccess = append(*g.MembersWithoutAccess, p)
		}
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

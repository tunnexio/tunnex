package beam

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type Project struct {
	ID        uuid.UUID `json:"id"`
	OrgID     uuid.UUID `json:"org_id"`
	OwnerID   uuid.UUID `json:"owner_id"`
	Name      string    `json:"name"`
	Target    Target    `json:"target"`
	Duration  int       `json:"duration_seconds"`
	Grants    []Grant   `json:"grants"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type ProjectInput struct {
	Name            string  `json:"name"`
	Target          Target  `json:"target"`
	Duration        int     `json:"duration_seconds"`
	Grants          []Grant `json:"grants"`
	ExpectedVersion int64   `json:"expected_version,omitempty"`
}

const projectColumns = `id,org_id,owner_id,name,target,duration_seconds,grants,version,created_at,updated_at`

func projectMissing() error { return apierr.NotFound("beam_project_not_found", "Project not found") }
func scanProject(row pgx.Row) (Project, error) {
	var p Project
	var target, grants []byte
	e := row.Scan(&p.ID, &p.OrgID, &p.OwnerID, &p.Name, &target, &p.Duration, &grants, &p.Version, &p.CreatedAt, &p.UpdatedAt)
	if e == nil {
		e = json.Unmarshal(target, &p.Target)
	}
	if e == nil {
		e = json.Unmarshal(grants, &p.Grants)
	}
	return p, e
}
func (s *Service) project(ctx context.Context, q reader, org, id uuid.UUID, a Actor) (Project, error) {
	if e := s.member(ctx, q, org, a.ID, rbac.PermBeamUse); e != nil {
		return Project{}, e
	}
	p, e := scanProject(q.QueryRow(ctx, `SELECT `+projectColumns+` FROM beam_projects WHERE org_id=$1 AND id=$2 AND owner_id=$3`, org, id, a.ID))
	if errors.Is(e, pgx.ErrNoRows) {
		return p, projectMissing()
	}
	return p, e
}
func (s *Service) GetProject(ctx context.Context, org, id uuid.UUID, a Actor) (Project, error) {
	return s.project(ctx, s.pool, org, id, a)
}
func (s *Service) Projects(ctx context.Context, org uuid.UUID, a Actor, limit, offset int) (Page[Project], error) {
	out := Page[Project]{Items: []Project{}, Limit: limit, Offset: offset, ServerTime: time.Now()}
	if e := s.member(ctx, s.pool, org, a.ID, rbac.PermBeamUse); e != nil {
		return out, e
	}
	rows, e := s.pool.Query(ctx, `SELECT `+projectColumns+` FROM beam_projects WHERE org_id=$1 AND owner_id=$2 ORDER BY updated_at DESC,id LIMIT $3 OFFSET $4`, org, a.ID, limit, offset)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		p, e := scanProject(rows)
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, p)
	}
	return out, rows.Err()
}
func validateProject(in *ProjectInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || !utf8.ValidString(in.Name) || utf8.RuneCountInString(in.Name) > 100 || strings.ContainsAny(in.Name, "\r\n\x00") {
		return invalid("Project name must contain 1 to 100 characters")
	}
	return ValidateTarget(in.Target)
}
func (s *Service) SaveProject(ctx context.Context, org, id uuid.UUID, a Actor, in ProjectInput) (Project, error) {
	if e := validateProject(&in); e != nil {
		return Project{}, e
	}
	tx, e := s.transaction(ctx, org)
	if e != nil {
		return Project{}, e
	}
	defer tx.Rollback(ctx)
	p, e := s.policy(ctx, tx, org)
	if e != nil {
		return Project{}, e
	}
	if e = s.publisher(ctx, tx, org, a.ID, p); e != nil {
		return Project{}, e
	}
	if in.Duration < 60 || in.Duration > p.MaxDuration {
		return Project{}, invalid("Project duration exceeds current organization policy")
	}
	if e = s.validateSubjects(ctx, tx, org, a.ID, p, in.Grants); e != nil {
		return Project{}, e
	}
	target, _ := json.Marshal(in.Target)
	grants, _ := json.Marshal(nonNil(in.Grants))
	var out Project
	if id == uuid.Nil {
		var count int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM beam_projects WHERE org_id=$1 AND owner_id=$2`, org, a.ID).Scan(&count); e != nil {
			return out, e
		}
		if count >= 100 {
			return out, apierr.New(429, "beam_project_quota_reached", "At most 100 saved projects per publisher")
		}
		out, e = scanProject(tx.QueryRow(ctx, `INSERT INTO beam_projects(org_id,owner_id,name,target,duration_seconds,grants) VALUES($1,$2,$3,$4,$5,$6) RETURNING `+projectColumns, org, a.ID, in.Name, target, in.Duration, grants))
	} else {
		previous, x := s.project(ctx, tx, org, id, a)
		if x != nil {
			return out, x
		}
		if previous.Version != in.ExpectedVersion {
			return out, conflict()
		}
		out, e = scanProject(tx.QueryRow(ctx, `UPDATE beam_projects SET name=$4,target=$5,duration_seconds=$6,grants=$7,version=version+1 WHERE org_id=$1 AND id=$2 AND owner_id=$3 RETURNING `+projectColumns, org, id, a.ID, in.Name, target, in.Duration, grants))
	}
	if e != nil {
		return out, e
	}
	// Updating a preset changes no serving share, grant or connector generation.
	_, e = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,'beam.project.saved','beam_project',$3,'{"outcome":"success"}')`, org, a.ID, out.ID.String())
	if e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
func (s *Service) ProjectSessions(ctx context.Context, org, id uuid.UUID, a Actor, limit, offset int, scope string) (Page[Share], error) {
	out := Page[Share]{Items: []Share{}, Limit: limit, Offset: offset, ServerTime: time.Now()}
	if scope != "" && scope != "active" && scope != "history" {
		return out, invalid("Invalid share scope")
	}
	if _, e := s.project(ctx, s.pool, org, id, a); e != nil {
		return out, e
	}
	// Use the exact inventory authority projection, then apply the project before pagination.
	return s.listProjectQuery(ctx, org, a, false, limit, offset, "", "", "", scope, &id)
}

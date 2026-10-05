package sandboxes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxscope"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type SkillField struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Choices  []string `json:"choices"`
	Required bool     `json:"required"`
}
type SkillRevision struct {
	UserOwned     bool         `json:"-"`
	CustomSkillID *uuid.UUID   `json:"-"`
	ID            uuid.UUID    `json:"id"`
	Name          string       `json:"name"`
	Description   string       `json:"description"`
	Version       string       `json:"version"`
	Instructions  string       `json:"instructions"`
	Digest        string       `json:"digest"`
	RequiredScope []Scope      `json:"required_scope"`
	Fields        []SkillField `json:"fields"`
}
type SkillSelection struct {
	RevisionID    uuid.UUID         `json:"revision_id"`
	Configuration map[string]string `json:"configuration"`
}

var skillKey = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,39}$`)

func skillText(v string, max int) bool {
	return v != "" && len(v) <= max && utf8.ValidString(v) && strings.TrimSpace(v) == v && !strings.ContainsFunc(v, unicode.IsControl)
}
func validateSkill(v SkillRevision) error {
	if v.ID == uuid.Nil || !skillText(v.Name, 80) || !skillText(v.Version, 40) || !skillText(v.Description, 256) || !utf8.ValidString(v.Instructions) || len(v.Instructions) == 0 || len(v.Instructions) > 32768 || strings.ContainsRune(v.Instructions, 0) || len(v.Fields) > 16 {
		return ErrInvalid
	}
	hash := sha256.Sum256([]byte(v.Instructions))
	if v.Digest != hex.EncodeToString(hash[:]) {
		return ErrInvalid
	}
	if _, err := sandboxscope.NormalizeScope(v.RequiredScope); err != nil {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, f := range v.Fields {
		if !skillKey.MatchString(f.Key) || seen[f.Key] || !skillText(f.Label, 80) || len(f.Choices) < 1 || len(f.Choices) > 32 {
			return ErrInvalid
		}
		seen[f.Key] = true
		choices := map[string]bool{}
		for _, choice := range f.Choices {
			if !skillText(choice, 80) || choices[choice] {
				return ErrInvalid
			}
			choices[choice] = true
		}
	}
	return nil
}
func normalizeSkills(values []SkillSelection) ([]SkillSelection, error) {
	if len(values) > 16 {
		return nil, ErrInvalid
	}
	out := make([]SkillSelection, 0, len(values))
	seen := map[uuid.UUID]bool{}
	for _, v := range values {
		if v.RevisionID == uuid.Nil || seen[v.RevisionID] || len(v.Configuration) > 16 {
			return nil, ErrInvalid
		}
		seen[v.RevisionID] = true
		copy := SkillSelection{RevisionID: v.RevisionID, Configuration: map[string]string{}}
		for key, value := range v.Configuration {
			if !skillKey.MatchString(key) || !skillText(value, 80) {
				return nil, ErrInvalid
			}
			copy.Configuration[key] = value
		}
		out = append(out, copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RevisionID.String() < out[j].RevisionID.String() })
	return out, nil
}
func validateSelection(selected SkillSelection, revision SkillRevision, requested, cap []Scope) error {
	if validateSkill(revision) != nil || selected.RevisionID != revision.ID {
		return ErrInvalid
	}
	if err := sandboxscope.AdmitScope(revision.RequiredScope, requested, cap); err != nil {
		return err
	}
	fields := map[string]SkillField{}
	for _, f := range revision.Fields {
		fields[f.Key] = f
		if f.Required && selected.Configuration[f.Key] == "" {
			return ErrInvalid
		}
	}
	for key, value := range selected.Configuration {
		f, ok := fields[key]
		if !ok {
			return ErrInvalid
		}
		found := false
		for _, choice := range f.Choices {
			found = found || choice == value
		}
		if !found {
			return ErrInvalid
		}
	}
	return nil
}
func admitSkills(ctx context.Context, tx pgx.Tx, org, actor, template uuid.UUID, selected []SkillSelection, requested, cap []Scope) error {
	_, err := selectedSkillRevisions(ctx, tx, org, actor, template, selected, requested, cap)
	return err
}

func selectedSkillRevisions(ctx context.Context, tx pgx.Tx, org, actor, template uuid.UUID, selected []SkillSelection, requested, cap []Scope) (map[string]SkillRevision, error) {
	out := map[string]SkillRevision{}
	for _, selection := range selected {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT r.manifest FROM sandbox_skill_revisions r WHERE r.org_id=$1 AND r.id=$3 AND r.enabled AND ((r.owner_id IS NULL AND EXISTS(SELECT 1 FROM sandbox_template_skills a WHERE a.org_id=r.org_id AND a.revision_id=r.id AND a.template_id=$2)) OR (r.owner_id=$4 AND EXISTS(SELECT 1 FROM sandbox_custom_skills c WHERE c.id=r.custom_skill_id AND c.org_id=r.org_id AND c.owner_id=$4 AND c.deleted_at IS NULL))) FOR SHARE OF r`, org, template, selection.RevisionID, actor).Scan(&raw)
		if err == pgx.ErrNoRows {
			return nil, ErrDisabled
		}
		if err != nil {
			return nil, err
		}
		var revision SkillRevision
		if json.Unmarshal(raw, &revision) != nil || revision.ID != selection.RevisionID {
			return nil, ErrInvalid
		}
		if err = validateSelection(selection, revision, requested, cap); err != nil {
			return nil, err
		}
		out[selection.RevisionID.String()] = revision
	}
	return out, nil
}
func (s *Store) Skills(ctx context.Context, org, actor uuid.UUID) ([]SkillRevision, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err = authorize(ctx, tx, org, actor, rbac.PermSandboxView); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT r.id,r.manifest,r.owner_id IS NOT NULL,r.custom_skill_id FROM sandbox_skill_revisions r WHERE r.org_id=$1 AND r.enabled AND ((r.owner_id IS NULL AND EXISTS(SELECT 1 FROM sandbox_template_skills a JOIN sandbox_templates t ON t.id=a.template_id AND t.org_id=a.org_id AND t.enabled WHERE a.org_id=r.org_id AND a.revision_id=r.id)) OR (r.owner_id=$2 AND EXISTS(SELECT 1 FROM sandbox_custom_skills c WHERE c.id=r.custom_skill_id AND c.current_revision_id=r.id AND c.org_id=r.org_id AND c.owner_id=$2 AND c.deleted_at IS NULL))) ORDER BY r.id LIMIT 100`, org, actor)
	if err != nil {
		return nil, err
	}
	out := []SkillRevision{}
	for rows.Next() {
		var id uuid.UUID
		var raw []byte
		var owned bool
		var custom *uuid.UUID
		if err = rows.Scan(&id, &raw, &owned, &custom); err != nil {
			rows.Close()
			return nil, err
		}
		var revision SkillRevision
		if json.Unmarshal(raw, &revision) == nil && revision.ID == id && validateSkill(revision) == nil {
			revision.UserOwned = owned
			revision.CustomSkillID = custom
			out = append(out, revision)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

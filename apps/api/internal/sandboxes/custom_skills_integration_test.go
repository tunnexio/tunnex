package sandboxes

import (
	"errors"
	"github.com/google/uuid"
	"strings"
	"testing"
)

func TestCustomSandboxSkillPostgresPrivateVersionedSelectableAndDeleted(t *testing.T) {
	f := newFixture(t)
	skill, replay, err := f.store.CreateCustomSkill(f.ctx, f.org, f.user, customSkillDocument, "custom-create")
	if err != nil || replay {
		t.Fatal("custom create failed", err)
	}
	same, replay, err := f.store.CreateCustomSkill(f.ctx, f.org, f.user, customSkillDocument, "custom-create")
	if err != nil || !replay || same.ID != skill.ID {
		t.Fatal("idempotency failed", err)
	}
	if _, _, err = f.store.CreateCustomSkill(f.ctx, f.org, f.user, customSkillDocument+"changed", "custom-create"); !errors.Is(err, ErrConflict) {
		t.Fatal("changed intent replayed", err)
	}
	ownerCatalog, err := f.store.Skills(f.ctx, f.org, f.user)
	if err != nil || len(ownerCatalog) != 1 || !ownerCatalog[0].UserOwned {
		t.Fatal("private catalog missing", err)
	}
	otherCatalog, err := f.store.Skills(f.ctx, f.org, f.other)
	if err != nil || len(otherCatalog) != 0 {
		t.Fatal("private catalog leaked", err)
	}
	if _, err = f.store.GetCustomSkill(f.ctx, f.org, f.other, skill.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("other owner read content", err)
	}
	if _, err = f.store.EditCustomSkill(f.ctx, f.org, f.other, skill.ID, 1, customSkillDocument); !errors.Is(err, ErrNotFound) {
		t.Fatal("other owner edited content", err)
	}
	if err = f.store.DeleteCustomSkill(f.ctx, f.org, f.other, skill.ID, 1); !errors.Is(err, ErrNotFound) {
		t.Fatal("other owner deleted content", err)
	}
	input := f.input("private-selection")
	input.SelectedSkills = []SkillSelection{{skill.RevisionID, map[string]string{}}}
	sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, input)
	if err != nil {
		t.Fatal("own skill could not be selected without catalog allowlist", err)
	}
	// A forged template link must never make another user's private revision usable.
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO sandbox_template_skills(org_id,template_id,revision_id) VALUES($1,$2,$3)`, f.org, f.template, skill.RevisionID); err != nil {
		t.Fatal(err)
	}
	input.Requested = []Scope{}
	input.IdempotencyKey = "other-private"
	if _, _, err = f.store.Create(f.ctx, f.org, f.other, input); !errors.Is(err, ErrDisabled) {
		t.Fatal("private revision crossed owner via template link", err)
	}
	newer, err := f.store.EditCustomSkill(f.ctx, f.org, f.user, skill.ID, skill.Generation, strings.Replace(customSkillDocument, "explain", "summarize", 1))
	if err != nil || newer.RevisionID == skill.RevisionID || newer.Generation != 2 {
		t.Fatal("edit did not version", err)
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil || current.SelectedSkills[0].RevisionID != skill.RevisionID {
		t.Fatal("edit silently changed selected revision", err)
	}
	stopped, err := f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, current.Revision, "stopped")
	if err != nil {
		t.Fatal(err)
	}
	started, err := f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, stopped.Revision, "started")
	if err != nil {
		t.Fatal("old pinned active revision no longer valid", err)
	}
	if _, err = f.store.EditCustomSkill(f.ctx, f.org, f.user, skill.ID, 1, customSkillDocument); !errors.Is(err, ErrConflict) {
		t.Fatal("stale edit accepted", err)
	}
	if err = f.store.DeleteCustomSkill(f.ctx, f.org, f.user, skill.ID, newer.Generation); err != nil {
		t.Fatal(err)
	}
	if err = f.store.DeleteCustomSkill(f.ctx, f.org, f.user, skill.ID, newer.Generation); err != nil {
		t.Fatal("delete retry failed", err)
	}
	if _, err = f.store.GetCustomSkill(f.ctx, f.org, f.user, skill.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted content listed", err)
	}
	if _, err = f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, started.Revision, "started"); !errors.Is(err, ErrDisabled) {
		t.Fatal("deleted selected skill remained eligible", err)
	}
	crossOrg := uuid.New()
	if _, err = f.store.GetCustomSkill(f.ctx, crossOrg, f.user, skill.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("cross org access accepted", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandbox_custom_skills SET owner_id=$2 WHERE id=$1`, skill.ID, f.other); err == nil {
		t.Fatal("custom ownership was mutable")
	}
}

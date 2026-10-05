package sandboxes

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"strings"
	"testing"
)

func TestSandboxSkillsPostgresScopeConfigImmutableAndCurrent(t *testing.T) {
	f := newFixture(t)
	revision := testSkill()
	raw, _ := json.Marshal(revision)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_skill_revisions(id,org_id,manifest,enabled) VALUES($1,$2,$3,true)`, revision.ID, f.org, raw); err != nil {
		t.Fatal(err)
	}
	in := f.input("selected")
	in.SelectedSkills = []SkillSelection{{revision.ID, map[string]string{"format": "short"}}}
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, in); !errors.Is(err, ErrDisabled) {
		t.Fatal("unallowed revision selected", err)
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_template_skills(org_id,template_id,revision_id) VALUES($1,$2,$3)`, f.org, f.template, revision.ID); err != nil {
		t.Fatal(err)
	}
	invalid := in
	invalid.SelectedSkills = []SkillSelection{{revision.ID, map[string]string{"format": "short", "secret": "no"}}}
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, invalid); !errors.Is(err, ErrInvalid) {
		t.Fatal("unsupported configuration selected", err)
	}
	current, _, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.SelectedSkills) != 1 || current.SelectedSkills[0].Configuration["format"] != "short" {
		t.Fatal("selection lost")
	}
	read, err := f.store.Get(f.ctx, f.org, f.user, current.Identity.ID)
	if err != nil || len(read.SelectedSkills) != 1 {
		t.Fatal("read selection lost", err)
	}
	catalog, err := f.store.Skills(f.ctx, f.org, f.user)
	if err != nil || len(catalog) != 1 {
		t.Fatal("catalog unavailable", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandboxes SET selected_skills='[]' WHERE id=$1`, current.Identity.ID); err == nil {
		t.Fatal("selection was mutable")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandbox_skill_revisions SET manifest='{}' WHERE id=$1`, revision.ID); err == nil {
		t.Fatal("revision was mutable")
	}
	other := uuid.New()
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'other',$2)`, other, other.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO sandbox_template_skills(org_id,template_id,revision_id) VALUES($1,$2,$3)`, other, f.template, revision.ID); err == nil {
		t.Fatal("cross-org link accepted")
	}
	peer := bindCleanupPeer(t, f, current)
	credential := "tnx_sandbox_runtime_" + strings.Repeat("A", 43)
	hash := sha256.Sum256([]byte(credential))
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO sandbox_runtime_credentials(org_id,sandbox_id,peer_id,token_hash) VALUES($1,$2,$3,$4)`, f.org, current.Identity.ID, peer, hash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AuthenticateRuntime(f.ctx, credential); err != nil {
		t.Fatal(err)
	}
	projections, err := sqlc.New(f.pool).ListActiveSandboxProjections(f.ctx, f.org)
	if err != nil || len(projections) != 1 {
		t.Fatal("eligible skill projection missing", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandbox_skill_revisions SET enabled=false WHERE id=$1`, revision.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AuthenticateRuntime(f.ctx, credential); err != ErrRuntimeUnauthorized {
		t.Fatal("disabled skill runtime accepted", err)
	}
	projections, err = sqlc.New(f.pool).ListActiveSandboxProjections(f.ctx, f.org)
	if err != nil || len(projections) != 0 {
		t.Fatal("disabled skill retained policy projection", err)
	}
	stopped, err := f.store.SetDesired(f.ctx, f.org, f.user, current.Identity.ID, current.Revision, "stopped")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SetDesired(f.ctx, f.org, f.user, stopped.Identity.ID, stopped.Revision, "started"); !errors.Is(err, ErrDisabled) {
		t.Fatal("disabled skill resumed", err)
	}
}

package sandboxes

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestWorkspacePostgresPrivateSelectedSkillDeliveryAndWithdrawal(t *testing.T) {
	f := newFixture(t)
	skill, _, err := f.store.CreateCustomSkill(f.ctx, f.org, f.user, customSkillDocument, "workspace-skill")
	if err != nil {
		t.Fatal(err)
	}
	in := f.input("workspace")
	in.SelectedSkills = []SkillSelection{{skill.RevisionID, map[string]string{}}}
	sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.PrepareWorkspace(f.ctx, sandbox.Identity.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("unbound provider delivered workspace", err)
	}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, sandbox.Identity.ID, &startProvider{}); err != nil {
		t.Fatal(err)
	}
	plan, err := f.store.PrepareWorkspace(f.ctx, sandbox.Identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SandboxID != sandbox.Identity.ID || plan.OrgID != f.org || plan.Generation != 1 || len(plan.Files) != 2 || !bytes.Contains(plan.Files[0].Content, []byte("explain")) {
		t.Fatal("selected private instructions missing")
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = MaterializeSkillBundle(root, plan.Files); err != nil {
		t.Fatal(err)
	}
	if err = f.store.DeleteCustomSkill(f.ctx, f.org, f.user, skill.ID, skill.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.PrepareWorkspace(f.ctx, sandbox.Identity.ID); !errors.Is(err, ErrDisabled) {
		t.Fatal("deleted skill still delivered", err)
	}
}

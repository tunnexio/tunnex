package vault

import (
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

// VAULT-UX-2 W2: the list names a person recipient with their email and a group recipient with its size,
// counted exactly as the recipient picker counts it. Personal entries carry neither.
func TestVaultListNamesRecipientsWithEmailAndGroupSize(t *testing.T) {
	f := newUX1Fixture(t)
	if _, err := f.assign(t, "user", f.alice, "Person share"); err != nil {
		t.Fatal(err)
	}
	group := uuid.New()
	f.exec(t, `INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Ops group')`, group, f.org)
	for _, id := range []uuid.UUID{f.alice, f.bob, f.aiViewer} {
		f.exec(t, `INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, f.org, group, id)
	}
	if _, err := f.assign(t, "group", group, "Group share"); err != nil {
		t.Fatal(err)
	}
	f.personal(t, f.admin, "Admin personal")

	subjects, err := f.s.Subjects(f.ctx, f.org, f.admin)
	if err != nil || len(subjects.Groups) != 1 || subjects.Groups[0].MemberCount == nil {
		t.Fatalf("subjects: %+v %v", subjects, err)
	}
	pickerCount := *subjects.Groups[0].MemberCount

	var aliceEmail string
	if err = f.pool.QueryRow(f.ctx, `SELECT email FROM users WHERE id=$1`, f.alice).Scan(&aliceEmail); err != nil {
		t.Fatal(err)
	}
	check := func(entries []api.VaultEntry) {
		t.Helper()
		for _, e := range entries {
			switch e.Title {
			case "Person share":
				if e.SubjectEmail == nil || *e.SubjectEmail != aliceEmail || e.SubjectMemberCount != nil {
					t.Fatalf("person recipient must carry their email only: %+v", e)
				}
			case "Group share":
				if e.SubjectMemberCount == nil || *e.SubjectMemberCount != pickerCount || *e.SubjectMemberCount != 3 || e.SubjectEmail != nil {
					t.Fatalf("group recipient must carry the picker's member count only: %+v", e)
				}
			case "Admin personal":
				if e.SubjectEmail != nil || e.SubjectMemberCount != nil {
					t.Fatalf("personal entry must not carry recipient facts: %+v", e)
				}
			}
		}
	}
	all, err := f.s.ListView(f.ctx, f.org, f.admin, 50, 0, "", "all")
	if err != nil || len(all.Entries) != 3 {
		t.Fatalf("admin list: %+v %v", all, err)
	}
	check(all.Entries)

	// A recipient sees the same facts for what is shared with them, and nothing new about anyone else.
	mine, err := f.s.ListView(f.ctx, f.org, f.alice, 50, 0, "", "shared")
	if err != nil || len(mine.Entries) != 2 {
		t.Fatalf("recipient list: %+v %v", mine, err)
	}
	check(mine.Entries)
	bob, err := f.s.ListView(f.ctx, f.org, f.bob, 50, 0, "", "all")
	if err != nil || len(bob.Entries) != 1 || bob.Entries[0].Title != "Group share" {
		t.Fatalf("group member sees only the group share: %+v %v", bob, err)
	}
	check(bob.Entries)
}

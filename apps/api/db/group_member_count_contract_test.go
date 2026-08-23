package db_test

import (
	"os"
	"strings"
	"testing"
)

// The console reads group counts from the two bounded list contracts.  Keep the
// aggregate rules close to the SQL so a future UI change cannot reintroduce a
// per-row member-list fetch or count removed identities as active members.
func TestBoundedGroupListsExposeExactDuplicateSafeMemberCounts(t *testing.T) {
	policySQL, err := os.ReadFile("queries/policy.sql")
	if err != nil {
		t.Fatal(err)
	}
	agentSQL, err := os.ReadFile("queries/agent_templates.sql")
	if err != nil {
		t.Fatal(err)
	}

	people := strings.ToLower(string(policySQL))
	for _, want := range []string{
		"listusergroupsbyorg",
		"count(distinct u.id)::bigint as member_count",
		"gm.org_id = g.org_id",
		"gm.group_id = g.id",
		"u.id = gm.user_id and u.deleted_at is null",
		"where g.org_id = $1",
		"group by g.id",
	} {
		if !strings.Contains(people, want) {
			t.Errorf("people/directory member-count contract missing %q", want)
		}
	}

	agents := strings.ToLower(string(agentSQL))
	for _, want := range []string{
		"listagentgroups",
		"count(distinct d.id)::bigint as member_count",
		"m.org_id = g.org_id",
		"m.agent_group_id = g.id",
		"d.id = m.device_id",
		"d.org_id = m.org_id",
		"d.kind = 'agent'",
		"d.deleted_at is null",
		"where g.org_id = $1 and g.archived_at is null",
		"group by g.id",
	} {
		if !strings.Contains(agents, want) {
			t.Errorf("agent member-count contract missing %q", want)
		}
	}
}

func TestGroupListCountsRemainBoundedInventoryQueries(t *testing.T) {
	for _, path := range []string{"queries/policy.sql", "queries/agent_templates.sql"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		low := strings.ToLower(string(body))
		if !strings.Contains(low, "member_count") {
			t.Errorf("%s must expose member_count on the bounded list query", path)
		}
	}
}

package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestAgentPolicyTemplatesMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0097_agent_groups_policy_templates.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0097_agent_groups_policy_templates.down.sql")
	if err != nil {
		t.Fatal(err)
	}

	u := string(up)
	for _, want := range []string{
		"agent_policy_templates_enabled boolean NOT NULL DEFAULT false",
		"CREATE TABLE agent_groups",
		"CREATE TABLE agent_group_members",
		"CREATE TABLE agent_policy_templates",
		"CREATE TABLE agent_policy_template_versions",
		"CREATE TABLE agent_policy_template_version_items",
		"CREATE TABLE agent_policy_template_assignments",
		"CREATE TABLE agent_policy_template_rule_bindings",
		"src_kind IN ('group', 'user', 'site', 'cidr', 'agent', 'agent_group')",
		"REFERENCES agent_groups (id, org_id) ON DELETE RESTRICT",
		"REFERENCES agent_policy_template_versions (id, org_id, template_id) ON DELETE RESTRICT",
		"REFERENCES agent_policy_template_assignments (id, org_id) ON DELETE RESTRICT",
		"REFERENCES policy_rules (id, org_id) ON DELETE RESTRICT",
		"agent_group_member_require_live_agent",
		"agent_policy_template_actor_require_membership",
		"policy_rules_id_org_key UNIQUE (id, org_id)",
		"idempotency_key        text NOT NULL",
		"UNIQUE (org_id, idempotency_key)",
		"WHERE state = 'active'",
		"ON DELETE RESTRICT",
	} {
		if !strings.Contains(u, want) {
			t.Fatalf("0097 up missing %q", want)
		}
	}
	if strings.Contains(u, "agent_policy_template_version_items (\n") &&
		(strings.Contains(u, "    protocol            text") || strings.Contains(u, "    port_low")) {
		t.Fatal("template items must inherit canonical destination L4 scope, not store rule-level overrides")
	}

	d := string(down)
	for _, want := range []string{
		"cannot roll back 0097",
		"agent_policy_templates_enabled",
		"agent_policy_template_rule_bindings",
		"src_kind = 'agent_group'",
		"DROP COLUMN src_agent_group_id",
		"DROP CONSTRAINT policy_rules_id_org_key",
		"DROP FUNCTION agent_group_member_require_live_agent",
		"DROP FUNCTION agent_policy_template_actor_require_membership",
		"DROP COLUMN agent_policy_templates_enabled",
	} {
		if !strings.Contains(d, want) {
			t.Fatalf("0097 down missing preservation guard %q", want)
		}
	}
}

func TestAgentPolicyTemplateOptInQueriesStayFinite(t *testing.T) {
	queryBytes, err := os.ReadFile("queries/organizations.sql")
	if err != nil {
		t.Fatal(err)
	}
	query := string(queryBytes)
	for _, name := range []string{"GetOrganizationAgentPolicyTemplatesEnabled", "SetOrganizationAgentPolicyTemplatesEnabled"} {
		start := strings.Index(query, "-- name: "+name+" :one")
		if start < 0 {
			t.Fatalf("missing %s", name)
		}
		end := strings.Index(query[start:], ";\n")
		if end < 0 {
			t.Fatalf("unterminated %s", name)
		}
		statement := query[start : start+end]
		if !strings.Contains(statement, "agent_policy_templates_enabled") {
			t.Fatalf("%s must project the template opt-in", name)
		}
		if strings.Contains(statement, "RETURNING *") || strings.Contains(statement, "SELECT *") {
			t.Fatalf("%s must not depend on the full evolving organization projection", name)
		}
	}
}

package db_test

import (
	"os"
	"strings"
	"testing"
)

// TestFQDNResourceAnswerGenerationMigrationContract is the cheap, always-run
// contract guard for the additive S21 scaffold.  The PostgreSQL integration
// proof below covers runtime constraints; this one keeps an accidental removal
// of the fail-closed lifecycle clauses visible in ordinary unit test runs.
func TestFQDNResourceAnswerGenerationMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0110_fqdn_resource_answer_generations.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0110_fqdn_resource_answer_generations.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"CREATE TABLE fqdn_resources",
		"FQDN resources are an independent entity",
		"fqdn_resources_org_name_key",
		"CREATE TABLE fqdn_resource_answer_generations",
		"state IN ('pending', 'active', 'retired', 'withdrawn')",
		"fqdn_resource_answer_generations_one_active",
		"fqdn_generation_require_nonempty_active",
		"CREATE TABLE fqdn_resource_generation_answers",
		"family(address) = 4 AND masklen(address) = 32",
		"family(address) = 6 AND masklen(address) = 128",
		"fqdn_generation_answer_require_mutable",
		"answer_count >= 32",
		"fqdn_generation_answer_immutable",
	} {
		if !strings.Contains(string(up), want) {
			t.Fatalf("0110 up missing %q", want)
		}
	}
	for _, want := range []string{
		"cannot roll back 0110: FQDN resource lifecycle data exists",
		"DROP TABLE fqdn_resource_generation_answers",
		"DROP FUNCTION fqdn_generation_require_nonempty_active()",
		"DROP TABLE fqdn_resource_answer_generations",
		"DROP TABLE fqdn_resources",
	} {
		if !strings.Contains(string(down), want) {
			t.Fatalf("0110 down missing %q", want)
		}
	}
}

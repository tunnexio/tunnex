package db_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// grandfathered migrations predate the rolling-upgrade contract (S11 D1). They are listed BY NAME rather than
// skipped by a version cutoff so that adding to this list is a deliberate, reviewable act — and so the two
// historical exceptions stay visible instead of being absorbed into a threshold nobody re-reads.
//
//	0013 — ALTER TABLE devices DROP COLUMN last_handshake_at
//	0038 — ALTER TABLE org_hub_set RENAME COLUMN members TO configured
//
// Both are long applied in every deployment, so they cannot break a roll today. They are, however, exactly
// the shapes that WOULD have: an old CP querying a dropped or renamed column fails against the new schema
// mid-roll, which is the failure this guard exists to prevent from recurring.
var grandfathered = map[string]string{
	"0013_device_status.up.sql":           "DROP COLUMN devices.last_handshake_at — predates the contract",
	"0038_hub_set_field_partition.up.sql": "RENAME org_hub_set.members TO configured — predates the contract",
}

// breaking matches statements that make the NEW schema unusable by the PREVIOUS control-plane version.
//
// Each is a real failure during a rolling upgrade, where old and new CP replicas run against ONE database:
//   - DROP COLUMN / DROP TABLE — the old replica's SELECT or INSERT references a column that is gone.
//   - RENAME COLUMN / RENAME TO — same, by a different route; the old name simply stops existing.
//   - ALTER COLUMN … TYPE — a narrowing conversion (text→uuid, bigint→int) rejects values the old replica writes.
//   - SET NOT NULL — the old replica, unaware of the new requirement, inserts NULL and gets a constraint error.
var breaking = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bdrop\s+column\b`),
	regexp.MustCompile(`(?i)\bdrop\s+table\b`),
	regexp.MustCompile(`(?i)\brename\s+column\b`),
	regexp.MustCompile(`(?i)\balter\s+table\s+\S+\s+rename\s+to\b`),
	regexp.MustCompile(`(?i)\balter\s+column\s+\S+\s+type\b`),
	regexp.MustCompile(`(?i)\bset\s+not\s+null\b`),
}

// TestMigrationsAreBackwardCompatibleForOneVersion — the guard behind D1's rolling procedure.
//
// THE PROCEDURE ASSUMES SOMETHING THE SCHEMA MUST GUARANTEE. "Migrate the database, roll the CP replicas,
// let the agents reconcile — never a flag day" only works if the PREVIOUS CP version keeps working against
// the NEW schema for the duration of the roll. That is a property of every migration, and a census of the 53
// shipped migrations found TWO that violate it (grandfathered above). So the assumption was never guaranteed
// by convention — it needs a guard, or the first non-backward-compatible migration is discovered during a
// customer's upgrade, halfway through, with half the replicas failing queries.
//
// EXPAND / MIGRATE / CONTRACT is the way through, and it is not a hardship: to remove a column, ship the
// removal of its LAST READER in version N, then drop the column in N+1. Two releases instead of one, and no
// customer ever runs a schema their CP cannot read.
//
// If a migration genuinely must break compatibility, that is a DECIDE-ITEM for a human: add it to
// `grandfathered` with the reason, and state the operational exception (a brief maintenance window) in the
// upgrade runbook. The guard exists to force that conversation, not to forbid the change.
func TestMigrationsAreBackwardCompatibleForOneVersion(t *testing.T) {
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}

	type finding struct{ file, stmt string }
	var findings []finding
	checked := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		checked++
		if _, ok := grandfathered[name]; ok {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			// Comments explain migrations at length in this codebase; only statements count.
			if idx := strings.Index(line, "--"); idx >= 0 {
				line = line[:idx]
			}
			if strings.TrimSpace(line) == "" {
				continue
			}
			for _, re := range breaking {
				if m := re.FindString(line); m != "" {
					findings = append(findings, finding{name, strings.TrimSpace(line)})
					break
				}
			}
		}
	}

	if checked == 0 {
		t.Fatal("no migrations were examined — the guard would vouch for nothing")
	}
	if len(findings) != 0 {
		sort.Slice(findings, func(i, j int) bool { return findings[i].file < findings[j].file })
		var b strings.Builder
		for _, f := range findings {
			b.WriteString("\n  " + f.file + ": " + f.stmt)
		}
		t.Fatalf("migration(s) break BACKWARD COMPATIBILITY, so the previous control-plane version cannot "+
			"run against the new schema — which is exactly what a ROLLING upgrade requires (S11 D1).%s\n\n"+
			"Use expand/migrate/contract: remove the last READER of the column in this release, drop the "+
			"column in the next. If the break is genuinely necessary, add the file to `grandfathered` with a "+
			"reason AND state the maintenance-window exception in docs/upgrade.md — that is a decision for a "+
			"human, not a test to silence.", b.String())
	}
	t.Logf("census: %d migrations checked, %d grandfathered, 0 new violations", checked, len(grandfathered))
}

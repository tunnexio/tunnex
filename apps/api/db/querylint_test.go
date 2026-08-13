package db_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Query-lint: make the tenancy conventions executable, not just documented.
//
//   - Every table is TENANT-OWNED by default and must scope by `org_id` — unless
//     it is in the explicit globalTables allowlist. New tables therefore default
//     to *protected*: forgetting to classify one fails the build, instead of
//     silently escaping the lint (the failure mode the hand-maintained list had).
//   - Any table with a `deleted_at` column must filter `deleted_at IS NULL` on
//     SELECT/UPDATE, or silently resurrect soft-deleted rows.
//
// Both rules have an explicit escape hatch (`lint:cross-org` /
// `lint:allow-deleted`) so intentional exceptions are reviewed, not accidental.
// Source-level lint over db/queries/*.sql; false positives are cheap (annotate),
// silent isolation bugs are not.

// globalTables are legitimately NOT org-scoped (see migrations/README).
var globalTables = map[string]bool{
	"organizations":    true, // the tenant root; scoped by id/slug
	"users":            true, // global — email-first login, org resolved after
	"auth_tokens":      true, // global — user-scoped auth tokens, predate org context
	"platform_secrets": true, // global — platform-wide sealed material (agent CA)
	// ⭐ THE LINT ASKED THE RIGHT QUESTION AND THIS IS THE ANSWER, NOT A SILENCING.
	//
	// The licence is DEPLOYMENT-WIDE, and that is measured rather than preferred: `CountOrganizations` —
	// the query the org ceiling checks — is `SELECT count(*) FROM organizations`, because "how many
	// organizations exist" cannot be scoped to an organization. The key itself carries an eTLD+1 domain
	// and NO organization identifier. Adding `org_id` here would encode a per-tenant licence the rest of
	// the system cannot honour.
	//
	// ⚠ It is the same class as platform_secrets above, with one difference worth stating: this row is
	// PLAIN, not sealed. The key is signed and self-verifying, so sealing buys nothing — and would couple
	// licence recovery to the master key, making a sealer rotation silently downgrade a paying deployment.
	"system_settings":  true, // global — deployment-wide settings; first tenant is the licence key
	"cli_credentials":  true, // global — user-scoped CLI credentials span orgs (S5.1)
	"cli_auth_codes":   true, // global — user-scoped one-time mint codes (S5.1)
	"cli_device_codes": true, // global — pre-auth device-flow codes (S5.1)
}

type schema struct {
	tenant     map[string]bool // tables requiring org_id scoping
	deletedAt  map[string]bool // tables with a deleted_at column
	tableNames []string
}

func parseSchema(t *testing.T) schema {
	t.Helper()
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	tableRe := regexp.MustCompile(`(?is)create table\s+(\w+)\s*\((.*?)\n\);`)
	s := schema{tenant: map[string]bool{}, deletedAt: map[string]bool{}}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		content, err := os.ReadFile(filepath.Join("migrations", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range tableRe.FindAllStringSubmatch(string(content), -1) {
			name, body := strings.ToLower(m[1]), strings.ToLower(m[2])
			s.tableNames = append(s.tableNames, name)
			if strings.Contains(body, "deleted_at") {
				s.deletedAt[name] = true
			}
			if !globalTables[name] {
				s.tenant[name] = true
			}
		}
	}
	if len(s.tableNames) == 0 {
		t.Fatal("no tables parsed from migrations — lint would pass vacuously")
	}
	return s
}

type query struct{ name, body string }

func loadQueries(t *testing.T) []query {
	t.Helper()
	entries, err := os.ReadDir("queries")
	if err != nil {
		t.Fatalf("read queries dir: %v", err)
	}
	nameRe := regexp.MustCompile(`(?m)^--\s*name:\s*(\w+)`)
	var out []query
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		content, err := os.ReadFile(filepath.Join("queries", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		locs := nameRe.FindAllStringSubmatchIndex(string(content), -1)
		for i, loc := range locs {
			end := len(content)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			out = append(out, query{name: string(content)[loc[2]:loc[3]], body: string(content)[loc[0]:end]})
		}
	}
	if len(out) == 0 {
		t.Fatal("no queries found — lint would pass vacuously")
	}
	return out
}

// refersTo matches SELECT/UPDATE/DELETE references that need scoping (INSERT
// sets columns in VALUES and is exempt from these read/update-scope rules).
func refersTo(low, table string) bool {
	return regexp.MustCompile(`(?:from|update|join|delete\s+from)\s+` + table + `\b`).MatchString(low)
}

func TestQueriesScopeDeletedAt(t *testing.T) {
	s := parseSchema(t)
	for _, q := range loadQueries(t) {
		low := strings.ToLower(q.body)
		if strings.Contains(low, "lint:allow-deleted") {
			continue
		}
		for tbl := range s.deletedAt {
			if refersTo(low, tbl) && !strings.Contains(low, "deleted_at") {
				t.Errorf("query %q reads/updates %q without `deleted_at IS NULL` "+
					"(add the filter, or annotate `-- lint:allow-deleted`)", q.name, tbl)
			}
		}
	}
}

func TestQueriesScopeOrgID(t *testing.T) {
	s := parseSchema(t)
	for _, q := range loadQueries(t) {
		low := strings.ToLower(q.body)
		if strings.Contains(low, "lint:cross-org") {
			continue
		}
		for tbl := range s.tenant {
			if refersTo(low, tbl) && !strings.Contains(low, "org_id") {
				t.Errorf("query %q touches tenant-owned table %q without `org_id` scoping "+
					"(add org_id, annotate `-- lint:cross-org`, or add %q to globalTables)",
					q.name, tbl, tbl)
			}
		}
	}
}

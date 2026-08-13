package db_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// nameKeyedNodeLookupsAllowed lists the queries permitted to select nodes by name, with the reason each is safe.
// Since migration 0056 a name may be held by several REVOKED rows plus at most one active one, so any unfiltered
// by-name lookup is ambiguous.
var nameKeyedNodeLookupsAllowed = map[string]string{
	"GetNodeByOrgName": "filtered to revoked_at IS NULL, so it resolves the at-most-one ACTIVE holder",
}

// TestNoAmbiguousNodeNameLookups — the census that ruling (a) required BEFORE it landed, kept as a guard so it
// stays true afterwards.
//
// WF-S11-8 removed the unconditional uniqueness of (org_id, name) so a revoked gateway frees its name and
// re-enrolment works as documented. The cost of that freedom is that node names are no longer unique across
// history. Anything that resolves a node BY NAME therefore has to say which one it means.
//
// The census run before the migration found exactly one name-keyed query, whose only caller was a test, no SQL
// join on nodes.name, and no Go-side by-name resolver — identity goes through cert_serial, which stays globally
// unique. This guard exists because that property is easy to lose later: a by-name lookup is the natural thing
// to write, it works in every test fixture (one node, one name), and it fails only on a deployment that has
// rebuilt a gateway. Exactly the shape that reaches production.
func TestNoAmbiguousNodeNameLookups(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("queries", "nodes.sql"))
	if err != nil {
		t.Fatal(err)
	}

	// Split on the sqlc query markers so each query can be judged whole — a WHERE clause several lines below the
	// name predicate still belongs to it.
	blocks := regexp.MustCompile(`(?m)^-- name: `).Split(string(raw), -1)
	if len(blocks) < 2 {
		t.Fatal("no sqlc queries parsed from nodes.sql — the guard would vouch for nothing")
	}

	nameMatch := regexp.MustCompile(`(?i)\bname\s*=\s*\$`)
	var ambiguous []string
	checked := 0
	for _, b := range blocks[1:] {
		qName := strings.Fields(strings.SplitN(b, "\n", 2)[0])
		if len(qName) == 0 {
			continue
		}
		name := strings.TrimSuffix(qName[0], ":")
		checked++

		// Statements only. This file's comments discuss names at length, and a comment mentioning `name = $2`
		// must not count as a lookup.
		var stmt strings.Builder
		for _, line := range strings.Split(b, "\n") {
			if idx := strings.Index(line, "--"); idx >= 0 {
				line = line[:idx]
			}
			stmt.WriteString(" " + line)
		}
		sql := stmt.String()
		lower := strings.ToLower(sql)
		// Scope to the nodes TABLE, not the file. nodes.sql also holds queries for platform_secrets and
		// node_join_tokens, whose own `name` columns are unrelated to this constraint — flagging those was the
		// first draft's false positive, the same over-broad-pattern class this guard is meant to catch.
		if !strings.Contains(lower, "from nodes") && !strings.Contains(lower, "update nodes") &&
			!strings.Contains(lower, "into nodes") {
			continue
		}
		if !nameMatch.MatchString(sql) {
			continue
		}
		if _, ok := nameKeyedNodeLookupsAllowed[name]; ok {
			// An allowlisted query still has to carry the filter that makes it safe — otherwise the allowlist
			// vouches for a query that stopped deserving it.
			if !strings.Contains(lower, "revoked_at is null") {
				ambiguous = append(ambiguous, name+" (allowlisted, but its revoked_at IS NULL filter is gone)")
			}
			continue
		}
		if !strings.Contains(lower, "revoked_at is null") {
			ambiguous = append(ambiguous, name)
		}
	}

	if checked == 0 {
		t.Fatal("no queries examined")
	}
	if len(ambiguous) != 0 {
		sort.Strings(ambiguous)
		t.Fatalf("node quer(ies) select by NAME without restricting to active rows: %v\n\n"+
			"Since migration 0056 a node name is unique only among non-revoked rows, so a name may be held by "+
			"several revoked gateways plus one live one. Add `AND revoked_at IS NULL`, or key the lookup on id "+
			"or cert_serial. This passes in any test fixture with one node per name and fails only on a "+
			"deployment that has rebuilt a gateway (S11 WF-S11-8).", ambiguous)
	}
	t.Logf("census: %d node queries, %d name-keyed and allowlisted, 0 ambiguous", checked, len(nameKeyedNodeLookupsAllowed))
}

package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The three conditions attached to the (i) ruling, asserted against the migration's actual SQL rather than
// against a description of it. A data-backfill migration is unusual in this repo and it is the kind of thing
// that gets "improved" later by someone who did not read the reasoning — so the reasoning is enforced.
func TestBackfill0055CannotFalsePositive(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("migrations", "0055_backfill_cert_not_after.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	// Statements only: this migration's comment block is long and deliberately explains the bound, so a naive
	// whole-file search would find every keyword in prose and vouch for nothing.
	var stmts []string
	for _, line := range strings.Split(string(raw), "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		if s := strings.TrimSpace(line); s != "" {
			stmts = append(stmts, s)
		}
	}
	sql := strings.ToLower(strings.Join(stmts, " "))

	// CONDITION 3 — a gateway that has never reported gets NO bound. Inventing one would be the false positive
	// the ruling exists to prevent: it would brick-flag a gateway on no evidence whatsoever.
	if !strings.Contains(sql, "last_seen_at is not null") {
		t.Error("the backfill MUST exclude rows with last_seen_at IS NULL — a gateway that never reported has " +
			"no basis for any bound, and a bound invented from nothing is exactly the false positive ruling (i) " +
			"was chosen to avoid")
	}

	// Only fill what is empty. Overwriting a REAL stamped expiry with a derived bound would replace a
	// measurement with an estimate — strictly worse, and silently.
	if !strings.Contains(sql, "cert_not_after is null") {
		t.Error("the backfill MUST be restricted to cert_not_after IS NULL — overwriting a stamped expiry with " +
			"a derived bound replaces a measurement with an estimate")
	}

	// The bound is derived from last_seen_at, which is what makes it an UPPER bound (issuance <= last_seen_at,
	// so issuance + TTL <= last_seen_at + TTL). Deriving it from anything later — created_at, now() — would
	// break the direction of the inequality and with it the no-false-positive guarantee.
	if !strings.Contains(sql, "last_seen_at + interval") {
		t.Error("the bound MUST be last_seen_at + CertTTL. The guarantee rests entirely on that direction: the " +
			"cert was valid at the last report, so issuance <= last_seen_at, so the true expiry is EARLIER than " +
			"this bound — which is why a bound in the past proves a real expiry in the past. Both plausible " +
			"substitutions break it in different directions: now() + TTL is always in the future, so the kind " +
			"NEVER fires (a silent false negative); created_at + TTL predates every renewal, so it can fire on " +
			"a gateway whose cert is still valid (a false positive). Only last_seen_at bounds it correctly")
	}
	if !strings.Contains(sql, "48 hours") {
		t.Error("the interval must match agentca.CertTTL (48h); a longer interval delays detection, a shorter " +
			"one breaks the upper-bound property and can false-positive")
	}

	// CONDITION 2 — the overwrite path. Asserted where it actually lives: the queries that stamp the column.
	// A backfilled bound must be self-correcting the moment an agent talks to us again, or the estimate becomes
	// permanent.
	q, err := os.ReadFile(filepath.Join("queries", "nodes.sql"))
	if err != nil {
		t.Fatal(err)
	}
	queries := string(q)
	// SCOPED through queryBlock (review #10). This was a whole-file substring match, and this branch added a
	// SECOND query — RekeyNode — containing the same `cert_not_after = $4` text, so the guard began passing on a
	// coincidence: deleting the clause from RenewNodeCert would have left it green. The neighbouring CreateNode
	// assertion was scoped in the same commit that minted the census law; this one was missed, which makes the
	// law's first violation its own commit.
	if !strings.Contains(queryBlock(queries, "RenewNodeCert"), "cert_not_after = $4") {
		t.Error("RenewNodeCert must SET cert_not_after unconditionally, so a renewal overwrites a backfilled " +
			"bound with the real NotAfter. Without that, an estimate written by 0055 outlives the condition it " +
			"estimated")
	}
	// Asserts the COLUMN IS RECORDED, not its position in the list. The first version matched
	// "cert_not_after)" — the closing paren of the INSERT column list — which broke the moment 0057 legitimately
	// appended cert_public_key after it. A guard pinned to an incidental detail fails on correct changes and
	// teaches the next author to weaken it; the same over-narrow-pattern class as the [a-z_]+ regex that silently
	// dropped k8s_endpoints_unavailable for containing a digit.
	if createNode := queryBlock(queries, "CreateNode"); !strings.Contains(createNode, "cert_not_after") {
		t.Error("CreateNode must record cert_not_after at enrollment — a re-enrolled gateway (the documented " +
			"remedy for WF-S11-6) must come back with a REAL expiry, not inherit a stale bound")
	}
}

// queryBlock returns one sqlc query's text, so an assertion about a specific query cannot be satisfied by a
// coincidence elsewhere in the file.
func queryBlock(all, name string) string {
	start := strings.Index(all, "-- name: "+name+" ")
	if start < 0 {
		return ""
	}
	rest := all[start+1:]
	if next := strings.Index(rest, "-- name: "); next >= 0 {
		return rest[:next]
	}
	return rest
}

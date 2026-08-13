// Command seed-fixtures loads the DEMO FIXTURE SET on top of `seed` (S14.5).
//
// ⛔ WHY IT IS A SEPARATE COMMAND rather than more rows inside `seed`: `seed` establishes the org, its users
// and the auth surfaces every environment needs, including CI. These fixtures are a REVIEW AID — a populated
// network so the redesigned screens have a designed picture instead of a wall of empty states. Mixing them
// would put demo topology into every CI database and make the base seed's contract fuzzier.
//
// Same shape as `seed-enterprise`: layered, idempotent, and refusing to run against real data.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/seeddata"
)

// ⛔ ONE POSTURE STATE IS UNREACHABLE FROM SQL, AND IT IS THE MOST SEVERE ONE.
//
// `devices.health_blocked` is written by exactly one code path — `ReportHealth` — and the stale-block sweep can
// only ever set it to FALSE (`SweepStaleHealthBlocks`). So no INSERT or UPDATE in fixtures.sql can produce a
// blocked device: THE INPUT IS AN HTTP REQUEST, NOT A ROW. Seeding the flag directly is the
// controller-owned-field mistake (the sweep silently undoes it and the row reads as applied).
//
// The Human Gate Limit Law requires the review stack to exercise every state the screen can render, and
// `posture blocked` is the DANGER tone on the Devices screen. Before this, it had never rendered on localhost
// and the device named `blocked-device` was not blocked.
//
// SO THE SEEDER REGISTERS IT THROUGH THE PRODUCT — the same pattern as the k3s cluster in scripts/k3s-demo.sh:
// log in as the demo owner and POST a failing posture report for ONE device. That exercises the real
// evaluation path (require-mode check + `disk_encrypted: false`) instead of asserting its conclusion.
//
// ⚠ IT REPORTS FOR EXACTLY ONE DEVICE, DELIBERATELY. A loop over the owner's devices destroys the fixture's
// posture SPREAD (compliant / unknown / not-reported), and that spread is the only thing that makes the
// POSTURE column reviewable. This is a fixed device id, not a query.
const blockedDeviceID = "01900000-0000-7000-8000-0000000c0009"

// reportBlockedPosture logs in as the demo owner and posts a failing report for the one device.
// Returns whether the state was produced — NEVER fatal: the SQL half has already succeeded, and a seeder that
// dies here would leave a half-seeded database over a review aid.
func reportBlockedPosture(ctx context.Context, base string) (bool, error) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	post := func(path string, body any) (*http.Response, error) {
		b, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		// The CSRF header is presence-checked for cookie-auth requests; any value satisfies it.
		req.Header.Set("X-Tunnex-CSRF", "seed")
		return c.Do(req)
	}

	// Prime the cookie jar so the CSRF cookie exists, then authenticate.
	if r, err := c.Get(base + "/api/v1/meta"); err == nil {
		r.Body.Close()
	}
	lr, err := post("/api/v1/auth/login", map[string]string{
		"email": seeddata.DemoOwnerEmail, "password": seeddata.DemoOwnerPassword,
	})
	if err != nil {
		return false, err
	}
	lr.Body.Close()
	if lr.StatusCode != http.StatusOK {
		return false, fmt.Errorf("login returned %d", lr.StatusCode)
	}

	rr, err := post(fmt.Sprintf("/api/v1/organizations/%s/devices/%s/health", seeddata.DemoOrgID, blockedDeviceID),
		map[string]any{"platform": "macos", "os_version": "14.4.0", "disk_encrypted": false})
	if err != nil {
		return false, err
	}
	defer rr.Body.Close()
	if rr.StatusCode != http.StatusOK {
		return false, fmt.Errorf("report returned %d", rr.StatusCode)
	}
	var out struct{ Blocked bool }
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		return false, err
	}
	// ⛔ THE SERVER'S OWN VERDICT IS THE CHECK. Asserting we posted is not asserting it blocked: if the org's
	// require-mode check were ever removed, this would post happily and produce nothing.
	return out.Blocked, nil
}

//go:embed fixtures.sql
var fixturesSQL string

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.Error("seed_fixtures_failed", slog.String("error", "DATABASE_URL is not set"))
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		logger.Error("seed_fixtures_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()

	// THE SAME GUARD AS `seed`, and for the same reason: fixtures are demo data, and demo data must never
	// land beside somebody's production org. The demo org itself is excluded from the count, so a reseed of
	// a demo-only database is always allowed.
	var realOrgs int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM organizations WHERE id <> $1 AND deleted_at IS NULL`,
		seeddata.DemoOrgID).Scan(&realOrgs); err != nil {
		logger.Error("seed_fixtures_check_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if realOrgs > 0 && os.Getenv("TUNNEX_SEED_FORCE") != "true" {
		logger.Error("seed_fixtures_refused",
			slog.Int64("real_orgs", realOrgs),
			slog.String("hint", "database has real data; set TUNNEX_SEED_FORCE=true to override"),
		)
		os.Exit(1)
	}

	// The demo org must already exist — these fixtures hang off it. Failing loudly here beats a confusing
	// foreign-key error thirty statements into the transaction.
	var orgExists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1 AND deleted_at IS NULL)`,
		seeddata.DemoOrgID).Scan(&orgExists); err != nil {
		logger.Error("seed_fixtures_check_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if !orgExists {
		logger.Error("seed_fixtures_refused",
			slog.String("error", "the demo org does not exist"),
			slog.String("hint", "run `make seed` first — these fixtures layer on top of it"),
		)
		os.Exit(1)
	}

	if _, err := pool.Exec(ctx, fixturesSQL); err != nil {
		logger.Error("seed_fixtures_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// ⛔ COUNTED, NOT ASSERTED — and the difference already misled a review.
	//
	// This line used to read "5 gateways, 4 sites, 6 subnets, 5 devices, 12 audit entries": the rows THIS FILE
	// INSERTS. The screen renders what EXISTS, which is those rows PLUS whatever `make seed` already wrote —
	// live totals were 6 gateways, 6 sites, 8 devices, 35 audit entries. The founder reviewed Gateways showing
	// "1/6" against a seeder that had just claimed 5.
	//
	// A fixture that reports its own INTENT rather than the resulting STATE is a census of the wrong thing.
	// These numbers now come from the database after the write, so the line cannot drift from what is there.
	var gateways, sites, subnets, devices, audits, clusters, services, rules, groups, members, resources, accessEvents, cliCreds, machineCreds int
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM nodes               WHERE org_id = $1),
		       (SELECT count(*) FROM sites               WHERE org_id = $1),
		       (SELECT count(*) FROM site_subnets ss     WHERE EXISTS (SELECT 1 FROM sites s WHERE s.id = ss.site_id AND s.org_id = $1)),
		       (SELECT count(*) FROM devices             WHERE org_id = $1),
		       (SELECT count(*) FROM audit_logs          WHERE org_id = $1),
		       (SELECT count(*) FROM k8s_clusters        WHERE org_id = $1),
		       (SELECT count(*) FROM k8s_services        WHERE org_id = $1),
		       (SELECT count(*) FROM policy_rules        WHERE org_id = $1),
		       (SELECT count(*) FROM user_groups         WHERE org_id = $1),
		       (SELECT count(*) FROM group_members       WHERE org_id = $1),
		       (SELECT count(*) FROM resources           WHERE org_id = $1),
		       (SELECT count(*) FROM access_events       WHERE org_id = $1),
		       (SELECT count(*) FROM cli_credentials c   WHERE EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = c.user_id AND m.org_id = $1)),
		       (SELECT count(*) FROM machine_credentials WHERE org_id = $1)`,
		seeddata.DemoOrgID,
	).Scan(&gateways, &sites, &subnets, &devices, &audits, &clusters, &services, &rules, &groups, &members, &resources, &accessEvents, &cliCreds, &machineCreds); err != nil {
		logger.Error("seed_fixtures_count_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// ⛔ THE ONE STATE SQL CANNOT PRODUCE, registered through the product. Non-fatal by design, and its outcome
	// is COUNTED below rather than assumed — a seeder that says "ok" while the severest state is missing is the
	// reassuring-green shape at fixture level.
	apiBase := os.Getenv("TUNNEX_API_URL")
	if apiBase == "" {
		apiBase = "http://nginx:8080" // the compose service the seeder shares a network with
	}
	postureBlocked, perr := reportBlockedPosture(ctx, apiBase)
	if perr != nil {
		logger.Warn("seed_fixtures_posture_block_unreached",
			slog.String("error", perr.Error()),
			slog.String("api", apiBase),
			slog.String("consequence", "`posture blocked` (the DANGER tone) will NOT render — it is reachable only through ReportHealth, never from SQL. Set TUNNEX_API_URL if the API is elsewhere."),
		)
	}

	// ⛔ HOW A CONSUMER KNOWS THE STATE IS MISSING RATHER THAN MERELY UNRENDERED.
	//
	// The seeder now depends on the API being up, which it did not before — so on a cold boot, a different
	// compose project, or any stack where TUNNEX_API_URL is wrong, the severest posture state is silently
	// absent. That is the SAME SHAPE as the `DO NOTHING` freshness bug this slice just fixed, one layer up: a
	// command that succeeds while the thing it exists to produce does not exist.
	//
	// THREE SIGNALS, because a warning alone is a line in a log nobody greps:
	//   1. `posture_blocked` is a COUNTED CENSUS FIELD below — it reads `false`, it is not merely absent.
	//   2. The warning above names the CONSEQUENCE, not just the error.
	//   3. STRICT IS THE DEFAULT and a missing state is a NON-ZERO EXIT. Founder-ruled S14.10, inverted from
	//      the original lenient default: this seeder has ZERO CI consumers (0 references in either workflow) and
	//      its ONLY consumer is the founder review. A lenient default therefore preserves exactly the failure
	//      mode it exists to eliminate — a review of a screen whose severest state is silently absent.
	//      `TUNNEX_SEED_STRICT=false` is the escape hatch for anyone who wants the SQL half regardless.
	// ⛔ THE EMPTY GROUP IS A CENSUSED STATE, NOT JUST A SEEDED ROW.
	//
	// `Interns` exists so `src_group_empty` has a permanent subject. A reviewer exercised the new
	// "Add a member" picker on it during the S14.12 pass — the obvious thing to try, on the one group with an
	// add control and no members — and the state was gone in four seconds. The SQL now deletes its members on
	// every seed, and this COUNTS the result, because a fixture that merely creates a state cannot tell you
	// the state survived.
	//
	//   A REVIEWABLE STATE THAT ANYONE CAN DESTROY BY USING THE PRODUCT IS NOT PERMANENTLY REVIEWABLE.
	var emptyGroupMembers int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM group_members WHERE group_id = '01900000-0000-7000-8000-0000000a0004'`,
	).Scan(&emptyGroupMembers); err != nil {
		emptyGroupMembers = -1 // unknown; strict below treats it as a failure rather than a pass
	}
	if emptyGroupMembers != 0 && os.Getenv("TUNNEX_SEED_STRICT") != "false" {
		logger.Error("seed_fixtures_incomplete",
			slog.String("missing", "src_group_empty subject"),
			slog.Int("interns_members", emptyGroupMembers),
			slog.String("consequence", "`SOURCE GROUP EMPTY` has no subject and will NOT render on any rule row"))
		os.Exit(1)
	}

	if !postureBlocked && os.Getenv("TUNNEX_SEED_STRICT") != "false" {
		logger.Error("seed_fixtures_incomplete",
			slog.String("missing", "posture_blocked"),
			slog.String("hint", "the API must be reachable at seed time; unset TUNNEX_SEED_STRICT to seed anyway"))
		os.Exit(1)
	}

	logger.Info("seed_fixtures_ok",
		slog.String("org", seeddata.DemoOrgID),
		slog.Int("gateways", gateways), slog.Int("sites", sites), slog.Int("subnets", subnets),
		slog.Int("devices", devices), slog.Int("audit_entries", audits),
		slog.Int("k8s_clusters", clusters), slog.Int("k8s_services", services),
		slog.Int("policy_rules", rules),
		// TRUE = the severest posture state exists and the screen can be reviewed against it.
		slog.Bool("posture_blocked", postureBlocked),
		slog.Int("empty_group_members", emptyGroupMembers), // 0 = the src_group_empty subject is intact slog.Int("user_groups", groups), slog.Int("group_members", members),
		slog.Int("resources", resources), slog.Int("access_events", accessEvents),
		slog.Int("cli_credentials", cliCreds), slog.Int("machine_credentials", machineCreds),
		slog.String("note", "totals as they now EXIST (fixture + make seed), counted after the write; health kinds are DERIVED, not seeded"),
	)
}

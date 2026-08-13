// S7.5.3 device health (posture checks v1). Facts are CLIENT-REPORTED — spoofable
// by a compromised client; this deters honest non-compliance and produces an audit
// trail, it is NOT attestation (docs/S7.5.3-decisions.md §Threat model). Evaluation
// is continuous (every report re-evaluates against the org's per-check config) and
// enforcement rides the existing exclude-then-push machinery: a require-mode failure
// sets devices.health_blocked, the active-device readers drop the device, and the
// org-wide push pulls its /32 from every gateway within seconds.

package devices

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

const (
	// healthActorSystem is the first-class system audit actor (0027) for
	// evaluation-driven gate flips: no human initiates them, the evaluator does.
	healthActorSystem = "device-health"

	// HealthStaleTTL: a report older than this is ABSENCE (D4) — the device shows
	// posture_unknown and, critically, a stale block is CLEARED by the sweep (only
	// a FRESH positive non-compliant report gates). ~3 report intervals.
	HealthStaleTTL = 30 * time.Minute

	// HealthSweepInterval paces the staleness sweep (StartHealthSweeper).
	HealthSweepInterval = 5 * time.Minute
)

// Check kinds and modes (v1: os_version + disk_encryption; EDR is S7.5.3b).
const (
	CheckOSVersion      = "os_version"
	CheckDiskEncryption = "disk_encryption"

	ModeWarn    = "warn"
	ModeRequire = "require"
)

// HealthFacts is one client self-report (raw facts; the server evaluates).
// DiskEncrypted nil = the client could NOT determine the fact (reported ABSENT,
// never guessed). A require-mode disk check treats that as indeterminate and
// blocks fail-closed; warn mode records noncompliance without gating.
type HealthFacts struct {
	Platform      string // macos | windows | linux | other
	OSVersion     string
	DiskEncrypted *bool
	CollectedAt   *time.Time // client-claimed; informational only
}

// FailedCheck is one configured check the latest report failed.
type FailedCheck struct {
	Kind string `json:"kind"`
	Mode string `json:"mode"`
}

// HealthEvaluation is the server's verdict on a report.
type HealthEvaluation struct {
	State        string // compliant | noncompliant
	Blocked      bool   // any require-mode check failed
	FailedChecks []FailedCheck
}

// HealthCheckConfig is one org opt-in row (no row = check off).
type HealthCheckConfig struct {
	Kind  string
	Mode  string
	Param json.RawMessage
}

// osVersionParam is the os_version check's param: per-platform minimums. A
// platform absent from Min is NOT enforced on that platform (fail-open per the
// threat model — we block what we can see is bad, not what we can't read).
type osVersionParam struct {
	Min map[string]string `json:"min"`
}

var validPlatforms = map[string]bool{"macos": true, "windows": true, "linux": true, "other": true}

// evaluateHealth applies the org's configured checks to reported facts. Pure —
// unit-testable without a DB.
func evaluateHealth(checks []HealthCheckConfig, f HealthFacts) HealthEvaluation {
	ev := HealthEvaluation{State: "compliant", FailedChecks: []FailedCheck{}}
	for _, c := range checks {
		failed := false
		switch c.Kind {
		case CheckDiskEncryption:
			if f.DiskEncrypted == nil {
				failed = true // require-mode posture must not pass without proof
				break
			}
			failed = !*f.DiskEncrypted
		case CheckOSVersion:
			var p osVersionParam
			if err := json.Unmarshal(c.Param, &p); err != nil {
				continue // malformed config never blocks; validated at write, belt+braces here
			}
			min, ok := p.Min[f.Platform]
			if !ok {
				continue // platform not configured => not enforced on it
			}
			failed = versionLess(f.OSVersion, min)
		}
		if failed {
			ev.State = "noncompliant"
			ev.FailedChecks = append(ev.FailedChecks, FailedCheck{Kind: c.Kind, Mode: c.Mode})
			if c.Mode == ModeRequire {
				ev.Blocked = true
			}
		}
	}
	return ev
}

// versionLess compares dotted numeric versions ("14.5" < "15.0"); non-numeric
// suffixes are ignored ("22631.foo" -> 22631). An UNPARSEABLE reported version
// counts as LESS (a require-mode min then blocks it): the org explicitly opted
// into a version floor, and "cannot even parse" is not a pass — this is a
// positive garbled report, not absence, so gating it is the honest reading.
func versionLess(v, min string) bool {
	vp, mp := splitVersion(v), splitVersion(min)
	for i := 0; i < len(vp) || i < len(mp); i++ {
		var a, b int
		if i < len(vp) {
			a = vp[i]
		}
		if i < len(mp) {
			b = mp[i]
		}
		if a != b {
			return a < b
		}
	}
	return false
}

func splitVersion(s string) []int {
	parts := strings.Split(strings.TrimSpace(s), ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		// Take the leading digits of each segment ("22631H2" -> 22631).
		j := 0
		for j < len(p) && p[j] >= '0' && p[j] <= '9' {
			j++
		}
		n, err := strconv.Atoi(p[:j])
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// validateHealthCheck validates a config write (kind/mode/param).
func validateHealthCheck(kind, mode string, param json.RawMessage) error {
	if mode != ModeWarn && mode != ModeRequire {
		return apierr.BadRequest("invalid_request", "mode must be warn or require")
	}
	switch kind {
	case CheckDiskEncryption:
		if len(param) > 0 && string(param) != "null" {
			return apierr.BadRequest("invalid_request", "disk_encryption takes no param")
		}
	case CheckOSVersion:
		var p osVersionParam
		if len(param) == 0 || json.Unmarshal(param, &p) != nil || len(p.Min) == 0 {
			return apierr.BadRequest("invalid_request", `os_version requires param {"min":{"macos":"14.0",...}}`)
		}
		for plat, v := range p.Min {
			if !validPlatforms[plat] {
				return apierr.BadRequest("invalid_request", fmt.Sprintf("unknown platform %q in min", plat))
			}
			if len(splitVersion(v)) == 0 {
				return apierr.BadRequest("invalid_request", fmt.Sprintf("min version %q is not a dotted numeric version", v))
			}
		}
	default:
		return apierr.BadRequest("invalid_request", "check kind must be os_version or disk_encryption")
	}
	return nil
}

// HealthInfo is the per-device posture projection for the list surfaces (S7.5.3
// slice 3). State "unknown" = no report, stale report (stale = absence), or —
// per-fact — a fact reported absent. ABSENCE IS NOT COMPLIANCE: the UI renders
// unknown distinctly, never as a pass. Blocked is the devices-row enforcement
// fact and is surfaced even when the backing report has gone stale (the device
// IS still excluded until the sweep clears it — hiding that would lie).
type HealthInfo struct {
	State         string // compliant | noncompliant | unknown
	Blocked       bool
	OSVersion     string
	DiskEncrypted *bool
	FailedChecks  []FailedCheck
	ReportedAt    *time.Time
}

// healthInfoFor computes the projection from a device row + its (possibly
// absent) health snapshot. Pure — unit-testable without a DB. failed_checks are
// surfaced only from a FRESH report: a stale report's failures are no longer a
// current claim (its state is unknown), but its raw facts stay visible.
func healthInfoFor(blocked bool, evaluatedState *string, failedChecks []byte,
	osVersion *string, diskEncrypted *bool, reportedAt *time.Time, now time.Time) HealthInfo {
	info := HealthInfo{State: "unknown", Blocked: blocked, DiskEncrypted: diskEncrypted,
		FailedChecks: []FailedCheck{}, ReportedAt: reportedAt}
	if osVersion != nil {
		info.OSVersion = *osVersion
	}
	if evaluatedState != nil && reportedAt != nil && now.Sub(*reportedAt) <= HealthStaleTTL {
		info.State = *evaluatedState
		_ = json.Unmarshal(failedChecks, &info.FailedChecks)
	}
	return info
}

// healthSurfaceActive reports whether the org has opted into ANY posture check —
// the gate for surfacing per-device health on list responses. An org that never
// opted in sees NO posture fields (no "unknown" noise on a feature it doesn't
// use); once a check exists, unknown devices MUST show as unknown (absence is
// not compliance).
//
// A config-read ERROR is PROPAGATED, never swallowed to false: silently omitting
// the surface would render an actively-blocked device as ordinary (no "posture
// blocked" badge) — a transient error reading as all-clear, the reassuring-green
// class this project fails toward showing (the S7.5.1 green-while-empty / S7.5.2
// transient-fetch law). The caller surfaces it as a retriable list failure.
func (s *Service) healthSurfaceActive(ctx context.Context, orgID uuid.UUID) (bool, error) {
	rows, err := s.q.ListOrgHealthChecks(ctx, orgID)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// deviceHealthProjection is the SINGLE per-row health attach (used by all three
// list surfaces so a health-field change is one edit, not three — the 7-arg
// healthInfoFor call lives here only). nil when the surface is inactive.
func (s *Service) deviceHealthProjection(surfaceHealth bool, blocked bool, evaluatedState *string,
	failedChecks []byte, osVersion *string, diskEncrypted *bool, reportedAt pgtype.Timestamptz, now time.Time) *HealthInfo {
	if !surfaceHealth {
		return nil
	}
	h := healthInfoFor(blocked, evaluatedState, failedChecks, osVersion, diskEncrypted, tsPtr(reportedAt), now)
	return &h
}

// ReleaseAllHealthBlocks frees EVERY posture-blocked device (the [1] downgrade-
// release fix). Called at open-build boot: when device-health is OFF, no report
// will ever arrive and the staleness sweeper never runs, so a device left
// health_blocked by a prior enterprise deployment would be excluded from every
// gateway FOREVER (silent permanent network loss). Disabling a feature must
// RELEASE its enforcement — the downgrade mirror of unlock-then-opt-in. Audited
// (system actor, cause posture_disabled) + pushes each affected org. Idempotent.
func (s *Service) ReleaseAllHealthBlocks(ctx context.Context) (int, error) {
	var cleared []sqlc.ClearAllHealthBlocksRow
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		rows, e := q.ClearAllHealthBlocks(ctx)
		if e != nil {
			return e
		}
		cleared = rows
		for _, r := range rows {
			if e := auditSystem(ctx, q, r.OrgID, "device.health_unblocked", "device", r.ID.String(),
				map[string]any{"cause": "posture_disabled"}); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	orgs := map[uuid.UUID]bool{}
	for _, r := range cleared {
		if !orgs[r.OrgID] {
			orgs[r.OrgID] = true
			s.PushOrgNodes(ctx, r.OrgID)
		}
	}
	if len(cleared) > 0 {
		s.logger.Info("health_blocks_released_on_downgrade", slog.Int("count", len(cleared)))
	}
	return len(cleared), nil
}

// auditSystem writes a system-actor audit row (0027) in the caller's tx — used
// for evaluation-driven flips where no human is the actor; metadata carries the
// CAUSE ("blocked by device-health because …").
func auditSystem(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, action, targetType, targetID string, meta map[string]any) error {
	b := []byte("{}")
	if meta != nil {
		b, _ = json.Marshal(meta)
	}
	as := healthActorSystem
	_, err := q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{
		OrgID: pgtype.UUID{Bytes: [16]byte(orgID), Valid: true}, ActorSystem: &as,
		Action: action, TargetType: &targetType, TargetID: &targetID, Metadata: b,
	})
	return err
}

// ReportHealth ingests one device self-report: verifies ownership (self-report
// only — the same ownership rule as device creation), evaluates against the
// org's checks, persists the snapshot, flips health_blocked on a transition,
// audits the transition, and pushes org-wide when enforcement changed.
func (s *Service) ReportHealth(ctx context.Context, orgID, actorID, deviceID uuid.UUID, facts HealthFacts) (HealthEvaluation, error) {
	if !validPlatforms[facts.Platform] {
		return HealthEvaluation{}, apierr.BadRequest("invalid_request", "platform must be macos, windows, linux or other")
	}
	if strings.TrimSpace(facts.OSVersion) == "" {
		return HealthEvaluation{}, apierr.BadRequest("invalid_request", "os_version is required")
	}

	checks, err := s.ListHealthChecks(ctx, orgID)
	if err != nil {
		return HealthEvaluation{}, err
	}
	ev := evaluateHealth(checks, facts)

	var blockChanged bool
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		dev, e := q.GetDevice(ctx, sqlc.GetDeviceParams{ID: deviceID, OrgID: orgID})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("device_not_found", "device not found")
		}
		if e != nil {
			return e
		}
		// ⛔ POSTURE IS A HUMAN-ENDPOINT CONTROL AND AN AGENT CANNOT PARTICIPATE IN IT — MEASURED, NOT
		// ASSUMED. An agent has no desktop client and no helper: it runs plain `wg-quick`, so it can never
		// self-report disk encryption or an OS version. Nothing about it is ever knowable here.
		//
		// The owner check below does NOT stop this, and that is the whole point. An agent's `user_id` is the
		// ADMIN WHO CREATED IT, so the admin passes the self-report gate and can post posture facts about a
		// machine they have never seen. On the live rig this produced, end to end:
		//
		//   report {"disk_encrypted": false}  ->  {"blocked": true}
		//   devices.health_blocked = true  ->  `NOT d.health_blocked` in ListActiveWireGuardPeersForNode
		//   ->  the agent's peer LEFT wg0 (peer count 1 -> 0)  ->  every granted request dead
		//
		// ⚠ A HUMAN-ENDPOINT CONTROL REACHED ALL THE WAY TO AN AGENT'S DATA PLANE, through a gate that was
		// written for humans and is satisfied by an owner who is not the machine. Refused here rather than
		// filtered downstream: the block must not be WRITABLE, because a stale `health_blocked = true` on an
		// agent row would keep killing its tunnel long after any filter was added.
		if dev.Kind == "agent" {
			return apierr.New(422, "posture_not_applicable",
				"this is an AI agent, not a user endpoint: it has no client to report posture and cannot be "+
					"evaluated against device health checks")
		}
		// Self-report ONLY: posture facts come from the device's owner, never a
		// third party (an admin has no better view of the machine than its owner).
		if dev.UserID != actorID {
			return apierr.New(403, "forbidden", "only the device owner may report its health")
		}
		if dev.Status == "revoked" {
			return apierr.Conflict("device_revoked", "device is revoked")
		}

		// Prior evaluated state (absence => treated as compliant baseline for
		// transition auditing — first noncompliant report still audits).
		priorState := "compliant"
		if prior, e := q.GetDeviceHealth(ctx, deviceID); e == nil {
			priorState = prior.EvaluatedState
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}

		fc, _ := json.Marshal(ev.FailedChecks)
		collected := pgtype.Timestamptz{}
		if facts.CollectedAt != nil {
			collected = pgtype.Timestamptz{Time: *facts.CollectedAt, Valid: true}
		}
		if _, e := q.UpsertDeviceHealth(ctx, sqlc.UpsertDeviceHealthParams{
			DeviceID: deviceID, Platform: facts.Platform, OsVersion: facts.OSVersion,
			// nil = fact reported absent (client couldn't read it) — stored NULL.
			DiskEncrypted: facts.DiskEncrypted, EvaluatedState: ev.State,
			FailedChecks: fc, CollectedAt: collected,
		}); e != nil {
			return e
		}

		meta := map[string]any{
			"owner": dev.UserID.String(), "platform": facts.Platform,
			"failed_checks": ev.FailedChecks,
		}
		if ev.Blocked != dev.HealthBlocked {
			blockChanged = true
			if _, e := q.SetDeviceHealthBlocked(ctx, sqlc.SetDeviceHealthBlockedParams{
				ID: deviceID, HealthBlocked: ev.Blocked,
			}); e != nil {
				return e
			}
			action, cause := "device.health_blocked", "noncompliant_report"
			if !ev.Blocked {
				action, cause = "device.health_unblocked", "compliant_report"
			}
			meta["cause"] = cause
			return auditSystem(ctx, q, orgID, action, "device", deviceID.String(), meta)
		}
		// No enforcement flip: audit only a warn-level state TRANSITION (the
		// S7.5.2 idempotent no-flood discipline — steady state writes nothing).
		if ev.State != priorState {
			action := "device.health_noncompliant"
			if ev.State == "compliant" {
				action = "device.health_compliant"
			}
			return auditSystem(ctx, q, orgID, action, "device", deviceID.String(), meta)
		}
		return nil
	})
	if err != nil {
		return HealthEvaluation{}, err
	}
	if blockChanged {
		// Org-wide (the S7.3/F1 pin): the device's /32 may be a group-resolved
		// DESTINATION on gateways that don't host it.
		s.PushOrgNodes(ctx, orgID)
	}
	return ev, nil
}

// ListHealthChecks returns the org's configured (opted-in) checks.
func (s *Service) ListHealthChecks(ctx context.Context, orgID uuid.UUID) ([]HealthCheckConfig, error) {
	rows, err := s.q.ListOrgHealthChecks(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]HealthCheckConfig, 0, len(rows))
	for _, r := range rows {
		out = append(out, HealthCheckConfig{Kind: r.CheckKind, Mode: r.Mode, Param: r.Param})
	}
	return out, nil
}

// SetHealthCheck opts the org into a check (or updates its mode/param), audited.
// The config write NEVER flips any device's gate (D4 grandfather: only a device's
// own next evaluation does) — the returned wouldFail is the best-effort,
// post-commit blast radius: devices whose LAST report would fail this check.
func (s *Service) SetHealthCheck(ctx context.Context, actor, orgID uuid.UUID, kind, mode string, param json.RawMessage) (wouldFail int64, err error) {
	if err := validateHealthCheck(kind, mode, param); err != nil {
		return 0, err
	}
	var paramB []byte
	if len(param) > 0 && string(param) != "null" {
		paramB = param
	}
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		if _, e := q.UpsertOrgHealthCheck(ctx, sqlc.UpsertOrgHealthCheckParams{
			OrgID: orgID, CheckKind: kind, Mode: mode, Param: paramB,
		}); e != nil {
			return e
		}
		return audit(ctx, q, orgID, &actor, "org.health_check_set", "organization", orgID.String(),
			map[string]any{"check_kind": kind, "mode": mode, "param": json.RawMessage(paramOrNull(paramB))})
	})
	if err != nil {
		return 0, err
	}
	// Best-effort AFTER commit (the S7.3 pass-4 #A lesson: a committed setting
	// flip never fails on the count query).
	cfg := HealthCheckConfig{Kind: kind, Mode: mode, Param: paramB}
	if rows, e := s.q.ListDeviceHealthForOrg(ctx, orgID); e != nil {
		s.logger.Warn("health_would_fail_count_failed_after_commit",
			slog.String("org_id", orgID.String()), slog.String("error", e.Error()))
	} else {
		now := time.Now()
		for _, r := range rows {
			// STALE reports don't count ([5]): a device gone silent past the TTL is
			// posture_unknown, not blocked, and will never report again — counting its
			// old non-compliant report would overstate a blast radius that models honesty.
			// Only devices that WILL actually be gated (a fresh report) are counted.
			if now.Sub(r.ReportedAt) > HealthStaleTTL {
				continue
			}
			f := HealthFacts{Platform: r.Platform, OSVersion: r.OsVersion, DiskEncrypted: r.DiskEncrypted}
			if v := evaluateHealth([]HealthCheckConfig{cfg}, f); v.State == "noncompliant" {
				wouldFail++
			}
		}
	}
	return wouldFail, nil
}

func paramOrNull(b []byte) []byte {
	if len(b) == 0 {
		return []byte("null")
	}
	return b
}

// DeleteHealthCheck opts the org out of a check (idempotent; audited only when a
// row was actually removed). Devices blocked by the removed check unblock on
// their NEXT report (≤ one report interval) — the same only-evaluation-flips-
// gates rule that protects the fleet on enable protects consistency on disable.
func (s *Service) DeleteHealthCheck(ctx context.Context, actor, orgID uuid.UUID, kind string) error {
	if kind != CheckOSVersion && kind != CheckDiskEncryption {
		return apierr.BadRequest("invalid_request", "check kind must be os_version or disk_encryption")
	}
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		n, e := q.DeleteOrgHealthCheck(ctx, sqlc.DeleteOrgHealthCheckParams{OrgID: orgID, CheckKind: kind})
		if e != nil {
			return e
		}
		if n == 0 {
			return nil // already off — idempotent, nothing to audit
		}
		return audit(ctx, q, orgID, &actor, "org.health_check_cleared", "organization", orgID.String(),
			map[string]any{"check_kind": kind})
	})
}

// SweepStaleHealthBlocks clears health_blocked wherever the backing report has
// gone stale (D4: staleness = absence, and absence never blocks — a device that
// goes SILENT is posture_unknown, not blocked; evasion-by-silence is accepted in
// the threat model because a liar defeats blocking anyway). Audited per device
// (system actor), then each affected org is pushed. Returns the cleared count.
func (s *Service) SweepStaleHealthBlocks(ctx context.Context) (int, error) {
	ttl := pgtype.Interval{Microseconds: HealthStaleTTL.Microseconds(), Valid: true}
	var cleared []sqlc.ClearStaleHealthBlocksRow
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		rows, e := q.ClearStaleHealthBlocks(ctx, ttl)
		if e != nil {
			return e
		}
		cleared = rows
		for _, r := range rows {
			if e := auditSystem(ctx, q, r.OrgID, "device.health_unblocked", "device", r.ID.String(),
				map[string]any{"cause": "report_stale"}); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	orgs := map[uuid.UUID]bool{}
	for _, r := range cleared {
		if !orgs[r.OrgID] {
			orgs[r.OrgID] = true
			s.PushOrgNodes(ctx, r.OrgID)
		}
	}
	return len(cleared), nil
}

// StartHealthSweeper runs the staleness sweep on an interval until ctx ends.
// Started only when the device-health edition is enabled (main.go); the sweep is
// cheap when nothing is blocked. First run is one interval out (boot is not a
// posture event).
// mayTick gates each sweep on scheduler leadership (S13.1 review #10): it clears health_blocked rows and pushes the
// affected orgs, so N replicas means N concurrent clear-and-push cycles. nil = ungated (tests).
func (s *Service) StartHealthSweeper(ctx context.Context, mayTick func() bool) {
	t := time.NewTicker(HealthSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if mayTick != nil && !mayTick() {
				continue // followers serve requests but never tick
			}
			if n, err := s.SweepStaleHealthBlocks(ctx); err != nil {
				s.logger.Warn("health_stale_sweep_failed", slog.String("error", err.Error()))
			} else if n > 0 {
				s.logger.Info("health_stale_sweep_cleared", slog.Int("count", n))
			}
		}
	}
}

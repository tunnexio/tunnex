package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccessEventRetentionHardeningMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0130_access_event_retention_hardening.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0130_access_event_retention_hardening.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL, downSQL := string(up), string(down)
	for _, want := range []string{
		"access_event_retention_authorizations",
		"access_event_retention_authorized(target_access_event uuid)",
		"access_event_retention_prune_batch(target_run uuid)",
		"SECURITY DEFINER SET search_path=public,pg_temp",
		"REVOKE ALL ON FUNCTION access_event_retention_authorized(uuid) FROM PUBLIC",
		"REVOKE ALL ON FUNCTION access_event_retention_prune_batch(uuid) FROM PUBLIC",
		"CREATE TRIGGER access_events_delete_guard",
		"CREATE TRIGGER access_events_truncate_guard",
		"CREATE TRIGGER access_event_retention_runs_lease_guard_before_update",
		"CREATE TRIGGER audit_log_retention_runs_lease_guard_before_update",
		"access_event_retention_run_lease_guard()",
		"audit_log_retention_run_lease_guard()",
		"guard_time := clock_timestamp()",
		"NEW.lease_expires_at := guard_time + interval '15 minutes'",
		"NEW.completed_at := GREATEST(guard_time,OLD.started_at)",
		"NEW.deleted_rows := OLD.deleted_rows",
		"NEW.batches := OLD.batches",
		"NEW.deleted_rows - OLD.deleted_rows <= OLD.batch_size",
		"NEW.deleted_rows - OLD.deleted_rows = (",
		"requested_by.id=OLD.requested_by_user_id",
		"REVOKE ALL ON FUNCTION access_event_retention_run_lease_guard() FROM PUBLIC",
		"REVOKE ALL ON FUNCTION audit_log_retention_run_lease_guard() FROM PUBLIC",
		"access_events_delete_not_authorized",
		"organization.id=OLD.org_id",
		"FOR UPDATE OF organization",
		"validation_time := clock_timestamp()",
		"run.lease_expires_at > validation_time",
		"run.retention_days=COALESCE(setting.retention_days,30)",
		"run.cleanup_interval_minutes=COALESCE(setting.cleanup_interval_minutes,60)",
		"run.settings_revision=COALESCE(setting.revision,0)",
		"CREATE TABLE access_event_retention_state",
		"LOCK TABLE organizations IN EXCLUSIVE MODE",
		"LOCK TABLE access_events IN SHARE ROW EXCLUSIVE MODE",
		"REFERENCING NEW TABLE AS inserted_events",
		"REFERENCING OLD TABLE AS deleted_events",
		"COALESCE(state.retained_rows,0)",
		"authorized_count=0 AND current_rows > protected_rows",
		"event.created_at < older_than",
		"WITH boundary AS MATERIALIZED",
		"CROSS JOIN boundary",
		"OFFSET protected_rows",
		"deleted_rows=run.deleted_rows + deleted_count",
		"batches=run.batches + 1",
		"membership.access_revoked_at IS NULL",
		"CREATE OR REPLACE FUNCTION audit_log_retention_prune_batch(target_run uuid)",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("0130 up missing %q", want)
		}
	}
	for _, want := range []string{
		"DROP TRIGGER access_events_truncate_guard ON access_events",
		"DROP TRIGGER access_events_delete_guard ON access_events",
		"DROP TRIGGER access_event_retention_runs_lease_guard_before_update ON access_event_retention_runs",
		"DROP TRIGGER audit_log_retention_runs_lease_guard_before_update ON audit_log_retention_runs",
		"DROP TRIGGER access_event_retention_state_delete ON access_events",
		"DROP TRIGGER access_event_retention_state_insert ON access_events",
		"DROP FUNCTION access_event_retention_prune_batch(uuid)",
		"DROP TABLE access_event_retention_authorizations",
		"DROP TABLE access_event_retention_state",
		"run.lease_expires_at > statement_timestamp()",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("0130 down missing %q", want)
		}
	}
	if strings.Contains(upSQL, "run.lease_expires_at > statement_timestamp()") {
		t.Fatal("0130 up validates a lease against a timestamp frozen before lock acquisition")
	}
	if strings.Count(upSQL, "WHERE requested_by.id=OLD.requested_by_user_id") != 2 {
		t.Fatal("0130 up must preserve the narrow requested-by user FK action for both retention run tables")
	}
	rootLock := strings.Index(upSQL, "LOCK TABLE organizations IN EXCLUSIVE MODE")
	eventLock := strings.Index(upSQL, "LOCK TABLE access_events IN SHARE ROW EXCLUSIVE MODE")
	firstChildChange := strings.Index(upSQL, "CREATE OR REPLACE FUNCTION access_event_retention_settings_actor_require_membership")
	if rootLock < 0 || eventLock < 0 || firstChildChange < 0 || rootLock > eventLock || eventLock > firstChildChange {
		t.Fatal("0130 up must lock organizations then access_events before child trigger/function/table changes")
	}
	if strings.Count(upSQL, "LOCK TABLE access_events IN SHARE ROW EXCLUSIVE MODE") != 1 {
		t.Fatal("0130 up must acquire the access_events migration fence exactly once")
	}
	downRootLock := strings.Index(downSQL, "LOCK TABLE organizations IN EXCLUSIVE MODE")
	downChildLock := strings.Index(downSQL, "LOCK TABLE access_event_retention_runs")
	if downRootLock < 0 || downChildLock < 0 || downRootLock > downChildLock {
		t.Fatal("0130 down must acquire the organizations EXCLUSIVE lock before child locks")
	}
}

func TestAccessEventRetentionHardeningMigrationOrder(t *testing.T) {
	for _, direction := range []string{"up", "down"} {
		matches, err := filepath.Glob(filepath.Join("migrations", "0130_*."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		want := "0130_access_event_retention_hardening." + direction + ".sql"
		if len(matches) != 1 || filepath.Base(matches[0]) != want {
			t.Fatalf("0130 %s migration must be unique and ordered after 0129, found %v", direction, matches)
		}
	}
}

package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccessEventIdentityFilterMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0128_access_event_identity_filters.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0128_access_event_identity_filters.down.sql")
	if err != nil {
		t.Fatal(err)
	}

	upSQL := string(up)
	for _, want := range []string{
		"DROP INDEX access_events_org_agent_created_id_idx",
		"access_events_org_device_created_id_idx",
		"(org_id, src_device_id, created_at DESC, id DESC)",
		"WHERE src_device_id IS NOT NULL",
		"access_events_org_user_created_id_idx",
		"(org_id, src_user_id, created_at DESC, id DESC)",
		"WHERE src_user_id IS NOT NULL",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("0128 up missing %q", want)
		}
	}
	downSQL := string(down)
	for _, want := range []string{
		"DROP INDEX access_events_org_user_created_id_idx",
		"DROP INDEX access_events_org_device_created_id_idx",
		"CREATE INDEX access_events_org_agent_created_id_idx",
		"WHERE src_kind = 'agent'",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("0128 down missing %q", want)
		}
	}
	for direction, sql := range map[string]string{"up": upSQL, "down": downSQL} {
		upper := strings.ToUpper(sql)
		for _, forbidden := range []string{
			"ALTER TABLE",
			"INSERT INTO ACCESS_EVENTS",
			"UPDATE ACCESS_EVENTS",
			"DELETE FROM ACCESS_EVENTS",
		} {
			if strings.Contains(upper, forbidden) {
				t.Fatalf("0128 %s must be an index-only migration; found %q", direction, forbidden)
			}
		}
	}
}

func TestAccessEventIdentityFilterMigrationOrder(t *testing.T) {
	for _, direction := range []string{"up", "down"} {
		predecessor, err := filepath.Glob(filepath.Join("migrations", "0127_*."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if len(predecessor) != 1 {
			t.Fatalf("0128 requires exactly one 0127 %s predecessor, found %v", direction, predecessor)
		}
		matches, err := filepath.Glob(filepath.Join("migrations", "0128_*."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || filepath.Base(matches[0]) != "0128_access_event_identity_filters."+direction+".sql" {
			t.Fatalf("0128 %s migration must be unique and ordered after 0127, found %v", direction, matches)
		}
	}
}

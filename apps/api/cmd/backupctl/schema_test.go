package main

import "testing"

func TestBackupSchemaCeiling(t *testing.T) {
	latest, err := supportedSchemaVersion()
	if err != nil || latest < 173 {
		t.Fatalf("embedded ceiling unavailable: %d %v", latest, err)
	}
	for _, v := range []int64{1, 172, int64(latest)} {
		if err := validateBackupSchemaVersion(v); err != nil {
			t.Fatalf("supported %d: %v", v, err)
		}
	}
	for _, v := range []int64{-1, 0, int64(latest) + 1, 1 << 62} {
		if validateBackupSchemaVersion(v) == nil {
			t.Fatalf("unsupported schema accepted: %d", v)
		}
	}
}
func TestRecoverySchemaRequiresCleanSupportedBoundary(t *testing.T) {
	latest, err := supportedSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		version                               uint
		dirty, initialized, upgraded, allowed bool
	}{
		{172, false, true, false, true}, {latest, false, true, false, true}, {latest, false, true, true, true},
		{172, false, true, true, false}, {latest, true, true, false, false}, {latest, false, false, false, false},
		{0, false, true, false, false}, {latest + 1, false, true, false, false}, {latest + 1, false, true, true, false},
	} {
		if got := validateRecoverySchema(c.version, c.dirty, c.initialized, c.upgraded) == nil; got != c.allowed {
			t.Fatalf("boundary %+v accepted=%v", c, got)
		}
	}
}

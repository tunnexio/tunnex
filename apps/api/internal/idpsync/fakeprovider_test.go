package idpsync

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeDir(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "dir.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileDirectory_ListMapsStatusAndGone(t *testing.T) {
	p := writeDir(t, `{"groups":{"grp-eng":[
		{"external_id":"u-alice","email":"Alice@Acme.test","status":"active"},
		{"external_id":"u-bob","email":"bob@acme.test","status":"disabled"}
	]}}`)
	d := NewFileDirectory(p)

	got, err := d.ListGroupMembers(context.Background(), "grp-eng")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 || got[0].Email != "alice@acme.test" || got[0].Status != StatusActive || got[1].Status != StatusDisabled {
		t.Fatalf("unexpected members: %+v", got)
	}

	// A group key that is absent → ErrGroupGone (the box-walk "delete the group" leg).
	if _, err := d.ListGroupMembers(context.Background(), "grp-missing"); err != ErrGroupGone {
		t.Fatalf("missing group: want ErrGroupGone, got %v", err)
	}
}

func TestFileDirectory_ReReadsBetweenCalls(t *testing.T) {
	p := writeDir(t, `{"groups":{"g":[{"external_id":"u1","email":"u1@t.test","status":"active"}]}}`)
	d := NewFileDirectory(p)
	if m, _ := d.ListGroupMembers(context.Background(), "g"); len(m) != 1 {
		t.Fatalf("pre-edit want 1 member, got %d", len(m))
	}
	// Mutate the "directory" — the walk's remove-a-member leg — and re-read.
	if err := os.WriteFile(p, []byte(`{"groups":{"g":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if m, _ := d.ListGroupMembers(context.Background(), "g"); len(m) != 0 {
		t.Fatalf("post-edit want 0 members, got %d", len(m))
	}
}

func TestFileDirectory_ResolveUserStatus(t *testing.T) {
	p := writeDir(t, `{"groups":{"g":[{"external_id":"u1","email":"u1@t.test","status":"disabled"}]}}`)
	d := NewFileDirectory(p)
	if s, _ := d.ResolveUserStatus(context.Background(), "u1"); s != StatusDisabled {
		t.Fatalf("u1: want disabled, got %v", s)
	}
	if s, _ := d.ResolveUserStatus(context.Background(), "u-nobody"); s != StatusGone {
		t.Fatalf("absent user: want gone, got %v", s)
	}
}

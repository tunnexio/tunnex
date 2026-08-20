package hostupgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRequestAuditsBeforePublishingExactTarget(t *testing.T) {
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request")
	statusPath := filepath.Join(dir, "status")
	actor := uuid.New()
	audited := false
	svc := New(requestPath, statusPath, func(_ context.Context, gotActor, requestID uuid.UUID, target Target) error {
		audited = true
		if gotActor != actor || requestID == uuid.Nil || target.Sequence != 9 {
			t.Fatalf("bad audit attribution: actor=%s request=%s target=%+v", gotActor, requestID, target)
		}
		if _, err := os.Stat(requestPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("watched request became visible before its audit committed")
		}
		return nil
	})
	svc.now = func() time.Time { return time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC) }
	target := Target{SourceSHA: strings.Repeat("a", 40), Version: "v9.0.0", Sequence: 9}
	status, created, err := svc.Request(context.Background(), actor, target)
	if err != nil || !created || !audited || status.State != "requested" {
		t.Fatalf("request = (%+v,%v,%v), audited=%v", status, created, err, audited)
	}
	body, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"source_sha=" + target.SourceSHA, "target_version=v9.0.0", "sequence=9", "requested_by=" + actor.String()} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("request omitted %q: %s", want, body)
		}
	}
	leftovers, err := filepath.Glob(requestPath + ".pending.*")
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("staging requests left behind: %v, %v", leftovers, err)
	}
}

func TestStatusPrefersCurrentPendingRequestOverStaleResult(t *testing.T) {
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request")
	statusPath := filepath.Join(dir, "status")
	oldID := uuid.New()
	if err := os.WriteFile(statusPath, []byte("request_id="+oldID.String()+"\nstate=healthy\ntarget_source_sha="+strings.Repeat("a", 40)+"\ntarget_version=v1\nbackup_dump=old.dump\nbackup_manifest=old.json\nreason_code=\nupdated_at=2026-08-20T00:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(requestPath, statusPath, func(context.Context, uuid.UUID, uuid.UUID, Target) error { return nil })
	target := Target{SourceSHA: strings.Repeat("b", 40), Version: "v2", Sequence: 2}
	requested, _, err := svc.Request(context.Background(), uuid.New(), target)
	if err != nil {
		t.Fatal(err)
	}
	status, err := svc.Status()
	if err != nil || status.RequestID != requested.RequestID || status.State != "requested" || status.TargetVersion != "v2" {
		t.Fatalf("status = (%+v, %v), want current pending request", status, err)
	}
}

func TestRequestDoesNotPublishWhenAuditFails(t *testing.T) {
	dir := t.TempDir()
	svc := New(filepath.Join(dir, "request"), filepath.Join(dir, "status"), func(context.Context, uuid.UUID, uuid.UUID, Target) error {
		return errors.New("database unavailable")
	})
	_, _, err := svc.Request(context.Background(), uuid.New(), Target{SourceSHA: strings.Repeat("a", 40), Version: "v9", Sequence: 9})
	if err == nil || !strings.Contains(err.Error(), "audit host upgrade request") {
		t.Fatalf("expected audit refusal, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "request")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unaudited request was published")
	}
}

func TestRequestIgnoresCrashLeftoverPendingFile(t *testing.T) {
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request")
	if err := os.WriteFile(requestPath+".pending.crashed", []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(requestPath, filepath.Join(dir, "status"), func(context.Context, uuid.UUID, uuid.UUID, Target) error { return nil })
	if _, created, err := svc.Request(context.Background(), uuid.New(), Target{SourceSHA: strings.Repeat("a", 40), Version: "v9", Sequence: 9}); err != nil || !created {
		t.Fatalf("request after crash leftover = (%v, %v)", created, err)
	}
}

func TestStatusRejectsPathsAndUnknownState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status")
	base := "request_id=" + uuid.NewString() + "\ntarget_source_sha=" + strings.Repeat("a", 40) + "\ntarget_version=v9\nbackup_manifest=\nreason_code=\nupdated_at=2026-08-20T00:00:00Z\n"
	for _, body := range []string{
		base + "state=unknown\nbackup_dump=\n",
		base + "state=healthy\nbackup_dump=/host/private.dump\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readStatus(path); !errors.Is(err, ErrInvalid) {
			t.Fatalf("malformed status accepted: %v", err)
		}
	}
}

func TestReadRequestRejectsInvalidSignedFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "request")
	actor := uuid.NewString()
	body := "request_id=" + uuid.NewString() + "\nsource_sha=" + strings.Repeat("a", 40) + "\ntarget_version=v9\nsequence=1\nrequested_by=" + actor + "\ncreated_at=2026-08-20T00:00:00Z\n"
	for _, bad := range []string{
		strings.Replace(body, "source_sha="+strings.Repeat("a", 40), "source_sha="+strings.Repeat("A", 40), 1),
		strings.Replace(body, "sequence=1", "sequence=0", 1),
		strings.Replace(body, "requested_by="+actor, "requested_by=not-a-uuid", 1),
	} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readRequest(path); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid request accepted: %v", err)
		}
	}
}

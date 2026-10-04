package backup

import (
	"errors"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRestoreMarkerNeverReusesOldCompletion(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "app-access.pending.json")
	first, err := BeginAppRestore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = BeginAppRestore(path); err == nil {
		t.Fatal("existing barrier was overwritten")
	}
	_, identity, err := ReadAppRestore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = FinishAppRestore(path, uuid.New(), identity); err == nil {
		t.Fatal("foreign completion removed barrier")
	}
	if err = FinishAppRestore(path, first.ID, identity); err != nil {
		t.Fatal(err)
	}
	second, err := BeginAppRestore(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID {
		t.Fatal("restore marker reused")
	}
	if err = FinishAppRestore(path, first.ID, identity); err == nil {
		t.Fatal("old recovery removed new barrier")
	}
}

func TestRestoreMarkerRefusesSymlinkAndMalformedData(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "pending")
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadAppRestore(path); err == nil {
		t.Fatal("marker symlink accepted")
	}
	os.Remove(path)
	if err := os.WriteFile(path, []byte(`{"version":1,"id":"00000000-0000-0000-0000-000000000000","completed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadAppRestore(path); err == nil {
		t.Fatal("malformed old completion accepted")
	}
}

func TestConcurrentRestoreRecoveryPreservesNewBarrier(t *testing.T) {
	dir := t.TempDir()
	var err error
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending")
	old, err := BeginAppRestore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := ReadAppRestore(path)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	recovered := make(chan error, 1)
	go func() {
		recovered <- RecoverAppRestore(path, old.ID, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	// All three supported operator actions contend with the entire recovery,
	// not just its final unlink. An old finisher cannot unlink a new marker.
	began := make(chan AppRestoreMarker, 1)
	beginErr := make(chan error, 1)
	finished := make(chan error, 1)
	secondRecovery := make(chan error, 1)
	var secondCalls atomic.Int32
	go func() { m, e := BeginAppRestore(path); began <- m; beginErr <- e }()
	go func() { finished <- FinishAppRestore(path, old.ID, identity) }()
	go func() {
		secondRecovery <- RecoverAppRestore(path, old.ID, func() error { secondCalls.Add(1); return nil })
	}()
	select {
	case e := <-finished:
		t.Fatal("finish bypassed recovery lock", e)
	case e := <-secondRecovery:
		t.Fatal("second recovery bypassed lock", e)
	case e := <-beginErr:
		t.Fatal("begin bypassed recovery lock", e)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if e := <-recovered; e != nil {
		t.Fatal(e)
	}
	if e := <-beginErr; e != nil {
		t.Fatal("new begin", e)
	}
	fresh := <-began
	if e := <-finished; e == nil {
		t.Fatal("old finisher accepted newer/missing barrier")
	}
	if e := <-secondRecovery; e == nil || secondCalls.Load() != 0 {
		t.Fatal("old recovery ran against new barrier", e)
	}
	current, _, e := ReadAppRestore(path)
	if e != nil || current.ID != fresh.ID || fresh.ID == old.ID {
		t.Fatal("fresh barrier lost", e)
	}
	if _, e = os.Stat(filepath.Join(dir, ".app-access-restore.lock")); e != nil {
		t.Fatal("stable lock removed", e)
	}
}

func TestFailedRecoveryRetainsBarrierForRetry(t *testing.T) {
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "pending")
	marker, e := BeginAppRestore(path)
	if e != nil {
		t.Fatal(e)
	}
	failure := errors.New("fixture recovery failure")
	if e = RecoverAppRestore(path, marker.ID, func() error { return failure }); !errors.Is(e, failure) {
		t.Fatal(e)
	}
	current, _, e := ReadAppRestore(path)
	if e != nil || current.ID != marker.ID {
		t.Fatal("failed recovery removed barrier", e)
	}
	if e = RecoverAppRestore(path, marker.ID, func() error { return nil }); e != nil {
		t.Fatal("retry", e)
	}
	if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("successful retry did not finish", e)
	}
}

func TestRecoveryUnsafeParentRefusesBeforeCallback(t *testing.T) {
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "pending")
	marker, e := BeginAppRestore(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0777); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(dir, 0700)
	var calls int
	if e = RecoverAppRestore(path, marker.ID, func() error { calls++; return nil }); e == nil || calls != 0 {
		t.Fatal("unsafe parent ran recovery", e, calls)
	}
	if _, _, e = ReadAppRestore(path); e != nil {
		t.Fatal("refusal removed marker", e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if e = os.Symlink(dir, alias); e != nil {
		t.Fatal(e)
	}
	if e = RecoverAppRestore(filepath.Join(alias, "pending"), marker.ID, func() error { calls++; return nil }); e == nil || calls != 0 {
		t.Fatal("symlink parent ran recovery", e, calls)
	}
}

func TestAuthorityMutationGuardSerializesRestoreBegin(t *testing.T) {
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "pending")
	entered, release := make(chan struct{}), make(chan struct{})
	mutated := make(chan error, 1)
	go func() { mutated <- WithAppRestoreGuard(path, func() error { close(entered); <-release; return nil }) }()
	<-entered
	began := make(chan AppRestoreMarker, 1)
	beginErr := make(chan error, 1)
	go func() { m, e := BeginAppRestore(path); began <- m; beginErr <- e }()
	select {
	case e := <-beginErr:
		t.Fatal("restore crossed authority mutation", e)
	case <-time.After(50 * time.Millisecond):
	}
	if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("marker appeared during guarded mutation", e)
	}
	close(release)
	if e := <-mutated; e != nil {
		t.Fatal(e)
	}
	if e := <-beginErr; e != nil {
		t.Fatal(e)
	}
	fresh := <-began
	var calls int
	if e := WithAppRestoreGuard(path, func() error { calls++; return nil }); e == nil || calls != 0 {
		t.Fatal("existing barrier permitted authority mutation", e, calls)
	}
	current, _, e := ReadAppRestore(path)
	if e != nil || current.ID != fresh.ID {
		t.Fatal("authority refusal removed barrier", e)
	}
}

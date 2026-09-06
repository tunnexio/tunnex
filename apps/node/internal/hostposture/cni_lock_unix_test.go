//go:build linux || darwin

package hostposture

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCNIOperationLockSerializesGatewayAndRevocation(t *testing.T) {
	writer, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenStore(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	j := cniTestJournal(t, 3, now)
	h := cniTestHeartbeat(now, 1)
	saveCNITestPair(t, writer, j, h)
	if _, release, err := reader.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now); err == nil || release != nil {
		t.Fatal("first proof admitted")
	}
	h.Sequence++
	saveCNITestPair(t, writer, j, h)
	_, releaseGateway, err := reader.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseGateway()
	before, err := os.ReadFile(writer.CNIAuthorityPath())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if release, err := writer.AcquireCNIOperationLock(ctx); err == nil || !errors.Is(err, context.DeadlineExceeded) || release != nil {
		t.Fatalf("held gateway lock did not bound manager acquisition: %v", err)
	}
	after, _ := os.ReadFile(writer.CNIAuthorityPath())
	if !bytes.Equal(before, after) {
		t.Fatal("blocked manager changed public authority")
	}
	done := make(chan error, 1)
	go func() {
		release, err := writer.AcquireCNIOperationLock(t.Context())
		if err != nil {
			done <- err
			return
		}
		defer release()
		done <- writer.RevokeCNIAuthority()
	}()
	select {
	case err := <-done:
		t.Fatalf("revocation raced held gateway operation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	releaseGateway()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("manager did not resume after release")
	}
	if _, release, err := reader.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now); err == nil || release != nil {
		t.Fatal("post-cleanup operation used cached authority")
	}
}

func TestCNIOperationLockMissingSymlinkAndMalformedFilesRefuseWithoutWrites(t *testing.T) {
	dir := t.TempDir()
	reader, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if release, err := reader.AcquireCNIOperationLock(t.Context()); err == nil || release != nil {
		t.Fatal("gateway created missing manager lock")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("read-only lock acquisition wrote files")
	}
	foreign := filepath.Join(t.TempDir(), "foreign")
	if err := os.WriteFile(foreign, []byte("foreign bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, reader.CNIOperationLockPath()); err != nil {
		t.Fatal(err)
	}
	if release, err := reader.AcquireCNIOperationLock(t.Context()); err == nil || release != nil {
		t.Fatal("symlink lock accepted")
	}
	if _, err := NewStore(dir); err == nil {
		t.Fatal("manager adopted malformed existing lock")
	}
	got, _ := os.ReadFile(foreign)
	if string(got) != "foreign bytes" {
		t.Fatal("foreign file changed")
	}
}

func TestCNIOperationLockHasBackgroundDeadline(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	release, err := store.AcquireCNIOperationLock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	start := time.Now()
	if other, err := store.AcquireCNIOperationLock(context.Background()); err == nil || other != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("background acquisition unbounded: %v", err)
	}
	if elapsed := time.Since(start); elapsed < CNIOperationLockTimeout || elapsed > CNIOperationLockTimeout+2*time.Second {
		t.Fatalf("background bound elapsed=%v", elapsed)
	}
}

func TestCNILockActualReadOnlyMount(t *testing.T) {
	rw, ro := os.Getenv("TUNNEX_TEST_POSTURE_RW"), os.Getenv("TUNNEX_TEST_POSTURE_RO")
	if rw == "" || ro == "" {
		t.Skip("requires isolated Linux fixture with one directory mounted RW and RO")
	}
	writer, err := NewStore(rw)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenStore(ro)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := os.OpenFile(reader.CNIOperationLockPath(), os.O_WRONLY, 0); err == nil {
		_ = f.Close()
		t.Fatal("fixture is not actually read-only")
	}
	now := time.Unix(1000, 0)
	j := cniTestJournal(t, 3, now)
	h := cniTestHeartbeat(now, 1)
	saveCNITestPair(t, writer, j, h)
	if _, release, err := reader.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now); err == nil || release != nil {
		t.Fatal("one proof admitted")
	}
	h.Sequence++
	saveCNITestPair(t, writer, j, h)
	_, release, err := reader.AcquireCNIAuthority(t.Context(), "worker-a", testOwner().UID, now)
	if err != nil {
		t.Fatalf("read-only mount cannot acquire authority flock: %v", err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if other, err := writer.AcquireCNIOperationLock(ctx); err == nil || other != nil {
		t.Fatal("RO and RW views do not serialize on the same inode")
	}
}

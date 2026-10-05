package sandboxes

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSandboxLifecycleLeasePostgresSerializesAndReleases(t *testing.T) {
	f := newFixture(t)
	id := uuid.New()
	_, release, err := f.store.acquireLifecycle(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.acquireLifecycle(f.ctx, id); !errors.Is(err, ErrConflict) {
		release()
		t.Fatal("concurrent lifecycle admitted", err)
	}
	_, otherRelease, err := f.store.acquireLifecycle(f.ctx, uuid.New())
	if err != nil {
		release()
		t.Fatal("unrelated sandbox blocked", err)
	}
	otherRelease()
	release()
	_, againRelease, err := f.store.acquireLifecycle(f.ctx, id)
	if err != nil {
		t.Fatal("session lease not released", err)
	}
	againRelease()
}

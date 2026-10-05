package sandboxes

import (
	"context"
	"github.com/google/uuid"
	"testing"
)

func TestInitialLaunchMissingAdapters(t *testing.T) {
	for _, coordinator := range []*InitialLaunchCoordinator{nil, {}} {
		if err := coordinator.Reconcile(context.Background(), uuid.New()); err != ErrDisabled {
			t.Fatal("unqualified launch admitted", err)
		}
	}
}

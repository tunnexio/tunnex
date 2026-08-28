package policy

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

type fqdnInvalidatorNotifier struct{ got []uuid.UUID }

func (n *fqdnInvalidatorNotifier) NotifyMany(ids []uuid.UUID) {
	n.got = append([]uuid.UUID(nil), ids...)
}

func TestFQDNOptInChangePushesAllAffectedNodesAfterCommit(t *testing.T) {
	org := uuid.New()
	first, second := uuid.New(), uuid.New()
	notify := &fqdnInvalidatorNotifier{}
	invalidator := &FQDNInvalidator{
		notify: notify,
		activeNodeIDs: func(got context.Context, gotOrg uuid.UUID) ([]uuid.UUID, error) {
			if got == nil || gotOrg != org {
				t.Fatalf("active-node lookup context/org = %v/%s", got, gotOrg)
			}
			return []uuid.UUID{first, second}, nil
		},
	}

	invalidator.InvalidateOrg(context.Background(), org)
	if len(notify.got) != 2 || notify.got[0] != first || notify.got[1] != second {
		t.Fatalf("FQDN opt-in change did not wake every affected node: %v", notify.got)
	}
}

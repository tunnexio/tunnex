package sandboxes

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"testing"
)

func TestQualificationScopeRefusesOtherOrganizationBeforeDatabase(t *testing.T) {
	allowed := uuid.New()
	store := NewStore(nil).WithQualificationOrg(allowed)
	if _, _, err := store.Create(context.Background(), uuid.New(), uuid.New(), CreateInput{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("foreign organization reached admission: %v", err)
	}
}

package nodes

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestIssueOrdinaryBaseStopsBeforeAuthorityWriteOnLatestReadFailure(t *testing.T) {
	databaseReadErr := errors.New("latest authority database read failed")
	for _, test := range []struct {
		name    string
		readErr error
	}{
		{name: "stored conflict", readErr: ErrKubernetesOwnershipBaseAuthorityConflict},
		{name: "database failure", readErr: databaseReadErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			issue := ordinaryBaseAuthorityIssueFixture()
			siteID := uuid.MustParse(issue.Authority.SiteID)
			tx := &ordinaryBaseLatestReadFailureTx{siteID: siteID, readErr: test.readErr}

			result, err := issueKubernetesOwnershipBaseAuthorityTx(context.Background(), tx, issue)
			if !errors.Is(err, test.readErr) {
				t.Fatalf("issue error = %v, want %v", err, test.readErr)
			}
			if result.DeliveryID != uuid.Nil {
				t.Fatalf("failed prior read returned delivery %s", result.DeliveryID)
			}
			if tx.latestReads != 1 {
				t.Fatalf("latest authority reads = %d, want 1", tx.latestReads)
			}
			if tx.authorityWrites != 0 {
				t.Fatalf("failed prior read attempted %d new authority writes", tx.authorityWrites)
			}
		})
	}
}

func ordinaryBaseAuthorityIssueFixture() KubernetesOwnershipBaseAuthorityIssue {
	authority := validKubernetesOwnershipAuthorityFixture()
	authority.AuthorityRevision = 0
	authority.Classifications[0].Disposition = KubernetesOwnershipPoolDispositionMaintainFence
	return KubernetesOwnershipBaseAuthorityIssue{
		Authority:          authority,
		Pools:              []KubernetesOwnershipBaseAuthorityPoolGeneration{{Scope: authority.Classifications[0].Scope, PromotionGeneration: 1}},
		ExpiresAt:          time.Now().Add(time.Hour).UTC(),
		OrdinaryBaseUpdate: true,
	}
}

type ordinaryBaseLatestReadFailureTx struct {
	siteID          uuid.UUID
	readErr         error
	latestReads     int
	authorityWrites int
}

var _ pgx.Tx = (*ordinaryBaseLatestReadFailureTx)(nil)

func (tx *ordinaryBaseLatestReadFailureTx) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("unexpected nested transaction")
}

func (tx *ordinaryBaseLatestReadFailureTx) Commit(context.Context) error {
	return errors.New("unexpected commit")
}

func (tx *ordinaryBaseLatestReadFailureTx) Rollback(context.Context) error { return nil }

func (tx *ordinaryBaseLatestReadFailureTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unexpected copy")
}

func (tx *ordinaryBaseLatestReadFailureTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nil
}

func (tx *ordinaryBaseLatestReadFailureTx) LargeObjects() pgx.LargeObjects {
	return pgx.LargeObjects{}
}

func (tx *ordinaryBaseLatestReadFailureTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("unexpected prepare")
}

func (tx *ordinaryBaseLatestReadFailureTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	switch {
	case strings.Contains(sql, "INSERT INTO k8s_base_authority_node_states"):
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	case strings.Contains(sql, "k8s_base_authority_delivery_pools"),
		strings.Contains(sql, "UPDATE k8s_base_authority_node_states SET next_authority_revision"):
		tx.authorityWrites++
		return pgconn.CommandTag{}, errors.New("authority write followed failed prior read")
	default:
		return pgconn.CommandTag{}, fmt.Errorf("unexpected exec: %s", sql)
	}
}

func (tx *ordinaryBaseLatestReadFailureTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected query")
}

func (tx *ordinaryBaseLatestReadFailureTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "SELECT id") && strings.Contains(sql, "LIMIT 1 FOR UPDATE"):
		return ordinaryBaseReadFailureRow{scan: func(dest ...any) error {
			if len(dest) != 1 {
				return fmt.Errorf("delivery-lock scan destinations = %d, want 1", len(dest))
			}
			deliveryID, ok := dest[0].(*uuid.UUID)
			if !ok {
				return fmt.Errorf("delivery-lock destination is %T", dest[0])
			}
			*deliveryID = uuid.New()
			return nil
		}}
	case strings.Contains(sql, "SELECT site_id,next_authority_revision,accepted_authority_revision"):
		return ordinaryBaseReadFailureRow{scan: func(dest ...any) error {
			if len(dest) != 3 {
				return fmt.Errorf("node-state scan destinations = %d, want 3", len(dest))
			}
			storedSite, ok := dest[0].(*uuid.UUID)
			if !ok {
				return fmt.Errorf("node-state site destination is %T", dest[0])
			}
			nextRevision, ok := dest[1].(*int64)
			if !ok {
				return fmt.Errorf("node-state next-revision destination is %T", dest[1])
			}
			acceptedRevision, ok := dest[2].(*int64)
			if !ok {
				return fmt.Errorf("node-state accepted-revision destination is %T", dest[2])
			}
			*storedSite, *nextRevision, *acceptedRevision = tx.siteID, 1, 0
			return nil
		}}
	case strings.Contains(sql, "SELECT COALESCE(("):
		return ordinaryBaseReadFailureRow{scan: func(dest ...any) error {
			if len(dest) != 1 {
				return fmt.Errorf("pending-transition scan destinations = %d, want 1", len(dest))
			}
			pending, ok := dest[0].(*bool)
			if !ok {
				return fmt.Errorf("pending-transition destination is %T", dest[0])
			}
			*pending = false
			return nil
		}}
	case strings.Contains(sql, "SELECT d.id,d.payload,d.payload_digest,d.expires_at,d.authority_revision"):
		tx.latestReads++
		return ordinaryBaseReadFailureRow{scan: func(...any) error { return tx.readErr }}
	case strings.Contains(sql, "INSERT INTO k8s_base_authority_deliveries"):
		tx.authorityWrites++
		return ordinaryBaseReadFailureRow{scan: func(...any) error {
			return errors.New("authority write followed failed prior read")
		}}
	default:
		return ordinaryBaseReadFailureRow{scan: func(...any) error {
			return fmt.Errorf("unexpected query row: %s", sql)
		}}
	}
}

func (tx *ordinaryBaseLatestReadFailureTx) Conn() *pgx.Conn { return nil }

type ordinaryBaseReadFailureRow struct {
	scan func(...any) error
}

func (row ordinaryBaseReadFailureRow) Scan(dest ...any) error { return row.scan(dest...) }

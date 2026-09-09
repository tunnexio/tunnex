package sqlc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type topologyBatchDB struct {
	DBTX
	batch  *pgx.Batch
	result *topologyBatchResult
}

type snapshotBatchDB struct {
	DBTX
	batch  *pgx.Batch
	result *snapshotBatchResult
}

func (db *snapshotBatchDB) SendBatch(_ context.Context, b *pgx.Batch) pgx.BatchResults {
	db.batch = b
	return db.result
}

type snapshotBatchResult struct {
	topologyBatchResult
	step, fail int
}

func (r *snapshotBatchResult) next() error {
	r.step++
	if r.step == r.fail {
		return context.DeadlineExceeded
	}
	return nil
}
func (r *snapshotBatchResult) Exec() (pgconn.CommandTag, error) { return pgconn.CommandTag{}, r.next() }
func (r *snapshotBatchResult) QueryRow() pgx.Row                { return timingRow{r.next()} }
func (r *snapshotBatchResult) Query() (pgx.Rows, error)         { return emptyTopologyRows{}, r.next() }

type timingRow struct{ err error }

func (r timingRow) Scan(dest ...any) error {
	if r.err == nil {
		*dest[0].(*time.Time) = time.Unix(123, 0)
	}
	return r.err
}

type emptyTopologyRows struct{ pgx.Rows }

func (emptyTopologyRows) Next() bool { return false }
func (emptyTopologyRows) Err() error { return nil }
func (emptyTopologyRows) Close()     {}

func TestTopologySnapshotDrainsAndDiscardsOnEveryFailure(t *testing.T) {
	for fail := 0; fail <= 7; fail++ {
		r := &snapshotBatchResult{fail: fail}
		if fail == 7 {
			r.err = context.DeadlineExceeded
		}
		db := &snapshotBatchDB{result: r}
		org := uuid.New()
		out, err := New(db).ReadLockedConnectivityTopology(context.Background(), org)
		if !r.closed {
			t.Fatal("batch not closed")
		}
		if fail == 0 {
			if err != nil || out.Now.IsZero() || out.HubSet != nil {
				t.Fatalf("missing hub set must succeed: %v", err)
			}
		} else if !errors.Is(err, context.DeadlineExceeded) || !out.Now.IsZero() || out.Gateways != nil || out.HubSet != nil {
			t.Fatalf("partial snapshot/error escaped at step %d: %v", fail, err)
		}
		want := []string{shareConnectivityHubSet, shareConnectivityTopologyNodes, shareConnectivityTopologySites, connectivityWallClock, listSiteGatewaysForOrg, getOrgHubSet}
		if db.batch.Len() != len(want) {
			t.Fatal("read set changed")
		}
		for i, sql := range want {
			got := db.batch.QueuedQueries[i]
			if got.SQL != sql {
				t.Fatalf("query order changed at %d", i)
			}
			if i == 3 {
				if len(got.Arguments) != 0 {
					t.Fatal("clock gained arguments")
				}
			} else if len(got.Arguments) != 1 || got.Arguments[0] != org {
				t.Fatal("scope changed")
			}
		}
	}
}

func (db *topologyBatchDB) SendBatch(_ context.Context, batch *pgx.Batch) pgx.BatchResults {
	db.batch = batch
	return db.result
}

type topologyBatchResult struct {
	pgx.BatchResults
	closed bool
	err    error
}

func (r *topologyBatchResult) Close() error { r.closed = true; return r.err }

func TestTopologyLockBatchPreservesOrderAndErrors(t *testing.T) {
	for _, wantErr := range []error{nil, context.DeadlineExceeded, errors.New("batch failed")} {
		db := &topologyBatchDB{result: &topologyBatchResult{err: wantErr}}
		org := uuid.New()
		if err := New(db).ShareConnectivityTopologyLocks(context.Background(), org); err != wantErr {
			t.Fatalf("batch error lost: %v", err)
		}
		if !db.result.closed || db.batch == nil || db.batch.Len() != 3 {
			t.Fatal("batch must drain all three locks")
		}
		for i, sql := range []string{shareConnectivityHubSet, shareConnectivityTopologyNodes, shareConnectivityTopologySites} {
			query := db.batch.QueuedQueries[i]
			if query.SQL != sql || len(query.Arguments) != 1 || query.Arguments[0] != org {
				t.Fatalf("lock SQL/order/scope changed at %d", i)
			}
		}
	}
}

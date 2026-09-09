package sqlc

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type topologyBatchDB struct {
	DBTX
	batch  *pgx.Batch
	result *topologyBatchResult
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

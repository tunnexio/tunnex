package connectivity

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// singleRoundTripTx avoids a prepare/describe network round trip on each cold
// mailbox query. Extended-protocol bound parameters remain parameters; no SQL
// interpolation or global pool configuration change is involved.
type singleRoundTripTx struct{ pgx.Tx }

func mailboxQueryArgs(args []any) []any {
	for _, arg := range args {
		if _, ok := arg.([]byte); ok {
			// sqlc represents both JSON and bytea as []byte. Keep server type
			// discovery for these writes rather than guessing their SQL type.
			return args
		}
	}
	return append([]any{pgx.QueryExecModeExec}, args...)
}

func (tx singleRoundTripTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return tx.Tx.Exec(ctx, sql, mailboxQueryArgs(args)...)
}

func (tx singleRoundTripTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return tx.Tx.Query(ctx, sql, mailboxQueryArgs(args)...)
}

func (tx singleRoundTripTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return tx.Tx.QueryRow(ctx, sql, mailboxQueryArgs(args)...)
}

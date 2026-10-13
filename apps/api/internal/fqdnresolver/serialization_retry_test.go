package fqdnresolver

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
)

func TestFQDNSerializationRetryBoundAndIdentity(t *testing.T) {
	serial := &pgconn.PgError{Code: "40001"}
	n := 0
	err := retryFQDNSerialization(context.Background(), nil, func() error { n++; return serial })
	if n != 3 || err != serial {
		t.Fatal("attempt limit/error changed", n, err)
	}
}
func TestFQDNSerializationRetryNoUnknownCommitOrOtherState(t *testing.T) {
	for _, e := range []error{errors.New("unknown commit transport"), &pgconn.PgError{Code: "40P01"}, context.Canceled, ErrSuperseded} {
		n := 0
		err := retryFQDNSerialization(context.Background(), nil, func() error { n++; return e })
		if n != 1 || err != e {
			t.Fatal("unapproved retry", n)
		}
	}
}
func TestFQDNSerializationRetryRollbackBeforeRevalidation(t *testing.T) {
	n := 0
	rolled := false
	gates := 0
	err := retryFQDNSerialization(context.Background(), func() error {
		gates++
		if !rolled {
			t.Fatal("gate before rollback")
		}
		return nil
	}, func() error {
		n++
		if n == 1 {
			defer func() { rolled = true }()
			return fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "40001"})
		}
		if !rolled {
			t.Fatal("next tx before rollback")
		}
		return nil
	})
	if err != nil || n != 2 || gates != 1 {
		t.Fatal(n, gates, err)
	}
}
func TestFQDNSerializationRetryAuthorityChangeTerminal(t *testing.T) {
	n := 0
	err := retryFQDNSerialization(context.Background(), nil, func() error {
		n++
		if n == 1 {
			return &pgconn.PgError{Code: "40001"}
		}
		return ErrSuperseded
	})
	if n != 2 || err != ErrSuperseded {
		t.Fatal(n, err)
	}
}
func TestFQDNSerializationRetryCanceledBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	err := retryFQDNSerialization(ctx, nil, func() error { n++; cancel(); return &pgconn.PgError{Code: "40001"} })
	if n != 1 || err != context.Canceled {
		t.Fatal(n, err)
	}
}
func TestFQDNSerializationRetryOriginalRequestDeadline(t *testing.T) {
	n := 0
	gate := errors.New("original deadline expired")
	err := retryFQDNSerialization(context.Background(), func() error { return gate }, func() error { n++; return &pgconn.PgError{Code: "40001"} })
	if n != 1 || err != gate {
		t.Fatal(n, err)
	}
}

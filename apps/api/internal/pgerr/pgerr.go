// Package pgerr holds small helpers for classifying PostgreSQL driver errors,
// so the same SQLSTATE checks are not re-inlined across services.
package pgerr

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// IsUnique reports whether err is a unique-violation (SQLSTATE 23505).
func IsUnique(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// UniqueConstraint returns the violated constraint's name if err is a
// unique-violation (23505), else "". Lets callers distinguish which index
// collided instead of mapping every 23505 to one error.
func UniqueConstraint(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return pgErr.ConstraintName
	}
	return ""
}

package sandboxes

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/ssh"
	"strings"
	"unicode/utf8"
)

type SavedSSHKey struct {
	ID                           uuid.UUID
	Name, PublicKey, Fingerprint string
	IsDefault                    bool
}

func normalizeSavedSSHKey(name, public string) (SavedSSHKey, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 80 || strings.ContainsAny(name, "\r\n\x00") {
		return SavedSSHKey{}, ErrInvalid
	}
	keys, err := NormalizeSSHPublicKeys([]string{public}, 1)
	if err != nil {
		return SavedSSHKey{}, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keys[0]))
	if err != nil {
		return SavedSSHKey{}, ErrInvalid
	}
	return SavedSSHKey{ID: uuid.New(), Name: name, PublicKey: keys[0], Fingerprint: ssh.FingerprintSHA256(key)}, nil
}
func (s *Store) ListSavedSSHKeys(ctx context.Context, user uuid.UUID) ([]SavedSSHKey, error) {
	if user == uuid.Nil {
		return nil, ErrForbidden
	}
	rows, err := s.pool.Query(ctx, `SELECT id,name,public_key,fingerprint,is_default FROM saved_ssh_keys WHERE user_id=$1 ORDER BY is_default DESC,name,id`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SavedSSHKey{}
	for rows.Next() {
		var v SavedSSHKey
		if err = rows.Scan(&v.ID, &v.Name, &v.PublicKey, &v.Fingerprint, &v.IsDefault); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) SaveSSHKey(ctx context.Context, user uuid.UUID, name, public string) (SavedSSHKey, error) {
	if user == uuid.Nil {
		return SavedSSHKey{}, ErrForbidden
	}
	v, err := normalizeSavedSSHKey(name, public)
	if err != nil {
		return v, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return v, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, user); err != nil {
		return v, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM saved_ssh_keys WHERE user_id=$1`, user).Scan(&count); err != nil {
		return v, err
	}
	if count >= 50 {
		return v, ErrQuota
	}
	v.IsDefault = count == 0
	_, err = tx.Exec(ctx, `INSERT INTO saved_ssh_keys(id,user_id,name,public_key,fingerprint,is_default) VALUES($1,$2,$3,$4,$5,$6)`, v.ID, user, v.Name, v.PublicKey, v.Fingerprint, v.IsDefault)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return v, ErrConflict
	}
	if err != nil {
		return v, err
	}
	return v, tx.Commit(ctx)
}
func (s *Store) ChangeSavedSSHKey(ctx context.Context, user, id uuid.UUID, makeDefault bool) error {
	if user == uuid.Nil {
		return ErrForbidden
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, user); err != nil {
		return err
	}
	var owned uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM saved_ssh_keys WHERE user_id=$1 AND id=$2`, user, id).Scan(&owned)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if makeDefault {
		if _, err = tx.Exec(ctx, `UPDATE saved_ssh_keys SET is_default=false WHERE user_id=$1 AND is_default`, user); err == nil {
			_, err = tx.Exec(ctx, `UPDATE saved_ssh_keys SET is_default=true WHERE user_id=$1 AND id=$2`, user, id)
		}
	} else {
		_, err = tx.Exec(ctx, `DELETE FROM saved_ssh_keys WHERE user_id=$1 AND id=$2`, user, id)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

package vault

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type envelope struct {
	Format       string    `json:"format"`
	Organization uuid.UUID `json:"organization"`
	Entry        uuid.UUID `json:"entry"`
	Version      int       `json:"version"`
	Value        string    `json:"value"`
	Username     string    `json:"username"`
}

func (s *Service) seal(org, id uuid.UUID, version int, value, username string) (string, error) {
	raw, err := json.Marshal(envelope{"tunnex-vault-v1", org, id, version, value, username})
	if err != nil {
		return "", apierr.Internal()
	}
	sealed, err := s.sealer.Seal(raw)
	if err != nil {
		return "", apierr.Internal()
	}
	return sealed, nil
}

func (s *Service) open(org, id uuid.UUID, version int, sealed string) (api.VaultSecret, error) {
	raw, err := s.sealer.Open(sealed)
	if err != nil {
		return api.VaultSecret{}, apierr.Internal()
	}
	var v envelope
	if json.Unmarshal(raw, &v) != nil || v.Format != "tunnex-vault-v1" || v.Organization != org || v.Entry != id || v.Version != version || !validText(v.Value, 16384, false) || !validText(v.Username, 320, true) {
		return api.VaultSecret{}, apierr.Internal()
	}
	return api.VaultSecret{Value: v.Value, Username: v.Username, Version: v.Version}, nil
}

func (s *Service) writeVersion(ctx context.Context, tx pgx.Tx, org, user, id uuid.UUID, version int, value, username string) error {
	sealed, err := s.seal(org, id, version, value, username)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO vault_versions(org_id,entry_id,version,sealed_payload,changed_by) VALUES($1,$2,$3,$4,$5)`, org, id, version, sealed, user)
	return err
}

func (s *Service) Versions(ctx context.Context, org, user, id uuid.UUID, limit, offset int32) (api.VaultHistory, error) {
	out := api.VaultHistory{Versions: []api.VaultVersion{}}
	limit, offset, err := pagination(limit, offset)
	if err != nil {
		return out, err
	}
	tx, a, err := s.begin(ctx, org, user)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	entry, err := readEntry(ctx, tx, org, user, id, a, false)
	if err != nil {
		return out, err
	}
	out.CurrentVersion = entry.CurrentVersion
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM vault_versions WHERE org_id=$1 AND entry_id=$2`, org, id).Scan(&out.Total); err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, `SELECT v.version,v.created_at,v.changed_by,coalesce(nullif(u.name,''),u.email::text)
 FROM vault_versions v JOIN users u ON u.id=v.changed_by WHERE v.org_id=$1 AND v.entry_id=$2 ORDER BY v.version DESC LIMIT $3 OFFSET $4`, org, id, limit, offset)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var v api.VaultVersion
		if err = rows.Scan(&v.Version, &v.CreatedAt, &v.ChangedBy, &v.ChangedByName); err != nil {
			rows.Close()
			return out, err
		}
		out.Versions = append(out.Versions, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}

func (s *Service) Reveal(ctx context.Context, org, user, id uuid.UUID, version int) (api.VaultSecret, error) {
	if version < 0 {
		return api.VaultSecret{}, invalid()
	}
	tx, a, err := s.begin(ctx, org, user)
	if err != nil {
		return api.VaultSecret{}, err
	}
	defer tx.Rollback(ctx)
	entry, err := readEntry(ctx, tx, org, user, id, a, false)
	if err != nil {
		return api.VaultSecret{}, err
	}
	if version == 0 {
		version = entry.CurrentVersion
	}
	var sealed string
	err = tx.QueryRow(ctx, `SELECT sealed_payload FROM vault_versions WHERE org_id=$1 AND entry_id=$2 AND version=$3`, org, id, version).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return api.VaultSecret{}, missing()
	}
	if err != nil {
		return api.VaultSecret{}, err
	}
	secret, err := s.open(org, id, version, sealed)
	if err != nil {
		return api.VaultSecret{}, err
	}
	if err = audit(ctx, tx, org, user, id, "revealed", version); err != nil {
		return api.VaultSecret{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return api.VaultSecret{}, err
	}
	return secret, nil
}

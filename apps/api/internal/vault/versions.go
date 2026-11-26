package vault

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

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

const (
	envelopeV1 = "tunnex-vault-v1"
	envelopeV2 = "tunnex-vault-v2"
	// "." is not a base64 character, so a v2 payload can never be mistaken for a v1 one.
	envelopeV2Prefix = "v2."
)

// envelopeAAD binds a v2 ciphertext to its organization, entry and version (VAULT-UX-1 V19). The JSON body
// repeats them, but associated data makes the AEAD itself refuse a payload moved to another row.
func envelopeAAD(org, id uuid.UUID, version int) []byte {
	return []byte(envelopeV2 + "|" + org.String() + "|" + id.String() + "|" + strconv.Itoa(version))
}

// seal writes the v2 envelope. v1 rows (no associated data) stay readable by open.
func (s *Service) seal(org, id uuid.UUID, version int, value, username string) (string, error) {
	raw, err := json.Marshal(envelope{envelopeV2, org, id, version, value, username})
	if err != nil {
		return "", apierr.Internal()
	}
	sealed, err := s.sealer.SealWithAAD(raw, envelopeAAD(org, id, version))
	if err != nil {
		return "", apierr.Internal()
	}
	return envelopeV2Prefix + sealed, nil
}

func (s *Service) open(org, id uuid.UUID, version int, sealed string) (api.VaultSecret, error) {
	format := envelopeV1
	var raw []byte
	var err error
	if rest, ok := strings.CutPrefix(sealed, envelopeV2Prefix); ok {
		format = envelopeV2
		raw, err = s.sealer.OpenWithAAD(rest, envelopeAAD(org, id, version))
	} else {
		raw, err = s.sealer.Open(sealed)
	}
	if err != nil {
		return api.VaultSecret{}, apierr.Internal()
	}
	var v envelope
	if json.Unmarshal(raw, &v) != nil || v.Format != format || v.Organization != org || v.Entry != id || v.Version != version || !validText(v.Value, maxSecret, false) || !validText(v.Username, 320, true) {
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

func (s *Service) versionValue(ctx context.Context, tx pgx.Tx, org, id uuid.UUID, version int) (api.VaultSecret, error) {
	var sealed string
	err := tx.QueryRow(ctx, `SELECT sealed_payload FROM vault_versions WHERE org_id=$1 AND entry_id=$2 AND version=$3`, org, id, version).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return api.VaultSecret{}, missing()
	}
	if err != nil {
		return api.VaultSecret{}, err
	}
	return s.open(org, id, version, sealed)
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
	rows, err := tx.Query(ctx, `SELECT v.version,v.created_at,v.changed_by,coalesce(nullif(u.name,''),u.email::text),u.email::text
 FROM vault_versions v JOIN users u ON u.id=v.changed_by WHERE v.org_id=$1 AND v.entry_id=$2 ORDER BY v.version DESC LIMIT $3 OFFSET $4`, org, id, limit, offset)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var v api.VaultVersion
		if err = rows.Scan(&v.Version, &v.CreatedAt, &v.ChangedBy, &v.ChangedByName, &v.ChangedByEmail); err != nil {
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

// RevealRequest is one explicit, audited read. StepUp is the caller's recent re-authentication check; it runs
// inside the transaction, after the entry is locked, and only for assigned entries (VAULT-UX-1 V4). With no
// StepUp an assigned entry is refused: the check can be forgotten, never skipped.
type RevealRequest struct {
	Version int
	Purpose string
	StepUp  func(context.Context) error
}

func reauthenticationRequired() error {
	return apierr.Forbidden("reauthentication_required", "Confirm it is you to open a shared credential")
}

func (s *Service) Reveal(ctx context.Context, org, user, id uuid.UUID, req RevealRequest) (api.VaultSecret, error) {
	action := "revealed"
	switch req.Purpose {
	case "", "reveal":
	case "copy":
		// Client-asserted: the server cannot see a clipboard. Equally authorized and budgeted.
		action = "copied"
	default:
		return api.VaultSecret{}, invalid()
	}
	if req.Version < 0 {
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
	if string(entry.Visibility) == "assigned" {
		if req.StepUp == nil {
			return api.VaultSecret{}, reauthenticationRequired()
		}
		if err = req.StepUp(ctx); err != nil {
			return api.VaultSecret{}, err
		}
	}
	version := req.Version
	if version == 0 {
		version = entry.CurrentVersion
	}
	secret, err := s.versionValue(ctx, tx, org, id, version)
	if err != nil {
		return api.VaultSecret{}, err
	}
	// The username is entry metadata; an earlier version keeps the one it was saved with.
	if version == entry.CurrentVersion {
		secret.Username = entry.Username
	}
	if err = audit(ctx, tx, org, user, entry, action, version, nil); err != nil {
		return api.VaultSecret{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return api.VaultSecret{}, err
	}
	return secret, nil
}

package sandboxes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type handoffSealer interface {
	Seal([]byte) (string, error)
	Open(string) ([]byte, error)
}

// LaunchHandoff belongs solely to trusted local worker transport. No HTTP
// inventory, audit or provider specification may expose its bootstrap secret.
type LaunchHandoff struct {
	OperationID    uuid.UUID
	OrgID          uuid.UUID
	SandboxID      uuid.UUID
	GatewayID      uuid.UUID
	Generation     int64
	RuntimeID      string
	SpecHash       string
	BootstrapToken string
}

// PrepareLaunch durably stores the one-time handoff in the same transaction as
// its token hash. Re-entry decrypts the exact operation; it never reissues a
// credential after uncertain redemption. The lifecycle lease also fences stop
// and cleanup reconciliation. This internal method is not wired to production.
func (s *Store) PrepareLaunch(ctx context.Context, id, gateway uuid.UUID, sealer handoffSealer) (LaunchHandoff, error) {
	if gateway == uuid.Nil || sealer == nil {
		return LaunchHandoff{}, ErrInvalid
	}
	conn, release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return LaunchHandoff{}, err
	}
	defer release()
	target, err := s.prepareStart(ctx, conn, id)
	if err != nil {
		return LaunchHandoff{}, err
	}
	var local pgtype.UUID
	if err = conn.QueryRow(ctx, `SELECT local_terminal_gateway_id FROM sandboxes WHERE id=$1`, id).Scan(&local); err != nil || (local.Valid && uuid.UUID(local.Bytes) != gateway) {
		return LaunchHandoff{}, ErrConflict
	}
	if target.runtimeID == nil || target.sandbox.PeerID != nil {
		return LaunchHandoff{}, ErrConflict
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return LaunchHandoff{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var generation int64
	var desired string
	var eligible bool
	var peer *uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT generation,desired_state,expires_at>now(),peer_id FROM sandboxes WHERE id=$1 FOR UPDATE`, id).Scan(&generation, &desired, &eligible, &peer); err != nil {
		return LaunchHandoff{}, err
	}
	if generation != target.sandbox.Revision || desired != "started" || !eligible || peer != nil {
		return LaunchHandoff{}, ErrConflict
	}
	var active bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1 AND org_id=$2 AND status='active' AND endpoint<>'' AND wg_public_key<>'')`, gateway, target.sandbox.Identity.OrgID).Scan(&active); err != nil {
		return LaunchHandoff{}, err
	}
	if !active {
		return LaunchHandoff{}, ErrDisabled
	}
	var out LaunchHandoff
	var cipher *string
	var hash []byte
	var usable bool
	err = tx.QueryRow(ctx, `SELECT l.id,l.org_id,l.sandbox_id,l.gateway_node_id,l.generation,l.runtime_id,l.spec_hash,l.handoff_ciphertext,t.token_hash,t.consumed_at IS NULL AND t.expires_at>now()
 FROM sandbox_launch_operations l JOIN sandbox_bootstrap_tokens t ON t.id=l.bootstrap_token_id WHERE l.sandbox_id=$1 AND l.generation=$2`, id, generation).Scan(&out.OperationID, &out.OrgID, &out.SandboxID, &out.GatewayID, &out.Generation, &out.RuntimeID, &out.SpecHash, &cipher, &hash, &usable)
	if err == nil {
		if cipher == nil || !usable || out.GatewayID != gateway || out.RuntimeID != *target.runtimeID {
			return LaunchHandoff{}, ErrConflict
		}
		raw, e := sealer.Open(*cipher)
		if e != nil {
			return LaunchHandoff{}, ErrConflict
		}
		var opened LaunchHandoff
		if json.Unmarshal(raw, &opened) != nil {
			return LaunchHandoff{}, ErrConflict
		}
		expected := opened
		expected.BootstrapToken = ""
		if expected != out || opened.BootstrapToken == "" {
			return LaunchHandoff{}, ErrConflict
		}
		digest := sha256.Sum256([]byte(opened.BootstrapToken))
		if !equalHash(hash, digest[:]) {
			return LaunchHandoff{}, ErrConflict
		}
		return opened, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return LaunchHandoff{}, err
	}
	// Existing IssueBootstrap or expired/consumed state cannot be replaced.
	var pending bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandbox_bootstrap_tokens WHERE sandbox_id=$1 AND generation=$2)`, id, generation).Scan(&pending); err != nil {
		return LaunchHandoff{}, err
	}
	if pending {
		return LaunchHandoff{}, ErrConflict
	}
	bytes := make([]byte, 32)
	if _, err = rand.Read(bytes); err != nil {
		return LaunchHandoff{}, err
	}
	token := "tnx_sandbox_bootstrap_" + base64.RawURLEncoding.EncodeToString(bytes)
	digest := sha256.Sum256([]byte(token))
	var tokenID uuid.UUID
	if err = tx.QueryRow(ctx, `INSERT INTO sandbox_bootstrap_tokens(org_id,sandbox_id,gateway_node_id,generation,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour') RETURNING id`, target.sandbox.Identity.OrgID, id, gateway, generation, digest[:]).Scan(&tokenID); err != nil {
		return LaunchHandoff{}, err
	}
	var specHash string
	if err = tx.QueryRow(ctx, `SELECT spec_hash FROM sandbox_runtime_bindings WHERE sandbox_id=$1`, id).Scan(&specHash); err != nil {
		return LaunchHandoff{}, err
	}
	out = LaunchHandoff{uuid.New(), target.sandbox.Identity.OrgID, id, gateway, generation, *target.runtimeID, specHash, token}
	raw, _ := json.Marshal(out)
	sealed, err := sealer.Seal(raw)
	if err != nil {
		return LaunchHandoff{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO sandbox_launch_operations(id,org_id,sandbox_id,generation,gateway_node_id,runtime_id,spec_hash,bootstrap_token_id,handoff_ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, out.OperationID, out.OrgID, id, generation, gateway, out.RuntimeID, specHash, tokenID, sealed); err != nil {
		return LaunchHandoff{}, err
	}
	return out, tx.Commit(ctx)
}

// HandoffConfirmation is supplied by trusted local transport after the bound
// runtime has persisted its bootstrap response. It is not a public Ready claim.
type HandoffConfirmation struct {
	OperationID uuid.UUID
	SandboxID   uuid.UUID
	PeerID      uuid.UUID
	Generation  int64
	RuntimeID   string
	Persisted   bool
}

func (s *Store) ConfirmLaunch(ctx context.Context, receipt HandoffConfirmation) error {
	if !receipt.Persisted || receipt.OperationID == uuid.Nil || receipt.PeerID == uuid.Nil {
		return ErrInvalid
	}
	conn, release, err := s.acquireLifecycle(ctx, receipt.SandboxID)
	if err != nil {
		return err
	}
	defer release()
	return confirmLaunch(ctx, conn, receipt)
}

func confirmLaunch(ctx context.Context, conn *pgxpool.Conn, receipt HandoffConfirmation) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var generation int64
	var peer *uuid.UUID
	var desired string
	if err = tx.QueryRow(ctx, `SELECT generation,peer_id,desired_state FROM sandboxes WHERE id=$1 FOR UPDATE`, receipt.SandboxID).Scan(&generation, &peer, &desired); err != nil {
		return err
	}
	if generation != receipt.Generation || peer == nil || *peer != receipt.PeerID || desired != "started" {
		return ErrConflict
	}
	result, err := tx.Exec(ctx, `UPDATE sandbox_launch_operations l SET handoff_ciphertext=NULL,confirmed_at=COALESCE(l.confirmed_at,now()) FROM sandbox_bootstrap_tokens t
 WHERE l.id=$1 AND l.sandbox_id=$2 AND l.generation=$3 AND l.runtime_id=$4 AND t.id=l.bootstrap_token_id AND t.consumed_at IS NOT NULL`, receipt.OperationID, receipt.SandboxID, generation, receipt.RuntimeID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	return tx.Commit(ctx)
}

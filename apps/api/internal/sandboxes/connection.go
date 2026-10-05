package sandboxes

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"golang.org/x/crypto/ssh"
	"strings"
)

func loadConnection(ctx context.Context, tx pgx.Tx, out *Sandbox) error {
	if out.State != StateReady || out.DesiredState != "started" || out.PeerID == nil {
		return nil
	}
	// Reuse the compiler's current eligibility rather than trusting a stale Ready
	// paint. No credential or host private path is read by the HTTP inventory.
	projections, err := sqlc.New(tx).ListActiveSandboxProjections(ctx, out.Identity.OrgID)
	if err != nil {
		return err
	}
	eligible := false
	for _, p := range projections {
		if p.ID == out.Identity.ID && p.PeerID.Valid && p.PeerID.Bytes == [16]byte(*out.PeerID) {
			eligible = true
			break
		}
	}
	if !eligible {
		return nil
	}
	var address, public, fingerprint string
	err = tx.QueryRow(ctx, `SELECT d.assigned_ip,t.host_public_key,t.host_key_fingerprint FROM devices d JOIN sandboxes s ON s.peer_id=d.id AND s.org_id=d.org_id JOIN sandbox_terminal_identities t ON t.sandbox_id=s.id AND t.org_id=s.org_id WHERE s.id=$1 AND s.org_id=$2 AND s.generation=$3 AND s.observed_state='ready' AND s.desired_state='started' AND s.expires_at>now() AND (`+sandboxEligibilitySQL+`) AND d.id=$4 AND d.kind='sandbox' AND d.status='active' AND NOT d.health_blocked AND d.deleted_at IS NULL AND EXISTS(SELECT 1 FROM sandbox_runtime_credentials c WHERE c.sandbox_id=s.id AND c.org_id=s.org_id AND c.peer_id=d.id AND c.revoked_at IS NULL)`, out.Identity.ID, out.Identity.OrgID, out.Revision, *out.PeerID).Scan(&address, &public, &fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	ip, err := parsePrivateAddress(address)
	if err != nil {
		return ErrConflict
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(public))
	if err != nil || len(options) != 0 || len(rest) != 0 || key.Type() != ssh.KeyAlgoED25519 || ssh.FingerprintSHA256(key) != fingerprint {
		return ErrConflict
	}
	out.Connection = &ConnectionInfo{ip.String(), "sandbox", 22, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), fingerprint}
	return nil
}

package sandboxes

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"testing"

	appcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
)

type alteredEnvelopeSealer struct{ handoffSealer }

func (s alteredEnvelopeSealer) Open(cipher string) ([]byte, error) {
	raw, err := s.handoffSealer.Open(cipher)
	if err != nil {
		return nil, err
	}
	var envelope LaunchHandoff
	if err = json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	envelope.OrgID = uuid.New()
	return json.Marshal(envelope)
}

func TestLaunchPostgresStableSealedHandoffAndConsumedRecovery(t *testing.T) {
	f := newFixture(t)
	_, public, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2 WHERE id=$1`, f.node, public); err != nil {
		t.Fatal(err)
	}
	out, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("launch"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, out.Identity.ID, &startProvider{}); err != nil {
		t.Fatal(err)
	}
	sealer, err := appcrypto.NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	a, err := f.store.PrepareLaunch(f.ctx, out.Identity.ID, f.node, sealer)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.store.PrepareLaunch(f.ctx, out.Identity.ID, f.node, sealer)
	if err != nil || a != b {
		t.Fatal("handoff replaced", err)
	}
	var ciphertext string
	if err = f.pool.QueryRow(f.ctx, `SELECT handoff_ciphertext FROM sandbox_launch_operations WHERE id=$1`, a.OperationID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(ciphertext), []byte(a.BootstrapToken)) {
		t.Fatal("stored cleartext credential")
	}
	if _, err = f.store.PrepareLaunch(f.ctx, out.Identity.ID, f.node, alteredEnvelopeSealer{sealer}); !errors.Is(err, ErrConflict) {
		t.Fatal("opened cross-identity envelope accepted", err)
	}
	otherSealer, _ := appcrypto.NewSealer(bytes.Repeat([]byte{8}, 32))
	if _, err = f.store.PrepareLaunch(f.ctx, out.Identity.ID, f.node, otherSealer); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong sealer accepted", err)
	}
	_, clientPublic, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := devices.NewService(f.pool, nil, nil).Create(f.ctx, devices.CreateInput{SandboxBootstrapToken: a.BootstrapToken, PublicKey: clientPublic})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.PrepareLaunch(f.ctx, out.Identity.ID, f.node, sealer); !errors.Is(err, ErrConflict) {
		t.Fatal("uncertain consumed enrollment reissued", err)
	}
	receipt := HandoffConfirmation{a.OperationID, out.Identity.ID, peer.Device.ID, a.Generation, a.RuntimeID, true}
	wrong := receipt
	wrong.Generation++
	if err = f.store.ConfirmLaunch(f.ctx, wrong); !errors.Is(err, ErrConflict) {
		t.Fatal("stale confirmation accepted", err)
	}
	if err = f.store.ConfirmLaunch(f.ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if err = f.store.ConfirmLaunch(f.ctx, receipt); err != nil {
		t.Fatal("confirmation retry failed", err)
	}
	var cleared bool
	var count int
	if err = f.pool.QueryRow(f.ctx, `SELECT handoff_ciphertext IS NULL AND confirmed_at IS NOT NULL FROM sandbox_launch_operations WHERE id=$1`, a.OperationID).Scan(&cleared); err != nil || !cleared {
		t.Fatal("sealed handoff retained", err)
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM sandbox_bootstrap_tokens WHERE sandbox_id=$1`, out.Identity.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate enrollment token", err)
	}
}

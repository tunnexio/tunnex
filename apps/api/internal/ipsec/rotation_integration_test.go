package ipsec_test

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"strings"
	"testing"
)

func TestRotationNeverDeliveredAtomicAndCAS(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(p.Config().ConnString(), 162); e != nil {
		t.Fatal(e)
	}
	s := ipsec.NewConnectionStore(p)
	c, e := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	var partner string
	if e = p.QueryRow(ctx, `SELECT sealed_psk FROM ipsec_tunnel_secrets WHERE tunnel_id=$1`, req.TunnelIDs[1]).Scan(&partner); e != nil {
		t.Fatal(e)
	}
	rotated, e := s.RotatePSKs(ctx, org, actor, c.ID, c.DesiredRevision, []ipsec.RotatePSK{{TunnelID: req.TunnelIDs[0], PSK: "Synthetic_Rotated_PSK_456"}}, sealer)
	if e != nil || rotated.DesiredRevision != 2 || rotated.DesiredIntent != "disabled" {
		t.Fatal("rotation", e)
	}
	var rev int64
	var sealed string
	if e = p.QueryRow(ctx, `SELECT secret_revision,sealed_psk FROM ipsec_tunnel_secrets WHERE tunnel_id=$1`, req.TunnelIDs[0]).Scan(&rev, &sealed); e != nil || rev != 2 {
		t.Fatal("revision", e)
	}
	plain, e := ipsec.OpenPSK(sealer, ipsec.PSKBinding{OrgID: org, ConnectionID: c.ID, TunnelID: req.TunnelIDs[0], Revision: 2}, sealed)
	if e != nil || plain != "Synthetic_Rotated_PSK_456" {
		t.Fatal("new envelope invalid")
	}
	if e = p.QueryRow(ctx, `SELECT sealed_psk FROM ipsec_tunnel_secrets WHERE tunnel_id=$1`, req.TunnelIDs[1]).Scan(&sealed); e != nil || sealed != partner {
		t.Fatal("partner changed")
	}
	if _, e = s.RotatePSKs(ctx, org, actor, c.ID, 1, []ipsec.RotatePSK{{TunnelID: req.TunnelIDs[0], PSK: "Synthetic_Rotated_PSK_789"}}, sealer); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatal("CAS", e)
	}
}

func TestRotationRefusesSameKeyAndSQLPartialWrites(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(p.Config().ConnString(), 162); e != nil {
		t.Fatal(e)
	}
	s := ipsec.NewConnectionStore(p)
	c, e := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RotatePSKs(ctx, org, actor, c.ID, 1, []ipsec.RotatePSK{{TunnelID: req.TunnelIDs[0], PSK: req.Config.Tunnels[0].PSK}}, sealer); !errors.Is(e, ipsec.ErrConnectionInvalid) {
		t.Fatal("same key accepted", e)
	}
	for _, kind := range []string{"ciphertext alone", "revision alone", "matched without operation", "operation only", "parent only", "children only", "double child", "audit removed before commit"} {
		t.Run(kind, func(t *testing.T) {
			tx, e := p.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(ctx)
			failed := false
			exec := func(q string, args ...any) {
				if failed {
					return
				}
				_, err := tx.Exec(ctx, q, args...)
				failed = err != nil
			}
			exec(`SET CONSTRAINTS ipsec_secret_revision_fk DEFERRED`)
			if kind == "operation only" || kind == "parent only" || kind == "children only" || kind == "double child" || kind == "audit removed before commit" {
				audit := uuid.New()
				exec(`INSERT INTO audit_logs(id,org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'ipsec.psk_rotated','ipsec_connection',$4,'{"revision":2}')`, audit, org, actor, c.ID.String())
				exec(`INSERT INTO ipsec_psk_rotations(connection_id,org_id,desired_revision,previous_revision,actor_id,audit_id,tunnel_ids) VALUES($1,$2,2,1,$3,$4,$5)`, c.ID, org, actor, audit, []uuid.UUID{req.TunnelIDs[0]})
			}
			switch kind {
			case "ciphertext alone":
				exec(`UPDATE ipsec_tunnel_secrets SET sealed_psk='invalid-replacement' WHERE tunnel_id=$1`, req.TunnelIDs[0])
			case "revision alone":
				exec(`UPDATE ipsec_tunnels SET secret_revision=2 WHERE id=$1`, req.TunnelIDs[0])
			case "matched without operation", "children only", "double child", "audit removed before commit":
				exec(`UPDATE ipsec_tunnels SET secret_revision=2 WHERE id=$1`, req.TunnelIDs[0])
				exec(`UPDATE ipsec_tunnel_secrets SET secret_revision=2,sealed_psk='invalid-replacement' WHERE tunnel_id=$1`, req.TunnelIDs[0])
				if kind == "audit removed before commit" {
					exec(`UPDATE ipsec_connections SET desired_revision=2 WHERE id=$1`, c.ID)
					// Fault injection bypasses audit delete guard only in this rolled-back transaction.
					exec(`ALTER TABLE audit_logs DISABLE TRIGGER USER`)
					exec(`DELETE FROM audit_logs WHERE target_id=$1 AND action='ipsec.psk_rotated'`, c.ID.String())
				}
				if kind == "double child" {
					exec(`UPDATE ipsec_tunnels SET secret_revision=3 WHERE id=$1`, req.TunnelIDs[0])
				}
			case "parent only":
				exec(`UPDATE ipsec_connections SET desired_revision=2 WHERE id=$1`, c.ID)
			}
			if !failed {
				e = tx.Commit(ctx)
				failed = e != nil
			}
			if !failed {
				t.Fatal("incoherent transaction committed")
			}
		})
	}
	var rev int64
	if e = p.QueryRow(ctx, `SELECT desired_revision FROM ipsec_connections WHERE id=$1`, c.ID).Scan(&rev); e != nil || rev != 1 {
		t.Fatal("partial changes escaped", e)
	}
}

func TestRotationDeliveredRequiresCleanupAndNewMaterial(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(p.Config().ConnString(), 162); e != nil {
		t.Fatal(e)
	}
	s := ipsec.NewConnectionStore(p)
	s.ConfigureRuntimePolicy(func(context.Context, *sqlc.Queries, ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
		return ipsec.RuntimePolicy{Hash: strings.Repeat("a", 64)}, nil
	})
	c, e := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.SetIntent(ctx, org, actor, c.ID, 1, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	var serial string
	if e = p.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE id=$1`, req.GatewayID).Scan(&serial); e != nil {
		t.Fatal(e)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: req.GatewayID, CertificateSerial: serial}
	old, e := s.Material(ctx, principal, c.ID, 2, sealer)
	if e != nil {
		t.Fatal(e)
	}
	changes := []ipsec.RotatePSK{{TunnelID: req.TunnelIDs[0], PSK: "Synthetic_New_Key_One_456"}, {TunnelID: req.TunnelIDs[1], PSK: "Synthetic_New_Key_Two_456"}}
	if _, e = s.RotatePSKs(ctx, org, actor, c.ID, 2, changes, sealer); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatal("enabled rotation", e)
	}
	c, e = s.SetIntent(ctx, org, actor, c.ID, 2, "disabled")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RotatePSKs(ctx, org, actor, c.ID, 3, changes, sealer); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatal("pending cleanup rotation", e)
	}
	cleanup, e := s.Cleanup(ctx, principal, c.ID, 3)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Acknowledge(ctx, principal, c.ID, ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: 3, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true}); e != nil {
		t.Fatal(e)
	}
	var rotated ipsec.Connection
	rotationErr, materialErr := rotationOrderedRace(t, ctx, p, org, func() error {
		var err error
		rotated, err = s.RotatePSKs(ctx, org, actor, c.ID, 3, changes, sealer)
		return err
	}, func() error { _, err := s.Material(ctx, principal, c.ID, 2, sealer); return err })
	c = rotated
	e = rotationErr
	if !errors.Is(materialErr, ipsec.ErrConnectionConflict) {
		t.Fatal("queued old material disclosed", materialErr)
	}
	if e != nil || c.DesiredRevision != 4 {
		t.Fatal("cleaned rotation", e)
	}
	if _, e = s.Material(ctx, principal, c.ID, 2, sealer); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatal("old material available", e)
	}
	c, e = s.SetIntent(ctx, org, actor, c.ID, 4, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	fresh, e := s.Material(ctx, principal, c.ID, 5, sealer)
	if e != nil || fresh.Manifest.ConfigurationRevision != 1 || fresh.Manifest.Tunnels[0].SecretRevision != 2 || fresh.Manifest.Tunnels[1].SecretRevision != 2 {
		t.Fatal("new manifest binding", e)
	}
	if fresh.Secrets[0].PSK != changes[0].PSK || fresh.Secrets[1].PSK != changes[1].PSK {
		t.Fatal("new material wrong")
	}
	var digest string
	if e = p.QueryRow(ctx, `SELECT ownership_digest FROM ipsec_runtime_deliveries WHERE id=$1`, old.ID).Scan(&digest); e != nil || digest != old.OwnershipDigest {
		t.Fatal("old lineage changed", e)
	}
	if e = db.MigrateTo(p.Config().ConnString(), 161); e == nil {
		t.Fatal("rotation history downgrade allowed")
	}
}

func TestRotationSecondWriteFailureRollsBack(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(p.Config().ConnString(), 162); e != nil {
		t.Fatal(e)
	}
	s := ipsec.NewConnectionStore(p)
	c, e := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.Exec(ctx, `CREATE FUNCTION fail_rotation_second() RETURNS trigger AS $$ BEGIN IF (SELECT slot FROM ipsec_tunnels WHERE id=NEW.tunnel_id)=2 THEN RAISE EXCEPTION 'synthetic failure';END IF;RETURN NEW;END $$ LANGUAGE plpgsql; CREATE TRIGGER fail_rotation_second BEFORE UPDATE ON ipsec_tunnel_secrets FOR EACH ROW EXECUTE FUNCTION fail_rotation_second()`)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.RotatePSKs(ctx, org, actor, c.ID, 1, []ipsec.RotatePSK{{TunnelID: req.TunnelIDs[0], PSK: "Synthetic_New_Key_One_456"}, {TunnelID: req.TunnelIDs[1], PSK: "Synthetic_New_Key_Two_456"}}, sealer)
	if e == nil {
		t.Fatal("injected write failure ignored")
	}
	var intact bool
	e = p.QueryRow(ctx, `SELECT desired_revision=1 AND NOT EXISTS(SELECT 1 FROM ipsec_tunnels WHERE connection_id=$1 AND secret_revision<>1) AND NOT EXISTS(SELECT 1 FROM ipsec_psk_rotations WHERE connection_id=$1) AND NOT EXISTS(SELECT 1 FROM audit_logs WHERE target_id=$2 AND action='ipsec.psk_rotated') FROM ipsec_connections WHERE id=$1`, c.ID, c.ID.String()).Scan(&intact)
	if e != nil || !intact {
		t.Fatal("partial rotation persisted", e)
	}
}

func TestRotationConcurrentCASAndUnexercisedDowngrade(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(p.Config().ConnString(), 162); e != nil {
		t.Fatal(e)
	}
	if e := db.MigrateTo(p.Config().ConnString(), 161); e != nil {
		t.Fatal("unexercised rollback", e)
	}
	if e := db.MigrateTo(p.Config().ConnString(), 162); e != nil {
		t.Fatal(e)
	}
	s := ipsec.NewConnectionStore(p)
	c, e := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	done := make(chan error, 2)
	for _, value := range []string{"Synthetic_Race_Key_One_456", "Synthetic_Race_Key_Two_456"} {
		go func(psk string) {
			<-start
			_, err := s.RotatePSKs(ctx, org, actor, c.ID, 1, []ipsec.RotatePSK{{TunnelID: req.TunnelIDs[0], PSK: psk}}, sealer)
			done <- err
		}(value)
	}
	close(start)
	success, conflict := 0, 0
	for i := 0; i < 2; i++ {
		err := <-done
		if err == nil {
			success++
		} else if errors.Is(err, ipsec.ErrConnectionConflict) {
			conflict++
		} else {
			t.Fatal("unexpected race result", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("CAS allowed competing rotations")
	}
}

func TestRotationSecondSealAndAuditFailureRollBack(t *testing.T) {
	for _, kind := range []string{"seal", "audit"} {
		t.Run(kind, func(t *testing.T) {
			ctx, p, org, actor, sealer, req := providerFixture(t)
			if e := db.MigrateTo(p.Config().ConnString(), 162); e != nil {
				t.Fatal(e)
			}
			s := ipsec.NewConnectionStore(p)
			c, e := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
			if e != nil {
				t.Fatal(e)
			}
			changes := []ipsec.RotatePSK{{TunnelID: req.TunnelIDs[0], PSK: "Synthetic_Fail_Key_One_456"}, {TunnelID: req.TunnelIDs[1], PSK: "Synthetic_Fail_Key_Two_456"}}
			if kind == "seal" {
				_, e = ipsec.RotatePSKsSecondSealFailureForTest(s, ctx, org, actor, c.ID, 1, changes, sealer)
			} else {
				if _, e = p.Exec(ctx, `CREATE FUNCTION fail_rotation_audit() RETURNS trigger AS $$ BEGIN IF NEW.action='ipsec.psk_rotated' THEN RAISE EXCEPTION 'synthetic audit failure';END IF;RETURN NEW;END $$ LANGUAGE plpgsql; CREATE TRIGGER fail_rotation_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION fail_rotation_audit()`); e != nil {
					t.Fatal(e)
				}
				_, e = s.RotatePSKs(ctx, org, actor, c.ID, 1, changes, sealer)
			}
			if !errors.Is(e, ipsec.ErrConnectionUnavailable) {
				t.Fatal("fault not refused", e)
			}
			var intact bool
			e = p.QueryRow(ctx, `SELECT desired_revision=1 AND NOT EXISTS(SELECT 1 FROM ipsec_tunnels WHERE connection_id=$1 AND secret_revision<>1) AND NOT EXISTS(SELECT 1 FROM ipsec_psk_rotations WHERE connection_id=$1) AND NOT EXISTS(SELECT 1 FROM audit_logs WHERE target_id=$2 AND action='ipsec.psk_rotated') FROM ipsec_connections WHERE id=$1`, c.ID, c.ID.String()).Scan(&intact)
			if e != nil || !intact {
				t.Fatal("fault left partial rotation", e)
			}
		})
	}
}

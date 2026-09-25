package ipsec_test

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"strings"
	"testing"
)

// Positive vulnerable controls run only against providerFixture's disposable
// database. They independently demonstrate that early constraint flushing was
// the bypass, rather than passing because an unrelated setup statement failed.
func TestRotationConstraintFlushOrdering(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, action := range []string{"enable", "audit delete"} {
			name := action
			if legacy {
				name += " old-schema control"
			}
			t.Run(name, func(t *testing.T) {
				ctx, p, org, actor, sealer, req := providerFixture(t)
				if err := db.MigrateTo(p.Config().ConnString(), 162); err != nil {
					t.Fatal(err)
				}
				c, err := ipsec.NewConnectionStore(p).CreateProviderDisabled(ctx, org, actor, sealer, req)
				if err != nil {
					t.Fatal(err)
				}
				if legacy {
					var definition string
					if err = p.QueryRow(ctx, `SELECT pg_get_functiondef('ipsec_connection_guard()'::regprocedure)`).Scan(&definition); err != nil {
						t.Fatal(err)
					}
					start := strings.Index(definition, " IF TG_OP='UPDATE' AND EXISTS(SELECT 1 FROM ipsec_psk_rotations")
					if start < 0 {
						t.Fatal("new parent guard absent")
					}
					end := strings.Index(definition[start:], "END IF;")
					if end < 0 {
						t.Fatal("parent guard boundary missing")
					}
					definition = definition[:start] + definition[start+end+len("END IF;"):]
					if _, err = p.Exec(ctx, definition); err != nil {
						t.Fatal(err)
					}
					if _, err = p.Exec(ctx, `DROP TRIGGER ipsec_rotation_parent_complete ON ipsec_connections;DROP TRIGGER ipsec_rotation_tunnel_complete ON ipsec_tunnels;DROP TRIGGER ipsec_rotation_secret_complete ON ipsec_tunnel_secrets;DROP TRIGGER ipsec_rotation_audit_guard ON audit_logs`); err != nil {
						t.Fatal(err)
					}
				}
				tx, err := p.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				exec := func(q string, args ...any) {
					t.Helper()
					if _, err := tx.Exec(ctx, q, args...); err != nil {
						t.Fatal("rotation setup failed", err)
					}
				}
				audit := uuid.New()
				exec(`INSERT INTO audit_logs(id,org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'ipsec.psk_rotated','ipsec_connection',$4,'{"revision":2}')`, audit, org, actor, c.ID.String())
				exec(`INSERT INTO ipsec_psk_rotations(connection_id,org_id,desired_revision,previous_revision,actor_id,audit_id,tunnel_ids) VALUES($1,$2,2,1,$3,$4,$5)`, c.ID, org, actor, audit, []uuid.UUID{req.TunnelIDs[0]})
				exec(`SET CONSTRAINTS ipsec_secret_revision_fk DEFERRED`)
				exec(`UPDATE ipsec_tunnels SET secret_revision=2 WHERE id=$1`, req.TunnelIDs[0])
				exec(`UPDATE ipsec_tunnel_secrets SET secret_revision=2,sealed_psk='synthetic-constraint-test' WHERE tunnel_id=$1`, req.TunnelIDs[0])
				exec(`UPDATE ipsec_connections SET desired_revision=2 WHERE id=$1`, c.ID)
				// Flush every queued coherence event before the forbidden trailing mutation.
				exec(`SET CONSTRAINTS ALL IMMEDIATE`)
				if action == "enable" {
					_, err = tx.Exec(ctx, `UPDATE ipsec_connections SET desired_revision=3,desired_intent='enabled' WHERE id=$1`, c.ID)
				} else {
					// Use the existing retention authorization seam, without disabling any
					// append-only or newly introduced rotation trigger.
					exec(`INSERT INTO audit_log_retention_authorizations(backend_pid,transaction_id,audit_log_id) VALUES(pg_backend_pid(),txid_current(),$1)`, audit)
					_, err = tx.Exec(ctx, `DELETE FROM audit_logs WHERE id=$1`, audit)
				}
				if err == nil {
					err = tx.Commit(ctx)
				}
				if legacy {
					if err != nil {
						t.Fatal("old-schema control did not reproduce bypass", err)
					}
					return
				}
				if err == nil {
					t.Fatal("constraint flush bypass committed")
				}
				_ = tx.Rollback(ctx)
				var unchanged bool
				if err = p.QueryRow(ctx, `SELECT desired_revision=1 AND desired_intent='disabled' AND NOT EXISTS(SELECT 1 FROM ipsec_psk_rotations WHERE connection_id=$1) AND NOT EXISTS(SELECT 1 FROM ipsec_tunnels WHERE connection_id=$1 AND secret_revision<>1) FROM ipsec_connections WHERE id=$1`, c.ID).Scan(&unchanged); err != nil || !unchanged {
					t.Fatal("refused rotation escaped rollback", err)
				}
			})
		}
	}
}

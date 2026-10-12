package ipsec_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

// Exercises the actual PostgreSQL transaction and exact original sentinel.
func TestPermitLeaseConflictBranchDiagnostic(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); err != nil {
		t.Fatal(err)
	}
	store := ipsec.NewConnectionStore(p)
	hash := strings.Repeat("a", 64)
	store.ConfigureRuntimePolicy(func(ctx context.Context, q *sqlc.Queries, in ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
		v, e := runtimeCompiler(ctx, q, in)
		v.Hash = hash
		return v, e
	})
	c, err := store.CreateProviderDisabled(ctx, org, actor, sealer, providerRequest(identity))
	if err != nil {
		t.Fatal(err)
	}
	c, err = store.SetIntent(ctx, org, actor, c.ID, 1, "enabled")
	if err != nil {
		t.Fatal(err)
	}
	var serial string
	if err = p.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE id=$1`, identity.GatewayID).Scan(&serial); err != nil {
		t.Fatal(err)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: identity.GatewayID, CertificateSerial: serial}
	var logs bytes.Buffer
	prior := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(prior)
	material, err := store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer)
	if err != nil {
		t.Fatal(err)
	}
	request := ipsec.RuntimeLeaseRequest{DeliveryID: material.ID, DesiredRevision: c.DesiredRevision, PolicyHash: material.Policy.Hash, Nonce: strings.Repeat("c", 64)}
	healthy := func() {
		t.Helper()
		logs.Reset()
		if _, e := store.PermitLease(ctx, principal, c.ID, request); e != nil {
			t.Fatal(e)
		}
		if logs.Len() != 0 {
			t.Fatal("successful lease emitted conflict log")
		}
	}
	if logs.Len() != 0 {
		t.Fatal("Material emitted conflict log")
	}
	healthy()
	for _, stage := range []string{"intent_revision_cleanup", "delivery_missing", "policy_hash"} {
		t.Run(stage, func(t *testing.T) {
			logs.Reset()
			r := request
			switch stage {
			case "intent_revision_cleanup":
				r.DesiredRevision++
			case "delivery_missing":
				r.DeliveryID = uuid.New()
			case "policy_hash":
				hash = strings.Repeat("b", 64)
			}
			_, e := store.PermitLease(ctx, principal, c.ID, r)
			hash = strings.Repeat("a", 64)
			if e != ipsec.ErrConnectionConflict {
				t.Fatalf("exact sentinel changed: %v", e)
			}
			var record map[string]any
			decoder := json.NewDecoder(&logs)
			if decoder.Decode(&record) != nil {
				t.Fatal("missing closed conflict diagnostic")
			}
			if record["msg"] != "ipsec_permit_lease_conflict" || record["stage"] != stage || record["connection_id"] != c.ID.String() {
				t.Fatalf("wrong closed diagnostic: %v", record)
			}
			if len(record) != 5 {
				t.Fatalf("unexpected diagnostic fields: %v", record)
			}
			if decoder.Decode(new(any)) != io.EOF {
				t.Fatal("duplicate diagnostic")
			}
			healthy()
		})
	}
}

package http

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

func TestPolicyRuleFQDNProjectionIsTruthfullyUnavailable(t *testing.T) {
	ruleID, orgID, resourceID := uuid.New(), uuid.New(), uuid.New()
	out := toAPIRule(sqlc.PolicyRule{
		ID: ruleID, OrgID: orgID, SrcKind: "group", DstKind: "fqdn_resource", CreatedAt: time.Now(),
		DstFqdnResourceID: pgtype.UUID{Bytes: resourceID, Valid: true},
	}, false, false)
	if out.DstFqdnResourceId == nil || *out.DstFqdnResourceId != resourceID {
		t.Fatal("FQDN rule identity was not projected")
	}
	if out.FqdnDestinationStatus != api.PendingCompiler {
		t.Fatalf("FQDN rule status = %q, want %q; the UI must not claim compiler support before Lane 2", out.FqdnDestinationStatus, api.PendingCompiler)
	}
	if normal := toAPIRule(sqlc.PolicyRule{ID: uuid.New(), OrgID: orgID, SrcKind: "group", DstKind: "resource", CreatedAt: time.Now()}, false, false); normal.FqdnDestinationStatus != api.NotApplicable {
		t.Fatalf("non-FQDN status = %q, want %q", normal.FqdnDestinationStatus, api.NotApplicable)
	}
}

package appaccess

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"testing"
	"time"
)

func TestAuditTargetFiltersLocalDatabase(t *testing.T) {
	p := grantPool(t)
	ctx := context.Background()
	a, b := uuid.New(), uuid.New()
	target, other := uuid.New().String(), uuid.New().String()
	exec := func(s string, args ...any) {
		t.Helper()
		if _, e := p.Exec(ctx, s, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec("INSERT INTO organizations(id,name,slug)VALUES($1,'Audit A',$2),($3,'Audit B',$4)", a, a.String(), b, b.String())
	now := time.Now().UTC()
	insert := `INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,created_at)VALUES($1,'app-access-recovery','fixture.target',$2,$3,$4)`
	exec(insert, a, "app_access", target, now.Add(-3*time.Minute))
	exec(insert, a, "organization", target, now.Add(-2*time.Minute))
	exec(insert, a, "app_access", other, now.Add(-time.Minute))
	exec(insert, b, "app_access", target, now)
	svc := tenancy.NewService(p)
	kind := "app_access"
	filtered, e := svc.ListAuditLogs(ctx, a, tenancy.AuditFilter{TargetType: &kind, TargetID: &target, Limit: 1})
	if e != nil || len(filtered) != 1 || filtered[0].TargetID == nil || *filtered[0].TargetID != target || filtered[0].TargetType == nil || *filtered[0].TargetType != kind {
		t.Fatal("exact targets filtered after page or crossed tenant", e)
	}
	latest, e := svc.ListAuditLogs(ctx, a, tenancy.AuditFilter{Limit: 1})
	if e != nil || len(latest) != 1 || latest[0].TargetID == nil || *latest[0].TargetID != other {
		t.Fatal("default changed", e)
	}
	id, ts := filtered[0].ID, filtered[0].CreatedAt
	next, e := svc.ListAuditLogs(ctx, a, tenancy.AuditFilter{TargetType: &kind, TargetID: &target, CursorID: &id, CursorTS: &ts, Limit: 1})
	if e != nil || len(next) != 0 {
		t.Fatal("target cursor replay", e)
	}
	kindOnly, e := svc.ListAuditLogs(ctx, a, tenancy.AuditFilter{TargetType: &kind, Limit: 10})
	if e != nil || len(kindOnly) != 2 {
		t.Fatal("type-only filter", e)
	}
	targetOnly, e := svc.ListAuditLogs(ctx, a, tenancy.AuditFilter{TargetID: &target, Limit: 10})
	if e != nil || len(targetOnly) != 2 {
		t.Fatal("id-only filter", e)
	}
}

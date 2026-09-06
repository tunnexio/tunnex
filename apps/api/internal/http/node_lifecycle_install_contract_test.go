package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	oapimw "github.com/oapi-codegen/nethttp-middleware"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

func TestNodeLifecycleInstallOpenAPIKeepsLegacyAbortByteCompatible(t *testing.T) {
	spec, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	abortSchema := spec.Components.Schemas["NodeLifecycleClaimAbortRequest"].Value
	if abortSchema == nil {
		t.Fatal("legacy lifecycle abort schema is absent")
	}
	for _, unexpected := range []string{"operation_id", "expected_epoch"} {
		if _, exists := abortSchema.Properties[unexpected]; exists {
			t.Fatalf("legacy abort schema gained D13h field %q; N-1 would reject the known route with 400", unexpected)
		}
	}
	newAbortPath := "/api/v1/organizations/{orgId}/nodes/lifecycle-claims/{claim}/install-operations/{operationId}/abort"
	item := spec.Paths.Value(newAbortPath)
	if item == nil {
		t.Fatalf("mixed-version-safe D13h request-abort route missing: %s", newAbortPath)
	}
	if item.Post == nil || item.Post.OperationID != "RequestNodeLifecycleInstallAbort" {
		t.Fatalf("mixed-version-safe D13h request-abort operation = %#v", item.Post)
	}
	legacyPath := spec.Paths.Value("/api/v1/organizations/{orgId}/nodes/lifecycle-claims/{claim}/abort")
	if legacyPath == nil || legacyPath.Post == nil || legacyPath.Post.Responses.Value("202") != nil {
		t.Fatal("legacy lifecycle abort response contract changed from its 200/default shape")
	}
	for _, schemaName := range []string{"NodeLifecycleInstallBeginRequest", "NodeLifecycleInstallOperationStatus"} {
		schema := spec.Components.Schemas[schemaName].Value
		if schema == nil {
			t.Fatalf("D13h schema %s is absent", schemaName)
		}
		if _, exists := schema.Properties["install_intent_digest"]; !exists {
			t.Fatalf("D13h schema %s lacks canonical install_intent_digest", schemaName)
		}
		if _, exists := schema.Properties["approved_plan_digest"]; exists {
			t.Fatalf("D13h schema %s reused ambiguous display-plan naming", schemaName)
		}
	}
	collectionPath := spec.Paths.Value("/api/v1/organizations/{orgId}/nodes/lifecycle-claims/{claim}/install-operations")
	if collectionPath == nil || collectionPath.Get == nil || collectionPath.Get.OperationID != "GetLatestNodeLifecycleInstall" {
		t.Fatalf("latest lifecycle install operation = %#v", collectionPath)
	}
	if collectionPath.Get.Responses.Value("404") == nil {
		t.Fatal("latest lifecycle install operation lacks explicit domain-absence 404")
	}
	if collectionPath.Post == nil || collectionPath.Post.Responses.Value("409") == nil {
		t.Fatal("Begin lifecycle install lacks explicit typed 409 recovery contract")
	}
}

func TestToAPINodeLifecycleInstallOperationStatusPreservesClockAndNoSecret(t *testing.T) {
	now := time.Now().UTC().Round(0)
	abortAt := now.Add(time.Second)
	status := nodes.LifecycleInstallOperationStatus{
		Claim: uuid.New(), Generation: 3, RequestID: uuid.New(), OperationID: uuid.New(), Epoch: 7,
		State: nodes.LifecycleInstallAbortRequested, ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RequestedDurationSeconds: 660, NotAfter: now.Add(11 * time.Minute), ServerTime: now,
		HeartbeatAt: now, AbortRequestedAt: &abortAt,
	}
	got := toAPINodeLifecycleInstallOperationStatus(status)
	if got.Claim != status.Claim || got.OperationId != status.OperationID || got.Epoch != 7 ||
		got.State != api.NodeLifecycleInstallOperationState(nodes.LifecycleInstallAbortRequested) ||
		!got.NotAfter.Equal(status.NotAfter) || !got.ServerTime.Equal(status.ServerTime) || got.AbortRequestedAt == nil {
		t.Fatalf("API operation mapping lost exact CAS/clock state: %+v", got)
	}
}

func TestGeneratedLifecycleInstallBeginUsesCanonicalIntentDigest(t *testing.T) {
	wire, err := json.Marshal(api.NodeLifecycleInstallBeginRequest{
		ExpectedGeneration: 1, RequestId: uuid.New(), OperationId: uuid.New(),
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire, []byte(`"install_intent_digest"`)) || bytes.Contains(wire, []byte(`"approved_plan_digest"`)) {
		t.Fatalf("generated begin request used ambiguous digest wire key: %s", wire)
	}
}

func TestNodeLifecycleInstallBeginWireRejectsDisplayPlanDigest(t *testing.T) {
	orgID := uuid.MustParse("00000000-0000-4000-8000-000000000010")
	principal := &authctx.Principal{
		UserID: uuid.New(), EmailVerified: true, AuthMethod: authctx.AuthLocalPassword,
		Roles: map[uuid.UUID]string{orgID: rbac.RoleOperator},
	}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{
		Orgs: tenancy.NewService(nil), AuthFn: func(*stdhttp.Request) *authctx.Principal { return principal },
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/organizations/00000000-0000-4000-8000-000000000010/nodes/lifecycle-claims/00000000-0000-4000-8000-000000000011/install-operations"
	base := `{"expected_generation":1,"request_id":"00000000-0000-4000-8000-000000000012","operation_id":"00000000-0000-4000-8000-000000000013","release_namespace":"tunnex","release_name":"tunnex-gateway","requested_duration_seconds":120,`
	oldRequest := httptest.NewRequest(stdhttp.MethodPost, path, strings.NewReader(base+`"approved_plan_digest":"sha256:`+strings.Repeat("a", 64)+`"}`))
	oldRequest.Header.Set("Content-Type", "application/json")
	oldResponse := httptest.NewRecorder()
	router.ServeHTTP(oldResponse, oldRequest)
	if oldResponse.Code != stdhttp.StatusBadRequest {
		t.Fatalf("display-plan digest field status=%d body=%s", oldResponse.Code, oldResponse.Body.String())
	}
}

func TestLifecycleInstallCollectionRollingCompatibilityTripwire(t *testing.T) {
	const collectionPath = "/api/v1/organizations/{orgId}/nodes/lifecycle-claims/{claim}/install-operations"
	requestPath := "/api/v1/organizations/" + uuid.NewString() + "/nodes/lifecycle-claims/" + uuid.NewString() + "/install-operations"

	// Authoritative N-1 has no install-operations collection at all; A1 POST
	// and A2 GET ship atomically. Removing the entire collection therefore
	// preserves D13c's exact 404 route-absence signature.
	nMinusOneSpec, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	nMinusOneSpec.Paths.Delete(collectionPath)
	nMinusOneSpec.Servers = nil
	next := stdhttp.HandlerFunc(func(response stdhttp.ResponseWriter, _ *stdhttp.Request) {
		response.WriteHeader(stdhttp.StatusNoContent)
	})
	nMinusOneValidator := oapimw.OapiRequestValidatorWithOptions(nMinusOneSpec, &oapimw.Options{
		ErrorHandler: validationErrorHandler,
		Options: openapi3filter.Options{
			AuthenticationFunc: func(context.Context, *openapi3filter.AuthenticationInput) error { return nil },
		},
	})(next)
	nMinusOneResponse := httptest.NewRecorder()
	nMinusOneValidator.ServeHTTP(nMinusOneResponse, httptest.NewRequest(stdhttp.MethodGet, requestPath, nil))
	var nMinusOneBody struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(nMinusOneResponse.Body.Bytes(), &nMinusOneBody); err != nil {
		t.Fatal(err)
	}
	if nMinusOneResponse.Code != stdhttp.StatusNotFound || nMinusOneBody.Error.Code != "validation_failed" || nMinusOneBody.Error.Message != "no matching operation was found" {
		t.Fatalf("authoritative N-1 route miss = %d %s", nMinusOneResponse.Code, nMinusOneResponse.Body.String())
	}

	// A synthetic partial rollout with POST but no GET is deliberately not the
	// supported A1+A2 release shape. Its 405 must remain distinguishable from
	// the exact D13c 404; clients therefore fail closed instead of broadening
	// route-missing retries.
	intermediateSpec, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	intermediateSpec.Paths.Value(collectionPath).Get = nil
	intermediateSpec.Servers = nil
	intermediateValidator := oapimw.OapiRequestValidatorWithOptions(intermediateSpec, &oapimw.Options{
		ErrorHandler: validationErrorHandler,
		Options: openapi3filter.Options{
			AuthenticationFunc: func(context.Context, *openapi3filter.AuthenticationInput) error { return nil },
		},
	})(next)
	intermediateResponse := httptest.NewRecorder()
	intermediateValidator.ServeHTTP(intermediateResponse, httptest.NewRequest(stdhttp.MethodGet, requestPath, nil))
	var intermediateBody struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(intermediateResponse.Body.Bytes(), &intermediateBody); err != nil {
		t.Fatal(err)
	}
	if intermediateResponse.Code != stdhttp.StatusMethodNotAllowed || intermediateBody.Error.Code != "validation_failed" || intermediateBody.Error.Message == "no matching operation was found" {
		t.Fatalf("synthetic POST-only intermediate = %d %s", intermediateResponse.Code, intermediateResponse.Body.String())
	}
}

func TestLifecycleInstallCASRejectsInvalidEpochAndGeneration(t *testing.T) {
	claim, operation, requestID := uuid.New(), uuid.New(), uuid.New()
	if _, err := lifecycleInstallCAS(claim, operation, 1, requestID, 0); err == nil {
		t.Fatal("zero install epoch reached service handler")
	}
	if _, err := lifecycleInstallCAS(claim, operation, 2147483648, requestID, 1); err == nil {
		t.Fatal("overflowing install generation narrowed at handler")
	}
	got, err := lifecycleInstallCAS(claim, operation, 1, requestID, 1)
	if err != nil || got.Claim != claim || got.OperationID != operation || got.RequestID != requestID || got.ExpectedEpoch != 1 {
		t.Fatalf("valid install CAS = %+v err=%v", got, err)
	}
}

func lifecycleInstallRouteTestPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run lifecycle install route integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	base, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	databaseName := "tnx_d13k_route_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+databaseName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+databaseName+" WITH (FORCE)")
	})
	fresh := *base
	fresh.Path = "/" + databaseName
	if err := db.MigrateTo(fresh.String(), 136); err != nil {
		t.Fatalf("migrate disposable D13k route database: %v", err)
	}
	pool, err := pgxpool.New(ctx, fresh.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var version int64
	var dirty bool
	if err := pool.QueryRow(ctx, `SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatal(err)
	}
	if version != 136 || dirty {
		t.Fatalf("disposable D13k route migration state version=%d dirty=%t, want 136/false", version, dirty)
	}
	return pool, ctx
}

func TestNodeLifecycleInstallRecoveryRoutesPostgres(t *testing.T) {
	pool, ctx := lifecycleInstallRouteTestPool(t)

	orgID, otherOrgID, actorID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,$2,$3),($4,$5,$6)`,
		orgID, "D13k Route", "d13k-route-"+orgID.String(),
		otherOrgID, "D13k Other", "d13k-other-"+otherOrgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,name) VALUES($1,$2,$3)`, actorID, actorID.String()+"@d13k.test", "D13k Actor"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1 OR id=$2`, orgID, otherOrgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actorID)
	})

	nodeService := nodes.NewService(pool, nil, nil)
	principal := &authctx.Principal{
		UserID: actorID, EmailVerified: true, AuthMethod: authctx.AuthLocalPassword,
		Roles: map[uuid.UUID]string{orgID: rbac.RoleOperator, otherOrgID: rbac.RoleOperator},
	}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{
		Orgs: tenancy.NewService(pool), Nodes: nodeService,
		AuthFn: func(*stdhttp.Request) *authctx.Principal { return principal },
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	type errorEnvelope struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	parseError := func(response *httptest.ResponseRecorder) errorEnvelope {
		var envelope errorEnvelope
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode error response %d %q: %v", response.Code, response.Body.String(), err)
		}
		return envelope
	}

	absentClaim, absentRequest, absentOperation, absentToken := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_join_tokens(
			id,org_id,node_name,token_hash,expires_at,issued_by,enrols_kind,
			lifecycle_claim,lifecycle_generation,lifecycle_request_id,lifecycle_acknowledged_at)
		VALUES($1,$2,$3,$4,clock_timestamp()-interval '1 second',$5,'gateway',$6,1,$7,clock_timestamp())`,
		absentToken, orgID, "d13k-absent", []byte(uuid.NewString()), actorID, absentClaim, absentRequest); err != nil {
		t.Fatal(err)
	}
	absentPath := "/api/v1/organizations/" + orgID.String() + "/nodes/lifecycle-claims/" + absentClaim.String() + "/install-operations"
	domainMissing := do(stdhttp.MethodGet, absentPath, "")
	domainEnvelope := parseError(domainMissing)
	if domainMissing.Code != stdhttp.StatusNotFound || domainEnvelope.Error.Code != "lifecycle_install_operation_not_found" || domainEnvelope.Error.RequestID == "" {
		t.Fatalf("domain absence = %d %s", domainMissing.Code, domainMissing.Body.String())
	}
	routeMissing := do(stdhttp.MethodGet, absentPath+"/"+absentOperation.String(), "")
	routeEnvelope := parseError(routeMissing)
	if routeMissing.Code != stdhttp.StatusNotFound || routeEnvelope.Error.Code != "validation_failed" || routeEnvelope.Error.Message != "no matching operation was found" {
		t.Fatalf("D13c route absence = %d %s", routeMissing.Code, routeMissing.Body.String())
	}
	if routeEnvelope.Error.Code == domainEnvelope.Error.Code || routeEnvelope.Error.Message == domainEnvelope.Error.Message {
		t.Fatal("domain absence was indistinguishable from D13c transport-route absence")
	}

	beginWire, err := json.Marshal(api.NodeLifecycleInstallBeginRequest{
		ExpectedGeneration: 1, RequestId: absentRequest, OperationId: absentOperation,
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("a", 64), RequestedDurationSeconds: 120,
	})
	if err != nil {
		t.Fatal(err)
	}
	absentBegin := do(stdhttp.MethodPost, absentPath, string(beginWire))
	absentBeginEnvelope := parseError(absentBegin)
	if absentBegin.Code != stdhttp.StatusConflict || absentBeginEnvelope.Error.Code != "lifecycle_install_operation_absent_after_expiry" || absentBeginEnvelope.Error.RequestID == "" {
		t.Fatalf("expired absent Begin = %d %s", absentBegin.Code, absentBegin.Body.String())
	}

	claim, requestID, operationID, tokenID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_join_tokens(
			id,org_id,node_name,token_hash,expires_at,issued_by,enrols_kind,
			lifecycle_claim,lifecycle_generation,lifecycle_request_id,lifecycle_acknowledged_at)
		VALUES($1,$2,$3,$4,clock_timestamp()+interval '1 hour',$5,'gateway',$6,1,$7,clock_timestamp())`,
		tokenID, orgID, "d13k-completed", []byte(uuid.NewString()), actorID, claim, requestID); err != nil {
		t.Fatal(err)
	}
	actor := nodes.LifecycleActor{IssuerUserID: actorID, AuditUserID: actorID}
	started, err := nodeService.BeginLifecycleInstall(ctx, actor, orgID, nodes.LifecycleInstallBegin{
		Claim: claim, ExpectedGeneration: 1, RequestID: requestID, OperationID: operationID,
		ReleaseNamespace: "tunnex", ReleaseName: "tunnex-gateway",
		InstallIntentDigest: "sha256:" + strings.Repeat("b", 64), RequestedDurationSeconds: 120,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `UPDATE node_join_tokens SET consumed_at=clock_timestamp() WHERE id=$1`, tokenID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO nodes(org_id,name,cert_serial,agent_version,lifecycle_claim)
		SELECT org_id,node_name,$2,'d13k-test',lifecycle_claim FROM node_join_tokens WHERE id=$1`,
		tokenID, "d13k-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := nodeService.CompleteLifecycleInstall(ctx, actor, orgID, nodes.LifecycleInstallComplete{
		LifecycleInstallCAS: nodes.LifecycleInstallCAS{
			Claim: claim, ExpectedGeneration: 1, RequestID: requestID,
			OperationID: operationID, ExpectedEpoch: started.Epoch,
		},
		ReleaseReady: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_join_tokens SET expires_at=clock_timestamp()-interval '1 second',lifecycle_token_sealed=NULL WHERE id=$1`, tokenID); err != nil {
		t.Fatal(err)
	}
	completedPath := "/api/v1/organizations/" + orgID.String() + "/nodes/lifecycle-claims/" + claim.String() + "/install-operations"
	completedResponse := do(stdhttp.MethodGet, completedPath, "")
	if completedResponse.Code != stdhttp.StatusOK {
		t.Fatalf("completed latest GET = %d %s", completedResponse.Code, completedResponse.Body.String())
	}
	var completed api.NodeLifecycleInstallOperationStatus
	if err := json.Unmarshal(completedResponse.Body.Bytes(), &completed); err != nil {
		t.Fatal(err)
	}
	if completed.State != api.NodeLifecycleInstallOperationStateCompleted || completed.OperationId != operationID || completed.CompletedAt == nil {
		t.Fatalf("completed latest body = %+v", completed)
	}
	for _, secretKey := range []string{"join_token", "token_hash", "lifecycle_token_sealed"} {
		if bytes.Contains(completedResponse.Body.Bytes(), []byte(secretKey)) {
			t.Fatalf("completed latest response leaked %q: %s", secretKey, completedResponse.Body.String())
		}
	}
	foreignPath := "/api/v1/organizations/" + otherOrgID.String() + "/nodes/lifecycle-claims/" + claim.String() + "/install-operations"
	foreignResponse := do(stdhttp.MethodGet, foreignPath, "")
	foreignEnvelope := parseError(foreignResponse)
	if foreignResponse.Code != stdhttp.StatusNotFound || foreignEnvelope.Error.Code != "lifecycle_install_operation_not_found" || strings.Contains(foreignResponse.Body.String(), operationID.String()) || strings.Contains(foreignResponse.Body.String(), "tunnex-gateway") {
		t.Fatalf("cross-org latest response = %d %s", foreignResponse.Code, foreignResponse.Body.String())
	}
}

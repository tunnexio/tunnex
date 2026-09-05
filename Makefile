# Tunnex.io — developer Makefile
# One-command boot lives here: `make up` / `make down`.

.DEFAULT_GOAL := help
# `make up` uses the same compose contract as an installed deployment. Configure SMTP in `.env` for mail.
COMPOSE := docker compose -f docker-compose.yml -f docker-compose.dev.yml
# The base stack ALONE — what a customer's deployment resembles. Used by targets that must not inherit
# dev conveniences.
COMPOSE_BASE := docker compose

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: up
up: ## Start the full DEV stack
	@test -f .env || cp .env.example .env
	$(COMPOSE) up -d --build
	@echo "Tunnex is starting → http://localhost"
	@# ⛔ SURFACE THE FIRST-RUN CREDENTIAL ON THE OPERATOR'S TERMINAL.
	@#
	@# The API prints a framed banner to ITS stdout — which `up -d` sends to the container log and NOT to
	@# the terminal the operator is sitting at. Three attempts failed on that same blind spot: a JSON log
	@# line (invisible in a wall of JSON), a file (path is inside the container, so `cat` on the host finds
	@# nothing), and the banner itself (correct, and detached mode hides it).
	@#
	@# ⭐ THE QUESTION WAS NEVER "WHERE DOES THE CREDENTIAL GO" — IT WAS "WHERE ARE THE OPERATOR'S EYES".
	@# They are here, on the output of the command they just ran.
	@#
	@# ⚠ Prints NOTHING on a deployment that already has an admin, because the banner is only emitted on a
	@# genuinely first run — so this cannot republish a live credential on every `make up`.
	@# ⛔ GATED ON THE CREDENTIAL STILL BEING UNCLAIMED, and that gate is not optional. The container LOG
	@# keeps the banner forever, so an ungated grep reprints it on every `make up` — republishing a
	@# password that may already have been changed, to a terminal, indefinitely. Asked of the database
	@# instead: `must_change_password` is true only until the operator sets their own, so this stops the
	@# moment the credential stops working.
	@if [ "$$($(COMPOSE) exec -T postgres psql -U $(PG_USER) -d $(PG_DB) -tAc \
	    "select count(*) from users where must_change_password" 2>/dev/null | tr -d ' ')" != "0" ]; then \
	  $(COMPOSE) logs api 2>/dev/null | grep -B1 -A14 "TUNNEX - FIRST RUN" \
	    | sed 's/^[a-z-]*-1  *| \{0,1\}//'; \
	fi

.PHONY: up-enterprise
up-enterprise: ## ⛔ THERE IS NO ENTERPRISE BUILD ANY MORE — edition comes from a LICENCE KEY (S12.1)
	@echo ""
	@echo "⛔ THIS TARGET NO LONGER DOES WHAT ITS NAME SAYS, AND IT IS KEPT ONLY TO SAY SO."
	@echo ""
	@echo "   S12.1 collapsed the build-tag split. There is ONE binary. It passed"
	@echo "   TUNNEX_BUILD_TAGS=enterprise, which now selects nothing, and promised"
	@echo "   '# -> enterprise', which the binary could not produce."
	@echo ""
	@echo "   ⚠ THAT LIE COST A REVIEW SESSION: both stacks reported \"open\", and the"
	@echo "   obvious suspects (stale image, wrong compose) were checked first because"
	@echo "   this target said the build could differ. It cannot."
	@echo ""
	@echo "   EDITION IS NOW A PROPERTY OF THE INSTALLED LICENCE:"
	@echo "     Community / no key  → /meta reports \"open\""
	@echo "     any paid tier       → /meta reports \"enterprise\""
	@echo ""
	@echo "   To get an enterprise deployment:"
	@echo "     1. make up"
	@echo "     2. install a licence key — Settings → Licence, or"
	@echo "        POST /api/v1/organizations/{orgId}/license  (owner only)"
	@echo ""
	@echo "   Verify from OUTSIDE, and ask the API rather than the badge:"
	@echo "     curl -s localhost/api/v1/meta | grep -o '\"edition\":\"[a-z]*\"'"
	@echo ""
	@exit 1

# ── ⛔ THE OPEN-EDITION REVIEW STACK (S14.12) ───────────────────────────────────────────────────────────
#
# WHY IT EXISTS: EVERY edition-gated render in EPIC 14 has been reviewed on an ENTERPRISE stack, where the
# open-edition path never executes. S14.11 found TWO edition-before-permission bugs in the web app, BOTH
# invisible on that stack. Access Policies is 100% edition-gated — the whole screen collapses to ONE state on
# the open build — so reviewing it on enterprise would sign off a render nobody has ever seen.
#
# SHAPE, and every choice is about NOT disturbing the primary stack:
#   project   COMPOSE_PROJECT_NAME=tunnex-open  -> its OWN network, volumes and postgres. No shared state.
#   edition   NO TUNNEX_BUILD_TAGS              -> the open api image. That is the entire difference.
#   ports     every host port overridden (+1 / +1000). The primary stack's defaults are UNCHANGED, so a
#             plain `make up-enterprise` still binds :80 exactly as before.
#   fixtures  the SAME embedded fixtures.sql, run by the SAME seeder binary, against this project's DB.
#             ⛔ ZERO DRIFT BY CONSTRUCTION: one source, two databases. The tables exist in both (migrations
#             are edition-independent); only the API binary differs, which is the point.
#
#   ⛔ ONE LEGITIMATE DIFFERENCE, NAMED SO IT IS NOT MISTAKEN FOR DRIFT: the seeder registers `posture_blocked`
#   THROUGH THE PRODUCT, and device-health reporting is edition-gated. On the open stack that POST answers
#   403 edition_required, so posture_blocked is ABSENT — correctly, because posture is an enterprise feature.
#   `seed-open` therefore runs with TUNNEX_SEED_STRICT=false. That is an EDITION difference, not a fixture gap.
OPEN_ENV = COMPOSE_PROJECT_NAME=tunnex-open HOST_HTTP_PORT=8081 HOST_API_MTLS_PORT=8444 \
           HOST_WG_PORT=51821

.PHONY: up-open-review
up-open-review: ## Start the OPEN-edition review stack alongside the primary one (http://localhost:8081)
	@test -f .env || cp .env.example .env
	$(OPEN_ENV) docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
	@echo ""
	@echo "OPEN-edition review stack -> http://localhost:8081"
	@echo "Verify:  curl -s localhost:8081/api/v1/meta | grep -o '\"edition\":\"[a-z]*\"'   # -> open"
	@echo "The ENTERPRISE stack is untouched on http://localhost"

.PHONY: seed-open
seed-open: ## Seed the open-edition review stack (migrate + base seed + fixtures, in that order)
	@# ⛔ THREE STEPS, IN ORDER, because `fixtures.sql` LAYERS ON TOP of the base seed and refuses without it
	@# ("the demo org does not exist"). The primary stack was seeded months ago so the ordering was invisible;
	@# a fresh database is what surfaced it. A one-command switch has to carry the whole chain or it is not one.
	$(OPEN_ENV) $(MAKE) migrate COMPOSE_PROJECT_NAME=tunnex-open
	$(OPEN_ENV) TUNNEX_SEED_FORCE=$(or $(TUNNEX_SEED_FORCE),false) $(MAKE) seed COMPOSE_PROJECT_NAME=tunnex-open
	$(OPEN_ENV) TUNNEX_SEED_FORCE=true TUNNEX_SEED_STRICT=false $(MAKE) seed-fixtures \
	  COMPOSE_PROJECT_NAME=tunnex-open

.PHONY: down-open-review
down-open-review: ## Stop the open-edition review stack (leaves the primary stack running)
	$(OPEN_ENV) docker compose -f docker-compose.yml -f docker-compose.dev.yml down

.PHONY: down
down: ## Stop the stack (keep volumes)
	$(COMPOSE) down

.PHONY: reset
reset: ## Stop the stack and delete all data volumes
	$(COMPOSE) down -v

.PHONY: ps
ps: ## Show service status
	$(COMPOSE) ps

.PHONY: logs
logs: ## Tail all service logs
	$(COMPOSE) logs -f

.PHONY: migrate
migrate: ## Apply all database migrations
	$(COMPOSE) run --rm --build migrate up

.PHONY: migrate-down
migrate-down: ## Roll back one database migration
	$(COMPOSE) run --rm --build migrate down

.PHONY: migrate-version
migrate-version: ## Print the current schema version
	$(COMPOSE) run --rm --build migrate version

.PHONY: migrate-create
migrate-create: ## Scaffold a migration pair: make migrate-create name=add_widgets
	@test -n "$(name)" || { echo "usage: make migrate-create name=<snake_case>"; exit 1; }
	@dir=apps/api/db/migrations; \
	next=$$(printf "%04d" $$(( $$(ls $$dir/*.up.sql 2>/dev/null | wc -l | tr -d ' ') + 1 ))); \
	touch $$dir/$${next}_$(name).up.sql $$dir/$${next}_$(name).down.sql; \
	echo "created $$dir/$${next}_$(name).{up,down}.sql"

.PHONY: sqlc
sqlc: ## Regenerate typed query code from db/queries
	docker run --rm -v "$(PWD)/apps/api":/src -w /src sqlc/sqlc generate

# --- Code generation (OpenAPI-first: the spec is the single source of truth) ---
# Pin the exact Go patch so local and container builds produce identical codegen.
# GUARD: the Go build/test recipes below pass GOFLAGS=-mod=readonly deliberately.
# The module path matches the canonical repository at github.com/tunnexio/tunnex.
# Keep -mod=readonly so builds remain reproducible and cannot silently rewrite
# go.mod/go.sum while resolving dependencies.
GO_IMAGE := golang:1.25.13-alpine
NODE_IMAGE := node:20-alpine
PW_IMAGE := mcr.microsoft.com/playwright:v1.48.2-jammy
OAPI_CODEGEN_VERSION := v2.4.1
OPENAPI_TS_VERSION := 7.4.4

# Compose network + dev DB creds (defaults match .env.example) used by seed/e2e.
# ⛔ DERIVED FROM COMPOSE_PROJECT_NAME, not hard-coded. Every docker-run target below (`migrate`, `seed`,
# `seed-fixtures`, `sqlc`) joins a compose network BY NAME. `COMPOSE_PROJECT_NAME=tunnex-s141 make up-enterprise`
# creates `tunnex-s141_default`, but a hard-coded `tunnex_default` sent all of those at a DIFFERENT STACK'S
# DATABASE while appearing to succeed. `seed-fixtures` refused (its real-data guard fired on 6690 orgs);
# `migrate` has no such guard. Found in S14.7 while seeding for review.
#
# Unset behaves exactly as before, so no existing invocation changes.
NET := $(if $(COMPOSE_PROJECT_NAME),$(COMPOSE_PROJECT_NAME)_default,tunnex_default)
PG_USER ?= tunnex
PG_PASS ?= tunnex_dev_password
PG_DB ?= tunnex
# The compose-managed named volume holding the master key. seed-enterprise mounts it to SEAL with the API's
# key — so the SAME class as NET one line up, and worse in effect: sealing against a different stack's master
# key produces a secret THAT STACK CANNOT UNSEAL, with no error at seal time.
SECRETS_VOL := $(if $(COMPOSE_PROJECT_NAME),$(COMPOSE_PROJECT_NAME)_tunnex_secrets,tunnex_tunnex_secrets)

# Dependency caches are independent of Compose networks/stores. Keep existing
# developer defaults, but allow isolated gates to avoid mutating another lane's
# installed dependency tree. Set this together with COMPOSE_PROJECT_NAME.
GATE_CACHE_PREFIX ?= tunnex
ROOT_NM_VOL := $(GATE_CACHE_PREFIX)-nm
SHARED_NM_VOL := $(GATE_CACHE_PREFIX)-shared-nm
WEB_NM_VOL := $(GATE_CACHE_PREFIX)-web-nm

.PHONY: generate
generate: generate-go generate-ts generate-rbac generate-tokens sqlc ## Regenerate all code from openapi/openapi.yaml

.PHONY: generate-tokens
generate-tokens: ## S14.1: emit the design-token artifacts from packages/shared/src/tokens.ts (the ONE authored form)
	# Configs consume the EMITTED css/json, never the TypeScript: a config file loads through Node, which
	# cannot read a raw .ts entry, and importing the .ts by relative path deadlocks TS project references.
	# Committing the artifacts and drift-guarding them is this repo's established pattern (api.d.ts,
	# rbac-policy.json) rather than a new one.
	docker run --rm -v "$(PWD)":/w -w /w/packages/shared \
	  -v $(ROOT_NM_VOL):/w/node_modules -v $(SHARED_NM_VOL):/w/packages/shared/node_modules \
	  node:20-alpine sh -c 'corepack enable && pnpm install --filter @tunnex/shared --no-frozen-lockfile >/dev/null && \
	    ./node_modules/.bin/tsc -p tsconfig.tokens.json && node scripts/emit-tokens.mjs'

.PHONY: generate-rbac
generate-rbac: ## Emit the RBAC grant table (rbac.Policy) as JSON for the web client mirror
	docker run --rm -v "$(PWD)":/repo -w /repo/apps/api -e GOFLAGS=-mod=mod $(GO_IMAGE) \
	  go run ./cmd/rbac-policy-gen /repo/apps/web/src/lib/rbac-policy.json

.PHONY: generate-go
generate-go: ## Generate the Go server (api) + Go client (cli) from the spec
	@mkdir -p apps/api/internal/api apps/cli/internal/api
	docker run --rm -v "$(PWD)":/repo -w /repo/apps/api -e GOFLAGS=-mod=mod $(GO_IMAGE) \
	  go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION) \
	  -config oapi-codegen.yaml ../../openapi/openapi.yaml
	docker run --rm -v "$(PWD)":/repo -w /repo/apps/cli -e GOFLAGS=-mod=mod $(GO_IMAGE) \
	  go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION) \
	  -config oapi-codegen.yaml ../../openapi/openapi.yaml

.PHONY: generate-ts
generate-ts: ## Generate the TypeScript API types from the spec
	docker run --rm -v "$(PWD)":/repo -w /repo/packages/shared $(NODE_IMAGE) \
	  npx --yes openapi-typescript@$(OPENAPI_TS_VERSION) ../../openapi/openapi.yaml -o src/api.d.ts

.PHONY: generate-check
generate-check: generate ## Fail if generated code is out of date (CI drift guard)
	@git diff --exit-code -- \
	  apps/api/internal/api apps/cli/internal/api apps/api/db/sqlc packages/shared/src/api.d.ts apps/web/src/lib/rbac-policy.json \
	  packages/shared/generated \
	  || { echo ""; echo "ERROR: generated code is stale. Run 'make generate' and commit the result."; exit 1; }
	@echo "generated code is up to date."

.PHONY: cli-dist
cli-dist: ## Cross-compile the tunnex CLI for release + SHA256SUMS (S5.1)
	@mkdir -p dist
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
	  goos=$${target%/*}; goarch=$${target#*/}; ext=""; \
	  [ "$$goos" = "windows" ] && ext=".exe"; \
	  echo ">> $$goos/$$goarch"; \
	  docker run --rm -v "$(PWD)":/repo -w /repo/apps/cli -e GOFLAGS=-mod=mod \
	    -e CGO_ENABLED=0 -e GOOS=$$goos -e GOARCH=$$goarch $(GO_IMAGE) \
	    go build -trimpath -ldflags="-s -w" -o /repo/dist/tunnex-$$goos-$$goarch$$ext ./cmd/tunnex || exit 1; \
	done
	@cd dist && sha256sum tunnex-* > SHA256SUMS && cat SHA256SUMS
	@echo ">> dist/ ready — publish the binaries WITH SHA256SUMS (S5.1 release convention)."

.PHONY: build-editions
build-editions: ## Compile both open and enterprise builds (catches edition rot)
	@echo ">> open build"
	docker run --rm -v "$(PWD)/apps/api":/src -w /src -e GOFLAGS=-mod=readonly $(GO_IMAGE) go build ./...
	@echo ">> enterprise build (-tags enterprise)"
	docker run --rm -v "$(PWD)/apps/api":/src -w /src -e GOFLAGS=-mod=readonly $(GO_IMAGE) go build -tags enterprise ./...

.PHONY: test-editions
# -p 1: api packages run SERIALLY. The integration suites share ONE live DB and several commit
# fixture rows (orgs) outside any tx — package-level parallelism made globally-counted state
# (the open-edition org limit, list counts) race across packages (first exposed by the S8.5
# sites suite on CI). Serial execution kills the class structurally; per-test scoping can't
# (the org limit is a GLOBAL count by product semantics).
test-editions: ## Run the suite in BOTH editions against the live DB
	$(COMPOSE) up -d --wait postgres
	@# The REPO ROOT is mounted, not just apps/api (S11). Several guards deliberately read files OUTSIDE the
	@# module — the api Dockerfile (TestEveryOperatorToolShipsInTheImage), openapi.yaml and the web health
	@# renderer (TestEveryHealthKindReachesItsMirrorSurfaces) — because the drift they catch lives BETWEEN
	@# surfaces, which is precisely what a module-scoped test cannot see. Mounting only apps/api made those
	@# guards fail here while passing locally; the alternative, skipping when the file is absent, would have
	@# made them pass here while checking nothing, which is the worse failure (see the witness-liveness law).
	@echo ">> open edition tests"
	docker run --rm --network $(NET) -v "$(PWD)":/repo -w /repo/apps/api -e GOFLAGS=-mod=readonly \
	  -e TUNNEX_TEST_DATABASE_URL="postgres://$(PG_USER):$(PG_PASS)@postgres:5432/$(PG_DB)?sslmode=disable" \
	  $(GO_IMAGE) go test -p 1 ./...
	@echo ">> enterprise edition tests (-tags enterprise)"
	docker run --rm --network $(NET) -v "$(PWD)":/repo -w /repo/apps/api -e GOFLAGS=-mod=readonly \
	  -e TUNNEX_TEST_DATABASE_URL="postgres://$(PG_USER):$(PG_PASS)@postgres:5432/$(PG_DB)?sslmode=disable" \
	  $(GO_IMAGE) go test -p 1 -tags enterprise ./...

.PHONY: test-node
test-node: ## Run the node-agent data-plane tests (reconcile idempotence, no DB)
	# openvpn: the ovpnserver WF-OVPN-1 acceptance red runs the real binary against the generated
	# server.conf (--dev null) — so the config is proven to be one openvpn ACCEPTS, not just key-present.
	# --cap-add=NET_ADMIN: the L11 nft-render-check (TestRenderedRulesetIsValidNft) runs `nft -c` which opens
	# netlink to init its cache — needs NET_ADMIN even in check-only mode. Without the cap that one test SKIPS
	# (never false-fails), so the render-valid proof only holds when the cap is present (it is, here + in CI).
	docker run --rm --cap-add=NET_ADMIN -v "$(PWD)/apps/node":/src -w /src -e GOFLAGS=-mod=readonly \
	  $(GO_IMAGE) sh -c "apk add --no-cache git openvpn nftables && go test ./..."

.PHONY: test-operator
test-operator: ## Build the GitOps operator + run the no-DB-import census (S10.2). Edition-agnostic (one build; the operator is open deployment tooling, no enterprise tag).
	# THE HARD RULE red: `go test` runs the no-DB-import census (hardrule_test.go) over the full dep graph.
	docker run --rm -v "$(PWD)/apps/operator":/src -w /src -e GOFLAGS=-mod=readonly \
	  $(GO_IMAGE) sh -c "apk add --no-cache git && go build ./... && go test ./..."

.PHONY: test-k8s-charts
test-k8s-charts: ## Lint and semantically render host posture, gateway, GitOps operator, and monotonic CRD charts.
	bash deploy/helm-package-reproducible-contract_test.sh
	bash deploy/k8s-host-posture-chart-contract_test.sh
	bash deploy/k8s-gateway-chart-contract_test.sh
	bash deploy/k8s-operator-crd-chart-contract_test.sh
	bash deploy/k8s-operator-chart-contract_test.sh
	bash deploy/k8s-walk-candidate-package-contract_test.sh

.PHONY: web-gate
web-gate: ## Run the FULL web gate (typecheck + test + build) in Node 20 — works on any host (S11 debt repayment)
	# The standing web-gate-local-env debt: the repo requires node>=20, hosts are often on 18, so
	# `pnpm --filter @tunnex/web typecheck` refused with ERR_PNPM_UNSUPPORTED_ENGINE and the web gate ran
	# ONLY in CI — three stories shipped with a "gates green" claim that silently excluded web test+build.
	# node_modules are CONTAINER-LOCAL named volumes (never the bind mount): pnpm links platform-specific
	# binaries (esbuild/rollup/vitest), and sharing them with a macOS host yields wrong-arch failures.
	docker run --rm -v "$(PWD)":/w -w /w \
	  -v $(ROOT_NM_VOL):/w/node_modules \
	  -v $(WEB_NM_VOL):/w/apps/web/node_modules \
	  -v $(SHARED_NM_VOL):/w/packages/shared/node_modules \
	  -e ELECTRON_SKIP_BINARY_DOWNLOAD=1 \
	  node:20-alpine sh -c 'apk add --no-cache jq >/dev/null && corepack enable && pnpm install --filter @tunnex/web... --no-frozen-lockfile && \
	    pnpm --filter @tunnex/web typecheck && pnpm --filter @tunnex/web test && pnpm --filter @tunnex/web build'

.PHONY: test-cli
test-cli: ## Build + vet + test the tunnex CLI (S11-2: this module had NO gate coverage at all)
	# S11-2: apps/cli was built by NO CI job — `generate-check` detects DRIFT in its generated client but
	# never COMPILES it, so a generated-code defect (an openapi schema name colliding with an oapi-codegen
	# response-wrapper type) shipped to main and sat there undetected. A shipped module with no gate is the
	# extreme case of the degraded-signal class this epic repays; build+vet+test closes it.
	docker run --rm -v "$(PWD)/apps/cli":/src -w /src -e GOFLAGS=-mod=readonly \
	  $(GO_IMAGE) sh -c "apk add --no-cache git && go build ./... && go vet ./... && go test ./..."

.PHONY: test-helper
test-helper: ## Vet + test the privilege-helper core (S6.3; x/sys dep for caller-path)
	docker run --rm -v "$(PWD)/apps/helper":/src -w /src -e GOFLAGS=-mod=readonly \
	  $(GO_IMAGE) sh -c "apk add --no-cache git && go vet ./... && go test ./..."

.PHONY: helper-crosscompile
helper-crosscompile: ## Compile-check the helper (incl platform build-tagged files) for all targets
	@for t in darwin/amd64 darwin/arm64 windows/amd64; do \
	  goos=$${t%/*}; goarch=$${t#*/}; echo ">> $$goos/$$goarch (CGO off)"; \
	  docker run --rm -v "$(PWD)/apps/helper":/src -w /src -e GOFLAGS=-mod=readonly \
	    -e CGO_ENABLED=0 -e GOOS=$$goos -e GOARCH=$$goarch \
	    $(GO_IMAGE) sh -c "apk add --no-cache git && go build ./..." || exit 1; \
	done
	@echo ">> helper cross-compiles (CGO off) for darwin/amd64+arm64 + windows/amd64."

.PHONY: seed
seed: ## Seed the demo org/user (idempotent, non-destructive)
	$(COMPOSE) up -d --wait postgres
	@# TUNNEX_SEED_FORCE is FORWARDED, not swallowed. `seed` refuses when the database already holds
	@# real orgs — a good guard — but the variable that overrides it never reached the container, so
	@# `seed-open` could not re-seed a review database once anything had accumulated in it (71 orgs,
	@# left by pointing a Go test run at that stack). The chain's own comment says a one-command
	@# switch has to carry the whole chain; it was not carrying this.
	docker run --rm --network $(NET) -v "$(PWD)/apps/api":/src -w /src -e GOFLAGS=-mod=readonly \
	  -e TUNNEX_SEED_FORCE="$(TUNNEX_SEED_FORCE)" \
	  -e DATABASE_URL="postgres://$(PG_USER):$(PG_PASS)@postgres:5432/$(PG_DB)?sslmode=disable" \
	  $(GO_IMAGE) go run ./cmd/seed

.PHONY: seed-enterprise
seed-enterprise: ## Seed the ENTERPRISE fixtures (SSO config + strandable device) ON TOP of `seed` (S7.4c)
	@echo '>> enterprise seed (requires the stack up so the master key exists; run after: make seed)'
	docker run --rm --network $(NET) -v "$(PWD)/apps/api":/src -w /src -e GOFLAGS=-mod=readonly \
	  -v $(SECRETS_VOL):/var/lib/tunnex/secrets -e TUNNEX_SECRETS_DIR=/var/lib/tunnex/secrets \
	  -e DATABASE_URL="postgres://$(PG_USER):$(PG_PASS)@postgres:5432/$(PG_DB)?sslmode=disable" \
	  $(GO_IMAGE) go run ./cmd/seed-enterprise

.PHONY: dev-sso-config
dev-sso-config: ## Point the LOCAL stack at a REAL IdP (dev only — see cmd/dev-sso-config)
	@# ⛔ APP_BASE_URL IS READ FROM .env, NOT PASSED THROUGH FROM THE CALLER'S SHELL. A bare
	@# `-e APP_BASE_URL` picked up nothing (nobody exports it), so config.Load() fell back to its
	@# default and the tool PRINTED `http://localhost/...` as the redirect_uri to go register — while
	@# the API container, which does read .env, was using the real one. A tool that reports a different
	@# URI than the server sends is worse than one that says nothing: it sends you off to edit the IdP.
	@#
	@# ⛔ THE SECRET IS FORWARDED FROM THE CALLER'S ENVIRONMENT, NEVER WRITTEN HERE OR INTO .env.
	@# `-e VAR` (no value) passes it through without it ever appearing in this file, in `make -n`
	@# output, or in the recipe echo — a secret spelled out in a Makefile is a secret in git.
	@#
	@#   TUNNEX_SSO_ORG_SLUG=demo TUNNEX_SSO_PROVIDER=microsoft \
	@#   TUNNEX_SSO_CLIENT_ID=... TUNNEX_SSO_CLIENT_SECRET=... TUNNEX_SSO_TENANT_ID=... \
	@#   make dev-sso-config
	@test -n "$$TUNNEX_SSO_CLIENT_SECRET" || { echo "TUNNEX_SSO_CLIENT_SECRET is not set in your environment"; exit 1; }
	docker run --rm --network $(NET) -v "$(PWD)/apps/api":/src -w /src -e GOFLAGS=-mod=readonly \
	  -v $(SECRETS_VOL):/var/lib/tunnex/secrets -e TUNNEX_SECRETS_DIR=/var/lib/tunnex/secrets \
	  -e DATABASE_URL="postgres://$(PG_USER):$(PG_PASS)@postgres:5432/$(PG_DB)?sslmode=disable" \
	  -e APP_BASE_URL="$(shell sed -n 's/^APP_BASE_URL=//p' .env)" \
	  -e TUNNEX_SSO_ORG_SLUG -e TUNNEX_SSO_PROVIDER \
	  -e TUNNEX_SSO_CLIENT_ID -e TUNNEX_SSO_CLIENT_SECRET -e TUNNEX_SSO_TENANT_ID \
	  $(GO_IMAGE) go run ./cmd/dev-sso-config

.PHONY: seed-fixtures
seed-fixtures: ## Seed the DEMO FIXTURES (populated network for UI review) ON TOP of `seed` (S14.5)
	@echo '>> demo fixtures: 5 gateways, 4 sites, 6 subnets, 5 devices, 12 audit entries (run after: make seed)'
	@# ⛔ TUNNEX_SEED_FORCE IS PASSED THROUGH. The seeder refuses on any non-demo org and its own hint names
	@# this variable as the override — but the Makefile did not forward it, so the DOCUMENTED escape hatch did
	@# not work through the documented entry point. TUNNEX_API_URL rides along for the posture-block report.
	docker run --rm --network $(NET) -v "$(PWD)/apps/api":/src -w /src -e GOFLAGS=-mod=readonly \
	  -e DATABASE_URL="postgres://$(PG_USER):$(PG_PASS)@postgres:5432/$(PG_DB)?sslmode=disable" \
	  -e TUNNEX_SEED_FORCE="$(TUNNEX_SEED_FORCE)" -e TUNNEX_API_URL="$(TUNNEX_API_URL)" \
	  -e TUNNEX_SEED_STRICT="$(TUNNEX_SEED_STRICT)" \
	  $(GO_IMAGE) go run ./cmd/seed-fixtures

.PHONY: k3s-demo k3s-demo-verify k3s-demo-down
k3s-demo: ## Bring up + register + expose the review k3s cluster for the Kubernetes screen, then VERIFY it (S14.8)
	scripts/k3s-demo.sh up

k3s-demo-verify: ## Verify the review cluster is up AND the control plane agrees with it (run before a review)
	scripts/k3s-demo.sh verify

k3s-demo-down: ## Stop the review cluster (CP rows stay -- that asymmetry is finding D9)
	scripts/k3s-demo.sh down

.PHONY: visual
visual: ## Run the viewport leg (visual regression). BASELINES ARE GENERATED IN THE SAME CONTAINER CI USES.
	# The playwright image is pinned to CI's. A baseline rendered on the host would NEVER match CI: font
	# rasterisation and subpixel AA differ per platform, so the suite would be red on its first run and the
	# only way out would be to widen the threshold — which is how a visual suite stops meaning anything.
	# UPDATE a baseline with:  make visual-update
	VITE_VISUAL_GALLERY=1 $(COMPOSE) up -d --build --wait
	docker run --rm --network $(NET) -v "$(PWD)/e2e":/e2e -w /e2e -e E2E_BASE_URL=http://nginx:8080 \
	  $(PW_IMAGE) sh -c "npm ci --no-audit --no-fund && npx playwright test -c playwright.visual.config.ts"

.PHONY: visual-update
visual-update: ## Re-render the visual baselines. THE RESULT MUST BE ITS OWN COMMIT, .png FILES ONLY.
	# A baseline update mixed into a feature commit is unreviewable — "N images changed" has to be a fact
	# someone can see, not something buried in a 40-file diff.
	VITE_VISUAL_GALLERY=1 $(COMPOSE) up -d --build --wait
	docker run --rm --network $(NET) -v "$(PWD)/e2e":/e2e -w /e2e -e E2E_BASE_URL=http://nginx:8080 \
	  $(PW_IMAGE) sh -c "npm ci --no-audit --no-fund && npx playwright test -c playwright.visual.config.ts --update-snapshots"

.PHONY: e2e-preflight
e2e-preflight: ## Clean CI-equivalent E2E dependency + source preflight (no stack required)
	@git ls-files --error-unmatch e2e/package-lock.json >/dev/null 2>&1 || \
	  { echo "ERROR: e2e/package-lock.json must be tracked for npm ci"; exit 1; }
	node e2e/check-heading-locators.mjs
	docker run --rm \
	  -v "$(PWD)/e2e":/e2e:ro \
	  --mount type=volume,target=/e2e/node_modules \
	  -w /e2e $(PW_IMAGE) \
	  sh -c "npm ci --no-audit --no-fund && npm run typecheck && npx playwright test --list >/dev/null"

.PHONY: e2e
e2e: ## One command: bring the stack up healthy, run API integration + Playwright e2e
	$(COMPOSE) up -d --wait
	@echo ">> API integration tests (unit + trigger schema check against live DB)"
	@# -p 1 IS NOT OPTIONAL, and it was missing here while test-editions had it. These packages share ONE
	@# database and several commit fixture rows without rolling back, so concurrent packages interfere.
	@# The interference was always present and only ever intermittent; the S12.1 organization ceiling made
	@# it reliable, because a concurrently-committed org now consumes the ONLY Community slot and
	@# TestOrgLifecycle's first create is refused. The ceiling exposed the race, it did not cause it —
	@# lifecycle_test.go's own comment has described this exact class since S8.5.
	docker run --rm --network $(NET) -v "$(PWD)/apps/api":/src -w /src -e GOFLAGS=-mod=readonly \
	  -e TUNNEX_TEST_DATABASE_URL="postgres://$(PG_USER):$(PG_PASS)@postgres:5432/$(PG_DB)?sslmode=disable" \
	  $(GO_IMAGE) go test -p 1 ./...
	@echo ">> Playwright browser e2e (SPA -> API correlation chain)"
	docker run --rm --network $(NET) -v "$(PWD)/e2e":/e2e -w /e2e -e E2E_BASE_URL=http://nginx:8080 \
	  $(PW_IMAGE) sh -c "npm ci --no-audit --no-fund && npx playwright test"
	@echo ">> e2e passed."

.PHONY: api
api: ## Run the API locally (outside docker)
	cd apps/api && go run ./cmd/server

.PHONY: agent
agent: ## Run the node agent locally (outside docker)
	cd apps/node && go run ./cmd/agent

.PHONY: web
web: ## Run the web dev server locally
	pnpm --filter @tunnex/web dev

.PHONY: tidy
tidy: ## Tidy Go modules
	cd apps/api && go mod tidy
	cd apps/node && go mod tidy

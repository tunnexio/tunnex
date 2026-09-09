#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME=tunnexworkload0909
test_context=colima-tunnex-sso-review
test_container=tunnexworkload0909-postgres-1
test_network=tunnexworkload0909_default
printf 'COMPOSE_PROJECT_NAME=%s\ncontainer=%s\nnetwork=%s\n' "$COMPOSE_PROJECT_NAME" "$test_container" "$test_network"
test "$(docker --context "$test_context" inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$test_container")" = "$COMPOSE_PROJECT_NAME"
test "$(docker --context "$test_context" network inspect --format '{{index .Labels "com.docker.compose.project"}}' "$test_network")" = "$COMPOSE_PROJECT_NAME"
test "$(docker --context "$test_context" inspect --format '{{with index .NetworkSettings.Networks "tunnexworkload0909_default"}}{{.NetworkID}}{{end}}' "$test_container")" = "$(docker --context "$test_context" network inspect --format '{{.Id}}' "$test_network")"
test "$(docker --context "$test_context" port "$test_container" 5432/tcp)" = '127.0.0.1:15489'
test "$(docker --context "$test_context" inspect --format '{{.State.Health.Status}}' "$test_container")" = healthy
export TUNNEX_TEST_DATABASE_URL='postgres://workload_test:workload_test_fixture@127.0.0.1:15489/workload_test?sslmode=disable'
export GOCACHE=/private/tmp/tunnex-workload-proof-gocache
export GOFLAGS=-mod=readonly
cd apps/api
# Older integration tests use the explicit fixture database directly, while
# testpostgres.New owns separate disposable children on the same server.
DATABASE_URL="$TUNNEX_TEST_DATABASE_URL" go run ./cmd/migrate up
go test "$@"

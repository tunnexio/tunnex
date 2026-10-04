#!/bin/sh
set -eu
cd "$(dirname "$0")"
./ownership.py
curl --fail --silent --show-error http://127.0.0.1:18083/healthz
curl --fail --silent --show-error http://127.0.0.1:19093/readyz
# Assertions fail loudly; readback alone is not acceptance.
./run.sh exec -T postgres psql -U aa0 -d aa0 -v ON_ERROR_STOP=1 -At <<'SQL'
DO $$ BEGIN
 IF current_database() <> 'aa0' OR current_user <> 'aa0' THEN RAISE EXCEPTION 'wrong database target'; END IF;
 IF (SELECT count(*) FROM schema_migrations) <> 1 OR EXISTS (SELECT 1 FROM schema_migrations WHERE dirty) THEN RAISE EXCEPTION 'migration dirty/missing'; END IF;
 IF (SELECT count(*) FROM nodes) <> 1 OR (SELECT count(*) FROM nodes WHERE name='aa0-gateway' AND status='active' AND enrolled_kind='gateway' AND last_seen_at > now()-interval '90 seconds' AND cert_not_after > now()) <> 1 THEN RAISE EXCEPTION 'active gateway identity/heartbeat assertion failed'; END IF;
END $$;
select version,dirty from schema_migrations;
select id,name,status,last_seen_at from nodes;
SQL
./docker-local.sh ps --filter label=com.docker.compose.project=tunnex-app-access-aa0-1003 --format '{{.ID}} {{.Names}} {{.Status}}'

#!/bin/sh
set -eu
cd "$(dirname "$0")"
./ownership.py
curl --fail --silent --show-error http://127.0.0.1:18283/healthz
curl --fail --silent --show-error http://127.0.0.1:19293/readyz
# Assertions fail loudly; readback alone is not acceptance.
./run.sh exec -T postgres psql -U bgplocal -d bgplocal -v ON_ERROR_STOP=1 -At <<'SQL'
DO $$ BEGIN
 IF current_database() <> 'bgplocal' OR current_user <> 'bgplocal' THEN RAISE EXCEPTION 'wrong database target'; END IF;
 IF (SELECT count(*) FROM schema_migrations) <> 1 OR EXISTS (SELECT 1 FROM schema_migrations WHERE dirty) THEN RAISE EXCEPTION 'migration dirty/missing'; END IF;
 IF (SELECT count(*) FROM nodes) <> 1 OR (SELECT count(*) FROM nodes WHERE name='bgp-local-gateway' AND status='active' AND enrolled_kind='gateway' AND last_seen_at > now()-interval '90 seconds' AND cert_not_after > now()) <> 1 THEN RAISE EXCEPTION 'active gateway identity/heartbeat assertion failed'; END IF;
END $$;
select version,dirty from schema_migrations;
select id,name,status,last_seen_at from nodes;
SQL
./docker-local.sh ps --filter label=com.docker.compose.project=tunnexs2sbgplocal1007 --format '{{.ID}} {{.Names}} {{.Status}}'

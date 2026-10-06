#!/bin/sh
set -eu
cd "$(dirname "$0")"
curl --fail --silent --show-error --retry 10 --retry-all-errors --retry-delay 2 http://127.0.0.1:18183/healthz
curl --fail --silent --show-error --retry 10 --retry-all-errors --retry-delay 2 http://127.0.0.1:19193/readyz
./run.sh exec -T postgres psql -U aa0 -d aa0 -v ON_ERROR_STOP=1 -At <<'SQL'
DO $$ BEGIN
 IF current_database() <> 'aa0' OR current_user <> 'aa0' THEN RAISE EXCEPTION 'wrong database'; END IF;
 IF (SELECT count(*) FROM schema_migrations) <> 1 OR EXISTS(SELECT 1 FROM schema_migrations WHERE dirty) THEN RAISE EXCEPTION 'dirty migration'; END IF;
 -- Identity qualification retains immutable audit rows and revoked identities.
 IF EXISTS(SELECT 1 FROM nodes n WHERE n.id<>'01a109d9-42ca-7d53-b4dd-3f166cd23192'::uuid AND
   (n.status<>'revoked' OR n.enrolled_kind<>'gateway' OR (n.id,n.org_id,n.name) NOT IN (
    ('01a10aa3-6d0b-7dfa-b06f-17fb19a0299c'::uuid,'b2891d06-c082-4800-a418-f987e52ef3e9'::uuid,'sa9-identity-foreign_org_gateway-b2891d06'),
    ('01a10aa4-1850-7b58-8c66-8aea22b0be6b'::uuid,'7e52582a-b12e-459d-8bd8-d167a727c4ef'::uuid,'sa9-identity-foreign_org_gateway-7e52582a'),
    ('01a10aa5-5f37-7fe9-8b1b-273ab1739cea'::uuid,'0f310c80-342e-47ee-9c11-e9862c9f58c6'::uuid,'sa9-identity-foreign_org_gateway-0f310c80'),
    ('01a10aa3-6c57-75a9-b302-c3ba82ccdac1'::uuid,'01a109d9-382b-7bc1-82c9-2b0bf036139c'::uuid,'sa9-identity-same_org_other_gateway-b2891d06'),
    ('01a10aa4-17c8-7ba3-be6c-39c6f9e6c075'::uuid,'01a109d9-382b-7bc1-82c9-2b0bf036139c'::uuid,'sa9-identity-same_org_other_gateway-7e52582a'),
    ('01a10aa5-5ebf-76ae-831a-925b52019574'::uuid,'01a109d9-382b-7bc1-82c9-2b0bf036139c'::uuid,'sa9-identity-same_org_other_gateway-0f310c80')
   ))) THEN RAISE EXCEPTION 'unexpected gateway identity'; END IF;
 IF (SELECT count(*) FROM nodes WHERE id='01a109d9-42ca-7d53-b4dd-3f166cd23192' AND org_id='01a109d9-382b-7bc1-82c9-2b0bf036139c' AND name='sa0-gateway' AND status='active' AND enrolled_kind='gateway' AND last_seen_at>now()-interval '90 seconds' AND cert_not_after>now()) <> 1 THEN RAISE EXCEPTION 'gateway identity/heartbeat invalid'; END IF;
END $$;
SELECT version,dirty FROM schema_migrations;
SELECT id,org_id,name,status,last_seen_at FROM nodes;
SQL
./run.sh ps

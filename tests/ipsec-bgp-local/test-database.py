#!/usr/bin/env python3
"""Run API Go tests in a disposable container; preserve the serving DB."""
import argparse, hashlib, json, os, pathlib, subprocess, sys, tempfile, uuid

root = pathlib.Path(__file__).resolve().parent
repo = root.parent.parent
parser = argparse.ArgumentParser()
parser.add_argument('--package', choices=['./internal/ipsec', './internal/http', './internal/testpostgres', './db'], default='./internal/ipsec')
parser.add_argument('--run', default='.')
args = parser.parse_args()
subprocess.run([str(root/'ownership.py')], check=True)
project = 'tunnexs2sbgplocal1007'
def docker(*argv, **kw):
    return subprocess.run([str(root/'docker-local.sh'), *argv], check=True, capture_output=True, **kw)
def snapshot():
    schema = docker('exec',project+'-postgres-1','pg_dump','-U','bgplocal','-d','bgplocal','--schema-only','--no-owner','--no-privileges').stdout
    # PostgreSQL emits a randomized psql restriction key per dump. This is
    # client metainformation, not database schema. Normalize only those lines.
    schema = b'\n'.join(line for line in schema.splitlines() if not line.startswith((b'\\restrict ', b'\\unrestrict ')))
    # Serving gateway heartbeats and request audits remain active. Capture stable
    # identities/counts plus exact schema, excluding only expected live telemetry.
    sql = "select json_build_object('migration',(select json_agg(m) from schema_migrations m),'orgs',(select json_agg(id order by id) from organizations),'users',(select json_agg(id order by id) from users),'nodes',(select json_agg(json_build_array(id,name,status) order by id) from nodes),'connections',(select count(*) from ipsec_connections));"
    data = docker('exec',project+'-postgres-1','psql','-U','bgplocal','-d','bgplocal','-At','-v','ON_ERROR_STOP=1','-c',sql).stdout
    return {'schema_sha256':hashlib.sha256(schema).hexdigest(),'stable_rows':json.loads(data)}

runid=uuid.uuid4().hex[:12]
evidence=root/'.runtime'/('db-tests-'+runid)
evidence.mkdir(mode=0o700)
arch=docker('info','--format','{{.Architecture}}').stdout.decode().strip()
arch={'aarch64':'arm64','arm64':'arm64','x86_64':'amd64','amd64':'amd64'}[arch]
go=pathlib.Path('/Users/pawangupta/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.8.darwin-arm64/bin/go')
if not go.exists(): raise SystemExit('Cached Go 1.26.8 missing')
env=dict(os.environ,GOFLAGS='-mod=readonly',CGO_ENABLED='0',GOOS='linux',GOARCH=arch)
binary=evidence/'api.test'
with (evidence/'compile.log').open('wb') as log:
    result=subprocess.run([str(go),'test','-c','-o',str(binary),args.package],cwd=repo/'apps/api',env=env,stdout=log,stderr=subprocess.STDOUT)
if result.returncode: raise SystemExit('Test compile failed; private log: '+str(evidence/'compile.log'))
before=snapshot()
(evidence/'parent-before.json').write_text(json.dumps(before,indent=2)+'\n')
name=project+'-test-'+runid
image='alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6'
command='export TUNNEX_TEST_DATABASE_URL="postgres://bgplocal:${BGPLOCAL_DB_PASSWORD}@postgres:5432/postgres?sslmode=disable"; exec /test/api.test -test.v -test.timeout=15m -test.run="$1"'
with (evidence/'tests.log').open('wb') as log:
    result=subprocess.run([str(root/'docker-local.sh'),'run','--rm','--name',name,'--label','com.docker.compose.project='+project,'--label','com.docker.compose.project.working_dir='+str(root),'--network',project+'_default','--cap-drop','ALL','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,size=64m','--security-opt','no-new-privileges','--env-file',str(root/'.runtime/env'),'--mount','type=bind,src='+str(binary)+',dst=/test/api.test,readonly',image,'/bin/sh','-ec',command,'test-runner',args.run],stdout=log,stderr=subprocess.STDOUT)
after=snapshot()
(evidence/'parent-after.json').write_text(json.dumps(after,indent=2)+'\n')
if before != after: raise SystemExit('Serving DB schema/stable rows changed; inspect private evidence '+str(evidence))
(evidence/'result.json').write_text(json.dumps({'package':args.package,'run':args.run,'exit_code':result.returncode,'parent_preserved':True,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()},indent=2)+'\n')
print('Serving database schema and stable rows unchanged. Private evidence: '+str(evidence))
if result.returncode: raise SystemExit('Tests failed; inspect private tests.log')
print('PASS '+args.package+' '+args.run)

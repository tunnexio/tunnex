#!/usr/bin/env python3
"""Render shipping manifests with synthetic settings; never deploy or read .env."""
import json,os,re,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[2]
def run(args,env=None,ok=True):
 p=subprocess.run(args,cwd=root,env=env,text=True,capture_output=True)
 if ok and p.returncode:raise AssertionError(p.stderr)
 return p
cp=['helm','template','sa-local','deploy/helm/tunnex-cp','--set','database.urlSecret=local-db','--set','redis.urlSecret=local-redis','--set','masterKey.existingSecret=local-master','--set','appBaseURL=https://cp.fixture.test']
def flag(render,enabled):
 assert re.search(r'name: TUNNEX_SERVER_ACCESS_ENABLED\s+value: "'+str(enabled).lower()+'"',render)
flag(run(cp).stdout,False)
enabled=run(cp+['--set','serverAccess.enabled=true','--set','serverAccess.recordingVolume.existingClaim=local-recordings']).stdout;flag(enabled,True)
assert 'claimName: "local-recordings"' in enabled and 'mountPath: /var/lib/tunnex/recordings' in enabled
rejected=run(cp+['--set','serverAccess.enabled=true','--set','api.replicas=2'],ok=False)
assert rejected.returncode and 'requires exactly one API replica' in rejected.stderr
run(cp+['--set','api.replicas=2'])
gateway=['helm','template','sa-local','deploy/helm/tunnex-gateway','--set','nodeName=sa-local-gateway','--set','acknowledgePrivileged=true','--set','controlPlane.apiURL=https://cp.fixture.test','--set','controlPlane.agentURL=https://cp.fixture.test:8443','--set','enrollment.existingSecret=local-enrollment']
flag(run(gateway).stdout,False);flag(run(gateway+['--set','serverAccess.enabled=true']).stdout,True)
# Persist only the public rendered proxy config for the owned proxy fixture.
match=re.search(r'  default.conf: \|\n(.*?)(?=\n---|\Z)',enabled,re.S);assert match
config='\n'.join(line[4:] for line in match[1].splitlines())+'\n'
(root/'tests/server-access-local/.runtime/chart-edge.conf').write_text(config)
source=(root/'deploy/tunnex.yml').read_text();env={k:v for k,v in os.environ.items() if not k.startswith(('TUNNEX_','COMPOSE_','POSTGRES_')) and k not in ('DATABASE_URL','REDIS_URL','APP_BASE_URL')}
for key in re.findall(r'\$\{([A-Z0-9_]+):\?',source):env[key]='synthetic-local-only'
env.update(APP_BASE_URL='http://127.0.0.1:18888',TUNNEX_EDGE_LISTEN='127.0.0.1:18888',TUNNEX_AI_ENGINE_IMAGE='alpine:3.23',TUNNEX_NODE_ENDPOINT='127.0.0.1:51820',DATABASE_URL='postgres://fixture:synthetic@postgres:5432/fixture',TUNNEX_AI_CUSTOM_PROXY_URL='http://fixture:8080')
env['TUNNEX_AI_CUSTOM_ENDPOINTS_FILE']='/private/tmp/sa-synthetic-policy.json'
env.pop('TUNNEX_SERVER_ACCESS_ENABLED',None)
compose=['tests/server-access-local/docker-local.sh','compose','--env-file','/dev/null','-f','deploy/tunnex.yml']
plain=json.loads(run(compose+['config','--format','json'],env).stdout)
for service in ['api','node-agent']:assert str(plain['services'][service]['environment']['TUNNEX_SERVER_ACCESS_ENABLED']).lower()=='false'
assert next(v for v in plain['services']['api']['volumes'] if v['target']=='/var/lib/tunnex/recordings')['source']=='server_access_recordings'
assert plain['volumes']['server_access_recordings']['name']=='tunnex_server_access_recordings'
env.update(TUNNEX_SERVER_ACCESS_RECORDING_VOLUME='sa-preexisting-volume',TUNNEX_SERVER_ACCESS_RECORDING_VOLUME_EXTERNAL='true')
external=json.loads(run(compose+['config','--format','json'],env).stdout)
assert external['volumes']['server_access_recordings']['name']=='sa-preexisting-volume' and external['volumes']['server_access_recordings']['external'] is True
env.pop('TUNNEX_SERVER_ACCESS_RECORDING_VOLUME');env.pop('TUNNEX_SERVER_ACCESS_RECORDING_VOLUME_EXTERNAL')
with tempfile.TemporaryDirectory(prefix='sa-recording-mount-') as directory:
 env.update(TUNNEX_SERVER_ACCESS_ENABLED='true',TUNNEX_SERVER_ACCESS_RECORDING_SOURCE=directory)
 mounted=json.loads(run(compose+['-f','deploy/server-access-storage.override.yml','config','--format','json'],env).stdout)
 for service in ['api','node-agent']:assert str(mounted['services'][service]['environment']['TUNNEX_SERVER_ACCESS_ENABLED']).lower()=='true'
 volume=next(v for v in mounted['services']['api']['volumes'] if v['target']=='/var/lib/tunnex/recordings')
 assert volume['type']=='bind' and volume['source']==directory and volume['bind']['create_host_path'] is False
print('Compose/Helm default-off, explicit CP+gateway enablement, preexisting recording volume and single-API fence PASS; no deployment')

#!/usr/bin/env python3
"""Actual CP + real session + pinned Linux engine, zero-spend synthetic provider.
Requires an explicitly selected Docker context/project and Linux ARM64 API binary.
Creates only new labelled resources, stops its containers, never deletes volumes.
"""
import argparse, base64, hashlib, io, json, os, pathlib, re, subprocess, tarfile, time, uuid, sys
from isolation import ensure_absent, verify_volume, verify_container
if not __debug__ or sys.flags.optimize:
 raise RuntimeError("Run without Python optimization so qualification assertions remain enabled")
ap=argparse.ArgumentParser()
for name in ['context','project','api-binary','output-dir']: ap.add_argument('--'+name,required=True)
a=ap.parse_args();P=a.project
if not re.fullmatch(r'tunnex[a-z0-9-]{4,40}',P) or P=='tunnex':
 raise RuntimeError('Explicit isolated project required')
root=pathlib.Path(__file__).resolve().parents[3];here=pathlib.Path(__file__).resolve().parent
out=pathlib.Path(a.output_dir).resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
os.umask(0o077)
(out/'.gitignore').write_text('*\n')  # Scratch credentials are ignored at creation.
D=['docker','--context',a.context];label='com.docker.compose.project='+P;net=P+'_engine'
image='maximhq/bifrost:v2.0.0@sha256:cf71be9fad4e0749b6e26cbb774c687413dad9a0970b83f4e1dadb6f503ea208'
created=[];container_ids={};counter=0
db_password=uuid.uuid4().hex;admin_password=uuid.uuid4().hex;provider_key=uuid.uuid4().hex;encryption_key=uuid.uuid4().hex

def d(*args,input=None):
 global counter
 r=subprocess.run(D+list(args),input=input,capture_output=True)
 if r.returncode:
  counter+=1;(out/('failure-'+str(counter)+'.log')).write_bytes(r.stdout+r.stderr)
  raise RuntimeError('Docker '+args[0]+' failed; output retained privately')
 return r.stdout.decode()

def file(path,data):
 raw=data.encode();buf=io.BytesIO()
 with tarfile.open(fileobj=buf,mode='w') as t:
  entry=tarfile.TarInfo(path.lstrip('/'));entry.size=len(raw);entry.mode=0o600;t.addfile(entry,io.BytesIO(raw))
 d('exec','-i',P+'-fixture','tar','-xf','-','-C','/',input=buf.getvalue())

def run(name,*args):
 identifier=d('create','--name',P+'-'+name,'--label',label,'--network',net,*args).strip();created.append(identifier);container_ids[name]=identifier
 if name=='cp-postgres':
  verify_container(d,identifier,P,net,{'/var/lib/postgresql/data':P+'_pg'})
  print('COMPOSE_PROJECT_NAME='+P+' verified pre-start container='+P+'-'+name+' network='+net+' volume='+P+'_pg',flush=True)
 d('start',identifier)

def checkdb():
 c=verify_container(d,container_ids['cp-postgres'],P,net,{'/var/lib/postgresql/data':P+'_pg'},running=True)
 print('COMPOSE_PROJECT_NAME='+P+' verified container='+c['Name']+' network='+net,flush=True)

def driver(stage):
 print(d('exec',P+'-fixture','python3','/tmp/driver.py',stage).strip(),flush=True)

def ready(target="http://cp-api:8080/healthz"):
 for _ in range(120):
  r=subprocess.run(D+['exec',P+'-fixture','wget','-T','2','-qO','/dev/null',target],capture_output=True)
  if r.returncode==0:return
  time.sleep(.5)
 raise RuntimeError('API readiness failed; inspect private API logs')

ensure_absent(d,{'container':[P+'-'+n for n in ['cp-postgres','cp-redis','fixture','cp-engine','cp-api']], 'volume':[P+'_'+v for v in ['pg','redis','secrets','config','logs']], 'network':[net]})
print('COMPOSE_PROJECT_NAME='+P+' context='+a.context+' dedicated network='+net,flush=True)
print('API binary SHA256='+hashlib.sha256(pathlib.Path(a.api_binary).read_bytes()).hexdigest(),flush=True)
subprocess.run(['go','run',str(here/'sign.go'),str(out)],check=True,env={**os.environ,'GOFLAGS':'-mod=readonly','GOWORK':'off'})
d('pull','--platform','linux/arm64',image)
d('network','create','--label',label,net)
network=json.loads(d('network','inspect',net))[0]
if network.get('Name')!=net or network.get('Labels',{}).get('com.docker.compose.project')!=P:
 raise RuntimeError('Network ownership verification failed')
for v in ['pg','redis','secrets','config','logs']:
 d('volume','create','--label',label,P+'_'+v);verify_volume(d,P+'_'+v,P)
try:
 run('cp-postgres','--network-alias','cp-postgres','-e','POSTGRES_USER=aiwalk','-e','POSTGRES_PASSWORD='+db_password,'-e','POSTGRES_DB=aiwalk','-v',P+'_pg:/var/lib/postgresql/data','postgres:16-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685');checkdb()
 run('cp-redis','--network-alias','cp-redis','-v',P+'_redis:/data','redis:7-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf','redis-server','--appendonly','yes')
 run('fixture','--network-alias','fixture','-v',P+'_config:/cpconfig','-v',P+'_logs:/cplogs','golang:1.25.13-alpine@sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946','sleep','infinity')
 d('exec',P+'-fixture','apk','add','--no-cache','python3')
 d('cp',str(here/'provider.py'),P+'-fixture:/provider.py');d('exec','-d',P+'-fixture','python3','/provider.py')
 cfg=json.loads((root/'deploy/ai-gateway/config.json').read_text());cfg['providers']['openrouter']['network_config'].update(base_url='http://fixture:8090',allow_private_network=True)
 cfg['providers']['openrouter']['keys'][0]['models']=['openai/gpt-4o-mini','openai/gpt-4o']
 file('/cpconfig/config.json',json.dumps(cfg));d('exec',P+'-fixture','sh','-ec','chown -R 1000:1000 /cpconfig /cplogs')
 run('cp-engine','--platform','linux/arm64','--network-alias','bifrost','--cap-drop','ALL','--security-opt','no-new-privileges:true','-e','BIFROST_ADMIN_USER=fixture-admin','-e','BIFROST_ADMIN_PASSWORD='+admin_password,'-e','OPENROUTER_API_KEY='+provider_key,'-e','BIFROST_ENCRYPTION_KEY='+encryption_key,'-e','LOG_LEVEL=error','-v',P+'_config:/app/data','-v',P+'_logs:/app/data/logs',image)
 ready('http://bifrost:8080/health')
 envs={'TUNNEX_ENV':'development','TUNNEX_API_ADDR':':8080','TUNNEX_AGENT_ADDR':':8443','TUNNEX_METRICS_ADDR':':9090','TUNNEX_SECRETS_DIR':'/cp-secrets','TUNNEX_DATABASE_URL':'postgres://aiwalk:'+db_password+'@cp-postgres:5432/aiwalk?sslmode=disable','TUNNEX_DATABASE_REQUIRE_TLS':'false','TUNNEX_REDIS_URL':'redis://cp-redis:6379/0','TUNNEX_AUTO_MIGRATE':'true','TUNNEX_COOKIE_SECURE':'false','TUNNEX_AI_GATEWAY_URL':'http://bifrost:8080','TUNNEX_AI_GATEWAY_ADMIN_USER':'fixture-admin','TUNNEX_AI_GATEWAY_ADMIN_PASSWORD':admin_password,'TUNNEX_RELEASE_MANIFEST_PATH':'/tmp/release.json','TUNNEX_RELEASE_PUBLIC_KEY':(out/'release.pub').read_text(),'TUNNEX_RELEASE_MANIFEST_URL':'https://fixture.invalid/releases/v0.4.0/release.json','APP_BASE_URL':'http://cp-api:8080','TUNNEX_LOG_LEVEL':'error'}
 envargs=[]
 for k,v in envs.items():envargs+=['-e',k+'='+v]
 run('cp-api','--network-alias','cp-api','-v',P+'_secrets:/cp-secrets',*envargs,'golang:1.25.13-alpine@sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946','sleep','infinity')
 d('cp',str(pathlib.Path(a.api_binary).resolve()),P+'-cp-api:/tmp/tunnex-api');d('cp',str(out/'release.json'),P+'-cp-api:/tmp/release.json')
 checkdb()
 for _ in range(60):
  r=subprocess.run(D+['exec',P+'-cp-postgres','pg_isready','-U','aiwalk','-d','aiwalk'],capture_output=True)
  if r.returncode==0:break
  time.sleep(.5)
 d('exec','-d',P+'-cp-api','sh','-c','umask 077; /tmp/tunnex-api > /tmp/private-start.log 2>&1');ready()
 d('cp',str(here/'driver.py'),P+'-fixture:/tmp/driver.py');file('/tmp/bootstrap-private.log',d('exec',P+'-cp-api','cat','/tmp/private-start.log'));driver('human')
 state=json.loads(d('exec',P+'-fixture','cat','/tmp/walk-state.json'));org=str(uuid.UUID(state['org']));node=str(uuid.uuid4());key=base64.b64encode(bytes([9])*32).decode();checkdb()
 sql=f"INSERT INTO nodes(id,org_id,name,cert_serial,wg_public_key,endpoint,status) VALUES('{node}','{org}','local-fixture-gateway','{node}','{key}','gateway.fixture.invalid:51820','active');"
 d('exec','-i',P+'-cp-postgres','psql','-U','aiwalk','-d','aiwalk','-v','ON_ERROR_STOP=1',input=sql.encode());state['node']=node;file('/tmp/walk-state.json',json.dumps(state))
 print('Gateway row only seeded; no gateway dataplane claim',flush=True)
 driver('enroll');driver('policy')
 d('exec',P+'-cp-api','sh','-c','kill -INT $(pidof tunnex-api)')
 for _ in range(30):
  if subprocess.run(D+['exec',P+'-cp-api','pidof','tunnex-api'],capture_output=True).returncode!=0:break
  time.sleep(.5)
 checkdb();d('exec','-d',P+'-cp-api','sh','-c','umask 077; /tmp/tunnex-api > /tmp/private-restart.log 2>&1');ready();driver('restart');file('/tmp/engine-auth.json',json.dumps({'password':admin_password}));driver('extended')
 verify_container(d,container_ids['cp-engine'],P,net)
 d('stop',container_ids['cp-engine'])
 privacy="import pathlib,sqlite3; p=pathlib.Path('/cplogs/logs.db'); c=sqlite3.connect(p); dump='\\n'.join(c.iterdump()); markers=['PRIVATE_PROMPT_LINUX_WALK','PRIVATE_RESPONSE_LINUX_WALK']; assert all(m not in dump for m in markers); assert all(m.encode() not in f.read_bytes() for m in markers for f in p.parent.glob('logs.db*')); print('PASS full installed stream/nonstream SQLite logical/raw content omission')"
 print(d('exec',P+'-fixture','python3','-c',privacy).strip(),flush=True)
 print('PASS actual installed API process walkthrough; no AuthFn bypass or provider spend',flush=True)
finally:
 for identifier in reversed(created):
  verify_container(d,identifier,P,net)
  d('stop',identifier)
 print('Stopped own containers; retained every project volume and network',flush=True)

#!/usr/bin/env python3
"""Read-only post-API preservation proof for the exact owned cloud fixture."""
import hashlib,json,os,pathlib,subprocess
os.umask(0o077);assert os.geteuid()==0
r=pathlib.Path('/home/ubuntu/tunnex-bgp-lab');b=r/'refresh-max-prefix-before';state=json.loads((r/'state.json').read_text());result=json.loads((b/'api-refresh-result.json').read_text());cid=result['new_id'];old=json.loads((b/'api-inspect.json').read_text());assert result['old_id']==old['Id']
def run(*args):return subprocess.check_output(['docker',*args],text=True)
d=json.loads(run('inspect',cid))[0];assert d['State']['Running']and d['Config']['Labels']['tunnex.lab']=='tunnex-bgp-20261007';assert run('exec',cid,'sha256sum','/proc/1/exe').split()[0]=='30de107bd8d56d83f18e6bd327c9beab866c16c6d455624543d5bfbe54f76c90'
health=json.loads(run('exec',cid,'wget','-qO-','http://127.0.0.1:8080/healthz'));assert health['status']=='ok'
def sql(q):return run('exec',state['postgres'],'psql','-U','bgpcloud','-d','bgpcloud','-At','-v','ON_ERROR_STOP=1','-c',q)
assert sql('SELECT version,dirty FROM schema_migrations;').strip()=='217|f'
q="SELECT json_agg(json_build_object('id',id,'org_id',org_id,'cert_serial',cert_serial,'cert_public_key',cert_public_key,'cert_key_fingerprint',cert_key_fingerprint,'revoked_at',revoked_at,'enrolled_at',enrolled_at)) FROM nodes; SELECT json_agg(to_jsonb(o)) FROM organizations o; SELECT json_agg(to_jsonb(s)) FROM ipsec_org_settings s;"
before=(b/'database-identity-license-private.txt').read_text().splitlines();after=sql(q).splitlines();assert len(before)==len(after)==3
for x,y in zip(before,after):assert (None if x==''else json.loads(x))==(None if y==''else json.loads(y)),'Identity/organization/license/settings baseline differs'
assert sql('SELECT count(*) FROM ipsec_connections; SELECT count(*) FROM ipsec_runtime_deliveries;').strip()=='0\n0'
g=json.loads((b/'gateway-inspect.json').read_text());volume=pathlib.Path(next(x['Source']for x in g['Mounts']if x['Destination']=='/state'))
for name in ['cert.pem','ca.pem']:assert (volume/name).read_bytes()==(b/('state-'+name)).read_bytes()
assert not(volume/'ipsec/journal.json').exists()
for role in ['gateway','postgres','redis']:
 original=json.loads((b/(role+'-inspect.json')).read_text());current=json.loads(run('inspect',original['Id']))[0];assert current['State']['Running']and current['Config']==original['Config']and current['HostConfig']==original['HostConfig']
proof={'new_api_id':cid,'old_api_id':old['Id'],'migration_version':217,'migration_dirty':False,'node_certificate_preserved':True,'license_preserved':True,'organization_and_optin_preserved':True,'api_healthy':True,'gateway_postgres_redis_unchanged':True,'connection_count':0,'delivery_count':0,'journal_absent':True,'actual_api_binary_sha256':'30de107bd8d56d83f18e6bd327c9beab866c16c6d455624543d5bfbe54f76c90','private_baseline_sha256':hashlib.sha256((b/'database-identity-license-private.txt').read_bytes()).hexdigest()}
p=b/'api-postrefresh-preservation.json'
with p.open('x')as f:f.write(json.dumps(proof,indent=2)+'\n');f.flush();os.fsync(f.fileno())
print(json.dumps(proof))

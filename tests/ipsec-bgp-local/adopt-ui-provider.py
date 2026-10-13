#!/usr/bin/env python3
"""Adopt an exact normal-UI disabled provider into private local fixture state."""
import datetime,http.cookiejar,json,os,pathlib,stat,subprocess,urllib.parse,urllib.request,uuid
os.umask(0o077);root=pathlib.Path(__file__).resolve().parent;runtime=root/'.runtime'
config_path=runtime/'integrated-local-api.json';state_path=runtime/'integrated-local-api-state.json';pending_path=runtime/'story9-ui-provider-pending.json'
for p in (config_path,state_path,pending_path):assert stat.S_IMODE(p.stat().st_mode)==0o600
config=json.loads(config_path.read_text());state=json.loads(state_path.read_text());pending=json.loads(pending_path.read_text());expected=json.loads(pathlib.Path(config['provider_config_file']).read_text())
client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));base=config['base_url'].rstrip('/')
def api(path,body=None):
 request=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'})
 with client.open(request,timeout=15) as response:return json.loads(response.read())
login=api('/api/v1/auth/login',{'email':config['email'],'password':config['password']});assert not login.get('mfa_required')
org='/api/v1/organizations/'+config['organization_id'];items=[];cursor=None
while True:
 page=api(org+'/ipsec/connections?'+urllib.parse.urlencode({'limit':100,**({'after':cursor} if cursor else {})}));items.extend(page['items']);cursor=page.get('next_cursor')
 if not cursor:break
matches=[item for item in items if item['name']==pending['connection_name']];assert len(matches)==1,'Exact UI provider name must be unique'
connection=api(org+'/ipsec/connections/'+matches[0]['id']);cid=connection['id'];uuid.UUID(cid)
assert connection['org_id']==config['organization_id'] and connection['site_id']==config['site_id'] and connection['gateway_node_id']==config['gateway_id'] and connection['desired_intent']=='disabled' and connection['deleted_at'] is None and connection['finalized_at'] is None
provider=api(org+'/ipsec/connections/'+cid+'/configuration');assert provider['profile_id']=='aws-bgp-ipv4-v1' and provider['configuration_revision']==1
public_expected={**expected,'tunnels':[{k:v for k,v in tunnel.items() if k!='psk'} for tunnel in expected['tunnels']]}
assert provider['configuration']==public_expected,'UI network configuration differs from exact private peer configuration'
status=api(org+'/ipsec/connections/'+cid+'/status');tunnels=sorted(status['tunnels'],key=lambda tunnel:tunnel['slot']);assert [t['slot'] for t in tunnels]==[1,2]
for tunnel in tunnels:uuid.UUID(tunnel['id'])
query="select json_build_object('enabled_count',(select count(*) from ipsec_connections where desired_intent='enabled'),'deliveries',(select count(*) from ipsec_runtime_deliveries));"
counters=json.loads(subprocess.check_output([str(root/'docker-local.sh'),'exec','tunnexs2sbgplocal1007-postgres-1','psql','-U','bgplocal','-d','bgplocal','-At','-c',query],text=True));assert counters['enabled_count']==0 and counters['deliveries']==0
assert not state.get('pending_connection_id') and (not state.get('connection_id') or state['connection_id']==cid)
assert state['identity']['fixture_name']==config['fixture_name']
state.update(connection_id=cid,desired_revision=connection['desired_revision'],tunnel_ids=[t['id'] for t in tunnels],provider_connection_name=connection['name'],provider_configuration_revision=provider['configuration_revision'])
pending.update(connection_id=cid,tunnel_ids=state['tunnel_ids'],desired_revision=connection['desired_revision'],awaiting_normal_ui_connection_id=False,normal_api_disabled_verified=True,normal_api_configuration_exact=True,delivery_count=0,adopted_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
config['provider_connection_name']=connection['name']
def save(path,value):
 nextfile=path.with_suffix('.next');nextfile.write_text(json.dumps(value,indent=2)+'\n');nextfile.chmod(0o600);nextfile.replace(path)
for path,value in ((state_path,state),(pending_path,pending),(config_path,config)):save(path,value)
save(runtime/'ui-provider-normal-api-readback.json',{'connection':connection,'provider':provider,'status':status,'counters':counters})
print(json.dumps({'connection_id':cid,'connection_name':connection['name'],'desired_intent':connection['desired_intent'],'delivery_count':0,'fixture_name_preserved':config['fixture_name'],'activation_performed':False}))

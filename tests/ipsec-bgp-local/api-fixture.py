#!/usr/bin/env python3
"""Normal authenticated API fixture; deliberately contains no enable operation."""
import argparse,http.cookiejar,ipaddress,json,os,pathlib,stat,urllib.request,urllib.error,uuid
os.umask(0o077)
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--private-config',type=pathlib.Path,required=True)
p.add_argument('--state',type=pathlib.Path,required=True)
p.add_argument('action',choices=['inspect','enforcing','topology','resource','grant','withdraw','provider-disabled','resolve-provider'])
a=p.parse_args()
assert stat.S_IMODE(a.private_config.stat().st_mode)&0o077==0,'Private config must be mode0600'
c=json.loads(a.private_config.read_text());base=c['base_url'].rstrip('/')
assert base.startswith('http://127.0.0.1:') or base.startswith('https://'),'Use loopback or authenticated HTTPS'
for k in ['organization_id','gateway_id']:uuid.UUID(c[k])
for k in ['local_prefix','target_prefix']:assert str(ipaddress.ip_network(c[k],strict=True))==c[k]
assert ipaddress.ip_network(c['target_prefix']).prefixlen==32,'Application target must be exact IPv4 /32'
client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,method='GET',body=None,allow404=False):
 req=urllib.request.Request(base+path,method=method,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'})
 try:
  with client.open(req,timeout=20)as r:
   raw=r.read();return json.loads(raw)if raw else None
 except urllib.error.HTTPError as e:
  if allow404 and e.code==404:return None
  # Neither bodies nor submitted configuration may escape into logs.
  try:code=json.loads(e.read()).get('error',{}).get('code','api_refusal')
  except Exception:code='api_refusal'
  raise SystemExit('API refused '+method+' '+path+': HTTP'+str(e.code)+' '+str(code))
login=api('/api/v1/auth/login','POST',{'email':c['email'],'password':c['password']})
assert not login.get('mfa_required') and not login.get('user',{}).get('must_change_password'),'Normal login prerequisites unresolved'
root='/api/v1/organizations/'+c['organization_id']
identity={k:c[k]for k in ['organization_id','gateway_id','fixture_name','local_prefix','target_prefix']}
state=json.loads(a.state.read_text())if a.state.exists()else {'identity':identity}
assert state['identity']==identity,'Recorded fixture ownership differs'
def save():
 a.state.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 temp=a.state.with_suffix('.next');temp.write_text(json.dumps(state,indent=2)+'\n');os.chmod(temp,0o600);temp.replace(a.state)
def site():
 sid=state.get('site_id')or c.get('site_id');sites=api(root+'/sites')
 if sid:
  assert any(s['id']==sid for s in sites),'Recorded site absent';return sid
 found=[s for s in sites if s['name']==c['fixture_name']];assert not found,'Unrecorded site collision'
 s=api(root+'/sites','POST',{'name':c['fixture_name']});state['site_id']=s['id'];save();return s['id']
if a.action=='inspect':
 state['last_inspection']={'gateway_present':any(n['id']==c['gateway_id']for n in api(root+'/nodes')),'ipsec_settings':api(root+'/ipsec/settings'),'zero_trust_mode':api(root+'/zero-trust-mode'),'eligibility':api(root+'/ipsec/eligibility?site_id='+(state.get('site_id')or c['site_id'])+'&gateway_node_id='+c['gateway_id'])};save()
elif a.action=='enforcing':
 assert c.get('allow_enforcing_mode_change')is True,'Explicit fixture config must authorize enforcing mode change'
 previous=api(root+'/zero-trust-mode')
 state.setdefault('prior_zero_trust_mode',previous);save()
 if previous['mode']!='enforcing':api(root+'/zero-trust-mode','PUT',{'mode':'enforcing'})
 assert api(root+'/zero-trust-mode')['mode']=='enforcing'
 state['enforcing_verified']=True;save()
elif a.action=='topology':
 sid=site();node=next(n for n in api(root+'/nodes')if n['id']==c['gateway_id'])
 if node.get('site_id'):assert node['site_id']==sid,'Gateway already bound elsewhere'
 else:api(root+'/sites/'+sid+'/bind','POST',{'node_id':c['gateway_id']})
 subnets=api(root+'/sites/'+sid+'/subnets');found=[s for s in subnets if s['cidr']==c['local_prefix']];assert len(found)<=1
 subnet=found[0]if found else api(root+'/sites/'+sid+'/subnets','POST',{'cidr':c['local_prefix']})
 if subnet.get('status')!='approved':api(root+'/site-subnets/'+subnet['id']+'/approve','POST')
 state.update(site_id=sid,subnet_id=subnet['id']);save()
elif a.action=='resource':
 name=c['fixture_name']+' TCP target';resources=api(root+'/resources');found=[r for r in resources if r['name']==name]
 if state.get('resource_id'):
  r=next(r for r in resources if r['id']==state['resource_id'])
  assert r['cidr']==c['target_prefix']and r['protocol']=='tcp'and r['port_low']==c['port']and r['port_high']==c['port'],'Resource changed'
 else:
  assert not found,'Unrecorded resource collision'
  r=api(root+'/resources','POST',{'name':name,'cidr':c['target_prefix'],'protocol':'tcp','port_low':c['port'],'port_high':c['port']});state['resource_id']=r['id'];save()
elif a.action=='grant':
 assert state.get('resource_id')and(state.get('site_id')or c.get('site_id')),'Prepare topology and resource first'
 assert not state.get('rule_id'),'Existing rule must be withdrawn before another grant'
 mode=api(root+'/zero-trust-mode')
 if mode['mode']!='enforcing':
  assert c.get('allow_enforcing_mode_change')is True,'Explicit fixture config must authorize enforcing mode change'
  api(root+'/zero-trust-mode','PUT',{'mode':'enforcing'})
 rule=api(root+'/policies','POST',{'src_kind':'site','src_site_id':state.get('site_id')or c['site_id'],'dst_kind':'resource','dst_resource_id':state['resource_id']});state['rule_id']=rule['id'];save()
elif a.action=='withdraw':
 assert state.get('rule_id'),'No recorded owned rule'
 rules=api(root+'/policies');rule=next(r for r in rules if r['id']==state['rule_id'])
 assert rule['dst_resource_id']==state['resource_id']and rule['src_site_id']==(state.get('site_id')or c['site_id']),'Rule ownership changed'
 api(root+'/policies/'+state['rule_id'],'DELETE');state.setdefault('withdrawn_rule_ids',[]).append(state.pop('rule_id'));save()
elif a.action=='resolve-provider':
 assert state.get('pending_connection_id'),'No uncertain provider to resolve'
 pending=state['pending_connection_id'];connection=api(root+'/ipsec/connections/'+pending,allow404=True)
 if connection is None:
  state.setdefault('refused_connection_ids',[]).append(state.pop('pending_connection_id'));state.pop('tunnel_ids',None)
 else:
  assert connection['site_id']==(state.get('site_id')or c['site_id'])and connection['gateway_node_id']==c['gateway_id']and connection['name']==c.get('provider_connection_name',c['fixture_name'])and connection['desired_intent']=='disabled','Resolved provider identity or intent differs'
  state['connection_id']=connection['id'];state['desired_revision']=connection['desired_revision'];state.pop('pending_connection_id')
 save()
elif a.action=='provider-disabled':
 assert not state.get('connection_id')and not state.get('pending_connection_id'),'Recorded or uncertain provider exists; resolve exact identity through GET before retry'
 private=pathlib.Path(c['provider_config_file']);assert stat.S_IMODE(private.stat().st_mode)&0o077==0
 config=json.loads(private.read_text());assert config['mode']in ['ipv4-bgp','ipv4-static']and config['local_prefixes']==[c['local_prefix']]
 body={'id':str(uuid.uuid4()),'name':c.get('provider_connection_name',c['fixture_name']),'site_id':state.get('site_id')or c['site_id'],'gateway_node_id':c['gateway_id'],'tunnel_ids':[str(uuid.uuid4()),str(uuid.uuid4())],'configuration':config}
 # Persist pending identities before sending so an unknown response cannot recreate silently.
 state['pending_connection_id']=body['id'];state['tunnel_ids']=body['tunnel_ids'];save()
 connection=api(root+'/ipsec/connections','POST',body);assert connection['desired_intent']=='disabled'
 state['connection_id']=connection['id'];state['desired_revision']=connection['desired_revision'];state.pop('pending_connection_id');save()
print(json.dumps({'action':a.action,'organization_id':c['organization_id'],'site_id':state.get('site_id')or c.get('site_id'),'resource_id':state.get('resource_id'),'rule_id':state.get('rule_id'),'connection_id':state.get('connection_id'),'activation_performed':False}))

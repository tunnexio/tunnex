#!/usr/bin/env python3
"""One-shot normal API active BGP deletion and bounded owned-cleanup proof."""
import argparse,datetime,hashlib,http.cookiejar,ipaddress,json,os,pathlib,re,subprocess,time,urllib.request
from enrolled_approval import reviewed_run
os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');a=p.parse_args()
r=pathlib.Path(__file__).resolve().parent;shared=r/'.runtime';private=shared/'story9-limits'
def read(path):
 assert not path.is_symlink()and path.stat().st_mode&0o777==0o600
 return json.loads(path.read_text())
c=read(private/'api.json');s=read(private/'state.json');assert c['base_url']=='http://127.0.0.1:18283'and c['fixture_name']=='BGP limit qualification'and s['connection_id']=='b0a538fd-3bbd-45ae-b264-50207539281b'and s['desired_revision']==10 and s['last_intent']=='enabled'
assert s['identity']=={k:c[k]for k in ['organization_id','gateway_id','fixture_name','local_prefix','target_prefix']}
run,approval,index=reviewed_run(shared,shared/'enrolled-repeat-20261008-4');finish=read(run/'enrolled-restoration-finish.json');pre=read(run/'enrolled-preallocation.json');assert index==4 and finish['worker_released'];gw=finish['new_container_id'];assert gw=='076fb85117c157f04b1cebf199108de067ae04ef2c8331acb1b9450fe41d8a54'
d=[str(r/'docker-local.sh')]
def out(*args):return subprocess.check_output(d+list(args),text=True)
def cmd(*args):return out('exec',gw,*args)
def same():
 x=json.loads(out('inspect',gw))[0];assert x['State']['Running']and x['Image']==approval['image']and x['Config']['Labels']['com.docker.compose.project']=='tunnexs2sbgplocal1007';assert cmd('readlink','/proc/1/ns/net').strip()==pre['new_namespace']=='net:[4026533140]';assert cmd('sha256sum','/proc/1/exe').split()[0]==approval['binary_sha256'];return hashlib.sha256(cmd('cat','/state/cert.pem').encode()).hexdigest()
cert=same();cl=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,method='GET',body=None,revision=None):
 h={'Content-Type':'application/json','Origin':c['base_url'],'X-Tunnex-CSRF':'1'}
 if revision is not None:h['If-Match']='"'+str(revision)+'"'
 req=urllib.request.Request(c['base_url']+path,method=method,data=None if body is None else json.dumps(body).encode(),headers=h)
 with cl.open(req,timeout=10)as response:return json.loads(response.read())
assert not api('/api/v1/auth/login','POST',{'email':c['email'],'password':c['password']}).get('mfa_required')
root='/api/v1/organizations/'+c['organization_id'];path=root+'/ipsec/connections/'+s['connection_id'];original_path=root+'/ipsec/connections/4ae1e806-d6ed-4791-8137-cff6871dbd4e';original=api(original_path);assert original['desired_intent']=='disabled'and original['desired_revision']==5 and not original['deleted_at']
zero=api(root+'/zero-trust-mode');assert zero['mode']=='enforcing'
def journal():return json.loads(cmd('cat','/state/ipsec/journal.json'))['Payload']['Entries']
def routes():return json.loads(cmd('ip','-j','-4','route','show','table','all'))
def sas():return cmd('env','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf','/opt/tunnex-ipsec/sbin/swanctl','--list-sas','--uri','unix:///run/tunnex-ipsec/charon.vici')
def conns():return cmd('env','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf','/opt/tunnex-ipsec/sbin/swanctl','--list-conns','--uri','unix:///run/tunnex-ipsec/charon.vici')
def owned(e):return e['Allocation']['ConnectionID']==s['connection_id']
def prefix(row):return str(ipaddress.ip_network(row['dst']))if row.get('dst')not in [None,'default']else row.get('dst')
def ownroute(row):
 if row.get('protocol')not in [242,'242']:return False
 for slot,(dev,peer)in enumerate([('tx6cc5a86d25d0','169.254.84.2/32'),('txa36bb24e6f33','169.254.84.6/32')],1):
  if prefix(row)in ['10.30.0.0/24','10.31.0.0/24',peer]and row.get('dev')==dev and row.get('metric')==50000+slot and row.get('table',254)in [254,'main']and not row.get('gateway')and not row.get('flags'):return True
 return False
def automatic_owned_address_route(row):
 # Exact auto-generated address routes vanish with the owned XFRM link.
 expected=[]
 for dev,local,broadcast in [('tx6cc5a86d25d0','169.254.84.1','169.254.84.3'),('txa36bb24e6f33','169.254.84.5','169.254.84.7')]:
  for dst,kind,scope in [(local,'local','host'),(broadcast,'broadcast','link')]:expected.append({'dev':dev,'dst':dst,'type':kind,'scope':scope,'protocol':'kernel','table':'local','prefsrc':local,'flags':[]})
 normalized=dict(row)
 if normalized.get('table')==255:normalized['table']='local'
 return normalized in expected
def clean_bgp_entry(e):
 assert e['Phase']=='retained_refusal'and e['ContractVersion']==3
 proc=e.get('BGPProcess');routes=e.get('BGPRoutes');history=e.get('BGPProcessRetired')or[]
 if routes is None:
  assert e['DeliveryID']=='39be0492-aac4-4e74-be0c-749af8f2c0ed'and proc is None and not history,'Unproven nil BGP duties'
 else:
  assert routes['Stage']=='completed'and not routes['Owned']and not routes['Target']
 assert proc is None or proc['Stage']=='cleaned';assert all(x['Stage']=='cleaned'for x in history)
def parse_xfrm_inventory(raw,kind):
 # This pinned iproute emits TEXT despite -j for policy, zero bytes for empty state.
 # Recognize only independently observed socket policies; all other text refuses.
 if raw=='':return []
 if kind=='policy'and raw.startswith('src '):
  lines=raw.splitlines();assert len(lines)%2==0 and lines
  rows=[]
  for i in range(0,len(lines),2):
   m=re.fullmatch(r'src (::/0|0\.0\.0\.0/0) dst (::/0|0\.0\.0\.0/0) *',lines[i]);assert m and m[1]==m[2]
   direction=re.fullmatch(r'\s+socket (in|out) priority 0 *',lines[i+1]);assert direction
   rows.append({'socket':direction[1],'src':m[1],'dst':m[2],'priority':0})
  return rows
 rows=json.loads(raw);assert isinstance(rows,list)and all(isinstance(x,dict)for x in rows),'Malformed XFRM inventory'
 for row in rows:
  assert 'if_id'in row,'Nonempty JSON inventory lacks exact XFRM identity'
  if 'if_id'in row:
   value=row['if_id'];assert not isinstance(value,bool)and isinstance(value,(str,int))
   value=int(value,16 if isinstance(value,str)and value.startswith('0x')else 10)if isinstance(value,str)else value;assert 0<value<=4294967295;row['if_id']=value
 return rows
def retained_guard(nft):
 sets=[x['set']for x in nft['nftables']if 'set'in x and x['set'].get('table')=='tunnex_ipsec'];assert sets and all(not x.get('elem')for x in sets)
 assert not any(x.get('element',{}).get('table')=='tunnex_ipsec'and x['element'].get('elem')for x in nft['nftables'])
 found=set()
 for item in nft['nftables']:
  rule=item.get('rule',{});expr=[e for e in rule.get('expr',[])if 'counter'not in e]
  if rule.get('table')!='tunnex_ipsec'or len(expr)!=2 or 'drop'not in expr[-1]:continue
  match=expr[0].get('match',{});left=match.get('left');right_value=match.get('right')
  if not isinstance(left,dict)or not isinstance(right_value,dict):continue
  payload=left.get('payload',{});right=right_value.get('prefix',{})
  if not isinstance(payload,dict)or not isinstance(right,dict):continue
  if match.get('op')=='=='and payload.get('protocol')=='ip'and right.get('len')==24 and right.get('addr')in ['10.30.0.0','10.31.0.0']:found.add((rule['chain'],payload.get('field'),right['addr']))
 expected={(chain,field,addr)for chain,fields in [('forward_guard',['saddr','daddr']),('output_guard',['saddr','daddr']),('input_guard',['saddr']),('postrouting_guard',['daddr'])]for field in fields for addr in ['10.30.0.0','10.31.0.0']};assert expected<=found,'Missing actual protected-prefix denial'
 # Hook binding validates the actual base chains.
 chains={x['chain']['name']:x['chain']for x in nft['nftables']if 'chain'in x and x['chain'].get('table')=='tunnex_ipsec'}
 for name,hook,priority in [('forward_guard','forward',-10),('output_guard','output',-10),('input_guard','input',-10),('postrouting_guard','postrouting',90),('postnat_guard','postrouting',300)]:
  ch=chains[name];assert ch.get('family')=='inet'and ch.get('type')=='filter'and ch.get('hook')==hook and ch.get('prio')==priority and ch.get('policy')=='accept'
 return {'empty_permit_sets':[x['name']for x in sets],'verified_drop_rules':sorted(found),'ruleset_sha256':hashlib.sha256(json.dumps(nft,sort_keys=True).encode()).hexdigest()}
def write(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(fd,(json.dumps(value,indent=2)+'\n').encode());os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
pending=private/'normal-delete-pending.json';proof=private/'normal-delete-finalized.json'
if pending.exists():
 saved=read(pending);assert saved['connection_id']==s['connection_id']and saved['revision']==10 and saved['gateway_id']==gw and saved['namespace']==pre['new_namespace'];baseline=saved['baseline'];assert a.execute,'Pending outcome requires read-only poll via --execute; mutation will not repeat'
else:
 record=api(path);assert record['desired_revision']==10 and record['desired_intent']=='enabled'and not record['deleted_at']and record['gateway_node_id']==c['gateway_id']
 cfg=api(path+'/configuration')['configuration'];assert cfg['mode']=='ipv4-bgp'and cfg['local_prefixes']==['10.10.0.0/24']and sorted(cfg['remote_prefixes'])==['10.30.0.0/24','10.31.0.0/24']and cfg['bgp']['local_asn']==65000 and cfg['bgp']['remote_asn']==64512 and cfg['bgp']['maximum_prefixes']==1
 status=api(path+'/status');age=(datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(status['observed_at'].replace('Z','+00:00'))).total_seconds();assert 0<=age<=30 and len(status['tunnels'])==2 and all(t['status']=='up'and not t['selected']for t in status['tunnels']);assert all(p['state']=='established'and p['accepted_prefixes']==1 for p in status['bgp']['peers'])and status['bgp']['routes']==[{'prefix':'10.30.0.0/24','slot':1}]
 entries=[e for e in journal()if owned(e)];active=[e for e in entries if e['Phase']=='applied'];assert len(active)==1;entry=active[0];assert entry['BGPProcess']['Stage']=='ready'and entry['BGPRoutes']['Stage']=='completed'and len(entry['BGPRoutes']['Owned'])==1
 tuple_=entry['BGPRoutes']['Owned'][0];assert tuple_['Prefix']=='10.30.0.0/24'and tuple_['Slot']==1 and tuple_['Table']==254 and tuple_['Protocol']==242 and tuple_['Metric']==50001
 rr=routes();selected=[x for x in rr if prefix(x)=='10.30.0.0/24'and ownroute(x)];assert len(selected)==1 and selected[0]['metric']==50001 and selected[0]['dev']==entry['Allocation']['Tunnels'][0]['Name']
 names=['tnx-ipsec-'+t['TunnelID']+'-d'+str(t['Binding']['DesiredRevision'])+'-c'+str(t['Binding']['ConfigurationRevision'])+'-s'+str(t['SecretRevision'])for t in entry['Engines']];sa=sas();assert all(name in sa for name in names)
 baseline={'foreign_routes':[x for x in rr if not ownroute(x)],'sas':sa,'connections':conns(),'engine_names':names,'xfrm_ids':[t['XFRMID']for t in entry['Engines']],'interface_names':[t['Name']for t in entry['Allocation']['Tunnels']],'status':status,'original_provider':original,'certificate_sha256':cert,'zero_trust_mode':zero}
 if not a.execute:print(json.dumps({'ready':True,'connection_id':s['connection_id'],'revision':10,'mutation_performed':False}));raise SystemExit(0)
 write(pending,{'connection_id':s['connection_id'],'revision':10,'gateway_id':gw,'namespace':pre['new_namespace'],'baseline':baseline,'delete_outcome_unknown':True})
 # Exactly one mutation; any exception leaves the exclusive pending proof for GET-only resolution.
 api(path,'DELETE',revision=10)
deadline=time.monotonic()+60
while True:
 record=api(path)
 if record.get('finalized_at'):break
 assert time.monotonic()<deadline,'Delete not finalized; retain pending evidence';time.sleep(1)
assert record['deleted_at']and record['finalized_at'];assert same()==baseline['certificate_sha256']and api(original_path)==baseline['original_provider']and api(root+'/zero-trust-mode')==baseline['zero_trust_mode']
entries=[e for e in journal()if owned(e)];assert entries and all(e['Phase']=='retained_refusal'for e in entries)
for e in entries:clean_bgp_entry(e)
all_names=['tnx-ipsec-'+t['TunnelID']+'-d'+str(t['Binding']['DesiredRevision'])+'-c'+str(t['Binding']['ConfigurationRevision'])+'-s'+str(t['SecretRevision'])for e in entries for t in e['Engines']]
links=json.loads(cmd('ip','-j','-d','link','show'));assert not any(x['ifname']in baseline['interface_names']or x.get('linkinfo',{}).get('info_data',{}).get('if_id')in baseline['xfrm_ids']for x in links)
policies=parse_xfrm_inventory(cmd('ip','-j','xfrm','policy'),'policy');assert not any(x.get('if_id')in baseline['xfrm_ids']for x in policies)
states=parse_xfrm_inventory(cmd('ip','-j','xfrm','state'),'state');assert not any(x.get('if_id')in baseline['xfrm_ids']for x in states)
assert all(name not in sas()and name not in conns()for name in all_names);after=routes();assert not any(ownroute(x)for x in after);normalized_foreign_baseline=[x for x in baseline['foreign_routes']if not automatic_owned_address_route(x)];automatic_routes=[x for x in baseline['foreign_routes']if automatic_owned_address_route(x)];assert len(automatic_routes)==4 and len({json.dumps(x,sort_keys=True)for x in automatic_routes})==4;assert sorted(json.dumps(x,sort_keys=True)for x in after)==sorted(json.dumps(x,sort_keys=True)for x in normalized_foreign_baseline)
nft=json.loads(cmd('/usr/sbin/nft','-j','list','ruleset'));guard_evidence=retained_guard(nft)
write(proof,{'connection_id':s['connection_id'],'normal_api_delete_finalized':True,'gateway_id':gw,'namespace':pre['new_namespace'],'certificate_unchanged':True,'original_provider_unchanged':True,'foreign_routes_unchanged':True,'automatic_owned_address_routes_excluded':automatic_routes,'pending_baseline_preserved':True,'retained_guard':guard_evidence,'owned_ipsec_bgp_absent':True,'record':record,'journal_entries':entries});print(json.dumps({'proof':str(proof),'normal_api_delete_finalized':True}))

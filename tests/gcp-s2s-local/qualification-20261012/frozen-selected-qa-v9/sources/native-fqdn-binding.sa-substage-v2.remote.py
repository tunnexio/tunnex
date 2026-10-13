NATIVE_REFUSAL_STAGES={'HA BGP': 'native_check_01', 'HA allocation': 'native_check_02', 'HA engine census': 'native_check_03', 'HA links': 'native_check_04', 'HA xfrm ID grammar': 'native_check_05', 'HA xfrm binding': 'native_check_06', 'HA xfrm census': 'native_check_07', 'XFRM ID binding': 'native_check_08', 'XFRM ID grammar': 'native_check_09', 'bounded native command refused': 'native_check_10', 'current delivery UUID': 'native_check_11', 'current desired7 identity': 'native_check_12', 'current link binding': 'native_check_13', 'current public delivery binding': 'native_check_14', 'deployed identity': 'native_check_15', 'duplicate JSON field': 'native_check_16', 'expected nine managed policies': 'native_check_17', 'journal bound': 'native_check_18', 'journal engine name grammar': 'native_check_19', 'lineage ownership': 'native_check_20', 'managed BGP path': 'native_check_21', 'managed PID grammar': 'native_check_22', 'managed process executable binding': 'native_check_23', 'measured allocation receipt drift': 'native_check_24', 'native bracket changed': 'native_check_25', 'native identity': 'native_check_26', 'native ip pin unmeasured': 'native_check_27', 'policy array': 'native_check_28', 'policy helper identity': 'native_check_29', 'production policy projection': 'native_check_30', 'recovery contract binding': 'native_check_31', 'recovery exact SA census': 'native_check_32', 'recovery exact route': 'native_check_33', 'recovery lineage census': 'native_check_34', 'recovery missing policies': 'native_check_35', 'recovery policy census': 'native_check_36', 'recovery policy reqid': 'native_check_37', 'retained original lineage drift': 'native_check_38'}
NATIVE_REFUSAL_STAGES.update({'recovery exact SA census connection_count': 'native_sa_connection_count', 'recovery exact SA census connection_names': 'native_sa_connection_names', 'recovery exact SA census ike_count': 'native_sa_ike_count', 'recovery exact SA census ike_states': 'native_sa_ike_states', 'recovery exact SA census child_count': 'native_sa_child_count', 'recovery exact SA census child_header_count': 'native_sa_child_header_count', 'recovery exact SA census child_states': 'native_sa_child_states', 'recovery exact SA census child_reqids': 'native_sa_child_reqids', 'recovery exact SA census sad_count': 'native_sa_sad_count'})
BOUND_HA_INDICES=[6,7]
"""Owned read-only native observation; never cleanup ACK or lease authority."""
import json,re,subprocess,signal,os,pathlib,hashlib,sys,uuid
CID='5ed2a7643f2756b58c2920e7f9f74cf68078c5a794cc128e8a6a112684ce283e'
IMAGE='sha256:b8f7ccba5b01cc9dd8ca0337c780c69d72e8037fcd5f16adfe98c53af4285ded'
SOURCE='5121dc3374656449dd53dab9abd248216d5d5581'
NODE='cbfabf16f1561f8dfb9d01cc49fad92a8ef2a8fed98dcd96b3e48a5533370bde'
BOOT='9617762e-19db-4a21-bdee-909dfb31e501';NS='net:[4026531840]'
HA='80c20667-8d84-4dd8-8e51-ae4a10445cbb';CLASSIC='b79d7eda-fafe-41cf-af2c-4115d4ef32c6'
TUNNEL='8494b8ef-e6e8-4d8d-b964-fc6faec7cb72';REQID=3912688814
POLICY_HELPER='/var/lib/tunnex-gcp-policy-observer-0249f7cf-20261011/policy-observer'
POLICY_HELPER_SOURCE='0249f7cf8804a7d6b4e1f82bf4dbf42b887bdfe7'
POLICY_HELPER_SHA='16a04c969ca284954f0c1a7b9fd10aec9b4d69eaae2a4ea68a272173e8ce7e2d'
IP_SHA='aa39a2d90d051a8dc3cdcb85f933b1306c399abaaa53c5310a0cfc819a4ac9a7'
JOURNAL='/var/lib/tunnex-gcp-s2s-cloud-20261010/ipsec/journal.json'
def unique(pairs):
 out={}
 for k,v in pairs:
  if k in out:raise ValueError('duplicate JSON field')
  out[k]=v
 return out
def loads(raw):return json.loads(raw,object_pairs_hook=unique)
def run(*args):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
 if p.returncode or len(p.stdout)>2097152:raise ValueError('bounded native command refused')
 return p.stdout.decode('utf-8').strip()
def execC(*args):return run('docker','exec',CID,*args)
def name(engine):
 b=engine['Binding'];tid=engine['TunnelID'];d=b['DesiredRevision'];c=b['ConfigurationRevision'];s=engine['SecretRevision']
 if not re.fullmatch('[0-9a-f-]{36}',tid) or any(type(x)is not int or x<1 for x in (d,c,s)):raise ValueError('journal engine name grammar')
 return 'tnx-ipsec-'+tid+'-d'+str(d)+'-c'+str(c)+'-s'+str(s)
def validate_public_binding(binding,delivery):
 expected={'OrgID':'01a124e7-60c7-78ca-aa85-d3a5025d9764','GatewayID':'01a125fa-32f3-762b-83d4-d368447bf6ed','ConnectionID':CLASSIC}
 if not isinstance(binding,dict)or any(binding.get(k)!=v for k,v in expected.items())or any(type(binding.get(k))is not int or binding[k]!=v for k,v in (('ConfigurationRevision',1),('DesiredRevision',7))):raise ValueError('current public delivery binding')
 if not isinstance(delivery,str)or str(uuid.UUID(delivery))!=delivery or uuid.UUID(delivery).int==0:raise ValueError('current delivery UUID')
def projection(journal):
 entries=journal['Payload']['Entries'];cl=[e for e in entries if e['Allocation']['ConnectionID']==CLASSIC];ha=[e for e in entries if e['Allocation']['ConnectionID']==HA]
 current=[e for e in cl if e['Phase']=='applied']
 if len(cl)!=3 or len(current)!=1 or len(ha)!=1 or ha[0]['Phase']!='applied' or ha[0]['ContractVersion']!=3:raise ValueError('recovery lineage census')
 historical={}
 for e in cl:
  a=e['Allocation'];ts=a['Tunnels'];es=e['Engines'];obs=e['Observed']
  if e['ContractVersion']!=4 or a['Namespace']!=NS or a.get('BGP',False) or len(ts)!=2 or len(es)!=2 or len(obs)!=2 or ts[0]['TunnelID']!=TUNNEL or ts[0]['Slot']!=1 or ts[1]['Slot']!=0 or es[0]['ReqID']!=REQID or es[0]['TunnelID']!=TUNNEL or ts[0]['XFRMID']!=es[0]['XFRMID'] or es[1]['ReqID']!=0 or obs[1]['InterfaceIndex']!=0:raise ValueError('recovery contract binding')
  idx=obs[0]['InterfaceIndex'];n=name(es[0])
  if type(idx)is not int or idx<=0 or n in historical:raise ValueError('lineage ownership')
  historical[n]=(e['Phase'],idx)
 prefix='tnx-ipsec-'+TUNNEL
 if historical.get(prefix+'-d2-c1-s1')!=('retained_refusal',8) or historical.get(prefix+'-d5-c1-s2')!=('retained_refusal',19):raise ValueError('retained original lineage drift')
 c=current[0];ce=c['Engines'][0]
 if name(ce)!=prefix+'-d7-c1-s2':raise ValueError('current desired7 identity')
 h=ha[0];a=h['Allocation']
 if a['Namespace']!=NS or [o['InterfaceIndex']for o in h['Observed']]!=BOUND_HA_INDICES:raise ValueError('HA allocation')
 hn={name(e):e['ReqID']for e in h['Engines']}
 if len(hn)!=2 or set(hn.values())!={2716755764,2378095810}:raise ValueError('HA engine census')
 directory=h['BGPProcess']['Directory']
 if not isinstance(directory,str)or not directory.startswith('/var/lib/tunnex-node/ipsec/')or '..'in pathlib.PurePosixPath(directory).parts:raise ValueError('managed BGP path')
 binding=ce['Binding']
 validate_public_binding(binding,c['DeliveryID'])
 return {'current_delivery_id':c['DeliveryID'],'current_binding':{k:binding[k]for k in ('OrgID','GatewayID','ConnectionID','ConfigurationRevision','DesiredRevision')},'ha_names':hn,'ha_links':[t['Name']for t in a['Tunnels']],'current_name':name(ce),'current_link':c['Allocation']['Tunnels'][0]['Name'],'current_index':c['Observed'][0]['InterfaceIndex'],'current_ifid':ce['XFRMID'],'current_reqid':ce['ReqID'],'bgp_directory':directory,'historical_lineages':historical}
def main_table(value):return (type(value)is int and value==254)or(type(value)is str and value in ('main','254'))
def verify(p,connections,sas,policies,links,routes,summary,sad):
 expected=dict(p['ha_names'],**{p['current_name']:p['current_reqid']})
 names=re.findall(r'^([^\s:]+):\s',connections,re.M)
 ike=re.findall(r'^([^\s:]+): #\d+, ([A-Z_]+),',sas,re.M)
 children=re.findall(r'^  ([^\s:]+): #\d+, reqid (\d+), ([A-Z_]+),',sas,re.M)
 if len(names)!=3:raise ValueError('recovery exact SA census connection_count')
 if set(names)!=set(expected):raise ValueError('recovery exact SA census connection_names')
 if len(ike)!=3:raise ValueError('recovery exact SA census ike_count')
 if set(ike)!={(n,'ESTABLISHED')for n in expected}:raise ValueError('recovery exact SA census ike_states')
 if len(children)!=3:raise ValueError('recovery exact SA census child_count')
 if len(re.findall(r'^  [^\s:]+: #',sas,re.M))!=3:raise ValueError('recovery exact SA census child_header_count')
 if any(state!='INSTALLED'for n,q,state in children):raise ValueError('recovery exact SA census child_states')
 if {n:int(q)for n,q,state in children}!=expected:raise ValueError('recovery exact SA census child_reqids')
 if sad!='SAD count 6':raise ValueError('recovery exact SA census sad_count')
 allowed=set(expected.values());seen=set();counts={q:0 for q in allowed}
 if len(policies)!=9:raise ValueError('expected nine managed policies')
 if not isinstance(policies,list):raise ValueError('policy array')
 for row in policies:
  if not isinstance(row,dict)or set(row)!={'if_id','tmpl'}or type(row['if_id'])is not int or row['if_id']not in allowed or not isinstance(row['tmpl'],list)or len(row['tmpl'])!=1:raise ValueError('recovery policy census')
  t=row['tmpl'][0]
  if not isinstance(t,dict)or set(t)!={'reqid'}or type(t['reqid'])is not int or t['reqid']!=row['if_id']:raise ValueError('recovery policy reqid')
  seen.add(t['reqid']);counts[t['reqid']]+=1
 if seen!=allowed or any(count!=3 for count in counts.values()):raise ValueError('recovery missing policies')
 selected=[l for l in links if l.get('ifname')==p['current_link']or l.get('ifindex')==p['current_index']]
 if len(selected)!=1 or selected[0]['ifname']!=p['current_link']or selected[0]['ifindex']!=p['current_index']or selected[0].get('linkinfo',{}).get('info_kind')!='xfrm':raise ValueError('current link binding')
 rawid=selected[0]['linkinfo'].get('info_data',{}).get('if_id')
 if type(rawid)is int:v=rawid
 elif isinstance(rawid,str)and re.fullmatch('0x[0-9a-fA-F]+',rawid):v=int(rawid,16)
 else:raise ValueError('XFRM ID grammar')
 if not 0<v<=4294967295 or v!=p['current_ifid']:raise ValueError('XFRM ID binding')
 hl={l['ifname']:l['ifindex']for l in links if l.get('ifname')in p['ha_links']}
 if hl!=dict(zip(p['ha_links'],BOUND_HA_INDICES)):raise ValueError('HA links')
 for link,q in zip(p['ha_links'],p['ha_names'].values()):
  rows=[l for l in links if l.get('ifname')==link]
  if len(rows)!=1 or rows[0].get('linkinfo',{}).get('info_kind')!='xfrm':raise ValueError('HA xfrm census')
  x=rows[0]['linkinfo'].get('info_data',{}).get('if_id')
  if type(x)is int:v=x
  elif isinstance(x,str)and re.fullmatch('0x[0-9a-fA-F]+',x):v=int(x,16)
  else:raise ValueError('HA xfrm ID grammar')
  if not 0<v<=4294967295 or v!=q:raise ValueError('HA xfrm binding')
 for dst,dev in [('10.80.0.0/24',p['ha_links'][0]),('10.81.0.0/24',p['current_link'])]:
  rs=[r for r in routes if r.get('dst')==dst]
  if len(rs)!=1 or rs[0].get('dev')!=dev or str(rs[0].get('protocol'))!='242' or rs[0].get('metric')!=50001 or not main_table(rs[0].get('table','main')):raise ValueError('recovery exact route')
 peers=summary.get('peers',{})
 if set(peers)!={'169.254.100.1','169.254.100.5'}or any(x.get('state')!='Established'for x in peers.values()):raise ValueError('HA BGP')
 return {'classic_installed_children':1,'ha_installed_children':2,'sad_count':6,'ha_established_bgp_peers':2,'current_index':p['current_index'],'current_name':p['current_name']}
def identity():
 if not re.fullmatch("[0-9a-f]{64}",CID) or not isinstance(BOUND_HA_INDICES,list) or len(BOUND_HA_INDICES)!=2 or any(type(i)is not int or i<=0 for i in BOUND_HA_INDICES) or len(set(BOUND_HA_INDICES))!=2:raise ValueError("fresh container and HA indices unbound")
 i=loads(run('docker','inspect',CID))[0]
 if i['Id']!=CID or i['Image']!=IMAGE or i['State']['Running']is not True or i['Config']['Labels'].get('org.opencontainers.image.revision')!=SOURCE:raise ValueError('deployed identity')
 if execC('sha256sum','/usr/local/bin/tunnex-node').split()[0]!=NODE or run('cat','/proc/sys/kernel/random/boot_id')!=BOOT or run('readlink','/proc/self/ns/net')!=NS or execC('readlink','/proc/self/ns/net')!=NS:raise ValueError('native identity')
 pid=i['State']['Pid']
 if type(pid)is not int or pid<=0:raise ValueError('managed PID grammar')
 proc=pathlib.Path('/proc')/str(pid);raw=(proc/'stat').read_text();parts=raw[raw.rfind(')')+2:].split();ticks=int(parts[19])
 if ticks<=0 or os.readlink(proc/'ns/net')!=NS or hashlib.sha256((proc/'exe').read_bytes()).hexdigest()!=NODE:raise ValueError('managed process executable binding')
 return {'pid_start_ticks':ticks,'source_commit':SOURCE,'image_id':IMAGE,'container_id':CID,'boot_id':BOOT,'namespace':NS,'node_sha256':NODE,'pid':i['State']['Pid'],'started_at':i['State']['StartedAt']}
def journal():
 p=pathlib.Path(JOURNAL)
 if p.stat().st_size>16777216:raise ValueError('journal bound')
 return loads(p.read_bytes())
def policy_projection():
 if not re.fullmatch('[0-9a-f]{64}',IP_SHA):raise ValueError('native ip pin unmeasured')
 helper=pathlib.Path(POLICY_HELPER)
 if helper.is_symlink() or helper.stat().st_uid!=0 or helper.stat().st_mode&0o777!=0o700 or hashlib.sha256(helper.read_bytes()).hexdigest()!=POLICY_HELPER_SHA:raise ValueError('policy helper identity')
 value=loads(run(POLICY_HELPER,'-ip-sha256',IP_SHA))
 if not isinstance(value,dict)or set(value)!={'completed','source_commit','namespace','policies'}or value['completed']is not True or value['source_commit']!=POLICY_HELPER_SOURCE or value['namespace']!=NS or not isinstance(value['policies'],list):raise ValueError('production policy projection')
 return value['policies']
def collect():
 before=identity();p=projection(journal());
 if before!=BOUND_IDENTITY or any(p[k]!=BOUND_ALLOCATION[a]for k,a in [('current_name','engine_name'),('current_link','interface_name'),('current_index','interface_index'),('current_ifid','xfrm_id'),('current_reqid','reqid')]) or p['ha_names']!=BOUND_ALLOCATION['ha_engines']:raise ValueError('measured allocation receipt drift')
 vici=('docker','exec','-e','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf',CID,'/opt/tunnex-ipsec/sbin/swanctl')
 connections=run(*vici,'--list-conns','--uri','unix:///run/tunnex-ipsec/charon.vici');sas=run(*vici,'--list-sas','--uri','unix:///run/tunnex-ipsec/charon.vici')
 policies=policy_projection();links=loads(run('ip','-j','-d','link','show'));routes=loads(run('ip','-j','-d','-N','-4','route','show','table','all'))
 summary=loads(execC('/opt/tunnex-bgp/vtysh','--vty_socket',p['bgp_directory'],'-d','bgpd','-c','show bgp ipv4 unicast summary json'))
 observed=verify(p,connections,sas,policies,links,routes,summary,run('ip','xfrm','state','count'))
 if projection(journal())!=p or identity()!=before:raise ValueError('native bracket changed')
 return {'allocation_receipt_sha256':BOUND_RECEIPT_SHA,'completed':True,'scope':'read-only native observation; desired7 complete native recovery observation only; no cleanup ACK/guard/packet claim','identity':before,'observation':observed,'journal_projection':p}
if __name__=='__main__':
 def expired(*args):raise TimeoutError('aggregate native observation')
 signal.signal(signal.SIGALRM,expired);signal.alarm(45)
 try:print(json.dumps(collect()))
 except BaseException as e:print(json.dumps({'completed':False,'error_type':type(e).__name__,'native_refusal_stage':NATIVE_REFUSAL_STAGES.get(str(e),'native_unclassified')}));raise SystemExit(1)
 finally:signal.alarm(0)

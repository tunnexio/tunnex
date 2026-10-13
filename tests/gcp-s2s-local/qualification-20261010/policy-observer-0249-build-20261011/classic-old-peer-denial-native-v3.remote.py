"""Owned read-only native observation; never cleanup ACK or lease authority."""
import json,re,subprocess,signal,os,pathlib,hashlib,sys
CID='3bad435938b37398218e1c28a278fe72a57735cc489719527d2f8d1167e732ed'
IMAGE='sha256:dfbe391873e7013111d47f489cf6ddbd6c8a83541b8bbb8aab191310879a8db9'
SOURCE='9c3ab006c13b72285f43baed1805da1af273ffa7'
NODE='eb319ffd37c12bb65b0d2ea5190e56cb3cdf3f8b131363642eb8db18c0766923'
BOOT='9617762e-19db-4a21-bdee-909dfb31e501';NS='net:[4026531840]'
HA='80c20667-8d84-4dd8-8e51-ae4a10445cbb';CLASSIC='b79d7eda-fafe-41cf-af2c-4115d4ef32c6'
TUNNEL='8494b8ef-e6e8-4d8d-b964-fc6faec7cb72';REQID=3912688814
POLICY_HELPER='/var/lib/tunnex-gcp-policy-observer-20261011/policy-observer'
POLICY_HELPER_SHA='e91d3189a13ac7d68e9a30dd411697779d4c44319725facd577f75a57321a904'
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
def projection(journal,expected_revision):
 entries=journal['Payload']['Entries'];ha=[e for e in entries if e['Allocation']['ConnectionID']==HA];cl=[e for e in entries if e['Allocation']['ConnectionID']==CLASSIC]
 if type(expected_revision)is not int or expected_revision!=5:raise ValueError('exact old-peer revision')
 if len(ha)!=1 or not cl or ha[0]['ContractVersion']!=3 or ha[0]['Phase']!='applied':raise ValueError('journal profile census')
 h=ha[0];engines=h['Engines'];alloc=h['Allocation'];obs=h['Observed']
 if alloc['Namespace']!=NS or len(engines)!=2 or [x['InterfaceIndex'] for x in obs]!=[6,7]:raise ValueError('HA native allocation binding')
 hn={name(e):e['ReqID'] for e in engines}
 if len(hn)!=2 or set(hn.values())!={2716755764,2378095810}:raise ValueError('HA engine identity')
 configs=set();links=set();ifids=set();indices=set();current=[]
 for e in cl:
  a=e['Allocation'];ts=a['Tunnels'];es=e['Engines'];observed=e['Observed']
  if e['ContractVersion']!=4 or e['Phase']not in ('retained_refusal','reserved','applying','applied') or a['Namespace']!=NS or a.get('BGP',False) or len(ts)!=2 or ts[0]['TunnelID']!=TUNNEL or ts[0]['Slot']!=1 or ts[1]['Slot']!=0:raise ValueError('Classic retained lineage')
  if es[0]['TunnelID']!=TUNNEL or es[0]['ReqID']!=REQID or es[1]['ReqID']!=0 or ts[0]['XFRMID']!=es[0]['XFRMID']:raise ValueError('Classic engine binding')
  revision=es[0]['Binding']['DesiredRevision']
  if type(revision)is not int or revision>expected_revision or (revision!=expected_revision and e['Phase']!='retained_refusal'):raise ValueError('owned covered epoch binding')
  if revision==expected_revision:
   if es[0]['Binding']['ConfigurationRevision']!=1 or es[0]['SecretRevision']!=2:raise ValueError('rotated delivery identity')
   current.append(name(es[0]))
  configs.add(name(es[0]));links.add(ts[0]['Name']);ifids.add(ts[0]['XFRMID']);indices.add(observed[0]['InterfaceIndex'])
  if observed[1]['InterfaceIndex']!=0:raise ValueError('inactive ownership')
 if len(current)!=1 or 0 in ifids or '' in links:raise ValueError('Classic original kernel identity')
 bgp=h.get('BGPProcess');directory=bgp.get('Directory')if bgp else None
 if not isinstance(directory,str) or not directory.startswith('/var/lib/tunnex-node/ipsec/') or '..'in pathlib.PurePosixPath(directory).parts:raise ValueError('managed BGP path')
 return {'ha_names':hn,'ha_links':[t['Name'] for t in alloc['Tunnels']],'classic_names':sorted(configs),'classic_links':sorted(links),'classic_ifids':sorted(ifids),'classic_indices':sorted(indices),'bgp_directory':directory,'classic_entries':len(cl),'classic_phases':[e['Phase']for e in cl],'old_peer_current_name':current[0],'expected_revision':expected_revision}
def main_table(value):return (type(value)is int and value==254)or(type(value)is str and value in ('main','254'))
def verify(p,connections,sas,policies,links,routes,summary,sad):
 names=re.findall(r'^([^\s:]+):\s',connections,re.M)
 if len(names)!=len(set(names)):raise ValueError('daemon config duplicate')
 if set(names)not in (set(p['ha_names']),set(p['ha_names'])|{p['old_peer_current_name']}):raise ValueError('daemon config census')
 ike=re.findall(r'^([^\s:]+): #\d+, ([A-Z_]+),',sas,re.M)
 all_children=re.findall(r'^  ([^\s:]+): #\d+, reqid (\d+), ([A-Z_]+),',sas,re.M)
 child_headers=re.findall(r'^  [^\s:]+: #',sas,re.M)
 if len(all_children)!=len(child_headers)or any(state!='INSTALLED'for n,q,state in all_children):raise ValueError('unknown child state/grammar')
 children=[(n,q)for n,q,state in all_children]
 classic_ike=[(n,state)for n,state in ike if n==p['old_peer_current_name']]
 if len(classic_ike)>1 or any(state!='CONNECTING'for n,state in classic_ike):raise ValueError('old peer IKE denial unproved')
 ha_ike=[(n,state)for n,state in ike if n!=p['old_peer_current_name']]
 if len(ha_ike)!=2 or set(ha_ike)!={(n,'ESTABLISHED')for n in p['ha_names']} or len(children)!=2 or {n:int(q)for n,q in children}!=p['ha_names'] or sad!='SAD count 4':raise ValueError('HA SA census')
 if not isinstance(policies,list):raise ValueError('policy array')
 for policy in policies:
  if not isinstance(policy,dict):raise ValueError('policy object grammar')
  if 'if_id'in policy and (type(policy['if_id'])is not int or policy['if_id']<0 or policy['if_id']>4294967295):raise ValueError('policy ifid grammar')
  templates=policy.get('tmpl',[])
  if not isinstance(templates,list):raise ValueError('policy template grammar')
  for template in templates:
   if not isinstance(template,dict):raise ValueError('template object grammar')
   if 'reqid'in template and (type(template['reqid'])is not int or template['reqid']<0 or template['reqid']>4294967295):raise ValueError('template reqid grammar')
  # Policies can be reserved before failed handshake; they do not prove CHILD/lease authority.
 classic_links=[l['ifname']for l in links if l.get('ifname')in p['classic_links']] 
 hl={l['ifname']:l['ifindex']for l in links if l.get('ifname')in p['ha_links']}
 if hl!=dict(zip(p['ha_links'],[6,7])):raise ValueError('HA links absent')
 classic_routes=[r for r in routes if r.get('dst')=='10.81.0.0/24'and str(r.get('protocol'))=='242']
 hr=[r for r in routes if r.get('dst')=='10.80.0.0/24']
 if len(hr)!=1 or hr[0].get('dev')!=p['ha_links'][0] or str(hr[0].get('protocol'))!='242' or hr[0].get('metric')!=50001 or not main_table(hr[0].get('table','main')):raise ValueError('HA route exact')
 peers=summary.get('peers',{})
 if set(peers)!={'169.254.100.1','169.254.100.5'} or any(v.get('state')!='Established'for v in peers.values()):raise ValueError('HA BGP census')
 return {'classic_installed_child_absent':True,'classic_established_ike_absent':True,'classic_connecting_ike_count':len(classic_ike),'classic_owned_config_loaded':p['old_peer_current_name']in names,'classic_observed_owned_links':classic_links,'classic_observed_owned_routes':classic_routes,'ha_installed_children':2,'sad_count':4,'ha_established_bgp_peers':2,'ha_selected_index':6}
def identity():
 i=loads(run('docker','inspect',CID))[0]
 if i['Id']!=CID or i['Image']!=IMAGE or i['State']['Running']is not True or i['Config']['Labels'].get('org.opencontainers.image.revision')!=SOURCE:raise ValueError('deployed identity')
 if execC('sha256sum','/usr/local/bin/tunnex-node').split()[0]!=NODE or run('cat','/proc/sys/kernel/random/boot_id')!=BOOT or run('readlink','/proc/self/ns/net')!=NS or execC('readlink','/proc/self/ns/net')!=NS:raise ValueError('native identity')
 return {'source_commit':SOURCE,'image_id':IMAGE,'container_id':CID,'boot_id':BOOT,'namespace':NS,'node_sha256':NODE,'pid':i['State']['Pid'],'started_at':i['State']['StartedAt']}
def journal():
 p=pathlib.Path(JOURNAL)
 if p.stat().st_size>16777216:raise ValueError('journal bound')
 return loads(p.read_bytes())
def policy_projection():
 if not re.fullmatch('[0-9a-f]{64}',IP_SHA):raise ValueError('native ip pin unmeasured')
 helper=pathlib.Path(POLICY_HELPER)
 if helper.is_symlink() or helper.stat().st_uid!=0 or helper.stat().st_mode&0o777!=0o700 or hashlib.sha256(helper.read_bytes()).hexdigest()!=POLICY_HELPER_SHA:raise ValueError('policy helper identity')
 value=loads(run(POLICY_HELPER,'-ip-sha256',IP_SHA))
 if not isinstance(value,dict)or set(value)!={'completed','source_commit','namespace','policies'}or value['completed']is not True or value['source_commit']!=SOURCE or value['namespace']!=NS or not isinstance(value['policies'],list):raise ValueError('production policy projection')
 return value['policies']
def collect():
 before=identity();p=projection(journal(),5);vici=('docker','exec','-e','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf',CID,'/opt/tunnex-ipsec/sbin/swanctl')
 connections=run(*vici,'--list-conns','--uri','unix:///run/tunnex-ipsec/charon.vici');sas=run(*vici,'--list-sas','--uri','unix:///run/tunnex-ipsec/charon.vici')
 policies=policy_projection();links=loads(run('ip','-j','-d','link','show'));routes=loads(run('ip','-j','-d','-N','-4','route','show','table','all'))
 summary=loads(execC('/opt/tunnex-bgp/vtysh','--vty_socket',p['bgp_directory'],'-d','bgpd','-c','show bgp ipv4 unicast summary json'))
 observed=verify(p,connections,sas,policies,links,routes,summary,run('ip','xfrm','state','count'))
 if projection(journal(),5)!=p or identity()!=before:raise ValueError('native bracket changed')
 return {'completed':True,'scope':'read-only native observation; enabled-old-peer SA denial observation only; no cleanup ACK/guard/packet claim','identity':before,'observation':observed,'journal_projection':p}
if __name__=='__main__':
 def expired(*args):raise TimeoutError('aggregate native observation')
 signal.signal(signal.SIGALRM,expired);signal.alarm(45)
 try:print(json.dumps(collect()))
 except BaseException as e:print(json.dumps({'completed':False,'error_type':type(e).__name__}));raise SystemExit(1)
 finally:signal.alarm(0)

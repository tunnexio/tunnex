import json,re,subprocess,signal,os,pathlib,hashlib
CID='3bad435938b37398218e1c28a278fe72a57735cc489719527d2f8d1167e732ed'
IMAGE='sha256:dfbe391873e7013111d47f489cf6ddbd6c8a83541b8bbb8aab191310879a8db9'
SOURCE='9c3ab006c13b72285f43baed1805da1af273ffa7'
NODE='eb319ffd37c12bb65b0d2ea5190e56cb3cdf3f8b131363642eb8db18c0766923'
BOOT='9617762e-19db-4a21-bdee-909dfb31e501'
NS='net:[4026531840]'
HA='80c20667-8d84-4dd8-8e51-ae4a10445cbb'
CLASSIC='b79d7eda-fafe-41cf-af2c-4115d4ef32c6'
TUNNEL='8494b8ef-e6e8-4d8d-b964-fc6faec7cb72'
REQID=3912688814
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
def identity():
 i=loads(run('docker','inspect',CID))[0]
 if i['Id']!=CID or i['Image']!=IMAGE or i['State']['Running']is not True or i['Config']['Labels'].get('org.opencontainers.image.revision')!=SOURCE:raise ValueError('deployed identity')
 if execC('sha256sum','/usr/local/bin/tunnex-node').split()[0]!=NODE or run('cat','/proc/sys/kernel/random/boot_id')!=BOOT or run('readlink','/proc/self/ns/net')!=NS or execC('readlink','/proc/self/ns/net')!=NS:raise ValueError('native identity')
 return {'source_commit':SOURCE,'image_id':IMAGE,'container_id':CID,'boot_id':BOOT,'namespace':NS,'node_sha256':NODE,'pid':i['State']['Pid'],'started_at':i['State']['StartedAt']}
def observational_topology():
 routes_main=json.loads(run('ip','-j','-4','route','show','table','main'))
 routes_all=json.loads(run('ip','-j','-4','route','show','table','all'))
 routes6_all=json.loads(run('ip','-j','-6','route','show','table','all'))
 links=json.loads(run('ip','-j','link','show'))
 assert all(isinstance(v,list) and all(isinstance(x,dict)for x in v)for v in (routes_main,routes_all,routes6_all,links))
 wg=[l for l in links if l.get('ifname')=='wg0'];assert len(wg)<=1
 wgmode=json.loads(run('ip','-j','-d','link','show','wg0')) if wg else []
 wgaddr=json.loads(run('ip','-j','addr','show','wg0')) if wg else []
 if wg:
  assert len(wgmode)==len(wgaddr)==1 and wgmode[0]['linkinfo']['info_kind']=='wireguard' and wgmode[0]['ifindex']==wg[0]['ifindex']==wgaddr[0]['ifindex']
  assert wgaddr[0]['addr_info'] and all(a.get('family')=='inet' and a.get('local')=='10.99.0.1' and a.get('prefixlen')==24 for a in wgaddr[0]['addr_info'])
 return {'fresh_wg_addresses':wgaddr,'fresh_wg_mode':wgmode,'main_routes':routes_main,'all_ipv4_routes':routes_all,'all_ipv6_routes':routes6_all,'links':links,'observed_wg0_links':wg,'scope':'key-free observation only; no authority/adoption/teardown allowance'}
WG_SCHEMA_SHA='ac14e9cd861b3260b0c30599fe02b8d4cc9730a5b0e1967cb9e0bb1e0382639e'
SOURCE_INPUT_PROOF_SHA='3678eb0404b2e538e37c0b123d39d50a2c697fb8aa484d0e81f9b1c775fd85fe'
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True).encode()).hexdigest()
def normalized(raw):
 out=[]
 for obj in loads(raw)['nftables']:
  if not isinstance(obj,dict)or len(obj)!=1:raise ValueError('nft object grammar')
  kind,value=next(iter(obj.items()))
  if kind=='metainfo':continue
  if kind=='rule':
   if not isinstance(value.get('expr'),list):raise ValueError('rule grammar')
   for expression in value['expr']:
    if isinstance(expression,dict)and 'counter'in expression:
     c=expression['counter']
     if len(expression)!=1 or not isinstance(c,dict)or set(c)!={'packets','bytes'}or any(type(v)is not int or not 0<=v<=18446744073709551615 for v in c.values()):raise ValueError('typed native counter')
     expression['counter']={'packets':0,'bytes':0}
  out.append(obj)
 return out
def wg_objects(objects):
 return [o for o in objects if isinstance(next(iter(o.values())),dict)and next(iter(o.values())).get('family')in('ip','ip6')and(next(iter(o.values())).get('table')=='tunnex'or(next(iter(o))=='table'and next(iter(o.values())).get('name')=='tunnex'))]
def shape(objects):
 rows=loads(json.dumps(objects))
 for o in rows:
  kind,v=next(iter(o.items()))
  if 'handle'in v:
   if type(v['handle'])is not int or v['handle']<=0:raise ValueError('native handle grammar')
   del v['handle']
 return rows
def journal_projection():
 path=pathlib.Path(JOURNAL)
 if path.stat().st_size>16777216:raise ValueError('journal bound')
 payload=loads(path.read_bytes())['Payload']
 entries=payload['Entries']
 if not isinstance(entries,list)or not 1<=len(entries)<=256:raise ValueError('journal census')
 expected={HA:3,CLASSIC:4}
 if {e['Allocation']['ConnectionID']:e['ContractVersion']for e in entries}!=expected:raise ValueError('journal profiles')
 projection=[{k:e[k]for k in('ContractVersion','DeliveryID','OwnershipDigest','Allocation','Engines')}for e in entries]
 return {'immutable_lineages':projection,'immutable_digest':digest(projection),'version':payload['Version'],'owner':payload['OwnerID'],'phases':[e['Phase']for e in entries]}
def collect():
 before=identity();j=journal_projection();topology=observational_topology()
 if execC('sha256sum','/usr/sbin/nft').split()[0]!='7156559ea0d2d062a40af33952eb412833a191cb7179e9ad9efe8b146a563d7f':raise ValueError('nft reader identity')
 raw=execC('/usr/sbin/nft','-j','list','ruleset');objects=normalized(raw);wg=wg_objects(objects)
 if len(wg)!=24 or digest(shape(wg))!=WG_SCHEMA_SHA:raise ValueError('source-owned whole WG schema unproved')
 foreign=[o for o in objects if o not in wg and not(isinstance(next(iter(o.values())),dict)and next(iter(o.values())).get('family')=='inet'and(next(iter(o.values())).get('table')=='tunnex_ipsec'or(next(iter(o))=='table'and next(iter(o.values())).get('name')=='tunnex_ipsec')))]
 if identity()!=before or journal_projection()!=j or observational_topology()!=topology:raise ValueError('capture bracket changed')
 return {'source_schema_verified':True,'schema_source_input_proof_sha256':SOURCE_INPUT_PROOF_SHA,'complete_schema_sha256':WG_SCHEMA_SHA,'completed':True,'identity':before,'journal':j,'topology':topology,'wg_whole_objects':wg,'wg_objects_sha256':digest(wg),'foreign_nft_objects':foreign,'foreign_nft_sha256':digest(foreign),'full_nft_sha256':hashlib.sha256(raw.encode()).hexdigest(),'full_nft':loads(raw),'scope':'key-free observational capture only; schema comparison ignores handles ONLY for source audit; exact runtime WG hash retains every actual handle; no adoption or teardown authority'}
if __name__=='__main__':
 if __import__('sys').flags.optimize:raise RuntimeError('optimized Python refused')
 signal.signal(signal.SIGALRM,lambda *a:(_ for _ in()).throw(TimeoutError('capture budget')));signal.alarm(60)
 try:print(json.dumps(collect()))
 except BaseException as e:print(json.dumps({'completed':False,'error_type':type(e).__name__}));raise SystemExit(1)

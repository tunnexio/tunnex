"""Normal API phased expiry qualification; no action on import.

Use prepare -> lease -> external bounded allow/expiry probes -> restore.
Lease failure attempts BOTH original restores; successful lease requires restore
even if an external probe fails. No API atomic CAS is claimed.
"""
import argparse,datetime,hashlib,importlib.util,ipaddress,json,os,pathlib,re,stat,urllib.request
ROOT=pathlib.Path('/private/tmp/gcp-s2s-cloud-policy-prep')
PRIVATE=ROOT/'deploy/ipsec/gcp-private-api-runner.py'
TEMPLATES=ROOT/'tests/gcp-s2s-local/GCP-CLOUD-KEYFREE-GRANT-TEMPLATES-20261010.json'
HISTORICAL=pathlib.Path('/private/tmp/gcp-cloud-provider-private-20261010/pre-replacement-api-baseline.json')
HISTORICAL_SHA='6f7806da72d02cd4bfc4a63e0973e42b220a4e06a82300d3adb7fb943b5c1aa1'
FIELDS=('src_kind','src_site_id','src_cidr','src_user_id','src_group_id','src_device_id','dst_kind','dst_resource_id','dst_group_id','dst_site_id','dst_k8s_service_id','dst_fqdn_resource_id','expires_at')
OWNED={'tcp':('01a12659-7de0-79ad-8a39-03d62cbcb3d5','01a12659-c017-70c0-b02d-2fe6051f51a5',8080),'udp':('01a12659-f410-74f3-8d4d-3b0dbbac1729','01a1265a-3527-7b51-b8fc-e7a9404981f4',9000)}
def parse_rfc3339(value):
 # Python3.9 only accepts selected fractional lengths. Go RFC3339Nano omits
 # insignificant trailing zeros. Pad exact microseconds, never round a deadline.
 if not isinstance(value,str):raise ValueError('RFC3339 timestamp required')
 match=re.fullmatch(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})',value)
 if match is None:raise ValueError('strict RFC3339 timestamp required')
 fraction=match.group(2)or ''
 if len(fraction)>6:
  if any(c!='0'for c in fraction[6:]):raise ValueError('submicrosecond precision cannot be preserved')
  fraction=fraction[:6]
 suffix='+00:00'if match.group(3)=='Z'else match.group(3)
 # datetime allows minute overflow in offsets; strict RFC3339 does not.
 if suffix[4:6]>'59' or suffix[1:3]>'23':raise ValueError('invalid RFC3339 offset')
 normalized=match.group(1)+('.'+fraction.ljust(6,'0')if fraction else '')+suffix
 return datetime.datetime.fromisoformat(normalized).astimezone(datetime.timezone.utc)
def sem(p):
 out={k:p.get(k) for k in FIELDS}
 if out['expires_at']is not None:out['expires_at']=parse_rfc3339(out['expires_at']).isoformat()
 return out
def audit(resources,policies,templates):
 if len({r['id']for r in resources})!=len(resources)or len({p['id']for p in policies})!=len(policies):raise ValueError('duplicate baseline IDs')
 selected=[]
 for protocol,(rid,pid,port)in OWNED.items():
  template=[t for t in templates if t['profile']=='classic'and t['resource_body']['protocol']==protocol and t['resource_body']['port_low']==port]
  if len(template)!=1:raise ValueError('exact template required')
  matches=[r for r in resources if r['id']==rid]
  if len(matches)!=1 or any(matches[0].get(k)!=v for k,v in template[0]['resource_body'].items()):raise ValueError('exact owned resource required')
  b=dict(template[0]['grant_body']);b['dst_resource_id']=rid
  grants=[p for p in policies if p['id']==pid]
  if len(grants)!=1 or sem(grants[0])!=sem(b)or grants[0].get('enabled')is not True:raise ValueError('exact owned permanent grant required')
  selected.append({'id':pid,'body':b})
 # Preserve the entire current snapshot. Every OTHER enabled rule must have a
 # resolved literal resource destination proven disjoint at the two app tuples.
 # Unknown group/site/FQDN/K8s coverage refuses rather than guessing authority.
 for p in policies:
  if p['id']in {v['id']for v in selected}or p.get('enabled')is False:continue
  if p.get('dst_kind')!='resource':raise ValueError('unresolved broader destination coverage')
  matches=[r for r in resources if r['id']==p.get('dst_resource_id')]
  if len(matches)!=1:raise ValueError('unresolved resource coverage')
  resource=matches[0];network=ipaddress.ip_network(resource['cidr'],strict=True)
  if ipaddress.ip_address('10.81.0.10')not in network:continue
  protocol=resource.get('protocol');low=resource.get('port_low');high=resource.get('port_high')
  if protocol not in ('tcp','udp')or type(low)is not int or type(high)is not int:raise ValueError('broad/unknown destination protocol')
  if low<=OWNED[protocol][2]<=high:raise ValueError('alternative Classic app authority')
 return selected
def historical_preserved(resources,policies,historical,templates):
 current_r={r['id']:r for r in resources};current_p={p['id']:p for p in policies}
 for r in historical['resources']:
  if current_r.get(r['id'])!=r:raise ValueError('historical resource changed')
 for p in historical['policies']:
  row=current_p.get(p['id'])
  if row is None or sem(row)!=sem(p)or row.get('enabled')!=p.get('enabled'):raise ValueError('historical policy semantics changed')
 oldr={r['id']for r in historical['resources']};oldp={p['id']for p in historical['policies']}
 # Only separately authorized Classic DNS tuple additions may coexist with the
 # fixed historical snapshot; complete current baseline is frozen afterwards.
 allowed=[t for t in templates if t['profile']=='classic'and t['resource_body']['port_low']==53]
 added={}
 for r in resources:
  if r['id']in oldr:continue
  matches=[t for t in allowed if all(r.get(k)==v for k,v in t['resource_body'].items())]
  if len(matches)!=1:raise ValueError('unreviewed resource delta')
  added[r['id']]=matches[0]
 for p in policies:
  if p['id']in oldp:continue
  t=added.get(p.get('dst_resource_id'))
  if t is None:raise ValueError('unreviewed policy delta')
  body=dict(t['grant_body']);body['dst_resource_id']=p['dst_resource_id']
  if sem(p)!=sem(body)or p.get('enabled')is not True:raise ValueError('unreviewed DNS policy delta')
def restore(request,baseline,record):
 errors=[]
 for owned in baseline['selected']:
  try:
   matches=[p for p in request('/policies')if p['id']==owned['id']]
   if len(matches)!=1 or sem(matches[0])!=sem(owned['body']):raise ValueError('owned restore semantics changed')
   if matches[0].get('enabled')is not True:request('/policies/'+owned['id'],'PATCH',{'enabled':True})
   after=[p for p in request('/policies')if p['id']==owned['id']]
   if len(after)!=1 or sem(after[0])!=sem(owned['body'])or after[0].get('enabled')is not True:raise ValueError('restore readback refused')
   record({'restored_original_id':owned['id']})
  except Exception as e:errors.append({'id':owned['id'],'error_type':type(e).__name__})
 if errors:record({'restore_errors':errors});raise ValueError('restore incomplete; no success claim')
 current={p['id']:p for p in request('/policies')}
 for original in baseline['policies']:
  if original['id']not in current or sem(current[original['id']])!=sem(original)or current[original['id']].get('enabled')!=original.get('enabled'):raise ValueError('original baseline policy preservation refused')
 if request('/resources')!=baseline['resources']:raise ValueError('original resources changed')
 record({'original_resources_and_policies_preserved':True})

def cleanup(request,events,record,now):
 owned=[v for v in events if 'created_temporary_id'in v]
 seen=set()
 for event in owned:
  identifier=event['created_temporary_id']
  if not identifier or identifier in seen:raise ValueError('uncertain temporary identity; no delete')
  seen.add(identifier)
  matches=[p for p in request('/policies')if p['id']==identifier]
  if not matches:record({'temporary_id':identifier,'already_absent':True});continue
  if len(matches)!=1 or sem(matches[0])!=sem(event['body']):raise ValueError('temporary identity/body changed')
  expires=parse_rfc3339(event['body']['expires_at'])
  if expires>now:raise ValueError('temporary grant not yet expired')
  request('/policies/'+identifier,'DELETE');record({'deleted_expired_temporary_id':identifier})
SITE='01a12500-95ae-7728-b901-54f20df98cc1'
PREFIX='10.70.0.0/24'
def prove_site_prefix(request):
 sites=request('/sites')
 if not isinstance(sites,list)or len([s for s in sites if s.get('id')==SITE])!=1:raise ValueError('exact source site absent')
 subnets=request('/sites/'+SITE+'/subnets')
 if not isinstance(subnets,list)or len(subnets)!=1:raise ValueError('source site must have singleton subnet')
 subnet=subnets[0]
 if subnet.get('site_id')!=SITE or subnet.get('status')!='approved' or subnet.get('cidr')!=PREFIX:raise ValueError('exact approved source prefix required')
 if str(ipaddress.ip_network(subnet['cidr'],strict=True))!=PREFIX:raise ValueError('source prefix not canonical')
def temporary_body(original):
 if original.get('src_kind')!='site'or original.get('src_site_id')!=SITE or any(original.get(k)is not None for k in ('src_cidr','src_user_id','src_group_id','src_device_id')):raise ValueError('exact original source identity required')
 if original.get('dst_kind')!='resource'or not original.get('dst_resource_id'):raise ValueError('exact resource destination required')
 body=dict(original);body.update(src_kind='cidr',src_cidr=PREFIX,src_site_id=None)
 return body
def prove_distinct_temporary_tuples(policies,selected):
 destinations={temporary_body(v['body'])['dst_resource_id']for v in selected}
 if len(destinations)!=2:raise ValueError('two distinct application resources required')
 for p in policies:
  # DB uniqueness is independent of enabled state and expiry. A disabled or
  # expired existing CIDR/resource tuple must therefore still refuse replay.
  if p.get('src_kind')=='cidr'and p.get('dst_kind')=='resource'and p.get('dst_resource_id')in destinations:
   try:cidr=ipaddress.ip_network(p.get('src_cidr'),strict=True)
   except (TypeError,ValueError):raise ValueError('uncertain existing CIDR tuple')
   if cidr==ipaddress.ip_network(PREFIX):raise ValueError('temporary CIDR tuple already exists')
def lease(request,baseline,record,now):
 if request('/resources')!=baseline['resources']or request('/policies')!=baseline['policies']:raise ValueError('baseline changed; no writes')
 prove_site_prefix(request)
 prove_distinct_temporary_tuples(baseline['policies'],baseline['selected'])
 record({'source_site_id':SITE,'verified_singleton_source_prefix':PREFIX,'temporary_source_kind':'cidr','original_source_kind':'site','effective_source_unchanged':True})
 expiry=(now+datetime.timedelta(seconds=90)).isoformat().replace('+00:00','Z')
 try:
  for owned in baseline['selected']:
   request('/policies/'+owned['id'],'PATCH',{'enabled':False})
   live=[p for p in request('/policies')if p['id']==owned['id']]
   if len(live)!=1 or sem(live[0])!=sem(owned['body'])or live[0].get('enabled')is not False:raise ValueError('disable readback refused')
   record({'disabled_original_id':owned['id']})
  for owned in baseline['selected']:
   body=temporary_body(owned['body']);body['expires_at']=expiry
   new=request('/policies','POST',body)
   # Preserve returned ID before readback: partial success must not replay.
   record({'created_temporary_id':new.get('id'),'expires_at':expiry,'body':body})
   if not new.get('id')or sem(new)!=sem(body)or new.get('enabled')is not True:raise ValueError('temporary grant readback refused')
  record({'leased':True,'expires_at':expiry,'restore_required':True})
 except BaseException:
  restore(request,baseline,record)
  raise
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
def main():
 p=argparse.ArgumentParser();p.add_argument('--phase',choices=['prepare','lease','restore','cleanup'],required=True);p.add_argument('--cookie-file',required=True);p.add_argument('--baseline',required=True);p.add_argument('--baseline-sha256');p.add_argument('--lease-receipt');p.add_argument('--lease-sha256');p.add_argument('--receipt',required=True);a=p.parse_args()
 if hashlib.sha256(PRIVATE.read_bytes()).hexdigest()!='5623fc4798a464e2926229646465b2603aea960d5f496abae136e871f9e4181e':raise ValueError('auth helper drift')
 spec=importlib.util.spec_from_file_location('private',PRIVATE);private=importlib.util.module_from_spec(spec);spec.loader.exec_module(private)
 cookie=private.cookie_header(private.private_read(a.cookie_file));opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 def request(path,method='GET',body=None):
  r=urllib.request.Request('http://127.0.0.1:38083/api/v1/organizations/'+private.ORG+path,method=method,data=None if body is None else json.dumps(body).encode(),headers={'Cookie':cookie,'X-Tunnex-CSRF':'1','Content-Type':'application/json'})
  with opener.open(r,timeout=15)as response:
   raw=response.read(2*1024*1024+1)
   if len(raw)>2*1024*1024:raise ValueError('bounded API response')
   return json.loads(raw,object_pairs_hook=private.unique)if raw else None
 for path in (a.receipt,a.baseline):
  s=os.lstat(pathlib.Path(path).parent)
  if not stat.S_ISDIR(s.st_mode)or s.st_uid!=os.getuid()or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('private output directory')
 fd=os.open(a.receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w')as f:
  def record(v):f.write(json.dumps(v)+'\n');f.flush();os.fsync(f.fileno())
  record({'phase':a.phase,'started':True})
  try:
   if a.phase=='prepare':
    raw=TEMPLATES.read_bytes()
    if hashlib.sha256(raw).hexdigest()!='a8c60386408bfc985d60400efe24a094a62f69784aa4783e50e7fc2b7a88c05a':raise ValueError('template drift')
    historic=private.private_read(HISTORICAL,2*1024*1024)
    if hashlib.sha256(historic).hexdigest()!=HISTORICAL_SHA:raise ValueError('historical baseline binding refused')
    resources=request('/resources');policies=request('/policies');templates=json.loads(raw)['items']
    historical_preserved(resources,policies,json.loads(historic,object_pairs_hook=private.unique),templates)
    baseline={'resources':resources,'policies':policies,'historical_sha256':HISTORICAL_SHA,'selected':audit(resources,policies,templates)}
    data=(json.dumps(baseline,sort_keys=True)+'\n').encode();bf=os.open(a.baseline,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(bf,'wb')as out:out.write(data);out.flush();os.fsync(out.fileno())
    record({'baseline_sha256':hashlib.sha256(data).hexdigest(),'selected_original_ids':[x['id']for x in baseline['selected']]})
   else:
    raw=private.private_read(a.baseline,2*1024*1024)
    if hashlib.sha256(raw).hexdigest()!=a.baseline_sha256:raise ValueError('bound baseline required')
    baseline=json.loads(raw,object_pairs_hook=private.unique)
    if a.phase=='lease':lease(request,baseline,record,datetime.datetime.now(datetime.timezone.utc))
    elif a.phase=='restore':restore(request,baseline,record)
    else:
     # Original authority must be restored BEFORE cleanup of only owned expired IDs.
     restore(request,baseline,record)
     events=private.private_read(a.lease_receipt,2*1024*1024)
     if hashlib.sha256(events).hexdigest()!=a.lease_sha256:raise ValueError('bound lease receipt required')
     cleanup(request,[json.loads(row,object_pairs_hook=private.unique)for row in events.splitlines()],record,datetime.datetime.now(datetime.timezone.utc))
   record({'completed':True})
  except BaseException as e:record({'completed':False,'error_type':type(e).__name__});raise
if __name__=='__main__':
 try:main()
 except BaseException as e:raise SystemExit('Owned expiry phase refused: '+type(e).__name__)

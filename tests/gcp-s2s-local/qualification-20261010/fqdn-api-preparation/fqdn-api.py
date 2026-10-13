"""Normal owned Classic FQDN API phases. No IO on import; no policy/native writes."""
import argparse,datetime,hashlib,importlib.util,json,os,pathlib,stat,time,urllib.request,urllib.error,uuid
import plan
PRIVATE=pathlib.Path('/private/tmp/gcp-s2s-cloud-policy-prep/deploy/ipsec/gcp-private-api-runner.py')
PRIVATE_SHA='5623fc4798a464e2926229646465b2603aea960d5f496abae136e871f9e4181e'
CONTEXT='/fqdn-resolver-contexts/'+plan.SITE+'/'+plan.NODE
LABELS=('app','alias','nx-qualification')
def uid(value):
 if not isinstance(value,str)or str(uuid.UUID(value))!=value or uuid.UUID(value).int==0:raise ValueError('actual UUID required')
 return value
def ids(rows):
 if not isinstance(rows,list):raise ValueError('list response required')
 out={uid(r['id']):r for r in rows}
 if len(out)!=len(rows):raise ValueError('duplicate inventory ID')
 return out
def connections(request):
 rows=[];cursor=None;seen=set()
 for _ in range(10):
  v=request('/ipsec/connections?limit=100'+('&cursor='+cursor if cursor else ''))
  if not isinstance(v,dict)or not isinstance(v.get('items'),list):raise ValueError('connections envelope')
  rows+=v['items'];cursor=v.get('next_cursor')
  if not cursor:ids(rows);return rows
  uid(cursor)
  if cursor in seen:raise ValueError('cursor loop')
  seen.add(cursor)
 raise ValueError('incomplete connection inventory')
def snapshot(request):
 configs={cid:request('/ipsec/connections/'+cid+'/configuration')for cid in ('80c20667-8d84-4dd8-8e51-ae4a10445cbb','b79d7eda-fafe-41cf-af2c-4115d4ef32c6','431fa305-4d3d-4c38-b0e4-88068c0e2297')}
 return {'configurations':configs,'connections':connections(request),'resources':request('/resources'),'policies':request('/policies'),'fqdn':request('/fqdn-resources'),'context':request(CONTEXT),'setting':request('/fqdn-resources/setting')}
def baseline_valid(b):
 for k,count in [('connections',9),('resources',13),('policies',12)]:
  if len(ids(b[k]))!=count:raise ValueError('unexpected current owned baseline')
 ids(b['fqdn']);plan.context(b['context'])
 if b['setting'].get('enabled')is not True:raise ValueError('existing opt-in required')
 names=[r['name']for r in b['fqdn']]
 for label in LABELS:plan.create(b['context'],label,names)
def preserve(b,current,owned):
 ignored={'connections':{'application_state','cleanup_state','updated_at'},'resources':{'created_at','updated_at'},'policies':{'fqdn_destination_status'}}
 for k,drop in ignored.items():
  projected=lambda rows:{rid:{field:value for field,value in row.items()if field not in drop}for rid,row in ids(rows).items()}
  if projected(current[k])!=projected(b[k]):raise ValueError('authoritative baseline drift')
 for k in ('configurations','context','setting'):
  if current[k]!=b[k]:raise ValueError('original configuration drift')
 old=ids(b['fqdn']);new=ids(current['fqdn'])
 if not set(old)<=set(new)or any(new[k]!=v for k,v in old.items()):raise ValueError('original FQDN drift')
 if set(new)-set(old)!=set(owned):raise ValueError('unknown new FQDN resource')
def resource_matches(r,body):
 uid(r['id'])
 for k in ('name','fqdn','protocol','port_low','port_high','label'):
  if r.get(k)!=body.get(k):raise ValueError('returned resource semantic mismatch')
 c=r.get('resolver_context')or{}
 if c.get('site_id')!=plan.SITE or c.get('gateway_id')!=plan.NODE:raise ValueError('returned resource context mismatch')
def check_impact(request):
 value=request('/fqdn-resources/setting/impact');plan.enforcement_body(value)
 return value['expected_impact_token']
def create(request,b,record):
 baseline_valid(b);preserve(b,snapshot(request),[]);check_impact(request);owned={}
 try:
  for label in LABELS:
   # Fresh read validates existing enabled/entitled state; create consumes no setting token.
   check_impact(request)
   body=plan.create(b['context'],label,[r['name']for r in b['fqdn']]);r=request('/fqdn-resources','POST',body)
   rid=uid(r['id']);owned[rid]={'label':label,'body':body};record({'created_id':rid,'label':label,'body':body})
   if rid in ids(b['fqdn'])or len(owned)!=LABELS.index(label)+1:raise ValueError('returned ID collision')
   resource_matches(r,body);detail=request('/fqdn-resources/'+rid);resource_matches(detail['resource'],body)
  record({'created':True,'owned':owned,'scope':'no policies or native authority modified'})
 finally:
  # Always independently verify original baseline even after partial POST failure.
  try:preserve(b,snapshot(request),owned);record({'original_baseline_preserved':True})
  except Exception as e:record({'original_baseline_preserved':False,'error_type':type(e).__name__});raise
 return owned
def observe(request,b,owned,record,seconds=90,clock=time.monotonic,sleep=time.sleep):
 if not 1<=seconds<=120:raise ValueError('observation budget')
 deadline=clock()+seconds;last={}
 while True:
  preserve(b,snapshot(request),owned)
  now=datetime.datetime.now(datetime.timezone.utc)
  for rid,v in owned.items():
   d=request('/fqdn-resources/'+uid(rid));resource_matches(d['resource'],v['body']);last[rid]=d
  accepted={rid:plan.generation(d,owned[rid]['label'],now)for rid,d in last.items()}
  record({'observed':last,'generation_accepted':accepted,'scope':'server API generation only; RPC/native/packet proof separate'})
  if all(accepted.values())and len(accepted)==3:return True
  if clock()>=deadline:return False
  sleep(min(5,max(0,deadline-clock())))
def cleanup(request,b,owned,record):
 preserve(b,snapshot(request),owned);remaining=dict(owned)
 try:
  for rid,v in owned.items():
   try:
    detail=request('/fqdn-resources/'+uid(rid));resource_matches(detail['resource'],v['body'])
    impact=request('/fqdn-resources/'+rid+'/impact');record({'cleanup_impact_id':rid,'impact':impact})
    # Backend refuses any references/active generation; do not PATCH context or bypass.
    request('/fqdn-resources/'+rid,'DELETE');remaining.pop(rid);record({'deleted_id':rid})
   except Exception as e:record({'retained_id':rid,'error_type':type(e).__name__})
 finally:preserve(b,snapshot(request),remaining);record({'original_baseline_preserved':True,'remaining_ids':list(remaining)})
 return remaining
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
def exclusive(path):
 p=pathlib.Path(path);s=p.parent.lstat()
 if not stat.S_ISDIR(s.st_mode)or s.st_uid!=os.getuid()or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('private parent required')
 return os.open(p,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o600)
def load_owned(raw):
 result={}
 for line in raw.decode().splitlines():
  v=json.loads(line)
  if 'created_id'in v:result[uid(v['created_id'])]={'label':v['label'],'body':v['body']}
  if 'deleted_id'in v:result.pop(v['deleted_id'],None)
 if not result or len(result)>3:raise ValueError('bound actual created IDs required')
 return result
def main():
 p=argparse.ArgumentParser();p.add_argument('--phase',choices=['prepare','create','observe','cleanup'],required=True);p.add_argument('--cookie-file',required=True);p.add_argument('--baseline',required=True);p.add_argument('--baseline-sha256');p.add_argument('--created-receipt');p.add_argument('--created-sha256');p.add_argument('--receipt',required=True);a=p.parse_args()
 if hashlib.sha256(PRIVATE.read_bytes()).hexdigest()!=PRIVATE_SHA:raise ValueError('auth helper drift')
 spec=importlib.util.spec_from_file_location('private',PRIVATE);private=importlib.util.module_from_spec(spec);spec.loader.exec_module(private)
 cookie=private.cookie_header(private.private_read(a.cookie_file));opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 def request(path,method='GET',body=None):
  r=urllib.request.Request('http://127.0.0.1:38083/api/v1/organizations/'+private.ORG+path,method=method,data=None if body is None else json.dumps(body).encode(),headers={'Cookie':cookie,'X-Tunnex-CSRF':'1','Content-Type':'application/json'})
  with opener.open(r,timeout=15)as response:
   raw=response.read(2*1024*1024+1)
   if len(raw)>2*1024*1024:raise ValueError('bounded API response')
   return json.loads(raw,object_pairs_hook=private.unique)if raw else None
 with os.fdopen(exclusive(a.receipt),'w')as f:
  def record(value):f.write(json.dumps(value)+'\n');f.flush();os.fsync(f.fileno())
  record({'started':True,'phase':a.phase})
  try:
   if a.phase=='prepare':
    b=snapshot(request);baseline_valid(b);check_impact(request)
    raw=(json.dumps(b,sort_keys=True)+'\n').encode()
    with os.fdopen(exclusive(a.baseline),'wb')as bf:bf.write(raw);bf.flush();os.fsync(bf.fileno())
    record({'prepared':True,'baseline_sha256':hashlib.sha256(raw).hexdigest()})
   else:
    raw=private.private_read(a.baseline,2*1024*1024)
    if hashlib.sha256(raw).hexdigest()!=a.baseline_sha256:raise ValueError('baseline digest required')
    b=json.loads(raw,object_pairs_hook=private.unique);baseline_valid(b)
    if a.phase=='create':create(request,b,record)
    else:
     raw=private.private_read(a.created_receipt,2*1024*1024)
     if hashlib.sha256(raw).hexdigest()!=a.created_sha256:raise ValueError('created receipt digest required')
     owned=load_owned(raw)
     if a.phase=='observe':record({'observation_complete':observe(request,b,owned,record)})
     else:cleanup(request,b,owned,record)
  except Exception as e:record({'completed':False,'error_type':type(e).__name__});raise SystemExit(1)
if __name__=='__main__':main()

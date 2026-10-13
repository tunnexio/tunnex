#!/usr/bin/env python3
"""One reviewed owned CloudDNS operation; run only on designated bastion."""
import argparse,json,os,pathlib,stat,subprocess,time
PROJECT='project-0048836f-6ba1-4a14-8da'
TARGETS={'ha':('6379914247511756275','10.80.0.'),'classic':('3397467516692614609','10.81.0.')}
def unique(pairs):
 out={}
 for k,v in pairs:
  if k in out:raise ValueError('duplicate JSON field')
  out[k]=v
 return out
def gcloud(*args):
 p=subprocess.run(['gcloud',*args,'--project='+PROJECT,'--format=json','--quiet'],capture_output=True,timeout=30,check=True)
 if len(p.stdout)>2*1024*1024:raise ValueError('bounded Google API output')
 return json.loads(p.stdout,object_pairs_hook=unique)if p.stdout.strip()else None
def rr_map(rows):
 out={}
 for r in rows:
  key=(r['name'],r['type'])
  if key in out:raise ValueError('duplicate RRset')
  out[key]={'name':r['name'],'type':r['type'],'ttl':r['ttl'],'rrdatas':sorted(r.get('rrdatas',[]))}
 return out
def record(profile):
 _,prefix=TARGETS[profile]
 return {'name':'large.'+profile+'.gcp.s2s-qa.tunnex.app.','type':'A','ttl':30,'rrdatas':sorted(prefix+str(n)for n in range(100,140))}
def validate_identity(profile,network,zone):
 id,_=TARGETS[profile];n='tn-gcps2s-20261010-'+profile;z=n+'-qa-zone'
 if network.get('id')!=id or network.get('name')!=n or network.get('selfLink')!='https://www.googleapis.com/compute/v1/projects/'+PROJECT+'/global/networks/'+n:raise ValueError('exact owned network')
 bindings=zone.get('privateVisibilityConfig',{}).get('networks',[])
 if zone.get('name')!=z or zone.get('dnsName')!=profile+'.gcp.s2s-qa.tunnex.app.'or zone.get('visibility')!='private' or bindings!=[{'networkUrl':network['selfLink']}]:raise ValueError('exact sole owned private zone')
def decide(before,expected):
 current=before.get((expected['name'],expected['type']))
 if current is not None and current!=expected:raise ValueError('existing large RRset mismatch')
 return 'absent'if current is None else'exact_exists'
def preserve(before,after,expected):
 wanted=dict(before);wanted[(expected['name'],expected['type'])]=expected
 if after!=wanted:raise ValueError('all prior RRsets/exact new record preservation')
def main():
 p=argparse.ArgumentParser();p.add_argument('--profile',choices=TARGETS,required=True);p.add_argument('--receipt',required=True);p.add_argument('--apply',action='store_true');a=p.parse_args()
 parent=pathlib.Path(a.receipt).parent;s=os.lstat(parent)
 if not stat.S_ISDIR(s.st_mode)or s.st_uid!=os.getuid()or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('private receipt parent')
 fd=os.open(a.receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);r={'started':True,'profile':a.profile,'apply_requested':a.apply,'completed':False,'created':False,'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
 try:
  n='tn-gcps2s-20261010-'+a.profile;z=n+'-qa-zone';network=gcloud('compute','networks','describe',n);zone=gcloud('dns','managed-zones','describe',z);validate_identity(a.profile,network,zone)
  before=rr_map(gcloud('dns','record-sets','list','--zone='+z));expected=record(a.profile);decision=decide(before,expected)
  r.update(zone=z,network_id=network['id'],dns_name=expected['name'],rrset=expected,decision=decision,baseline_record_count=len(before),baseline_rrsets=list(before.values()))
  # Only explicit reviewed --apply can create; exact existing records are no-op.
  if a.apply and decision=='absent':
   gcloud('dns','record-sets','create',expected['name'],'--zone='+z,'--type=A','--ttl=30','--rrdatas='+','.join(expected['rrdatas']));r['created']=True
  after=rr_map(gcloud('dns','record-sets','list','--zone='+z))
  if a.apply or decision=='exact_exists':preserve(before,after,expected)
  elif after!=before:raise ValueError('read-only plan baseline changed')
  r.update(completed=True,prior_records_exact_preserved=True,current_record_count=len(after),scope='Only exact owned diagnostic40-A record; no application grant or hosting claim')
 except Exception as e:r['error_type']=type(e).__name__;raise
 finally:
  with os.fdopen(fd,'w')as f:json.dump(r,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 if r['completed']:print(json.dumps({k:r[k]for k in ['profile','created','completed','prior_records_exact_preserved','decision','dns_name']}))
if __name__=='__main__':
 try:main()
 except Exception as e:raise SystemExit('Owned CloudDNS record operation refused: '+type(e).__name__)

import argparse, pathlib, os, json, datetime, subprocess, sys, hashlib
D=pathlib.Path(__file__).parent
RUN=D/'run-selected-udp-continuation.bound-v9.py'
RUN_SHA='7dcac5966e69a3b1a0324d9ef4fdbe27c1a1bbe89c1a19427d31049795e20f4e'
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
def main():
 p=argparse.ArgumentParser();p.add_argument('--protocol',choices=['udp'],required=True);p.add_argument('--attempt',required=True);p.add_argument('--accepted-predecessor',required=True);p.add_argument('--accepted-predecessor-sha256',required=True);p.add_argument('--accepted-state',required=True);x=p.parse_args()
 if not x.attempt.isdigit():raise ValueError('numeric exclusive attempt')
 if hashlib.sha256(RUN.read_bytes()).hexdigest()!=RUN_SHA:raise ValueError('frozen runner changed')
 if (x.accepted_predecessor,x.accepted_predecessor_sha256,x.accepted_state)!=('/private/tmp/gcp-grant-transition-readiness-20261012/v5/actual-selected-tcp-v5-1/result.json','e8cb3eb519b025b548d3699179dac4e1e56177148a575fed2fcc537476e4ce4a','/private/tmp/gcp-grant-transition-readiness-20261012/v5/actual-selected-tcp-v5-1/096-api-retain-resource/state.json'):raise ValueError('exact accepted TCP v5 predecessor required')
 C=D/('actual-selected-'+x.protocol+'-control-v9-'+x.attempt);C.mkdir(mode=0o700,exist_ok=False)
 def save(n,v):
  with os.fdopen(os.open(C/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
 out=D/('actual-selected-'+x.protocol+'-v9-'+x.attempt)
 args=[sys.executable,str(RUN),'--out',str(out),'--baseline','/private/tmp/gcp-post-cas-baseline-20261011-v1/baseline.json','--cookie-file','/Users/pawangupta/.codex/worktrees/gcp-s2s/tunnex/tests/gcp-s2s-local/.runtime/gateway-owner.cookies','--selected-protocol',x.protocol,'--apply']
 if x.accepted_predecessor:args+=['--accepted-predecessor',x.accepted_predecessor,'--accepted-predecessor-sha256',x.accepted_predecessor_sha256,'--accepted-state',x.accepted_state]
 save('started.json',{'started_at':now(),'runner_sha256':RUN_SHA,'selected_protocol':x.protocol,'out':str(out)})
 r=None;e=None
 with os.fdopen(os.open(C/'stdout',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as sf,os.fdopen(os.open(C/'stderr',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as ef:
  try:r=subprocess.run(args,stdout=sf,stderr=ef,timeout=180)
  except BaseException as error:e=type(error).__name__
  finally:sf.flush();ef.flush();os.fsync(sf.fileno());os.fsync(ef.fileno())
 v={'finished_at':now(),'returncode':r.returncode if r else None,'error_type':e,'stdout_sha256':hashlib.sha256((C/'stdout').read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256((C/'stderr').read_bytes()).hexdigest()};save('finished.json',v);print(json.dumps(v));raise SystemExit(0 if e is None and r.returncode==0 else 1)
if __name__=='__main__':main()

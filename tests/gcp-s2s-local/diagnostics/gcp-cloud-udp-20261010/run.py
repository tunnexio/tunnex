import argparse,base64,hashlib,json,os,pathlib,shlex,stat,subprocess,sys,time
BASE=pathlib.Path('/private/tmp/gcp-s2s-cloud-packet-runner/deploy/ipsec/gcp-cloud-packet-check.py')
BASE_SHA='b459a936a7d2b1899cdda72e311a217ea60b771dd97a649291ecb63a82a8bf49'
ORCHESTRATE=r'''
def read_final_preserving_capture(proc,capture):
 try:return line(proc,15)
 except Exception as e:
  return dict(capture,stable_gate=False,transport_identity_stable=False,guard_identity_stable=False,final_frame_missing=True,final_error_type=type(e).__name__)
def diagnostic(base_source,gateway_source):
 nonce=str(uuid.uuid4());verify_pin(CLIENT);verify_pin(TARGETS['classic']);observers=[]
 target_cmd='sudo -n python3 -c '+shlex.quote(base_source+'\nobserve("10.81.0.10","udp",'+repr(nonce)+')')
 gateway_cmd='sudo -n python3 -c '+shlex.quote(gateway_source+'\ngateway_observe('+repr(nonce)+')')
 gw=['ssh','-i','/home/cyberking9560/.ssh/google_compute_engine','-o','UserKnownHostsFile=/home/cyberking9560/.ssh/google_compute_known_hosts','-o','HostKeyAlias=compute.1860325440445762510','-o','StrictHostKeyChecking=yes','-o','CheckHostIP=no','-o','BatchMode=yes','-o','ConnectTimeout=10','cyberking9560@34.131.136.132',gateway_cmd]
 try:
  for argv in [ssh(TARGETS['classic'],target_cmd),gw]:observers.append(subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True))
  target_ready=line(observers[0],15);gateway_ready=line(observers[1],15)
  if target_ready.get('ready')is not True or target_ready.get('target')!='10.81.0.10' or gateway_ready.get('ready')is not True:raise ValueError('all observer READY required')
  cmd='python3 -c '+shlex.quote(base_source+'\nprint(json.dumps(probe("10.81.0.10","10.70.0.10","udp",'+repr(nonce)+')))')
  result=subprocess.run(ssh(CLIENT,cmd),capture_output=True,text=True,timeout=15,check=True)
  if len(result.stdout)>32768:raise ValueError('bounded client')
  probe_result=json.loads(result.stdout,object_pairs_hook=unique)
  for proc in observers:proc.stdin.write('STOP\n');proc.stdin.flush()
  target_after=line(observers[0],8);gateway_capture=line(observers[1],15)
  if gateway_capture.get('capture_complete')is not True:raise ValueError('capture frame required')
  gateway_after=read_final_preserving_capture(observers[1],gateway_capture)
  for proc in observers:
   if proc is observers[1] and gateway_after.get('final_frame_missing'):continue
   proc.wait(timeout=5)
   if proc.returncode:raise ValueError('observer clean exit required')
  return {'nonce':nonce,'protocol_probes':['udp'],'probe_count':1,'client':probe_result,'target_ready':target_ready,'target_after':target_after,'gateway_ready':gateway_ready,'gateway_capture':gateway_capture,'gateway_after':gateway_after,'diagnostic_stable':gateway_after['stable_gate'] and target_after['stopped_by_request'] and target_after['capture_drops']==0,'scope':'one UDP observation only; no remediation, retry, guard/SA lease renewal or policy change'}
 finally:
  for proc in observers:
   if proc.poll()is None:proc.terminate();proc.wait(timeout=5)
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--evidence',required=True);a=p.parse_args();b=BASE.read_bytes()
 if hashlib.sha256(b).hexdigest()!=BASE_SHA:raise ValueError('reviewed target observer drift')
 base=b.decode().split('\nif __name__')[0];gateway=pathlib.Path(__file__).with_name('gateway-observer.py').read_text()
 parent=pathlib.Path(a.evidence).parent;s=os.lstat(parent)
 if not stat.S_ISDIR(s.st_mode)or s.st_uid!=os.getuid()or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('private evidence parent')
 fd=os.open(a.evidence,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);r=None
 metadata={'started':True,'protocol_probes':['udp'],'probe_count_limit':1,'base_sha256':BASE_SHA,'gateway_observer_sha256':hashlib.sha256(gateway.encode()).hexdigest(),'orchestrator_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
 try:
  code=base+ORCHESTRATE+'\nprint(json.dumps(diagnostic('+repr(base)+','+repr(gateway)+')))'
  r=subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','cyberking9560@34.131.23.179','python3 -c '+shlex.quote(code)],capture_output=True,timeout=90)
  if r.returncode or len(r.stdout)>256*1024:raise ValueError('bounded diagnostic refused')
  value=json.loads(r.stdout);metadata.update(completed=True,result=value)
 except Exception as e:
  by=lambda v:v.encode()if isinstance(v,str)else v or b''
  metadata.update(completed=False,error_type=type(e).__name__,returncode=r.returncode if r else None,stdout_sha256=hashlib.sha256(by(r.stdout if r else getattr(e,'stdout',None))).hexdigest(),stderr_sha256=hashlib.sha256(by(r.stderr if r else getattr(e,'stderr',None))).hexdigest());raise
 finally:
  with os.fdopen(fd,'w')as f:json.dump(metadata,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
if __name__=='__main__':
 try:main()
 except Exception as e:print('Instrumented UDP diagnostic refused: '+type(e).__name__,file=sys.stderr);sys.exit(1)

"""Root-coordinated single read-only observation; no API or cloud writes."""
import pathlib,hashlib,types,subprocess,shlex,base64,json,os,stat,argparse,sys
D=pathlib.Path('/private/tmp/gcp-native-reader-fixed-stage-v7-diagnostic-20261012')
REMOTE=D/'native-fqdn-binding.diagnostic-v1.remote.py';REMOTE_SHA='1f36429fe0639d2c7eebe58776c0879e45449ee5faeaad707e26d05fce173bd8'
TRANSPORT=pathlib.Path('/private/tmp/gcp-cloud-native-build-20261010-1/build.py');TRANSPORT_SHA='f2b27b12b40073ed5ad0d9625d92778047dbf766d460368db2fc97602d77ce38'
def exclusive(p):
 parent=p.parent.lstat()
 if not stat.S_ISDIR(parent.st_mode)or parent.st_uid!=os.geteuid()or stat.S_IMODE(parent.st_mode)!=0o700:raise ValueError('owned private output parent')
 return os.fdopen(os.open(p,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o600),'wb')
def main():
 a=argparse.ArgumentParser();a.add_argument('--receipt',required=True);a.add_argument('--allocation',required=True);a.add_argument('--allocation-sha256',required=True);args=a.parse_args();out=pathlib.Path(args.receipt)
 allocation=pathlib.Path(args.allocation);fd=os.open(allocation,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode)or st.st_uid!=os.geteuid()or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>2097152:raise ValueError('private allocation receipt')
  raw=os.read(fd,2097153);after=os.fstat(fd)
  if len(raw)!=st.st_size or (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)or hashlib.sha256(raw).hexdigest()!=args.allocation_sha256:raise ValueError('allocation receipt identity')
 finally:os.close(fd)
 def unique(pairs):
  out={}
  for k,v in pairs:
   if k in out:raise ValueError('duplicate allocation receipt field')
   out[k]=v
  return out
 rows=[json.loads(line,object_pairs_hook=unique)for line in raw.splitlines()];complete=[r for r in rows if r.get('completed')is True]
 starts=[r for r in rows if r.get('started')is True]
 if len(starts)!=1 or starts[0].get('remote_source_sha256')!='4c4e0d306ab15c3847492bdcf9eaab161cb7306d1ebe71632211cba17f069b63':raise ValueError('allocation source receipt')
 if len(complete)!=1 or complete[0].get('remote_source_sha256', '4c4e0d306ab15c3847492bdcf9eaab161cb7306d1ebe71632211cba17f069b63')!='4c4e0d306ab15c3847492bdcf9eaab161cb7306d1ebe71632211cba17f069b63':raise ValueError('allocation producer')
 observation=complete[0]['observation'];binding=observation['current_allocation'];identity=observation['identity']
 if observation.get('completed')is not True or binding['connection_id']!='b79d7eda-fafe-41cf-af2c-4115d4ef32c6' or not binding['engine_name'].endswith('-d7-c1-s2'):raise ValueError('allocation purpose')
 remote=REMOTE.read_bytes();transport=TRANSPORT.read_bytes()
 if hashlib.sha256(remote).hexdigest()!=REMOTE_SHA or hashlib.sha256(transport).hexdigest()!=TRANSPORT_SHA:raise ValueError('reviewed source drift')
 ns={};exec(compile(transport.decode().split('receipt=json.loads')[0],str(TRANSPORT),'exec'),ns)
 prefix='BOUND_ALLOCATION='+repr(binding)+'\nBOUND_IDENTITY='+repr(identity)+'\nBOUND_RECEIPT_SHA='+repr(args.allocation_sha256)+'\n';encoded=base64.b64encode(prefix.encode()+remote).decode();program="import base64;exec(compile(base64.b64decode("+repr(encoded)+"),'owned-classic-current-allocation','exec'),{'__name__':'__main__'})"
 command='sudo -n python3 -c '+shlex.quote(program)
 stdout=out.with_name(out.name+'.stdout');stderr=out.with_name(out.name+'.stderr')
 with exclusive(out)as receipt,exclusive(stdout)as sf,exclusive(stderr)as ef:
  def record(v):receipt.write((json.dumps(v,sort_keys=True)+'\n').encode());receipt.flush();os.fsync(receipt.fileno())
  record({'started':True,'mutations':0,'remote_source_sha256':REMOTE_SHA,'transport_sha256':TRANSPORT_SHA})
  try:
   result=subprocess.run(ns['B']+[shlex.join(ns['G']+[command])],stdout=sf,stderr=ef,timeout=75)
   sf.flush();ef.flush();os.fsync(sf.fileno());os.fsync(ef.fileno())
   raw=stdout.read_bytes()
   if result.returncode or len(raw)>2097152:raise ValueError('native observer returned refusal')
   value=json.loads(raw)
   if not isinstance(value,dict)or value.get('completed')is not True:raise ValueError('native observation incomplete')
   record({'completed':True,'scope':'native observation only; separate normalAPI cleanup ACK and fullguard required','observation':value,'stdout_sha256':hashlib.sha256(raw).hexdigest(),'stderr_sha256':hashlib.sha256(stderr.read_bytes()).hexdigest()})
  except BaseException as e:
   sf.flush();ef.flush();os.fsync(sf.fileno());os.fsync(ef.fileno())
   record({'completed':False,'error_type':type(e).__name__,'stdout_sha256':hashlib.sha256(stdout.read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256(stderr.read_bytes()).hexdigest(),'retry_forbidden':True});raise
if __name__=='__main__':
 try:main()
 except BaseException as e:print(json.dumps({'completed':False,'error_type':type(e).__name__}));raise SystemExit(1)
